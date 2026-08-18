package scanner

// Login Security Scanner
// -----------------------------------------------------------------------------
// Assesses the authentication surface of a target: it discovers the login
// endpoint (Laravel / Frappe-ERPNext / WordPress / generic), then evaluates
// four authentication weaknesses (OWASP A07:2021 — Identification & Auth
// Failures):
//
//   1. Login Transport Security   — is the login form reachable over plain HTTP?
//   2. Account Lockout Protection — does the login rate-limit / lock out after
//                                   repeated failures? (brute-force resistance)
//   3. Weak or Default Credentials — are common/default credentials accepted?
//   4. Username Enumeration        — does the app leak which usernames exist?
//
// SAFETY / AUTHORIZATION GATE
// ---------------------------
// Checks 2-4 send real login POST requests and are therefore ACTIVE/INTRUSIVE.
// They run ONLY when BOTH of these are set, so the scanner can never be pointed
// at a third party by accident:
//
//   SEKU_ENABLE_ACTIVE_LOGIN_TEST=1
//   SEKU_LOGIN_TEST_ALLOWLIST="ums.erticaz.com,*.uoturath.edu.iq,..."
//
// Otherwise only passive discovery (GET) runs and the active checks report
// "skipped — authorization required". All active traffic is capped and
// rate-limited (via the shared ScanTransport), non-destructive, and probes
// lockout with a random NON-EXISTENT username so it never locks a real account.
//
// Optional tuning:
//   SEKU_LOGIN_MAX_ATTEMPTS   (default 30)  — cap for the weak-credential probe
//   SEKU_LOGIN_USERS_FILE     path to a larger username list (overrides embed)
//   SEKU_LOGIN_PASS_FILE      path to a larger password list (e.g. rockyou)

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "embed"

	"seku/internal/models"
)

//go:embed wordlists/users.txt
var embeddedUsers string

//go:embed wordlists/passwords.txt
var embeddedPasswords string

type LoginScanner struct{}

func NewLoginScanner() *LoginScanner { return &LoginScanner{} }

func (s *LoginScanner) Name() string     { return "Login Security Scanner" }
func (s *LoginScanner) Category() string { return "login" }
func (s *LoginScanner) Weight() float64  { return 12.0 }

const (
	loginLockoutMax  = 10 // apps commonly lock/slow only after ~10; 6 caused false "no lockout"
	loginWeakCredMax = 30
	loginReqTimeout  = 12 * time.Second
	loginBodyCap     = 256 * 1024
)

var (
	rePwField   = regexp.MustCompile(`(?is)<input[^>]*type=["']?password["']?[^>]*>`)
	reInputTag  = regexp.MustCompile(`(?is)<input[^>]*>`)
	reNameAttr  = regexp.MustCompile(`(?i)\bname=["']([^"']+)["']`)
	reTypeAttr  = regexp.MustCompile(`(?i)\btype=["']?([a-zA-Z]+)`)
	reValueAttr = regexp.MustCompile(`(?i)\bvalue=["']([^"']*)["']`)
	reMetaCSRF  = regexp.MustCompile(`(?i)<meta[^>]*name=["']csrf-token["'][^>]*content=["']([^"']+)["']`)
	reFrappeTok = regexp.MustCompile(`(?i)csrf_token\s*[=:]\s*["']([0-9a-zA-Z]+)["']`)
)

var lockoutKeywords = []string{
	"too many", "throttle", "temporarily", "locked", "try again later",
	"rate limit", "retry after", "kindly wait", "wait a", "exceeded",
	"disabled due to", "محاولات", "حظر", "انتظر",
}

var mfaKeywords = []string{
	"otp", "one-time", "one time", "2fa", "two-factor", "two factor",
	"authenticator", "verification code", "mfa", "التحقق بخطوتين", "رمز التحقق",
}

// register CVSS / OWASP / confidence metadata for this scanner's failing checks
// (kept here so cvss.go / owasp.go / confidence.go stay untouched).
func init() {
	CheckCVSSMap["Weak or Default Credentials"] = CVSSMapping{9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical"}
	CheckCVSSMap["Account Lockout Protection"] = CVSSMapping{5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", "Medium"} // a heuristic control gap, not a confirmed exploit
	CheckCVSSMap["Username Enumeration"] = CVSSMapping{5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"}
	CheckCVSSMap["Login Transport Security"] = CVSSMapping{7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"}

	CheckOWASPMap["Weak or Default Credentials"] = OWASPMapping{"A07:2021", "Identification and Authentication Failures", "CWE-1392", "Use of Default Credentials", "Critical"}
	CheckOWASPMap["Account Lockout Protection"] = OWASPMapping{"A07:2021", "Identification and Authentication Failures", "CWE-307", "Improper Restriction of Excessive Authentication Attempts", "High"}
	CheckOWASPMap["Username Enumeration"] = OWASPMapping{"A07:2021", "Identification and Authentication Failures", "CWE-204", "Observable Response Discrepancy", "Medium"}
	CheckOWASPMap["Login Transport Security"] = OWASPMapping{"A02:2021", "Cryptographic Failures", "CWE-319", "Cleartext Transmission of Sensitive Information", "High"}

	CheckConfidence["Weak or Default Credentials"] = 95
	CheckConfidence["Account Lockout Protection"] = 85
	CheckConfidence["Username Enumeration"] = 65
	CheckConfidence["Login Transport Security"] = 90
}

type loginTarget struct {
	host      string
	pageURL   string
	postURL   string
	kind      string // laravel | frappe | wordpress | generic
	userField string
	passField string
	csrfField string
	csrfToken string
	body      string
	found     bool
}

func (s *LoginScanner) Scan(rawURL string) []models.CheckResult { return s.scan(rawURL, nil) }

// ScanWithConfig lets a scan enable active login testing per-run with an
// explicit authorization acknowledgement, bypassing the env allowlist.
func (s *LoginScanner) ScanWithConfig(rawURL string, cfg *ScanConfig) []models.CheckResult {
	return s.scan(rawURL, cfg)
}

func (s *LoginScanner) scan(rawURL string, cfg *ScanConfig) []models.CheckResult {
	var results []models.CheckResult

	base := ensureHTTPS(rawURL)
	t := s.discover(base)
	t.host = extractHost(base)

	results = append(results, s.discoveryResult(t))
	if !t.found {
		return results
	}

	// passive checks (safe on any target)
	results = append(results, s.checkTransport(t))
	results = append(results, s.checkMFA(t))

	// authorization gate for the active checks
	allowed, reason := activeLoginAllowed(t.host)
	if !allowed && cfg != nil && cfg.EnableLogin && cfg.Authorized {
		allowed, reason = true, ""
	}
	if !allowed {
		results = append(results, s.skipped("Account Lockout Protection", reason))
		results = append(results, s.skipped("Username Enumeration", reason))
		results = append(results, s.skipped("Weak or Default Credentials", reason))
		return results
	}

	results = append(results, s.checkLockout(t))
	results = append(results, s.checkUsernameEnum(t))
	results = append(results, s.checkWeakCredentials(t))
	return results
}

// ---------------------------------------------------------------- discovery

func (s *LoginScanner) discover(base string) loginTarget {
	client := s.newClient()
	candidates := []string{
		"/login", "/wp-login.php", "/admin/login", "/user/login",
		"/account/login", "/auth/login", "/signin", "/administrator/", "/admin",
	}
	for _, p := range candidates {
		resp, body, err := doHTTP(client, "GET", base+p, nil, nil)
		if err != nil || resp == nil || resp.StatusCode >= 400 {
			continue
		}
		if !rePwField.MatchString(body) && !strings.Contains(strings.ToLower(body), "password") {
			continue
		}
		t := loginTarget{pageURL: base + p, body: body, found: true}
		s.classify(base, t.pageURL, body, &t)
		return t
	}
	return loginTarget{}
}

func (s *LoginScanner) classify(base, pageURL, body string, t *loginTarget) {
	lb := strings.ToLower(body)
	switch {
	case strings.Contains(lb, "wp-login.php") || strings.Contains(lb, "wp-submit") || strings.Contains(lb, "wordpress"):
		t.kind = "wordpress"
		t.postURL = base + "/wp-login.php"
		t.userField, t.passField = "log", "pwd"
	case strings.Contains(lb, "/assets/frappe") || strings.Contains(lb, "frappe.csrf") || strings.Contains(lb, "frappe.boot"):
		t.kind = "frappe"
		t.postURL = base + "/api/method/login"
		t.userField, t.passField = "usr", "pwd"
	case reMetaCSRF.MatchString(body) || strings.Contains(body, `name="_token"`) || strings.Contains(lb, "laravel_session"):
		t.kind = "laravel"
		t.postURL = pageURL
		t.userField, t.passField = detectFields(body, "email", "password")
		t.csrfField = "_token"
	default:
		t.kind = "generic"
		t.postURL = pageURL
		t.userField, t.passField = detectFields(body, "username", "password")
	}

	if m := reMetaCSRF.FindStringSubmatch(body); m != nil {
		t.csrfToken = m[1]
		if t.csrfField == "" {
			t.csrfField = "_token"
		}
	} else if f, v := findHidden(body, "_token", "csrf", "authenticity_token"); f != "" {
		t.csrfField, t.csrfToken = f, v
	}
}

func detectFields(body, defUser, defPass string) (string, string) {
	userField, passField := defUser, defPass
	userSet := false
	for _, in := range reInputTag.FindAllString(body, -1) {
		typ, name := "", ""
		if m := reTypeAttr.FindStringSubmatch(in); m != nil {
			typ = strings.ToLower(m[1])
		}
		if m := reNameAttr.FindStringSubmatch(in); m != nil {
			name = m[1]
		}
		if name == "" {
			continue
		}
		switch typ {
		case "password":
			passField = name
		case "text", "email", "tel":
			if !userSet {
				userField, userSet = name, true
			}
		}
	}
	return userField, passField
}

func findHidden(body string, keys ...string) (string, string) {
	for _, in := range reInputTag.FindAllString(body, -1) {
		name := ""
		if m := reNameAttr.FindStringSubmatch(in); m != nil {
			name = m[1]
		}
		if name == "" {
			continue
		}
		ln := strings.ToLower(name)
		for _, k := range keys {
			if strings.Contains(ln, k) {
				val := ""
				if m := reValueAttr.FindStringSubmatch(in); m != nil {
					val = m[1]
				}
				return name, val
			}
		}
	}
	return "", ""
}

// ---------------------------------------------------------------- passive checks

func (s *LoginScanner) discoveryResult(t loginTarget) models.CheckResult {
	c := models.CheckResult{Category: s.Category(), CheckName: "Login Endpoint Discovery", Weight: 0, Status: "info", Score: 1000, Severity: "info"}
	if !t.found {
		c.Details = toJSON(map[string]string{"message": "No public login endpoint detected on common paths."})
		return c
	}
	c.Details = toJSON(map[string]interface{}{
		"message":        "Login endpoint detected.",
		"endpoint":       t.pageURL,
		"type":           t.kind,
		"user_field":     t.userField,
		"password_field": t.passField,
	})
	return c
}

func (s *LoginScanner) checkTransport(t loginTarget) models.CheckResult {
	c := models.CheckResult{Category: s.Category(), CheckName: "Login Transport Security", Weight: 4.0}
	client := s.newClient()
	resp, body, err := doHTTP(client, "GET", ensureHTTP(t.pageURL), nil, nil)
	servedOverHTTP := err == nil && resp != nil && resp.StatusCode < 300 &&
		(rePwField.MatchString(body) || strings.Contains(strings.ToLower(body), "password"))
	if servedOverHTTP {
		c.Status, c.Score, c.Severity = "fail", 0, "high"
		c.Details = toJSON(map[string]string{"message": "Login form is served over plain HTTP without redirecting to HTTPS — credentials can be intercepted (MITM)."})
	} else {
		c.Status, c.Score, c.Severity = "pass", 1000, "info"
		c.Details = toJSON(map[string]string{"message": "Login is only reachable over HTTPS (HTTP is redirected or unavailable)."})
	}
	return c
}

func (s *LoginScanner) checkMFA(t loginTarget) models.CheckResult {
	c := models.CheckResult{Category: s.Category(), CheckName: "Multi-Factor Authentication", Weight: 0, Status: "info", Score: 1000, Severity: "info"}
	lb := strings.ToLower(t.body)
	for _, k := range mfaKeywords {
		if strings.Contains(lb, k) {
			c.Details = toJSON(map[string]string{"message": "MFA / one-time-code indicators found on the login page."})
			return c
		}
	}
	c.Details = toJSON(map[string]string{"message": "No MFA indicators on the primary login form — verify MFA is enforced for privileged accounts."})
	return c
}

// ---------------------------------------------------------------- active checks

func (s *LoginScanner) checkLockout(t loginTarget) models.CheckResult {
	c := models.CheckResult{Category: s.Category(), CheckName: "Account Lockout Protection", Weight: 8.0}
	client := s.newClient()
	badUser := "seku_probe_" + randHex(8) + "@example.invalid"
	attempts, locked, lastCode := 0, false, 0
	for i := 0; i < loginLockoutMax; i++ {
		attempts++
		code, body, hdr := s.attemptLogin(client, t, badUser, "SekuWrong!"+randHex(4))
		lastCode = code
		if code == http.StatusTooManyRequests || hdr.Get("Retry-After") != "" || lockoutSignal(body) {
			locked = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if locked {
		c.Status, c.Score, c.Severity = "pass", 1000, "info"
		c.Details = toJSON(map[string]interface{}{
			"message":              "Login enforces rate-limiting / lockout after repeated failures.",
			"attempts_before_lock": attempts,
		})
	} else {
		c.Status, c.Score, c.Severity = "fail", 0, "high"
		c.Details = toJSON(map[string]interface{}{
			"message":     fmt.Sprintf("No rate-limiting or account lockout after %d failed logins — vulnerable to brute-force / credential stuffing. Add throttling (e.g. Laravel throttle, fail2ban, WAF rate rules, or Limit-Login plugins).", attempts),
			"last_status": lastCode,
		})
	}
	return c
}

func (s *LoginScanner) checkUsernameEnum(t loginTarget) models.CheckResult {
	c := models.CheckResult{Category: s.Category(), CheckName: "Username Enumeration", Weight: 4.0}
	client := s.newClient()
	validUser := "admin"
	if t.kind == "frappe" {
		validUser = "Administrator"
	}
	invalidUser := "seku_" + randHex(12)

	cA, bA, _ := s.attemptLogin(client, t, validUser, "WrongPass!"+randHex(4))
	time.Sleep(300 * time.Millisecond)
	cB, bB, _ := s.attemptLogin(client, t, invalidUser, "WrongPass!"+randHex(4))

	// Establish a noise floor: two identical invalid attempts should look the
	// same. If per-request dynamics (CSRF token, nonce, timestamp) already make
	// them "significantly different", the valid-vs-invalid diff is unreliable —
	// don't flag enumeration on page noise.
	time.Sleep(300 * time.Millisecond)
	cN, bN, _ := s.attemptLogin(client, t, invalidUser, "WrongPass!"+randHex(4))
	noisy := cB != cN || significantlyDifferent(bB, bN)

	distinct := !noisy && (cA != cB || significantlyDifferent(bA, bB))
	if distinct {
		c.Status, c.Score, c.Severity = "fail", 100, "medium"
		c.Details = toJSON(map[string]interface{}{
			"message":             "The login responds differently to valid vs invalid usernames — usernames can be enumerated, easing targeted brute-force. Return an identical generic error for both cases.",
			"valid_user_status":   cA,
			"invalid_user_status": cB,
		})
	} else {
		c.Status, c.Score, c.Severity = "pass", 1000, "info"
		c.Details = toJSON(map[string]string{"message": "No observable difference between valid and invalid usernames — enumeration not detected."})
	}
	return c
}

func (s *LoginScanner) checkWeakCredentials(t loginTarget) models.CheckResult {
	c := models.CheckResult{Category: s.Category(), CheckName: "Weak or Default Credentials", Weight: 10.0}
	client := s.newClient()

	users := prioritizeUsers(loadList(embeddedUsers, os.Getenv("SEKU_LOGIN_USERS_FILE")), t)
	passwords := loadList(embeddedPasswords, os.Getenv("SEKU_LOGIN_PASS_FILE"))
	maxAttempts := envInt("SEKU_LOGIN_MAX_ATTEMPTS", loginWeakCredMax)

	attempts, locked := 0, false
	var found []string

outer:
	for _, u := range users {
		for _, p := range passwords {
			if attempts >= maxAttempts {
				break outer
			}
			attempts++
			code, body, hdr := s.attemptLogin(client, t, u, p)
			if code == http.StatusTooManyRequests || hdr.Get("Retry-After") != "" || lockoutSignal(body) {
				locked = true
				break outer
			}
			if s.loginSucceeded(t, code, body, hdr) {
				found = append(found, u+" : "+p)
				break outer
			}
			time.Sleep(250 * time.Millisecond)
		}
	}

	switch {
	case len(found) > 0:
		c.Status, c.Score, c.Severity = "fail", 0, "critical"
		c.Details = toJSON(map[string]interface{}{
			"message":     "Weak or default credentials are accepted — change them immediately and enforce a strong password policy.",
			"credentials": found,
			"attempts":    attempts,
		})
	case locked:
		c.Status, c.Score, c.Severity = "pass", 1000, "info"
		c.Details = toJSON(map[string]interface{}{
			"message":  fmt.Sprintf("Lockout / rate-limiting stopped the credential probe after %d attempts — no weak credential confirmed and brute-force protection is active.", attempts),
			"attempts": attempts,
		})
	default:
		c.Status, c.Score, c.Severity = "pass", 1000, "info"
		c.Details = toJSON(map[string]interface{}{
			"message":  fmt.Sprintf("No weak or default credentials accepted across %d tested combinations.", attempts),
			"attempts": attempts,
		})
	}
	return c
}

// ---------------------------------------------------------------- login mechanics

func (s *LoginScanner) attemptLogin(client *http.Client, t loginTarget, user, pass string) (int, string, http.Header) {
	form := url.Values{}
	form.Set(t.userField, user)
	form.Set(t.passField, pass)
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

	switch t.kind {
	case "laravel":
		if tok := s.freshCSRF(client, t); tok != "" {
			form.Set(t.csrfFieldOr("_token"), tok)
		} else if t.csrfToken != "" {
			form.Set(t.csrfFieldOr("_token"), t.csrfToken)
		}
	case "frappe":
		if tok := s.frappeCSRF(client, t); tok != "" {
			headers["X-Frappe-CSRF-Token"] = tok
		}
	case "wordpress":
		form.Set("wp-submit", "Log In")
		form.Set("testcookie", "1")
		headers["Cookie"] = "wordpress_test_cookie=WP+Cookie+check"
	default:
		if t.csrfField != "" && t.csrfToken != "" {
			form.Set(t.csrfField, t.csrfToken)
		}
	}

	resp, body, err := doHTTP(client, "POST", t.postURL, strings.NewReader(form.Encode()), headers)
	if err != nil || resp == nil {
		return 0, "", http.Header{}
	}
	return resp.StatusCode, body, resp.Header
}

func (s *LoginScanner) loginSucceeded(t loginTarget, code int, body string, hdr http.Header) bool {
	setCookie := strings.ToLower(strings.Join(hdr["Set-Cookie"], "; "))
	loc := hdr.Get("Location")
	switch t.kind {
	case "frappe":
		return code == 200 && strings.Contains(body, "Logged In")
	case "wordpress":
		if strings.Contains(setCookie, "wordpress_logged_in") {
			return true
		}
		return code >= 300 && code < 400 && strings.Contains(strings.ToLower(loc), "/wp-admin")
	default: // laravel / generic
		// A redirect ALONE is not proof of auth — a failed login often redirects
		// (PRG back to /, captcha, rate-limit page). Require a real session/auth
		// cookie to be set on that redirect, so we don't report a false
		// "default credentials" critical for every app that redirects on failure.
		if code >= 300 && code < 400 && loc != "" {
			ll := strings.ToLower(loc)
			redirectedAway := !strings.Contains(ll, "login") && !strings.Contains(ll, "signin")
			hasSession := strings.Contains(setCookie, "session") || strings.Contains(setCookie, "auth") ||
				strings.Contains(setCookie, "token") || strings.Contains(setCookie, "remember")
			return redirectedAway && hasSession
		}
		return false
	}
}

func (s *LoginScanner) freshCSRF(client *http.Client, t loginTarget) string {
	_, body, err := doHTTP(client, "GET", t.pageURL, nil, nil)
	if err != nil {
		return ""
	}
	if m := reMetaCSRF.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	if _, v := findHidden(body, "_token", "csrf", "authenticity_token"); v != "" {
		return v
	}
	return ""
}

func (s *LoginScanner) frappeCSRF(client *http.Client, t loginTarget) string {
	_, body, err := doHTTP(client, "GET", strings.TrimSuffix(t.postURL, "/api/method/login")+"/login", nil, nil)
	if err != nil {
		return ""
	}
	if m := reFrappeTok.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

func (t loginTarget) csrfFieldOr(def string) string {
	if t.csrfField != "" {
		return t.csrfField
	}
	return def
}

// ---------------------------------------------------------------- helpers

func (s *LoginScanner) newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout:   loginReqTimeout,
		Transport: ScanTransport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func doHTTP(client *http.Client, method, u string, body io.Reader, headers map[string]string) (*http.Response, string, error) {
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, loginBodyCap))
	return resp, string(b), nil
}

func (s *LoginScanner) skipped(check, reason string) models.CheckResult {
	return models.CheckResult{
		Category:  s.Category(),
		CheckName: check,
		Weight:    0, // excluded from scoring when not actually tested
		Status:    "info",
		Score:     0,
		Severity:  "info",
		Details:   toJSON(map[string]string{"state": "skipped", "message": reason}),
	}
}

func activeLoginAllowed(host string) (bool, string) {
	if strings.TrimSpace(os.Getenv("SEKU_ENABLE_ACTIVE_LOGIN_TEST")) != "1" {
		return false, "Active login testing is disabled. Set SEKU_ENABLE_ACTIVE_LOGIN_TEST=1 and allowlist the host to run brute-force / lockout / enumeration checks on systems you are authorized to test."
	}
	allow := strings.TrimSpace(os.Getenv("SEKU_LOGIN_TEST_ALLOWLIST"))
	if allow == "" {
		return false, "No authorized hosts configured. Add the target to SEKU_LOGIN_TEST_ALLOWLIST (comma-separated host globs, e.g. ums.erticaz.com,*.uoturath.edu.iq)."
	}
	host = strings.ToLower(strings.TrimSpace(host))
	for _, pat := range strings.Split(allow, ",") {
		if hostMatch(strings.ToLower(strings.TrimSpace(pat)), host) {
			return true, ""
		}
	}
	return false, "Target host is not in SEKU_LOGIN_TEST_ALLOWLIST — active login testing skipped (authorization required)."
}

func hostMatch(pat, host string) bool {
	if pat == "" {
		return false
	}
	if pat == host {
		return true
	}
	if strings.HasPrefix(pat, "*.") {
		return host == pat[2:] || strings.HasSuffix(host, pat[1:])
	}
	return false
}

func lockoutSignal(body string) bool {
	lb := strings.ToLower(body)
	for _, k := range lockoutKeywords {
		if strings.Contains(lb, k) {
			return true
		}
	}
	return false
}

func significantlyDifferent(a, b string) bool {
	la, lb := len(a), len(b)
	d := la - lb
	if d < 0 {
		d = -d
	}
	max := la
	if lb > max {
		max = lb
	}
	if max == 0 {
		return false
	}
	return d > 200 && float64(d)/float64(max) > 0.1
}

func prioritizeUsers(users []string, t loginTarget) []string {
	pri := []string{"Administrator", "admin", "administrator", "root", "test", "user"}
	if t.host != "" {
		pri = append(pri, "admin@"+t.host)
	}
	seen := map[string]bool{}
	var out []string
	for _, u := range append(pri, users...) {
		u = strings.TrimSpace(u)
		key := strings.ToLower(u)
		if u == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, u)
	}
	return out
}

func loadList(embedded, overridePath string) []string {
	raw := embedded
	if p := strings.TrimSpace(overridePath); p != "" {
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
			raw = string(b) // baked/override list; empty or missing → keep embedded fallback
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimRight(ln, "\r")
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || seen[ln] {
			continue
		}
		seen[ln] = true
		out = append(out, ln)
	}
	return out
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

const hexDigits = "0123456789abcdef"

func randHex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = hexDigits[rand.Intn(len(hexDigits))]
	}
	return string(b)
}
