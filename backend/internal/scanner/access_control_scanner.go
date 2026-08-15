package scanner

// Access Control (IDOR / BOLA) Scanner
// -----------------------------------------------------------------------------
// The single most impactful gap for multi-role portals (e.g. ERPNext student /
// faculty / guardian / admin): broken object-level authorization. This scanner
// runs ONLY when an authenticated session is supplied (Advanced options). It:
//   1. Confirms the session actually authenticates (session A vs anonymous).
//   2. Crawls the app AS session A to discover object URLs (paths with IDs).
//   3. Re-requests each object as a SECOND identity B (or anonymously) and flags
//      cases where the other identity receives the same authorized content —
//      a candidate IDOR/BOLA that a human should confirm.
//
// Findings are reported at moderate confidence with a "verify manually" note,
// because a URL that looks object-specific may legitimately be public/shared.

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"seku/internal/models"
)

type AccessControlScanner struct{}

func NewAccessControlScanner() *AccessControlScanner { return &AccessControlScanner{} }

func (s *AccessControlScanner) Name() string     { return "Access Control (IDOR/BOLA) Scanner" }
func (s *AccessControlScanner) Category() string { return "access_control" }
func (s *AccessControlScanner) Weight() float64  { return 12.0 }

// Scan without config can't test access control (needs a session).
func (s *AccessControlScanner) Scan(rawURL string) []models.CheckResult {
	return []models.CheckResult{s.info("Access Control (IDOR/BOLA)",
		"Provide a session cookie under Advanced options to enable authenticated IDOR/BOLA testing.")}
}

var hrefRe = regexp.MustCompile(`(?i)(?:href|src|action)=["']([^"'#>]+)["']`)
var idPathRe = regexp.MustCompile(`/\d{1,10}(?:/|$|\?)|[?&](?:id|uid|user|account|doc|record|order|invoice|no)=\w`)

func (s *AccessControlScanner) ScanWithConfig(rawURL string, cfg *ScanConfig) []models.CheckResult {
	if !cfg.HasAuth() {
		return []models.CheckResult{s.info("Access Control (IDOR/BOLA)",
			"Provide a session cookie under Advanced options to enable authenticated IDOR/BOLA testing.")}
	}

	base := ensureHTTPS(rawURL)
	baseHost := hostOf(base)
	client := &http.Client{Timeout: 12 * time.Second, Transport: ScanTransport}

	// 1) Confirm the session authenticates: A's homepage should differ from anon.
	aStatus, aBody, _ := s.fetch(client, base, func(r *http.Request) { cfg.applyAuth(r) })
	_, anonBody, _ := s.fetch(client, base, nil)
	if aStatus >= 400 || len(aBody) == 0 {
		return []models.CheckResult{{
			Category: s.Category(), CheckName: "Access Control (IDOR/BOLA)", Weight: 4.0,
			Status: "warn", Score: 700, Severity: "low", Confidence: 60,
			Details: toJSON(map[string]string{"message": "The authenticated request to the homepage failed — check that the session cookie is valid and current, then re-run."}),
		}}
	}
	sessionWorks := similarLen(len(aBody), len(anonBody)) == false // A and anon differ ⇒ auth likely effective

	// 2) Discover object-like URLs as session A (homepage links, capped).
	candidates := s.candidates(base, baseHost, aBody)

	// 3) Differential access check.
	results := []models.CheckResult{}
	tested, flagged := 0, 0
	usingSecondUser := strings.TrimSpace(cfg.AuthCookieB) != ""
	for _, u := range candidates {
		if tested >= 20 || flagged >= 12 {
			break
		}
		tested++
		aS, _, aLen := s.fetch(client, u, func(r *http.Request) { cfg.applyAuth(r) })
		if aS != 200 || aLen < 200 {
			continue // A itself can't meaningfully read it
		}
		bS, bBody, bLen := s.fetch(client, u, func(r *http.Request) { cfg.applyAuthB(r) })
		if bS != 200 || looksLikeLogin(u, bBody) {
			continue // other identity was denied / bounced to login (good)
		}
		if similarLen(aLen, bLen) {
			flagged++
			who := "an anonymous visitor"
			sev := "medium"
			if usingSecondUser {
				who = "a different logged-in user"
			}
			results = append(results, models.CheckResult{
				Category: s.Category(), CheckName: "Possible Broken Access Control: " + acShortPath(u), Weight: 8.0,
				Status: "warn", Score: 300, Severity: sev, Confidence: 60,
				OWASP: "A01:2021 - Broken Access Control",
				Details: toJSON(map[string]string{
					"message": "This object URL returned near-identical authorized content to " + who + ", suggesting missing object-level authorization (IDOR/BOLA). Verify manually that the resource is user-specific and not intentionally public/shared.",
					"url":     u,
					"fix":     "Enforce per-object ownership checks on the server for this endpoint.",
				}),
			})
		}
	}

	// Summary
	summary := models.CheckResult{Category: s.Category(), CheckName: "Access Control (IDOR/BOLA)", Weight: 4.0}
	if len(results) == 0 {
		note := "No obvious broken-access-control candidates found among discovered object URLs."
		if !sessionWorks {
			note += " Note: the authenticated and anonymous homepages looked similar — the session cookie may not be taking effect."
		}
		summary.Status, summary.Score, summary.Severity, summary.Confidence = "pass", 1000, "info", 60
		summary.Details = toJSON(map[string]interface{}{"message": note, "urls_tested": tested})
	} else {
		summary.Status, summary.Score, summary.Severity, summary.Confidence = "warn", 300, "medium", 60
		summary.Details = toJSON(map[string]interface{}{
			"message":       "Found candidate IDOR/BOLA URLs — verify each manually.",
			"candidates":    len(results),
			"urls_tested":   tested,
			"second_user":   usingSecondUser,
		})
	}
	return append([]models.CheckResult{summary}, results...)
}

// fetch performs a GET with an optional request mutator, returning status, body, len.
func (s *AccessControlScanner) fetch(client *http.Client, u string, mut func(*http.Request)) (int, string, int) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, "", 0
	}
	req.Header.Set("User-Agent", "Seku-AccessControl/1.0")
	if mut != nil {
		mut(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", 0
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return resp.StatusCode, string(body), len(body)
}

// candidates extracts same-origin, object-like URLs from a page body (capped).
func (s *AccessControlScanner) candidates(base, baseHost, body string) []string {
	seen := map[string]bool{}
	var out []string
	baseURL, _ := url.Parse(base)
	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "data:") {
			continue
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := baseURL.ResolveReference(ref)
		if abs.Host != baseHost {
			continue
		}
		if !idPathRe.MatchString(abs.Path + "?" + abs.RawQuery) {
			continue
		}
		u := abs.String()
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
		if len(out) >= 20 {
			break
		}
	}
	return out
}

func (s *AccessControlScanner) info(check, msg string) models.CheckResult {
	return models.CheckResult{
		Category: s.Category(), CheckName: check, Weight: 2.0,
		Status: "info", Score: 1000, Severity: "info",
		Details: toJSON(map[string]string{"message": msg, "state": "skipped"}),
	}
}

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return p.Host
}

func acShortPath(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	s := p.Path
	if p.RawQuery != "" {
		s += "?" + p.RawQuery
	}
	if len(s) > 60 {
		s = s[:57] + "..."
	}
	return s
}

// similarLen reports whether two body lengths are within 25% of each other
// (and both non-trivial) — a heuristic that the same content was returned.
func similarLen(a, b int) bool {
	if a < 200 || b < 200 {
		return false
	}
	hi, lo := a, b
	if lo > hi {
		hi, lo = b, a
	}
	return float64(hi-lo) <= float64(hi)*0.25
}

func looksLikeLogin(finalURL, body string) bool {
	lu := strings.ToLower(finalURL)
	if strings.Contains(lu, "login") || strings.Contains(lu, "signin") || strings.Contains(lu, "/auth") {
		return true
	}
	lb := strings.ToLower(body)
	return strings.Contains(lb, `type="password"`) || strings.Contains(lb, "name=\"password\"") || strings.Contains(lb, "name='password'")
}
