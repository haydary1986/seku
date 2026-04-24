package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"seku/internal/models"
)

// WPDeepScanner performs deep WordPress security audits beyond the basic
// WordPressScanner: plugin/theme enumeration with CVE matching, user
// enumeration detection, default-admin username check, security-plugin
// presence, and wp-cron abuse testing.
//
// 80%+ of real-world WordPress compromises happen through vulnerable
// plugins or themes (not core), so this scanner is the highest-ROI
// addition for university sites.
type WPDeepScanner struct{}

func NewWPDeepScanner() *WPDeepScanner {
	return &WPDeepScanner{}
}

func (s *WPDeepScanner) Name() string     { return "WordPress Deep Security Scanner" }
func (s *WPDeepScanner) Category() string { return "wp_deep" }
func (s *WPDeepScanner) Weight() float64  { return 18.0 }

// pluginCVE describes a known vulnerability in a specific plugin.
// maxAffected uses semver: any version <= maxAffected is vulnerable.
type pluginCVE struct {
	id          string
	cvss        float64
	severity    string
	title       string
	maxAffected string
}

// Curated plugin CVE database — focused on plugins commonly found on
// Iraqi university sites and CVEs with high impact (RCE, auth bypass,
// SQLi). Last reviewed 2025-Q4.
var pluginCVEs = map[string][]pluginCVE{
	"elementor": {
		{"CVE-2023-48777", 9.9, "critical", "Elementor authenticated arbitrary file upload to RCE", "3.18.1"},
		{"CVE-2024-2117", 8.8, "high", "Elementor stored XSS via upload widget", "3.20.1"},
	},
	"elementor-pro": {
		{"CVE-2023-3746", 8.8, "high", "Elementor Pro broken access control", "3.11.6"},
	},
	"woocommerce": {
		{"CVE-2023-28121", 9.8, "critical", "WooCommerce Payments unauth admin access", "5.6.1"},
		{"CVE-2024-37251", 8.5, "high", "WooCommerce SQL injection in order list", "8.9.2"},
	},
	"contact-form-7": {
		{"CVE-2020-35489", 9.8, "critical", "CF7 unrestricted file upload to RCE", "5.3.1"},
	},
	"yoast-seo": {
		{"CVE-2023-40680", 6.4, "medium", "Yoast SEO authenticated stored XSS", "21.0"},
	},
	"wpforms-lite": {
		{"CVE-2024-9168", 8.5, "high", "WPForms Lite SQL injection", "1.8.9.4"},
	},
	"wp-super-cache": {
		{"CVE-2021-24209", 8.8, "high", "WP Super Cache authenticated RCE", "1.7.2"},
	},
	"all-in-one-wp-migration": {
		{"CVE-2023-40004", 7.5, "high", "AIWPM authentication bypass on import", "7.78"},
	},
	"jetpack": {
		{"CVE-2024-10916", 7.5, "high", "Jetpack contact form data leak", "13.9.1"},
	},
	"wpvivid-backuprestore": {
		{"CVE-2022-3590", 9.8, "critical", "WPvivid arbitrary file upload", "0.9.83"},
	},
	"litespeed-cache": {
		{"CVE-2024-44000", 9.8, "critical", "LiteSpeed Cache unauth account takeover via debug log", "6.5.0.1"},
	},
	"backup-migration": {
		{"CVE-2023-6553", 9.8, "critical", "Backup Migration unauth RCE", "1.3.7"},
	},
	"essential-addons-for-elementor-lite": {
		{"CVE-2023-32243", 9.8, "critical", "Essential Addons unauth password reset", "5.7.1"},
	},
	"forminator": {
		{"CVE-2024-28890", 9.8, "critical", "Forminator unauth arbitrary file upload", "1.29.0"},
	},
	"better-search-replace": {
		{"CVE-2023-6933", 8.8, "high", "Better Search Replace PHP object injection", "1.4.4"},
	},
	"wp-file-manager": {
		{"CVE-2020-25213", 9.8, "critical", "WP File Manager unauth RCE (mass exploited)", "6.8"},
	},
	"file-manager-advanced": {
		{"CVE-2021-25001", 8.8, "high", "File Manager Advanced authenticated RCE", "4.5"},
	},
	"duplicator": {
		{"CVE-2023-6114", 8.5, "high", "Duplicator authenticated arbitrary file deletion", "1.5.7.1"},
	},
	"updraftplus": {
		{"CVE-2022-0633", 8.5, "high", "UpdraftPlus arbitrary backup download", "1.22.3"},
	},
	"loginizer": {
		{"CVE-2020-27615", 9.8, "critical", "Loginizer SQL injection", "1.6.3"},
	},
	"wp-statistics": {
		{"CVE-2022-4230", 8.0, "high", "WP Statistics blind SQL injection", "13.2.10"},
	},
	"smart-slider-3": {
		{"CVE-2023-26326", 7.5, "high", "Smart Slider 3 sensitive data exposure", "3.5.1.18"},
	},
	"revslider": {
		{"CVE-2014-9734", 9.8, "critical", "RevSlider arbitrary file upload (legendary)", "4.1.4"},
	},
	"ninja-forms": {
		{"CVE-2023-37979", 7.5, "high", "Ninja Forms reflected XSS to admin takeover", "3.6.25"},
	},
	"social-warfare": {
		{"CVE-2019-9978", 9.8, "critical", "Social Warfare unauth RCE (mass exploited)", "3.5.2"},
	},
}

// themeCVEs - common WordPress themes with known issues.
var themeCVEs = map[string][]pluginCVE{
	"newspaper": {
		{"CVE-2016-10972", 9.8, "critical", "Newspaper theme unauthenticated arbitrary file upload", "6.7.1"},
	},
	"avada": {
		{"CVE-2023-1916", 8.8, "high", "Avada theme authenticated arbitrary file upload", "7.11.4"},
	},
	"divi": {
		{"CVE-2023-30490", 7.5, "high", "Divi/Extra/Bloom auth bypass", "4.20.0"},
	},
}

func (s *WPDeepScanner) newClient() *http.Client {
	return &http.Client{
		Timeout:   12 * time.Second,
		Transport: ScanTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

func (s *WPDeepScanner) Scan(url string) []models.CheckResult {
	client := s.newClient()
	baseURL := strings.TrimRight(ensureHTTPS(url), "/")

	homeBody := s.fetchBody(client, baseURL)
	if homeBody == "" {
		return []models.CheckResult{}
	}

	// Confirm WordPress before running deep checks
	if !s.isWordPress(client, baseURL, homeBody) {
		return []models.CheckResult{
			{
				Category:   s.Category(),
				CheckName:  "WordPress Detection",
				Status:     "pass",
				Score:      1000,
				Weight:     s.Weight(),
				Severity:   "info",
				Confidence: 80,
				Details:    "Site does not appear to be WordPress. Deep scan skipped.",
			},
		}
	}

	results := []models.CheckResult{}

	// Run all deep checks in parallel
	var wg sync.WaitGroup
	resultsCh := make(chan models.CheckResult, 8)

	wg.Add(7)
	go func() { defer wg.Done(); resultsCh <- s.checkPlugins(client, baseURL, homeBody) }()
	go func() { defer wg.Done(); resultsCh <- s.checkThemes(client, baseURL, homeBody) }()
	go func() { defer wg.Done(); resultsCh <- s.checkUserEnumeration(client, baseURL) }()
	go func() { defer wg.Done(); resultsCh <- s.checkDefaultAdminUsername(client, baseURL) }()
	go func() { defer wg.Done(); resultsCh <- s.checkSecurityPlugin(client, baseURL, homeBody) }()
	go func() { defer wg.Done(); resultsCh <- s.checkWPCronAbuse(client, baseURL) }()
	go func() { defer wg.Done(); resultsCh <- s.checkLicenseLeaks(client, baseURL) }()

	wg.Wait()
	close(resultsCh)

	for r := range resultsCh {
		results = append(results, r)
	}
	return results
}

// === Detection helpers ===

func (s *WPDeepScanner) isWordPress(client *http.Client, baseURL, body string) bool {
	low := strings.ToLower(body)
	if strings.Contains(low, "/wp-content/") || strings.Contains(low, "/wp-includes/") {
		return true
	}
	loginBody := s.fetchBody(client, baseURL+"/wp-login.php")
	return strings.Contains(strings.ToLower(loginBody), "wordpress")
}

func (s *WPDeepScanner) fetchBody(client *http.Client, fetchURL string) string {
	req, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return string(body)
}

// === Check 1: Plugin enumeration + CVE matching ===

var pluginPathRe = regexp.MustCompile(`/wp-content/plugins/([a-z0-9\-_]+)`)

func (s *WPDeepScanner) checkPlugins(client *http.Client, baseURL, homeBody string) models.CheckResult {
	// Step 1: Discover plugin slugs from page source
	matches := pluginPathRe.FindAllStringSubmatch(homeBody, -1)
	plugins := map[string]bool{}
	for _, m := range matches {
		if len(m) >= 2 {
			plugins[m[1]] = true
		}
	}

	if len(plugins) == 0 {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  "Plugin Enumeration & CVE Matching",
			Status:     "pass",
			Score:      950,
			Weight:     s.Weight(),
			Severity:   "info",
			Confidence: 70,
			Details:    "No plugins detected from home page source. Plugins may be loaded conditionally or hidden.",
		}
	}

	// Step 2: For each plugin, fetch readme.txt to detect version
	type pluginInfo struct {
		slug    string
		version string
		cves    []pluginCVE
	}

	var detected []pluginInfo
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for slug := range plugins {
		wg.Add(1)
		sem <- struct{}{}
		go func(slug string) {
			defer wg.Done()
			defer func() { <-sem }()

			version := s.fetchPluginVersion(client, baseURL, slug)
			info := pluginInfo{slug: slug, version: version}

			if cves, ok := pluginCVEs[slug]; ok && version != "" {
				for _, cve := range cves {
					if compareVersions(version, cve.maxAffected) <= 0 {
						info.cves = append(info.cves, cve)
					}
				}
			}

			mu.Lock()
			detected = append(detected, info)
			mu.Unlock()
		}(slug)
	}
	wg.Wait()

	// Step 3: Build report
	totalCVEs := 0
	worstSev := "low"
	worstCVSS := 0.0
	var details strings.Builder
	details.WriteString(fmt.Sprintf("Detected %d plugins on this WordPress site:\n\n", len(detected)))

	for _, p := range detected {
		ver := p.version
		if ver == "" {
			ver = "unknown"
		}
		details.WriteString(fmt.Sprintf("📦 %s (v%s)", p.slug, ver))
		if len(p.cves) == 0 {
			details.WriteString("  ✅ no known CVEs\n")
			continue
		}
		details.WriteString(fmt.Sprintf("  ⚠️  %d known CVE(s):\n", len(p.cves)))
		for _, cve := range p.cves {
			details.WriteString(fmt.Sprintf("     • %s (CVSS %.1f, %s) — %s [fixed in > %s]\n",
				cve.id, cve.cvss, strings.ToUpper(cve.severity), cve.title, cve.maxAffected))
			totalCVEs++
			if cve.cvss > worstCVSS {
				worstCVSS = cve.cvss
			}
			if severityRank(cve.severity) > severityRank(worstSev) {
				worstSev = cve.severity
			}
		}
		details.WriteString("\n")
	}

	if totalCVEs == 0 {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  fmt.Sprintf("Plugin Enumeration (%d plugins, 0 known CVEs)", len(detected)),
			Status:     "pass",
			Score:      900,
			Weight:     s.Weight(),
			Severity:   "info",
			Confidence: 80,
			Details:    details.String() + "\nAction: keep monitoring vendor advisories. Consider hiding plugin paths via security plugin.",
		}
	}

	score := 1000.0
	switch worstSev {
	case "critical":
		score = 0
	case "high":
		score = 150
	case "medium":
		score = 450
	case "low":
		score = 700
	}
	details.WriteString(fmt.Sprintf("\nAction: update affected plugins to latest version IMMEDIATELY. %d critical/high CVEs found.\n", totalCVEs))

	return models.CheckResult{
		Category:   s.Category(),
		CheckName:  fmt.Sprintf("Plugin CVEs (%d plugins, %d vulnerabilities)", len(detected), totalCVEs),
		Status:     statusFromSeverity(worstSev),
		Score:      score,
		Weight:     s.Weight(),
		Severity:   worstSev,
		CWE:        "CWE-1395",
		CWEName:    "Dependency on Vulnerable Third-Party Component",
		OWASP:      "A06",
		OWASPName:  "Vulnerable and Outdated Components",
		Confidence: 85,
		CVSSScore:  worstCVSS,
		Details:    details.String(),
	}
}

var pluginVersionRe = regexp.MustCompile(`(?i)stable\s+tag:\s*([\d.]+)`)
var pluginVersionAltRe = regexp.MustCompile(`(?i)version:\s*([\d.]+)`)

func (s *WPDeepScanner) fetchPluginVersion(client *http.Client, baseURL, slug string) string {
	// Try readme.txt (most common)
	body := s.fetchBody(client, baseURL+"/wp-content/plugins/"+slug+"/readme.txt")
	if body != "" {
		if m := pluginVersionRe.FindStringSubmatch(body); len(m) >= 2 {
			return m[1]
		}
		if m := pluginVersionAltRe.FindStringSubmatch(body); len(m) >= 2 {
			return m[1]
		}
	}
	// Try plugin main PHP file with same name
	body = s.fetchBody(client, baseURL+"/wp-content/plugins/"+slug+"/"+slug+".php")
	if body != "" {
		if m := pluginVersionAltRe.FindStringSubmatch(body); len(m) >= 2 {
			return m[1]
		}
	}
	return ""
}

// === Check 2: Theme enumeration + CVE matching ===

var themePathRe = regexp.MustCompile(`/wp-content/themes/([a-z0-9\-_]+)`)

func (s *WPDeepScanner) checkThemes(client *http.Client, baseURL, homeBody string) models.CheckResult {
	matches := themePathRe.FindAllStringSubmatch(homeBody, -1)
	themes := map[string]bool{}
	for _, m := range matches {
		if len(m) >= 2 {
			themes[m[1]] = true
		}
	}

	if len(themes) == 0 {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  "Theme Enumeration",
			Status:     "pass",
			Score:      900,
			Weight:     s.Weight(),
			Severity:   "info",
			Confidence: 60,
			Details:    "No themes detected from home page source.",
		}
	}

	type themeInfo struct {
		slug    string
		version string
		cves    []pluginCVE
	}

	var detected []themeInfo
	for slug := range themes {
		version := s.fetchThemeVersion(client, baseURL, slug)
		info := themeInfo{slug: slug, version: version}
		if cves, ok := themeCVEs[slug]; ok && version != "" {
			for _, cve := range cves {
				if compareVersions(version, cve.maxAffected) <= 0 {
					info.cves = append(info.cves, cve)
				}
			}
		}
		detected = append(detected, info)
	}

	totalCVEs := 0
	worstSev := "low"
	worstCVSS := 0.0
	var details strings.Builder
	details.WriteString(fmt.Sprintf("Detected %d theme(s):\n\n", len(detected)))

	for _, t := range detected {
		ver := t.version
		if ver == "" {
			ver = "unknown"
		}
		details.WriteString(fmt.Sprintf("🎨 %s (v%s)", t.slug, ver))
		if len(t.cves) == 0 {
			details.WriteString("  ✅\n")
			continue
		}
		details.WriteString(fmt.Sprintf("  ⚠️  %d CVE(s):\n", len(t.cves)))
		for _, cve := range t.cves {
			details.WriteString(fmt.Sprintf("     • %s (CVSS %.1f) — %s\n", cve.id, cve.cvss, cve.title))
			totalCVEs++
			if cve.cvss > worstCVSS {
				worstCVSS = cve.cvss
			}
			if severityRank(cve.severity) > severityRank(worstSev) {
				worstSev = cve.severity
			}
		}
	}

	if totalCVEs == 0 {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  fmt.Sprintf("Theme Enumeration (%d themes, 0 CVEs)", len(detected)),
			Status:     "pass",
			Score:      900,
			Weight:     s.Weight(),
			Severity:   "info",
			Confidence: 80,
			Details:    details.String(),
		}
	}

	score := 1000.0
	switch worstSev {
	case "critical":
		score = 50
	case "high":
		score = 200
	case "medium":
		score = 500
	}

	return models.CheckResult{
		Category:   s.Category(),
		CheckName:  fmt.Sprintf("Theme CVEs (%d themes, %d vulnerabilities)", len(detected), totalCVEs),
		Status:     statusFromSeverity(worstSev),
		Score:      score,
		Weight:     s.Weight(),
		Severity:   worstSev,
		CWE:        "CWE-1395",
		OWASP:      "A06",
		OWASPName:  "Vulnerable and Outdated Components",
		Confidence: 85,
		CVSSScore:  worstCVSS,
		Details:    details.String(),
	}
}

func (s *WPDeepScanner) fetchThemeVersion(client *http.Client, baseURL, slug string) string {
	body := s.fetchBody(client, baseURL+"/wp-content/themes/"+slug+"/style.css")
	if body == "" {
		return ""
	}
	if m := pluginVersionAltRe.FindStringSubmatch(body); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// === Check 3: User enumeration ===

func (s *WPDeepScanner) checkUserEnumeration(client *http.Client, baseURL string) models.CheckResult {
	exposedVia := []string{}

	// Method A: ?author=N redirect leak
	for i := 1; i <= 3; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/?author=%d", baseURL, i), nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "/author/") {
			exposedVia = append(exposedVia, fmt.Sprintf("?author=%d → %s", i, loc))
		}
	}

	// Method B: REST API users endpoint
	body := s.fetchBody(client, baseURL+"/wp-json/wp/v2/users")
	var users []map[string]interface{}
	if err := json.Unmarshal([]byte(body), &users); err == nil && len(users) > 0 {
		exposedVia = append(exposedVia, fmt.Sprintf("/wp-json/wp/v2/users → %d users disclosed", len(users)))
	}

	if len(exposedVia) == 0 {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  "User Enumeration Protection",
			Status:     "pass",
			Score:      1000,
			Weight:     s.Weight(),
			Severity:   "info",
			Confidence: 90,
			Details:    "Username enumeration is blocked. Both ?author=N and /wp-json/wp/v2/users do not disclose usernames.",
		}
	}

	return models.CheckResult{
		Category:   s.Category(),
		CheckName:  "User Enumeration Possible",
		Status:     "fail",
		Score:      300,
		Weight:     s.Weight(),
		Severity:   "high",
		CWE:        "CWE-200",
		CWEName:    "Information Exposure",
		OWASP:      "A01",
		OWASPName:  "Broken Access Control",
		Confidence: 95,
		CVSSScore:  7.5,
		Details: fmt.Sprintf("Username enumeration is possible via:\n\n%s\n\nAttackers can harvest usernames then perform targeted brute-force attacks against /wp-login.php. Mitigation: install Wordfence or use plugin to block ?author= queries and disable /wp-json/wp/v2/users for unauthenticated requests.",
			strings.Join(exposedVia, "\n")),
	}
}

// === Check 4: Default admin username ===

func (s *WPDeepScanner) checkDefaultAdminUsername(client *http.Client, baseURL string) models.CheckResult {
	// Try ?author=1 to see if user #1 is "admin"
	req, _ := http.NewRequest("GET", baseURL+"/?author=1", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  "Default Admin Username Check",
			Status:     "pass",
			Score:      900,
			Weight:     s.Weight(),
			Severity:   "info",
			Confidence: 50,
			Details:    "Could not determine — site may block enumeration (good).",
		}
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	username := ""
	if idx := strings.Index(loc, "/author/"); idx != -1 {
		rest := loc[idx+len("/author/"):]
		if slash := strings.Index(rest, "/"); slash != -1 {
			username = rest[:slash]
		} else {
			username = rest
		}
	}

	// Also try REST API
	if username == "" {
		body := s.fetchBody(client, baseURL+"/wp-json/wp/v2/users/1")
		var u map[string]interface{}
		if err := json.Unmarshal([]byte(body), &u); err == nil {
			if slug, ok := u["slug"].(string); ok {
				username = slug
			}
		}
	}

	if username == "" {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  "Default Admin Username Check",
			Status:     "pass",
			Score:      950,
			Weight:     s.Weight(),
			Severity:   "info",
			Confidence: 60,
			Details:    "User #1 username could not be determined.",
		}
	}

	weak := []string{"admin", "administrator", "root", "user", "test", "demo", "wpadmin", "webmaster"}
	for _, w := range weak {
		if strings.EqualFold(username, w) {
			return models.CheckResult{
				Category:   s.Category(),
				CheckName:  fmt.Sprintf("Weak Admin Username: '%s'", username),
				Status:     "fail",
				Score:      200,
				Weight:     s.Weight(),
				Severity:   "high",
				CWE:        "CWE-521",
				CWEName:    "Weak Password Requirements",
				OWASP:      "A07",
				OWASPName:  "Identification and Authentication Failures",
				Confidence: 95,
				CVSSScore:  7.5,
				Details:    fmt.Sprintf("The administrator username is '%s' — one of the most commonly brute-forced credentials. Combined with username enumeration, this drastically lowers the cost of a credential-stuffing attack.\n\nMitigation: create a new admin user with an obscure username, then delete '%s'.", username, username),
			}
		}
	}

	return models.CheckResult{
		Category:   s.Category(),
		CheckName:  fmt.Sprintf("Admin Username Strength ('%s')", username),
		Status:     "pass",
		Score:      1000,
		Weight:     s.Weight(),
		Severity:   "info",
		Confidence: 90,
		Details:    fmt.Sprintf("Admin username '%s' is not one of the common weak defaults.", username),
	}
}

// === Check 5: Security plugin presence ===

func (s *WPDeepScanner) checkSecurityPlugin(client *http.Client, baseURL, homeBody string) models.CheckResult {
	securityPlugins := map[string]string{
		"wordfence":                      "Wordfence Security",
		"better-wp-security":             "iThemes Security (legacy)",
		"ithemes-security-pro":           "iThemes Security Pro",
		"sucuri-scanner":                 "Sucuri Scanner",
		"all-in-one-wp-security-and-firewall": "All In One WP Security",
		"wp-cerber":                      "WP Cerber Security",
		"shield-security":                "Shield Security",
		"defender-security":              "WP Defender",
	}

	found := []string{}
	for slug, name := range securityPlugins {
		if strings.Contains(homeBody, "/wp-content/plugins/"+slug+"/") {
			found = append(found, name)
		}
	}

	// Header-based detection (Wordfence sets X-Powered-By sometimes)
	resp, err := client.Get(baseURL)
	if err == nil {
		defer resp.Body.Close()
		if strings.Contains(strings.ToLower(resp.Header.Get("X-Powered-By")), "wordfence") {
			found = append(found, "Wordfence (header)")
		}
	}

	if len(found) > 0 {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  fmt.Sprintf("Security Plugin Detected (%s)", strings.Join(found, ", ")),
			Status:     "pass",
			Score:      1000,
			Weight:     s.Weight(),
			Severity:   "info",
			Confidence: 90,
			Details:    fmt.Sprintf("Detected security plugin(s): %s.\n\nThis significantly reduces attack surface (login lockout, malware scanning, file integrity monitoring).", strings.Join(found, ", ")),
		}
	}

	return models.CheckResult{
		Category:   s.Category(),
		CheckName:  "No Security Plugin Detected",
		Status:     "warn",
		Score:      400,
		Weight:     s.Weight(),
		Severity:   "medium",
		CWE:        "CWE-1188",
		CWEName:    "Insecure Default Initialization of Resource",
		OWASP:      "A05",
		OWASPName:  "Security Misconfiguration",
		Confidence: 70,
		CVSSScore:  5.3,
		Details:    "No major WordPress security plugin detected (Wordfence, iThemes, Sucuri, AIOWPS, WP Cerber, Shield, Defender).\n\nA security plugin provides essential protections: login brute-force lockout, malware scanning, file integrity monitoring, two-factor auth, and IP blocking. Strong recommendation: install Wordfence (free) at minimum.",
	}
}

// === Check 6: wp-cron.php abuse ===

func (s *WPDeepScanner) checkWPCronAbuse(client *http.Client, baseURL string) models.CheckResult {
	start := time.Now()
	req, _ := http.NewRequest("GET", baseURL+"/wp-cron.php", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  "wp-cron.php Accessibility",
			Status:     "pass",
			Score:      1000,
			Weight:     s.Weight(),
			Severity:   "info",
			Confidence: 60,
			Details:    "wp-cron.php is unreachable or blocked (good).",
		}
	}
	resp.Body.Close()
	elapsed := time.Since(start)

	// If accessible AND slow → DoS amplification risk
	if resp.StatusCode == 200 && elapsed > 2*time.Second {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  "wp-cron.php DoS Amplification Risk",
			Status:     "warn",
			Score:      400,
			Weight:     s.Weight(),
			Severity:   "medium",
			CWE:        "CWE-400",
			CWEName:    "Uncontrolled Resource Consumption",
			OWASP:      "A05",
			OWASPName:  "Security Misconfiguration",
			Confidence: 75,
			CVSSScore:  5.3,
			Details:    fmt.Sprintf("wp-cron.php is publicly accessible and took %.1fs to respond. Attackers can flood this endpoint to overload the server (DoS amplification).\n\nMitigation: disable web-trigger cron and use system cron instead:\n1. Add to wp-config.php: define('DISABLE_WP_CRON', true);\n2. Add system cron: */15 * * * * wget -q -O - https://example.com/wp-cron.php?doing_wp_cron > /dev/null 2>&1", elapsed.Seconds()),
		}
	}

	if resp.StatusCode == 200 {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  "wp-cron.php Accessible (low risk)",
			Status:     "pass",
			Score:      900,
			Weight:     s.Weight(),
			Severity:   "info",
			Confidence: 70,
			Details:    fmt.Sprintf("wp-cron.php is publicly accessible but responds quickly (%.2fs). For high-traffic sites, consider disabling web-trigger cron.", elapsed.Seconds()),
		}
	}

	return models.CheckResult{
		Category:   s.Category(),
		CheckName:  "wp-cron.php Protected",
		Status:     "pass",
		Score:      1000,
		Weight:     s.Weight(),
		Severity:   "info",
		Confidence: 85,
		Details:    fmt.Sprintf("wp-cron.php returned HTTP %d — not publicly accessible.", resp.StatusCode),
	}
}

// === Check 7: License/readme/install file leaks ===

func (s *WPDeepScanner) checkLicenseLeaks(client *http.Client, baseURL string) models.CheckResult {
	leaks := []struct {
		path  string
		label string
	}{
		{"/license.txt", "WordPress license.txt"},
		{"/wp-admin/install-helper.php", "Install helper script"},
		{"/wp-admin/upgrade.php", "Upgrade script"},
		{"/wp-content/uploads/", "Uploads directory listing"},
	}

	exposed := []string{}
	for _, l := range leaks {
		req, _ := http.NewRequest("HEAD", baseURL+l.path, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			exposed = append(exposed, fmt.Sprintf("%s (%s)", l.label, l.path))
		}
	}

	if len(exposed) == 0 {
		return models.CheckResult{
			Category:   s.Category(),
			CheckName:  "WordPress Sensitive Files",
			Status:     "pass",
			Score:      1000,
			Weight:     s.Weight(),
			Severity:   "info",
			Confidence: 90,
			Details:    "No leaked WP installation/upgrade/license files exposed.",
		}
	}

	return models.CheckResult{
		Category:   s.Category(),
		CheckName:  fmt.Sprintf("WP Sensitive Files Exposed (%d)", len(exposed)),
		Status:     "warn",
		Score:      600,
		Weight:     s.Weight(),
		Severity:   "low",
		CWE:        "CWE-200",
		CWEName:    "Information Exposure",
		OWASP:      "A05",
		OWASPName:  "Security Misconfiguration",
		Confidence: 90,
		CVSSScore:  3.7,
		Details:    "Exposed:\n• " + strings.Join(exposed, "\n• ") + "\n\nThese files leak version info or directory contents. Block via .htaccess or nginx rules.",
	}
}

// We need strconv import for unused checks — keep here in case of expansion.
var _ = strconv.Atoi
