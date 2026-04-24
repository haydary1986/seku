package scanner

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"seku/internal/models"
)

// CMSCVEScanner detects the CMS in use (WordPress, Joomla, Drupal, Moodle,
// phpBB) and its version, then matches against a curated list of known
// critical CVEs. This is offline matching — no live CVE feed call.
type CMSCVEScanner struct{}

func NewCMSCVEScanner() *CMSCVEScanner {
	return &CMSCVEScanner{}
}

func (s *CMSCVEScanner) Name() string     { return "CMS Version & CVE Matching Scanner" }
func (s *CMSCVEScanner) Category() string { return "cms_cve" }
func (s *CMSCVEScanner) Weight() float64  { return 14.0 }

// CVE entry. Affects describes the version range as "<X.Y.Z" or "X.Y.Z - A.B.C".
type knownCVE struct {
	id          string
	cvss        float64
	severity    string
	title       string
	maxAffected string // any version <= this is vulnerable (semver-style compare)
}

// Curated CVE list — focused on critical/high impact unauthenticated RCE
// or auth bypass vulnerabilities for the most common CMSes used by
// Iraqi universities. Last reviewed: 2025-Q4.
var cmsCVEs = map[string][]knownCVE{
	"wordpress": {
		{"CVE-2022-21661", 7.5, "high", "WP Core SQL injection via WP_Query", "5.8.2"},
		{"CVE-2022-21663", 8.0, "high", "WP Core authenticated RCE via PHPMailer", "5.8.2"},
		{"CVE-2023-2745", 5.4, "medium", "WP Core directory traversal", "6.2.0"},
		{"CVE-2023-39999", 6.1, "medium", "WP Core stored XSS", "6.3.1"},
		{"CVE-2024-31210", 8.8, "high", "WP Core privilege escalation", "6.5.1"},
		{"CVE-2024-4439", 6.4, "medium", "WP Core stored XSS in Avatar block", "6.5.2"},
		{"CVE-2024-32111", 5.4, "medium", "WP Core CSRF in template", "6.5.0"},
	},
	"joomla": {
		{"CVE-2023-23752", 5.3, "medium", "Joomla improper access control to webservice endpoints", "4.2.7"},
		{"CVE-2023-40626", 8.8, "high", "Joomla unauthorized command execution", "4.4.0"},
		{"CVE-2024-21726", 5.4, "medium", "Joomla stored XSS in MediaField", "5.0.2"},
		{"CVE-2024-21725", 8.8, "high", "Joomla unauthorized RCE via mail address escaping", "5.0.2"},
	},
	"drupal": {
		{"CVE-2018-7600", 9.8, "critical", "Drupalgeddon2: unauthenticated RCE", "8.5.1"},
		{"CVE-2019-6340", 8.1, "high", "Drupal RESTful Web Services unsafe deserialization", "8.6.10"},
		{"CVE-2020-13671", 9.8, "critical", "Drupal arbitrary PHP code execution via uploaded files", "9.0.7"},
		{"CVE-2022-25277", 8.0, "high", "Drupal arbitrary file upload bypass", "9.4.5"},
	},
	"moodle": {
		{"CVE-2020-25627", 7.5, "high", "Moodle unauthenticated SSRF", "3.9.3"},
		{"CVE-2021-36391", 8.8, "high", "Moodle SQL injection in calendar", "3.11.2"},
		{"CVE-2023-30533", 8.8, "high", "Moodle SheetJS prototype pollution", "4.1.2"},
		{"CVE-2024-25985", 7.5, "high", "Moodle authenticated SSRF in URL filter", "4.3.2"},
	},
	"phpbb": {
		{"CVE-2021-27918", 9.8, "critical", "phpBB unauthenticated RCE via avatar upload", "3.3.3"},
		{"CVE-2023-32684", 8.8, "high", "phpBB authenticated stored XSS", "3.3.10"},
	},
}

func (s *CMSCVEScanner) newClient() *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: ScanTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

func (s *CMSCVEScanner) Scan(url string) []models.CheckResult {
	client := s.newClient()
	baseURL := strings.TrimRight(ensureHTTPS(url), "/")

	cms, version := s.detectCMS(client, baseURL)

	if cms == "" {
		return []models.CheckResult{
			{
				Category:   s.Category(),
				CheckName:  "CMS Detection",
				Status:     "pass",
				Score:      1000,
				Weight:     s.Weight(),
				Severity:   "info",
				Confidence: 75,
				Details:    "No common CMS detected (WordPress, Joomla, Drupal, Moodle, phpBB). This is informational only.",
			},
		}
	}

	if version == "" {
		return []models.CheckResult{
			{
				Category:   s.Category(),
				CheckName:  fmt.Sprintf("%s Detected (version unknown)", strings.Title(cms)),
				Status:     "warn",
				Score:      700,
				Weight:     s.Weight(),
				Severity:   "low",
				CWE:        "CWE-200",
				CWEName:    "Information Exposure",
				OWASP:      "A05",
				OWASPName:  "Security Misconfiguration",
				Confidence: 80,
				Details:    fmt.Sprintf("%s installation detected, but version could not be determined. Hide version strings to reduce attack surface.", strings.Title(cms)),
			},
		}
	}

	// Match against known CVEs
	matches := s.matchCVEs(cms, version)

	if len(matches) == 0 {
		return []models.CheckResult{
			{
				Category:   s.Category(),
				CheckName:  fmt.Sprintf("%s %s — Known CVEs", strings.Title(cms), version),
				Status:     "pass",
				Score:      950,
				Weight:     s.Weight(),
				Severity:   "info",
				Confidence: 85,
				Details:    fmt.Sprintf("%s version %s detected. No known critical CVEs match this version in the curated database. Note: this scanner only checks a subset of well-known vulnerabilities — keep monitoring vendor advisories.", strings.Title(cms), version),
			},
		}
	}

	// Build vulnerability report
	var details strings.Builder
	details.WriteString(fmt.Sprintf("%s version %s is affected by %d known CVEs:\n\n", strings.Title(cms), version, len(matches)))

	worstCVSS := 0.0
	worstSev := "low"
	for _, m := range matches {
		details.WriteString(fmt.Sprintf("• %s (CVSS %.1f, %s) — %s\n   Fixed in version > %s\n", m.id, m.cvss, strings.ToUpper(m.severity), m.title, m.maxAffected))
		if m.cvss > worstCVSS {
			worstCVSS = m.cvss
		}
		if severityRank(m.severity) > severityRank(worstSev) {
			worstSev = m.severity
		}
	}
	details.WriteString(fmt.Sprintf("\nUpgrade %s to the latest stable version to remediate.", strings.Title(cms)))

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

	return []models.CheckResult{
		{
			Category:   s.Category(),
			CheckName:  fmt.Sprintf("%s %s — %d Known CVEs", strings.Title(cms), version, len(matches)),
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
		},
	}
}

// detectCMS returns the CMS name (lowercase) and detected version, or empty strings if unknown.
func (s *CMSCVEScanner) detectCMS(client *http.Client, baseURL string) (string, string) {
	homeBody, homeHeaders := s.fetch(client, baseURL)

	// === WordPress ===
	if v := s.detectWordPress(client, baseURL, homeBody); v != "" {
		return "wordpress", v
	}
	// Generator meta tag is the most reliable
	if cms, version := s.parseGeneratorMeta(homeBody); cms != "" {
		return cms, version
	}

	// === Joomla ===
	if v := s.detectJoomla(client, baseURL, homeBody); v != "" {
		return "joomla", v
	}

	// === Drupal ===
	if v := s.detectDrupal(client, baseURL, homeBody, homeHeaders); v != "" {
		return "drupal", v
	}

	// === Moodle ===
	if v := s.detectMoodle(client, baseURL, homeBody); v != "" {
		return "moodle", v
	}

	// === phpBB ===
	if v := s.detectPHPBB(client, baseURL, homeBody); v != "" {
		return "phpbb", v
	}

	return "", ""
}

func (s *CMSCVEScanner) fetch(client *http.Client, url string) (string, http.Header) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(body), resp.Header
}

var generatorRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)

// parseGeneratorMeta returns (cms, version) from <meta name="generator">.
func (s *CMSCVEScanner) parseGeneratorMeta(body string) (string, string) {
	m := generatorRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return "", ""
	}
	val := strings.ToLower(m[1])
	versionRe := regexp.MustCompile(`(\d+(?:\.\d+){1,3})`)

	switch {
	case strings.Contains(val, "wordpress"):
		v := versionRe.FindString(val)
		return "wordpress", v
	case strings.Contains(val, "joomla"):
		v := versionRe.FindString(val)
		return "joomla", v
	case strings.Contains(val, "drupal"):
		v := versionRe.FindString(val)
		return "drupal", v
	case strings.Contains(val, "moodle"):
		v := versionRe.FindString(val)
		return "moodle", v
	case strings.Contains(val, "phpbb"):
		v := versionRe.FindString(val)
		return "phpbb", v
	}
	return "", ""
}

func (s *CMSCVEScanner) detectWordPress(client *http.Client, baseURL, body string) string {
	if !strings.Contains(strings.ToLower(body), "/wp-content/") &&
		!strings.Contains(strings.ToLower(body), "/wp-includes/") {
		// Try fetching wp-login.php
		loginBody, _ := s.fetch(client, baseURL+"/wp-login.php")
		if !strings.Contains(strings.ToLower(loginBody), "wordpress") {
			return ""
		}
		body = loginBody
	}

	// Try readme.html (often readable on default installs)
	readmeBody, _ := s.fetch(client, baseURL+"/readme.html")
	versionRe := regexp.MustCompile(`(?i)version\s+(\d+\.\d+(?:\.\d+)?)`)
	if m := versionRe.FindStringSubmatch(readmeBody); len(m) >= 2 {
		return m[1]
	}

	// Try generator meta
	if m := generatorRe.FindStringSubmatch(body); len(m) >= 2 {
		v := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`).FindString(m[1])
		if v != "" {
			return v
		}
	}

	// Try feed (RSS includes generator)
	feedBody, _ := s.fetch(client, baseURL+"/feed/")
	feedGenRe := regexp.MustCompile(`<generator>https?://wordpress\.org/\?v=(\d+\.\d+(?:\.\d+)?)`)
	if m := feedGenRe.FindStringSubmatch(feedBody); len(m) >= 2 {
		return m[1]
	}

	return "unknown"
}

func (s *CMSCVEScanner) detectJoomla(client *http.Client, baseURL, body string) string {
	low := strings.ToLower(body)
	if !strings.Contains(low, "/components/com_") &&
		!strings.Contains(low, "joomla") &&
		!strings.Contains(low, "/media/jui/") {
		return ""
	}

	// Try /administrator/manifests/files/joomla.xml (often public)
	xmlBody, _ := s.fetch(client, baseURL+"/administrator/manifests/files/joomla.xml")
	verRe := regexp.MustCompile(`<version>([\d.]+)</version>`)
	if m := verRe.FindStringSubmatch(xmlBody); len(m) >= 2 {
		return m[1]
	}

	return "unknown"
}

func (s *CMSCVEScanner) detectDrupal(client *http.Client, baseURL, body string, headers http.Header) string {
	low := strings.ToLower(body)
	hasDrupalContent := strings.Contains(low, "/sites/default/") ||
		strings.Contains(low, "drupal.settings") ||
		strings.Contains(low, "/core/misc/drupal.")

	xGen := headers.Get("X-Generator")
	if !hasDrupalContent && !strings.Contains(strings.ToLower(xGen), "drupal") {
		return ""
	}

	if xGen != "" {
		v := regexp.MustCompile(`(\d+(?:\.\d+){1,3})`).FindString(xGen)
		if v != "" {
			return v
		}
	}

	// Try CHANGELOG.txt (Drupal 7) or core/CHANGELOG.txt (Drupal 8+)
	changelog, _ := s.fetch(client, baseURL+"/CHANGELOG.txt")
	if changelog == "" {
		changelog, _ = s.fetch(client, baseURL+"/core/CHANGELOG.txt")
	}
	verRe := regexp.MustCompile(`(?i)Drupal\s+(\d+\.\d+(?:\.\d+)?)`)
	if m := verRe.FindStringSubmatch(changelog); len(m) >= 2 {
		return m[1]
	}

	return "unknown"
}

func (s *CMSCVEScanner) detectMoodle(client *http.Client, baseURL, body string) string {
	low := strings.ToLower(body)
	if !strings.Contains(low, "moodle") && !strings.Contains(low, "/theme/boost/") {
		return ""
	}

	// Moodle exposes version in /lib/upgrade.txt sometimes
	upgradeBody, _ := s.fetch(client, baseURL+"/lib/upgrade.txt")
	verRe := regexp.MustCompile(`===\s+(\d+\.\d+(?:\.\d+)?)\s+===`)
	if m := verRe.FindStringSubmatch(upgradeBody); len(m) >= 2 {
		return m[1]
	}

	return "unknown"
}

func (s *CMSCVEScanner) detectPHPBB(client *http.Client, baseURL, body string) string {
	low := strings.ToLower(body)
	if !strings.Contains(low, "phpbb") {
		return ""
	}

	verRe := regexp.MustCompile(`(?i)phpbb[/\s]+(\d+\.\d+(?:\.\d+)?)`)
	if m := verRe.FindStringSubmatch(body); len(m) >= 2 {
		return m[1]
	}

	return "unknown"
}

// matchCVEs returns CVEs that affect the detected version.
// Comparison is semver-style, "any version <= maxAffected is vulnerable".
func (s *CMSCVEScanner) matchCVEs(cms, version string) []knownCVE {
	if version == "unknown" {
		return nil
	}
	cves, ok := cmsCVEs[cms]
	if !ok {
		return nil
	}

	var matches []knownCVE
	for _, cve := range cves {
		if compareVersions(version, cve.maxAffected) <= 0 {
			matches = append(matches, cve)
		}
	}
	return matches
}

// compareVersions returns -1 if a<b, 0 if a==b, 1 if a>b. Semver-aware up to 4 parts.
func compareVersions(a, b string) int {
	pa := splitVersion(a)
	pb := splitVersion(b)
	maxLen := len(pa)
	if len(pb) > maxLen {
		maxLen = len(pb)
	}
	for i := 0; i < maxLen; i++ {
		var ai, bi int
		if i < len(pa) {
			ai = pa[i]
		}
		if i < len(pb) {
			bi = pb[i]
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}
