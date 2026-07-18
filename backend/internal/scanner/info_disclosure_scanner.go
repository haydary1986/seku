package scanner

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"seku/internal/models"
)

type InfoDisclosureScanner struct{}

func NewInfoDisclosureScanner() *InfoDisclosureScanner {
	return &InfoDisclosureScanner{}
}

func (s *InfoDisclosureScanner) Name() string     { return "Information Disclosure Scanner" }
func (s *InfoDisclosureScanner) Category() string { return "info_disclosure" }
func (s *InfoDisclosureScanner) Weight() float64  { return 7.0 }

func (s *InfoDisclosureScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: ScanTransport,
	}

	targetURL := ensureHTTPS(url)
	resp, err := client.Get(targetURL)
	if err != nil {
		targetURL = ensureHTTP(url)
		resp, err = client.Get(targetURL)
		if err != nil {
			return []models.CheckResult{
				{Category: s.Category(), CheckName: "Error Page Information Disclosure", Status: "error", Score: 0, Weight: 0, Severity: "info", Details: toJSON(map[string]string{"message": "Cannot reach website"})},
				{Category: s.Category(), CheckName: "Sensitive HTML Comments", Status: "error", Score: 0, Weight: 0, Severity: "info", Details: toJSON(map[string]string{"message": "Cannot reach website"})},
				{Category: s.Category(), CheckName: "Technology Version Disclosure", Status: "error", Score: 0, Weight: 0, Severity: "info", Details: toJSON(map[string]string{"message": "Cannot reach website"})},
			}
		}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	bodyStr := string(body)

	// Check error page information disclosure
	results = append(results, s.checkErrorPages(client, targetURL))

	// Check for comments with sensitive info
	results = append(results, s.checkHTMLComments(bodyStr))

	// Check for version disclosure in HTML
	results = append(results, s.checkVersionDisclosure(bodyStr, resp))

	return results
}

func (s *InfoDisclosureScanner) checkErrorPages(client *http.Client, baseURL string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Error Page Information Disclosure",
		Weight:    3.0,
	}

	errorURL := baseURL + "/this-page-does-not-exist-test-404"
	resp, err := client.Get(errorURL)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Weight = 0
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Cannot check error pages (timeout or network error)"})
		return check
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := strings.ToLower(string(body))

	disclosures := []string{}

	// Check for stack traces - very dangerous
	if strings.Contains(bodyStr, "stack trace") || strings.Contains(bodyStr, "stacktrace") {
		disclosures = append(disclosures, "Stack trace exposed")
	}
	// Check for server version info
	if strings.Contains(bodyStr, "apache/") || strings.Contains(bodyStr, "nginx/") || strings.Contains(bodyStr, "iis/") {
		disclosures = append(disclosures, "Server version in error page")
	}
	// Check for framework info
	if strings.Contains(bodyStr, "laravel") || strings.Contains(bodyStr, "django") || strings.Contains(bodyStr, "asp.net") {
		disclosures = append(disclosures, "Framework name in error page")
	}
	// Check for path disclosure
	pathPattern := regexp.MustCompile(`(?i)(\/var\/www|\/home\/|c:\\|\/usr\/|\/opt\/)`)
	if pathPattern.MatchString(bodyStr) {
		disclosures = append(disclosures, "Server file paths exposed")
	}
	// Check for SQL errors — specific database error signatures only, never the
	// generic word "error" (which appears on any normal 404 page).
	for _, sig := range []string{"sql syntax", "sqlstate", "mysql_fetch", "ora-0", "warning: pg_", "unclosed quotation"} {
		if strings.Contains(bodyStr, sig) {
			disclosures = append(disclosures, "SQL error messages exposed")
			break
		}
	}
	// Framework debug pages / stack traces — specific signatures only, never the
	// bare word "debug".
	for _, sig := range []string{"whoops, looks like", "traceback (most recent call last)", "symfony\\component", "stack trace:"} {
		if strings.Contains(bodyStr, sig) {
			disclosures = append(disclosures, "Framework debug/stack trace exposed")
			break
		}
	}

	if len(disclosures) >= 3 {
		// Multiple types of information disclosed - very serious
		check.Status = "fail"
		check.Score = 50
		check.Severity = "critical"
		check.Details = toJSON(map[string]interface{}{
			"message":     "Error page reveals extensive sensitive information",
			"disclosures": disclosures,
		})
	} else if len(disclosures) == 2 {
		check.Status = "fail"
		check.Score = 125
		check.Severity = "high"
		check.Details = toJSON(map[string]interface{}{
			"message":     "Error page reveals multiple types of sensitive information",
			"disclosures": disclosures,
		})
	} else if len(disclosures) == 1 {
		check.Status = "fail"
		check.Score = 225
		check.Severity = "high"
		check.Details = toJSON(map[string]interface{}{
			"message":     "Error page reveals sensitive information",
			"disclosures": disclosures,
		})
	} else {
		check.Status = "pass"
		check.Score = 1000
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "Error pages do not reveal sensitive information",
		})
	}

	return check
}

// commentSecretValueRe matches an assigned secret-looking VALUE inside a comment
// (e.g. `password: hunter2`, `api_key = ab12cd34`). commentSecretAssignRe matches
// a named secret assignment even without capturing the value length. Bare
// keywords like "admin", "bug" or "debug" are intentionally NOT flagged.
var (
	commentSecretValueRe  = regexp.MustCompile(`(?i)(password|passwd|api[_-]?key|secret|token)\s*[:=]\s*\S{6,}`)
	commentSecretAssignRe = regexp.MustCompile(`(?i)(db_password|aws_secret)\s*[:=]`)
)

func (s *InfoDisclosureScanner) checkHTMLComments(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Sensitive HTML Comments",
		Weight:    2.0,
	}

	commentPattern := regexp.MustCompile(`<!--[\s\S]*?-->`)
	comments := commentPattern.FindAllString(body, -1)

	// Only flag a comment when it contains an actual assigned secret-looking VALUE,
	// not a bare keyword like "admin", "debug" or "bug" (harmless in dev comments).
	sensitiveComments := []string{}
	for _, comment := range comments {
		if commentSecretValueRe.MatchString(comment) || commentSecretAssignRe.MatchString(comment) {
			c := comment
			if len(c) > 100 {
				c = c[:100] + "..."
			}
			sensitiveComments = append(sensitiveComments, c)
		}
	}

	if len(sensitiveComments) > 0 {
		check.Status = "fail"
		check.Score = 175
		check.Severity = "high"
		check.Details = toJSON(map[string]interface{}{
			"message":  "HTML comments contain an assigned secret-looking value (credentials, API key, secret or token)",
			"count":    len(sensitiveComments),
			"examples": sensitiveComments[:min(len(sensitiveComments), 3)],
		})
	} else {
		check.Status = "pass"
		check.Score = 1000
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message":        "No assigned secret values found in HTML comments",
			"total_comments": fmt.Sprintf("%d", len(comments)),
		})
	}

	return check
}

func (s *InfoDisclosureScanner) checkVersionDisclosure(body string, resp *http.Response) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Technology Version Disclosure",
		Weight:    2.0,
	}

	disclosures := []string{}
	headerDisclosures := 0

	// Check meta generator tag
	generatorPattern := regexp.MustCompile(`(?i)<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`)
	if matches := generatorPattern.FindStringSubmatch(body); len(matches) > 1 {
		disclosures = append(disclosures, "Generator: "+matches[1])
	}

	// Check for WordPress version — only count an ACTUAL version number, not the
	// bare wp-content/wp-includes asset paths (which every WP site exposes and
	// which carry no version information).
	wpPattern := regexp.MustCompile(`(?i)wordpress[\s/v]*(\d+\.\d+(?:\.\d+)?)`)
	if matches := wpPattern.FindStringSubmatch(body); len(matches) > 1 {
		disclosures = append(disclosures, "WordPress version: "+matches[1])
	}

	// Check for jQuery version — require a real version number (major.minor), not
	// a lone "jquery.min.js" reference without a version.
	jqPattern := regexp.MustCompile(`(?i)jquery[-./]?v?(\d+\.\d+(?:\.\d+)?)`)
	if matches := jqPattern.FindStringSubmatch(body); len(matches) > 1 {
		disclosures = append(disclosures, "jQuery version: "+matches[1])
	}

	// Check X-Powered-By header (header-based disclosures are more severe)
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		disclosures = append(disclosures, "X-Powered-By: "+poweredBy)
		headerDisclosures++
	}

	// Check X-AspNet-Version
	if aspNet := resp.Header.Get("X-AspNet-Version"); aspNet != "" {
		disclosures = append(disclosures, "X-AspNet-Version: "+aspNet)
		headerDisclosures++
	}

	// Check X-AspNetMvc-Version
	if aspMvc := resp.Header.Get("X-AspNetMvc-Version"); aspMvc != "" {
		disclosures = append(disclosures, "X-AspNetMvc-Version: "+aspMvc)
		headerDisclosures++
	}

	if len(disclosures) > 0 {
		// Header-based disclosures are worse because they're on every response
		if headerDisclosures >= 2 {
			check.Status = "fail"
			check.Score = 225
			check.Severity = "high"
			check.Details = toJSON(map[string]interface{}{
				"message":     "Multiple technology versions exposed via HTTP headers",
				"disclosures": disclosures,
			})
		} else if headerDisclosures == 1 {
			check.Status = "warn"
			check.Score = 350
			check.Severity = "medium"
			check.Details = toJSON(map[string]interface{}{
				"message":     "Technology version exposed via HTTP header and page source",
				"disclosures": disclosures,
			})
		} else if len(disclosures) > 2 {
			// Multiple in-page disclosures
			check.Status = "warn"
			check.Score = 425
			check.Severity = "medium"
			check.Details = toJSON(map[string]interface{}{
				"message":     "Multiple technology versions exposed in page source",
				"disclosures": disclosures,
			})
		} else {
			// Minor in-page disclosure (e.g., jQuery version)
			check.Status = "warn"
			check.Score = 550
			check.Severity = "medium"
			check.Details = toJSON(map[string]interface{}{
				"message":     "Technology versions are exposed in page source",
				"disclosures": disclosures,
			})
		}
	} else {
		check.Status = "pass"
		check.Score = 1000
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No significant technology version disclosures found",
		})
	}

	return check
}
