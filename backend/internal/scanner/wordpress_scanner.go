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

// WordPressScanner detects WordPress installations and checks for common vulnerabilities.
type WordPressScanner struct{}

// NewWordPressScanner creates a new WordPressScanner instance.
func NewWordPressScanner() *WordPressScanner {
	return &WordPressScanner{}
}

func (s *WordPressScanner) Name() string     { return "WordPress Security Scanner" }
func (s *WordPressScanner) Category() string { return "wordpress" }
func (s *WordPressScanner) Weight() float64  { return 8.0 }

// WordPress check weights
const (
	weightWPVersion     = 2.0
	weightWPLogin       = 1.5
	weightWPXMLRPC      = 1.5
	weightWPRESTUsers   = 1.0
	weightWPReadme      = 1.0
	weightWPDebug       = 1.0
)

func (s *WordPressScanner) newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: ScanTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

func (s *WordPressScanner) Scan(url string) []models.CheckResult {
	client := s.newHTTPClient()
	baseURL := ensureHTTPS(url)

	// Check 1: WordPress Version Detection
	wpVersionResult, isWordPress, detectedVersion := s.checkWordPressVersion(client, baseURL)

	// If NOT WordPress, return early with only the version check (score 1000)
	if !isWordPress {
		return []models.CheckResult{wpVersionResult}
	}

	// WordPress detected — run all remaining checks
	results := []models.CheckResult{
		wpVersionResult,
		s.checkLoginPageExposure(client, baseURL),
		s.checkXMLRPCExposure(client, baseURL),
		s.checkRESTAPIUserEnum(client, baseURL),
		s.checkReadmeLicenseExposure(client, baseURL),
		s.checkDebugMode(client, baseURL, detectedVersion),
	}

	return results
}

// ---------------------------------------------------------------------------
// 1. WordPress Version Detection (Weight: 2.0)
// ---------------------------------------------------------------------------

var (
	reMetaGenerator = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([\d.]+)?["']`)
	reWPEmbed       = regexp.MustCompile(`wp-includes/js/wp-embed\.min\.js\?ver=([\d.]+)`)
	reFeedGenerator = regexp.MustCompile(`<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>`)
)

func (s *WordPressScanner) checkWordPressVersion(client *http.Client, baseURL string) (models.CheckResult, bool, string) {
	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "WordPress Version",
		Weight:    weightWPVersion,
	}

	detectedVersion := ""
	isWordPress := false

	// Strategy 1: Fetch main page and look for meta generator + wp-embed version
	resp, err := client.Get(baseURL)
	if err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		bodyStr := string(body)

		if matches := reMetaGenerator.FindStringSubmatch(bodyStr); len(matches) > 0 {
			isWordPress = true
			if len(matches) > 1 && matches[1] != "" {
				detectedVersion = matches[1]
			}
		}

		if detectedVersion == "" {
			if matches := reWPEmbed.FindStringSubmatch(bodyStr); len(matches) > 1 {
				isWordPress = true
				detectedVersion = matches[1]
			}
		}

		// Also detect WP by common patterns even without version
		if !isWordPress {
			wpIndicators := []string{
				"/wp-content/",
				"/wp-includes/",
				"/wp-json/",
				"wp-emoji-release.min.js",
			}
			for _, indicator := range wpIndicators {
				if strings.Contains(bodyStr, indicator) {
					isWordPress = true
					break
				}
			}
		}
	}

	// Strategy 2: Check /feed/ for generator tag
	if detectedVersion == "" {
		feedResp, feedErr := client.Get(baseURL + "/feed/")
		if feedErr == nil {
			feedBody, _ := io.ReadAll(io.LimitReader(feedResp.Body, 64*1024))
			feedResp.Body.Close()
			feedStr := string(feedBody)

			if matches := reFeedGenerator.FindStringSubmatch(feedStr); len(matches) > 1 {
				isWordPress = true
				detectedVersion = matches[1]
			} else if strings.Contains(feedStr, "wordpress.org") {
				isWordPress = true
			}
		}
	}

	// Not WordPress — return early signal
	if !isWordPress {
		result.Score = 1000
		result.Status = statusFromScore(1000)
		result.Severity = "info"
		result.Details = toJSON(map[string]string{
			"message": "WordPress not detected - this scanner is not applicable",
		})
		return result, false, ""
	}

	// WordPress detected — score based on version
	score := scoreWordPressVersion(detectedVersion)
	result.Score = score
	result.Status = statusFromScore(score)
	result.Severity = severityFromScore(score)

	msg := "WordPress detected"
	if detectedVersion != "" {
		msg = fmt.Sprintf("WordPress version %s detected", detectedVersion)
	} else {
		msg = "WordPress detected but version could not be determined (good: version is hidden)"
	}

	// Detect HOW WordPress was found
	var detectionMethods []string
	if resp, err := client.Get(baseURL); err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		b := string(body)
		if strings.Contains(b, "wp-content/") {
			detectionMethods = append(detectionMethods, "wp-content/ paths in HTML")
		}
		if strings.Contains(b, "wp-includes/") {
			detectionMethods = append(detectionMethods, "wp-includes/ paths in HTML")
		}
		if strings.Contains(b, "wp-json") {
			detectionMethods = append(detectionMethods, "wp-json API references")
		}
		if strings.Contains(b, "wp-embed") {
			detectionMethods = append(detectionMethods, "wp-embed.min.js script")
		}
	}
	if r, err := client.Get(baseURL + "/wp-json/"); err == nil {
		r.Body.Close()
		if r.StatusCode == 200 {
			detectionMethods = append(detectionMethods, "/wp-json/ REST API accessible (200)")
		}
	}
	if r, err := client.Get(baseURL + "/wp-login.php"); err == nil {
		r.Body.Close()
		if r.StatusCode == 200 {
			detectionMethods = append(detectionMethods, "/wp-login.php login page accessible (200)")
		}
	}

	details := map[string]interface{}{
		"version":           detectedVersion,
		"message":           msg,
		"detection_methods": detectionMethods,
		"hardening_tips": []string{
			"Install WP Hide plugin or add rewrite rules to mask wp-content paths",
			"Disable /wp-json/ REST API: add_filter('rest_authentication_errors', ...)",
			"Move or protect /wp-login.php: use WPS Hide Login plugin",
			"Remove wp-emoji and wp-embed scripts: add_action('init', 'disable_emojis')",
			"Use Cloudflare WAF rules to block WordPress fingerprinting",
		},
	}

	result.Details = toJSON(details)

	return result, true, detectedVersion
}

// scoreWordPressVersion returns a 0-1000 score based on the detected WP version.
func scoreWordPressVersion(version string) float64 {
	if version == "" {
		return 600 // Unknown version — moderate risk
	}

	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return 600
	}

	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 600
	}

	switch {
	case major > 6 || (major == 6 && minor >= 8):
		return 1000 // Latest (6.8+)
	case major == 6 && minor == 7:
		return 800 // One major version behind
	case major == 6 && minor == 6:
		return 600 // Two behind
	case major == 6 && minor >= 0:
		return 400 // Old (6.0-6.5)
	default:
		return 100 // Very old (<6.0)
	}
}

// ---------------------------------------------------------------------------
// 2. Login Page Exposure (Weight: 1.5)
// ---------------------------------------------------------------------------

func (s *WordPressScanner) checkLoginPageExposure(client *http.Client, baseURL string) models.CheckResult {
	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "WP Login Page Exposure",
		Weight:    weightWPLogin,
	}

	// Use a non-redirecting client to see the actual response
	noRedirectClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: ScanTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := noRedirectClient.Get(baseURL + "/wp-login.php")
	if err != nil {
		result.Score = 0
		result.Weight = 0
		result.Status = "error"
		result.Severity = "info"
		result.Details = toJSON(map[string]string{
			"path":    "/wp-login.php",
			"message": "Could not reach login page (timeout or network error)",
		})
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 || resp.StatusCode == 403 || resp.StatusCode == 410 {
		result.Score = 1000
		result.Status = statusFromScore(1000)
		result.Severity = "info"
		result.Details = toJSON(map[string]string{
			"path":        "/wp-login.php",
			"status_code": fmt.Sprintf("%d", resp.StatusCode),
			"message":     "Login page is blocked or hidden",
		})
		return result
	}

	if resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 301 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		bodyStr := string(body)

		hasStandardForm := strings.Contains(bodyStr, "loginform") ||
			strings.Contains(bodyStr, "wp-login") ||
			strings.Contains(bodyStr, "user_login")

		if hasStandardForm {
			// Check if protected by security plugin (Wordfence, Sucuri, etc.)
			hasProtection := strings.Contains(bodyStr, "wordfence") ||
				strings.Contains(bodyStr, "wfls-") ||
				strings.Contains(bodyStr, "sucuri") ||
				strings.Contains(bodyStr, "recaptcha") ||
				strings.Contains(bodyStr, "g-recaptcha") ||
				strings.Contains(bodyStr, "hcaptcha") ||
				strings.Contains(bodyStr, "turnstile") ||
				strings.Contains(bodyStr, "limit-login") ||
				strings.Contains(bodyStr, "two-factor")

			if hasProtection {
				// Login page visible but protected by security plugin — acceptable
				result.Score = 850
				result.Status = statusFromScore(850)
				result.Severity = "info"
				result.Details = toJSON(map[string]string{
					"path":        "/wp-login.php",
					"status_code": fmt.Sprintf("%d", resp.StatusCode),
					"message":     "Login page is publicly accessible but protected by a security plugin (brute-force protection active)",
				})
				return result
			}

			// Login visible without any detected protection
			result.Score = 600
			result.Status = statusFromScore(600)
			result.Severity = severityFromScore(600)
			result.Details = toJSON(map[string]string{
				"path":        "/wp-login.php",
				"status_code": fmt.Sprintf("%d", resp.StatusCode),
				"message":     "Login page is publicly accessible. Consider adding brute-force protection (Wordfence, Limit Login Attempts, or reCAPTCHA)",
			})
			return result
		}

		// Returns 200 but no standard WP form (custom login page)
		result.Score = 700
		result.Status = statusFromScore(700)
		result.Severity = severityFromScore(700)
		result.Details = toJSON(map[string]string{
			"path":        "/wp-login.php",
			"status_code": fmt.Sprintf("%d", resp.StatusCode),
			"message":     "Login page responds but uses a custom form (not standard WP)",
		})
		return result
	}

	// Any other status code
	result.Score = 1000
	result.Status = statusFromScore(1000)
	result.Severity = "info"
	result.Details = toJSON(map[string]string{
		"path":        "/wp-login.php",
		"status_code": fmt.Sprintf("%d", resp.StatusCode),
		"message":     "Login page returned unexpected status",
	})
	return result
}

// ---------------------------------------------------------------------------
// 3. XML-RPC Exposure (Weight: 1.5)
// ---------------------------------------------------------------------------

func (s *WordPressScanner) checkXMLRPCExposure(client *http.Client, baseURL string) models.CheckResult {
	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "WP XML-RPC Exposure",
		Weight:    weightWPXMLRPC,
	}

	xmlPayload := `<methodCall><methodName>system.listMethods</methodName></methodCall>`
	resp, err := client.Post(
		baseURL+"/xmlrpc.php",
		"text/xml",
		strings.NewReader(xmlPayload),
	)
	if err != nil {
		result.Score = 0
		result.Weight = 0
		result.Status = "error"
		result.Severity = "info"
		result.Details = toJSON(map[string]string{
			"path":    "/xmlrpc.php",
			"message": "Could not reach XML-RPC endpoint (timeout or network error)",
		})
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 404 || resp.StatusCode == 405 {
		result.Score = 1000
		result.Status = statusFromScore(1000)
		result.Severity = "info"
		result.Details = toJSON(map[string]string{
			"path":        "/xmlrpc.php",
			"status_code": fmt.Sprintf("%d", resp.StatusCode),
			"message":     "XML-RPC endpoint is blocked or disabled",
		})
		return result
	}

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		bodyStr := string(body)

		// Check if response lists methods (fully open)
		if strings.Contains(bodyStr, "<methodResponse>") && strings.Contains(bodyStr, "<value>") {
			methodCount := strings.Count(bodyStr, "<value>")
			result.Score = 100
			result.Status = statusFromScore(100)
			result.Severity = "critical"
			result.Details = toJSON(map[string]string{
				"path":         "/xmlrpc.php",
				"status_code":  "200",
				"method_count": fmt.Sprintf("%d", methodCount),
				"message":      fmt.Sprintf("XML-RPC is fully open and exposes %d methods - critical vulnerability (brute force, DDoS amplification)", methodCount),
			})
			return result
		}

		// Returns 200 but blocked content (e.g., WAF or plugin blocking)
		result.Score = 700
		result.Status = statusFromScore(700)
		result.Severity = severityFromScore(700)
		result.Details = toJSON(map[string]string{
			"path":        "/xmlrpc.php",
			"status_code": "200",
			"message":     "XML-RPC endpoint responds but appears to be restricted",
		})
		return result
	}

	// Other status codes
	result.Score = 1000
	result.Status = statusFromScore(1000)
	result.Severity = "info"
	result.Details = toJSON(map[string]string{
		"path":        "/xmlrpc.php",
		"status_code": fmt.Sprintf("%d", resp.StatusCode),
		"message":     "XML-RPC endpoint returned non-standard response",
	})
	return result
}

// ---------------------------------------------------------------------------
// 4. REST API User Enumeration (Weight: 1.0)
// ---------------------------------------------------------------------------

func (s *WordPressScanner) checkRESTAPIUserEnum(client *http.Client, baseURL string) models.CheckResult {
	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "WP REST API User Enumeration",
		Weight:    weightWPRESTUsers,
	}

	resp, err := client.Get(baseURL + "/wp-json/wp/v2/users")
	if err != nil {
		result.Score = 0
		result.Weight = 0
		result.Status = "error"
		result.Severity = "info"
		result.Details = toJSON(map[string]string{
			"path":    "/wp-json/wp/v2/users",
			"message": "Could not reach REST API endpoint (timeout or network error)",
		})
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 404 || resp.StatusCode == 401 {
		result.Score = 1000
		result.Status = statusFromScore(1000)
		result.Severity = "info"
		result.Details = toJSON(map[string]string{
			"path":        "/wp-json/wp/v2/users",
			"status_code": fmt.Sprintf("%d", resp.StatusCode),
			"message":     "User enumeration via REST API is blocked",
		})
		return result
	}

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		bodyStr := strings.TrimSpace(string(body))

		// Empty array or no user data
		if bodyStr == "[]" || bodyStr == "" || bodyStr == "null" {
			result.Score = 800
			result.Status = statusFromScore(800)
			result.Severity = severityFromScore(800)
			result.Details = toJSON(map[string]string{
				"path":        "/wp-json/wp/v2/users",
				"status_code": "200",
				"message":     "REST API users endpoint returns empty data",
			})
			return result
		}

		// Contains user data (exposes usernames)
		result.Score = 200
		result.Status = statusFromScore(200)
		result.Severity = severityFromScore(200)
		result.Details = toJSON(map[string]string{
			"path":        "/wp-json/wp/v2/users",
			"status_code": "200",
			"message":     "REST API exposes user information (usernames, slugs) - enables targeted attacks",
		})
		return result
	}

	result.Score = 1000
	result.Status = statusFromScore(1000)
	result.Severity = "info"
	result.Details = toJSON(map[string]string{
		"path":        "/wp-json/wp/v2/users",
		"status_code": fmt.Sprintf("%d", resp.StatusCode),
		"message":     "REST API users endpoint returned non-standard response",
	})
	return result
}

// ---------------------------------------------------------------------------
// 5. Readme/License Exposure (Weight: 1.0)
// ---------------------------------------------------------------------------

func (s *WordPressScanner) checkReadmeLicenseExposure(client *http.Client, baseURL string) models.CheckResult {
	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "WP Readme/License Exposure",
		Weight:    weightWPReadme,
	}

	readmeAccessible := false
	licenseAccessible := false

	// Check /readme.html
	if resp, err := client.Get(baseURL + "/readme.html"); err == nil {
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
			bodyStr := string(body)
			if strings.Contains(strings.ToLower(bodyStr), "wordpress") {
				readmeAccessible = true
			}
		}
		resp.Body.Close()
	}

	// Check /license.txt
	if resp, err := client.Get(baseURL + "/license.txt"); err == nil {
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
			bodyStr := string(body)
			if strings.Contains(strings.ToLower(bodyStr), "wordpress") ||
				strings.Contains(strings.ToLower(bodyStr), "gnu general public") {
				licenseAccessible = true
			}
		}
		resp.Body.Close()
	}

	switch {
	case readmeAccessible && licenseAccessible:
		result.Score = 300
		result.Status = statusFromScore(300)
		result.Severity = severityFromScore(300)
		result.Details = toJSON(map[string]string{
			"readme_accessible":  "true",
			"license_accessible": "true",
			"message":            "Both readme.html and license.txt are accessible - reveals WordPress version and platform",
		})
	case readmeAccessible || licenseAccessible:
		exposed := "readme.html"
		if licenseAccessible {
			exposed = "license.txt"
		}
		result.Score = 600
		result.Status = statusFromScore(600)
		result.Severity = severityFromScore(600)
		result.Details = toJSON(map[string]string{
			"readme_accessible":  fmt.Sprintf("%t", readmeAccessible),
			"license_accessible": fmt.Sprintf("%t", licenseAccessible),
			"message":            fmt.Sprintf("%s is accessible - reveals platform information", exposed),
		})
	default:
		result.Score = 1000
		result.Status = statusFromScore(1000)
		result.Severity = "info"
		result.Details = toJSON(map[string]string{
			"readme_accessible":  "false",
			"license_accessible": "false",
			"message":            "readme.html and license.txt are not accessible",
		})
	}

	return result
}

// ---------------------------------------------------------------------------
// 6. Debug Mode Detection (Weight: 1.0)
// ---------------------------------------------------------------------------

func (s *WordPressScanner) checkDebugMode(client *http.Client, baseURL string, version string) models.CheckResult {
	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "WP Debug Mode",
		Weight:    weightWPDebug,
	}

	debugLogAccessible := false
	phpNoticesInSource := false

	// Check /wp-content/debug.log
	if resp, err := client.Get(baseURL + "/wp-content/debug.log"); err == nil {
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
			bodyStr := string(body)
			// Verify it actually looks like a debug log
			if strings.Contains(bodyStr, "PHP") ||
				strings.Contains(bodyStr, "Notice") ||
				strings.Contains(bodyStr, "Warning") ||
				strings.Contains(bodyStr, "Fatal") ||
				strings.Contains(bodyStr, "Stack trace") {
				debugLogAccessible = true
			}
		}
		resp.Body.Close()
	}

	// Check main page for PHP notices/warnings
	if resp, err := client.Get(baseURL); err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		bodyStr := string(body)
		resp.Body.Close()

		phpPatterns := []string{
			"<b>Notice</b>:",
			"<b>Warning</b>:",
			"<b>Fatal error</b>:",
			"<b>Deprecated</b>:",
			"PHP Notice:",
			"PHP Warning:",
			"PHP Fatal error:",
			"on line <b>",
		}
		for _, pattern := range phpPatterns {
			if strings.Contains(bodyStr, pattern) {
				phpNoticesInSource = true
				break
			}
		}
	}

	switch {
	case debugLogAccessible:
		result.Score = 50
		result.Status = statusFromScore(50)
		result.Severity = "critical"
		result.Details = toJSON(map[string]string{
			"debug_log_accessible": "true",
			"php_notices":          fmt.Sprintf("%t", phpNoticesInSource),
			"message":              "CRITICAL: debug.log is publicly accessible - exposes error messages, file paths, and potentially sensitive data",
		})
	case phpNoticesInSource:
		result.Score = 400
		result.Status = statusFromScore(400)
		result.Severity = severityFromScore(400)
		result.Details = toJSON(map[string]string{
			"debug_log_accessible": "false",
			"php_notices":          "true",
			"message":              "PHP notices/warnings found in page source - WP_DEBUG is likely enabled",
		})
	default:
		result.Score = 1000
		result.Status = statusFromScore(1000)
		result.Severity = "info"
		result.Details = toJSON(map[string]string{
			"debug_log_accessible": "false",
			"php_notices":          "false",
			"message":              "No debug indicators found - debug mode appears to be disabled",
		})
	}

	return result
}
