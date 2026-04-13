package scanner

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type JSLibScanner struct{}

func NewJSLibScanner() *JSLibScanner {
	return &JSLibScanner{}
}

func (s *JSLibScanner) Name() string     { return "JavaScript Library Scanner" }
func (s *JSLibScanner) Category() string { return "js_libraries" }
func (s *JSLibScanner) Weight() float64  { return 6.0 }

func (s *JSLibScanner) Scan(url string) []models.CheckResult {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: ScanTransport,
	}

	targetURL := ensureHTTPS(url)
	resp, err := client.Get(targetURL)
	if err != nil {
		targetURL = ensureHTTP(url)
		resp, err = client.Get(targetURL)
		if err != nil {
			return []models.CheckResult{{
				Category:  s.Category(),
				CheckName: "JavaScript Libraries",
				Status:    "error",
				Score:     0,
				Weight:    s.Weight(),
				Severity:  "critical",
				Details:   toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()}),
			}}
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyStr := string(body)

	var results []models.CheckResult
	results = append(results, s.checkjQuery(bodyStr))
	results = append(results, s.checkVulnerableLibraries(bodyStr))
	results = append(results, s.checkInlineScripts(bodyStr))

	return results
}

// ---------------------------------------------------------------------------
// Outdated jQuery Detection  (Weight: 3.0)
// ---------------------------------------------------------------------------

func (s *JSLibScanner) checkjQuery(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Outdated jQuery Detection",
		Weight:    3.0,
	}

	lower := strings.ToLower(body)

	// Search for jQuery version patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)jquery[/.\-](\d+\.\d+\.\d+)`),
		regexp.MustCompile(`(?i)jQuery v(\d+\.\d+\.\d+)`),
		regexp.MustCompile(`(?i)jquery\.min\.js\?ver=(\d+\.\d+\.\d+)`),
	}

	var detectedVersion string
	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(lower)
		if len(matches) > 1 {
			detectedVersion = matches[1]
			break
		}
	}

	if detectedVersion == "" {
		// jQuery not found - not using it is safe
		check.Score = 1000
		check.Status = statusFromScore(check.Score)
		check.Severity = severityFromScore(check.Score)
		check.Details = toJSON(map[string]string{
			"message": "jQuery not detected - site does not appear to use jQuery",
		})
		return check
	}

	// Parse the major.minor.patch version
	major, minor, patch := parseVersion(detectedVersion)

	var score float64
	var message string

	switch {
	case major > 3 || (major == 3 && minor >= 7):
		score = 1000
		message = fmt.Sprintf("jQuery %s detected - latest version, fully up to date", detectedVersion)
	case major == 3 && minor >= 5:
		score = 850
		message = fmt.Sprintf("jQuery %s detected - has important XSS fix (CVE-2020-11022/11023)", detectedVersion)
	case major == 3 && minor >= 0:
		score = 650
		message = fmt.Sprintf("jQuery %s detected - version 3.x but missing XSS fixes from 3.5.0+", detectedVersion)
	case major == 2:
		score = 400
		message = fmt.Sprintf("jQuery %s detected - old version with multiple known CVEs", detectedVersion)
	case major == 1 && minor >= 12:
		score = 250
		message = fmt.Sprintf("jQuery %s detected - very old version with known vulnerabilities", detectedVersion)
	default:
		score = 50
		message = fmt.Sprintf("jQuery %s detected - critically outdated with severe vulnerabilities", detectedVersion)
	}

	_ = patch // patch used in version parsing

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"jquery_version": detectedVersion,
		"message":        message,
	})
	return check
}

// parseVersion splits a "major.minor.patch" string into its integer components.
func parseVersion(version string) (int, int, int) {
	parts := strings.SplitN(version, ".", 3)
	var major, minor, patch int
	if len(parts) >= 1 {
		major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	return major, minor, patch
}

// ---------------------------------------------------------------------------
// Known Vulnerable Libraries  (Weight: 2.0)
// ---------------------------------------------------------------------------

func (s *JSLibScanner) checkVulnerableLibraries(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Known Vulnerable Libraries",
		Weight:    2.0,
	}

	lower := strings.ToLower(body)
	var vulnerableLibs []string

	// Angular.js 1.x (any 1.x version) - known XSS vulnerabilities
	angularRe := regexp.MustCompile(`(?i)angular[/.\-v]1\.\d+`)
	if angularRe.MatchString(lower) {
		vulnerableLibs = append(vulnerableLibs, "AngularJS 1.x (known XSS vulnerabilities)")
	}

	// Bootstrap < 3.4.1 or < 4.3.1 - XSS in tooltip/popover
	bootstrapRe := regexp.MustCompile(`(?i)bootstrap[/.\-v](\d+)\.(\d+)\.(\d+)`)
	if matches := bootstrapRe.FindStringSubmatch(lower); len(matches) > 3 {
		bMajor, _ := strconv.Atoi(matches[1])
		bMinor, _ := strconv.Atoi(matches[2])
		bPatch, _ := strconv.Atoi(matches[3])
		vulnerable := false
		if bMajor < 3 {
			vulnerable = true
		} else if bMajor == 3 && (bMinor < 4 || (bMinor == 4 && bPatch < 1)) {
			vulnerable = true
		} else if bMajor == 4 && (bMinor < 3 || (bMinor == 3 && bPatch < 1)) {
			vulnerable = true
		}
		if vulnerable {
			vulnerableLibs = append(vulnerableLibs, fmt.Sprintf("Bootstrap %d.%d.%d (XSS in tooltip/popover)", bMajor, bMinor, bPatch))
		}
	}

	// Lodash < 4.17.21 - prototype pollution
	lodashRe := regexp.MustCompile(`(?i)lodash[/.\-v](\d+)\.(\d+)\.(\d+)`)
	if matches := lodashRe.FindStringSubmatch(lower); len(matches) > 3 {
		lMajor, _ := strconv.Atoi(matches[1])
		lMinor, _ := strconv.Atoi(matches[2])
		lPatch, _ := strconv.Atoi(matches[3])
		if lMajor < 4 || (lMajor == 4 && lMinor < 17) || (lMajor == 4 && lMinor == 17 && lPatch < 21) {
			vulnerableLibs = append(vulnerableLibs, fmt.Sprintf("Lodash %d.%d.%d (prototype pollution)", lMajor, lMinor, lPatch))
		}
	}

	// Moment.js (any version) - deprecated, ReDoS vulnerabilities
	momentRe := regexp.MustCompile(`(?i)(moment[/.\-v]\d+\.\d+|moment\.min\.js)`)
	if momentRe.MatchString(lower) {
		vulnerableLibs = append(vulnerableLibs, "Moment.js (deprecated, ReDoS vulnerabilities)")
	}

	// Vue.js < 2.5.0 - XSS vulnerability
	vueRe := regexp.MustCompile(`(?i)vue[@/.\-v](\d+)\.(\d+)`)
	if matches := vueRe.FindStringSubmatch(lower); len(matches) > 2 {
		vMajor, _ := strconv.Atoi(matches[1])
		vMinor, _ := strconv.Atoi(matches[2])
		if vMajor == 1 || (vMajor == 2 && vMinor < 5) {
			vulnerableLibs = append(vulnerableLibs, fmt.Sprintf("Vue.js %d.%d.x (XSS vulnerability)", vMajor, vMinor))
		}
	}

	// React < 16.4.0 - XSS vulnerability
	reactRe := regexp.MustCompile(`(?i)react[/.\-v@](\d+)\.(\d+)`)
	if matches := reactRe.FindStringSubmatch(lower); len(matches) > 2 {
		rMajor, _ := strconv.Atoi(matches[1])
		rMinor, _ := strconv.Atoi(matches[2])
		if rMajor < 16 || (rMajor == 16 && rMinor < 4) {
			vulnerableLibs = append(vulnerableLibs, fmt.Sprintf("React %d.%d.x (XSS vulnerability)", rMajor, rMinor))
		}
	}

	var score float64
	var message string

	switch len(vulnerableLibs) {
	case 0:
		score = 1000
		message = "No known vulnerable JavaScript libraries detected"
	case 1:
		score = 500
		message = fmt.Sprintf("1 vulnerable library detected: %s", vulnerableLibs[0])
	case 2:
		score = 300
		message = fmt.Sprintf("2 vulnerable libraries detected")
	default:
		score = 100
		message = fmt.Sprintf("%d vulnerable libraries detected", len(vulnerableLibs))
	}

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"vulnerable_libraries": vulnerableLibs,
		"count":                len(vulnerableLibs),
		"message":              message,
	})
	return check
}

// ---------------------------------------------------------------------------
// Inline Script Analysis  (Weight: 1.0)
// ---------------------------------------------------------------------------

func (s *JSLibScanner) checkInlineScripts(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Inline Script Analysis",
		Weight:    1.0,
	}

	// Find all <script> blocks without src attribute (inline scripts)
	inlineScriptRe := regexp.MustCompile(`(?i)<script(?:\s[^>]*)?>[\s\S]*?</script>`)
	srcAttrRe := regexp.MustCompile(`(?i)\ssrc\s*=`)

	allScripts := inlineScriptRe.FindAllString(body, -1)
	var inlineScripts []string
	for _, script := range allScripts {
		if !srcAttrRe.MatchString(script) {
			inlineScripts = append(inlineScripts, script)
		}
	}

	inlineCount := len(inlineScripts)
	inlineContent := strings.Join(inlineScripts, "\n")
	lower := strings.ToLower(inlineContent)

	// Base score based on count
	var score float64
	switch {
	case inlineCount <= 3:
		score = 1000
	case inlineCount <= 10:
		score = 800
	default:
		score = 600
	}

	// Check for dangerous patterns and apply penalties
	var dangerousPatterns []string

	if strings.Contains(lower, "eval(") {
		score -= 200
		dangerousPatterns = append(dangerousPatterns, "eval()")
	}
	if strings.Contains(lower, "document.write(") {
		score -= 150
		dangerousPatterns = append(dangerousPatterns, "document.write()")
	}
	if strings.Contains(lower, "innerhtml") {
		score -= 100
		dangerousPatterns = append(dangerousPatterns, "innerHTML =")
	}

	// Enforce minimum score of 100
	if score < 100 {
		score = 100
	}

	var message string
	if len(dangerousPatterns) > 0 {
		message = fmt.Sprintf("%d inline scripts found with dangerous patterns: %s",
			inlineCount, strings.Join(dangerousPatterns, ", "))
	} else if inlineCount == 0 {
		message = "No inline scripts detected"
	} else {
		message = fmt.Sprintf("%d inline scripts found, no dangerous patterns detected", inlineCount)
	}

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"inline_script_count":  inlineCount,
		"dangerous_patterns":   dangerousPatterns,
		"message":              message,
	})
	return check
}
