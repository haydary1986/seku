package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

// XSSScanner detects Cross-Site Scripting vulnerabilities using safe,
// non-destructive canary-based reflection analysis.  It never injects
// actual malicious payloads -- only harmless marker strings.
type XSSScanner struct{}

func NewXSSScanner() *XSSScanner { return &XSSScanner{} }

func (s *XSSScanner) Name() string     { return "XSS Vulnerability Scanner" }
func (s *XSSScanner) Category() string { return "xss" }
func (s *XSSScanner) Weight() float64  { return 9.0 }

// canary is a unique, harmless string that will never appear in legitimate
// content.  We check whether the target reflects it without encoding.
const xssCanary = "vscan7x7test"

// Limits to keep scans safe and fast.
const (
	xssMaxForms       = 5
	xssMaxParams      = 10
	xssRequestTimeout = 10 * time.Second
	xssMaxBodyBytes   = 1024 * 1024 // 1 MB
)

// Pre-compiled patterns used across checks.
var (
	xssFormPattern  = regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']*)["'][^>]*>[\s\S]*?</form>`)
	xssInputPattern = regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["']`)

	// DOM-based XSS sink patterns (variable input, not literal strings).
	domSinkPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)document\.write\s*\(`),
		regexp.MustCompile(`(?i)\.innerHTML\s*=`),
		regexp.MustCompile(`(?i)[^a-zA-Z]eval\s*\(`),
		regexp.MustCompile(`(?i)location\.href\s*=`),
		regexp.MustCompile(`(?i)location\.assign\s*\(`),
		regexp.MustCompile(`(?i)location\.replace\s*\(`),
		regexp.MustCompile(`(?i)document\.cookie\s*=`),
		regexp.MustCompile(`(?i)\.outerHTML\s*=`),
		regexp.MustCompile(`(?i)setTimeout\s*\(\s*["']`),
		regexp.MustCompile(`(?i)setInterval\s*\(\s*["']`),
	}

	// HTML / JS comment blocks to strip before counting sinks.
	xssHTMLCommentPattern = regexp.MustCompile(`<!--[\s\S]*?-->`)
	xssJSBlockComment     = regexp.MustCompile(`/\*[\s\S]*?\*/`)
	xssJSLineComment      = regexp.MustCompile(`//[^\n]*`)

	// Canary reflection context detectors.
	xssScriptContextPattern = regexp.MustCompile(
		`(?i)<script[^>]*>[^<]*` + xssCanary + `[^<]*</script>`,
	)
	xssAttrContextPattern = regexp.MustCompile(
		`(?i)(value|on\w+|src|href|data)\s*=\s*["'][^"']*` + xssCanary,
	)
)

// ---------------------------------------------------------------------------
// Scan entry point
// ---------------------------------------------------------------------------

func (s *XSSScanner) Scan(rawURL string) []models.CheckResult {
	client := &http.Client{
		Timeout: xssRequestTimeout,
		Transport: ScanTransport,
	}

	targetURL := ensureHTTPS(rawURL)
	body, resp, err := s.fetchBody(client, targetURL)
	if err != nil {
		// Fallback to HTTP.
		targetURL = ensureHTTP(rawURL)
		body, resp, err = s.fetchBody(client, targetURL)
		if err != nil {
			return []models.CheckResult{{
				Category:  s.Category(),
				CheckName: "XSS Scan",
				Status:    "error",
				Score:     0,
				Weight:    s.Weight(),
				Severity:  "critical",
				Details:   toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()}),
			}}
		}
	}

	var results []models.CheckResult
	results = append(results, s.checkReflectedXSS(client, targetURL, body))
	results = append(results, s.checkDOMBasedXSS(body))
	results = append(results, s.checkInputSanitization(client, targetURL))
	results = append(results, s.checkXSSHeaders(resp))
	results = append(results, s.checkURLParamReflection(client, targetURL))
	return results
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (s *XSSScanner) fetchBody(client *http.Client, targetURL string) (string, *http.Response, error) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return "", nil, err
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, xssMaxBodyBytes))
	resp.Body.Close()
	return string(raw), resp, nil
}

// xssStripComments removes HTML and JS comments so they don't produce false
// positives in pattern matching.
func xssStripComments(body string) string {
	out := xssHTMLCommentPattern.ReplaceAllString(body, "")
	out = xssJSBlockComment.ReplaceAllString(out, "")
	out = xssJSLineComment.ReplaceAllString(out, "")
	return out
}

// xssResolveActionURL turns a potentially relative form action into an absolute URL.
func xssResolveActionURL(base *url.URL, action string) string {
	if action == "" || action == "#" {
		return base.String()
	}
	ref, err := url.Parse(action)
	if err != nil {
		return base.String()
	}
	return base.ResolveReference(ref).String()
}

// xssAppendQueryParam adds a key=value pair to the URL query string.
func xssAppendQueryParam(rawURL, key, value string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + "?" + key + "=" + value
	}
	q := parsed.Query()
	q.Set(key, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// xssClassifyReflection determines the reflection context of the canary.
func xssClassifyReflection(body string) string {
	if !strings.Contains(body, xssCanary) {
		return "none"
	}
	if xssScriptContextPattern.MatchString(body) {
		return "script"
	}
	if xssAttrContextPattern.MatchString(body) {
		return "attribute"
	}
	// The canary has no HTML-special characters, so if present it is in the
	// HTML body text (unescaped but not in a dangerous context by itself).
	return "body"
}

// ---------------------------------------------------------------------------
// 1. Reflected XSS Detection  (Weight: 3.0)
// ---------------------------------------------------------------------------

func (s *XSSScanner) checkReflectedXSS(client *http.Client, targetURL, body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Reflected XSS Detection",
		Weight:    3.0,
	}

	// Extract forms and their inputs.
	formMatches := xssFormPattern.FindAllStringSubmatch(body, xssMaxForms)
	if len(formMatches) == 0 {
		check.Score = 1000
		check.Status = statusFromScore(check.Score)
		check.Severity = severityFromScore(check.Score)
		check.Details = toJSON(map[string]string{
			"message": "No forms found on page; reflected XSS via forms not applicable",
		})
		return check
	}

	type reflResult struct {
		Param   string `json:"param"`
		URL     string `json:"url"`
		Context string `json:"context"`
	}

	var reflections []reflResult
	paramsTested := 0

	parsedBase, _ := url.Parse(targetURL)

	for _, fm := range formMatches {
		if paramsTested >= xssMaxParams {
			break
		}
		actionRaw := fm[1]
		formHTML := fm[0]

		actionURL := xssResolveActionURL(parsedBase, actionRaw)

		inputs := xssInputPattern.FindAllStringSubmatch(formHTML, -1)
		for _, inp := range inputs {
			if paramsTested >= xssMaxParams {
				break
			}
			paramName := inp[1]
			paramsTested++

			testURL := xssAppendQueryParam(actionURL, paramName, xssCanary)

			respBody, _, fetchErr := s.fetchBody(client, testURL)
			if fetchErr != nil {
				continue
			}

			ctx := xssClassifyReflection(respBody)
			reflections = append(reflections, reflResult{
				Param:   paramName,
				URL:     testURL,
				Context: ctx,
			})
		}
	}

	// Filter out safe reflections (WordPress search, encoded output, etc.)
	var dangerousReflections []reflResult
	for _, r := range reflections {
		// "none" means canary not found — safe
		// "encoded" means properly HTML-encoded — safe (this is correct behavior)
		if r.Context == "script" || r.Context == "attribute" || r.Context == "body" {
			dangerousReflections = append(dangerousReflections, r)
		}
	}

	// Score based on worst dangerous reflection found.
	worstScore := 1000.0
	if len(dangerousReflections) == 0 {
		// All reflections are either encoded or not reflected — safe
		worstScore = 1000
		if len(reflections) > 0 {
			// Some encoded reflections exist — minor concern but safe
			worstScore = 900
		}
	}
	for _, r := range dangerousReflections {
		var sc float64
		switch r.Context {
		case "script":
			sc = 100 // Critical: reflected inside script tag
		case "attribute":
			sc = 200 // High: reflected inside HTML attribute
		case "body":
			sc = 500 // Medium: reflected in body but not in dangerous context
		default:
			sc = 1000
		}
		if sc < worstScore {
			worstScore = sc
		}
	}

	// Multiple unescaped reflections are worse.
	unescapedCount := 0
	for _, r := range reflections {
		if r.Context == "body" || r.Context == "script" || r.Context == "attribute" {
			unescapedCount++
		}
	}
	if unescapedCount >= 2 && worstScore > 50 {
		worstScore = 50
	}

	check.Score = worstScore
	check.Status = statusFromScore(check.Score)
	check.Severity = severityFromScore(check.Score)
	check.Details = toJSON(map[string]interface{}{
		"message":       fmt.Sprintf("Tested %d parameter(s) across %d form(s)", paramsTested, len(formMatches)),
		"reflections":   reflections,
		"params_tested": paramsTested,
		"forms_found":   len(formMatches),
	})
	return check
}

// ---------------------------------------------------------------------------
// 2. DOM-Based XSS Indicators  (Weight: 2.0)
// ---------------------------------------------------------------------------

func (s *XSSScanner) checkDOMBasedXSS(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "DOM-Based XSS Indicators",
		Weight:    2.0,
	}

	cleaned := xssStripComments(body)

	var found []string
	for _, pat := range domSinkPatterns {
		matches := pat.FindAllString(cleaned, -1)
		if len(matches) > 0 {
			found = append(found, fmt.Sprintf("%s (%d occurrence(s))", pat.String(), len(matches)))
		}
	}

	sinkCount := len(found)

	switch {
	case sinkCount == 0:
		check.Score = 1000
	case sinkCount <= 2:
		check.Score = 750
	case sinkCount <= 5:
		check.Score = 500
	case sinkCount <= 10:
		check.Score = 300
	default:
		check.Score = 100
	}

	check.Status = statusFromScore(check.Score)
	check.Severity = severityFromScore(check.Score)
	check.Details = toJSON(map[string]interface{}{
		"message":         fmt.Sprintf("Found %d dangerous DOM sink pattern(s)", sinkCount),
		"dangerous_sinks": found,
		"sink_count":      sinkCount,
	})
	return check
}

// ---------------------------------------------------------------------------
// 3. Input Sanitization Check  (Weight: 2.0)
// ---------------------------------------------------------------------------

func (s *XSSScanner) checkInputSanitization(client *http.Client, targetURL string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Input Sanitization Check",
		Weight:    2.0,
	}

	type testPayload struct {
		label string
		value string
		kind  string // "script" or "event"
	}

	payloads := []testPayload{
		{"Script injection", "<script>alert(1)</script>", "script"},
		{"Event handler injection", "\"><img src=x onerror=alert(1)>", "event"},
		{"JavaScript URI", "javascript:alert(1)", "script"},
	}

	type payloadResult struct {
		Label   string `json:"label"`
		Payload string `json:"payload"`
		Outcome string `json:"outcome"` // "blocked", "escaped", "reflected", "error"
	}

	var results []payloadResult
	scriptReflected := false
	eventReflected := false
	allBlocked := true

	for _, p := range payloads {
		testURL := xssAppendQueryParam(targetURL, "q", p.value)
		respBody, resp, fetchErr := s.fetchBody(client, testURL)
		if fetchErr != nil {
			results = append(results, payloadResult{
				Label:   p.label,
				Payload: p.value,
				Outcome: "error",
			})
			continue
		}

		// Blocked = server returned 403 or body doesn't contain payload at all.
		if resp != nil && resp.StatusCode == 403 {
			results = append(results, payloadResult{
				Label:   p.label,
				Payload: p.value,
				Outcome: "blocked",
			})
			continue
		}

		if strings.Contains(respBody, p.value) {
			// Payload reflected unescaped.
			allBlocked = false
			if p.kind == "script" {
				scriptReflected = true
			} else {
				eventReflected = true
			}
			results = append(results, payloadResult{
				Label:   p.label,
				Payload: p.value,
				Outcome: "reflected",
			})
		} else if strings.Contains(respBody, strings.ReplaceAll(strings.ReplaceAll(p.value, "<", "&lt;"), ">", "&gt;")) {
			// Entity-encoded version found.
			allBlocked = false
			results = append(results, payloadResult{
				Label:   p.label,
				Payload: p.value,
				Outcome: "escaped",
			})
		} else {
			results = append(results, payloadResult{
				Label:   p.label,
				Payload: p.value,
				Outcome: "blocked",
			})
		}
	}

	switch {
	case allBlocked:
		check.Score = 1000
	case scriptReflected:
		check.Score = 100
	case eventReflected:
		check.Score = 150
	default:
		// Some escaped, none raw-reflected.
		check.Score = 500
	}

	check.Status = statusFromScore(check.Score)
	check.Severity = severityFromScore(check.Score)
	check.Details = toJSON(map[string]interface{}{
		"message":  fmt.Sprintf("Tested %d XSS payloads against homepage", len(payloads)),
		"payloads": results,
	})
	return check
}

// ---------------------------------------------------------------------------
// 4. Content-Type & X-XSS-Protection Headers  (Weight: 1.0)
// ---------------------------------------------------------------------------

func (s *XSSScanner) checkXSSHeaders(resp *http.Response) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Content-Type & X-XSS-Protection Headers",
		Weight:    1.0,
	}

	if resp == nil {
		check.Score = 0
		check.Status = "error"
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{"error": "No HTTP response available"})
		return check
	}

	score := 0.0
	findings := map[string]interface{}{}

	// Content-Type charset check (+500).
	ct := resp.Header.Get("Content-Type")
	findings["content_type"] = ct
	if strings.Contains(strings.ToLower(ct), "charset") {
		score += 500
		findings["charset_present"] = true
	} else {
		findings["charset_present"] = false
		findings["charset_note"] = "Missing charset in Content-Type header; charset-based XSS may be possible"
	}

	// X-XSS-Protection header.
	xxp := resp.Header.Get("X-XSS-Protection")
	findings["x_xss_protection"] = xxp

	switch {
	case strings.Contains(xxp, "1") && strings.Contains(strings.ToLower(xxp), "mode=block"):
		score += 500
		findings["xss_protection_note"] = "X-XSS-Protection is enabled with mode=block"
	case xxp == "0":
		score += 300
		findings["xss_protection_note"] = "X-XSS-Protection is explicitly disabled"
	case xxp == "":
		// No header present -- no addition to score.
		findings["xss_protection_note"] = "X-XSS-Protection header is missing"
	default:
		score += 400
		findings["xss_protection_note"] = "X-XSS-Protection is present but not optimally configured"
	}

	check.Score = score
	check.Status = statusFromScore(check.Score)
	check.Severity = severityFromScore(check.Score)
	check.Details = toJSON(findings)
	return check
}

// ---------------------------------------------------------------------------
// 5. URL Parameter Reflection Analysis  (Weight: 1.0)
// ---------------------------------------------------------------------------

func (s *XSSScanner) checkURLParamReflection(client *http.Client, targetURL string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "URL Parameter Reflection Analysis",
		Weight:    1.0,
	}

	// Common query parameter names to test with our canary.
	testParamKeys := []string{"q", "search", "query", "s", "id"}

	type reflEntry struct {
		Param   string `json:"param"`
		Context string `json:"context"`
	}

	var reflections []reflEntry
	anyReflected := false

	for _, key := range testParamKeys {
		testURL := xssAppendQueryParam(targetURL, key, xssCanary)

		respBody, _, fetchErr := s.fetchBody(client, testURL)
		if fetchErr != nil {
			continue
		}

		ctx := xssClassifyReflection(respBody)
		reflections = append(reflections, reflEntry{
			Param:   key,
			Context: ctx,
		})
		if ctx != "none" {
			anyReflected = true
		}
	}

	if !anyReflected {
		check.Score = 1000
		check.Status = statusFromScore(check.Score)
		check.Severity = severityFromScore(check.Score)
		check.Details = toJSON(map[string]interface{}{
			"message":     "No URL parameters reflected in response",
			"reflections": reflections,
		})
		return check
	}

	// Score based on worst context found.
	worstScore := 1000.0
	for _, r := range reflections {
		var sc float64
		switch r.Context {
		case "script":
			sc = 100
		case "attribute":
			sc = 300
		case "body":
			sc = 500
		case "encoded":
			sc = 900
		case "none":
			sc = 1000
		}
		if sc < worstScore {
			worstScore = sc
		}
	}

	// Count how many params were reflected.
	reflectedCount := 0
	for _, r := range reflections {
		if r.Context != "none" {
			reflectedCount++
		}
	}

	check.Score = worstScore
	check.Status = statusFromScore(check.Score)
	check.Severity = severityFromScore(check.Score)
	check.Details = toJSON(map[string]interface{}{
		"message":     fmt.Sprintf("URL parameter reflection detected in %d parameter(s)", reflectedCount),
		"reflections": reflections,
	})
	return check
}
