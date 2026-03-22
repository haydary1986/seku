package scanner

import (
	"crypto/tls"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type HeaderScanner struct{}

func NewHeaderScanner() *HeaderScanner {
	return &HeaderScanner{}
}

func (s *HeaderScanner) Name() string     { return "Security Headers Scanner" }
func (s *HeaderScanner) Category() string { return "headers" }
func (s *HeaderScanner) Weight() float64  { return 20.0 }

// Header weights that sum to the total scanner weight (20.0).
const (
	weightHSTS               = 5.0
	weightCSP                = 5.0
	weightXFrameOptions      = 3.0
	weightXContentTypeOpts   = 3.0
	weightXXSSProtection     = 2.0
	weightReferrerPolicy     = 2.0
	weightPermissionsPolicy  = 2.0
)

func (s *HeaderScanner) Scan(url string) []models.CheckResult {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(ensureHTTPS(url))
	if err != nil {
		// Try HTTP if HTTPS fails
		resp, err = client.Get(ensureHTTP(url))
		if err != nil {
			return []models.CheckResult{{
				Category:  s.Category(),
				CheckName: "Security Headers",
				Status:    "error",
				Score:     0,
				Weight:    s.Weight(),
				Severity:  "critical",
				Details:   toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()}),
			}}
		}
	}
	defer resp.Body.Close()

	headers := resp.Header

	results := []models.CheckResult{
		s.checkHSTS(headers),
		s.checkCSP(headers),
		s.checkXFrameOptions(headers),
		s.checkXContentTypeOptions(headers),
		s.checkXXSSProtection(headers),
		s.checkReferrerPolicy(headers),
		s.checkPermissionsPolicy(headers),
	}

	return results
}

// ---------------------------------------------------------------------------
// HSTS  (Weight: 5.0)
// ---------------------------------------------------------------------------

func (s *HeaderScanner) checkHSTS(headers http.Header) models.CheckResult {
	headerName := "Strict-Transport-Security"
	value := headers.Get(headerName)

	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "HSTS",
		Weight:    weightHSTS,
	}

	if value == "" {
		result.Status = "fail"
		result.Score = 0
		result.Severity = "critical"
		result.Details = toJSON(map[string]string{
			"header":      headerName,
			"description": "Enforces HTTPS connections, preventing downgrade attacks",
			"message":     "HSTS header is missing",
		})
		return result
	}

	lower := strings.ToLower(value)
	maxAge := parseMaxAge(lower)
	hasIncludeSub := strings.Contains(lower, "includesubdomains")
	hasPreload := strings.Contains(lower, "preload")

	var score float64
	var message string

	switch {
	case maxAge == 0:
		score = 100
		message = "HSTS present but max-age is 0 (effectively disabled)"
	case maxAge < 15768000:
		score = 400
		message = "HSTS present but max-age is less than 6 months"
	case maxAge < 31536000:
		score = 650
		message = "HSTS present with max-age >= 6 months but less than 1 year"
	case maxAge >= 31536000 && !hasIncludeSub:
		score = 800
		message = "HSTS present with max-age >= 1 year but missing includeSubDomains"
	case maxAge >= 31536000 && hasIncludeSub && !hasPreload:
		score = 920
		message = "HSTS present with max-age >= 1 year and includeSubDomains, but missing preload"
	case maxAge >= 31536000 && hasIncludeSub && hasPreload:
		score = 1000
		message = "HSTS fully configured with max-age >= 1 year, includeSubDomains, and preload"
	}

	result.Score = score
	result.Status = statusFromScore(score)
	result.Severity = severityFromScore(score)
	result.Details = toJSON(map[string]string{
		"header":      headerName,
		"value":       value,
		"description": "Enforces HTTPS connections, preventing downgrade attacks",
		"message":     message,
	})
	return result
}

// ---------------------------------------------------------------------------
// Content-Security-Policy  (Weight: 5.0)
// ---------------------------------------------------------------------------

func (s *HeaderScanner) checkCSP(headers http.Header) models.CheckResult {
	headerName := "Content-Security-Policy"
	value := headers.Get(headerName)

	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Content Security Policy",
		Weight:    weightCSP,
	}

	if value == "" {
		result.Status = "fail"
		result.Score = 0
		result.Severity = "high"
		result.Details = toJSON(map[string]string{
			"header":      headerName,
			"description": "Prevents XSS and data injection attacks",
			"message":     "Content-Security-Policy header is missing",
		})
		return result
	}

	lower := strings.ToLower(value)
	hasUnsafeInline := strings.Contains(lower, "'unsafe-inline'")
	hasUnsafeEval := strings.Contains(lower, "'unsafe-eval'")
	tooPermissive := strings.Contains(lower, "default-src *") ||
		strings.Contains(lower, "default-src *;") ||
		strings.TrimSpace(lower) == "default-src *"

	var score float64
	var message string

	switch {
	case tooPermissive:
		score = 200
		message = "CSP present but too permissive (default-src *)"
	case hasUnsafeInline && hasUnsafeEval:
		score = 400
		message = "CSP present but uses both 'unsafe-inline' and 'unsafe-eval'"
	case hasUnsafeInline && !hasUnsafeEval:
		score = 700
		message = "CSP present with 'unsafe-inline' but no 'unsafe-eval'"
	default:
		score = 1000
		message = "CSP present with specific sources and no unsafe directives"
	}

	result.Score = score
	result.Status = statusFromScore(score)
	result.Severity = severityFromScore(score)
	result.Details = toJSON(map[string]string{
		"header":      headerName,
		"value":       value,
		"description": "Prevents XSS and data injection attacks",
		"message":     message,
	})
	return result
}

// ---------------------------------------------------------------------------
// X-Frame-Options  (Weight: 3.0)
// ---------------------------------------------------------------------------

func (s *HeaderScanner) checkXFrameOptions(headers http.Header) models.CheckResult {
	headerName := "X-Frame-Options"
	value := headers.Get(headerName)

	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "X-Frame-Options",
		Weight:    weightXFrameOptions,
	}

	if value == "" {
		result.Status = "fail"
		result.Score = 0
		result.Severity = "high"
		result.Details = toJSON(map[string]string{
			"header":      headerName,
			"description": "Prevents clickjacking attacks",
			"message":     "X-Frame-Options header is missing",
		})
		return result
	}

	upper := strings.ToUpper(strings.TrimSpace(value))

	var score float64
	var message string

	switch {
	case upper == "DENY":
		score = 1000
		message = "X-Frame-Options set to DENY (strongest protection)"
	case upper == "SAMEORIGIN":
		score = 900
		message = "X-Frame-Options set to SAMEORIGIN"
	case strings.HasPrefix(upper, "ALLOW-FROM"):
		score = 700
		message = "X-Frame-Options set to ALLOW-FROM a specific origin"
	default:
		score = 400
		message = "X-Frame-Options present but with unrecognized value"
	}

	result.Score = score
	result.Status = statusFromScore(score)
	result.Severity = severityFromScore(score)
	result.Details = toJSON(map[string]string{
		"header":      headerName,
		"value":       value,
		"description": "Prevents clickjacking attacks",
		"message":     message,
	})
	return result
}

// ---------------------------------------------------------------------------
// X-Content-Type-Options  (Weight: 3.0)
// ---------------------------------------------------------------------------

func (s *HeaderScanner) checkXContentTypeOptions(headers http.Header) models.CheckResult {
	headerName := "X-Content-Type-Options"
	value := headers.Get(headerName)

	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "X-Content-Type-Options",
		Weight:    weightXContentTypeOpts,
	}

	if value == "" {
		result.Status = "fail"
		result.Score = 0
		result.Severity = "medium"
		result.Details = toJSON(map[string]string{
			"header":      headerName,
			"description": "Prevents MIME type sniffing",
			"message":     "X-Content-Type-Options header is missing",
		})
		return result
	}

	lower := strings.ToLower(strings.TrimSpace(value))

	var score float64
	var message string

	if lower == "nosniff" {
		score = 1000
		message = "X-Content-Type-Options correctly set to nosniff"
	} else {
		score = 400
		message = "X-Content-Type-Options present but not set to nosniff"
	}

	result.Score = score
	result.Status = statusFromScore(score)
	result.Severity = severityFromScore(score)
	result.Details = toJSON(map[string]string{
		"header":      headerName,
		"value":       value,
		"description": "Prevents MIME type sniffing",
		"message":     message,
	})
	return result
}

// ---------------------------------------------------------------------------
// X-XSS-Protection  (Weight: 2.0)
// ---------------------------------------------------------------------------

func (s *HeaderScanner) checkXXSSProtection(headers http.Header) models.CheckResult {
	headerName := "X-XSS-Protection"
	value := headers.Get(headerName)

	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "X-XSS-Protection",
		Weight:    weightXXSSProtection,
	}

	if value == "" {
		result.Status = "fail"
		result.Score = 0
		result.Severity = "medium"
		result.Details = toJSON(map[string]string{
			"header":      headerName,
			"description": "Legacy XSS protection (modern browsers use CSP instead)",
			"message":     "X-XSS-Protection header is missing",
		})
		return result
	}

	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(strings.ReplaceAll(trimmed, " ", ""))

	var score float64
	var message string

	switch {
	case strings.Contains(lower, "1;mode=block"):
		score = 1000
		message = "X-XSS-Protection enabled with mode=block"
	case strings.HasPrefix(lower, "1"):
		score = 700
		message = "X-XSS-Protection enabled but without mode=block"
	case strings.HasPrefix(lower, "0"):
		score = 500
		message = "X-XSS-Protection intentionally disabled (acceptable when CSP is present)"
	default:
		score = 300
		message = "X-XSS-Protection present but with unrecognized value"
	}

	result.Score = score
	result.Status = statusFromScore(score)
	result.Severity = severityFromScore(score)
	result.Details = toJSON(map[string]string{
		"header":      headerName,
		"value":       value,
		"description": "Legacy XSS protection (modern browsers use CSP instead)",
		"message":     message,
	})
	return result
}

// ---------------------------------------------------------------------------
// Referrer-Policy  (Weight: 2.0)
// ---------------------------------------------------------------------------

func (s *HeaderScanner) checkReferrerPolicy(headers http.Header) models.CheckResult {
	headerName := "Referrer-Policy"
	value := headers.Get(headerName)

	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Referrer-Policy",
		Weight:    weightReferrerPolicy,
	}

	if value == "" {
		result.Status = "fail"
		result.Score = 0
		result.Severity = "medium"
		result.Details = toJSON(map[string]string{
			"header":      headerName,
			"description": "Controls how much referrer information is shared",
			"message":     "Referrer-Policy header is missing",
		})
		return result
	}

	// The header may contain multiple comma-separated policies; use the last one
	// (browsers pick the last supported value).
	policies := strings.Split(value, ",")
	policy := strings.ToLower(strings.TrimSpace(policies[len(policies)-1]))

	var score float64
	var message string

	switch policy {
	case "no-referrer", "same-origin":
		score = 1000
		message = "Referrer-Policy set to " + policy + " (most restrictive)"
	case "strict-origin-when-cross-origin":
		score = 900
		message = "Referrer-Policy set to strict-origin-when-cross-origin (recommended)"
	case "strict-origin":
		score = 850
		message = "Referrer-Policy set to strict-origin"
	case "origin-when-cross-origin":
		score = 600
		message = "Referrer-Policy set to origin-when-cross-origin"
	case "origin":
		score = 500
		message = "Referrer-Policy set to origin"
	case "no-referrer-when-downgrade":
		score = 400
		message = "Referrer-Policy set to no-referrer-when-downgrade"
	case "unsafe-url":
		score = 100
		message = "Referrer-Policy set to unsafe-url (leaks full URL on all requests)"
	default:
		score = 300
		message = "Referrer-Policy present but with unrecognized value: " + policy
	}

	result.Score = score
	result.Status = statusFromScore(score)
	result.Severity = severityFromScore(score)
	result.Details = toJSON(map[string]string{
		"header":      headerName,
		"value":       value,
		"description": "Controls how much referrer information is shared",
		"message":     message,
	})
	return result
}

// ---------------------------------------------------------------------------
// Permissions-Policy  (Weight: 2.0)
// ---------------------------------------------------------------------------

func (s *HeaderScanner) checkPermissionsPolicy(headers http.Header) models.CheckResult {
	headerName := "Permissions-Policy"
	value := headers.Get(headerName)

	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Permissions-Policy",
		Weight:    weightPermissionsPolicy,
	}

	if value == "" {
		result.Status = "fail"
		result.Score = 0
		result.Severity = "medium"
		result.Details = toJSON(map[string]string{
			"header":      headerName,
			"description": "Controls which browser features can be used",
			"message":     "Permissions-Policy header is missing",
		})
		return result
	}

	var score float64
	var message string

	if isPermissivePP(value) {
		score = 500
		message = "Permissions-Policy present but permissive (features are broadly allowed)"
	} else {
		score = 1000
		message = "Permissions-Policy present with restrictive settings"
	}

	result.Score = score
	result.Status = statusFromScore(score)
	result.Severity = severityFromScore(score)
	result.Details = toJSON(map[string]string{
		"header":      headerName,
		"value":       value,
		"description": "Controls which browser features can be used",
		"message":     message,
	})
	return result
}

// ===========================================================================
// Helpers
// ===========================================================================

// parseMaxAge extracts the max-age value from a lowercased HSTS header.
func parseMaxAge(lower string) int64 {
	idx := strings.Index(lower, "max-age")
	if idx == -1 {
		return 0
	}
	rest := lower[idx+len("max-age"):]
	// skip optional whitespace and '='
	rest = strings.TrimLeft(rest, " \t")
	if len(rest) == 0 || rest[0] != '=' {
		return 0
	}
	rest = rest[1:]
	rest = strings.TrimLeft(rest, " \t")

	// Collect digits
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.ParseInt(rest[:end], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// isPermissivePP checks whether a Permissions-Policy header is overly permissive.
// A policy is considered permissive if it contains wildcard (*) allowlists or
// if it lacks restriction directives (i.e. no "=()" self-restriction patterns).
func isPermissivePP(value string) bool {
	// Wildcard means everything is allowed for that feature.
	if strings.Contains(value, "=*") {
		return true
	}
	// A restrictive policy typically contains "=()" to deny a feature entirely
	// or "=(self)" to limit it. If there are none, the policy is likely permissive.
	if !strings.Contains(value, "=()") && !strings.Contains(value, "=(self)") {
		return true
	}
	return false
}

