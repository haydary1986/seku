package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type DDoSScanner struct{}

func NewDDoSScanner() *DDoSScanner {
	return &DDoSScanner{}
}

func (s *DDoSScanner) Name() string     { return "DDoS Protection Scanner" }
func (s *DDoSScanner) Category() string { return "ddos" }
func (s *DDoSScanner) Weight() float64  { return 10.0 }

func (s *DDoSScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	targetURL := ensureHTTPS(url)
	resp, err := client.Get(targetURL)
	if err != nil {
		targetURL = ensureHTTP(url)
		resp, err = client.Get(targetURL)
		if err != nil {
			return []models.CheckResult{{
				Category:  s.Category(),
				CheckName: "DDoS Protection",
				Status:    "error",
				Score:     0,
				Weight:    s.Weight(),
				Severity:  "critical",
				Details:   toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()}),
			}}
		}
	}
	defer resp.Body.Close()

	// Check for CDN/DDoS protection services
	results = append(results, s.checkCDNProtection(resp))

	// Check rate limiting headers
	results = append(results, s.checkRateLimiting(resp))

	// Check WAF (Web Application Firewall) indicators
	results = append(results, s.checkWAF(resp, targetURL, client))

	return results
}

func (s *DDoSScanner) checkCDNProtection(resp *http.Response) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "CDN/DDoS Protection Service",
		Weight:    4.0,
	}

	headers := resp.Header
	detected := []string{}
	provider := "None detected"
	bestScore := 0.0

	// Cloudflare - top-tier DDoS protection
	if headers.Get("CF-RAY") != "" || headers.Get("cf-cache-status") != "" {
		detected = append(detected, "Cloudflare")
		provider = "Cloudflare"
		bestScore = 1000
	}

	// AWS CloudFront - excellent enterprise CDN
	if headers.Get("X-Amz-Cf-Id") != "" || headers.Get("X-Amz-Cf-Pop") != "" {
		detected = append(detected, "AWS CloudFront")
		provider = "AWS CloudFront"
		if bestScore < 975 {
			bestScore = 975
		}
	}

	// Akamai - major enterprise CDN
	if headers.Get("X-Akamai-Transformed") != "" || strings.Contains(headers.Get("Server"), "AkamaiGHost") {
		detected = append(detected, "Akamai")
		provider = "Akamai"
		if bestScore < 975 {
			bestScore = 975
		}
	}

	// Fastly - high-performance CDN
	if headers.Get("X-Fastly-Request-ID") != "" || headers.Get("Fastly-Debug-Digest") != "" {
		detected = append(detected, "Fastly")
		provider = "Fastly"
		if bestScore < 950 {
			bestScore = 950
		}
	}

	// Sucuri - specialized security CDN
	if headers.Get("X-Sucuri-ID") != "" || strings.Contains(headers.Get("Server"), "Sucuri") {
		detected = append(detected, "Sucuri")
		provider = "Sucuri"
		if bestScore < 925 {
			bestScore = 925
		}
	}

	// Incapsula / Imperva - enterprise WAF/CDN
	if headers.Get("X-CDN") == "Imperva" || headers.Get("X-Iinfo") != "" {
		detected = append(detected, "Imperva/Incapsula")
		provider = "Imperva/Incapsula"
		if bestScore < 950 {
			bestScore = 950
		}
	}

	// Azure Front Door
	if headers.Get("X-Azure-Ref") != "" {
		detected = append(detected, "Azure Front Door")
		provider = "Azure Front Door"
		if bestScore < 950 {
			bestScore = 950
		}
	}

	// Google Cloud CDN
	if headers.Get("X-Goog-Component") != "" {
		detected = append(detected, "Google Cloud CDN")
		provider = "Google Cloud CDN"
		if bestScore < 950 {
			bestScore = 950
		}
	}

	// Check server header for generic CDN indicators
	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(server, "cloudflare") || strings.Contains(server, "cdn") {
		if len(detected) == 0 {
			detected = append(detected, "Generic CDN")
			provider = "Unknown CDN"
			bestScore = 750
		}
	}

	details := map[string]interface{}{
		"provider":          provider,
		"services_detected": detected,
	}

	if len(detected) > 0 {
		// Multiple CDN providers is even better
		if len(detected) > 1 && bestScore < 1000 {
			bestScore += 25
			if bestScore > 1000 {
				bestScore = 1000
			}
		}
		check.Status = statusFromScore(bestScore)
		check.Score = bestScore
		check.Severity = severityFromScore(bestScore)
		details["message"] = fmt.Sprintf("DDoS protection detected: %s", strings.Join(detected, ", "))
	} else {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["message"] = "No CDN or DDoS protection service detected"
	}

	check.Details = toJSON(details)
	return check
}

func (s *DDoSScanner) checkRateLimiting(resp *http.Response) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Rate Limiting",
		Weight:    3.0,
	}

	headers := resp.Header
	indicators := []string{}

	// Standard rate limit headers
	rateLimitHeaders := []string{
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"X-RateLimit-Reset",
		"RateLimit-Limit",
		"RateLimit-Remaining",
		"RateLimit-Reset",
		"Retry-After",
		"X-Rate-Limit",
	}

	for _, h := range rateLimitHeaders {
		if val := headers.Get(h); val != "" {
			indicators = append(indicators, fmt.Sprintf("%s: %s", h, val))
		}
	}

	details := map[string]interface{}{
		"indicators": indicators,
	}

	if len(indicators) >= 3 {
		// Full rate limiting headers (Limit + Remaining + Reset)
		check.Status = "pass"
		check.Score = 1000
		check.Severity = "info"
		details["message"] = "Comprehensive rate limiting headers detected"
	} else if len(indicators) == 2 {
		// Partial rate limiting headers
		check.Status = "pass"
		check.Score = 850
		check.Severity = "info"
		details["message"] = "Rate limiting headers detected (partial set)"
	} else if len(indicators) == 1 {
		// Minimal rate limiting indication
		check.Status = "warn"
		check.Score = 700
		check.Severity = "low"
		details["message"] = "Minimal rate limiting header detected"
	} else {
		check.Status = "warn"
		check.Score = 250
		check.Severity = "high"
		details["message"] = "No rate limiting headers detected (may still be configured server-side)"
	}

	check.Details = toJSON(details)
	return check
}

func (s *DDoSScanner) checkWAF(resp *http.Response, baseURL string, client *http.Client) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Web Application Firewall (WAF)",
		Weight:    3.0,
	}

	wafIndicators := []string{}
	wafScore := 0.0

	// Check response headers for WAF indicators
	headers := resp.Header

	if headers.Get("X-ModSecurity") != "" || headers.Get("X-Mod-Security") != "" {
		wafIndicators = append(wafIndicators, "ModSecurity")
		wafScore = 925
	}

	if headers.Get("X-Sucuri-ID") != "" {
		wafIndicators = append(wafIndicators, "Sucuri WAF")
		if wafScore < 950 {
			wafScore = 950
		}
	}

	if headers.Get("X-CDN") == "Imperva" || headers.Get("X-Iinfo") != "" {
		wafIndicators = append(wafIndicators, "Imperva WAF")
		if wafScore < 975 {
			wafScore = 975
		}
	}

	// Cloudflare WAF
	if headers.Get("CF-RAY") != "" {
		wafIndicators = append(wafIndicators, "Cloudflare WAF")
		if wafScore < 1000 {
			wafScore = 1000
		}
	}

	// Try a simple WAF detection by sending a suspicious parameter
	testURL := baseURL + "/?test=<script>alert(1)</script>"
	testResp, err := client.Get(testURL)
	if err == nil {
		body, _ := io.ReadAll(io.LimitReader(testResp.Body, 2048))
		testResp.Body.Close()

		bodyStr := strings.ToLower(string(body))

		if testResp.StatusCode == 403 || testResp.StatusCode == 406 || testResp.StatusCode == 429 {
			wafIndicators = append(wafIndicators, fmt.Sprintf("Blocked suspicious request (HTTP %d)", testResp.StatusCode))
			if wafScore < 900 {
				wafScore = 900
			}
		}

		// Check if the script tag was reflected (indicates no WAF)
		if strings.Contains(bodyStr, "<script>alert(1)</script>") {
			wafIndicators = append(wafIndicators, "WARNING: XSS payload reflected without filtering")
		}

		// Check for common WAF block pages
		if strings.Contains(bodyStr, "access denied") || strings.Contains(bodyStr, "blocked") ||
			strings.Contains(bodyStr, "firewall") || strings.Contains(bodyStr, "waf") {
			wafIndicators = append(wafIndicators, "WAF block page detected")
			if wafScore < 875 {
				wafScore = 875
			}
		}
	}

	details := map[string]interface{}{
		"indicators": wafIndicators,
	}

	hasPositiveIndicator := false
	for _, ind := range wafIndicators {
		if !strings.Contains(ind, "WARNING") {
			hasPositiveIndicator = true
			break
		}
	}

	if hasPositiveIndicator {
		// Bonus for multiple WAF indicators
		if len(wafIndicators) > 2 && wafScore < 1000 {
			wafScore += 50
			if wafScore > 1000 {
				wafScore = 1000
			}
		}
		check.Status = statusFromScore(wafScore)
		check.Score = wafScore
		check.Severity = severityFromScore(wafScore)
		details["message"] = "Web Application Firewall detected"
	} else {
		check.Status = "fail"
		check.Score = 75
		check.Severity = "critical"
		details["message"] = "No Web Application Firewall detected"
	}

	check.Details = toJSON(details)
	return check
}
