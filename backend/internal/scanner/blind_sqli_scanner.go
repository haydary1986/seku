package scanner

import (
	"fmt"
	"io"
	"net/url"
	"time"

	"seku/internal/models"
)

// BlindSQLiScanner detects time-based and boolean-based blind SQL injection.
type BlindSQLiScanner struct{}

func NewBlindSQLiScanner() *BlindSQLiScanner { return &BlindSQLiScanner{} }

func (s *BlindSQLiScanner) Name() string     { return "Blind SQL Injection Scanner" }
func (s *BlindSQLiScanner) Category() string { return "sqli" }
func (s *BlindSQLiScanner) Weight() float64  { return 5.0 }

// blindSQLiParams is a focused set of parameters to test for blind SQLi.
var blindSQLiParams = []string{"id", "page", "cat"}

func (s *BlindSQLiScanner) Scan(targetURL string) []models.CheckResult {
	return []models.CheckResult{
		s.checkBlindSQLi(targetURL),
	}
}

func (s *BlindSQLiScanner) checkBlindSQLi(targetURL string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Blind SQL Injection Test",
		Weight:    s.Weight(),
	}

	// Use a longer timeout client for time-based tests
	client := NewScanClient(15 * time.Second)
	baseURL := ensureHTTPS(targetURL)

	type finding struct {
		Parameter string `json:"parameter"`
		Type      string `json:"type"`
		Evidence  string `json:"evidence"`
	}

	var findings []finding
	testedCount := 0

	for _, param := range blindSQLiParams {
		// --- Time-based blind SQLi ---
		// First, measure baseline response time
		baselineURL := fmt.Sprintf("%s?%s=1", baseURL, param)
		baseStart := time.Now()
		resp, err := client.Get(baselineURL)
		if err != nil {
			continue
		}
		resp.Body.Close()
		baselineDuration := time.Since(baseStart)

		// Send SLEEP payload
		sleepPayload := "' AND SLEEP(3)--"
		sleepURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(sleepPayload))
		testedCount++

		sleepStart := time.Now()
		sleepResp, err := client.Get(sleepURL)
		if err != nil {
			continue
		}
		sleepResp.Body.Close()
		sleepDuration := time.Since(sleepStart)

		// If the sleep payload took >3 seconds more than baseline, likely vulnerable
		if sleepDuration-baselineDuration > 3*time.Second {
			findings = append(findings, finding{
				Parameter: param,
				Type:      "time-based",
				Evidence: fmt.Sprintf(
					"Baseline: %dms, SLEEP payload: %dms (delta: %dms)",
					baselineDuration.Milliseconds(),
					sleepDuration.Milliseconds(),
					(sleepDuration - baselineDuration).Milliseconds(),
				),
			})
			continue // Skip boolean test for this param since it's already confirmed
		}

		// --- Boolean-based blind SQLi ---
		truePayload := "' AND 1=1--"
		falsePayload := "' AND 1=2--"

		trueURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(truePayload))
		falseURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(falsePayload))
		testedCount += 2

		trueResp, err := client.Get(trueURL)
		if err != nil {
			continue
		}
		trueBody, err := io.ReadAll(io.LimitReader(trueResp.Body, 100*1024))
		trueResp.Body.Close()
		if err != nil {
			continue
		}

		falseResp, err := client.Get(falseURL)
		if err != nil {
			continue
		}
		falseBody, err := io.ReadAll(io.LimitReader(falseResp.Body, 100*1024))
		falseResp.Body.Close()
		if err != nil {
			continue
		}

		trueLen := len(trueBody)
		falseLen := len(falseBody)

		// If the true and false conditions produce significantly different response sizes,
		// this indicates boolean-based blind SQLi.
		// We require at least 10% difference and minimum 50 bytes difference.
		diff := trueLen - falseLen
		if diff < 0 {
			diff = -diff
		}
		minLen := trueLen
		if falseLen < minLen {
			minLen = falseLen
		}

		if diff > 50 && minLen > 0 && float64(diff)/float64(minLen) > 0.1 {
			findings = append(findings, finding{
				Parameter: param,
				Type:      "boolean-based",
				Evidence: fmt.Sprintf(
					"AND 1=1 response: %d bytes, AND 1=2 response: %d bytes (diff: %d bytes)",
					trueLen, falseLen, diff,
				),
			})
		}
	}

	details := map[string]interface{}{
		"parameters_tested": testedCount,
	}

	if len(findings) > 0 {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["message"] = fmt.Sprintf(
			"Blind SQL Injection detected in %d parameter(s)",
			len(findings),
		)
		details["findings"] = findings
		details["recommendation"] = "Use parameterized queries or prepared statements for all database operations"
	} else {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = fmt.Sprintf(
			"No blind SQL injection detected across %d tests on %d parameters",
			testedCount, len(blindSQLiParams),
		)
	}

	check.Details = toJSON(details)
	return check
}
