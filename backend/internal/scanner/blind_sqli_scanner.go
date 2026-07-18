package scanner

import (
	"fmt"
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
		// timing measures one request's wall-clock and status.
		timing := func(payload string) (time.Duration, int, bool) {
			u := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
			start := time.Now()
			r, err := client.Get(u)
			if err != nil {
				return 0, 0, false
			}
			r.Body.Close()
			return time.Since(start), r.StatusCode, true
		}

		// --- Time-based blind SQLi (confirmed by scaling) ---
		// Measure a benign baseline, then require the delay to SCALE with the
		// requested sleep. A one-off latency spike or a WAF tarpit/429-retry does
		// not scale, so this rejects those false positives.
		baseDur, _, okB := timing("1")
		if okB {
			testedCount++
			d3, s3, ok3 := timing("' AND SLEEP(3)--")
			if ok3 && !isBlockedStatus(s3) && d3-baseDur > 3*time.Second {
				testedCount++
				d6, s6, ok6 := timing("' AND SLEEP(6)--")
				if ok6 && !isBlockedStatus(s6) && d6-d3 > 2*time.Second {
					findings = append(findings, finding{
						Parameter: param,
						Type:      "time-based",
						Evidence: fmt.Sprintf(
							"baseline=%dms SLEEP(3)=%dms SLEEP(6)=%dms (delay scales with requested sleep)",
							baseDur.Milliseconds(), d3.Milliseconds(), d6.Milliseconds(),
						),
					})
					continue // confirmed; skip boolean test
				}
			}
		}

		// --- Boolean-based blind SQLi (with stability baseline) ---
		lenOf := func(payload string) (int, bool) {
			u := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
			body, status, ok := fetchLowerBody(client, u, 100*1024)
			if !ok || isBlockedStatus(status) {
				return 0, false
			}
			return len(body), true
		}
		testedCount += 3
		true1, ok1 := lenOf("' AND 1=1--")
		true2, ok2 := lenOf("' AND 1=1--") // same input twice → stability check
		falseLen, okF := lenOf("' AND 1=2--")
		if !ok1 || !ok2 || !okF {
			continue
		}

		stability := absInt(true1 - true2) // noise floor of identical requests
		tfDiff := absInt(true1 - falseLen)
		minLen := true1
		if falseLen < minLen {
			minLen = falseLen
		}

		// Flag only when the page is stable for identical input (stability small)
		// yet true≠false well beyond that noise floor.
		if minLen > 0 && stability <= 50 && tfDiff > 50 &&
			float64(tfDiff)/float64(minLen) > 0.1 && tfDiff > stability*3 {
			findings = append(findings, finding{
				Parameter: param,
				Type:      "boolean-based",
				Evidence: fmt.Sprintf(
					"stable %d/%d bytes for 1=1, %d bytes for 1=2 (diff %d >> noise %d)",
					true1, true2, falseLen, tfDiff, stability,
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
