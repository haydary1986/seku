package scanner

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

// SSRFScanner detects Server-Side Request Forgery vulnerabilities.
type SSRFScanner struct{}

func NewSSRFScanner() *SSRFScanner { return &SSRFScanner{} }

func (s *SSRFScanner) Name() string     { return "SSRF Detection Scanner" }
func (s *SSRFScanner) Category() string { return "ssrf" }
func (s *SSRFScanner) Weight() float64  { return 8.0 }

// ssrfParams are common URL parameters susceptible to SSRF.
var ssrfParams = []string{
	"url", "uri", "path", "src", "dest", "redirect",
	"img", "image", "load", "fetch", "proxy",
}

// ssrfPayloads are internal URLs used to test SSRF.
var ssrfPayloads = []struct {
	label string
	value string
}{
	{"localhost", "http://127.0.0.1:80"},
	{"aws_metadata", "http://169.254.169.254/latest/meta-data/"},
}

// ssrfSignatures are patterns in the response body that indicate a successful SSRF.
var ssrfSignatures = []string{
	"meta-data",
	"ami-id",
	"instance-id",
	"local-hostname",
	"public-hostname",
	"instance-type",
	"placement/availability-zone",
	"security-credentials",
	"<title>index of /</title>",
	"<!doctype html>",
	"<html",
	"apache",
	"nginx",
	"localhost",
	"127.0.0.1",
}

func (s *SSRFScanner) Scan(targetURL string) []models.CheckResult {
	return []models.CheckResult{
		s.checkSSRF(targetURL),
	}
}

func (s *SSRFScanner) checkSSRF(targetURL string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "SSRF Detection",
		Weight:    s.Weight(),
	}

	client := NewScanClient(10 * time.Second)
	baseURL := ensureHTTPS(targetURL)

	// First, get a baseline response to compare against
	baselineResp, err := client.Get(baseURL)
	baselineLen := 0
	if err == nil {
		baselineBody, _ := io.ReadAll(io.LimitReader(baselineResp.Body, 100*1024))
		baselineResp.Body.Close()
		baselineLen = len(baselineBody)
	}

	type finding struct {
		Parameter string `json:"parameter"`
		Payload   string `json:"payload"`
		Evidence  string `json:"evidence"`
	}

	var findings []finding
	testedCount := 0

	for _, param := range ssrfParams {
		for _, payload := range ssrfPayloads {
			testURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload.value))
			testedCount++

			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}

			body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
			resp.Body.Close()
			if err != nil {
				continue
			}

			bodyLower := strings.ToLower(string(body))
			bodyLen := len(body)

			// Check for SSRF signatures in the response
			for _, sig := range ssrfSignatures {
				if strings.Contains(bodyLower, sig) {
					// Verify this signature is not in the normal response
					// by checking if response size changed significantly
					diff := bodyLen - baselineLen
					if diff < 0 {
						diff = -diff
					}

					// Only flag if the response is meaningfully different from baseline
					// or contains AWS metadata-specific signatures
					isAWSSignature := sig == "ami-id" || sig == "instance-id" ||
						sig == "local-hostname" || sig == "security-credentials" ||
						sig == "placement/availability-zone"

					if isAWSSignature || (diff > 100 && bodyLen > 0) {
						findings = append(findings, finding{
							Parameter: param,
							Payload:   payload.label,
							Evidence:  fmt.Sprintf("Response contains '%s' (response size: %d bytes)", sig, bodyLen),
						})
						break
					}
				}
			}
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
			"Potential SSRF vulnerability detected in %d test(s)",
			len(findings),
		)
		details["findings"] = findings
		details["recommendation"] = "Validate and whitelist all URLs used in server-side requests; block access to internal networks and cloud metadata endpoints"
	} else {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = fmt.Sprintf(
			"No SSRF indicators detected across %d tests",
			testedCount,
		)
	}

	check.Details = toJSON(details)
	return check
}
