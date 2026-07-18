package scanner

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"seku/internal/models"
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

// ssrfSignatures are patterns that specifically indicate a successful SSRF into
// a cloud metadata endpoint. Generic tokens (<html>, <!doctype>, apache, nginx,
// localhost, 127.0.0.1) were removed: they match ANY HTML page, a reflected
// payload, or a WAF block page, producing false criticals whenever the app
// simply ignored the parameter and returned a page of a different size.
var ssrfSignatures = []string{
	"ami-id",
	"instance-id",
	"local-hostname",
	"public-hostname",
	"instance-type",
	"placement/availability-zone",
	"security-credentials",
	"iam/security-credentials",
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

	// Baseline response — any signature already present here is site content,
	// not SSRF evidence.
	baselineBody, _, _ := fetchLowerBody(client, baseURL, 100*1024)
	baselineSigs := signaturesIn(baselineBody, ssrfSignatures)

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

			bodyLower, status, ok := fetchLowerBody(client, testURL, 100*1024)
			if !ok {
				continue
			}
			// A WAF/edge block is not a successful SSRF.
			if isBlockedStatus(status) {
				continue
			}

			// Every remaining signature is cloud-metadata-specific; flag it only
			// when the payload introduced it (absent from baseline).
			for _, sig := range ssrfSignatures {
				if baselineSigs[sig] {
					continue
				}
				if strings.Contains(bodyLower, sig) {
					findings = append(findings, finding{
						Parameter: param,
						Payload:   payload.label,
						Evidence:  fmt.Sprintf("Response contains cloud-metadata field '%s'", sig),
					})
					break
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
