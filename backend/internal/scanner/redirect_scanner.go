package scanner

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"seku/internal/models"
)

// RedirectScanner detects open redirect vulnerabilities.
type RedirectScanner struct{}

func NewRedirectScanner() *RedirectScanner { return &RedirectScanner{} }

func (s *RedirectScanner) Name() string     { return "Open Redirect Scanner" }
func (s *RedirectScanner) Category() string { return "open_redirect" }
func (s *RedirectScanner) Weight() float64  { return 7.0 }

// redirectParams are common URL parameters used for redirects.
var redirectParams = []string{
	"url", "redirect", "next", "return", "returnTo", "goto",
	"dest", "destination", "redir", "redirect_uri", "continue",
	"target", "link", "out",
}

const evilRedirectTarget = "https://evil.example.com"

func (s *RedirectScanner) Scan(targetURL string) []models.CheckResult {
	return []models.CheckResult{
		s.checkOpenRedirect(targetURL),
	}
}

func (s *RedirectScanner) checkOpenRedirect(targetURL string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Open Redirect Test",
		Weight:    s.Weight(),
	}

	client := NewScanClientNoRedirect(10 * time.Second)
	baseURL := ensureHTTPS(targetURL)

	type finding struct {
		Parameter string `json:"parameter"`
		Location  string `json:"location"`
		Status    int    `json:"status_code"`
	}

	var findings []finding
	testedCount := 0

	for _, param := range redirectParams {
		testURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(evilRedirectTarget))
		testedCount++

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check for redirect status codes (301, 302, 303, 307, 308)
		if resp.StatusCode >= 301 && resp.StatusCode <= 308 {
			location := resp.Header.Get("Location")
			if strings.Contains(strings.ToLower(location), "evil.example.com") {
				findings = append(findings, finding{
					Parameter: param,
					Location:  location,
					Status:    resp.StatusCode,
				})
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
			"Open redirect vulnerability found in %d parameter(s)",
			len(findings),
		)
		details["vulnerable_parameters"] = findings
		details["recommendation"] = "Validate and whitelist all redirect URLs; never redirect to user-supplied external URLs"
	} else {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = fmt.Sprintf(
			"No open redirect detected across %d parameters",
			testedCount,
		)
	}

	check.Details = toJSON(details)
	return check
}
