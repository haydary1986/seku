package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"seku/internal/models"
)

type WAFScanner struct{}

func NewWAFScanner() *WAFScanner { return &WAFScanner{} }

func (s *WAFScanner) Name() string     { return "WAF Detection Scanner" }
func (s *WAFScanner) Category() string { return "waf" }
func (s *WAFScanner) Weight() float64  { return 5.0 }

type wafSignature struct {
	Header string
	Value  string
	Name   string
}

var wafSignatures = []wafSignature{
	{"cf-ray", "", "Cloudflare"},
	{"cf-cache-status", "", "Cloudflare"},
	{"server", "cloudflare", "Cloudflare"},
	{"server", "sucuri", "Sucuri"},
	{"x-sucuri", "", "Sucuri"},
	{"server", "akamaighost", "Akamai"},
	{"x-akamai", "", "Akamai"},
	{"x-cdn", "incapsula", "Imperva Incapsula"},
	{"x-iinfo", "", "Imperva Incapsula"},
	{"server", "awselb", "AWS ELB/WAF"},
	{"x-amz-cf", "", "AWS CloudFront"},
	{"server", "bigip", "F5 BIG-IP"},
	{"server", "ddos-guard", "DDoS-Guard"},
	{"server", "barracuda", "Barracuda WAF"},
	{"x-protected-by", "", "Generic WAF"},
}

func (s *WAFScanner) Scan(targetURL string) []models.CheckResult {
	return []models.CheckResult{s.detectWAF(targetURL)}
}

func (s *WAFScanner) detectWAF(targetURL string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "WAF Detection",
		Weight:    5.0,
	}

	client := NewScanClient(10 * time.Second)
	baseURL := ensureHTTPS(targetURL)

	normalResp, err := client.Get(baseURL)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Weight = 0
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Could not reach target for WAF detection"})
		return check
	}
	normalResp.Body.Close()

	var detectedWAFs []string
	detected := map[string]bool{}

	for _, sig := range wafSignatures {
		val := normalResp.Header.Get(sig.Header)
		if val == "" {
			continue
		}
		if sig.Value == "" || strings.Contains(strings.ToLower(val), sig.Value) {
			if !detected[sig.Name] {
				detectedWAFs = append(detectedWAFs, sig.Name)
				detected[sig.Name] = true
			}
		}
	}

	testURL := baseURL + "?test=" + url.QueryEscape("<script>alert(1)</script>")
	req, _ := http.NewRequest("GET", testURL, nil)
	req.Header.Set("User-Agent", RandomUA())
	suspResp, err := client.Do(req)
	blocked := false
	if err == nil {
		suspResp.Body.Close()
		if suspResp.StatusCode == 403 || suspResp.StatusCode == 406 || suspResp.StatusCode == 429 {
			blocked = true
			for _, sig := range wafSignatures {
				val := suspResp.Header.Get(sig.Header)
				if val == "" {
					continue
				}
				if sig.Value == "" || strings.Contains(strings.ToLower(val), sig.Value) {
					if !detected[sig.Name] {
						detectedWAFs = append(detectedWAFs, sig.Name)
						detected[sig.Name] = true
					}
				}
			}
		}
	}

	details := map[string]interface{}{
		"waf_detected":    len(detectedWAFs) > 0 || blocked,
		"waf_products":    detectedWAFs,
		"blocked_payload": blocked,
	}

	if len(detectedWAFs) > 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = fmt.Sprintf("WAF detected: %s", strings.Join(detectedWAFs, ", "))
	} else if blocked {
		check.Status = "pass"
		check.Score = 900
		check.Severity = "info"
		details["message"] = "Unknown WAF detected (blocked suspicious request)"
	} else {
		check.Status = "warn"
		check.Score = 400
		check.Severity = "medium"
		details["message"] = "No WAF detected — website may be directly exposed to attacks"
		details["recommendation"] = "Consider enabling a Web Application Firewall (Cloudflare, AWS WAF, or ModSecurity)"
	}

	check.Details = toJSON(details)
	return check
}
