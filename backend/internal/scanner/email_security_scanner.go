package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

// EmailSecurityScanner checks DKIM, BIMI, and aggregates an email security score.
type EmailSecurityScanner struct{}

func NewEmailSecurityScanner() *EmailSecurityScanner { return &EmailSecurityScanner{} }

func (s *EmailSecurityScanner) Name() string     { return "Email Security Scanner" }
func (s *EmailSecurityScanner) Category() string { return "email_security" }
func (s *EmailSecurityScanner) Weight() float64  { return 8.0 }

// dkimSelectors are common DKIM selectors to check.
var dkimSelectors = []string{"default", "selector1", "google"}

func (s *EmailSecurityScanner) Scan(targetURL string) []models.CheckResult {
	host := extractHost(targetURL)
	return []models.CheckResult{
		s.checkDKIM(host),
		s.checkBIMI(host),
		s.checkEmailSecurityScore(host),
	}
}

// checkDKIM looks up DKIM TXT records for common selectors.
func (s *EmailSecurityScanner) checkDKIM(host string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "DKIM Record",
		Weight:    3.0,
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	type selectorResult struct {
		Selector string `json:"selector"`
		Found    bool   `json:"found"`
		Record   string `json:"record,omitempty"`
	}

	var results []selectorResult
	dkimFound := false
	foundRecord := ""

	for _, sel := range dkimSelectors {
		dkimHost := fmt.Sprintf("%s._domainkey.%s", sel, host)
		txtRecords, err := resolver.LookupTXT(context.Background(), dkimHost)
		if err != nil {
			results = append(results, selectorResult{Selector: sel, Found: false})
			continue
		}

		selFound := false
		for _, txt := range txtRecords {
			if strings.Contains(strings.ToLower(txt), "v=dkim1") {
				selFound = true
				dkimFound = true
				foundRecord = txt
				results = append(results, selectorResult{
					Selector: sel,
					Found:    true,
					Record:   txt,
				})
				break
			}
		}
		if !selFound {
			results = append(results, selectorResult{Selector: sel, Found: false})
		}
	}

	details := map[string]interface{}{
		"selectors_checked": results,
	}

	if dkimFound {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "DKIM record found"
		details["record"] = foundRecord
	} else {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "high"
		details["message"] = "No DKIM record found for any common selector"
		details["recommendation"] = "Configure DKIM signing for your email domain to prevent email spoofing"
	}

	check.Details = toJSON(details)
	return check
}

// checkBIMI looks up BIMI TXT records.
func (s *EmailSecurityScanner) checkBIMI(host string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "BIMI Record",
		Weight:    2.0,
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	bimiHost := fmt.Sprintf("default._bimi.%s", host)
	txtRecords, err := resolver.LookupTXT(context.Background(), bimiHost)

	details := map[string]interface{}{}

	if err != nil {
		check.Status = "warn"
		check.Score = 500
		check.Severity = "low"
		details["message"] = "No BIMI record found"
		details["recommendation"] = "Consider adding a BIMI record to display your brand logo in email clients"
		check.Details = toJSON(details)
		return check
	}

	bimiFound := false
	bimiRecord := ""
	for _, txt := range txtRecords {
		if strings.Contains(strings.ToLower(txt), "v=bimi1") {
			bimiFound = true
			bimiRecord = txt
			break
		}
	}

	if bimiFound {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "BIMI record found"
		details["record"] = bimiRecord
	} else {
		check.Status = "warn"
		check.Score = 500
		check.Severity = "low"
		details["message"] = "BIMI DNS entry exists but no valid BIMI record found"
		details["recommendation"] = "Ensure the BIMI record contains 'v=BIMI1' and a valid logo URL"
	}

	check.Details = toJSON(details)
	return check
}

// checkEmailSecurityScore aggregates SPF + DKIM + DMARC + BIMI into an overall score.
// SPF and DMARC are already checked in dns_scanner.go, so this check performs
// its own lookups for the aggregate view.
func (s *EmailSecurityScanner) checkEmailSecurityScore(host string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Email Security Score",
		Weight:    3.0,
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	type componentScore struct {
		Name   string  `json:"name"`
		Found  bool    `json:"found"`
		Score  float64 `json:"score"`
		Detail string  `json:"detail"`
	}

	var components []componentScore
	totalScore := 0.0
	maxPossible := 4.0 // SPF + DKIM + DMARC + BIMI

	// 1. Check SPF
	spfFound := false
	txtRecords, err := resolver.LookupTXT(context.Background(), host)
	if err == nil {
		for _, txt := range txtRecords {
			if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
				spfFound = true
				break
			}
		}
	}
	if spfFound {
		totalScore++
		components = append(components, componentScore{Name: "SPF", Found: true, Score: 1, Detail: "SPF record configured"})
	} else {
		components = append(components, componentScore{Name: "SPF", Found: false, Score: 0, Detail: "No SPF record found"})
	}

	// 2. Check DKIM
	dkimFound := false
	for _, sel := range dkimSelectors {
		dkimHost := fmt.Sprintf("%s._domainkey.%s", sel, host)
		dkimRecords, err := resolver.LookupTXT(context.Background(), dkimHost)
		if err != nil {
			continue
		}
		for _, txt := range dkimRecords {
			if strings.Contains(strings.ToLower(txt), "v=dkim1") {
				dkimFound = true
				break
			}
		}
		if dkimFound {
			break
		}
	}
	if dkimFound {
		totalScore++
		components = append(components, componentScore{Name: "DKIM", Found: true, Score: 1, Detail: "DKIM record configured"})
	} else {
		components = append(components, componentScore{Name: "DKIM", Found: false, Score: 0, Detail: "No DKIM record found"})
	}

	// 3. Check DMARC
	dmarcFound := false
	dmarcHost := fmt.Sprintf("_dmarc.%s", host)
	dmarcRecords, err := resolver.LookupTXT(context.Background(), dmarcHost)
	if err == nil {
		for _, txt := range dmarcRecords {
			if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
				dmarcFound = true
				break
			}
		}
	}
	if dmarcFound {
		totalScore++
		components = append(components, componentScore{Name: "DMARC", Found: true, Score: 1, Detail: "DMARC record configured"})
	} else {
		components = append(components, componentScore{Name: "DMARC", Found: false, Score: 0, Detail: "No DMARC record found"})
	}

	// 4. Check BIMI
	bimiFound := false
	bimiHost := fmt.Sprintf("default._bimi.%s", host)
	bimiRecords, err := resolver.LookupTXT(context.Background(), bimiHost)
	if err == nil {
		for _, txt := range bimiRecords {
			if strings.Contains(strings.ToLower(txt), "v=bimi1") {
				bimiFound = true
				break
			}
		}
	}
	if bimiFound {
		totalScore++
		components = append(components, componentScore{Name: "BIMI", Found: true, Score: 1, Detail: "BIMI record configured"})
	} else {
		components = append(components, componentScore{Name: "BIMI", Found: false, Score: 0, Detail: "No BIMI record found"})
	}

	// Calculate overall score on 0-1000 scale
	overallScore := (totalScore / maxPossible) * MaxScore

	check.Score = overallScore
	check.Status = statusFromScore(overallScore)
	check.Severity = severityFromScore(overallScore)

	details := map[string]interface{}{
		"message": fmt.Sprintf(
			"Email security: %d/%d components configured (SPF, DKIM, DMARC, BIMI)",
			int(totalScore), int(maxPossible),
		),
		"components":    components,
		"overall_score": overallScore,
	}

	if totalScore < maxPossible {
		var missing []string
		for _, c := range components {
			if !c.Found {
				missing = append(missing, c.Name)
			}
		}
		details["recommendation"] = fmt.Sprintf("Configure missing email security records: %s", strings.Join(missing, ", "))
	}

	check.Details = toJSON(details)
	return check
}
