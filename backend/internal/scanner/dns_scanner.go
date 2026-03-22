package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type DNSScanner struct{}

func NewDNSScanner() *DNSScanner {
	return &DNSScanner{}
}

func (s *DNSScanner) Name() string     { return "DNS Security Scanner" }
func (s *DNSScanner) Category() string { return "dns" }
func (s *DNSScanner) Weight() float64  { return 8.0 }

func (s *DNSScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult
	host := extractHost(url)

	results = append(results, s.checkDNSSEC(host))
	results = append(results, s.checkSPF(host))
	results = append(results, s.checkDMARC(host))
	results = append(results, s.checkCAA(host))

	return results
}

func (s *DNSScanner) checkDNSSEC(host string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "DNSSEC",
		Weight:    2.0,
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	_, err := resolver.LookupHost(context.Background(), host)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "medium"
		check.Details = toJSON(map[string]string{
			"error":   err.Error(),
			"message": "Cannot resolve domain",
		})
		return check
	}

	// Check for DNSKEY record existence via TXT lookup approach
	// Without deep DNSSEC validation, we note DNS resolves but full verification needs external tools
	check.Status = "warn"
	check.Score = 650
	check.Severity = "low"
	check.Details = toJSON(map[string]string{
		"message": "DNS resolves successfully. DNSSEC validation requires external tools for full verification.",
		"host":    host,
	})

	return check
}

func (s *DNSScanner) checkSPF(host string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "SPF Record (Email Security)",
		Weight:    2.0,
	}

	txtRecords, err := net.LookupTXT(host)
	if err != nil {
		check.Status = "warn"
		check.Score = 275
		check.Severity = "high"
		check.Details = toJSON(map[string]string{
			"message": "Cannot lookup TXT records: " + err.Error(),
		})
		return check
	}

	spfFound := false
	spfRecord := ""
	for _, txt := range txtRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			spfFound = true
			spfRecord = txt
			break
		}
	}

	if spfFound {
		details := map[string]string{
			"message": "SPF record found",
			"record":  spfRecord,
		}

		if strings.Contains(spfRecord, "-all") {
			// Strict SPF - best practice
			check.Status = "pass"
			check.Score = 1000
			check.Severity = "info"
			details["policy"] = "Strict (-all): unauthorized senders are rejected"
		} else if strings.Contains(spfRecord, "~all") {
			// Soft fail - decent but not ideal
			check.Status = "warn"
			check.Score = 725
			check.Severity = "low"
			details["policy"] = "Soft fail (~all): unauthorized senders are marked but not rejected"
		} else if strings.Contains(spfRecord, "?all") {
			// Neutral - basically no enforcement
			check.Status = "warn"
			check.Score = 450
			check.Severity = "medium"
			details["policy"] = "Neutral (?all): no enforcement on unauthorized senders"
		} else {
			// Permissive or unclear
			check.Status = "warn"
			check.Score = 525
			check.Severity = "medium"
			details["policy"] = "Permissive: consider using -all for strict enforcement"
		}
		check.Details = toJSON(details)
	} else {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{
			"message": "No SPF record found - emails can be spoofed from this domain",
		})
	}

	return check
}

func (s *DNSScanner) checkDMARC(host string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "DMARC Record (Email Security)",
		Weight:    2.0,
	}

	dmarcHost := fmt.Sprintf("_dmarc.%s", host)
	txtRecords, err := net.LookupTXT(dmarcHost)
	if err != nil {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{
			"message": "No DMARC record found - domain is vulnerable to email spoofing",
		})
		return check
	}

	dmarcFound := false
	dmarcRecord := ""
	for _, txt := range txtRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
			dmarcFound = true
			dmarcRecord = txt
			break
		}
	}

	if dmarcFound {
		details := map[string]string{
			"message": "DMARC record found",
			"record":  dmarcRecord,
		}

		lower := strings.ToLower(dmarcRecord)
		if strings.Contains(lower, "p=reject") {
			// Reject policy - strongest DMARC enforcement
			check.Status = "pass"
			check.Score = 1000
			check.Severity = "info"
			details["policy"] = "Reject: spoofed emails are rejected"
		} else if strings.Contains(lower, "p=quarantine") {
			// Quarantine - good but not the strongest
			check.Status = "pass"
			check.Score = 825
			check.Severity = "info"
			details["policy"] = "Quarantine: spoofed emails are sent to spam"
		} else if strings.Contains(lower, "p=none") {
			// Monitor only - provides visibility but no protection
			check.Status = "warn"
			check.Score = 375
			check.Severity = "medium"
			details["policy"] = "None/Monitor: spoofed emails are not blocked"
		} else {
			// Unknown or missing policy
			check.Status = "warn"
			check.Score = 325
			check.Severity = "medium"
			details["policy"] = "DMARC record present but policy is unclear"
		}
		check.Details = toJSON(details)
	} else {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{
			"message": "No DMARC record found",
		})
	}

	return check
}

func (s *DNSScanner) checkCAA(host string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "CAA Record (Certificate Authority)",
		Weight:    2.0,
	}

	// Go's net package doesn't support CAA directly, use NS lookup as a proxy
	// to verify DNS is working, then provide guidance
	_, err := net.LookupNS(host)
	if err != nil {
		check.Status = "warn"
		check.Score = 525
		check.Severity = "medium"
		check.Details = toJSON(map[string]string{
			"message": "Cannot verify CAA records directly. Consider adding CAA records to restrict which CAs can issue certificates for your domain.",
		})
		return check
	}

	check.Status = "warn"
	check.Score = 675
	check.Severity = "low"
	check.Details = toJSON(map[string]string{
		"message": "DNS is properly configured. Consider adding CAA records (e.g., 0 issue \"letsencrypt.org\") to restrict certificate issuance.",
	})

	return check
}
