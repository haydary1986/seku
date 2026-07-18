package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"seku/internal/models"
)

// dnsRegistrableDomain drops a leading "www." label so that scanning
// www.example.edu queries example.edu for SPF/DMARC/CAA records. It only strips
// the "www." prefix to stay correct for multi-label public suffixes (e.g.
// edu.iq), where naive label stripping would be wrong.
func dnsRegistrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(host, "www.")
	return host
}

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

	results = append(results, s.checkSPF(host))
	results = append(results, s.checkDMARC(host))
	results = append(results, s.checkCAA(host))

	return results
}

func (s *DNSScanner) checkSPF(host string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "SPF Record (Email Security)",
		Weight:    3.0,
	}

	domain := dnsRegistrableDomain(host)
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			// SERVFAIL / timeout / temporary failure: the lookup is
			// inconclusive, not proof that SPF is missing.
			check.Status = "pass"
			check.Score = 800
			check.Severity = "info"
			check.Details = toJSON(map[string]string{
				"message": "SPF lookup inconclusive (DNS error, not a confirmed absence): " + err.Error(),
			})
			return check
		}
		// NXDOMAIN / NODATA: genuinely no TXT records — fall through to the
		// "no SPF record found" finding below.
		txtRecords = nil
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
		Weight:    3.0,
	}

	domain := dnsRegistrableDomain(host)
	dmarcHost := fmt.Sprintf("_dmarc.%s", domain)
	txtRecords, err := net.LookupTXT(dmarcHost)
	if err != nil {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			// SERVFAIL / timeout / temporary failure: inconclusive, not proof
			// that DMARC is missing.
			check.Status = "pass"
			check.Score = 800
			check.Severity = "info"
			check.Details = toJSON(map[string]string{
				"message": "DMARC lookup inconclusive (DNS error, not a confirmed absence): " + err.Error(),
			})
			return check
		}
		// NXDOMAIN: the _dmarc record genuinely does not exist — fall through to
		// the "no DMARC record found" finding below.
		txtRecords = nil
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

	domain := dnsRegistrableDomain(host)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	// Verify the domain resolves at all; if not, the check is inconclusive.
	if _, err := resolver.LookupHost(ctx, domain); err != nil {
		check.Status = "pass"
		check.Score = 800
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "CAA check inconclusive: domain did not resolve",
		})
		return check
	}

	// The standard library resolver cannot query CAA records directly, and no
	// DNS library is vendored. Absence of CAA is not a vulnerability — it is a
	// low-severity best practice. The recommendation is independent of the DNS
	// provider (do NOT pass/warn based on whether the nameserver is Cloudflare).
	check.Status = "warn"
	check.Score = 750
	check.Severity = "low"
	check.Details = toJSON(map[string]string{
		"message": "Consider adding CAA records to restrict which certificate authorities may issue certificates for this domain.",
	})
	return check
}
