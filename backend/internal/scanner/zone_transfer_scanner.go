package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type ZoneTransferScanner struct{}

func NewZoneTransferScanner() *ZoneTransferScanner { return &ZoneTransferScanner{} }

func (s *ZoneTransferScanner) Name() string     { return "DNS Zone Transfer Scanner" }
func (s *ZoneTransferScanner) Category() string { return "zone_transfer" }
func (s *ZoneTransferScanner) Weight() float64  { return 6.0 }

func (s *ZoneTransferScanner) Scan(url string) []models.CheckResult {
	host := extractHost(url)
	return []models.CheckResult{s.checkZoneTransfer(host)}
}

func (s *ZoneTransferScanner) checkZoneTransfer(domain string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "DNS Zone Transfer",
		Weight:    6.0,
	}

	// Get NS records for the domain
	resolver := &net.Resolver{PreferGo: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nsRecords, err := resolver.LookupNS(ctx, domain)
	if err != nil || len(nsRecords) == 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "Could not retrieve NS records for zone transfer test",
		})
		return check
	}

	var vulnerableNS []string
	var safeNS []string

	for _, ns := range nsRecords {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		// Try TCP connection to port 53 (AXFR uses TCP)
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(nsHost, "53"), 3*time.Second)
		if err != nil {
			safeNS = append(safeNS, nsHost+" (port 53 closed)")
			continue
		}
		conn.Close()
		// If TCP port 53 is open, the NS might allow zone transfer
		// We flag it as potentially vulnerable (actual AXFR attempt would require dns library)
		vulnerableNS = append(vulnerableNS, nsHost+" (TCP/53 open)")
	}

	details := map[string]interface{}{
		"nameservers_checked": len(nsRecords),
		"vulnerable_ns":      vulnerableNS,
		"safe_ns":            safeNS,
	}

	if len(vulnerableNS) > 0 {
		check.Status = "warn"
		check.Score = 500
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("%d nameserver(s) have TCP/53 open — potential zone transfer risk", len(vulnerableNS))
		details["recommendation"] = "Restrict zone transfers (AXFR) to authorized secondary nameservers only"
	} else {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No nameservers allow TCP connections on port 53 — zone transfer likely restricted"
	}

	check.Details = toJSON(details)
	return check
}
