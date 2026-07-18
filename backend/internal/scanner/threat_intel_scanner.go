package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"seku/internal/models"
)

type ThreatIntelScanner struct{}

func NewThreatIntelScanner() *ThreatIntelScanner {
	return &ThreatIntelScanner{}
}

func (s *ThreatIntelScanner) Name() string     { return "Threat Intelligence Scanner" }
func (s *ThreatIntelScanner) Category() string { return "threat_intel" }
func (s *ThreatIntelScanner) Weight() float64  { return 8.0 }

func (s *ThreatIntelScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult
	host := extractHost(url)

	results = append(results, s.checkCryptojacking(url))
	results = append(results, s.checkC2Callbacks(url))
	results = append(results, s.checkBlacklists(host))
	results = append(results, s.checkDomainAge(host))

	return results
}

// checkCryptojacking detects resource-intensive crypto mining via WebWorkers, WASM, and resource hints
func (s *ThreatIntelScanner) checkCryptojacking(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Cryptojacking Detection",
		Weight:    2.5,
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: ScanTransport,
	}

	targetURL := ensureHTTPS(url)
	resp, err := client.Get(targetURL)
	if err != nil {
		check.Score = 0
		check.Weight = 0
		check.Status = "error"
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Cannot fetch page for cryptojacking check"})
		return check
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	resp.Body.Close()
	bodyLower := strings.ToLower(string(body))

	threats := []string{}

	// Require an ACTUAL miner signature. Generic JS APIs (WebWorker, WASM,
	// crypto.subtle) plus common words (mine/hash/block/pool) fire on ordinary
	// minified bundles, so those heuristics were removed. Only unambiguous
	// known-miner scripts/domains and a real stratum WebSocket count.
	minerSignatures := []string{
		"coinhive", "coin-hive", "cryptonight", "webminepool",
		"crypto-loot", "cryptoloot", "coinimp", "jsecoin",
		"minero.cc", "cryptonoter", "deepminer", "minexmr", "webmine.pro",
	}
	for _, sig := range minerSignatures {
		if strings.Contains(bodyLower, sig) {
			threats = append(threats, "Known miner signature: "+sig)
		}
	}

	// Real mining WebSocket / stratum handshake to a mining pool endpoint.
	wsPattern := regexp.MustCompile(`(?i)wss?://[^"'\s]*(stratum|xmr|monero|cryptonight|minexmr|coinhive|nanopool|minergate)[^"'\s]*`)
	for _, m := range wsPattern.FindAllString(bodyLower, -1) {
		threats = append(threats, "Mining WebSocket: "+m)
	}

	if len(threats) == 0 {
		check.Score = 1000
		check.Status = "pass"
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "No cryptojacking miner signatures detected"})
	} else {
		// The remaining signatures are unambiguous — any hit is a real finding.
		check.Score = 0
		check.Status = "fail"
		check.Severity = "critical"
		check.Details = toJSON(map[string]interface{}{
			"message": fmt.Sprintf("Cryptojacking miner signature(s) detected: %d", len(threats)),
			"threats": threats,
		})
	}

	return check
}

// checkC2Callbacks checks if the site communicates with known C2 (Command & Control) servers
func (s *ThreatIntelScanner) checkC2Callbacks(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "C2 Server Communication",
		Weight:    2.5,
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: ScanTransport,
	}

	targetURL := ensureHTTPS(url)
	resp, err := client.Get(targetURL)
	if err != nil {
		check.Score = 0
		check.Weight = 0
		check.Status = "error"
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Cannot fetch page for C2 check"})
		return check
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	resp.Body.Close()
	bodyLower := strings.ToLower(string(body))

	threats := []string{}

	// Known C2 communication patterns
	c2Patterns := []struct {
		pattern *regexp.Regexp
		name    string
	}{
		// Beacon/callback patterns
		{regexp.MustCompile(`(?i)(xmlhttprequest|fetch)\s*\([^)]*\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`), "HTTP callback to direct IP address"},
		// Base64 encoded URLs (data exfiltration)
		{regexp.MustCompile(`(?i)(btoa|atob)\s*\([^)]*\)\s*\+.*?(xmlhttprequest|fetch|ajax)`), "Base64 encoded data exfiltration attempt"},
		// Suspicious POST to external domains
		{regexp.MustCompile(`(?i)method\s*[:=]\s*["']post["'].*?(action|url)\s*[:=]\s*["'](https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`), "Form POST to direct IP address"},
		// WebSocket to IP addresses
		{regexp.MustCompile(`(?i)new\s+websocket\s*\(\s*["']wss?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), "WebSocket connection to direct IP"},
		// Dynamic script loading from suspicious sources
		{regexp.MustCompile(`(?i)createelement\s*\(\s*["']script["']\s*\).*?src\s*=\s*["'](https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`), "Dynamic script loading from direct IP"},
	}

	for _, c2 := range c2Patterns {
		if matches := c2.pattern.FindAllString(bodyLower, -1); len(matches) > 0 {
			threats = append(threats, fmt.Sprintf("%s (%d instances)", c2.name, len(matches)))
		}
	}

	// Known-malicious C2 framework indicators only. Generic filenames
	// (upload.php, connect.php, beacon.js, cmd.php, shell.php) and the standard
	// Let's Encrypt path (/.well-known/acme-challenge/) were removed: they are
	// benign on ordinary sites and produced false positives.
	c2Frameworks := []struct {
		indicator string
		name      string
	}{
		{"cobaltstrike", "Cobalt Strike beacon"},
		{"meterpreter", "Meterpreter payload"},
	}

	frameworkHit := false
	for _, fw := range c2Frameworks {
		if strings.Contains(bodyLower, fw.indicator) {
			threats = append(threats, "C2 framework indicator: "+fw.name)
			frameworkHit = true
		}
	}

	// Check for data exfiltration patterns
	exfilPatterns := regexp.MustCompile(`(?i)(document\.cookie|localstorage|sessionstorage)\s*\+.*?(fetch|xmlhttprequest|new\s+image|\.src\s*=)`)
	if matches := exfilPatterns.FindAllString(bodyLower, -1); len(matches) > 0 {
		threats = append(threats, fmt.Sprintf("Data exfiltration pattern detected: %d instances", len(matches)))
	}

	switch {
	case len(threats) == 0:
		check.Score = 1000
		check.Status = "pass"
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "No C2 communication indicators detected"})
	case frameworkHit || len(threats) >= 3:
		// A known-malicious framework signature, or several corroborating
		// heuristic indicators, is a real finding.
		check.Score = 0
		check.Status = "fail"
		check.Severity = "critical"
		check.Details = toJSON(map[string]interface{}{
			"message": fmt.Sprintf("C2 communication indicators (high confidence): %d", len(threats)),
			"threats": threats,
		})
	default:
		// One or two heuristic-only indicators (e.g. a fetch to a raw IP) are
		// not sufficient evidence of C2 — report informationally, do not fail.
		check.Score = 800
		check.Status = "pass"
		check.Severity = "low"
		check.Details = toJSON(map[string]interface{}{
			"message": fmt.Sprintf("Low-confidence heuristic indicator(s), not treated as C2: %d", len(threats)),
			"threats": threats,
		})
	}

	return check
}

// checkBlacklists checks domain against DNS-based blacklists (DNSBL)
func (s *ThreatIntelScanner) checkBlacklists(host string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Blacklist Check",
		Weight:    2.0,
	}

	// Resolve the domain IP first
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		check.Score = 0
		check.Weight = 0
		check.Status = "error"
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Cannot resolve domain IP for blacklist check"})
		return check
	}

	// Get first IPv4
	var ip string
	for _, addr := range ips {
		if v4 := addr.To4(); v4 != nil {
			ip = v4.String()
			break
		}
	}
	if ip == "" {
		check.Score = 800
		check.Status = "pass"
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "No IPv4 address found, skipping DNSBL check"})
		return check
	}

	// Reverse IP for DNSBL lookup
	parts := strings.Split(ip, ".")
	reversed := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]

	// Check against major DNS blacklists
	// Range-based lists were removed: dnsbl-1.uceprotect.net (UCEPROTECT L1) and
	// the SORBS lists (dnsbl.sorbs.net / spam.dnsbl.sorbs.net) list whole ranges
	// / neighbouring IPs, which false-positives on shared or institutional
	// hosting. Only precise, reputable lists remain.
	blacklists := []struct {
		dnsbl string
		name  string
	}{
		{"zen.spamhaus.org", "Spamhaus ZEN"},
		{"bl.spamcop.net", "SpamCop"},
		{"b.barracudacentral.org", "Barracuda"},
		{"cbl.abuseat.org", "CBL (Composite Blocking List)"},
		{"psbl.surriel.com", "PSBL"},
	}

	listed := []string{}
	checked := 0

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	for _, bl := range blacklists {
		query := reversed + "." + bl.dnsbl
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		addrs, err := resolver.LookupHost(ctx, query)
		cancel()

		checked++
		if err == nil && len(addrs) > 0 {
			// Listed! Response typically 127.0.0.x
			for _, addr := range addrs {
				if strings.HasPrefix(addr, "127.") {
					listed = append(listed, fmt.Sprintf("%s (response: %s)", bl.name, addr))
					break
				}
			}
		}
	}

	details := map[string]interface{}{
		"ip":                 ip,
		"blacklists_checked": checked,
		"blacklists_listed":  len(listed),
	}

	switch {
	case len(listed) == 0:
		check.Score = 1000
		check.Status = "pass"
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Not listed on any of %d checked blacklists", checked)
	case len(listed) == 1:
		// A single hit is low-confidence (possible transient/neighbour noise) —
		// report it but do not fail on it.
		check.Score = 700
		check.Status = "warn"
		check.Severity = "low"
		details["message"] = fmt.Sprintf("Listed on 1 of %d blacklists (single low-confidence hit)", checked)
		details["listed_on"] = listed
	case len(listed) >= 3:
		check.Score = 50
		check.Status = "fail"
		check.Severity = "critical"
		details["message"] = fmt.Sprintf("Listed on %d blacklists (out of %d checked)", len(listed), checked)
		details["listed_on"] = listed
	default: // exactly 2 independent reputable-list hits
		check.Score = 300
		check.Status = "fail"
		check.Severity = "high"
		details["message"] = fmt.Sprintf("Listed on %d independent blacklists", len(listed))
		details["listed_on"] = listed
	}

	check.Details = toJSON(details)
	return check
}

// checkDomainAge checks WHOIS-like data using DNS records and domain creation hints
func (s *ThreatIntelScanner) checkDomainAge(host string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Domain Reputation & Age",
		Weight:    1.0,
	}

	// Check SOA record for domain age indicators
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	// Check basic DNS health indicators
	ctx := context.Background()

	// MX records (established domains usually have mail)
	hasMX := false
	mx, err := resolver.LookupMX(ctx, host)
	if err == nil && len(mx) > 0 {
		hasMX = true
	}

	// NS records
	hasNS := false
	ns, err := net.LookupNS(host)
	if err == nil && len(ns) > 0 {
		hasNS = true
	}

	// TXT records (established domains have SPF, DKIM, etc.)
	hasTXT := false
	txtCount := 0
	txt, err := net.LookupTXT(host)
	if err == nil {
		txtCount = len(txt)
		hasTXT = txtCount > 0
	}

	// RDAP/WHOIS via public API (rdap.org)
	domainAge := ""
	registrar := ""
	client := &http.Client{Timeout: 5 * time.Second}
	rdapURL := fmt.Sprintf("https://rdap.org/domain/%s", host)
	rdapResp, err := client.Get(rdapURL)
	if err == nil {
		rdapBody, _ := io.ReadAll(io.LimitReader(rdapResp.Body, 64*1024))
		rdapResp.Body.Close()

		var rdapData map[string]interface{}
		if json.Unmarshal(rdapBody, &rdapData) == nil {
			// Extract registration date
			if events, ok := rdapData["events"].([]interface{}); ok {
				for _, event := range events {
					if e, ok := event.(map[string]interface{}); ok {
						if action, _ := e["eventAction"].(string); action == "registration" {
							if date, _ := e["eventDate"].(string); date != "" {
								domainAge = date
							}
						}
					}
				}
			}

			// Extract registrar
			if entities, ok := rdapData["entities"].([]interface{}); ok {
				for _, entity := range entities {
					if e, ok := entity.(map[string]interface{}); ok {
						if roles, ok := e["roles"].([]interface{}); ok {
							for _, role := range roles {
								if r, _ := role.(string); r == "registrar" {
									if vcards, ok := e["vcardArray"].([]interface{}); ok && len(vcards) > 1 {
										if entries, ok := vcards[1].([]interface{}); ok {
											for _, entry := range entries {
												if arr, ok := entry.([]interface{}); ok && len(arr) >= 4 {
													if name, _ := arr[0].(string); name == "fn" {
														if val, _ := arr[3].(string); val != "" {
															registrar = val
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// A resolvable domain is presumed legitimate: start from a neutral-good
	// base. MX is NOT required for a website, and missing RDAP data (common for
	// .iq / .edu.iq) must not dock the score — the age component is only applied
	// when RDAP actually returns a registration date.
	score := 900.0
	indicators := []string{}

	if hasMX {
		score += 30
		indicators = append(indicators, "Has MX records (email configured)")
	}
	if hasNS {
		score += 30
		indicators = append(indicators, fmt.Sprintf("Has NS records (%d nameservers)", len(ns)))
	}
	if hasTXT {
		score += 40
		indicators = append(indicators, fmt.Sprintf("Has TXT records (%d records - SPF/DKIM/etc.)", txtCount))
	}
	if domainAge != "" {
		// Parse age
		t, err := time.Parse(time.RFC3339, domainAge)
		if err == nil {
			years := time.Since(t).Hours() / 24 / 365
			switch {
			case years >= 5:
				score += 100
				indicators = append(indicators, fmt.Sprintf("Domain registered: %s (%.0f years - well established)", domainAge[:10], years))
			case years >= 2:
				score += 50
				indicators = append(indicators, fmt.Sprintf("Domain registered: %s (%.0f years)", domainAge[:10], years))
			case years >= 1:
				indicators = append(indicators, fmt.Sprintf("Domain registered: %s (%.0f year)", domainAge[:10], years))
			default:
				// Only a genuinely new domain (RDAP-confirmed) is a negative.
				score -= 200
				indicators = append(indicators, fmt.Sprintf("Domain registered: %s (less than 1 year - new domain)", domainAge[:10]))
			}
		}
	} else {
		indicators = append(indicators, "Registration date unavailable via RDAP (common for .iq/.edu.iq) - treated as neutral")
	}
	if registrar != "" {
		indicators = append(indicators, "Registrar: "+registrar)
	}

	if score > 1000 {
		score = 1000
	}
	if score < 0 {
		score = 0
	}

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"message":    fmt.Sprintf("Domain reputation score: %.0f/1000", score),
		"indicators": indicators,
		"domain":     host,
		"has_mx":     hasMX,
		"has_ns":     hasNS,
		"has_txt":    hasTXT,
		"domain_age": domainAge,
		"registrar":  registrar,
	})

	return check
}
