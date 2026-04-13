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

	"vscan-mohesr/internal/models"
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
		Timeout: 15 * time.Second,
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

	// WebWorker crypto mining
	workerPatterns := []struct {
		pattern string
		name    string
	}{
		{"new worker", "WebWorker instantiation (potential mining worker)"},
		{"importscripts", "Worker importScripts (may load mining script)"},
		{"webassembly.instantiate", "WebAssembly instantiation (potential WASM miner)"},
		{"webassembly.compile", "WebAssembly compilation"},
		{"crypto.subtle", "Web Crypto API usage"},
		{"sharedarraybuffer", "SharedArrayBuffer (used by advanced miners)"},
	}

	for _, wp := range workerPatterns {
		if strings.Contains(bodyLower, wp.pattern) {
			// Check context - these are legitimate APIs, so look for mining-specific context
			idx := strings.Index(bodyLower, wp.pattern)
			start := idx - 100
			if start < 0 {
				start = 0
			}
			end := idx + len(wp.pattern) + 100
			if end > len(bodyLower) {
				end = len(bodyLower)
			}
			context := bodyLower[start:end]

			// Only flag if mining-related keywords are nearby
			miningKeywords := []string{"mine", "hash", "nonce", "block", "stratum", "pool", "monero", "xmr", "cryptonight"}
			for _, kw := range miningKeywords {
				if strings.Contains(context, kw) {
					threats = append(threats, fmt.Sprintf("%s (near '%s')", wp.name, kw))
					break
				}
			}
		}
	}

	// High CPU indicators in meta/headers
	if strings.Contains(bodyLower, "cpu") && strings.Contains(bodyLower, "throttle") {
		threats = append(threats, "CPU throttle references found (mining control)")
	}

	// Known cryptojacking WebSocket patterns
	wsPattern := regexp.MustCompile(`(?i)wss?://[^"'\s]*(mine|pool|hash|stratum|xmr|monero)[^"'\s]*`)
	if matches := wsPattern.FindAllString(bodyLower, -1); len(matches) > 0 {
		for _, m := range matches {
			threats = append(threats, "Mining WebSocket: "+m)
		}
	}

	if len(threats) == 0 {
		check.Score = 1000
		check.Status = "pass"
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "No cryptojacking indicators detected"})
	} else if len(threats) >= 3 {
		check.Score = 0
		check.Status = "fail"
		check.Severity = "critical"
		check.Details = toJSON(map[string]interface{}{
			"message": fmt.Sprintf("Strong cryptojacking indicators: %d", len(threats)),
			"threats": threats,
		})
	} else {
		check.Score = 300
		check.Status = "fail"
		check.Severity = "high"
		check.Details = toJSON(map[string]interface{}{
			"message": fmt.Sprintf("Possible cryptojacking indicators: %d", len(threats)),
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
		Timeout: 15 * time.Second,
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

	// Known C2 framework indicators
	c2Frameworks := []struct {
		indicator string
		name      string
	}{
		{"cobaltstrike", "Cobalt Strike beacon"},
		{"meterpreter", "Meterpreter payload"},
		{"empire", "PowerShell Empire"},
		{"/.well-known/acme-challenge/", "Suspicious ACME challenge abuse"},
		{"beacon.js", "C2 Beacon script"},
		{"shell.php", "PHP Shell reference"},
		{"cmd.php", "Command execution script"},
		{"upload.php", "File upload script"},
		{"connect.php", "Connection script"},
	}

	for _, fw := range c2Frameworks {
		if strings.Contains(bodyLower, fw.indicator) {
			threats = append(threats, "C2 framework indicator: "+fw.name)
		}
	}

	// Check for data exfiltration patterns
	exfilPatterns := regexp.MustCompile(`(?i)(document\.cookie|localstorage|sessionstorage)\s*\+.*?(fetch|xmlhttprequest|new\s+image|\.src\s*=)`)
	if matches := exfilPatterns.FindAllString(bodyLower, -1); len(matches) > 0 {
		threats = append(threats, fmt.Sprintf("Data exfiltration pattern detected: %d instances", len(matches)))
	}

	if len(threats) == 0 {
		check.Score = 1000
		check.Status = "pass"
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "No C2 communication indicators detected"})
	} else if len(threats) >= 3 {
		check.Score = 0
		check.Status = "fail"
		check.Severity = "critical"
		check.Details = toJSON(map[string]interface{}{
			"message": fmt.Sprintf("Multiple C2 communication indicators: %d", len(threats)),
			"threats": threats,
		})
	} else {
		check.Score = 200
		check.Status = "fail"
		check.Severity = "high"
		check.Details = toJSON(map[string]interface{}{
			"message": fmt.Sprintf("C2 communication indicators found: %d", len(threats)),
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
	blacklists := []struct {
		dnsbl string
		name  string
	}{
		{"zen.spamhaus.org", "Spamhaus ZEN"},
		{"bl.spamcop.net", "SpamCop"},
		{"b.barracudacentral.org", "Barracuda"},
		{"dnsbl.sorbs.net", "SORBS"},
		{"spam.dnsbl.sorbs.net", "SORBS Spam"},
		{"cbl.abuseat.org", "CBL (Composite Blocking List)"},
		{"dnsbl-1.uceprotect.net", "UCEPROTECT Level 1"},
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
		"ip":               ip,
		"blacklists_checked": checked,
		"blacklists_listed": len(listed),
	}

	if len(listed) == 0 {
		check.Score = 1000
		check.Status = "pass"
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Not listed on any of %d checked blacklists", checked)
	} else if len(listed) >= 3 {
		check.Score = 50
		check.Status = "fail"
		check.Severity = "critical"
		details["message"] = fmt.Sprintf("Listed on %d blacklists (out of %d checked)", len(listed), checked)
		details["listed_on"] = listed
	} else if len(listed) >= 1 {
		check.Score = 350
		check.Status = "fail"
		check.Severity = "high"
		details["message"] = fmt.Sprintf("Listed on %d blacklist(s)", len(listed))
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

	// Calculate score based on indicators
	score := 500.0 // Base score
	indicators := []string{}

	if hasMX {
		score += 100
		indicators = append(indicators, "Has MX records (email configured)")
	}
	if hasNS {
		score += 50
		indicators = append(indicators, fmt.Sprintf("Has NS records (%d nameservers)", len(ns)))
	}
	if hasTXT {
		score += 50
		indicators = append(indicators, fmt.Sprintf("Has TXT records (%d records - SPF/DKIM/etc.)", txtCount))
	}
	if domainAge != "" {
		// Parse age
		t, err := time.Parse(time.RFC3339, domainAge)
		if err == nil {
			years := time.Since(t).Hours() / 24 / 365
			if years >= 5 {
				score += 250
				indicators = append(indicators, fmt.Sprintf("Domain registered: %s (%.0f years - well established)", domainAge[:10], years))
			} else if years >= 2 {
				score += 150
				indicators = append(indicators, fmt.Sprintf("Domain registered: %s (%.0f years)", domainAge[:10], years))
			} else if years >= 1 {
				score += 50
				indicators = append(indicators, fmt.Sprintf("Domain registered: %s (%.0f year)", domainAge[:10], years))
			} else {
				indicators = append(indicators, fmt.Sprintf("Domain registered: %s (less than 1 year - new domain)", domainAge[:10]))
			}
		}
	}
	if registrar != "" {
		indicators = append(indicators, "Registrar: "+registrar)
	}

	if score > 1000 {
		score = 1000
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
