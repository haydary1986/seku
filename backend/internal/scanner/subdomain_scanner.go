package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vscan-mohesr/internal/models"
	"vscan-mohesr/internal/utils"
)

type SubdomainScanner struct{}

func NewSubdomainScanner() *SubdomainScanner {
	return &SubdomainScanner{}
}

func (s *SubdomainScanner) Name() string     { return "Subdomain Discovery Scanner" }
func (s *SubdomainScanner) Category() string { return "subdomains" }
func (s *SubdomainScanner) Weight() float64  { return 5.0 }

// cloudflareRanges contains known Cloudflare IP prefixes for detection.
var cloudflareRanges = []string{
	"103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.",
	"104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
	"104.24.", "104.25.", "104.26.", "104.27.", "108.162.", "131.0.72.",
	"141.101.", "162.158.", "172.64.", "172.65.", "172.66.", "172.67.",
	"173.245.", "188.114.", "190.93.", "197.234.", "198.41.",
}

// discoveredSubdomain holds the result of a subdomain probe.
type discoveredSubdomain struct {
	Subdomain    string   `json:"subdomain"`
	IPs          []string `json:"ips"`
	HasHTTPS     bool     `json:"has_https"`
	CNAME        string   `json:"cname,omitempty"`
	IsCloudflare bool     `json:"is_cloudflare"`
}

func (s *SubdomainScanner) Scan(url string) []models.CheckResult {
	host := extractHost(url)
	found := s.enumerateSubdomains(host)

	results := []models.CheckResult{
		s.checkSubdomainEnumeration(found),
		s.checkSubdomainSecurity(found),
		s.checkDanglingDNS(host, found),
	}

	// Run individual security scan for each discovered subdomain
	results = append(results, s.scanIndividualSubdomains(found)...)

	return results
}

func (s *SubdomainScanner) enumerateSubdomains(baseDomain string) []discoveredSubdomain {
	// Phase 1: Collect subdomain names from multiple free API sources in parallel.
	// Use cache (24h TTL) to avoid hammering external APIs on repeated scans.
	cacheKey := "subdomains:" + baseDomain
	candidates := make(map[string]struct{})

	if cached := utils.SubdomainCache.Get(cacheKey); cached != nil {
		if cachedList, ok := cached.([]string); ok {
			for _, sub := range cachedList {
				candidates[sub] = struct{}{}
			}
		}
	}

	if len(candidates) == 0 {
		var mu sync.Mutex
		var wg sync.WaitGroup

		// Launch all API sources concurrently
		sources := []func(string) []string{
			s.fetchCrtSh,
			s.fetchHackerTarget,
			s.fetchAlienVaultOTX,
			s.fetchRapidDNS,
			s.fetchWebArchive,
		}
		for _, fetchFn := range sources {
			wg.Add(1)
			go func(fn func(string) []string) {
				defer wg.Done()
				subs := fn(baseDomain)
				mu.Lock()
				for _, sub := range subs {
					candidates[sub] = struct{}{}
				}
				mu.Unlock()
			}(fetchFn)
		}
		wg.Wait()

		// Cache the collected subdomain names for 24 hours
		var cachedList []string
		for sub := range candidates {
			cachedList = append(cachedList, sub)
		}
		utils.SubdomainCache.Set(cacheKey, cachedList, 24*time.Hour)
	}

	// Phase 2: DNS-resolve and probe each candidate
	var (
		mu2   sync.Mutex
		found []discoveredSubdomain
		sem   = make(chan struct{}, 20) // max 20 concurrent lookups
	)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	var wg2 sync.WaitGroup
	for fqdn := range candidates {
		wg2.Add(1)
		sem <- struct{}{}
		go func(fqdn string) {
			defer wg2.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			ips, err := resolver.LookupHost(ctx, fqdn)
			if err != nil || len(ips) == 0 {
				return
			}

			sub := discoveredSubdomain{
				Subdomain:    fqdn,
				IPs:          ips,
				IsCloudflare: isCloudflareIP(ips),
			}

			// Check CNAME
			cname, err := resolver.LookupCNAME(ctx, fqdn)
			if err == nil && cname != "" && cname != fqdn+"." {
				sub.CNAME = strings.TrimSuffix(cname, ".")
			}

			// Check HTTPS
			sub.HasHTTPS = s.probeHTTPS(fqdn)

			mu2.Lock()
			found = append(found, sub)
			mu2.Unlock()
		}(fqdn)
	}

	wg2.Wait()
	return found
}

// isCloudflareIP checks if any of the IPs belong to Cloudflare.
func isCloudflareIP(ips []string) bool {
	for _, ip := range ips {
		for _, prefix := range cloudflareRanges {
			if strings.HasPrefix(ip, prefix) {
				return true
			}
		}
	}
	return false
}

// fetchCrtSh queries Certificate Transparency logs via crt.sh to discover
// real subdomains that have been issued SSL certificates.
func (s *SubdomainScanner) fetchCrtSh(baseDomain string) []string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://crt.sh/?q=%25." + baseDomain + "&output=json")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB limit
	if err != nil {
		return nil
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var results []string
	for _, entry := range entries {
		// name_value can contain multiple names separated by newlines
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			// Skip wildcards and the base domain itself
			if name == "" || strings.HasPrefix(name, "*.") || name == baseDomain {
				continue
			}
			// Must be a subdomain of the base domain
			if !strings.HasSuffix(name, "."+baseDomain) {
				continue
			}
			if _, exists := seen[name]; exists {
				continue
			}
			seen[name] = struct{}{}
			results = append(results, name)
		}
	}
	return results
}

// fetchHackerTarget queries the HackerTarget free API for subdomains.
func (s *SubdomainScanner) fetchHackerTarget(baseDomain string) []string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://api.hackertarget.com/hostsearch/?q=" + baseDomain)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var results []string
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ",", 2)
		if len(parts) == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		if name == "" || name == baseDomain {
			continue
		}
		if !strings.HasSuffix(name, "."+baseDomain) {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		results = append(results, name)
	}
	return results
}

// fetchAlienVaultOTX queries AlienVault OTX for passive DNS subdomain data.
func (s *SubdomainScanner) fetchAlienVaultOTX(baseDomain string) []string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://otx.alienvault.com/api/v1/indicators/domain/" + baseDomain + "/passive_dns")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil
	}

	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var results []string
	for _, entry := range data.PassiveDNS {
		name := strings.ToLower(strings.TrimSpace(entry.Hostname))
		if name == "" || name == baseDomain || !strings.HasSuffix(name, "."+baseDomain) {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		results = append(results, name)
	}
	return results
}

// fetchRapidDNS queries rapiddns.io for subdomains.
func (s *SubdomainScanner) fetchRapidDNS(baseDomain string) []string {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://rapiddns.io/subdomain/"+baseDomain+"?full=1", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Seku/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil
	}

	// Parse HTML table rows — extract subdomain names matching the domain
	content := string(body)
	seen := make(map[string]struct{})
	var results []string

	// Simple extraction: find all occurrences of subdomains in the HTML
	suffix := "." + baseDomain
	for _, word := range strings.Fields(content) {
		// Strip HTML tags
		word = strings.TrimLeft(word, "<>")
		word = strings.TrimRight(word, "<>/")
		if idx := strings.Index(word, ">"); idx >= 0 {
			word = word[idx+1:]
		}
		if idx := strings.Index(word, "<"); idx >= 0 {
			word = word[:idx]
		}
		word = strings.ToLower(strings.TrimSpace(word))
		if !strings.HasSuffix(word, suffix) || word == baseDomain {
			continue
		}
		// Basic validation: only alphanumeric, dots, hyphens
		valid := true
		for _, ch := range word {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		if _, exists := seen[word]; exists {
			continue
		}
		seen[word] = struct{}{}
		results = append(results, word)
	}
	return results
}

// fetchWebArchive queries the Wayback Machine's CDX API for subdomains.
func (s *SubdomainScanner) fetchWebArchive(baseDomain string) []string {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get("https://web.archive.org/cdx/search/cdx?url=*." + baseDomain + "&output=json&fl=original&collapse=urlkey&limit=500")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var results []string
	suffix := "." + baseDomain
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		rawURL := strings.ToLower(row[0])
		// Extract host from URL
		rawURL = strings.TrimPrefix(rawURL, "https://")
		rawURL = strings.TrimPrefix(rawURL, "http://")
		host := strings.SplitN(rawURL, "/", 2)[0]
		host = strings.SplitN(host, ":", 2)[0] // remove port
		host = strings.TrimSpace(host)

		if host == "" || host == baseDomain || !strings.HasSuffix(host, suffix) {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		results = append(results, host)
	}
	return results
}

func (s *SubdomainScanner) probeHTTPS(host string) bool {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("https://" + host)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func (s *SubdomainScanner) checkSubdomainEnumeration(found []discoveredSubdomain) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Common Subdomain Enumeration",
		Weight:    2.0,
	}

	count := len(found)
	details := map[string]interface{}{
		"subdomains_found": count,
		"subdomains":       found,
	}

	switch {
	case count <= 5:
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Small attack surface: %d subdomains discovered", count)
	case count <= 15:
		check.Status = "pass"
		check.Score = 800
		check.Severity = "low"
		details["message"] = fmt.Sprintf("Moderate attack surface: %d subdomains discovered", count)
	case count <= 30:
		check.Status = "warn"
		check.Score = 600
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Large attack surface: %d subdomains discovered", count)
	default:
		check.Status = "warn"
		check.Score = 400
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Very large attack surface: %d subdomains discovered", count)
	}

	check.Details = toJSON(details)
	return check
}

func (s *SubdomainScanner) checkSubdomainSecurity(found []discoveredSubdomain) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Subdomain Security Check",
		Weight:    2.0,
	}

	if len(found) == 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No subdomains to check for HTTPS",
		})
		return check
	}

	httpsCount := 0
	var withHTTPS, withoutHTTPS []string
	for _, sub := range found {
		if sub.HasHTTPS {
			httpsCount++
			withHTTPS = append(withHTTPS, sub.Subdomain)
		} else {
			withoutHTTPS = append(withoutHTTPS, sub.Subdomain)
		}
	}

	total := len(found)
	ratio := float64(httpsCount) / float64(total)
	details := map[string]interface{}{
		"checked":       total,
		"https_count":   httpsCount,
		"https_ratio":   fmt.Sprintf("%.0f%%", ratio*100),
		"with_https":    withHTTPS,
		"without_https": withoutHTTPS,
	}

	switch {
	case ratio >= 1.0:
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "All checked subdomains support HTTPS"
	case ratio >= 0.8:
		check.Status = "pass"
		check.Score = 800
		check.Severity = "low"
		details["message"] = fmt.Sprintf("%.0f%% of checked subdomains support HTTPS", ratio*100)
	case ratio >= 0.5:
		check.Status = "warn"
		check.Score = 600
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Only %.0f%% of checked subdomains support HTTPS", ratio*100)
	default:
		check.Status = "fail"
		check.Score = 300
		check.Severity = "high"
		details["message"] = fmt.Sprintf("Only %.0f%% of checked subdomains support HTTPS", ratio*100)
	}

	check.Details = toJSON(details)
	return check
}

// takeoverTargets lists CNAME suffixes that are known to be vulnerable to subdomain takeover.
var takeoverTargets = []string{
	".github.io",
	".herokuapp.com",
	".s3.amazonaws.com",
	".azurewebsites.net",
	".cloudfront.net",
	".shopify.com",
	".ghost.io",
	".pantheon.io",
	".zendesk.com",
	".surge.sh",
	".bitbucket.io",
	".wordpress.com",
	".tumblr.com",
	".flywheel.com",
}

func (s *SubdomainScanner) checkDanglingDNS(baseDomain string, found []discoveredSubdomain) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Dangling DNS / Subdomain Takeover Risk",
		Weight:    1.0,
	}

	if len(found) == 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No subdomains to check for takeover risk",
		})
		return check
	}

	var potentialTakeovers []map[string]string
	var safeCNAMEs []string

	for _, sub := range found {
		if sub.CNAME == "" {
			continue
		}

		cnameLower := strings.ToLower(sub.CNAME)
		for _, target := range takeoverTargets {
			if strings.HasSuffix(cnameLower, target) {
				// CNAME points to a takeover-vulnerable service; check if it returns 404
				is404 := s.probeReturns404(sub.Subdomain)
				if is404 {
					potentialTakeovers = append(potentialTakeovers, map[string]string{
						"subdomain": sub.Subdomain,
						"cname":     sub.CNAME,
						"status":    "potential_takeover",
					})
				} else {
					safeCNAMEs = append(safeCNAMEs, sub.Subdomain+" -> "+sub.CNAME)
				}
				break
			}
		}
	}

	details := map[string]interface{}{}

	switch {
	case len(potentialTakeovers) > 0:
		check.Status = "fail"
		check.Score = 100
		check.Severity = "critical"
		details["message"] = fmt.Sprintf(
			"%d subdomain(s) potentially vulnerable to takeover",
			len(potentialTakeovers),
		)
		details["potential_takeovers"] = potentialTakeovers
		if len(safeCNAMEs) > 0 {
			details["safe_cnames"] = safeCNAMEs
		}
	case len(safeCNAMEs) > 0:
		check.Status = "pass"
		check.Score = 800
		check.Severity = "low"
		details["message"] = "CNAMEs to external services found but all services respond correctly"
		details["cnames"] = safeCNAMEs
	default:
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No dangerous CNAME records detected"
	}

	check.Details = toJSON(details)
	return check
}

// probeReturns404 checks whether the given host returns a 404 via HTTP or HTTPS.
func (s *SubdomainScanner) probeReturns404(host string) bool {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Try HTTPS first, then HTTP
	for _, scheme := range []string{"https://", "http://"} {
		resp, err := client.Get(scheme + host)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 404 {
			return true
		}
		return false
	}
	// If neither scheme could be reached, treat as potentially dangling
	return true
}

// scanIndividualSubdomains runs a lightweight security scan on each discovered
// subdomain and returns one CheckResult per subdomain with its findings.
func (s *SubdomainScanner) scanIndividualSubdomains(found []discoveredSubdomain) []models.CheckResult {
	if len(found) == 0 {
		return nil
	}

	var (
		mu      sync.Mutex
		results []models.CheckResult
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 10) // max 10 concurrent scans
	)

	for _, sub := range found {
		wg.Add(1)
		sem <- struct{}{}
		go func(sub discoveredSubdomain) {
			defer wg.Done()
			defer func() { <-sem }()

			check := s.scanOneSubdomain(sub)
			mu.Lock()
			results = append(results, check)
			mu.Unlock()
		}(sub)
	}

	wg.Wait()
	return results
}

// scanOneSubdomain performs a lightweight security assessment of a single subdomain.
func (s *SubdomainScanner) scanOneSubdomain(sub discoveredSubdomain) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: fmt.Sprintf("Subdomain Scan: %s", sub.Subdomain),
		Weight:    0.5,
	}

	findings := map[string]interface{}{
		"subdomain": sub.Subdomain,
		"ips":       sub.IPs,
		"has_https":    sub.HasHTTPS,
		"is_cloudflare": sub.IsCloudflare,
	}
	if sub.CNAME != "" {
		findings["cname"] = sub.CNAME
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Try HTTPS first, then HTTP
	var resp *http.Response
	var scheme string
	var err error
	for _, s := range []string{"https://", "http://"} {
		resp, err = client.Get(s + sub.Subdomain)
		if err == nil {
			scheme = s
			break
		}
	}

	if err != nil || resp == nil {
		check.Status = "warn"
		check.Score = 500
		check.Severity = "medium"
		findings["status"] = "unreachable"
		findings["message"] = "Subdomain resolved in DNS but is not reachable via HTTP/HTTPS"
		check.Details = toJSON(findings)
		return check
	}
	defer resp.Body.Close()

	findings["scheme"] = strings.TrimSuffix(scheme, "://")
	findings["status_code"] = resp.StatusCode

	// ---- Collect security header findings ----
	var issues []string
	var good []string

	headers := resp.Header

	// Server header (information disclosure)
	if server := headers.Get("Server"); server != "" {
		findings["server"] = server
		issues = append(issues, "Server header exposes software: "+server)
	}

	// X-Powered-By (information disclosure)
	if powered := headers.Get("X-Powered-By"); powered != "" {
		findings["x_powered_by"] = powered
		issues = append(issues, "X-Powered-By header exposes technology: "+powered)
	}

	// HSTS
	if hsts := headers.Get("Strict-Transport-Security"); hsts != "" {
		findings["hsts"] = hsts
		good = append(good, "HSTS is enabled")
	} else if scheme == "https://" {
		issues = append(issues, "Missing Strict-Transport-Security header")
	}

	// Content-Security-Policy
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		findings["csp"] = true
		good = append(good, "Content-Security-Policy is set")
	} else {
		issues = append(issues, "Missing Content-Security-Policy header")
	}

	// X-Frame-Options
	if xfo := headers.Get("X-Frame-Options"); xfo != "" {
		findings["x_frame_options"] = xfo
		good = append(good, "X-Frame-Options: "+xfo)
	} else {
		issues = append(issues, "Missing X-Frame-Options header (clickjacking risk)")
	}

	// X-Content-Type-Options
	if xcto := headers.Get("X-Content-Type-Options"); xcto != "" {
		findings["x_content_type_options"] = xcto
		good = append(good, "X-Content-Type-Options: "+xcto)
	} else {
		issues = append(issues, "Missing X-Content-Type-Options header")
	}

	// Check SSL certificate
	if scheme == "https://" {
		tlsInfo := s.checkSubdomainTLS(sub.Subdomain)
		for k, v := range tlsInfo {
			findings[k] = v
		}
		if tlsInfo["tls_valid"] == false {
			issues = append(issues, fmt.Sprintf("SSL/TLS issue: %v", tlsInfo["tls_error"]))
		} else {
			good = append(good, "Valid SSL/TLS certificate")
		}
	} else {
		issues = append(issues, "Not using HTTPS")
	}

	findings["issues"] = issues
	findings["good"] = good
	findings["issues_count"] = len(issues)
	findings["good_count"] = len(good)

	// Score based on issue count
	issueCount := len(issues)
	switch {
	case issueCount == 0:
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		findings["message"] = fmt.Sprintf("%s: All security checks passed", sub.Subdomain)
	case issueCount <= 2:
		check.Status = "pass"
		check.Score = 750
		check.Severity = "low"
		findings["message"] = fmt.Sprintf("%s: %d minor issue(s) found", sub.Subdomain, issueCount)
	case issueCount <= 4:
		check.Status = "warn"
		check.Score = 500
		check.Severity = "medium"
		findings["message"] = fmt.Sprintf("%s: %d issue(s) found", sub.Subdomain, issueCount)
	default:
		check.Status = "fail"
		check.Score = 250
		check.Severity = "high"
		findings["message"] = fmt.Sprintf("%s: %d issue(s) found — needs attention", sub.Subdomain, issueCount)
	}

	check.Details = toJSON(findings)
	return check
}

// checkSubdomainTLS checks the TLS certificate of a subdomain.
func (s *SubdomainScanner) checkSubdomainTLS(host string) map[string]interface{} {
	result := map[string]interface{}{}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp", host+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		result["tls_valid"] = false
		result["tls_error"] = err.Error()
		return result
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		result["tls_valid"] = false
		result["tls_error"] = "no certificates presented"
		return result
	}

	cert := certs[0]
	now := time.Now()

	result["tls_issuer"] = cert.Issuer.CommonName
	result["tls_expires"] = cert.NotAfter.Format("2006-01-02")
	result["tls_valid"] = now.Before(cert.NotAfter) && now.After(cert.NotBefore)

	if now.After(cert.NotAfter) {
		result["tls_error"] = "certificate expired"
	} else if now.Before(cert.NotBefore) {
		result["tls_error"] = "certificate not yet valid"
	}

	// Check if cert matches the subdomain
	if err := cert.VerifyHostname(host); err != nil {
		result["tls_hostname_match"] = false
		result["tls_hostname_error"] = err.Error()
	} else {
		result["tls_hostname_match"] = true
	}

	return result
}
