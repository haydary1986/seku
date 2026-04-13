package scanner

import (
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"seku/internal/models"
)

type HostingScanner struct{}

func NewHostingScanner() *HostingScanner {
	return &HostingScanner{}
}

func (s *HostingScanner) Name() string     { return "Hosting Quality Scanner" }
func (s *HostingScanner) Category() string { return "hosting" }
func (s *HostingScanner) Weight() float64  { return 12.0 }

func (s *HostingScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	results = append(results, s.checkHTTP2Support(url))
	results = append(results, s.checkHTTP3Support(url))
	results = append(results, s.checkBrotliCompression(url))
	results = append(results, s.checkIPv6Support(url))
	results = append(results, s.checkKeepAlive(url))
	results = append(results, s.checkDNSResolutionTime(url))

	return results
}

// checkHTTP2Support connects via TLS with ALPN to determine HTTP/2 support.
func (s *HostingScanner) checkHTTP2Support(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "HTTP/2 Support",
		Weight:    25,
	}

	host := extractHost(url)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		host+":443",
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		},
	)
	if err != nil {
		check.Score = 0
		check.Status = statusFromScore(0)
		check.Severity = severityFromScore(0)
		check.Details = toJSON(map[string]interface{}{
			"supported_protocol": "none",
			"error":              err.Error(),
			"message":            "TLS connection failed; cannot determine HTTP/2 support",
		})
		return check
	}
	defer conn.Close()

	proto := conn.ConnectionState().NegotiatedProtocol

	var score float64
	switch proto {
	case "h2":
		score = 1000
	case "http/1.1":
		score = 300
	default:
		score = 300
	}

	check.Score = math.Round(score)
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"negotiated_protocol": proto,
		"http2_supported":     proto == "h2",
		"message":             fmt.Sprintf("Negotiated protocol: %s (score: %.0f/1000)", proto, score),
	})

	return check
}

// checkHTTP3Support checks the Alt-Svc response header for h3 (QUIC) indicator.
func (s *HostingScanner) checkHTTP3Support(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "HTTP/3 (QUIC) Support",
		Weight:    20,
	}

	targetURL := ensureHTTPS(url)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: ScanTransport,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		check.Score = 0
		check.Status = statusFromScore(0)
		check.Severity = severityFromScore(0)
		check.Details = toJSON(map[string]interface{}{
			"error":   err.Error(),
			"message": "Cannot reach website to check HTTP/3 support",
		})
		return check
	}
	defer resp.Body.Close()

	altSvc := resp.Header.Get("Alt-Svc")
	h3Supported := strings.Contains(altSvc, "h3=") || strings.Contains(altSvc, "h3\"")

	var score float64
	if h3Supported {
		score = 1000
	} else {
		score = 400
	}

	check.Score = math.Round(score)
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"alt_svc_header": altSvc,
		"h3_supported":   h3Supported,
		"message":        fmt.Sprintf("HTTP/3 (QUIC) supported: %v (score: %.0f/1000)", h3Supported, score),
	})

	return check
}

// checkBrotliCompression sends a request with Accept-Encoding and inspects Content-Encoding.
func (s *HostingScanner) checkBrotliCompression(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Brotli Compression",
		Weight:    25,
	}

	targetURL := ensureHTTPS(url)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		check.Score = 0
		check.Status = statusFromScore(0)
		check.Severity = severityFromScore(0)
		check.Details = toJSON(map[string]interface{}{
			"error":   err.Error(),
			"message": "Failed to create request",
		})
		return check
	}

	req.Header.Set("Accept-Encoding", "br, gzip, deflate")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Seku/1.0)")

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: ScanTransport,
	}

	resp, err := client.Do(req)
	if err != nil {
		check.Score = 0
		check.Status = statusFromScore(0)
		check.Severity = severityFromScore(0)
		check.Details = toJSON(map[string]interface{}{
			"error":   err.Error(),
			"message": "Cannot reach website to check compression",
		})
		return check
	}
	defer resp.Body.Close()

	contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding"))

	var score float64
	var compression string
	switch {
	case strings.Contains(contentEncoding, "br"):
		score = 1000
		compression = "brotli"
	case strings.Contains(contentEncoding, "gzip"):
		score = 750
		compression = "gzip"
	case strings.Contains(contentEncoding, "deflate"):
		score = 500
		compression = "deflate"
	default:
		score = 100
		compression = "none"
	}

	check.Score = math.Round(score)
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"content_encoding": contentEncoding,
		"compression":      compression,
		"message":          fmt.Sprintf("Compression: %s (score: %.0f/1000)", compression, score),
	})

	return check
}

// checkIPv6Support looks up IP addresses for the domain and checks for AAAA records.
func (s *HostingScanner) checkIPv6Support(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "IPv6 Support",
		Weight:    15,
	}

	host := extractHost(url)

	ips, err := net.LookupIP(host)
	if err != nil {
		check.Score = 0
		check.Status = statusFromScore(0)
		check.Severity = severityFromScore(0)
		check.Details = toJSON(map[string]interface{}{
			"error":   err.Error(),
			"message": "DNS lookup failed; cannot determine IPv6 support",
		})
		return check
	}

	var ipv4Addrs []string
	var ipv6Addrs []string
	for _, ip := range ips {
		if strings.Contains(ip.String(), ":") {
			ipv6Addrs = append(ipv6Addrs, ip.String())
		} else {
			ipv4Addrs = append(ipv4Addrs, ip.String())
		}
	}

	hasIPv6 := len(ipv6Addrs) > 0

	var score float64
	if hasIPv6 {
		score = 1000
	} else {
		score = 350
	}

	check.Score = math.Round(score)
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"ipv4_addresses": ipv4Addrs,
		"ipv6_addresses": ipv6Addrs,
		"ipv6_supported": hasIPv6,
		"message":        fmt.Sprintf("IPv6 supported: %v (score: %.0f/1000)", hasIPv6, score),
	})

	return check
}

// checkKeepAlive inspects the Connection header and protocol for persistent connections.
func (s *HostingScanner) checkKeepAlive(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Keep-Alive",
		Weight:    10,
	}

	targetURL := ensureHTTPS(url)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: ScanTransport,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		check.Score = 0
		check.Status = statusFromScore(0)
		check.Severity = severityFromScore(0)
		check.Details = toJSON(map[string]interface{}{
			"error":   err.Error(),
			"message": "Cannot reach website to check keep-alive",
		})
		return check
	}
	defer resp.Body.Close()

	isHTTP2 := resp.Proto == "HTTP/2.0" || resp.Proto == "HTTP/2"
	connectionHeader := strings.ToLower(resp.Header.Get("Connection"))

	var score float64
	var reason string
	switch {
	case isHTTP2:
		score = 1000
		reason = "HTTP/2 uses persistent connections by default"
	case strings.Contains(connectionHeader, "keep-alive"):
		score = 1000
		reason = "Connection: keep-alive header present"
	case strings.Contains(connectionHeader, "close"):
		score = 300
		reason = "Connection: close header present"
	default:
		score = 700
		reason = "No explicit Connection header (keep-alive assumed for HTTP/1.1)"
	}

	check.Score = math.Round(score)
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"protocol":          resp.Proto,
		"connection_header": connectionHeader,
		"http2":             isHTTP2,
		"reason":            reason,
		"message":           fmt.Sprintf("Keep-Alive: %s (score: %.0f/1000)", reason, score),
	})

	return check
}

// scoreDNSResolution returns a 0-1000 score for DNS resolution time using
// piecewise linear decay across defined brackets.
func scoreDNSResolution(ms float64) float64 {
	switch {
	case ms <= 20:
		return 1000
	case ms <= 50:
		return linearScore(ms, 20, 50, 1000, 920)
	case ms <= 100:
		return linearScore(ms, 50, 100, 920, 800)
	case ms <= 200:
		return linearScore(ms, 100, 200, 800, 600)
	case ms <= 500:
		return linearScore(ms, 200, 500, 600, 300)
	default:
		return 100
	}
}

// checkDNSResolutionTime measures the time to resolve the domain via DNS.
func (s *HostingScanner) checkDNSResolutionTime(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "DNS Resolution Time",
		Weight:    25,
	}

	host := extractHost(url)

	start := time.Now()
	addrs, err := net.LookupHost(host)
	elapsed := time.Since(start)

	if err != nil {
		check.Score = 0
		check.Status = statusFromScore(0)
		check.Severity = severityFromScore(0)
		check.Details = toJSON(map[string]interface{}{
			"error":   err.Error(),
			"message": "DNS resolution failed",
		})
		return check
	}

	ms := float64(elapsed.Milliseconds())
	score := math.Round(scoreDNSResolution(ms))

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"dns_resolution_ms": int64(ms),
		"resolved_addresses": addrs,
		"message":            fmt.Sprintf("DNS resolution: %dms (score: %.0f/1000)", int64(ms), score),
	})

	return check
}
