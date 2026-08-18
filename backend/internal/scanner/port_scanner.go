package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"seku/internal/models"
)

type PortScanner struct{}

func NewPortScanner() *PortScanner { return &PortScanner{} }

func (s *PortScanner) Name() string     { return "Port Scanner" }
func (s *PortScanner) Category() string { return "ports" }
func (s *PortScanner) Weight() float64  { return 8.0 }

// portInfo describes a well-known port.
type portInfo struct {
	Port    int
	Service string
	Risk    string // safe, caution, dangerous
}

// commonPorts lists well-known ports to scan.
var commonPorts = []portInfo{
	// Web
	{80, "HTTP", "safe"},
	{443, "HTTPS", "safe"},
	{8080, "HTTP-Alt", "caution"},
	{8443, "HTTPS-Alt", "caution"},
	{8888, "HTTP-Alt", "caution"},

	// Email
	{25, "SMTP", "caution"},
	{465, "SMTPS", "safe"},
	{587, "SMTP-Submission", "safe"},
	{110, "POP3", "caution"},
	{995, "POP3S", "safe"},
	{143, "IMAP", "caution"},
	{993, "IMAPS", "safe"},

	// File Transfer
	{21, "FTP", "dangerous"},
	{22, "SSH", "caution"},
	{69, "TFTP", "dangerous"},
	{115, "SFTP", "caution"},

	// Database
	{3306, "MySQL", "dangerous"},
	{5432, "PostgreSQL", "dangerous"},
	{1433, "MSSQL", "dangerous"},
	{1521, "Oracle", "dangerous"},
	{27017, "MongoDB", "dangerous"},
	{6379, "Redis", "dangerous"},
	{5984, "CouchDB", "dangerous"},
	{9200, "Elasticsearch", "dangerous"},

	// Remote Access
	{23, "Telnet", "dangerous"},
	{3389, "RDP", "dangerous"},
	{5900, "VNC", "dangerous"},
	{5901, "VNC-1", "dangerous"},

	// DNS & Network
	{53, "DNS", "safe"},
	{161, "SNMP", "dangerous"},
	{162, "SNMP-Trap", "dangerous"},
	{389, "LDAP", "dangerous"},
	{636, "LDAPS", "caution"},

	// Admin / Management
	{2082, "cPanel", "caution"},
	{2083, "cPanel-SSL", "caution"},
	{2086, "WHM", "caution"},
	{2087, "WHM-SSL", "caution"},
	{10000, "Webmin", "dangerous"},
	{8081, "Admin", "caution"},
	{9090, "Admin", "caution"},
	{2222, "SSH-Alt", "caution"},

	// Other
	{11211, "Memcached", "dangerous"},
	{6380, "Redis-Alt", "dangerous"},
	{9092, "Kafka", "dangerous"},
	{15672, "RabbitMQ", "dangerous"},
}

// cdnProxyPorts are the HTTP/HTTPS ports a CDN (Cloudflare) accepts AT THE EDGE
// for every zone, independent of the origin. A connect to these on a CDN-fronted
// host says nothing about the origin — they are NOT origin services (cPanel/WHM).
var cdnProxyPorts = map[int]bool{
	80: true, 443: true, 8080: true, 8443: true, 8880: true,
	2052: true, 2053: true, 2082: true, 2083: true, 2086: true, 2087: true, 2095: true, 2096: true,
}

// detectCDN returns the CDN name if the host is fronted by one (so port results
// can be interpreted as the edge, not the origin). Best-effort; "" if none/error.
func detectCDN(host string) string {
	// Retry once — a single flaky self-probe timing out would otherwise leave a
	// genuinely CDN-fronted host's edge ports (2082/2083/8080…) mislabeled.
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := ScanGet(NewScanClient(6*time.Second), ensureHTTPS(host))
		if err != nil {
			continue
		}
		cdn := cdnFromHeaders(resp.Header)
		resp.Body.Close()
		if cdn != "" {
			return cdn
		}
		return "" // reached the origin/edge fine, just no CDN signature
	}
	return ""
}

func (s *PortScanner) Scan(targetURL string) []models.CheckResult {
	host := extractHost(targetURL)
	return []models.CheckResult{
		s.scanPorts(host),
	}
}

func (s *PortScanner) scanPorts(host string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Open Port Detection",
		Weight:    8.0,
	}

	cdn := detectCDN(host)

	var (
		mu        sync.Mutex
		openPorts []map[string]interface{}
		wg        sync.WaitGroup
		sem       = make(chan struct{}, 8) // max 8 concurrent port checks (low noise)
	)

	for _, p := range commonPorts {
		wg.Add(1)
		sem <- struct{}{}
		go func(pi portInfo) {
			defer wg.Done()
			defer func() { <-sem }()

			address := net.JoinHostPort(host, fmt.Sprintf("%d", pi.Port))
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			openPorts = append(openPorts, map[string]interface{}{
				"port":    pi.Port,
				"service": pi.Service,
				"risk":    pi.Risk,
			})
			mu.Unlock()
		}(p)
	}

	wg.Wait()

	details := map[string]interface{}{
		"ports_scanned": len(commonPorts),
		"open_ports":    openPorts,
		"open_count":    len(openPorts),
	}

	// Behind a CDN, its proxy ports answer at the edge for every zone and are NOT
	// origin services — reclassify them so they aren't reported as cPanel/WHM etc.
	cdnEdgeCount := 0
	if cdn != "" {
		for _, op := range openPorts {
			if port, ok := op["port"].(int); ok && cdnProxyPorts[port] {
				op["cdn_edge"] = true
				op["service"] = cdn + " edge"
				op["risk"] = "safe"
				cdnEdgeCount++
			}
		}
		details["cdn"] = cdn
		details["cdn_edge_count"] = cdnEdgeCount
		details["cdn_note"] = "Host is behind " + cdn + " (CDN). Open ports reflect the CDN edge, not the origin. CDN proxy ports (80/443/8080/8443/2082/2083/2086/2087/…) are accepted for every zone and are NOT origin services such as cPanel/WHM."
	}

	// Count risky ports (CDN edge ports were downgraded to "safe" above).
	dangerousCount := 0
	cautionCount := 0
	var dangerousList []string
	for _, op := range openPorts {
		risk, _ := op["risk"].(string)
		switch risk {
		case "dangerous":
			dangerousCount++
			dangerousList = append(dangerousList, fmt.Sprintf("%v (%s)", op["port"], op["service"]))
		case "caution":
			cautionCount++
		}
	}

	details["dangerous_count"] = dangerousCount
	details["caution_count"] = cautionCount

	originOpen := len(openPorts) - cdnEdgeCount // ports that actually reflect the origin

	switch {
	case dangerousCount > 0:
		check.Status = "fail"
		check.Score = 200
		check.Severity = "critical"
		details["message"] = fmt.Sprintf("%d dangerous port(s) open: %s", dangerousCount, joinStrings(dangerousList))
		details["dangerous_ports"] = dangerousList
		details["recommendation"] = "Close unnecessary ports and restrict database/admin ports to internal networks only"
	case cautionCount > 3:
		check.Status = "warn"
		check.Score = 500
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("%d port(s) need attention", cautionCount)
	case originOpen <= 3:
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		if cdn != "" {
			details["message"] = fmt.Sprintf("Minimal origin attack surface (%d) behind %s; %d CDN edge port(s) are expected", originOpen, cdn, cdnEdgeCount)
		} else {
			details["message"] = fmt.Sprintf("Minimal attack surface: %d port(s) open", originOpen)
		}
	default:
		check.Status = "pass"
		check.Score = 800
		check.Severity = "low"
		details["message"] = fmt.Sprintf("%d port(s) open — review if all are necessary", originOpen)
	}

	check.Details = toJSON(details)
	return check
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}
