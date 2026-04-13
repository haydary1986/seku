package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"vscan-mohesr/internal/models"
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

	// Count dangerous ports
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
		details["message"] = fmt.Sprintf("%d ports open (%d need attention)", len(openPorts), cautionCount)
	case len(openPorts) <= 3:
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Minimal attack surface: %d port(s) open", len(openPorts))
	default:
		check.Status = "pass"
		check.Score = 800
		check.Severity = "low"
		details["message"] = fmt.Sprintf("%d port(s) open — review if all are necessary", len(openPorts))
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
