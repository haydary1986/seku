package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type DirectoryScanner struct{}

func NewDirectoryScanner() *DirectoryScanner {
	return &DirectoryScanner{}
}

func (s *DirectoryScanner) Name() string     { return "Directory Listing Scanner" }
func (s *DirectoryScanner) Category() string { return "directory" }
func (s *DirectoryScanner) Weight() float64  { return 10.0 }

func (s *DirectoryScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: ScanTransport,
	}

	baseURL := ensureHTTPS(url)

	// Common sensitive paths to check
	sensitivePaths := []struct {
		path     string
		name     string
		severity string
	}{
		{"/robots.txt", "Robots.txt Exposure", "info"},
		{"/.env", "Environment File Exposure", "critical"},
		{"/.git/config", "Git Repository Exposure", "critical"},
		{"/phpinfo.php", "PHP Info Exposure", "high"},
		{"/admin/", "Admin Panel Exposure", "high"},
		{"/backup/", "Backup Directory Exposure", "critical"},
		{"/.htaccess", "Htaccess File Exposure", "high"},
		{"/wp-config.php.bak", "WordPress Config Backup", "critical"},
		{"/server-status", "Server Status Exposure", "high"},
	}

	weightPerCheck := s.Weight() / float64(len(sensitivePaths))

	for _, sp := range sensitivePaths {
		check := models.CheckResult{
			Category:  s.Category(),
			CheckName: sp.name,
			Weight:    weightPerCheck,
		}

		checkURL := baseURL + sp.path
		resp, err := client.Get(checkURL)
		if err != nil {
			check.Status = "error"
			check.Score = 0
			check.Weight = 0
			check.Severity = "info"
			check.Details = toJSON(map[string]string{
				"path":    sp.path,
				"message": "Could not reach path (timeout or network error)",
			})
			results = append(results, check)
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		bodyStr := string(body)

		if resp.StatusCode == 200 {
			// Check if it's actually exposing sensitive data
			if sp.path == "/robots.txt" {
				// robots.txt is expected, but could disclose sensitive paths
				hasDisallow := strings.Contains(bodyStr, "Disallow")
				if hasDisallow {
					check.Status = "pass"
					check.Score = 875
					check.Severity = "info"
					check.Details = toJSON(map[string]string{
						"path":    sp.path,
						"message": "robots.txt found with disallow rules - review for sensitive path disclosure",
						"preview": truncate(bodyStr, 200),
					})
				} else {
					check.Status = "pass"
					check.Score = 925
					check.Severity = "info"
					check.Details = toJSON(map[string]string{
						"path":    sp.path,
						"message": "robots.txt found with minimal content",
						"preview": truncate(bodyStr, 200),
					})
				}
			} else if strings.Contains(bodyStr, "Index of") || strings.Contains(bodyStr, "Directory listing") {
				// Directory listing enabled - worst case
				check.Status = "fail"
				check.Score = 0
				check.Severity = sp.severity
				check.Details = toJSON(map[string]string{
					"path":    sp.path,
					"message": fmt.Sprintf("Directory listing enabled at %s", sp.path),
				})
			} else {
				// Check if /admin/ is actually a WordPress redirect to wp-admin (normal behavior)
				isWPAdminRedirect := sp.path == "/admin/" && (strings.Contains(bodyStr, "wp-login") ||
					strings.Contains(bodyStr, "wp-admin") ||
					strings.Contains(bodyStr, "wordpress") ||
					strings.Contains(bodyStr, "wordfence"))

				if isWPAdminRedirect {
					// WordPress /admin/ → wp-admin redirect is expected behavior, not a vulnerability
					check.Status = "pass"
					check.Score = 850
					check.Severity = "info"
					check.Details = toJSON(map[string]string{
						"path":    sp.path,
						"message": "WordPress admin panel detected — this is standard CMS behavior, not a vulnerability. Protected by authentication.",
					})
				} else {
					// Truly sensitive path accessible without protection
					var score float64
					switch sp.severity {
					case "critical":
						score = 50
					case "high":
						score = 125
					default:
						score = 175
					}
					check.Status = "fail"
					check.Score = score
					check.Severity = sp.severity
					check.Details = toJSON(map[string]string{
						"path":    sp.path,
						"message": fmt.Sprintf("Sensitive path accessible: %s", sp.path),
					})
				}
			}
		} else if resp.StatusCode == 403 {
			// 403 can mean WAF/CDN protection (Cloudflare, etc.) or server config
			// Check if it's a WAF/CDN blocking (which is good security)
			isWAFProtected := resp.Header.Get("CF-RAY") != "" ||
				resp.Header.Get("Server") == "cloudflare" ||
				resp.Header.Get("X-Sucuri-ID") != "" ||
				resp.Header.Get("X-CDN") != ""

			if isWAFProtected {
				// WAF/CDN is blocking access - this is good protection
				check.Status = "pass"
				check.Score = 900
				check.Severity = "info"
				check.Details = toJSON(map[string]string{
					"path":    sp.path,
					"message": fmt.Sprintf("Path blocked by WAF/CDN (403): %s - well protected", sp.path),
				})
			} else {
				// Server returns 403 without WAF - path confirmed to exist
				check.Status = "warn"
				check.Score = 725
				check.Severity = "low"
				check.Details = toJSON(map[string]string{
					"path":    sp.path,
					"message": fmt.Sprintf("Path exists but forbidden (403): %s", sp.path),
				})
			}
		} else {
			check.Status = "pass"
			check.Score = 1000
			check.Severity = "info"
			check.Details = toJSON(map[string]string{
				"path":        sp.path,
				"message":     "Path not found",
				"status_code": fmt.Sprintf("%d", resp.StatusCode),
			})
		}

		results = append(results, check)
	}

	return results
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
