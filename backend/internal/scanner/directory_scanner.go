package scanner

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"seku/internal/models"
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
		Timeout:   10 * time.Second,
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
				} else if typed, confirmed := directoryContentConfirmsExposure(sp.path, bodyStr); typed && !confirmed {
					// 200 OK but the body lacks the expected signature for this
					// file type (e.g. a soft-404 serving the site's normal HTML).
					check.Status = "pass"
					check.Score = 900
					check.Severity = "info"
					check.Details = toJSON(map[string]string{
						"path":    sp.path,
						"message": fmt.Sprintf("Path returned 200 but content does not match the expected sensitive-file signature (likely soft-404): %s", sp.path),
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
		} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
			// 401/403 means access is DENIED — the sensitive path is protected.
			// This is good security whether a WAF/CDN or the origin server
			// enforced it, so it is a pass regardless of CDN headers.
			check.Status = "pass"
			check.Score = 900
			check.Severity = "info"
			check.Details = toJSON(map[string]string{
				"path":    sp.path,
				"message": fmt.Sprintf("Access denied (%d) — path is protected: %s", resp.StatusCode, sp.path),
			})
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

// directoryEnvKeyRe matches an UPPERCASE environment-variable assignment line
// (e.g. "APP_ENV=production"), used to confirm a genuine .env file body.
var directoryEnvKeyRe = regexp.MustCompile(`(?m)^\s*[A-Z][A-Z0-9_]*\s*=`)

// directoryContentConfirmsExposure decides whether a 200 body genuinely confirms
// a sensitive file/path is exposed, rather than a soft-404 serving the site's
// normal HTML page. It returns (typed, confirmed): typed is true when the path is
// a recognized sensitive file type, and confirmed is true when the body carries
// the expected content signature for that type. Non-HTML file types additionally
// reject bodies that look like HTML.
func directoryContentConfirmsExposure(path, body string) (typed bool, confirmed bool) {
	p := strings.ToLower(path)
	lower := strings.ToLower(body)
	switch {
	case strings.Contains(p, ".env"):
		return true, !bodyLooksLikeHTML(body) && directoryEnvKeyRe.MatchString(body)
	case strings.Contains(p, ".git/config"):
		return true, !bodyLooksLikeHTML(body) && strings.Contains(lower, "[core]")
	case strings.Contains(p, ".git/head"):
		return true, !bodyLooksLikeHTML(body) && strings.Contains(lower, "ref:")
	case strings.Contains(p, "phpinfo"):
		// phpinfo() output is itself HTML, so only require its signature strings.
		return true, strings.Contains(lower, "phpinfo()") || strings.Contains(lower, "php version")
	case strings.Contains(p, "wp-config") || strings.HasSuffix(p, ".bak") ||
		strings.HasSuffix(p, ".php.old") || strings.HasSuffix(p, ".php~"):
		return true, !bodyLooksLikeHTML(body) &&
			(strings.Contains(lower, "<?php") || strings.Contains(lower, "db_password") || strings.Contains(lower, "db_name"))
	case strings.HasSuffix(p, ".sql"):
		return true, !bodyLooksLikeHTML(body) &&
			(strings.Contains(lower, "insert into") || strings.Contains(lower, "create table") || strings.Contains(lower, "-- mysql dump"))
	case strings.HasSuffix(p, ".htaccess"):
		// A real .htaccess is plain text; an HTML body here is a soft-404.
		return true, !bodyLooksLikeHTML(body)
	}
	return false, false
}
