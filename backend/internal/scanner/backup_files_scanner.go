package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"seku/internal/models"
)

// BackupFilesScanner enumerates common backup/sensitive file paths that
// administrators frequently leave in webroot by accident: SQL dumps,
// config backups, IDE files, archive files, etc.
type BackupFilesScanner struct{}

func NewBackupFilesScanner() *BackupFilesScanner {
	return &BackupFilesScanner{}
}

func (s *BackupFilesScanner) Name() string     { return "Backup & Sensitive Files Scanner" }
func (s *BackupFilesScanner) Category() string { return "backup_files" }
func (s *BackupFilesScanner) Weight() float64  { return 12.0 }

type sensitivePath struct {
	path        string
	label       string
	severity    string // critical, high, medium, low
	cwe         string
	owasp       string
	mustContain string // substring expected in body to confirm true positive (optional)
	cvss        float64
}

func (s *BackupFilesScanner) paths() []sensitivePath {
	return []sensitivePath{
		// === SQL dumps (CRITICAL) ===
		{"/backup.sql", "SQL Backup Exposed", "critical", "CWE-538", "A05", "", 9.8},
		{"/database.sql", "Database Dump Exposed", "critical", "CWE-538", "A05", "", 9.8},
		{"/db.sql", "DB Dump Exposed", "critical", "CWE-538", "A05", "", 9.8},
		{"/dump.sql", "SQL Dump Exposed", "critical", "CWE-538", "A05", "", 9.8},
		{"/backup.sql.gz", "Compressed SQL Backup Exposed", "critical", "CWE-538", "A05", "", 9.8},
		{"/db.sql.zip", "ZIP SQL Dump Exposed", "critical", "CWE-538", "A05", "", 9.8},
		{"/site.sql", "Site SQL Dump Exposed", "critical", "CWE-538", "A05", "", 9.8},
		{"/wp-content/backup-db/", "WP Database Backup Folder", "critical", "CWE-538", "A05", "", 9.8},

		// === Config backups (CRITICAL) ===
		{"/wp-config.php.bak", "WordPress Config Backup", "critical", "CWE-538", "A05", "", 9.8},
		{"/wp-config.php~", "WordPress Config Editor Backup", "critical", "CWE-538", "A05", "", 9.8},
		{"/wp-config.php.old", "WordPress Old Config", "critical", "CWE-538", "A05", "", 9.8},
		{"/wp-config.bak", "WordPress Config Backup", "critical", "CWE-538", "A05", "", 9.8},
		{"/configuration.php.bak", "Joomla Config Backup", "critical", "CWE-538", "A05", "", 9.8},
		{"/configuration.php~", "Joomla Config Editor Backup", "critical", "CWE-538", "A05", "", 9.8},
		{"/config.php.bak", "Generic Config Backup", "critical", "CWE-538", "A05", "", 9.8},
		{"/config.inc.php.bak", "PHPMyAdmin Config Backup", "critical", "CWE-538", "A05", "", 9.8},
		{"/settings.php.bak", "Drupal Settings Backup", "critical", "CWE-538", "A05", "", 9.8},

		// === Archive files (HIGH) ===
		{"/backup.zip", "Site Archive Exposed", "high", "CWE-538", "A05", "", 8.6},
		{"/backup.tar.gz", "Site Archive Exposed", "high", "CWE-538", "A05", "", 8.6},
		{"/backup.tar", "TAR Archive Exposed", "high", "CWE-538", "A05", "", 8.6},
		{"/backup.rar", "RAR Archive Exposed", "high", "CWE-538", "A05", "", 8.6},
		{"/site.zip", "Site ZIP Exposed", "high", "CWE-538", "A05", "", 8.6},
		{"/website.zip", "Website ZIP Exposed", "high", "CWE-538", "A05", "", 8.6},
		{"/www.zip", "WWW ZIP Exposed", "high", "CWE-538", "A05", "", 8.6},
		{"/htdocs.zip", "Htdocs Archive Exposed", "high", "CWE-538", "A05", "", 8.6},
		{"/public_html.zip", "Public HTML Archive Exposed", "high", "CWE-538", "A05", "", 8.6},
		{"/old.zip", "Old Archive Exposed", "high", "CWE-538", "A05", "", 8.6},

		// === IDE / Editor leftovers ===
		{"/.idea/workspace.xml", "JetBrains IDE Config Exposed", "medium", "CWE-538", "A05", "", 5.3},
		{"/.vscode/settings.json", "VSCode Config Exposed", "low", "CWE-538", "A05", "", 3.7},
		{"/.DS_Store", "macOS DS_Store Exposed", "low", "CWE-538", "A05", "", 3.7},
		{"/Thumbs.db", "Windows Thumbs.db Exposed", "low", "CWE-538", "A05", "", 3.1},

		// === Log files ===
		{"/error.log", "Server Error Log Exposed", "medium", "CWE-532", "A09", "", 5.3},
		{"/error_log", "PHP Error Log Exposed", "medium", "CWE-532", "A09", "", 5.3},
		{"/access.log", "Access Log Exposed", "medium", "CWE-532", "A09", "", 5.3},
		{"/debug.log", "Debug Log Exposed", "medium", "CWE-532", "A09", "", 5.3},
		{"/wp-content/debug.log", "WordPress Debug Log Exposed", "high", "CWE-532", "A09", "", 7.5},

		// === Git/SVN/Mercurial (additional to directory scanner) ===
		{"/.git/HEAD", "Git Repository Exposed (HEAD)", "critical", "CWE-538", "A05", "ref:", 9.8},
		{"/.git/index", "Git Repository Exposed (index)", "critical", "CWE-538", "A05", "", 9.8},
		{"/.svn/entries", "SVN Repository Exposed", "critical", "CWE-538", "A05", "", 9.8},
		{"/.svn/wc.db", "SVN Working Copy DB Exposed", "critical", "CWE-538", "A05", "", 9.8},
		{"/.hg/hgrc", "Mercurial Repository Exposed", "high", "CWE-538", "A05", "", 8.6},
		{"/.bzr/branch-format", "Bazaar Repository Exposed", "high", "CWE-538", "A05", "", 8.6},

		// === Environment files ===
		{"/.env.backup", "Backup Environment File", "critical", "CWE-538", "A05", "", 9.8},
		{"/.env.bak", "Backup Environment File", "critical", "CWE-538", "A05", "", 9.8},
		{"/.env.old", "Old Environment File", "critical", "CWE-538", "A05", "", 9.8},
		{"/.env.local", "Local Environment File", "critical", "CWE-538", "A05", "", 9.8},
		{"/.env.production", "Production Environment File", "critical", "CWE-538", "A05", "", 9.8},
		{"/.env.development", "Development Environment File", "high", "CWE-538", "A05", "", 7.5},

		// === Composer / Node leftovers ===
		{"/composer.lock", "Composer Lock File Exposed", "low", "CWE-538", "A05", "", 3.1},
		{"/composer.json", "Composer Config Exposed", "low", "CWE-538", "A05", "", 3.1},
		{"/package-lock.json", "NPM Lock File Exposed", "low", "CWE-538", "A05", "", 3.1},
		{"/yarn.lock", "Yarn Lock File Exposed", "low", "CWE-538", "A05", "", 3.1},

		// === Docker/CI files ===
		{"/Dockerfile", "Dockerfile Exposed", "low", "CWE-538", "A05", "FROM", 3.7},
		{"/docker-compose.yml", "Docker Compose Exposed", "medium", "CWE-538", "A05", "", 5.3},
		{"/.dockerignore", "Docker Ignore Exposed", "low", "CWE-538", "A05", "", 2.0},

		// === phpMyAdmin / Adminer ===
		{"/phpmyadmin/", "phpMyAdmin Login Exposed", "high", "CWE-284", "A07", "phpMyAdmin", 7.5},
		{"/pma/", "phpMyAdmin Login Exposed (alt)", "high", "CWE-284", "A07", "phpMyAdmin", 7.5},
		{"/adminer.php", "Adminer Login Exposed", "high", "CWE-284", "A07", "", 7.5},
		{"/dbadmin/", "Database Admin Exposed", "high", "CWE-284", "A07", "", 7.5},

		// === Server status pages ===
		{"/server-status", "Apache Server Status Exposed", "high", "CWE-200", "A05", "Apache", 7.5},
		{"/server-info", "Apache Server Info Exposed", "high", "CWE-200", "A05", "Apache", 7.5},

		// === CMS-specific install/setup pages ===
		{"/wp-admin/install.php", "WordPress Install Page Exposed", "high", "CWE-284", "A05", "WordPress", 7.5},
		{"/installation/", "Joomla Install Folder Present", "high", "CWE-284", "A05", "", 7.5},
		{"/install.php", "Generic Install Script Exposed", "high", "CWE-284", "A05", "", 7.5},
		{"/setup.php", "Generic Setup Script Exposed", "high", "CWE-284", "A05", "", 7.5},
	}
}

type backupCheckResult struct {
	path  sensitivePath
	found bool
	body  string
}

func (s *BackupFilesScanner) Scan(url string) []models.CheckResult {
	baseURL := strings.TrimRight(ensureHTTPS(url), "/")

	client := &http.Client{
		Timeout:   8 * time.Second,
		Transport: ScanTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	paths := s.paths()
	results := make(chan backupCheckResult, len(paths))
	sem := make(chan struct{}, 15) // 15 concurrent probes

	var wg sync.WaitGroup
	for _, p := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(p sensitivePath) {
			defer wg.Done()
			defer func() { <-sem }()

			req, err := http.NewRequest("GET", baseURL+p.path, nil)
			if err != nil {
				results <- backupCheckResult{path: p, found: false}
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			req.Header.Set("Range", "bytes=0-2047") // only need first 2KB to confirm

			resp, err := client.Do(req)
			if err != nil {
				results <- backupCheckResult{path: p, found: false}
				return
			}
			defer resp.Body.Close()

			// 200 or 206 (partial content) means file exists and is served
			if resp.StatusCode != 200 && resp.StatusCode != 206 {
				results <- backupCheckResult{path: p, found: false}
				return
			}

			// Read small sample to verify (and check mustContain)
			sample := make([]byte, 2048)
			n, _ := resp.Body.Read(sample)
			body := string(sample[:n])

			// Filter false positives: HTML 404 pages that return 200
			lower := strings.ToLower(body)
			if strings.Contains(lower, "<!doctype html") && (strings.Contains(lower, "not found") || strings.Contains(lower, "404") || strings.Contains(lower, "error")) {
				results <- backupCheckResult{path: p, found: false}
				return
			}

			// If mustContain is set, require match
			if p.mustContain != "" && !strings.Contains(body, p.mustContain) {
				results <- backupCheckResult{path: p, found: false}
				return
			}

			results <- backupCheckResult{path: p, found: true, body: body}
		}(p)
	}

	wg.Wait()
	close(results)

	var findings []backupCheckResult
	for r := range results {
		if r.found {
			findings = append(findings, r)
		}
	}

	return s.buildResults(findings, len(paths))
}

func (s *BackupFilesScanner) buildResults(findings []backupCheckResult, totalChecked int) []models.CheckResult {
	if len(findings) == 0 {
		return []models.CheckResult{
			{
				Category:   s.Category(),
				CheckName:  "Backup & Sensitive Files Exposure",
				Status:     "pass",
				Score:      1000,
				Weight:     s.Weight(),
				Severity:   "info",
				CWE:        "CWE-538",
				CWEName:    "Insertion of Sensitive Information into Externally-Accessible File or Directory",
				OWASP:      "A05",
				OWASPName:  "Security Misconfiguration",
				Confidence: 95,
				Details:    fmt.Sprintf("No exposed backup or sensitive files detected. Checked %d common paths including SQL dumps, config backups, archives, IDE files, version control, and admin panels.", totalChecked),
			},
		}
	}

	// Group findings by severity
	criticalCount, highCount, mediumCount, lowCount := 0, 0, 0, 0
	var details strings.Builder
	details.WriteString(fmt.Sprintf("Found %d exposed sensitive files (out of %d checked):\n\n", len(findings), totalChecked))

	for _, f := range findings {
		switch f.path.severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		}
		details.WriteString(fmt.Sprintf("• [%s] %s — %s\n", strings.ToUpper(f.path.severity), f.path.label, f.path.path))
	}

	// Score based on worst severity
	score := 1000.0
	severity := "info"
	switch {
	case criticalCount > 0:
		score = 0
		severity = "critical"
	case highCount > 0:
		score = 200
		severity = "high"
	case mediumCount > 0:
		score = 500
		severity = "medium"
	case lowCount > 0:
		score = 750
		severity = "low"
	}

	worst := findings[0].path
	for _, f := range findings {
		if severityRank(f.path.severity) > severityRank(worst.severity) {
			worst = f.path
		}
	}

	return []models.CheckResult{
		{
			Category:   s.Category(),
			CheckName:  "Backup & Sensitive Files Exposure",
			Status:     statusFromSeverity(severity),
			Score:      score,
			Weight:     s.Weight(),
			Severity:   severity,
			CWE:        worst.cwe,
			CWEName:    "Insertion of Sensitive Information into Externally-Accessible File or Directory",
			OWASP:      worst.owasp,
			OWASPName:  "Security Misconfiguration",
			Confidence: 90,
			CVSSScore:  worst.cvss,
			Details:    details.String(),
		},
	}
}

func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func statusFromSeverity(sev string) string {
	switch sev {
	case "critical", "high":
		return "fail"
	case "medium", "low":
		return "warn"
	}
	return "pass"
}
