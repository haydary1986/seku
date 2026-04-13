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

type SecretsScanner struct{}

func NewSecretsScanner() *SecretsScanner {
	return &SecretsScanner{}
}

func (s *SecretsScanner) Name() string     { return "Secrets Detection Scanner" }
func (s *SecretsScanner) Category() string { return "secrets" }
func (s *SecretsScanner) Weight() float64  { return 8.0 }

func (s *SecretsScanner) Scan(url string) []models.CheckResult {
	body := s.fetchBody(url)

	return []models.CheckResult{
		s.checkAPIKeyExposure(body),
		s.checkPrivateKeyExposure(body),
		s.checkDBConnectionString(body),
		s.checkEmailPasswordExposure(body),
	}
}

func (s *SecretsScanner) fetchBody(url string) string {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: ScanTransport,
	}

	resp, err := client.Get(ensureHTTPS(url))
	if err != nil {
		resp, err = client.Get(ensureHTTP(url))
		if err != nil {
			return ""
		}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return ""
	}
	return string(bodyBytes)
}

// apiKeyPattern defines a named pattern for detecting API keys.
type apiKeyPattern struct {
	name    string
	pattern *regexp.Regexp
}

var apiKeyPatterns = []apiKeyPattern{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"Stripe Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"GitHub PAT (classic)", regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`)},
	{"GitHub PAT (fine-grained)", regexp.MustCompile(`github_pat_[0-9a-zA-Z_]{82}`)},
	{"Slack Bot Token", regexp.MustCompile(`xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}`)},
	{"Generic API Key", regexp.MustCompile(`(?i)api[_\-]?key['":\s]*=?\s*['"]?[0-9a-zA-Z]{20,}['"]?`)},
}

func (s *SecretsScanner) checkAPIKeyExposure(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "API Key Exposure",
		Weight:    3.0,
	}

	if body == "" {
		check.Status = "error"
		check.Score = 0
		check.Weight = 0
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "Could not fetch page body; skipping API key check",
		})
		return check
	}

	var found []map[string]string
	for _, p := range apiKeyPatterns {
		matches := p.pattern.FindAllString(body, 5)
		for _, m := range matches {
			// Redact most of the match to avoid leaking the key in results
			redacted := m
			if len(m) > 8 {
				redacted = m[:8] + strings.Repeat("*", len(m)-8)
			}
			found = append(found, map[string]string{
				"type":  p.name,
				"match": redacted,
			})
		}
	}

	details := map[string]interface{}{
		"keys_found": len(found),
	}

	switch {
	case len(found) == 0:
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No API keys detected in page source"
	case len(found) == 1:
		check.Status = "fail"
		check.Score = 100
		check.Severity = "critical"
		details["message"] = "1 potential API key found in page source"
		details["findings"] = found
	default:
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["message"] = fmt.Sprintf("%d potential API keys found in page source", len(found))
		details["findings"] = found
	}

	check.Details = toJSON(details)
	return check
}

var privateKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+)?PRIVATE KEY-----`),
	regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
}

func (s *SecretsScanner) checkPrivateKeyExposure(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Private Key Exposure",
		Weight:    2.0,
	}

	if body == "" {
		check.Status = "error"
		check.Score = 0
		check.Weight = 0
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "Could not fetch page body; skipping private key check",
		})
		return check
	}

	var found []string
	for _, p := range privateKeyPatterns {
		if p.MatchString(body) {
			found = append(found, p.String())
		}
	}

	details := map[string]interface{}{}

	if len(found) > 0 {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["message"] = fmt.Sprintf("Private key or certificate material found in page source (%d pattern(s) matched)", len(found))
		details["patterns_matched"] = found
	} else {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No private keys or certificate material detected in page source"
	}

	check.Details = toJSON(details)
	return check
}

var dbConnPatterns = []struct {
	name    string
	pattern *regexp.Regexp
	hasCred *regexp.Regexp // optional: checks if credentials are embedded
}{
	{
		"MySQL Connection String",
		regexp.MustCompile(`(?i)mysql://[^\s'"<>]+`),
		regexp.MustCompile(`(?i)mysql://[^:]+:[^@]+@`),
	},
	{
		"PostgreSQL Connection String",
		regexp.MustCompile(`(?i)postgres(?:ql)?://[^\s'"<>]+`),
		regexp.MustCompile(`(?i)postgres(?:ql)?://[^:]+:[^@]+@`),
	},
	{
		"MongoDB Connection String",
		regexp.MustCompile(`(?i)mongodb(?:\+srv)?://[^\s'"<>]+`),
		regexp.MustCompile(`(?i)mongodb(?:\+srv)?://[^:]+:[^@]+@`),
	},
	{
		"Redis Connection String",
		regexp.MustCompile(`(?i)redis://[^\s'"<>]+`),
		regexp.MustCompile(`(?i)redis://[^:]*:[^@]+@`),
	},
	{
		"JDBC MySQL Connection",
		regexp.MustCompile(`(?i)jdbc:mysql://[^\s'"<>]+`),
		nil,
	},
	{
		"JDBC PostgreSQL Connection",
		regexp.MustCompile(`(?i)jdbc:postgresql://[^\s'"<>]+`),
		nil,
	},
	{
		"DB Password Variable",
		regexp.MustCompile(`(?i)(DB_PASSWORD|DATABASE_URL)\s*=\s*['"]?[^\s'"<>]+`),
		nil,
	},
}

func (s *SecretsScanner) checkDBConnectionString(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Database Connection String Exposure",
		Weight:    2.0,
	}

	if body == "" {
		check.Status = "error"
		check.Score = 0
		check.Weight = 0
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "Could not fetch page body; skipping database connection string check",
		})
		return check
	}

	var withCreds []string
	var withoutCreds []string

	for _, p := range dbConnPatterns {
		matches := p.pattern.FindAllString(body, 3)
		for _, m := range matches {
			redacted := m
			if len(m) > 20 {
				redacted = m[:20] + "***REDACTED***"
			}
			if p.hasCred != nil && p.hasCred.MatchString(m) {
				withCreds = append(withCreds, p.name+": "+redacted)
			} else {
				withoutCreds = append(withoutCreds, p.name+": "+redacted)
			}
		}
	}

	details := map[string]interface{}{}

	switch {
	case len(withCreds) > 0:
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["message"] = fmt.Sprintf("Database connection strings with credentials found (%d)", len(withCreds))
		details["with_credentials"] = withCreds
		if len(withoutCreds) > 0 {
			details["without_credentials"] = withoutCreds
		}
	case len(withoutCreds) > 0:
		check.Status = "warn"
		check.Score = 400
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Database connection strings found without embedded credentials (%d)", len(withoutCreds))
		details["findings"] = withoutCreds
	default:
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No database connection strings detected in page source"
	}

	check.Details = toJSON(details)
	return check
}

var emailPasswordPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password\s*[:=]\s*['"][^'"]{3,}['"]`),
	regexp.MustCompile(`(?i)(smtp_pass|mail_password|email_password)\s*[:=]\s*['"][^'"]+['"]`),
	regexp.MustCompile(`(?i)(DB_PASSWORD|APP_KEY|SECRET_KEY|API_SECRET)\s*=\s*[^\s<>]+`),
}

func (s *SecretsScanner) checkEmailPasswordExposure(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Email/Password Exposure",
		Weight:    1.0,
	}

	if body == "" {
		check.Status = "error"
		check.Score = 0
		check.Weight = 0
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "Could not fetch page body; skipping email/password check",
		})
		return check
	}

	var found []string
	for _, p := range emailPasswordPatterns {
		matches := p.FindAllString(body, 3)
		for _, m := range matches {
			redacted := m
			if len(m) > 15 {
				redacted = m[:15] + "***"
			}
			found = append(found, redacted)
		}
	}

	details := map[string]interface{}{}

	if len(found) > 0 {
		check.Status = "fail"
		check.Score = 100
		check.Severity = "critical"
		details["message"] = fmt.Sprintf("Potential hardcoded passwords or .env content found (%d match(es))", len(found))
		details["findings"] = found
	} else {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No hardcoded passwords or leaked .env content detected"
	}

	check.Details = toJSON(details)
	return check
}
