package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"seku/internal/models"
)

// JSSecretsScanner fetches all external JavaScript files referenced from
// the home page and scans them for accidentally embedded secrets:
// AWS keys, Google API keys, Stripe tokens, JWT tokens, generic API
// keys, and base64 secrets. This complements SecretsScanner which only
// scans the inline HTML body.
type JSSecretsScanner struct{}

func NewJSSecretsScanner() *JSSecretsScanner {
	return &JSSecretsScanner{}
}

func (s *JSSecretsScanner) Name() string     { return "JavaScript Secrets Scanner" }
func (s *JSSecretsScanner) Category() string { return "js_secrets" }
func (s *JSSecretsScanner) Weight() float64  { return 12.0 }

// secretPattern is one regex + label for one type of leaked secret.
type secretPattern struct {
	name     string
	severity string
	regex    *regexp.Regexp
	cwe      string
	cvss     float64
}

// All patterns are ordered most-specific first so we don't double-flag.
var jsSecretPatterns = []secretPattern{
	{
		"AWS Access Key ID",
		"critical",
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"CWE-798",
		9.8,
	},
	{
		"AWS Secret Access Key",
		"critical",
		regexp.MustCompile(`(?i)aws(.{0,20})?(?-i)['"][0-9a-zA-Z/+]{40}['"]`),
		"CWE-798",
		9.8,
	},
	{
		"Google API Key",
		"high",
		regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		"CWE-798",
		7.5,
	},
	{
		"Google OAuth Client ID",
		"medium",
		regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
		"CWE-798",
		5.3,
	},
	{
		"Stripe Secret Key (live)",
		"critical",
		regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
		"CWE-798",
		9.8,
	},
	{
		"Stripe Restricted Key",
		"critical",
		regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24,}`),
		"CWE-798",
		9.8,
	},
	{
		"Stripe Publishable Key",
		"low",
		regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`),
		"CWE-200",
		3.1,
	},
	{
		"GitHub Personal Access Token (classic)",
		"critical",
		regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		"CWE-798",
		9.8,
	},
	{
		"GitHub Fine-grained Token",
		"critical",
		regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`),
		"CWE-798",
		9.8,
	},
	{
		"GitHub OAuth Token",
		"critical",
		regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
		"CWE-798",
		9.8,
	},
	{
		"Slack Token",
		"critical",
		regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,}`),
		"CWE-798",
		9.1,
	},
	{
		"Slack Webhook URL",
		"high",
		regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}`),
		"CWE-798",
		7.5,
	},
	{
		"Discord Webhook URL",
		"high",
		regexp.MustCompile(`https://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/[A-Za-z0-9_-]+`),
		"CWE-798",
		7.5,
	},
	{
		"Mapbox Access Token",
		"medium",
		regexp.MustCompile(`pk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
		"CWE-798",
		5.3,
	},
	{
		"SendGrid API Key",
		"critical",
		regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),
		"CWE-798",
		9.1,
	},
	{
		"Twilio API Key",
		"critical",
		regexp.MustCompile(`SK[a-fA-F0-9]{32}`),
		"CWE-798",
		8.6,
	},
	{
		"Mailgun API Key",
		"high",
		regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		"CWE-798",
		7.5,
	},
	{
		"Firebase URL",
		"low",
		regexp.MustCompile(`https?://[a-z0-9-]+\.firebaseio\.com`),
		"CWE-200",
		3.7,
	},
	{
		"Firebase Server Key",
		"high",
		regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
		"CWE-798",
		7.5,
	},
	{
		"JWT Token",
		"medium",
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
		"CWE-798",
		5.3,
	},
	{
		"Generic Bearer Token",
		"medium",
		regexp.MustCompile(`(?i)bearer\s+[a-z0-9_\-\.=]{30,}`),
		"CWE-200",
		4.3,
	},
	{
		"Private RSA Key",
		"critical",
		regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`),
		"CWE-798",
		9.8,
	},
	{
		"Generic API Key (long hex)",
		"low",
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)['"]?\s*[:=]\s*['"][a-f0-9]{32,}['"]`),
		"CWE-200",
		3.7,
	},
}

func (s *JSSecretsScanner) Scan(targetURL string) []models.CheckResult {
	baseURL := ensureHTTPS(targetURL)

	client := &http.Client{
		Timeout:   12 * time.Second,
		Transport: ScanTransport,
	}

	// 1. Fetch home page
	homeBody := s.fetchBody(client, baseURL)
	if homeBody == "" {
		return []models.CheckResult{
			{
				Category:   s.Category(),
				CheckName:  "JavaScript Secrets",
				Status:     "warn",
				Score:      700,
				Weight:     s.Weight(),
				Severity:   "low",
				Confidence: 50,
				Details:    "Could not fetch home page to enumerate JS files.",
			},
		}
	}

	// 2. Extract <script src="..."> URLs
	scriptURLs := s.extractScriptURLs(baseURL, homeBody)

	if len(scriptURLs) == 0 {
		return []models.CheckResult{
			{
				Category:   s.Category(),
				CheckName:  "JavaScript Secrets",
				Status:     "pass",
				Score:      1000,
				Weight:     s.Weight(),
				Severity:   "info",
				Confidence: 70,
				Details:    "No external JavaScript files found on home page.",
			},
		}
	}

	// 3. Scan each JS file in parallel (cap to 25 to keep scan fast)
	const maxFiles = 25
	if len(scriptURLs) > maxFiles {
		scriptURLs = scriptURLs[:maxFiles]
	}

	results := make(chan fileFinding, len(scriptURLs))
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, scriptURL := range scriptURLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			body := s.fetchBody(client, u)
			if body == "" {
				results <- fileFinding{url: u}
				return
			}
			secrets := s.scanForSecrets(body)
			results <- fileFinding{url: u, secrets: secrets}
		}(scriptURL)
	}

	wg.Wait()
	close(results)

	// 4. Aggregate findings
	var allFindings []fileFinding
	totalSecrets := 0
	for r := range results {
		if len(r.secrets) > 0 {
			allFindings = append(allFindings, r)
			totalSecrets += len(r.secrets)
		}
	}

	if totalSecrets == 0 {
		return []models.CheckResult{
			{
				Category:   s.Category(),
				CheckName:  "JavaScript Secrets",
				Status:     "pass",
				Score:      1000,
				Weight:     s.Weight(),
				Severity:   "info",
				Confidence: 85,
				Details:    fmt.Sprintf("Scanned %d JavaScript files. No exposed secrets detected.", len(scriptURLs)),
			},
		}
	}

	return s.buildSecretsResult(allFindings, totalSecrets, len(scriptURLs))
}

type foundSecret struct {
	name     string
	severity string
	cwe      string
	cvss     float64
	excerpt  string
}

type fileFinding struct {
	url     string
	secrets []foundSecret
}

func (s *JSSecretsScanner) scanForSecrets(body string) []foundSecret {
	var found []foundSecret
	seen := map[string]bool{}

	for _, p := range jsSecretPatterns {
		matches := p.regex.FindAllString(body, -1)
		for _, m := range matches {
			key := p.name + "|" + m
			if seen[key] {
				continue
			}
			seen[key] = true

			// Truncate and mask middle for safety
			excerpt := m
			if len(excerpt) > 40 {
				excerpt = excerpt[:8] + "..." + excerpt[len(excerpt)-6:]
			}

			found = append(found, foundSecret{
				name:     p.name,
				severity: p.severity,
				cwe:      p.cwe,
				cvss:     p.cvss,
				excerpt:  excerpt,
			})
		}
	}
	return found
}

func (s *JSSecretsScanner) buildSecretsResult(findings []fileFinding, totalSecrets, filesScanned int) []models.CheckResult {
	worstSev := "low"
	worstCVSS := 0.0
	worstCWE := "CWE-200"

	var details strings.Builder
	details.WriteString(fmt.Sprintf("Found %d exposed secrets across %d JavaScript files (out of %d scanned):\n\n", totalSecrets, len(findings), filesScanned))

	for _, f := range findings {
		details.WriteString(fmt.Sprintf("📄 %s\n", f.url))
		for _, sec := range f.secrets {
			details.WriteString(fmt.Sprintf("   • [%s] %s — %s\n", strings.ToUpper(sec.severity), sec.name, sec.excerpt))
			if severityRank(sec.severity) > severityRank(worstSev) {
				worstSev = sec.severity
				worstCWE = sec.cwe
			}
			if sec.cvss > worstCVSS {
				worstCVSS = sec.cvss
			}
		}
		details.WriteString("\n")
	}
	details.WriteString("Action: rotate exposed secrets immediately and remove them from JS bundles. Use environment variables on the backend instead.")

	score := 1000.0
	switch worstSev {
	case "critical":
		score = 0
	case "high":
		score = 200
	case "medium":
		score = 500
	case "low":
		score = 750
	}

	return []models.CheckResult{
		{
			Category:   s.Category(),
			CheckName:  fmt.Sprintf("JavaScript Secrets (%d found)", totalSecrets),
			Status:     statusFromSeverity(worstSev),
			Score:      score,
			Weight:     s.Weight(),
			Severity:   worstSev,
			CWE:        worstCWE,
			CWEName:    "Use of Hard-coded Credentials",
			OWASP:      "A07",
			OWASPName:  "Identification and Authentication Failures",
			Confidence: 88,
			CVSSScore:  worstCVSS,
			Details:    details.String(),
		},
	}
}

func (s *JSSecretsScanner) fetchBody(client *http.Client, fetchURL string) string {
	req, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	// Cap each JS file at 1MB to avoid huge bundles
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return string(body)
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// extractScriptURLs returns absolute URLs of all <script src="..."> on the page.
func (s *JSSecretsScanner) extractScriptURLs(baseURL, body string) []string {
	matches := scriptSrcRe.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var urls []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		raw := strings.TrimSpace(m[1])
		if raw == "" {
			continue
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := base.ResolveReference(ref).String()

		// Only HTTP(S) and skip third-party CDNs that aren't the target's responsibility.
		// We still scan same-host or same-org subdomains.
		if !strings.HasPrefix(abs, "http://") && !strings.HasPrefix(abs, "https://") {
			continue
		}

		// Limit to same host to avoid scanning Google Analytics, jQuery CDN, etc.
		// — those are out of the target's control and would produce noise.
		absParsed, _ := url.Parse(abs)
		if absParsed.Host != base.Host && !strings.HasSuffix(absParsed.Host, "."+base.Host) {
			continue
		}

		if seen[abs] {
			continue
		}
		seen[abs] = true
		urls = append(urls, abs)
	}
	return urls
}
