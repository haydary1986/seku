package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type ThirdPartyScanner struct{}

func NewThirdPartyScanner() *ThirdPartyScanner {
	return &ThirdPartyScanner{}
}

func (s *ThirdPartyScanner) Name() string     { return "Third-Party Scripts Risk Scanner" }
func (s *ThirdPartyScanner) Category() string { return "third_party" }
func (s *ThirdPartyScanner) Weight() float64  { return 6.0 }

// trustedCDNs lists known/trusted CDN and analytics domains.
var trustedCDNs = []string{
	"googleapis.com",
	"gstatic.com",
	"cloudflare.com",
	"cdnjs.cloudflare.com",
	"jsdelivr.net",
	"unpkg.com",
	"bootstrapcdn.com",
	"jquery.com",
	"google.com",
	"googletagmanager.com",
	"facebook.net",
	"twitter.com",
	"youtube.com",
	"google-analytics.com",
}

// suspiciousTLDs are TLDs commonly associated with abuse.
var suspiciousTLDs = []string{".tk", ".ml", ".ga", ".cf", ".xyz", ".top"}

func (s *ThirdPartyScanner) Scan(rawURL string) []models.CheckResult {
	var results []models.CheckResult

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: ScanTransport,
	}

	targetURL := ensureHTTPS(rawURL)
	resp, err := client.Get(targetURL)
	if err != nil {
		return []models.CheckResult{{
			Category:  s.Category(),
			CheckName: "Third-Party Scripts",
			Status:    "error",
			Score:     0,
			Weight:    s.Weight(),
			Severity:  "medium",
			Details:   toJSON(map[string]string{"error": "Cannot reach website"}),
		}}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyStr := string(body)

	siteHost := extractHost(targetURL)

	// Collect external scripts and CSS once and share across checks
	extScripts := s.findExternalScripts(bodyStr, siteHost)
	extCSS := s.findExternalCSS(bodyStr, siteHost)

	results = append(results, s.checkExternalScriptCount(extScripts))
	results = append(results, s.checkSubresourceIntegrity(bodyStr, extScripts))
	results = append(results, s.checkTrustedSources(extScripts))
	results = append(results, s.checkExternalCSSCount(extCSS))

	return results
}

// externalResource holds metadata about a discovered external resource.
type externalResource struct {
	URL       string
	Host      string
	HasSRI    bool
	IsTrusted bool
}

// findExternalScripts extracts external <script src="https://..."> tags whose
// host differs from the site's own host.
func (s *ThirdPartyScanner) findExternalScripts(body, siteHost string) []externalResource {
	// Match <script ... src="http(s)://..." ... >
	pattern := regexp.MustCompile(`(?i)<script[^>]*\ssrc\s*=\s*["'](https?://[^"']+)["'][^>]*>`)
	matches := pattern.FindAllStringSubmatch(body, -1)

	var resources []externalResource
	for _, m := range matches {
		srcURL := m[1]
		host := extractHostFromURL(srcURL)
		if host == "" || strings.EqualFold(host, siteHost) {
			continue
		}

		// Check if the full tag contains integrity attribute
		fullTag := m[0]
		hasSRI := regexp.MustCompile(`(?i)integrity\s*=\s*["']sha`).MatchString(fullTag)

		resources = append(resources, externalResource{
			URL:       srcURL,
			Host:      host,
			HasSRI:    hasSRI,
			IsTrusted: isTrustedHost(host),
		})
	}
	return resources
}

// findExternalCSS extracts external <link rel="stylesheet" href="https://..."> tags.
func (s *ThirdPartyScanner) findExternalCSS(body, siteHost string) []externalResource {
	pattern := regexp.MustCompile(`(?i)<link[^>]*\srel\s*=\s*["']stylesheet["'][^>]*\shref\s*=\s*["'](https?://[^"']+)["'][^>]*>`)
	// Also match when href comes before rel
	pattern2 := regexp.MustCompile(`(?i)<link[^>]*\shref\s*=\s*["'](https?://[^"']+)["'][^>]*\srel\s*=\s*["']stylesheet["'][^>]*>`)

	seen := map[string]bool{}
	var resources []externalResource

	for _, pat := range []*regexp.Regexp{pattern, pattern2} {
		matches := pat.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			hrefURL := m[1]
			if seen[hrefURL] {
				continue
			}
			seen[hrefURL] = true

			host := extractHostFromURL(hrefURL)
			if host == "" || strings.EqualFold(host, siteHost) {
				continue
			}
			resources = append(resources, externalResource{
				URL:  hrefURL,
				Host: host,
			})
		}
	}
	return resources
}

// ---------- Check 1: External Script Count ----------

func (s *ThirdPartyScanner) checkExternalScriptCount(scripts []externalResource) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "External Script Count",
		Weight:    2.0,
	}

	count := len(scripts)
	var score float64

	switch {
	case count <= 3:
		score = 1000
	case count <= 6:
		score = 850
	case count <= 10:
		score = 700
	case count <= 15:
		score = 500
	case count <= 20:
		score = 300
	default:
		score = 150
	}

	// Collect unique hosts for details
	hostSet := map[string]bool{}
	for _, r := range scripts {
		hostSet[r.Host] = true
	}
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"message":          fmt.Sprintf("Found %d external script(s) from %d unique domain(s)", count, len(hosts)),
		"external_scripts": count,
		"unique_domains":   len(hosts),
		"domains":          hosts,
	})

	return check
}

// ---------- Check 2: Subresource Integrity (SRI) ----------

func (s *ThirdPartyScanner) checkSubresourceIntegrity(body string, scripts []externalResource) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Subresource Integrity (SRI)",
		Weight:    2.0,
	}

	total := len(scripts)
	if total == 0 {
		check.Score = 1000
		check.Status = "pass"
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No external scripts found - SRI check not applicable",
		})
		return check
	}

	withSRI := 0
	var missingSRI []string
	for _, r := range scripts {
		if r.HasSRI {
			withSRI++
		} else {
			missingSRI = append(missingSRI, r.URL)
		}
	}

	ratio := float64(withSRI) / float64(total)
	var score float64

	switch {
	case ratio >= 1.0:
		score = 1000
	case ratio >= 0.75:
		score = 800
	case ratio >= 0.50:
		score = 600
	case withSRI > 0:
		score = 400
	default:
		score = 150
	}

	// Trim the missing list for display
	displayMissing := missingSRI
	if len(displayMissing) > 10 {
		displayMissing = displayMissing[:10]
	}

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"message":            fmt.Sprintf("%d/%d external scripts have SRI (%.0f%%)", withSRI, total, ratio*100),
		"total_external":     total,
		"with_sri":           withSRI,
		"without_sri":        total - withSRI,
		"missing_sri_sample": displayMissing,
	})

	return check
}

// ---------- Check 3: Trusted Sources ----------

func (s *ThirdPartyScanner) checkTrustedSources(scripts []externalResource) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Trusted Sources",
		Weight:    1.0,
	}

	total := len(scripts)
	if total == 0 {
		check.Score = 1000
		check.Status = "pass"
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No external scripts found",
		})
		return check
	}

	trusted := 0
	var untrustedHosts []string
	hasSuspiciousTLD := false

	for _, r := range scripts {
		if r.IsTrusted {
			trusted++
		} else {
			untrustedHosts = append(untrustedHosts, r.Host)
			for _, tld := range suspiciousTLDs {
				if strings.HasSuffix(strings.ToLower(r.Host), tld) {
					hasSuspiciousTLD = true
					break
				}
			}
		}
	}

	ratio := float64(trusted) / float64(total)
	var score float64

	switch {
	case hasSuspiciousTLD:
		score = 50
	case ratio >= 1.0:
		score = 1000
	case ratio >= 0.80:
		score = 800
	case ratio >= 0.60:
		score = 600
	default:
		score = 300
	}

	// Deduplicate untrusted hosts for display
	hostSet := map[string]bool{}
	var uniqueUntrusted []string
	for _, h := range untrustedHosts {
		if !hostSet[h] {
			hostSet[h] = true
			uniqueUntrusted = append(uniqueUntrusted, h)
		}
	}
	if len(uniqueUntrusted) > 10 {
		uniqueUntrusted = uniqueUntrusted[:10]
	}

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"message":            fmt.Sprintf("%d/%d scripts from trusted sources (%.0f%%)", trusted, total, ratio*100),
		"total":              total,
		"trusted":            trusted,
		"untrusted":          total - trusted,
		"has_suspicious_tld": hasSuspiciousTLD,
		"untrusted_hosts":    uniqueUntrusted,
	})

	return check
}

// ---------- Check 4: External CSS Count ----------

func (s *ThirdPartyScanner) checkExternalCSSCount(cssResources []externalResource) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "External CSS Count",
		Weight:    1.0,
	}

	count := len(cssResources)
	var score float64

	switch {
	case count <= 3:
		score = 1000
	case count <= 6:
		score = 800
	case count <= 10:
		score = 600
	default:
		score = 400
	}

	hosts := map[string]bool{}
	for _, r := range cssResources {
		hosts[r.Host] = true
	}
	hostList := make([]string, 0, len(hosts))
	for h := range hosts {
		hostList = append(hostList, h)
	}

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"message":         fmt.Sprintf("Found %d external stylesheet(s)", count),
		"external_css":    count,
		"unique_domains":  len(hostList),
		"domains":         hostList,
	})

	return check
}

// ---------- helpers ----------

// extractHostFromURL parses an absolute URL and returns its hostname.
func extractHostFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// isTrustedHost checks whether a host belongs to a known trusted CDN.
func isTrustedHost(host string) bool {
	host = strings.ToLower(host)
	for _, cdn := range trustedCDNs {
		if host == cdn || strings.HasSuffix(host, "."+cdn) {
			return true
		}
	}
	return false
}
