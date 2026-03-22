package scanner

import (
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type SEOScanner struct{}

func NewSEOScanner() *SEOScanner {
	return &SEOScanner{}
}

func (s *SEOScanner) Name() string     { return "SEO & Technical Health Scanner" }
func (s *SEOScanner) Category() string { return "seo" }
func (s *SEOScanner) Weight() float64  { return 7.0 }

func (s *SEOScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	targetURL := ensureHTTPS(url)

	// Fetch the page HTML once and reuse it for multiple checks
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		resp, err = client.Get(strings.Replace(targetURL, "https://", "http://", 1))
	}

	var html string
	if err == nil {
		defer resp.Body.Close()
		const maxRead = 5 * 1024 * 1024
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRead))
		if readErr == nil {
			html = string(body)
		}
	}

	results = append(results, s.checkMetaTags(html))
	results = append(results, s.checkOpenGraphTags(html))
	results = append(results, s.checkSitemap(targetURL))
	results = append(results, s.checkRobotsTxt(targetURL, client))
	results = append(results, s.checkStructuredData(html))
	results = append(results, s.checkMobileFriendliness(html))

	return results
}

// ---------------------------------------------------------------------------
// 1. Meta Tags Quality (Weight: 2.0)
// ---------------------------------------------------------------------------

func (s *SEOScanner) checkMetaTags(html string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Meta Tags Quality",
		Weight:    2.0,
	}

	if html == "" {
		check.Score = 0
		check.Status = "error"
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{"error": "Could not fetch page HTML"})
		return check
	}

	var score float64
	findings := map[string]interface{}{}
	htmlLower := strings.ToLower(html)

	// Check <title> tag: present and length 10-70
	titleRe := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	titleMatch := titleRe.FindStringSubmatch(html)
	if len(titleMatch) > 1 {
		titleText := strings.TrimSpace(titleMatch[1])
		titleLen := len(titleText)
		findings["title"] = titleText
		findings["title_length"] = titleLen
		if titleLen >= 10 && titleLen <= 70 {
			score += 250
			findings["title_status"] = "good"
		} else {
			findings["title_status"] = "bad_length"
		}
	} else {
		findings["title_status"] = "missing"
	}

	// Check <meta name="description">: present and length 50-160
	descRe := regexp.MustCompile(`(?i)<meta[^>]+name\s*=\s*["']description["'][^>]+content\s*=\s*["'](.*?)["']`)
	descMatch := descRe.FindStringSubmatch(html)
	if len(descMatch) < 2 {
		// Try alternate attribute order
		descRe2 := regexp.MustCompile(`(?i)<meta[^>]+content\s*=\s*["'](.*?)["'][^>]+name\s*=\s*["']description["']`)
		descMatch = descRe2.FindStringSubmatch(html)
	}
	if len(descMatch) > 1 {
		descText := strings.TrimSpace(descMatch[1])
		descLen := len(descText)
		findings["description_length"] = descLen
		if descLen >= 50 && descLen <= 160 {
			score += 250
			findings["description_status"] = "good"
		} else {
			findings["description_status"] = "bad_length"
		}
	} else {
		findings["description_status"] = "missing"
	}

	// Check <meta name="viewport">
	if strings.Contains(htmlLower, `name="viewport"`) || strings.Contains(htmlLower, `name='viewport'`) {
		score += 200
		findings["viewport"] = "present"
	} else {
		findings["viewport"] = "missing"
	}

	// Check <link rel="canonical">
	if strings.Contains(htmlLower, `rel="canonical"`) || strings.Contains(htmlLower, `rel='canonical'`) {
		score += 150
		findings["canonical"] = "present"
	} else {
		findings["canonical"] = "missing"
	}

	// Check <html lang="...">
	langRe := regexp.MustCompile(`(?i)<html[^>]+lang\s*=\s*["'][^"']+["']`)
	if langRe.MatchString(html) {
		score += 150
		findings["html_lang"] = "present"
	} else {
		findings["html_lang"] = "missing"
	}

	if score > 1000 {
		score = 1000
	}

	findings["score_breakdown"] = "title(250) + description(250) + viewport(200) + canonical(150) + lang(150)"
	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(findings)

	return check
}

// ---------------------------------------------------------------------------
// 2. Open Graph Tags (Weight: 1.5)
// ---------------------------------------------------------------------------

func (s *SEOScanner) checkOpenGraphTags(html string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Open Graph Tags",
		Weight:    1.5,
	}

	if html == "" {
		check.Score = 0
		check.Status = "error"
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{"error": "Could not fetch page HTML"})
		return check
	}

	var score float64
	findings := map[string]interface{}{}
	htmlLower := strings.ToLower(html)

	// og:title (+250)
	if strings.Contains(htmlLower, `property="og:title"`) || strings.Contains(htmlLower, `property='og:title'`) {
		score += 250
		findings["og_title"] = "present"
	} else {
		findings["og_title"] = "missing"
	}

	// og:description (+250)
	if strings.Contains(htmlLower, `property="og:description"`) || strings.Contains(htmlLower, `property='og:description'`) {
		score += 250
		findings["og_description"] = "present"
	} else {
		findings["og_description"] = "missing"
	}

	// og:image (+250)
	if strings.Contains(htmlLower, `property="og:image"`) || strings.Contains(htmlLower, `property='og:image'`) {
		score += 250
		findings["og_image"] = "present"
	} else {
		findings["og_image"] = "missing"
	}

	// og:url (+125)
	if strings.Contains(htmlLower, `property="og:url"`) || strings.Contains(htmlLower, `property='og:url'`) {
		score += 125
		findings["og_url"] = "present"
	} else {
		findings["og_url"] = "missing"
	}

	// og:type (+125)
	if strings.Contains(htmlLower, `property="og:type"`) || strings.Contains(htmlLower, `property='og:type'`) {
		score += 125
		findings["og_type"] = "present"
	} else {
		findings["og_type"] = "missing"
	}

	if score > 1000 {
		score = 1000
	}

	findings["score_breakdown"] = "og:title(250) + og:description(250) + og:image(250) + og:url(125) + og:type(125)"
	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(findings)

	return check
}

// ---------------------------------------------------------------------------
// 3. Sitemap Accessibility (Weight: 1.5)
// ---------------------------------------------------------------------------

func (s *SEOScanner) checkSitemap(baseURL string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Sitemap Accessibility",
		Weight:    1.5,
	}

	findings := map[string]interface{}{}

	sitemapPaths := []string{"/sitemap.xml", "/sitemap_index.xml"}

	noRedirectClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, path := range sitemapPaths {
		sitemapURL := baseURL + path
		resp, err := noRedirectClient.Get(sitemapURL)
		if err != nil {
			continue
		}

		const maxRead = 1 * 1024 * 1024
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRead))
		resp.Body.Close()
		if readErr != nil {
			continue
		}

		bodyStr := string(body)
		bodyLower := strings.ToLower(bodyStr)

		findings["url"] = sitemapURL
		findings["status_code"] = resp.StatusCode

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			// Redirect
			check.Score = 700
			findings["message"] = "Sitemap found but returns redirect"
			findings["redirect_location"] = resp.Header.Get("Location")
			check.Status = statusFromScore(check.Score)
			check.Severity = severityFromScore(check.Score)
			check.Details = toJSON(findings)
			return check
		}

		if resp.StatusCode == 200 {
			if strings.Contains(bodyLower, "<?xml") || strings.Contains(bodyLower, "<urlset") || strings.Contains(bodyLower, "<sitemapindex") {
				check.Score = 1000
				findings["message"] = "Sitemap found with valid XML content"
				findings["content_type"] = resp.Header.Get("Content-Type")
			} else {
				check.Score = 600
				findings["message"] = "Sitemap found but does not contain XML content"
				findings["content_type"] = resp.Header.Get("Content-Type")
			}
			check.Status = statusFromScore(check.Score)
			check.Severity = severityFromScore(check.Score)
			check.Details = toJSON(findings)
			return check
		}
	}

	// No sitemap found
	check.Score = 200
	findings["message"] = "No sitemap found at /sitemap.xml or /sitemap_index.xml"
	check.Status = statusFromScore(check.Score)
	check.Severity = severityFromScore(check.Score)
	check.Details = toJSON(findings)

	return check
}

// ---------------------------------------------------------------------------
// 4. Robots.txt Quality (Weight: 1.0)
// ---------------------------------------------------------------------------

func (s *SEOScanner) checkRobotsTxt(baseURL string, client *http.Client) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Robots.txt Quality",
		Weight:    1.0,
	}

	findings := map[string]interface{}{}

	robotsURL := baseURL + "/robots.txt"
	resp, err := client.Get(robotsURL)
	if err != nil {
		check.Score = 200
		check.Status = statusFromScore(check.Score)
		check.Severity = severityFromScore(check.Score)
		findings["message"] = "Could not fetch robots.txt"
		findings["error"] = err.Error()
		check.Details = toJSON(findings)
		return check
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		check.Score = 200
		check.Status = statusFromScore(check.Score)
		check.Severity = severityFromScore(check.Score)
		findings["message"] = "robots.txt not found"
		findings["status_code"] = resp.StatusCode
		check.Details = toJSON(findings)
		return check
	}

	const maxRead = 512 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if err != nil {
		check.Score = 200
		check.Status = statusFromScore(check.Score)
		check.Severity = severityFromScore(check.Score)
		findings["message"] = "Failed to read robots.txt body"
		check.Details = toJSON(findings)
		return check
	}

	content := string(body)
	contentLower := strings.ToLower(content)
	lines := strings.Split(content, "\n")

	// Check if it is empty or minimal (fewer than 3 non-empty lines)
	nonEmpty := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			nonEmpty++
		}
	}

	if nonEmpty < 3 {
		check.Score = 500
		check.Status = statusFromScore(check.Score)
		check.Severity = severityFromScore(check.Score)
		findings["message"] = "robots.txt exists but is empty or minimal"
		findings["non_empty_lines"] = nonEmpty
		check.Details = toJSON(findings)
		return check
	}

	var score float64

	// Has Sitemap directive: +400
	sitemapRe := regexp.MustCompile(`(?i)^sitemap\s*:`)
	hasSitemap := false
	for _, line := range lines {
		if sitemapRe.MatchString(strings.TrimSpace(line)) {
			hasSitemap = true
			break
		}
	}
	if hasSitemap {
		score += 400
		findings["has_sitemap_directive"] = true
	} else {
		findings["has_sitemap_directive"] = false
	}

	// Has specific Allow/Disallow rules: +300
	hasRules := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(trimmed, "allow:") || strings.HasPrefix(trimmed, "disallow:") {
			// Check it has a path (not just empty disallow)
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
				hasRules = true
				break
			}
		}
	}
	if hasRules {
		score += 300
		findings["has_specific_rules"] = true
	} else {
		findings["has_specific_rules"] = false
	}

	// Not blocking important paths (/, /css, /js): +300
	importantPaths := []string{"/css", "/js"}
	blockingImportant := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "disallow:") {
			parts := strings.SplitN(lower, ":", 2)
			if len(parts) == 2 {
				path := strings.TrimSpace(parts[1])
				// Blocking root entirely
				if path == "/" {
					blockingImportant = true
					break
				}
				for _, imp := range importantPaths {
					if path == imp || strings.HasPrefix(path, imp+"/") {
						blockingImportant = true
						break
					}
				}
			}
		}
		if blockingImportant {
			break
		}
	}

	if !blockingImportant {
		score += 300
		findings["blocking_important_paths"] = false
	} else {
		findings["blocking_important_paths"] = true
	}

	if score > 1000 {
		score = 1000
	}

	_ = contentLower // used implicitly via lines

	findings["score_breakdown"] = "sitemap_directive(400) + specific_rules(300) + not_blocking_important(300)"
	findings["non_empty_lines"] = nonEmpty

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(findings)

	return check
}

// ---------------------------------------------------------------------------
// 5. Structured Data (Weight: 0.5)
// ---------------------------------------------------------------------------

func (s *SEOScanner) checkStructuredData(html string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Structured Data",
		Weight:    0.5,
	}

	if html == "" {
		check.Score = 0
		check.Status = "error"
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{"error": "Could not fetch page HTML"})
		return check
	}

	findings := map[string]interface{}{}
	htmlLower := strings.ToLower(html)

	// Check for JSON-LD blocks
	jsonLdRe := regexp.MustCompile(`(?i)<script[^>]+type\s*=\s*["']application/ld\+json["'][^>]*>`)
	jsonLdMatches := jsonLdRe.FindAllStringIndex(html, -1)
	jsonLdCount := len(jsonLdMatches)

	if jsonLdCount > 0 {
		check.Score = 1000
		if jsonLdCount > 1 {
			findings["message"] = "Multiple JSON-LD structured data blocks found"
		} else {
			findings["message"] = "JSON-LD structured data found"
		}
		findings["json_ld_count"] = jsonLdCount
		check.Status = statusFromScore(check.Score)
		check.Severity = severityFromScore(check.Score)
		check.Details = toJSON(findings)
		return check
	}

	// Check for microdata (itemscope)
	if strings.Contains(htmlLower, "itemscope") {
		check.Score = 600
		findings["message"] = "No JSON-LD found but microdata (itemscope) detected"
		findings["has_microdata"] = true
		check.Status = statusFromScore(check.Score)
		check.Severity = severityFromScore(check.Score)
		check.Details = toJSON(findings)
		return check
	}

	// No structured data
	check.Score = 200
	findings["message"] = "No structured data found (no JSON-LD or microdata)"
	check.Status = statusFromScore(check.Score)
	check.Severity = severityFromScore(check.Score)
	check.Details = toJSON(findings)

	return check
}

// ---------------------------------------------------------------------------
// 6. Mobile Friendliness (Weight: 0.5)
// ---------------------------------------------------------------------------

func (s *SEOScanner) checkMobileFriendliness(html string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Mobile Friendliness",
		Weight:    0.5,
	}

	if html == "" {
		check.Score = 0
		check.Status = "error"
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{"error": "Could not fetch page HTML"})
		return check
	}

	var score float64
	findings := map[string]interface{}{}
	htmlLower := strings.ToLower(html)

	// Check for <meta name="viewport" content="width=device-width">: +500
	viewportRe := regexp.MustCompile(`(?i)<meta[^>]+name\s*=\s*["']viewport["'][^>]+content\s*=\s*["'][^"']*width\s*=\s*device-width[^"']*["']`)
	if !viewportRe.MatchString(html) {
		// Try alternate attribute order
		viewportRe2 := regexp.MustCompile(`(?i)<meta[^>]+content\s*=\s*["'][^"']*width\s*=\s*device-width[^"']*["'][^>]+name\s*=\s*["']viewport["']`)
		if viewportRe2.MatchString(html) {
			score += 500
			findings["viewport_device_width"] = "present"
		} else {
			findings["viewport_device_width"] = "missing"
		}
	} else {
		score += 500
		findings["viewport_device_width"] = "present"
	}

	// Check no viewport with fixed width: +250
	fixedWidthRe := regexp.MustCompile(`(?i)<meta[^>]+name\s*=\s*["']viewport["'][^>]+content\s*=\s*["'][^"']*width\s*=\s*\d+[^"']*["']`)
	if !fixedWidthRe.MatchString(html) {
		score += 250
		findings["no_fixed_viewport_width"] = true
	} else {
		findings["no_fixed_viewport_width"] = false
	}

	// Check body/container not using fixed pixel widths in inline styles: +250
	fixedInlineRe := regexp.MustCompile(`(?i)<(?:body|div)[^>]+style\s*=\s*["'][^"']*width\s*:\s*\d{4,}px`)
	if strings.Contains(htmlLower, "style=") && fixedInlineRe.MatchString(html) {
		findings["no_fixed_inline_widths"] = false
	} else {
		score += 250
		findings["no_fixed_inline_widths"] = true
	}

	if score > 1000 {
		score = 1000
	}

	findings["score_breakdown"] = "viewport_device_width(500) + no_fixed_viewport(250) + no_fixed_inline_widths(250)"
	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(findings)

	return check
}
