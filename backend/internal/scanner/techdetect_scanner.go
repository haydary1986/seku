package scanner

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type TechDetectScanner struct{}

func NewTechDetectScanner() *TechDetectScanner {
	return &TechDetectScanner{}
}

func (s *TechDetectScanner) Name() string     { return "Technology Detection Scanner" }
func (s *TechDetectScanner) Category() string { return "tech_stack" }
func (s *TechDetectScanner) Weight() float64  { return 4.0 }

// frameworkSignature describes a detectable web framework.
type frameworkSignature struct {
	name     string
	patterns []string // strings to search in body
	header   string   // specific header to check
	version  string   // regex to extract version from body or header value
}

var frameworkSignatures = []frameworkSignature{
	{"WordPress", []string{"wp-content", "wp-includes"}, "X-Powered-By", `WordPress\s*([0-9.]+)`},
	{"Drupal", []string{"Drupal.settings", "sites/default"}, "X-Generator", `Drupal\s*([0-9.]+)`},
	{"Joomla", []string{"com_content", "/media/jui/"}, "X-Content-Encoded-By", `Joomla!\s*([0-9.]+)`},
	{"Laravel", []string{"laravel_session"}, "X-Powered-By", ``},
	{"Django", []string{"csrfmiddlewaretoken", "django"}, "", ``},
	{"Express", []string{}, "X-Powered-By", `Express`},
	{"ASP.NET", []string{"__VIEWSTATE", "__EVENTVALIDATION"}, "X-AspNet-Version", `([0-9.]+)`},
	{"Ruby on Rails", []string{"csrf-token", "authenticity_token"}, "X-Powered-By", `Phusion Passenger`},
	{"Next.js", []string{"__NEXT_DATA__", "_next/"}, "", ``},
	{"Nuxt.js", []string{"__NUXT__", "_nuxt/"}, "", ``},
	{"React", []string{"react-root", "__react", "data-reactroot"}, "", ``},
	{"Vue.js", []string{"data-v-", "__vue__", "Vue.js"}, "", ``},
	{"Angular", []string{"ng-version", "ng-app", "angular.min.js"}, "", ``},
	{"Svelte", []string{"svelte", "__svelte"}, "", ``},
	{"Moodle", []string{"moodle", "M.cfg"}, "", ``},
	{"Elementor", []string{"elementor", "elementor-frontend"}, "", ``},
}

// techFetchResult stores the fetched response for reuse across checks.
type techFetchResult struct {
	body    string
	headers http.Header
}

func (s *TechDetectScanner) Scan(url string) []models.CheckResult {
	fetched := s.fetchPage(url)

	return []models.CheckResult{
		s.checkWebFramework(fetched),
		s.checkServerTechnology(fetched),
		s.checkJSLibraries(fetched),
	}
}

func (s *TechDetectScanner) fetchPage(url string) techFetchResult {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: ScanTransport,
	}

	resp, err := client.Get(ensureHTTPS(url))
	if err != nil {
		resp, err = client.Get(ensureHTTP(url))
		if err != nil {
			return techFetchResult{}
		}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return techFetchResult{headers: resp.Header}
	}

	return techFetchResult{
		body:    string(bodyBytes),
		headers: resp.Header,
	}
}

func (s *TechDetectScanner) checkWebFramework(fetched techFetchResult) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Web Framework Detection",
		Weight:    1.5,
	}

	var detected []map[string]string

	for _, fw := range frameworkSignatures {
		matchedByBody := false
		for _, pattern := range fw.patterns {
			if strings.Contains(fetched.body, pattern) {
				matchedByBody = true
				break
			}
		}

		matchedByHeader := false
		if fw.header != "" && fetched.headers != nil {
			headerVal := fetched.headers.Get(fw.header)
			if headerVal != "" {
				if fw.version != "" {
					re := regexp.MustCompile(fw.version)
					if re.MatchString(headerVal) {
						matchedByHeader = true
					}
				}
				// Also check if the header simply contains the framework name
				if strings.Contains(strings.ToLower(headerVal), strings.ToLower(fw.name)) {
					matchedByHeader = true
				}
			}
		}

		if !matchedByBody && !matchedByHeader {
			continue
		}

		entry := map[string]string{
			"framework": fw.name,
			"source":    "body",
		}
		if matchedByHeader {
			entry["source"] = "header"
		}

		// Try to extract version
		if fw.version != "" {
			re := regexp.MustCompile(fw.version)
			if matches := re.FindStringSubmatch(fetched.body); len(matches) > 1 {
				entry["version"] = matches[1]
			}
			if fetched.headers != nil && fw.header != "" {
				headerVal := fetched.headers.Get(fw.header)
				if matches := re.FindStringSubmatch(headerVal); len(matches) > 1 {
					entry["version"] = matches[1]
				}
			}
		}

		detected = append(detected, entry)
	}

	details := map[string]interface{}{
		"frameworks_detected": len(detected),
		"frameworks":          detected,
	}

	if len(detected) > 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		names := make([]string, 0, len(detected))
		for _, d := range detected {
			name := d["framework"]
			if v, ok := d["version"]; ok {
				name += " " + v
			}
			names = append(names, name)
		}
		details["message"] = fmt.Sprintf("Detected frameworks: %s", strings.Join(names, ", "))
	} else {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No known web frameworks detected"
	}

	check.Details = toJSON(details)
	return check
}

// knownServers maps server header values to canonical names.
var knownServers = []struct {
	pattern string
	name    string
}{
	{"apache", "Apache"},
	{"nginx", "Nginx"},
	{"litespeed", "LiteSpeed"},
	{"microsoft-iis", "Microsoft IIS"},
	{"cloudflare", "Cloudflare"},
	{"openresty", "OpenResty"},
	{"caddy", "Caddy"},
	{"gunicorn", "Gunicorn"},
	{"express", "Express"},
	{"jetty", "Jetty"},
	{"tomcat", "Apache Tomcat"},
}

var knownCDNs = []struct {
	header  string
	value   string
	name    string
}{
	{"Server", "cloudflare", "Cloudflare"},
	{"X-CDN", "", "CDN detected"},
	{"X-Cache", "HIT", "CDN Cache"},
	{"Via", "cloudfront", "AWS CloudFront"},
	{"X-Akamai-Transformed", "", "Akamai"},
	{"X-Fastly-Request-ID", "", "Fastly"},
	{"X-Served-By", "cache-", "Fastly"},
}

var versionRegex = regexp.MustCompile(`[0-9]+\.[0-9]+(?:\.[0-9]+)?`)

func (s *TechDetectScanner) checkServerTechnology(fetched techFetchResult) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Server Technology Detection",
		Weight:    1.5,
	}

	if fetched.headers == nil {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "Could not fetch headers; skipping server technology detection",
		})
		return check
	}

	var detected []map[string]string
	versionExposed := false

	// Detect server
	serverHeader := fetched.headers.Get("Server")
	if serverHeader != "" {
		serverLower := strings.ToLower(serverHeader)
		serverName := serverHeader
		for _, ks := range knownServers {
			if strings.Contains(serverLower, ks.pattern) {
				serverName = ks.name
				break
			}
		}

		entry := map[string]string{
			"type":   "server",
			"name":   serverName,
			"raw":    serverHeader,
			"source": "Server header",
		}
		if v := versionRegex.FindString(serverHeader); v != "" {
			entry["version"] = v
			versionExposed = true
		}
		detected = append(detected, entry)
	}

	// Detect X-Powered-By
	poweredBy := fetched.headers.Get("X-Powered-By")
	if poweredBy != "" {
		entry := map[string]string{
			"type":   "runtime",
			"name":   poweredBy,
			"source": "X-Powered-By header",
		}
		if v := versionRegex.FindString(poweredBy); v != "" {
			entry["version"] = v
			versionExposed = true
		}

		// Detect language
		pbLower := strings.ToLower(poweredBy)
		switch {
		case strings.Contains(pbLower, "php"):
			entry["language"] = "PHP"
		case strings.Contains(pbLower, "asp.net"):
			entry["language"] = "ASP.NET"
		case strings.Contains(pbLower, "express"):
			entry["language"] = "Node.js"
		case strings.Contains(pbLower, "passenger"):
			entry["language"] = "Ruby"
		}

		detected = append(detected, entry)
	}

	// Detect CDNs
	for _, cdn := range knownCDNs {
		headerVal := fetched.headers.Get(cdn.header)
		if headerVal == "" {
			continue
		}
		if cdn.value != "" && !strings.Contains(strings.ToLower(headerVal), cdn.value) {
			continue
		}
		detected = append(detected, map[string]string{
			"type":   "cdn",
			"name":   cdn.name,
			"source": cdn.header + " header",
		})
	}

	// Detect programming language from other headers
	if xGenerated := fetched.headers.Get("X-Generator"); xGenerated != "" {
		detected = append(detected, map[string]string{
			"type":   "generator",
			"name":   xGenerated,
			"source": "X-Generator header",
		})
		if v := versionRegex.FindString(xGenerated); v != "" {
			versionExposed = true
		}
	}

	details := map[string]interface{}{
		"technologies_detected": len(detected),
		"technologies":          detected,
		"version_exposed":       versionExposed,
	}

	if versionExposed {
		check.Status = "warn"
		check.Score = 700
		check.Severity = "low"
		details["message"] = "Server technologies detected with version numbers exposed (information leak)"
	} else if len(detected) > 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = fmt.Sprintf("%d server technologies detected", len(detected))
	} else {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No server technologies detected from headers"
	}

	check.Details = toJSON(details)
	return check
}

// jsLibSignature describes a JavaScript library to detect.
type jsLibSignature struct {
	name           string
	bodyPatterns   []string
	versionRegex   string
	latestMajor    int // latest known major version (for outdated detection)
	outdatedBefore string // version string; anything below this is considered outdated
}

var jsLibSignatures = []jsLibSignature{
	{
		"jQuery",
		[]string{"jquery", "jQuery"},
		`jquery[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)`,
		3, "3.5.0",
	},
	{
		"React",
		[]string{"react.production.min.js", "react.development.js", "react@"},
		`react(?:\.min)?\.js.*?([0-9]+\.[0-9]+\.[0-9]+)`,
		18, "17.0.0",
	},
	{
		"Vue.js",
		[]string{"vue.min.js", "vue.global", "vue@", "vue.js"},
		`vue(?:\.min)?\.js.*?([0-9]+\.[0-9]+\.[0-9]+)`,
		3, "2.7.0",
	},
	{
		"Angular",
		[]string{"angular.min.js", "angular.js", "@angular/core"},
		`angular(?:\.min)?\.js.*?([0-9]+\.[0-9]+\.[0-9]+)`,
		17, "14.0.0",
	},
	{
		"Lodash",
		[]string{"lodash.min.js", "lodash.js", "lodash@"},
		`lodash(?:\.min)?\.js.*?([0-9]+\.[0-9]+\.[0-9]+)`,
		4, "4.17.21",
	},
	{
		"Moment.js",
		[]string{"moment.min.js", "moment.js", "moment@"},
		`moment(?:\.min)?\.js.*?([0-9]+\.[0-9]+\.[0-9]+)`,
		2, "2.29.0",
	},
	{
		"Bootstrap",
		[]string{"bootstrap.min.js", "bootstrap.min.css", "bootstrap@", "bootstrap.js"},
		`bootstrap[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)`,
		5, "4.6.0",
	},
	{
		"Tailwind CSS",
		[]string{"tailwindcss", "tailwind.min.css", "tailwind@"},
		`tailwindcss[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)`,
		3, "3.0.0",
	},
}

func (s *TechDetectScanner) checkJSLibraries(fetched techFetchResult) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "JavaScript Library Inventory",
		Weight:    1.0,
	}

	if fetched.body == "" {
		check.Status = "error"
		check.Score = 0
		check.Weight = 0
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "Could not fetch page body; skipping JS library detection",
		})
		return check
	}

	bodyLower := strings.ToLower(fetched.body)
	var inventory []map[string]string
	outdatedCount := 0

	for _, lib := range jsLibSignatures {
		found := false
		for _, pattern := range lib.bodyPatterns {
			if strings.Contains(bodyLower, strings.ToLower(pattern)) {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		entry := map[string]string{
			"library": lib.name,
		}

		// Try to extract version
		if lib.versionRegex != "" {
			re := regexp.MustCompile(`(?i)` + lib.versionRegex)
			if matches := re.FindStringSubmatch(fetched.body); len(matches) > 1 {
				entry["version"] = matches[1]
				if isVersionOutdated(matches[1], lib.outdatedBefore) {
					entry["outdated"] = "true"
					outdatedCount++
				}
			}
		}

		inventory = append(inventory, entry)
	}

	details := map[string]interface{}{
		"libraries_found":   len(inventory),
		"outdated_count":    outdatedCount,
		"library_inventory": inventory,
	}

	if outdatedCount > 0 {
		check.Status = "warn"
		check.Score = 600
		check.Severity = "medium"
		details["message"] = fmt.Sprintf(
			"%d JS libraries detected, %d potentially outdated",
			len(inventory), outdatedCount,
		)
	} else if len(inventory) > 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = fmt.Sprintf("%d JS libraries detected, none appear outdated", len(inventory))
	} else {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No common JS libraries detected in page source"
	}

	check.Details = toJSON(details)
	return check
}

// isVersionOutdated performs a simple semver comparison.
// Returns true if current is older than threshold.
func isVersionOutdated(current, threshold string) bool {
	cParts := parseVersionArray(current)
	tParts := parseVersionArray(threshold)

	for i := 0; i < 3; i++ {
		if cParts[i] < tParts[i] {
			return true
		}
		if cParts[i] > tParts[i] {
			return false
		}
	}
	return false // equal
}

// parseVersionArray splits a version string into [major, minor, patch].
func parseVersionArray(v string) [3]int {
	var parts [3]int
	idx := 0
	num := 0
	started := false
	for _, ch := range v {
		if ch >= '0' && ch <= '9' {
			num = num*10 + int(ch-'0')
			started = true
		} else if ch == '.' && started {
			if idx < 3 {
				parts[idx] = num
			}
			idx++
			num = 0
			started = false
		}
	}
	if idx < 3 && started {
		parts[idx] = num
	}
	return parts
}
