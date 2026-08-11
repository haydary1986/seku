package scanner

// Crawl & Attack-Surface Scanner
// -----------------------------------------------------------------------------
// Integrates ProjectDiscovery's katana (https://github.com/projectdiscovery/katana)
// to crawl the target and map its attack surface, then flags sensitive endpoints
// that are commonly targeted (admin panels, APIs, uploads, VCS/config leaks, etc.).
//
// Same integration style as the nuclei scanner: shell out to the katana binary
// and parse its output (JSONL, with a plain-URL fallback). No SDK dependency is
// added to go.mod, and the scanner degrades gracefully if the binary is absent.
//
// Crawling is active and heavier than passive checks, so it is OPT-IN:
//
//   SEKU_ENABLE_KATANA=1
//
// Optional tuning:
//   SEKU_KATANA_DEPTH     crawl depth, default "2"
//   SEKU_KATANA_TIMEOUT   overall seconds budget, default 90
//   SEKU_KATANA_MAX_URLS  cap collected URLs, default 2000
//   SEKU_KATANA_BIN       path to the katana binary, default "katana"

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"seku/internal/models"
)

type CrawlScanner struct{}

func NewCrawlScanner() *CrawlScanner { return &CrawlScanner{} }

func (s *CrawlScanner) Name() string     { return "Crawl & Attack Surface Scanner" }
func (s *CrawlScanner) Category() string { return "crawl" }
func (s *CrawlScanner) Weight() float64  { return 8.0 }

const (
	crawlDefaultTimeout = 90
	crawlDefaultMaxURLs = 2000
)

// path substring -> (label, severity) for endpoints worth flagging when exposed.
var sensitiveEndpoints = []struct {
	pat, label, sev string
}{
	{"/.git", "Version control (.git) exposed", "high"},
	{"/.svn", "Version control (.svn) exposed", "high"},
	{"/.env", "Environment file exposed", "critical"},
	{"/wp-admin", "WordPress admin", "medium"},
	{"/wp-login.php", "WordPress login", "medium"},
	{"/xmlrpc.php", "WordPress XML-RPC", "medium"},
	{"/administrator", "Admin panel", "medium"},
	{"/admin", "Admin panel", "medium"},
	{"/phpmyadmin", "phpMyAdmin", "high"},
	{"/adminer", "Adminer DB tool", "high"},
	{"/actuator", "Spring Boot actuator", "high"},
	{"/swagger", "API docs (Swagger)", "low"},
	{"/openapi", "API docs (OpenAPI)", "low"},
	{"/graphql", "GraphQL endpoint", "medium"},
	{"/server-status", "Apache server-status", "medium"},
	{"/metrics", "Metrics endpoint", "low"},
	{"/phpinfo", "phpinfo()", "high"},
	{"/backup", "Backup path", "medium"},
	{"/upload", "Upload endpoint", "low"},
	{"/debug", "Debug endpoint", "medium"},
	{"/console", "Web console", "high"},
}

func (s *CrawlScanner) Scan(rawURL string) []models.CheckResult { return s.scan(rawURL, nil) }

// ScanWithConfig lets a scan enable crawling per-run without the env flag.
func (s *CrawlScanner) ScanWithConfig(rawURL string, cfg *ScanConfig) []models.CheckResult {
	return s.scan(rawURL, cfg)
}

func (s *CrawlScanner) scan(rawURL string, cfg *ScanConfig) []models.CheckResult {
	if strings.TrimSpace(os.Getenv("SEKU_ENABLE_KATANA")) != "1" && !(cfg != nil && cfg.EnableCrawl) {
		return []models.CheckResult{s.info("Attack Surface Map",
			"Crawling is disabled. Enable it per-scan (Advanced options) or set SEKU_ENABLE_KATANA=1.")}
	}

	bin := envStr("SEKU_KATANA_BIN", "katana")
	if _, err := exec.LookPath(bin); err != nil {
		return []models.CheckResult{s.info("Attack Surface Map",
			"katana binary not found in the image — crawling skipped.")}
	}

	target := ensureHTTPS(rawURL)
	host := extractHost(target)
	urls := s.run(bin, target)

	withParams := 0
	hits := map[string][]string{} // label -> example URLs
	sevOf := map[string]string{}
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		if parsed.RawQuery != "" {
			withParams++
		}
		lp := strings.ToLower(parsed.Path)
		for _, se := range sensitiveEndpoints {
			if strings.Contains(lp, se.pat) {
				if len(hits[se.label]) < 5 {
					hits[se.label] = append(hits[se.label], u)
				}
				sevOf[se.label] = se.sev
			}
		}
	}

	// summary
	summary := models.CheckResult{Category: s.Category(), CheckName: "Attack Surface Map", Weight: 3.0, Status: "info", Score: 1000, Severity: "info"}
	summary.Details = toJSON(map[string]interface{}{
		"message":          fmt.Sprintf("Crawled %s and discovered %d unique URL(s).", host, len(urls)),
		"urls_discovered":  len(urls),
		"urls_with_params": withParams,
	})

	// sensitive endpoints
	sensitive := models.CheckResult{Category: s.Category(), CheckName: "Sensitive Endpoints Exposed", Weight: 6.0}
	if len(hits) == 0 {
		sensitive.Status, sensitive.Score, sensitive.Severity = "pass", 1000, "info"
		sensitive.Details = toJSON(map[string]string{"message": "No commonly-sensitive endpoints found during the crawl."})
	} else {
		worst := worstEndpointSeverity(sevOf)
		score, sevLabel, status := endpointScore(worst)
		sensitive.Status, sensitive.Score, sensitive.Severity = status, score, sevLabel
		sensitive.Details = toJSON(map[string]interface{}{
			"message":  fmt.Sprintf("Found %d category(ies) of sensitive/interesting endpoints — review whether each should be publicly reachable.", len(hits)),
			"findings": hits,
		})
	}

	return []models.CheckResult{summary, sensitive}
}

func (s *CrawlScanner) run(bin, target string) []string {
	timeout := time.Duration(envInt("SEKU_KATANA_TIMEOUT", crawlDefaultTimeout)) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{
		"-u", target,
		"-jsonl", "-silent", "-nc",
		"-d", envStr("SEKU_KATANA_DEPTH", "2"),
		"-c", "10",
		"-timeout", "10",
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	if err := cmd.Start(); err != nil {
		return nil
	}

	maxURLs := envInt("SEKU_KATANA_MAX_URLS", crawlDefaultMaxURLs)
	seen := map[string]bool{}
	var urls []string
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		u := extractCrawlURL(strings.TrimSpace(sc.Text()))
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		urls = append(urls, u)
		if len(urls) >= maxURLs {
			break
		}
	}
	_ = cmd.Wait()

	sort.Strings(urls)
	return urls
}

// extractCrawlURL handles both katana JSONL ({"url":"..."} / {"request":{"endpoint":"..."}})
// and plain one-URL-per-line output.
func extractCrawlURL(line string) string {
	if line == "" {
		return ""
	}
	if line[0] == '{' {
		var obj struct {
			URL     string `json:"url"`
			Request struct {
				Endpoint string `json:"endpoint"`
				URL      string `json:"url"`
			} `json:"request"`
		}
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			switch {
			case obj.URL != "":
				return obj.URL
			case obj.Request.Endpoint != "":
				return obj.Request.Endpoint
			case obj.Request.URL != "":
				return obj.Request.URL
			}
		}
		return ""
	}
	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
		return line
	}
	return ""
}

func (s *CrawlScanner) info(check, msg string) models.CheckResult {
	return models.CheckResult{
		Category:  s.Category(),
		CheckName: check,
		Weight:    0,
		Status:    "info",
		Score:     1000,
		Severity:  "info",
		Details:   toJSON(map[string]string{"message": msg, "state": "skipped"}),
	}
}

func endpointScore(sev string) (float64, string, string) {
	switch sev {
	case "critical":
		return 100, "critical", "fail"
	case "high":
		return 250, "high", "fail"
	case "medium":
		return 500, "medium", "warn"
	default:
		return 750, "low", "warn"
	}
}

func worstEndpointSeverity(sevOf map[string]string) string {
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		for _, v := range sevOf {
			if v == sev {
				return sev
			}
		}
	}
	return "low"
}
