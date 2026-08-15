package scanner

// Passive URL Discovery
// -----------------------------------------------------------------------------
// Pulls historical/known URLs for the target from passive sources (Wayback
// Machine, Common Crawl, OTX, URLScan) via `gau`, WITHOUT touching the target.
// These are endpoints/parameters that live crawling (katana) often misses —
// forgotten pages, old API routes, parameter-bearing URLs — i.e. prime targets
// for the injection scanners. v1 surfaces the attack surface (counts, param URLs,
// sensitive endpoints); wiring these URLs into the active scanners is the next step.
//
// Opt-in: runs when crawling is enabled (Advanced options) or SEKU_ENABLE_GAU=1.

import (
	"bufio"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"seku/internal/models"
)

type PassiveURLScanner struct{}

func NewPassiveURLScanner() *PassiveURLScanner { return &PassiveURLScanner{} }

func (s *PassiveURLScanner) Name() string     { return "Passive URL Discovery" }
func (s *PassiveURLScanner) Category() string { return "passive_urls" }
func (s *PassiveURLScanner) Weight() float64  { return 3.0 }

const passiveURLDefaultTimeout = 90
const passiveURLMax = 8000

func (s *PassiveURLScanner) Scan(rawURL string) []models.CheckResult { return s.scan(rawURL, nil) }

func (s *PassiveURLScanner) ScanWithConfig(rawURL string, cfg *ScanConfig) []models.CheckResult {
	return s.scan(rawURL, cfg)
}

func (s *PassiveURLScanner) scan(rawURL string, cfg *ScanConfig) []models.CheckResult {
	if strings.TrimSpace(envStr("SEKU_ENABLE_GAU", "")) != "1" && !(cfg != nil && cfg.EnableCrawl) {
		return []models.CheckResult{s.info("Passive URL Discovery",
			"Disabled. Enable crawling (Advanced options) or set SEKU_ENABLE_GAU=1 to pull historical URLs.")}
	}
	bin := envStr("SEKU_GAU_BIN", "gau")
	if _, err := exec.LookPath(bin); err != nil {
		return []models.CheckResult{s.info("Passive URL Discovery",
			"gau binary not found in the image — passive URL discovery skipped.")}
	}

	host := extractHost(ensureHTTPS(rawURL))
	urls := s.run(bin, host)

	seen := map[string]bool{}
	withParams := 0
	unique := 0
	hits := map[string][]string{}
	sevOf := map[string]string{}
	paramExamples := []string{}
	for _, u := range urls {
		if seen[u] {
			continue
		}
		seen[u] = true
		unique++
		lu := strings.ToLower(u)
		// only keep same-registrable-host results
		if host != "" && !strings.Contains(lu, strings.ToLower(host)) {
			continue
		}
		if strings.Contains(u, "?") && strings.Contains(u, "=") {
			withParams++
			if len(paramExamples) < 15 {
				paramExamples = append(paramExamples, u)
			}
		}
		for _, se := range sensitiveEndpoints {
			if strings.Contains(lu, se.pat) {
				if len(hits[se.label]) < 5 {
					hits[se.label] = append(hits[se.label], u)
				}
				sevOf[se.label] = se.sev
			}
		}
	}

	summary := models.CheckResult{Category: s.Category(), CheckName: "Passive URL Discovery", Weight: 2.0,
		Status: "info", Score: 1000, Severity: "info", Confidence: 80}
	summary.Details = toJSON(map[string]interface{}{
		"message":          "Discovered " + strconv.Itoa(unique) + " historical URL(s) for " + host + " from passive sources.",
		"urls_discovered":  unique,
		"urls_with_params": withParams,
		"note":             "Parameter-bearing URLs are prime candidates for injection testing.",
	})

	results := []models.CheckResult{summary}

	// Param-bearing URLs = injection candidates (advisory, low).
	if withParams > 0 {
		results = append(results, models.CheckResult{
			Category: s.Category(), CheckName: "Historical Parameter Endpoints", Weight: 4.0,
			Status: "warn", Score: 750, Severity: "low", Confidence: 65,
			OWASP: "A05:2021 - Security Misconfiguration",
			Details: toJSON(map[string]interface{}{
				"message":  strconv.Itoa(withParams) + " historical URL(s) carry parameters — review/scan them for injection (SQLi/XSS/SSRF/redirect).",
				"examples": paramExamples,
			}),
		})
	}

	// Sensitive historical endpoints.
	if len(hits) > 0 {
		worst := worstEndpointSeverity(sevOf)
		score, sevLabel, status := endpointScore(worst)
		results = append(results, models.CheckResult{
			Category: s.Category(), CheckName: "Sensitive Historical Endpoints", Weight: 6.0,
			Status: status, Score: score, Severity: sevLabel, Confidence: 60,
			Details: toJSON(map[string]interface{}{
				"message":  "Passive sources reveal historically-exposed sensitive endpoints — verify they are not still reachable.",
				"findings": hits,
			}),
		})
	}

	return results
}

func (s *PassiveURLScanner) run(bin, host string) []string {
	if host == "" {
		return nil
	}
	timeout := time.Duration(envInt("SEKU_GAU_TIMEOUT", passiveURLDefaultTimeout)) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "--threads", "5", "--timeout", "15", host)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	if err := cmd.Start(); err != nil {
		return nil
	}
	var urls []string
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 256*1024), 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "http") {
			continue
		}
		urls = append(urls, line)
		if len(urls) >= passiveURLMax {
			break
		}
	}
	_ = cmd.Wait()
	return urls
}

func (s *PassiveURLScanner) info(check, msg string) models.CheckResult {
	return models.CheckResult{
		Category: s.Category(), CheckName: check, Weight: 2.0,
		Status: "info", Score: 1000, Severity: "info",
		Details: toJSON(map[string]string{"message": msg, "state": "skipped"}),
	}
}
