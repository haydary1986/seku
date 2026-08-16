package scanner

// Nuclei DAST (Active Fuzzing) Scanner
// -----------------------------------------------------------------------------
// Runs nuclei in DAST/fuzzing mode (`-dast`) against parameter-bearing URLs to
// find INJECTION-class vulnerabilities that template matching alone misses:
// SSTI, LFI/path-traversal, XXE, OS command injection, reflected SQLi/XSS via
// parameter fuzzing, open-redirect, and SSRF. It reuses the nuclei binary and
// the full nuclei-templates tree already baked into the image (the fuzzing
// templates live under templates `dast/` + `http/fuzzing/`).
//
// This is ACTIVE, intrusive testing (it sends crafted payloads into parameters),
// so it is strictly OPT-IN and gated behind the caller's authorization:
//
//   per-scan:  enable_nuclei_dast=true  (Advanced options, requires authorized=true)
//   server:    SEKU_ENABLE_NUCLEI_DAST=1
//
// Candidate URLs = the target itself PLUS parameter-bearing historical URLs
// discovered passively via gau (bounded). The scanner degrades gracefully: if
// nuclei/gau are missing, or nothing is fuzzable, it returns an informational
// result instead of failing the scan.
//
// Tuning (safe defaults):
//   SEKU_DAST_TIMEOUT      overall seconds budget, default 180
//   SEKU_DAST_RATE         requests/sec, default 50 (gentler than template mode)
//   SEKU_DAST_MAX_URLS     max candidate URLs to fuzz, default 40
//   SEKU_DAST_TAGS         narrow to specific classes, default "" (all fuzzing templates)
//   SEKU_NUCLEI_MAX_RESULTS cap emitted findings (shared with template mode), default 100

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"seku/internal/models"
)

type NucleiDastScanner struct{}

func NewNucleiDastScanner() *NucleiDastScanner { return &NucleiDastScanner{} }

func (s *NucleiDastScanner) Name() string     { return "Nuclei DAST (Active Fuzzing)" }
func (s *NucleiDastScanner) Category() string { return "dast" }
func (s *NucleiDastScanner) Weight() float64  { return 15.0 }

const (
	dastDefaultTimeout = 180
	dastDefaultRate    = "50"
	dastDefaultMaxURLs = 40
)

func (s *NucleiDastScanner) Scan(rawURL string) []models.CheckResult { return s.scan(rawURL, nil) }

// ScanWithConfig lets a scan enable DAST fuzzing per-run without the env flag.
func (s *NucleiDastScanner) ScanWithConfig(rawURL string, cfg *ScanConfig) []models.CheckResult {
	return s.scan(rawURL, cfg)
}

func (s *NucleiDastScanner) scan(rawURL string, cfg *ScanConfig) []models.CheckResult {
	enabled := strings.TrimSpace(os.Getenv("SEKU_ENABLE_NUCLEI_DAST")) == "1" ||
		(cfg != nil && cfg.EnableNucleiDast)
	if !enabled {
		return []models.CheckResult{s.info("Active Fuzzing (DAST)",
			"DAST fuzzing is disabled. Enable it per-scan (Advanced options) or set SEKU_ENABLE_NUCLEI_DAST=1. This is intrusive — run it only on systems you own or are authorized to test.")}
	}

	bin := envStr("SEKU_NUCLEI_BIN", "nuclei")
	if _, err := exec.LookPath(bin); err != nil {
		return []models.CheckResult{s.info("Active Fuzzing (DAST)",
			"nuclei binary not found in the image — DAST fuzzing skipped.")}
	}

	target := ensureHTTPS(rawURL)
	urls := s.candidateURLs(target)

	findings, runErr := s.run(bin, urls, cfg)
	return s.assemble(findings, len(urls), runErr)
}

// candidateURLs returns the target plus parameter-bearing URLs discovered
// passively via gau (bounded). Fuzzing is only meaningful on URLs that carry
// parameters, so we prioritise those.
func (s *NucleiDastScanner) candidateURLs(target string) []string {
	seen := map[string]bool{target: true}
	urls := []string{target}

	max := envInt("SEKU_DAST_MAX_URLS", dastDefaultMaxURLs)
	gau := envStr("SEKU_GAU_BIN", "gau")
	if _, err := exec.LookPath(gau); err != nil {
		return urls // gau absent → fuzz the target alone
	}
	host := extractHost(target)
	if host == "" {
		return urls
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, gau, "--threads", "5", "--timeout", "12", host)
	out, err := cmd.Output()
	if err != nil {
		return urls
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		u := strings.TrimSpace(sc.Text())
		if u == "" || !strings.Contains(u, "?") || seen[u] {
			continue // only parameter-bearing, deduped
		}
		seen[u] = true
		urls = append(urls, u)
		if len(urls) >= max {
			break
		}
	}
	return urls
}

func (s *NucleiDastScanner) run(bin string, urls []string, cfg *ScanConfig) ([]nucleiFinding, error) {
	// Write candidate URLs to a temp list for `nuclei -l`.
	tmp, err := os.CreateTemp("", "seku-dast-*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	for _, u := range urls {
		fmt.Fprintln(tmp, u)
	}
	tmp.Close()

	timeout := time.Duration(envInt("SEKU_DAST_TIMEOUT", dastDefaultTimeout)) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{
		"-dast",
		"-l", tmp.Name(),
		"-jsonl", "-silent", "-no-color",
		"-disable-update-check", "-no-interactsh",
		"-timeout", "10", "-retries", "1",
		"-rate-limit", envStr("SEKU_DAST_RATE", dastDefaultRate),
	}
	if td := envStr("SEKU_NUCLEI_TEMPLATES_DIR", ""); td != "" {
		args = append(args, "-t", td)
	}
	if tags := strings.TrimSpace(os.Getenv("SEKU_DAST_TAGS")); tags != "" {
		args = append(args, "-tags", tags)
	}
	// Authenticated fuzzing: inject the session so DAST reaches pages behind login.
	args = append(args, cfg.authToolArgs()...)

	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var findings []nucleiFinding
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var f nucleiFinding
		if err := json.Unmarshal([]byte(line), &f); err == nil && f.Info.Name != "" {
			findings = append(findings, f)
		}
	}
	_ = cmd.Wait() // non-zero exit / ctx timeout are expected; use what we parsed
	if ctx.Err() == context.DeadlineExceeded {
		return findings, fmt.Errorf("DAST hit the %ds time budget", int(timeout.Seconds()))
	}
	return findings, nil
}

// assemble turns raw DAST findings into CheckResults (summary first), under the
// "dast" category so scoring treats confirmed injections as critical.
func (s *NucleiDastScanner) assemble(findings []nucleiFinding, urlCount int, runErr error) []models.CheckResult {
	results := make([]models.CheckResult, 0, len(findings)+1)

	maxResults := envInt("SEKU_NUCLEI_MAX_RESULTS", nucleiDefaultMax)
	counts := map[string]int{}
	emitted := 0
	for _, f := range findings {
		counts[strings.ToLower(f.Info.Severity)]++
		if emitted >= maxResults {
			continue
		}
		emitted++
		results = append(results, s.findingResult(f))
	}

	summary := models.CheckResult{Category: s.Category(), CheckName: "Active Fuzzing (DAST)", Weight: 5.0}
	if len(findings) == 0 {
		summary.Status, summary.Score, summary.Severity = "pass", 1000, "info"
		msg := fmt.Sprintf("No injection found by DAST fuzzing across %d URL(s).", urlCount)
		if runErr != nil {
			msg = fmt.Sprintf("DAST completed with no findings across %d URL(s) (%s).", urlCount, runErr.Error())
		}
		summary.Details = toJSON(map[string]interface{}{"message": msg, "urls_fuzzed": urlCount})
	} else {
		worst := worstSeverity(counts)
		score, sevLabel, status := nucleiSeverity(worst)
		summary.Status, summary.Score, summary.Severity = status, score, sevLabel
		summary.Details = toJSON(map[string]interface{}{
			"message":        fmt.Sprintf("DAST fuzzing found %d injection issue(s) across %d URL(s).", len(findings), urlCount),
			"by_severity":    counts,
			"emitted":        emitted,
			"truncated":      len(findings) > emitted,
			"worst_severity": worst,
			"urls_fuzzed":    urlCount,
		})
	}
	return append([]models.CheckResult{summary}, results...)
}

func (s *NucleiDastScanner) findingResult(f nucleiFinding) models.CheckResult {
	score, sevLabel, status := nucleiSeverity(f.Info.Severity)
	name := nucleiCheckName(f)
	name = "DAST: " + strings.TrimPrefix(name, "Nuclei: ")
	c := models.CheckResult{
		Category:  s.Category(),
		CheckName: name,
		Weight:    5.0,
		Status:    status,
		Score:     score,
		Severity:  sevLabel,
	}
	details := map[string]interface{}{
		"message":     f.Info.Description,
		"template_id": f.TemplateID,
		"matched_at":  f.MatchedAt,
		"tags":        f.Info.Tags,
		"severity":    strings.ToLower(f.Info.Severity),
	}
	if f.Info.Classification != nil && f.Info.Classification.CVSSScore > 0 {
		c.CVSSScore = f.Info.Classification.CVSSScore
		c.CVSSVector = f.Info.Classification.CVSSMetrics
		c.CVSSRating = sevLabel
		details["cvss_score"] = f.Info.Classification.CVSSScore
	}
	c.Confidence = 85 // fuzzing confirms via response differential — high confidence
	c.Details = toJSON(details)
	return c
}

func (s *NucleiDastScanner) info(check, msg string) models.CheckResult {
	return models.CheckResult{
		Category:  s.Category(),
		CheckName: check,
		Weight:    5.0,
		Status:    "info",
		Score:     1000,
		Severity:  "info",
		Details:   toJSON(map[string]string{"message": msg, "state": "skipped"}),
	}
}
