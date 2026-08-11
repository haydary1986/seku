package scanner

// Nuclei Template Scanner
// -----------------------------------------------------------------------------
// Integrates ProjectDiscovery's nuclei (https://github.com/projectdiscovery/nuclei)
// as a Seku scanner. Rather than vendoring the very large nuclei Go SDK (which
// would pull a huge dependency tree into this module), we shell out to the
// nuclei binary and parse its JSONL output. This keeps Seku's go.mod clean and
// lets template/version management live in the Dockerfile. The scanner degrades
// gracefully: if the binary or templates are missing it returns an informational
// result instead of failing the scan.
//
// nuclei runs thousands of active detection templates (CVEs, exposures,
// misconfigurations, and 240+ default-login templates), so it is heavier/slower
// than the other checks and is therefore OPT-IN:
//
//   SEKU_ENABLE_NUCLEI=1
//
// Optional tuning (all have safe defaults):
//   SEKU_NUCLEI_SEVERITY       default "low,medium,high,critical" (skip info noise)
//   SEKU_NUCLEI_TAGS           e.g. "cve,default-login,exposure" (empty = all)
//   SEKU_NUCLEI_RATE           requests/sec, default "150"
//   SEKU_NUCLEI_TIMEOUT        overall seconds budget, default 120
//   SEKU_NUCLEI_MAX_RESULTS    cap emitted findings, default 100
//   SEKU_NUCLEI_TEMPLATES_DIR  custom -templates-directory
//   SEKU_NUCLEI_BIN            path to the nuclei binary, default "nuclei"

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

type NucleiScanner struct{}

func NewNucleiScanner() *NucleiScanner { return &NucleiScanner{} }

func (s *NucleiScanner) Name() string     { return "Nuclei Template Scanner" }
func (s *NucleiScanner) Category() string { return "nuclei" }
func (s *NucleiScanner) Weight() float64  { return 15.0 }

const (
	nucleiDefaultTimeout = 120
	nucleiDefaultMax     = 100
)

type nucleiFinding struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Tags           []string `json:"tags"`
		Classification *struct {
			CVSSScore   float64 `json:"cvss-score"`
			CVSSMetrics string  `json:"cvss-metrics"`
		} `json:"classification"`
	} `json:"info"`
}

func (s *NucleiScanner) Scan(rawURL string) []models.CheckResult { return s.scan(rawURL, nil) }

// ScanWithConfig lets a scan enable nuclei per-run without the env flag.
func (s *NucleiScanner) ScanWithConfig(rawURL string, cfg *ScanConfig) []models.CheckResult {
	return s.scan(rawURL, cfg)
}

func (s *NucleiScanner) scan(rawURL string, cfg *ScanConfig) []models.CheckResult {
	if strings.TrimSpace(os.Getenv("SEKU_ENABLE_NUCLEI")) != "1" && !(cfg != nil && cfg.EnableNuclei) {
		return []models.CheckResult{s.info("Nuclei Template Scan",
			"nuclei is disabled. Enable it per-scan (Advanced options) or set SEKU_ENABLE_NUCLEI=1.", 0)}
	}

	bin := envStr("SEKU_NUCLEI_BIN", "nuclei")
	if _, err := exec.LookPath(bin); err != nil {
		return []models.CheckResult{s.info("Nuclei Template Scan",
			"nuclei binary not found in the image — template scanning skipped. Install nuclei to enable it.", 0)}
	}

	findings, runErr := s.run(bin, ensureHTTPS(rawURL),
		envStr("SEKU_NUCLEI_SEVERITY", "low,medium,high,critical"),
		envStr("SEKU_NUCLEI_TAGS", ""))
	return s.assemble(findings, runErr)
}

// assemble turns raw nuclei findings into CheckResults (summary first).
func (s *NucleiScanner) assemble(findings []nucleiFinding, runErr error) []models.CheckResult {
	results := make([]models.CheckResult, 0, len(findings)+1)

	maxResults := envInt("SEKU_NUCLEI_MAX_RESULTS", nucleiDefaultMax)
	counts := map[string]int{}
	emitted := 0
	for _, f := range findings {
		sev := strings.ToLower(f.Info.Severity)
		counts[sev]++
		if emitted >= maxResults {
			continue
		}
		emitted++
		results = append(results, s.findingResult(f))
	}

	summary := models.CheckResult{Category: s.Category(), CheckName: "Nuclei Template Scan", Weight: 5.0}
	total := len(findings)
	if total == 0 {
		summary.Status, summary.Score, summary.Severity = "pass", 1000, "info"
		msg := "No nuclei template matched the target."
		if runErr != nil {
			msg = "nuclei completed with no findings (" + runErr.Error() + ")."
		}
		summary.Details = toJSON(map[string]string{"message": msg})
	} else {
		worst := worstSeverity(counts)
		score, sevLabel, status := nucleiSeverity(worst)
		summary.Status, summary.Score, summary.Severity = status, score, sevLabel
		summary.Details = toJSON(map[string]interface{}{
			"message":        fmt.Sprintf("nuclei matched %d template(s).", total),
			"by_severity":    counts,
			"emitted":        emitted,
			"truncated":      total > emitted,
			"worst_severity": worst,
		})
	}
	return append([]models.CheckResult{summary}, results...)
}

// RunNucleiAdHoc runs nuclei against a single target with explicit severity/tags,
// bypassing the enable gate. Used by the dedicated single-target admin tool.
func RunNucleiAdHoc(target, severity, tags string) []models.CheckResult {
	s := &NucleiScanner{}
	bin := envStr("SEKU_NUCLEI_BIN", "nuclei")
	if _, err := exec.LookPath(bin); err != nil {
		return []models.CheckResult{s.info("Nuclei Template Scan", "nuclei binary not found in the image.", 0)}
	}
	if strings.TrimSpace(severity) == "" {
		severity = "low,medium,high,critical"
	}
	findings, runErr := s.run(bin, ensureHTTPS(target), severity, tags)
	return s.assemble(findings, runErr)
}

func (s *NucleiScanner) run(bin, target, severity, tags string) ([]nucleiFinding, error) {
	timeout := time.Duration(envInt("SEKU_NUCLEI_TIMEOUT", nucleiDefaultTimeout)) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{
		"-u", target,
		"-jsonl", "-silent", "-no-color",
		"-disable-update-check", "-no-interactsh",
		"-timeout", "10", "-retries", "1",
		"-rate-limit", envStr("SEKU_NUCLEI_RATE", "150"),
	}
	if severity != "" {
		args = append(args, "-severity", severity)
	}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	if td := envStr("SEKU_NUCLEI_TEMPLATES_DIR", ""); td != "" {
		args = append(args, "-t", td) // -t accepts a template directory
	}

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
	_ = cmd.Wait() // non-zero exit / ctx timeout are expected; we use what we parsed
	if ctx.Err() == context.DeadlineExceeded {
		return findings, fmt.Errorf("nuclei hit the %ds time budget", int(timeout.Seconds()))
	}
	return findings, nil
}

func (s *NucleiScanner) findingResult(f nucleiFinding) models.CheckResult {
	score, sevLabel, status := nucleiSeverity(f.Info.Severity)
	c := models.CheckResult{
		Category:  s.Category(),
		CheckName: nucleiCheckName(f),
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
	c.Confidence = 80
	c.Details = toJSON(details)
	return c
}

func nucleiCheckName(f nucleiFinding) string {
	name := strings.TrimSpace(f.Info.Name)
	if name == "" {
		name = f.TemplateID
	}
	// keep names readable/bounded
	if len(name) > 120 {
		name = name[:117] + "..."
	}
	return "Nuclei: " + name
}

func (s *NucleiScanner) info(check, msg string, weight float64) models.CheckResult {
	return models.CheckResult{
		Category:  s.Category(),
		CheckName: check,
		Weight:    weight,
		Status:    "info",
		Score:     1000,
		Severity:  "info",
		Details:   toJSON(map[string]string{"message": msg, "state": "skipped"}),
	}
}

func nucleiSeverity(sev string) (float64, string, string) {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 0, "critical", "fail"
	case "high":
		return 150, "high", "fail"
	case "medium":
		return 400, "medium", "fail"
	case "low":
		return 700, "low", "fail"
	case "info":
		return 1000, "info", "info"
	default:
		return 800, "low", "warn"
	}
}

func worstSeverity(counts map[string]int) string {
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[sev] > 0 {
			return sev
		}
	}
	return "info"
}

func envStr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
