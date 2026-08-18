package scanner

// Dalfox Advanced XSS Scanner
// -----------------------------------------------------------------------------
// Integrates hahwul/dalfox (https://github.com/hahwul/dalfox) — a powerful XSS
// scanner with parameter mining, DOM analysis, and payload verification. Same
// binary+JSON integration style as nuclei/katana (no SDK dependency added).
// Complements Seku's built-in XSS scanner with deeper, verified detection.
//
// Active scanner — OPT-IN, per-scan (Advanced options) or via env:
//   SEKU_ENABLE_DALFOX=1
// Optional: SEKU_DALFOX_TIMEOUT (default 120s), SEKU_DALFOX_BIN.

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

type DalfoxScanner struct{}

func NewDalfoxScanner() *DalfoxScanner { return &DalfoxScanner{} }

func (s *DalfoxScanner) Name() string     { return "Dalfox Advanced XSS Scanner" }
func (s *DalfoxScanner) Category() string { return "xss_advanced" }
func (s *DalfoxScanner) Weight() float64  { return 12.0 }

type dalfoxFinding struct {
	Type       string `json:"type"`
	InjectType string `json:"inject_type"`
	Param      string `json:"param"`
	Data       string `json:"data"` // PoC URL
	Payload    string `json:"payload"`
	Evidence   string `json:"evidence"`
	CWE        string `json:"cwe"`
	Severity   string `json:"severity"`
	MessageStr string `json:"message_str"`
}

func (s *DalfoxScanner) Scan(rawURL string) []models.CheckResult { return s.scan(rawURL, nil) }

func (s *DalfoxScanner) ScanWithConfig(rawURL string, cfg *ScanConfig) []models.CheckResult {
	return s.scan(rawURL, cfg)
}

func (s *DalfoxScanner) scan(rawURL string, cfg *ScanConfig) []models.CheckResult {
	if strings.TrimSpace(os.Getenv("SEKU_ENABLE_DALFOX")) != "1" && !(cfg != nil && cfg.EnableDalfox) {
		return []models.CheckResult{s.info("Dalfox XSS Scan",
			"Advanced XSS scanning is disabled. Enable it per-scan (Advanced options) or set SEKU_ENABLE_DALFOX=1.")}
	}
	bin := envStr("SEKU_DALFOX_BIN", "dalfox")
	if _, err := exec.LookPath(bin); err != nil {
		return []models.CheckResult{s.info("Dalfox XSS Scan",
			"dalfox binary not found in the image — advanced XSS scan skipped.")}
	}

	findings := s.run(bin, ensureHTTPS(rawURL))

	results := make([]models.CheckResult, 0, len(findings)+1)
	for _, f := range findings {
		results = append(results, s.findingResult(f))
	}

	summary := models.CheckResult{Category: s.Category(), CheckName: "Dalfox XSS Scan", Weight: 4.0}
	if len(findings) == 0 {
		summary.Status, summary.Score, summary.Severity = "pass", 1000, "info"
		summary.Details = toJSON(map[string]string{"message": "No XSS confirmed by dalfox."})
	} else {
		summary.Status, summary.Score, summary.Severity = "fail", 0, "high"
		summary.Details = toJSON(map[string]interface{}{
			"message": fmt.Sprintf("dalfox confirmed %d XSS finding(s).", len(findings)),
			"count":   len(findings),
		})
	}
	return append([]models.CheckResult{summary}, results...)
}

func (s *DalfoxScanner) run(bin, target string) []dalfoxFinding {
	timeout := time.Duration(envInt("SEKU_DALFOX_TIMEOUT", 120)) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{"url", target, "--format", "json", "--silence", "--no-color",
		"--timeout", "10", "--worker", "20", "--skip-bav"}
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	_ = cmd.Run()

	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 {
		return nil
	}
	// dalfox --format json emits a JSON array; fall back to line-delimited objects.
	var arr []dalfoxFinding
	if err := json.Unmarshal(out, &arr); err == nil {
		return arr
	}
	var findings []dalfoxFinding
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var f dalfoxFinding
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			findings = append(findings, f)
		}
	}
	return findings
}

func (s *DalfoxScanner) findingResult(f dalfoxFinding) models.CheckResult {
	score, sevLabel, status := xssSeverity(f.Severity, f.Type)
	verified := strings.EqualFold(f.Type, "V") // dalfox 'V' = browser-verified
	if !verified {
		// 'R' (reflected) / 'A' (AST) are UNCONFIRMED — don't report them like a
		// verified exploit. Downgrade to a warning so a mere reflection isn't a
		// false high/critical.
		status = "warn"
		if score < 550 {
			score = 550
		}
		sevLabel = "medium"
	}
	name := "Dalfox XSS"
	if f.Param != "" {
		name = "Dalfox XSS: param " + f.Param
	}
	c := models.CheckResult{
		Category:   s.Category(),
		CheckName:  name,
		Weight:     6.0,
		Status:     status,
		Score:      score,
		Severity:   sevLabel,
		Confidence: 55,
	}
	if verified {
		c.Confidence = 99
	}
	details := map[string]interface{}{
		"message":     f.MessageStr,
		"param":       f.Param,
		"payload":     f.Payload,
		"poc":         f.Data,
		"inject_type": f.InjectType,
		"type":        f.Type,
	}
	if f.CWE != "" {
		c.CWE = f.CWE
	}
	c.Details = toJSON(details)
	return c
}

func (s *DalfoxScanner) info(check, msg string) models.CheckResult {
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

func xssSeverity(sev, typ string) (float64, string, string) {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 0, "critical", "fail"
	case "high":
		return 100, "high", "fail"
	case "medium":
		return 400, "medium", "fail"
	case "low":
		return 650, "low", "warn"
	case "info":
		return 1000, "info", "info"
	default:
		if strings.EqualFold(typ, "V") {
			return 100, "high", "fail"
		}
		return 400, "medium", "fail"
	}
}
