package scanner

// Streaming nuclei runner for the async single-target tool.
// Unlike RunNucleiAdHoc (synchronous, bounded to an HTTP request), this streams
// nuclei's live -stats progress and each finding as it is matched via onLine,
// and is time-boxed only by SEKU_NUCLEI_TOOL_TIMEOUT (default 30m) — so it can
// run ALL templates to completion.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"seku/internal/models"
)

// RunNucleiStream runs nuclei against target and invokes onLine for each log
// line (banner, periodic -stats progress on stderr, and each finding on stdout).
// onLine may be called concurrently from two goroutines; callers must guard it.
func RunNucleiStream(target, severity, tags string, onLine func(string)) []models.CheckResult {
	s := &NucleiScanner{}
	bin := envStr("SEKU_NUCLEI_BIN", "nuclei")
	if _, err := exec.LookPath(bin); err != nil {
		onLine("error: nuclei binary not found in the image")
		return []models.CheckResult{s.info("Nuclei Template Scan", "nuclei binary not found.", 0)}
	}
	if strings.TrimSpace(severity) == "" {
		severity = "low,medium,high,critical"
	}
	tags = strings.TrimSpace(tags)

	timeout := time.Duration(envInt("SEKU_NUCLEI_TOOL_TIMEOUT", 1800)) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	target = ensureHTTPS(target)
	args := []string{
		"-u", target,
		"-jsonl", "-no-color",
		"-disable-update-check", "-no-interactsh",
		"-timeout", "10", "-retries", "1",
		"-rate-limit", envStr("SEKU_NUCLEI_RATE", "150"),
		"-stats", "-stats-interval", "5",
		"-severity", severity,
	}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	if td := envStr("SEKU_NUCLEI_TEMPLATES_DIR", ""); td != "" {
		args = append(args, "-t", td)
	}

	scope := "all templates"
	if tags != "" {
		scope = "tags: " + tags
	}
	onLine(fmt.Sprintf("starting nuclei against %s  (severity: %s, %s)", target, severity, scope))

	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		onLine("error: " + err.Error())
		return []models.CheckResult{s.info("Nuclei Template Scan", "failed to open nuclei stdout.", 0)}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		onLine("error: " + err.Error())
		return []models.CheckResult{s.info("Nuclei Template Scan", "failed to open nuclei stderr.", 0)}
	}
	if err := cmd.Start(); err != nil {
		onLine("error starting nuclei: " + err.Error())
		return []models.CheckResult{s.info("Nuclei Template Scan", "failed to start nuclei.", 0)}
	}

	var mu sync.Mutex
	var findings []nucleiFinding
	var wg sync.WaitGroup
	wg.Add(2)

	// stdout: JSONL findings
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<23)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] != '{' {
				continue
			}
			var f nucleiFinding
			if err := json.Unmarshal([]byte(line), &f); err == nil && f.Info.Name != "" {
				mu.Lock()
				findings = append(findings, f)
				mu.Unlock()
				onLine(fmt.Sprintf("[%s] %s  ->  %s", strings.ToUpper(f.Info.Severity), f.Info.Name, f.MatchedAt))
			}
		}
	}()
	// stderr: banner + periodic -stats progress
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 1<<20), 1<<23)
		for sc.Scan() {
			if t := strings.TrimSpace(sc.Text()); t != "" {
				onLine(t)
			}
		}
	}()

	wg.Wait()
	_ = cmd.Wait()
	if ctx.Err() == context.DeadlineExceeded {
		onLine(fmt.Sprintf("stopped: reached the %d-minute time budget", int(timeout.Minutes())))
	}

	mu.Lock()
	total := len(findings)
	mu.Unlock()
	onLine(fmt.Sprintf("done — %d finding(s)", total))
	return s.assemble(findings, nil)
}
