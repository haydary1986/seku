package scanner

// Content Discovery Scanner (ffuf)
// -----------------------------------------------------------------------------
// Integrates ffuf/ffuf (https://github.com/ffuf/ffuf) to brute-force common
// paths/files and surface hidden endpoints (admin panels, backups, VCS/config
// leaks, API docs). Same binary+JSON integration style as nuclei/katana.
// A curated common-paths wordlist is embedded and written to a temp file at
// runtime, so no wordlist has to be managed in the image.
//
// Active scanner — OPT-IN, per-scan (Advanced options) or via env:
//   SEKU_ENABLE_FFUF=1
// Optional: SEKU_FFUF_TIMEOUT (default 90s), SEKU_FFUF_WORDLIST (override),
//           SEKU_FFUF_MAX_RESULTS (default 100), SEKU_FFUF_BIN.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	_ "embed"

	"seku/internal/models"
)

//go:embed wordlists/content.txt
var embeddedContentPaths string

type FFUFScanner struct{}

func NewFFUFScanner() *FFUFScanner { return &FFUFScanner{} }

func (s *FFUFScanner) Name() string     { return "Content Discovery Scanner" }
func (s *FFUFScanner) Category() string { return "content_discovery" }
func (s *FFUFScanner) Weight() float64  { return 8.0 }

type ffufOutput struct {
	Results []struct {
		Input  map[string]string `json:"input"`
		URL    string            `json:"url"`
		Status int               `json:"status"`
		Length int               `json:"length"`
	} `json:"results"`
}

func (s *FFUFScanner) Scan(rawURL string) []models.CheckResult { return s.scan(rawURL, nil) }

func (s *FFUFScanner) ScanWithConfig(rawURL string, cfg *ScanConfig) []models.CheckResult {
	return s.scan(rawURL, cfg)
}

func (s *FFUFScanner) scan(rawURL string, cfg *ScanConfig) []models.CheckResult {
	if strings.TrimSpace(os.Getenv("SEKU_ENABLE_FFUF")) != "1" && !(cfg != nil && cfg.EnableFFUF) {
		return []models.CheckResult{s.info("Content Discovery",
			"Content discovery is disabled. Enable it per-scan (Advanced options) or set SEKU_ENABLE_FFUF=1.")}
	}
	bin := envStr("SEKU_FFUF_BIN", "ffuf")
	if _, err := exec.LookPath(bin); err != nil {
		return []models.CheckResult{s.info("Content Discovery",
			"ffuf binary not found in the image — content discovery skipped.")}
	}

	results := s.run(bin, ensureHTTPS(rawURL))
	maxResults := envInt("SEKU_FFUF_MAX_RESULTS", 100)

	found := make([]models.CheckResult, 0, len(results)+1)
	sensitive := 0
	for i, r := range results {
		if i >= maxResults {
			break
		}
		cr, isSensitive := s.pathResult(r.URL, r.Status, r.Length)
		if isSensitive {
			sensitive++
		}
		found = append(found, cr)
	}

	summary := models.CheckResult{Category: s.Category(), CheckName: "Content Discovery", Weight: 3.0, Status: "info", Score: 1000, Severity: "info"}
	summary.Details = toJSON(map[string]interface{}{
		"message":        fmt.Sprintf("Discovered %d reachable path(s); %d are potentially sensitive.", len(results), sensitive),
		"paths_found":    len(results),
		"sensitive_hits": sensitive,
	})
	return append([]models.CheckResult{summary}, found...)
}

func (s *FFUFScanner) run(bin, target string) []struct {
	Input  map[string]string
	URL    string
	Status int
	Length int
} {
	// write the wordlist to a temp file
	wl := envStr("SEKU_FFUF_WORDLIST", "")
	if wl != "" {
		if st, err := os.Stat(wl); err != nil || st.Size() == 0 {
			wl = "" // baked wordlist missing/empty → fall back to the embedded list
		}
	}
	cleanup := func() {}
	if wl == "" {
		f, err := os.CreateTemp("", "seku-ffuf-*.txt")
		if err != nil {
			return nil
		}
		_, _ = f.WriteString(embeddedContentPaths)
		_ = f.Close()
		wl = f.Name()
		cleanup = func() { _ = os.Remove(wl) }
	}
	defer cleanup()

	outFile, err := os.CreateTemp("", "seku-ffuf-out-*.json")
	if err != nil {
		return nil
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer os.Remove(outPath)

	timeout := time.Duration(envInt("SEKU_FFUF_TIMEOUT", 90)) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{
		"-u", strings.TrimRight(target, "/") + "/FUZZ",
		"-w", wl,
		"-mc", "200,204,301,302,307,401,403,405",
		"-ac", "-t", "20", "-timeout", "10",
		"-of", "json", "-o", outPath, "-s", "-noninteractive",
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	_ = cmd.Run()

	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil
	}
	var parsed ffufOutput
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil
	}
	out := make([]struct {
		Input  map[string]string
		URL    string
		Status int
		Length int
	}, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		out = append(out, struct {
			Input  map[string]string
			URL    string
			Status int
			Length int
		}{r.Input, r.URL, r.Status, r.Length})
	}
	return out
}

func (s *FFUFScanner) pathResult(u string, status, length int) (models.CheckResult, bool) {
	lu := strings.ToLower(u)
	label, sev := "", ""
	for _, se := range sensitiveEndpoints {
		if strings.Contains(lu, se.pat) {
			label, sev = se.label, se.sev
			break
		}
	}
	c := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Path: " + shortPath(u),
		Weight:    4.0,
		Confidence: 85,
	}
	details := map[string]interface{}{"url": u, "status": status, "length": length}
	if label != "" {
		score, sevLabel, st := endpointScore(sev)
		c.Status, c.Score, c.Severity = st, score, sevLabel
		details["message"] = "Potentially sensitive path is reachable: " + label
		c.Details = toJSON(details)
		return c, true
	}
	c.Status, c.Score, c.Severity = "info", 1000, "info"
	details["message"] = "Reachable path discovered."
	c.Details = toJSON(details)
	return c, false
}

func (s *FFUFScanner) info(check, msg string) models.CheckResult {
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

func shortPath(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			p := rest[j:]
			if len(p) > 60 {
				return p[:57] + "..."
			}
			return p
		}
	}
	if len(u) > 60 {
		return u[:57] + "..."
	}
	return u
}
