package scanner

// Out-of-Band (OOB) Scanner — interactsh integration
// -----------------------------------------------------------------------------
// Confirms BLIND server-side vulnerabilities using ProjectDiscovery's interactsh
// (https://github.com/projectdiscovery/interactsh). Unlike response-diff/timing
// heuristics, an OOB interaction is near-zero false-positive: if the target's
// server actually calls back to our unique interactsh domain, the vulnerability
// is proven.
//
// This is an ADDITIVE, self-contained scanner (it does not modify the existing
// SSRF / Blind-SQLi scanners). It uses the interactsh client SDK in-process for
// reliable correlation, and degrades gracefully if no interactsh server is
// reachable. It sends active probes, so it is OPT-IN:
//
//   SEKU_ENABLE_OOB=1
//
// Optional:
//   SEKU_INTERACTSH_SERVER   custom self-hosted server(s), default public oast.*
//   SEKU_INTERACTSH_TOKEN    auth token for a private server
//   SEKU_OOB_MAX_PARAMS      cap probed parameters, default 25
//   SEKU_OOB_WAIT            seconds to wait for callbacks, default 12

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"

	"seku/internal/models"
)

type OOBScanner struct{}

func NewOOBScanner() *OOBScanner { return &OOBScanner{} }

func (s *OOBScanner) Name() string     { return "Out-of-Band (interactsh) Scanner" }
func (s *OOBScanner) Category() string { return "oob" }
func (s *OOBScanner) Weight() float64  { return 10.0 }

// parameter names commonly vulnerable to SSRF when they accept a URL.
var ssrfProneParams = []string{
	"url", "uri", "link", "src", "source", "dest", "destination", "redirect",
	"redirect_url", "return", "returnurl", "next", "target", "callback",
	"webhook", "image", "imageurl", "img", "file", "path", "host", "domain",
	"site", "page", "feed", "data", "proxy", "fetch", "load", "open", "to",
	"out", "view", "continue", "forward",
}

func (s *OOBScanner) Scan(rawURL string) []models.CheckResult { return s.scan(rawURL, nil) }

// ScanWithConfig lets a scan enable OOB testing per-run without the env flag.
func (s *OOBScanner) ScanWithConfig(rawURL string, cfg *ScanConfig) []models.CheckResult {
	return s.scan(rawURL, cfg)
}

func (s *OOBScanner) scan(rawURL string, cfg *ScanConfig) []models.CheckResult {
	if strings.TrimSpace(os.Getenv("SEKU_ENABLE_OOB")) != "1" && !(cfg != nil && cfg.EnableOOB) {
		return []models.CheckResult{s.info("Blind SSRF (OOB)",
			"Out-of-band testing is disabled. Enable it per-scan (Advanced options) or set SEKU_ENABLE_OOB=1.")}
	}

	opts := *client.DefaultOptions
	if srv := envStr("SEKU_INTERACTSH_SERVER", ""); srv != "" {
		opts.ServerURL = srv
	}
	if tok := envStr("SEKU_INTERACTSH_TOKEN", ""); tok != "" {
		opts.Token = tok
	}

	c, err := client.New(&opts)
	if err != nil {
		return []models.CheckResult{s.info("Blind SSRF (OOB)",
			"Could not reach an interactsh server ("+err.Error()+") — OOB test skipped.")}
	}
	defer c.Close()

	var mu sync.Mutex
	interactions := []*server.Interaction{}
	_ = c.StartPolling(5*time.Second, func(in *server.Interaction) {
		mu.Lock()
		interactions = append(interactions, in)
		mu.Unlock()
	})
	defer func() { _ = c.StopPolling() }()

	base := stripURLQuery(ensureHTTPS(rawURL))
	httpClient := &http.Client{Timeout: 12 * time.Second, Transport: ScanTransport}

	type probe struct{ host, param string }
	var probes []probe
	maxParams := envInt("SEKU_OOB_MAX_PARAMS", 25)
	for i, p := range ssrfProneParams {
		if i >= maxParams {
			break
		}
		payloadHost := c.URL() // unique <id>.oast.pro per call
		probes = append(probes, probe{host: payloadHost, param: p})
		testURL := fmt.Sprintf("%s?%s=%s", base, p, url.QueryEscape("http://"+payloadHost))
		if req, err := http.NewRequest("GET", testURL, nil); err == nil {
			if resp, err := httpClient.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}
	}

	// give the target time to make the callback
	time.Sleep(time.Duration(envInt("SEKU_OOB_WAIT", 12)) * time.Second)

	mu.Lock()
	received := interactions
	mu.Unlock()

	var confirmed []string
	seen := map[string]bool{}
	for _, pr := range probes {
		for _, in := range received {
			if (in.FullId != "" && strings.Contains(pr.host, in.FullId)) ||
				(in.UniqueID != "" && strings.Contains(pr.host, in.UniqueID)) {
				if !seen[pr.param] {
					seen[pr.param] = true
					confirmed = append(confirmed, fmt.Sprintf("%s (%s)", pr.param, in.Protocol))
				}
				break
			}
		}
	}

	res := models.CheckResult{Category: s.Category(), CheckName: "Blind SSRF (OOB)", Weight: 10.0}
	if len(confirmed) > 0 {
		res.Status, res.Score, res.Severity = "fail", 0, "critical"
		res.CVSSScore = 9.1
		res.CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"
		res.CVSSRating = "Critical"
		res.Confidence = 99
		res.Details = toJSON(map[string]interface{}{
			"message":    "Out-of-band interaction received — the server fetched an attacker-controlled URL. Blind SSRF confirmed.",
			"parameters": confirmed,
		})
	} else {
		res.Status, res.Score, res.Severity = "pass", 1000, "info"
		res.Confidence = 90
		res.Details = toJSON(map[string]interface{}{
			"message": fmt.Sprintf("No out-of-band interaction from %d SSRF probe(s) — no blind SSRF confirmed.", len(probes)),
		})
	}
	return []models.CheckResult{res}
}

func (s *OOBScanner) info(check, msg string) models.CheckResult {
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

func stripURLQuery(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		if i := strings.IndexByte(u, '?'); i >= 0 {
			return u[:i]
		}
		return u
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
