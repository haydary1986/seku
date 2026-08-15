package api

import (
	"math"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"seku/internal/models"
	"seku/internal/scanner"
)

// PublicQuickScan runs a FAST, unauthenticated teaser scan for the landing page.
// It is heavily rate-limited (see routes), SSRF-guarded, runs only a few quick
// passive checks, persists nothing, and returns a summary — the full report
// requires signing up. This is a conversion driver, not a real scan.
// POST /public/quickscan  {url}
func PublicQuickScan(c *fiber.Ctx) error {
	var req struct {
		URL string `json:"url"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	raw := strings.TrimSpace(req.URL)
	if raw == "" {
		return c.Status(400).JSON(fiber.Map{"error": "url is required"})
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	// SSRF guard: only scan public hosts that actually resolve.
	if !isSafeOutboundHost(raw) {
		return c.Status(400).JSON(fiber.Map{"error": "This host cannot be scanned (must be a public, reachable domain)."})
	}

	// Curated fast, passive scanners only — run concurrently with a hard cap.
	runners := []scanner.Scanner{
		scanner.NewSSLScanner(),
		scanner.NewHeaderScanner(),
		scanner.NewCookieScanner(),
		scanner.NewAdvancedSecurityScanner(),
		scanner.NewDNSScanner(),
	}
	ch := make(chan []models.CheckResult, len(runners))
	for _, s := range runners {
		go func(sc scanner.Scanner) {
			defer func() {
				if r := recover(); r != nil {
					ch <- nil
				}
			}()
			ch <- sc.Scan(raw)
		}(s)
	}

	var checks []models.CheckResult
	deadline := time.After(20 * time.Second)
	for i := 0; i < len(runners); i++ {
		select {
		case cks := <-ch:
			checks = append(checks, cks...)
		case <-deadline:
			i = len(runners) // stop waiting; use whatever arrived
		}
	}

	var sum float64
	var n int
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "passed": 0}
	top := make([]fiber.Map, 0, 6)
	for _, ck := range checks {
		sum += ck.Score
		n++
		if ck.Status == "fail" || ck.Status == "warn" {
			sev := strings.ToLower(ck.Severity)
			if _, ok := counts[sev]; ok {
				counts[sev]++
			}
			if len(top) < 6 {
				top = append(top, fiber.Map{"name": ck.CheckName, "severity": sev})
			}
		} else {
			counts["passed"]++
		}
	}
	avg := 1000.0
	if n > 0 {
		avg = sum / float64(n)
	}

	return c.JSON(fiber.Map{
		"domain":       extractDomain(raw),
		"score":        math.Round(avg),
		"grade":        scanner.SecurityGrade(avg),
		"summary":      counts,
		"top_findings": top,
		"checks_run":   n,
		"teaser":       true,
	})
}
