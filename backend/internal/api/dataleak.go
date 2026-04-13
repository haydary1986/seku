package api

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"

	"vscan-mohesr/internal/models"
	"vscan-mohesr/internal/scanner"
)

// dataLeakStore holds results in memory (separate from main scan DB)
var dataLeakStore = &dataLeakResults{
	results: make(map[string]*DataLeakResult),
}

type dataLeakResults struct {
	mu      sync.RWMutex
	results map[string]*DataLeakResult // keyed by domain
}

type DataLeakResult struct {
	Domain    string                   `json:"domain"`
	Name      string                   `json:"name"`
	Status    string                   `json:"status"` // pending, running, completed, failed
	StartedAt *time.Time               `json:"started_at"`
	EndedAt   *time.Time               `json:"ended_at"`
	Checks    []models.CheckResult     `json:"checks"`
	Summary   map[string]interface{}   `json:"summary"`
}

// RunDataLeakScan starts data leak scans for selected targets
func RunDataLeakScan(c *fiber.Ctx) error {
	var req struct {
		TargetIDs []uint `json:"target_ids"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Get targets
	var targets []models.ScanTarget
	if len(req.TargetIDs) > 0 {
		ScopedDB(c).Where("id IN ?", req.TargetIDs).Find(&targets)
	} else {
		ScopedDB(c).Find(&targets)
	}

	if len(targets) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No targets found"})
	}

	// Mark all as pending
	for _, t := range targets {
		domain := extractLeakDomain(t.URL)
		now := time.Now()
		dataLeakStore.mu.Lock()
		dataLeakStore.results[domain] = &DataLeakResult{
			Domain:    domain,
			Name:      t.Name,
			Status:    "pending",
			StartedAt: &now,
		}
		dataLeakStore.mu.Unlock()
	}

	// Run scans in background
	go func() {
		s := scanner.NewDataLeakScanner()
		sem := make(chan struct{}, 2) // 2 concurrent (HIBP rate limit)

		var wg sync.WaitGroup
		for _, t := range targets {
			wg.Add(1)
			sem <- struct{}{}
			go func(target models.ScanTarget) {
				defer wg.Done()
				defer func() { <-sem }()

				domain := extractLeakDomain(target.URL)

				dataLeakStore.mu.Lock()
				if r, ok := dataLeakStore.results[domain]; ok {
					r.Status = "running"
				}
				dataLeakStore.mu.Unlock()

				// Run the scanner
				checks := s.Scan(target.URL)

				// Build summary
				summary := buildLeakSummary(checks)

				ended := time.Now()
				dataLeakStore.mu.Lock()
				if r, ok := dataLeakStore.results[domain]; ok {
					r.Status = "completed"
					r.EndedAt = &ended
					r.Checks = checks
					r.Summary = summary
				}
				dataLeakStore.mu.Unlock()
			}(t)
		}
		wg.Wait()
	}()

	return c.Status(202).JSON(fiber.Map{
		"message": "Data leak scan started",
		"targets": len(targets),
	})
}

// GetDataLeakResults returns all data leak scan results
func GetDataLeakResults(c *fiber.Ctx) error {
	domain := c.Query("domain", "")

	dataLeakStore.mu.RLock()
	defer dataLeakStore.mu.RUnlock()

	if domain != "" {
		if r, ok := dataLeakStore.results[domain]; ok {
			return c.JSON(r)
		}
		return c.Status(404).JSON(fiber.Map{"error": "No results for this domain"})
	}

	// Return all results
	var results []*DataLeakResult
	totalBreaches := 0
	totalExposed := 0
	completedCount := 0
	runningCount := 0

	for _, r := range dataLeakStore.results {
		results = append(results, r)
		if r.Status == "completed" {
			completedCount++
			if r.Summary != nil {
				if b, ok := r.Summary["total_breaches"].(int); ok {
					totalBreaches += b
				}
				if e, ok := r.Summary["total_exposed_emails"].(int); ok {
					totalExposed += e
				}
			}
		} else if r.Status == "running" || r.Status == "pending" {
			runningCount++
		}
	}

	return c.JSON(fiber.Map{
		"results":          results,
		"total_scanned":    len(results),
		"completed":        completedCount,
		"running":          runningCount,
		"total_breaches":   totalBreaches,
		"total_exposed":    totalExposed,
	})
}

func buildLeakSummary(checks []models.CheckResult) map[string]interface{} {
	summary := map[string]interface{}{
		"total_breaches":      0,
		"total_exposed_emails": 0,
		"risk_level":          "safe",
		"data_types":          []string{},
	}

	for _, ch := range checks {
		if ch.Details == "" {
			continue
		}
		var details map[string]interface{}
		if json.Unmarshal([]byte(ch.Details), &details) != nil {
			continue
		}

		switch ch.CheckName {
		case "Domain Breach History":
			if count, ok := details["breaches_found"].(float64); ok {
				summary["total_breaches"] = int(count)
			}
			if types, ok := details["data_types_leaked"].([]interface{}); ok {
				var strs []string
				for _, t := range types {
					if s, ok := t.(string); ok {
						strs = append(strs, s)
					}
				}
				summary["data_types"] = strs
			}
		case "Email Breach Detection":
			if count, ok := details["exposed_count"].(float64); ok {
				summary["total_exposed_emails"] = int(count)
			}
		}
	}

	// Determine risk level
	breaches, _ := summary["total_breaches"].(int)
	exposed, _ := summary["total_exposed_emails"].(int)

	switch {
	case breaches > 3 || exposed > 5:
		summary["risk_level"] = "critical"
	case breaches > 0 || exposed > 2:
		summary["risk_level"] = "high"
	case exposed > 0:
		summary["risk_level"] = "medium"
	default:
		summary["risk_level"] = "safe"
	}

	return summary
}

func extractLeakDomain(rawURL string) string {
	d := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	d = strings.TrimRight(d, "/")
	if idx := strings.Index(d, "/"); idx > 0 {
		d = d[:idx]
	}
	return d
}
