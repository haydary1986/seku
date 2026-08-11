package api

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
	"seku/internal/scanner"
)

// liveLog buffers a running scan's log so polling can see progress before the
// run finishes. It is flushed to the DB row every ~1.5s by the runner goroutine.
type liveLog struct {
	mu  sync.Mutex
	buf strings.Builder
}

var nucleiLive = struct {
	mu sync.Mutex
	m  map[uint]*liveLog
}{m: map[uint]*liveLog{}}

// RunNucleiTool starts an async nuclei run against a single target and returns
// the run id immediately. Progress + findings are polled via GetNucleiRun.
func RunNucleiTool(c *fiber.Ctx) error {
	var req struct {
		Target   string `json:"target"`
		Severity string `json:"severity"`
		Tags     string `json:"tags"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	target := strings.TrimSpace(req.Target)
	if target == "" || len(target) < 3 || strings.ContainsAny(target, " \t\r\n") {
		return c.Status(400).JSON(fiber.Map{"error": "Provide a valid single URL or IP (no spaces)"})
	}

	userID, _ := c.Locals("user_id").(uint)
	now := time.Now()
	run := models.NucleiRun{
		UserID: userID, Target: target, Severity: req.Severity, Tags: req.Tags,
		Status: "running", StartedAt: &now,
	}
	config.DB.Create(&run)

	ll := &liveLog{}
	nucleiLive.mu.Lock()
	nucleiLive.m[run.ID] = ll
	nucleiLive.mu.Unlock()

	go runNucleiJob(run.ID, target, req.Severity, req.Tags, ll)

	return c.Status(201).JSON(fiber.Map{"id": run.ID, "status": "running"})
}

func runNucleiJob(runID uint, target, severity, tags string, ll *liveLog) {
	start := time.Now()
	onLine := func(s string) {
		ll.mu.Lock()
		ll.buf.WriteString(time.Now().Format("15:04:05") + "  " + s + "\n")
		ll.mu.Unlock()
	}

	// periodically flush the live log to the DB so pollers see progress
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(1500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				ll.mu.Lock()
				s := ll.buf.String()
				ll.mu.Unlock()
				config.DB.Model(&models.NucleiRun{}).Where("id = ?", runID).Update("log", s)
			case <-done:
				return
			}
		}
	}()

	results := scanner.RunNucleiStream(target, severity, tags, onLine)
	close(done)

	findings := 0
	for _, r := range results {
		if strings.HasPrefix(r.CheckName, "Nuclei:") {
			findings++
		}
	}
	fin := time.Now()
	ll.mu.Lock()
	logStr := ll.buf.String()
	ll.mu.Unlock()
	resBytes, _ := json.Marshal(results)

	config.DB.Model(&models.NucleiRun{}).Where("id = ?", runID).Updates(map[string]interface{}{
		"status":       "finished",
		"finished_at":  &fin,
		"duration_sec": int(fin.Sub(start).Seconds()),
		"findings":     findings,
		"results_json": string(resBytes),
		"log":          logStr,
	})

	nucleiLive.mu.Lock()
	delete(nucleiLive.m, runID)
	nucleiLive.mu.Unlock()
}

// ListNucleiRuns returns the recent runs (history tab) without heavy fields.
func ListNucleiRuns(c *fiber.Ctx) error {
	var runs []models.NucleiRun
	config.DB.Order("created_at desc").Limit(100).Find(&runs)

	type row struct {
		ID          uint      `json:"id"`
		Target      string    `json:"target"`
		Status      string    `json:"status"`
		DurationSec int       `json:"duration_sec"`
		Findings    int       `json:"findings"`
		Severity    string    `json:"severity"`
		Tags        string    `json:"tags"`
		CreatedAt   time.Time `json:"created_at"`
	}
	out := make([]row, 0, len(runs))
	for _, r := range runs {
		out = append(out, row{r.ID, r.Target, r.Status, r.DurationSec, r.Findings, r.Severity, r.Tags, r.CreatedAt})
	}
	return c.JSON(out)
}

// GetNucleiRun returns a single run with its full log + findings.
func GetNucleiRun(c *fiber.Ctx) error {
	var run models.NucleiRun
	if err := config.DB.First(&run, c.Params("id")).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	return c.JSON(run)
}
