package scheduler

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/robfig/cron/v3"

	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/models"
	"vscan-mohesr/internal/scanner"
)

// Start initializes the cron scheduler that checks for due scheduled scans every minute.
func Start() {
	c := cron.New()

	_, err := c.AddFunc("* * * * *", runDueScans)
	if err != nil {
		log.Printf("[Scheduler] Failed to register cron job: %v", err)
		return
	}

	c.Start()
	log.Println("[Scheduler] Started – checking for due scans every minute")
}

// runDueScans finds all active scheduled scans whose next_run_at has passed and executes them.
func runDueScans() {
	var schedules []models.ScheduledScan
	now := time.Now()

	config.DB.Where("is_active = ? AND next_run_at <= ?", true, now).Find(&schedules)

	for _, sched := range schedules {
		log.Printf("[Scheduler] Running scheduled scan: %s (ID %d)", sched.Name, sched.ID)

		// Parse target IDs from JSON
		var targetIDs []uint
		if err := json.Unmarshal([]byte(sched.TargetIDs), &targetIDs); err != nil {
			log.Printf("[Scheduler] Failed to parse target_ids for schedule %d: %v", sched.ID, err)
			continue
		}

		// Load targets
		var targets []models.ScanTarget
		if len(targetIDs) > 0 {
			config.DB.Where("id IN ?", targetIDs).Find(&targets)
		}
		if len(targets) == 0 {
			log.Printf("[Scheduler] No targets found for schedule %d, skipping", sched.ID)
			continue
		}

		// Create ScanJob
		job := models.ScanJob{
			OrganizationID: sched.OrganizationID,
			Name:           fmt.Sprintf("[Scheduled] %s – %s", sched.Name, now.Format("2006-01-02 15:04")),
			Status:         "pending",
			UserID:         sched.CreatedBy,
		}
		config.DB.Create(&job)

		// Create ScanResults for each target
		for _, target := range targets {
			result := models.ScanResult{
				ScanJobID:    job.ID,
				ScanTargetID: target.ID,
				Status:       "pending",
			}
			config.DB.Create(&result)
		}

		// Run scan in background
		engine := scanner.NewEngine()
		go engine.RunScan(&job)

		// Update schedule timestamps
		nextRun := CalculateNextRun(sched.Schedule, sched.DayOfWeek, sched.HourUTC)
		config.DB.Model(&sched).Updates(map[string]interface{}{
			"last_run_at": now,
			"next_run_at": nextRun,
		})

		log.Printf("[Scheduler] Scheduled scan %d queued (job %d), next run: %s", sched.ID, job.ID, nextRun.Format(time.RFC3339))
	}
}

// CalculateNextRun returns the next execution time based on schedule type.
func CalculateNextRun(schedule string, dayOfWeek, hourUTC int) time.Time {
	now := time.Now().UTC()

	switch schedule {
	case "daily":
		next := time.Date(now.Year(), now.Month(), now.Day(), hourUTC, 0, 0, 0, time.UTC)
		if !next.After(now) {
			next = next.AddDate(0, 0, 1)
		}
		return next

	case "weekly":
		// dayOfWeek: 0=Sunday, 1=Monday, ... 6=Saturday
		next := time.Date(now.Year(), now.Month(), now.Day(), hourUTC, 0, 0, 0, time.UTC)
		daysUntil := (dayOfWeek - int(next.Weekday()) + 7) % 7
		if daysUntil == 0 && !next.After(now) {
			daysUntil = 7
		}
		next = next.AddDate(0, 0, daysUntil)
		return next

	case "monthly":
		// dayOfWeek is repurposed as day-of-month (1-28) for monthly schedules
		dayOfMonth := dayOfWeek
		if dayOfMonth < 1 || dayOfMonth > 28 {
			dayOfMonth = 1
		}
		next := time.Date(now.Year(), now.Month(), dayOfMonth, hourUTC, 0, 0, 0, time.UTC)
		if !next.After(now) {
			next = next.AddDate(0, 1, 0)
		}
		return next

	default:
		// Fall back to daily
		return time.Now().UTC().Add(24 * time.Hour)
	}
}
