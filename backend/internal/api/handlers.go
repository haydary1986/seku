package api

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/models"
	"vscan-mohesr/internal/scanner"
)

// --- Scan Targets ---

func GetTargets(c *fiber.Ctx) error {
	var targets []models.ScanTarget
	config.DB.Order("created_at desc").Find(&targets)
	return c.JSON(targets)
}

func CreateTarget(c *fiber.Ctx) error {
	var target models.ScanTarget
	if err := c.BodyParser(&target); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if target.URL == "" {
		return c.Status(400).JSON(fiber.Map{"error": "URL is required"})
	}
	config.DB.Create(&target)
	return c.Status(201).JSON(target)
}

type BulkTargetsRequest struct {
	Targets []models.ScanTarget `json:"targets"`
}

func CreateBulkTargets(c *fiber.Ctx) error {
	var req BulkTargetsRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if len(req.Targets) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "At least one target is required"})
	}

	for i := range req.Targets {
		if req.Targets[i].URL == "" {
			return c.Status(400).JSON(fiber.Map{"error": "All targets must have a URL"})
		}
	}

	config.DB.Create(&req.Targets)
	return c.Status(201).JSON(req.Targets)
}

func DeleteTarget(c *fiber.Ctx) error {
	id := c.Params("id")
	var target models.ScanTarget
	if err := config.DB.First(&target, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Target not found"})
	}
	config.DB.Delete(&target)
	return c.JSON(fiber.Map{"message": "Target deleted"})
}

func UpdateTarget(c *fiber.Ctx) error {
	id := c.Params("id")
	var target models.ScanTarget
	if err := config.DB.First(&target, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Target not found"})
	}

	var update models.ScanTarget
	if err := c.BodyParser(&update); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	config.DB.Model(&target).Updates(update)
	return c.JSON(target)
}

// --- Scan Jobs ---

func GetScanJobs(c *fiber.Ctx) error {
	var jobs []models.ScanJob
	config.DB.Order("created_at desc").Find(&jobs)

	// Add progress info to each job
	var result []fiber.Map
	for _, job := range jobs {
		var total, completed, failed int64
		config.DB.Model(&models.ScanResult{}).Where("scan_job_id = ?", job.ID).Count(&total)
		config.DB.Model(&models.ScanResult{}).Where("scan_job_id = ? AND status = ?", job.ID, "completed").Count(&completed)
		config.DB.Model(&models.ScanResult{}).Where("scan_job_id = ? AND status = ?", job.ID, "failed").Count(&failed)

		progress := 0.0
		if total > 0 {
			progress = float64(completed+failed) / float64(total) * 100
		}

		result = append(result, fiber.Map{
			"ID":         job.ID,
			"CreatedAt":  job.CreatedAt,
			"name":       job.Name,
			"status":     job.Status,
			"started_at": job.StartedAt,
			"ended_at":   job.EndedAt,
			"progress": fiber.Map{
				"total":     total,
				"completed": completed,
				"failed":    failed,
				"percent":   progress,
			},
		})
	}

	return c.JSON(result)
}

func GetScanJob(c *fiber.Ctx) error {
	id := c.Params("id")
	var job models.ScanJob
	if err := config.DB.Preload("Results.ScanTarget").Preload("Results.Checks").First(&job, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan job not found"})
	}

	// Calculate progress
	total := len(job.Results)
	completed := 0
	running := 0
	pending := 0
	failed := 0
	for _, r := range job.Results {
		switch r.Status {
		case "completed":
			completed++
		case "running":
			running++
		case "failed":
			failed++
		default:
			pending++
		}
	}

	progress := 0.0
	if total > 0 {
		progress = float64(completed+failed) / float64(total) * 100
	}

	return c.JSON(fiber.Map{
		"ID":         job.ID,
		"CreatedAt":  job.CreatedAt,
		"UpdatedAt":  job.UpdatedAt,
		"name":       job.Name,
		"status":     job.Status,
		"started_at": job.StartedAt,
		"ended_at":   job.EndedAt,
		"user_id":    job.UserID,
		"results":    job.Results,
		"progress": fiber.Map{
			"total":     total,
			"completed": completed,
			"running":   running,
			"pending":   pending,
			"failed":    failed,
			"percent":   progress,
		},
	})
}

type StartScanRequest struct {
	Name      string `json:"name"`
	TargetIDs []uint `json:"target_ids"`
}

func StartScan(c *fiber.Ctx) error {
	var req StartScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	userID := c.Locals("user_id").(uint)

	// Get user's organization via OrgMembership
	var membership models.OrgMembership
	var org models.Organization
	plan := "enterprise" // default for users without org (e.g. legacy admin)

	if err := config.DB.Where("user_id = ?", userID).First(&membership).Error; err == nil {
		if err := config.DB.First(&org, membership.OrganizationID).Error; err == nil {
			plan = org.Plan

			// Check target count against org.MaxTargets
			var targetCount int64
			config.DB.Model(&models.ScanTarget{}).Where("organization_id = ?", org.ID).Count(&targetCount)
			if int(targetCount) >= org.MaxTargets {
				return c.Status(403).JSON(fiber.Map{
					"error": "Target limit reached for your plan. Please upgrade.",
					"limit": org.MaxTargets,
					"current": targetCount,
					"plan":  org.Plan,
				})
			}
		}
	}

	// If no target IDs provided, scan all targets
	var targets []models.ScanTarget
	if len(req.TargetIDs) > 0 {
		config.DB.Where("id IN ?", req.TargetIDs).Find(&targets)
	} else {
		config.DB.Find(&targets)
	}

	if len(targets) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No targets found to scan"})
	}

	// Create scan job
	job := models.ScanJob{
		Name:   req.Name,
		Status: "pending",
		UserID: userID,
	}
	if job.Name == "" {
		job.Name = "Scan " + time.Now().Format("2006-01-02 15:04")
	}
	config.DB.Create(&job)

	// Create scan results for each target
	for _, target := range targets {
		result := models.ScanResult{
			ScanJobID:    job.ID,
			ScanTargetID: target.ID,
			Status:       "pending",
		}
		config.DB.Create(&result)
	}

	// Run scan in background using plan-based engine
	engine := scanner.NewEngineForPlan(plan)
	go engine.RunScan(&job)

	return c.Status(201).JSON(job)
}

func DeleteScanJob(c *fiber.Ctx) error {
	id := c.Params("id")
	var job models.ScanJob
	if err := config.DB.First(&job, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan job not found"})
	}

	// Delete associated results and checks
	var results []models.ScanResult
	config.DB.Where("scan_job_id = ?", job.ID).Find(&results)
	for _, r := range results {
		config.DB.Where("scan_result_id = ?", r.ID).Delete(&models.CheckResult{})
	}
	config.DB.Where("scan_job_id = ?", job.ID).Delete(&models.ScanResult{})
	config.DB.Delete(&job)

	return c.JSON(fiber.Map{"message": "Scan job deleted"})
}

// --- Dashboard Stats ---

func GetDashboardStats(c *fiber.Ctx) error {
	var targetCount int64
	config.DB.Model(&models.ScanTarget{}).Count(&targetCount)

	var jobCount int64
	config.DB.Model(&models.ScanJob{}).Count(&jobCount)

	var completedJobs int64
	config.DB.Model(&models.ScanJob{}).Where("status = ?", "completed").Count(&completedJobs)

	// Get only the latest scan result per target (not all historical results)
	var latestResults []models.ScanResult
	config.DB.Raw(`
		SELECT sr.* FROM scan_results sr
		INNER JOIN (
			SELECT scan_target_id, MAX(id) AS max_id
			FROM scan_results
			WHERE status = 'completed'
			GROUP BY scan_target_id
		) latest ON sr.id = latest.max_id
		ORDER BY sr.overall_score DESC
		LIMIT 20
	`).Preload("ScanTarget").Find(&latestResults)

	// Calculate average score from latest results only
	var avgScore float64
	config.DB.Raw(`
		SELECT COALESCE(AVG(sr.overall_score), 0) FROM scan_results sr
		INNER JOIN (
			SELECT scan_target_id, MAX(id) AS max_id
			FROM scan_results
			WHERE status = 'completed'
			GROUP BY scan_target_id
		) latest ON sr.id = latest.max_id
	`).Scan(&avgScore)

	// Score distribution
	type ScoreBucket struct {
		Range string `json:"range"`
		Count int64  `json:"count"`
	}
	var excellent, good, average, poor, critical int64
	config.DB.Model(&models.ScanResult{}).Where("status = ? AND overall_score >= 800", "completed").Count(&excellent)
	config.DB.Model(&models.ScanResult{}).Where("status = ? AND overall_score >= 600 AND overall_score < 800", "completed").Count(&good)
	config.DB.Model(&models.ScanResult{}).Where("status = ? AND overall_score >= 400 AND overall_score < 600", "completed").Count(&average)
	config.DB.Model(&models.ScanResult{}).Where("status = ? AND overall_score >= 200 AND overall_score < 400", "completed").Count(&poor)
	config.DB.Model(&models.ScanResult{}).Where("status = ? AND overall_score < 200", "completed").Count(&critical)

	return c.JSON(fiber.Map{
		"total_targets":  targetCount,
		"total_scans":    jobCount,
		"completed_scans": completedJobs,
		"average_score":  avgScore,
		"latest_results": latestResults,
		"score_distribution": []fiber.Map{
			{"range": "Excellent (800-1000)", "count": excellent},
			{"range": "Good (600-799)", "count": good},
			{"range": "Average (400-599)", "count": average},
			{"range": "Poor (200-399)", "count": poor},
			{"range": "Critical (0-199)", "count": critical},
		},
	})
}

// --- Scan Result Detail ---

func GetScanResult(c *fiber.Ctx) error {
	id := c.Params("id")
	var result models.ScanResult
	if err := config.DB.Preload("ScanTarget").Preload("Checks").First(&result, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan result not found"})
	}

	// Group checks by category
	categories := map[string][]models.CheckResult{}
	for _, check := range result.Checks {
		categories[check.Category] = append(categories[check.Category], check)
	}

	return c.JSON(fiber.Map{
		"result":     result,
		"categories": categories,
	})
}

// --- Leaderboard: All websites ranked by security score ---

func GetLeaderboard(c *fiber.Ctx) error {
	type RankedSite struct {
		ScanTargetID uint    `json:"scan_target_id"`
		URL          string  `json:"url"`
		Name         string  `json:"name"`
		Institution  string  `json:"institution"`
		LatestScore  float64 `json:"latest_score"`
		ScanResultID uint    `json:"scan_result_id"`
		ScannedAt    string  `json:"scanned_at"`
	}

	var ranked []RankedSite
	config.DB.Raw(`
		SELECT sr.scan_target_id, st.url, st.name, st.institution,
			   sr.overall_score AS latest_score, sr.id AS scan_result_id,
			   sr.ended_at AS scanned_at
		FROM scan_results sr
		INNER JOIN scan_targets st ON st.id = sr.scan_target_id
		INNER JOIN (
			SELECT scan_target_id, MAX(id) AS max_id
			FROM scan_results
			WHERE status = 'completed'
			GROUP BY scan_target_id
		) latest ON sr.id = latest.max_id
		ORDER BY sr.overall_score DESC
	`).Scan(&ranked)

	// Category breakdown for each site
	type CategoryScore struct {
		Category string  `json:"category"`
		Score    float64 `json:"score"`
	}

	type RankedSiteWithCategories struct {
		RankedSite
		Rank       int             `json:"rank"`
		Grade      string          `json:"grade"`
		Categories []CategoryScore `json:"categories"`
	}

	var result []RankedSiteWithCategories
	for i, site := range ranked {
		entry := RankedSiteWithCategories{
			RankedSite: site,
			Rank:       i + 1,
			Grade:      scoreToGrade(site.LatestScore),
		}

		// Get category scores
		var checks []models.CheckResult
		config.DB.Where("scan_result_id = ?", site.ScanResultID).Find(&checks)

		catScores := map[string]struct{ total, weight float64 }{}
		for _, ch := range checks {
			cs := catScores[ch.Category]
			cs.total += ch.Score * ch.Weight
			cs.weight += ch.Weight
			catScores[ch.Category] = cs
		}

		for cat, cs := range catScores {
			score := 0.0
			if cs.weight > 0 {
				score = cs.total / cs.weight
			}
			entry.Categories = append(entry.Categories, CategoryScore{
				Category: cat,
				Score:    score,
			})
		}

		result = append(result, entry)
	}

	// Summary stats
	var totalSites int64
	config.DB.Model(&models.ScanTarget{}).Count(&totalSites)

	var avgScore float64
	if len(ranked) > 0 {
		sum := 0.0
		for _, r := range ranked {
			sum += r.LatestScore
		}
		avgScore = sum / float64(len(ranked))
	}

	return c.JSON(fiber.Map{
		"rankings":     result,
		"total_sites":  totalSites,
		"scanned_sites": len(ranked),
		"average_score": avgScore,
	})
}

// --- Score History ---

func GetScoreHistory(c *fiber.Ctx) error {
	targetID := c.Params("id")

	type HistoryPoint struct {
		Score     float64 `json:"score"`
		ScannedAt string  `json:"scanned_at"`
		ScanJobID uint    `json:"scan_job_id"`
		ResultID  uint    `json:"result_id"`
	}

	var history []HistoryPoint
	config.DB.Raw(`
		SELECT overall_score AS score, ended_at AS scanned_at,
		       scan_job_id, id AS result_id
		FROM scan_results
		WHERE scan_target_id = ? AND status = 'completed'
		ORDER BY created_at ASC
	`, targetID).Scan(&history)

	return c.JSON(history)
}

func scoreToGrade(score float64) string {
	switch {
	case score >= 900:
		return "A+"
	case score >= 800:
		return "A"
	case score >= 700:
		return "B"
	case score >= 600:
		return "C"
	case score >= 500:
		return "D"
	default:
		return "F"
	}
}
