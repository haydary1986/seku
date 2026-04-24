package api

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"seku/internal/config"
	"seku/internal/models"
	"seku/internal/scanner"
	"seku/internal/services"
)

// --- Scan Targets ---

func GetTargets(c *fiber.Ctx) error {
	page, _ := strconv.Atoi(c.Query("page", "1"))
	limit, _ := strconv.Atoi(c.Query("limit", "50"))
	search := c.Query("search", "")

	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := (page - 1) * limit

	db := ScopedDB(c)
	if search != "" {
		like := "%" + search + "%"
		db = db.Where("url LIKE ? OR name LIKE ? OR institution LIKE ?", like, like, like)
	}

	var total int64
	db.Model(&models.ScanTarget{}).Count(&total)

	var targets []models.ScanTarget
	db.Order("created_at desc").Offset(offset).Limit(limit).Find(&targets)

	return c.JSON(fiber.Map{
		"data":  targets,
		"total": total,
		"page":  page,
		"limit": limit,
		"pages": int(math.Ceil(float64(total) / float64(limit))),
	})
}

func CreateTarget(c *fiber.Ctx) error {
	var target models.ScanTarget
	if err := c.BodyParser(&target); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if target.URL == "" {
		return c.Status(400).JSON(fiber.Map{"error": "URL is required"})
	}
	target.OrganizationID = GetUserOrgID(c)
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

	orgID := GetUserOrgID(c)
	for i := range req.Targets {
		if req.Targets[i].URL == "" {
			return c.Status(400).JSON(fiber.Map{"error": "All targets must have a URL"})
		}
		req.Targets[i].OrganizationID = orgID
	}

	config.DB.Create(&req.Targets)
	return c.Status(201).JSON(req.Targets)
}

func DeleteTarget(c *fiber.Ctx) error {
	id := c.Params("id")
	var target models.ScanTarget
	if err := ScopedDB(c).First(&target, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Target not found"})
	}

	// Hard-delete all scan results + check results + AI analyses for this target
	var results []models.ScanResult
	config.DB.Unscoped().Where("scan_target_id = ?", target.ID).Find(&results)
	for _, r := range results {
		config.DB.Unscoped().Where("scan_result_id = ?", r.ID).Delete(&models.CheckResult{})
		config.DB.Unscoped().Where("scan_result_id = ?", r.ID).Delete(&models.AIAnalysis{})
	}
	config.DB.Unscoped().Where("scan_target_id = ?", target.ID).Delete(&models.ScanResult{})
	config.DB.Unscoped().Delete(&target)

	return c.JSON(fiber.Map{"message": "Target and all associated data permanently deleted"})
}

func UpdateTarget(c *fiber.Ctx) error {
	id := c.Params("id")
	var target models.ScanTarget
	if err := ScopedDB(c).First(&target, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Target not found"})
	}

	var update models.ScanTarget
	if err := c.BodyParser(&update); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	config.DB.Model(&target).Updates(update)
	return c.JSON(target)
}

// --- Cleanup Dead Targets ---

func CleanupDeadTargets(c *fiber.Ctx) error {
	var targets []models.ScanTarget
	ScopedDB(c).Find(&targets)

	if len(targets) == 0 {
		return c.JSON(fiber.Map{"message": "No targets to check", "removed": 0})
	}

	type deadTarget struct {
		ID   uint   `json:"id"`
		URL  string `json:"url"`
		Name string `json:"name"`
	}

	// Lenient liveness check: 10s timeout, realistic UA, tries multiple URL variants.
	// A target is considered alive if ANY variant returns ANY response (even 5xx —
	// that means the server is up, just misbehaving, not dead).
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	probe := func(rawURL string) bool {
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true // any HTTP response means the server is alive
	}

	type checkResult struct {
		target models.ScanTarget
		alive  bool
	}

	results := make(chan checkResult, len(targets))
	sem := make(chan struct{}, 20)

	for _, t := range targets {
		sem <- struct{}{}
		go func(t models.ScanTarget) {
			defer func() { <-sem }()

			raw := strings.TrimSpace(t.URL)
			raw = strings.TrimPrefix(raw, "https://")
			raw = strings.TrimPrefix(raw, "http://")
			raw = strings.TrimPrefix(raw, "www.")
			raw = strings.TrimRight(raw, "/")

			// Try 4 variants in order of likelihood
			variants := []string{
				"https://" + raw,
				"https://www." + raw,
				"http://" + raw,
				"http://www." + raw,
			}

			alive := false
			for _, v := range variants {
				if probe(v) {
					alive = true
					break
				}
			}
			results <- checkResult{target: t, alive: alive}
		}(t)
	}

	// Collect results
	var dead []deadTarget
	for i := 0; i < len(targets); i++ {
		r := <-results
		if !r.alive {
			dead = append(dead, deadTarget{ID: r.target.ID, URL: r.target.URL, Name: r.target.Name})
		}
	}

	// Hard-delete if not dry run
	dryRun := c.Query("dry_run", "true")
	if dryRun == "false" && len(dead) > 0 {
		for _, d := range dead {
			var scanResults []models.ScanResult
			config.DB.Unscoped().Where("scan_target_id = ?", d.ID).Find(&scanResults)
			for _, r := range scanResults {
				config.DB.Unscoped().Where("scan_result_id = ?", r.ID).Delete(&models.CheckResult{})
				config.DB.Unscoped().Where("scan_result_id = ?", r.ID).Delete(&models.AIAnalysis{})
			}
			config.DB.Unscoped().Where("scan_target_id = ?", d.ID).Delete(&models.ScanResult{})
			config.DB.Unscoped().Delete(&models.ScanTarget{}, d.ID)
		}
	}

	return c.JSON(fiber.Map{
		"total_checked": len(targets),
		"dead_count":    len(dead),
		"alive_count":   len(targets) - len(dead),
		"dry_run":       dryRun != "false",
		"dead_targets":  dead,
		"message": func() string {
			if dryRun != "false" {
				return fmt.Sprintf("Deleted %d dead targets", len(dead))
			}
			return "Dry run complete. Review and confirm deletion."
		}(),
	})
}

// CleanupDuplicateTargets finds targets with the same normalized URL
// (case-insensitive, www stripped, protocol stripped, trailing slash removed)
// and deletes all but the lowest-ID one. All scan history is preserved on
// the kept target.
func CleanupDuplicateTargets(c *fiber.Ctx) error {
	var targets []models.ScanTarget
	ScopedDB(c).Order("id ASC").Find(&targets)

	normalize := func(u string) string {
		s := strings.TrimSpace(strings.ToLower(u))
		s = strings.TrimPrefix(s, "https://")
		s = strings.TrimPrefix(s, "http://")
		s = strings.TrimPrefix(s, "www.")
		s = strings.TrimRight(s, "/")
		return s
	}

	// Group by normalized URL. First occurrence wins.
	seen := map[string]models.ScanTarget{}
	type dupEntry struct {
		ID     uint   `json:"id"`
		URL    string `json:"url"`
		Name   string `json:"name"`
		KeptID uint   `json:"kept_id"`
	}
	var duplicates []dupEntry

	for _, t := range targets {
		key := normalize(t.URL)
		if key == "" {
			continue
		}
		if kept, ok := seen[key]; ok {
			duplicates = append(duplicates, dupEntry{
				ID:     t.ID,
				URL:    t.URL,
				Name:   t.Name,
				KeptID: kept.ID,
			})
			continue
		}
		seen[key] = t
	}

	dryRun := c.Query("dry_run", "true")
	if dryRun == "false" && len(duplicates) > 0 {
		for _, d := range duplicates {
			var scanResults []models.ScanResult
			config.DB.Unscoped().Where("scan_target_id = ?", d.ID).Find(&scanResults)
			for _, r := range scanResults {
				config.DB.Unscoped().Where("scan_result_id = ?", r.ID).Delete(&models.CheckResult{})
				config.DB.Unscoped().Where("scan_result_id = ?", r.ID).Delete(&models.AIAnalysis{})
			}
			config.DB.Unscoped().Where("scan_target_id = ?", d.ID).Delete(&models.ScanResult{})
			config.DB.Unscoped().Delete(&models.ScanTarget{}, d.ID)
		}
	}

	return c.JSON(fiber.Map{
		"total_checked":    len(targets),
		"duplicate_count":  len(duplicates),
		"unique_count":     len(seen),
		"dry_run":          dryRun != "false",
		"duplicates":       duplicates,
		"message": func() string {
			if dryRun == "false" {
				return fmt.Sprintf("Deleted %d duplicate targets", len(duplicates))
			}
			return "Dry run complete. Review and confirm deletion."
		}(),
	})
}

// --- Scan Jobs ---

func GetScanJobs(c *fiber.Ctx) error {
	page, _ := strconv.Atoi(c.Query("page", "1"))
	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	status := c.Query("status", "")

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	db := ScopedDB(c)
	if status != "" {
		db = db.Where("status = ?", status)
	}

	var total int64
	db.Model(&models.ScanJob{}).Count(&total)

	var jobs []models.ScanJob
	db.Order("created_at desc").Offset(offset).Limit(limit).Find(&jobs)

	// Add progress info to each job
	items := make([]fiber.Map, 0)
	for _, job := range jobs {
		var jobTotal, completed, failed int64
		config.DB.Model(&models.ScanResult{}).Where("scan_job_id = ?", job.ID).Count(&jobTotal)
		config.DB.Model(&models.ScanResult{}).Where("scan_job_id = ? AND status = ?", job.ID, "completed").Count(&completed)
		config.DB.Model(&models.ScanResult{}).Where("scan_job_id = ? AND status = ?", job.ID, "failed").Count(&failed)

		progress := 0.0
		if jobTotal > 0 {
			progress = float64(completed+failed) / float64(jobTotal) * 100
		}

		items = append(items, fiber.Map{
			"ID":         job.ID,
			"CreatedAt":  job.CreatedAt,
			"name":       job.Name,
			"status":     job.Status,
			"started_at": job.StartedAt,
			"ended_at":   job.EndedAt,
			"progress": fiber.Map{
				"total":     jobTotal,
				"completed": completed,
				"failed":    failed,
				"percent":   progress,
			},
		})
	}

	return c.JSON(fiber.Map{
		"data":  items,
		"total": total,
		"page":  page,
		"limit": limit,
		"pages": int(math.Ceil(float64(total) / float64(limit))),
	})
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

// PurgeAllScans deletes ALL scan jobs, results, checks, and AI analyses.
func PurgeAllScans(c *fiber.Ctx) error {
	config.DB.Exec("DELETE FROM check_results")
	config.DB.Exec("DELETE FROM ai_analyses")
	config.DB.Exec("DELETE FROM scan_results")
	config.DB.Exec("DELETE FROM scan_jobs")
	return c.JSON(fiber.Map{"message": "All scan data purged"})
}

type StartScanRequest struct {
	Name      string `json:"name"`
	TargetIDs []uint `json:"target_ids"`
	Policy    string `json:"policy"` // light, standard, deep — overrides plan-based engine
}

func StartScan(c *fiber.Ctx) error {
	var req StartScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	userID, _ := c.Locals("user_id").(uint)

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
					"error":   "Target limit reached for your plan. Please upgrade.",
					"limit":   org.MaxTargets,
					"current": targetCount,
					"plan":    org.Plan,
				})
			}

			// Enforce monthly scan limit
			now := time.Now()
			startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
			var monthlyScans int64
			config.DB.Model(&models.ScanJob{}).
				Where("organization_id = ? AND created_at >= ?", org.ID, startOfMonth).
				Count(&monthlyScans)
			if org.MaxScans > 0 && int(monthlyScans) >= org.MaxScans {
				return c.Status(403).JSON(fiber.Map{
					"error":   "Monthly scan limit reached for your plan. Please upgrade.",
					"limit":   org.MaxScans,
					"used":    monthlyScans,
					"plan":    org.Plan,
				})
			}
		}
	}

	// If no target IDs provided, scan all targets (scoped to org)
	var targets []models.ScanTarget
	if len(req.TargetIDs) > 0 {
		ScopedDB(c).Where("id IN ?", req.TargetIDs).Find(&targets)
	} else {
		ScopedDB(c).Find(&targets)
	}

	if len(targets) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No targets found to scan"})
	}

	// Check domain verification (skip for system admin)
	userRole, _ := c.Locals("role").(string)
	if userRole != "admin" {
		var unverifiedDomains []string
		for _, target := range targets {
			var verification models.DomainVerification
			err := config.DB.Where("scan_target_id = ? AND is_verified = ?", target.ID, true).First(&verification).Error
			if err != nil {
				unverifiedDomains = append(unverifiedDomains, target.URL)
			}
		}
		if len(unverifiedDomains) > 0 {
			return c.Status(403).JSON(fiber.Map{
				"error":              "Some targets are not verified. Please verify domain ownership before scanning.",
				"unverified_domains": unverifiedDomains,
			})
		}
	}

	// Create scan job
	job := models.ScanJob{
		OrganizationID: GetUserOrgID(c),
		Name:           req.Name,
		Status:         "pending",
		UserID:         userID,
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

	// Run scan in background — use policy-based engine if specified, otherwise plan-based
	var engine *scanner.Engine
	if req.Policy != "" {
		engine = scanner.NewEngineForPolicy(req.Policy)
	} else {
		engine = scanner.NewEngineForPlan(plan)
	}
	go engine.RunScan(&job)

	return c.Status(201).JSON(job)
}

func DeleteScanJob(c *fiber.Ctx) error {
	id := c.Params("id")
	var job models.ScanJob
	if err := config.DB.First(&job, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan job not found"})
	}

	// Hard-delete associated results, checks, and AI analyses (no soft-delete leftovers)
	var results []models.ScanResult
	config.DB.Unscoped().Where("scan_job_id = ?", job.ID).Find(&results)
	for _, r := range results {
		config.DB.Unscoped().Where("scan_result_id = ?", r.ID).Delete(&models.CheckResult{})
		config.DB.Unscoped().Where("scan_result_id = ?", r.ID).Delete(&models.AIAnalysis{})
	}
	config.DB.Unscoped().Where("scan_job_id = ?", job.ID).Delete(&models.ScanResult{})
	config.DB.Unscoped().Delete(&job)

	return c.JSON(fiber.Map{"message": "Scan job permanently deleted"})
}

// --- Dashboard Stats ---

func GetDashboardStats(c *fiber.Ctx) error {
	orgID := GetUserOrgID(c)
	role, _ := c.Locals("role").(string)
	isAdmin := role == "admin"

	var targetCount int64
	if isAdmin {
		config.DB.Model(&models.ScanTarget{}).Count(&targetCount)
	} else {
		config.DB.Model(&models.ScanTarget{}).Where("organization_id = ?", orgID).Count(&targetCount)
	}

	var jobCount int64
	if isAdmin {
		config.DB.Model(&models.ScanJob{}).Count(&jobCount)
	} else {
		config.DB.Model(&models.ScanJob{}).Where("organization_id = ?", orgID).Count(&jobCount)
	}

	var completedJobs int64
	if isAdmin {
		config.DB.Model(&models.ScanJob{}).Where("status = ?", "completed").Count(&completedJobs)
	} else {
		config.DB.Model(&models.ScanJob{}).Where("organization_id = ? AND status = ?", orgID, "completed").Count(&completedJobs)
	}

	// Get latest scan results - scoped to org for non-admins
	var latestResults []models.ScanResult
	if isAdmin {
		config.DB.Raw(`
			SELECT sr.* FROM scan_results sr
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results WHERE status = 'completed'
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			ORDER BY sr.overall_score DESC LIMIT 20
		`).Preload("ScanTarget").Find(&latestResults)
	} else {
		config.DB.Raw(`
			SELECT sr.* FROM scan_results sr
			INNER JOIN scan_targets st ON st.id = sr.scan_target_id
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results WHERE status = 'completed'
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			WHERE st.organization_id = ?
			ORDER BY sr.overall_score DESC LIMIT 20
		`, orgID).Preload("ScanTarget").Find(&latestResults)
	}

	// Get worst 5 scan results (bottom scores)
	var worstResults []models.ScanResult
	if isAdmin {
		config.DB.Raw(`
			SELECT sr.* FROM scan_results sr
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results WHERE status = 'completed'
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			ORDER BY sr.overall_score ASC LIMIT 5
		`).Preload("ScanTarget").Find(&worstResults)
	} else {
		config.DB.Raw(`
			SELECT sr.* FROM scan_results sr
			INNER JOIN scan_targets st ON st.id = sr.scan_target_id
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results WHERE status = 'completed'
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			WHERE st.organization_id = ?
			ORDER BY sr.overall_score ASC LIMIT 5
		`, orgID).Preload("ScanTarget").Find(&worstResults)
	}

	// Average score
	var avgScore float64
	if isAdmin {
		config.DB.Raw(`
			SELECT COALESCE(AVG(sr.overall_score), 0) FROM scan_results sr
			INNER JOIN (SELECT scan_target_id, MAX(id) AS max_id FROM scan_results WHERE status = 'completed' GROUP BY scan_target_id) latest ON sr.id = latest.max_id
		`).Scan(&avgScore)
	} else {
		config.DB.Raw(`
			SELECT COALESCE(AVG(sr.overall_score), 0) FROM scan_results sr
			INNER JOIN scan_targets st ON st.id = sr.scan_target_id
			INNER JOIN (SELECT scan_target_id, MAX(id) AS max_id FROM scan_results WHERE status = 'completed' GROUP BY scan_target_id) latest ON sr.id = latest.max_id
			WHERE st.organization_id = ?
		`, orgID).Scan(&avgScore)
	}

	// Score distribution - scoped (each count uses a fresh session to avoid chaining)
	var excellent, good, average, poor, critical int64
	scopeFilter := func() *gorm.DB {
		q := config.DB.Model(&models.ScanResult{}).Where("status = ?", "completed")
		if !isAdmin {
			q = q.Where("scan_target_id IN (SELECT id FROM scan_targets WHERE organization_id = ?)", orgID)
		}
		return q
	}
	scopeFilter().Where("overall_score >= 800").Count(&excellent)
	scopeFilter().Where("overall_score >= 600 AND overall_score < 800").Count(&good)
	scopeFilter().Where("overall_score >= 400 AND overall_score < 600").Count(&average)
	scopeFilter().Where("overall_score >= 200 AND overall_score < 400").Count(&poor)
	scopeFilter().Where("overall_score < 200").Count(&critical)

	return c.JSON(fiber.Map{
		"total_targets":   targetCount,
		"total_scans":     jobCount,
		"completed_scans": completedJobs,
		"average_score":   avgScore,
		"latest_results":  latestResults,
		"worst_results":   worstResults,
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

	orgID := GetUserOrgID(c)
	role, _ := c.Locals("role").(string)
	isAdmin := role == "admin"

	var ranked []RankedSite
	if isAdmin {
		config.DB.Raw(`
			SELECT sr.scan_target_id, st.url, st.name, st.institution,
				   sr.overall_score AS latest_score, sr.id AS scan_result_id,
				   sr.ended_at AS scanned_at
			FROM scan_results sr
			INNER JOIN scan_targets st ON st.id = sr.scan_target_id
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results
				WHERE status = 'completed' AND deleted_at IS NULL
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			WHERE sr.deleted_at IS NULL AND st.deleted_at IS NULL
			ORDER BY sr.overall_score DESC
		`).Scan(&ranked)
	} else {
		config.DB.Raw(`
			SELECT sr.scan_target_id, st.url, st.name, st.institution,
				   sr.overall_score AS latest_score, sr.id AS scan_result_id,
				   sr.ended_at AS scanned_at
			FROM scan_results sr
			INNER JOIN scan_targets st ON st.id = sr.scan_target_id
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results
				WHERE status = 'completed' AND deleted_at IS NULL
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			WHERE st.organization_id = ?
			  AND sr.deleted_at IS NULL AND st.deleted_at IS NULL
			ORDER BY sr.overall_score DESC
		`, orgID).Scan(&ranked)
	}

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

	// Summary stats - scoped to org for non-admins
	var totalSites int64
	if isAdmin {
		config.DB.Model(&models.ScanTarget{}).Count(&totalSites)
	} else {
		config.DB.Model(&models.ScanTarget{}).Where("organization_id = ?", orgID).Count(&totalSites)
	}

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

// --- Scan Comparison ---

func CompareScanResults(c *fiber.Ctx) error {
	oldID := c.Query("old")
	newID := c.Query("new")

	if oldID == "" || newID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Both 'old' and 'new' result IDs are required"})
	}

	var oldResult, newResult models.ScanResult
	if err := config.DB.Preload("ScanTarget").First(&oldResult, oldID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Old result not found"})
	}
	if err := config.DB.Preload("ScanTarget").First(&newResult, newID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "New result not found"})
	}

	var oldChecks, newChecks []models.CheckResult
	config.DB.Where("scan_result_id = ?", oldResult.ID).Find(&oldChecks)
	config.DB.Where("scan_result_id = ?", newResult.ID).Find(&newChecks)

	// Build category scores for both
	type CategoryComparison struct {
		Category string  `json:"category"`
		OldScore float64 `json:"old_score"`
		NewScore float64 `json:"new_score"`
		Change   float64 `json:"change"`
		Status   string  `json:"status"` // improved, declined, unchanged
	}

	type CheckComparison struct {
		CheckName string  `json:"check_name"`
		Category  string  `json:"category"`
		OldScore  float64 `json:"old_score"`
		NewScore  float64 `json:"new_score"`
		OldStatus string  `json:"old_status"`
		NewStatus string  `json:"new_status"`
		Change    float64 `json:"change"`
		Status    string  `json:"status"`
	}

	// Calculate category scores
	calcCatScores := func(checks []models.CheckResult) map[string]float64 {
		catTotal := map[string]float64{}
		catWeight := map[string]float64{}
		for _, ch := range checks {
			catTotal[ch.Category] += ch.Score * ch.Weight
			catWeight[ch.Category] += ch.Weight
		}
		result := map[string]float64{}
		for cat, total := range catTotal {
			if catWeight[cat] > 0 {
				result[cat] = total / catWeight[cat]
			}
		}
		return result
	}

	oldCatScores := calcCatScores(oldChecks)
	newCatScores := calcCatScores(newChecks)

	// All categories
	allCats := map[string]bool{}
	for cat := range oldCatScores {
		allCats[cat] = true
	}
	for cat := range newCatScores {
		allCats[cat] = true
	}

	var categories []CategoryComparison
	for cat := range allCats {
		oldScore := oldCatScores[cat]
		newScore := newCatScores[cat]
		change := newScore - oldScore
		status := "unchanged"
		if change > 10 {
			status = "improved"
		}
		if change < -10 {
			status = "declined"
		}
		categories = append(categories, CategoryComparison{
			Category: cat, OldScore: oldScore, NewScore: newScore, Change: change, Status: status,
		})
	}

	// Check-level comparison
	oldCheckMap := map[string]models.CheckResult{}
	for _, ch := range oldChecks {
		oldCheckMap[ch.CheckName] = ch
	}

	var checks []CheckComparison
	for _, newCh := range newChecks {
		oldCh, exists := oldCheckMap[newCh.CheckName]
		oldScore := 0.0
		oldStatus := "N/A"
		if exists {
			oldScore = oldCh.Score
			oldStatus = oldCh.Status
		}
		change := newCh.Score - oldScore
		status := "unchanged"
		if change > 50 {
			status = "improved"
		}
		if change < -50 {
			status = "declined"
		}
		checks = append(checks, CheckComparison{
			CheckName: newCh.CheckName, Category: newCh.Category,
			OldScore: oldScore, NewScore: newCh.Score,
			OldStatus: oldStatus, NewStatus: newCh.Status,
			Change: change, Status: status,
		})
	}

	// Summary
	improved := 0
	declined := 0
	for _, ch := range checks {
		if ch.Status == "improved" {
			improved++
		}
		if ch.Status == "declined" {
			declined++
		}
	}

	return c.JSON(fiber.Map{
		"old_result": fiber.Map{
			"id": oldResult.ID, "score": oldResult.OverallScore,
			"date": oldResult.EndedAt, "target": oldResult.ScanTarget,
		},
		"new_result": fiber.Map{
			"id": newResult.ID, "score": newResult.OverallScore,
			"date": newResult.EndedAt, "target": newResult.ScanTarget,
		},
		"score_change": newResult.OverallScore - oldResult.OverallScore,
		"categories":   categories,
		"checks":       checks,
		"summary": fiber.Map{
			"total_checks": len(checks),
			"improved":     improved,
			"declined":     declined,
			"unchanged":    len(checks) - improved - declined,
		},
	})
}

// --- Compliance Report ---

func GetComplianceReport(c *fiber.Ctx) error {
	resultID := c.Params("id")

	var checks []models.CheckResult
	config.DB.Where("scan_result_id = ?", resultID).Find(&checks)

	// Group by OWASP category
	type OWASPCompliance struct {
		ID           string      `json:"id"`
		Name         string      `json:"name"`
		TotalChecks  int         `json:"total_checks"`
		PassedChecks int         `json:"passed_checks"`
		FailedChecks int         `json:"failed_checks"`
		WarnChecks   int         `json:"warn_checks"`
		Compliance   float64     `json:"compliance"`
		Severity     string      `json:"severity"`
		Checks       []fiber.Map `json:"checks"`
	}

	owaspMap := map[string]*OWASPCompliance{}

	for _, ch := range checks {
		if ch.OWASP == "" {
			continue
		}

		if _, exists := owaspMap[ch.OWASP]; !exists {
			owaspMap[ch.OWASP] = &OWASPCompliance{
				ID: ch.OWASP, Name: ch.OWASPName,
			}
		}

		entry := owaspMap[ch.OWASP]
		entry.TotalChecks++

		switch ch.Status {
		case "pass":
			entry.PassedChecks++
		case "fail":
			entry.FailedChecks++
		case "warn", "warning":
			entry.WarnChecks++
		}

		entry.Checks = append(entry.Checks, fiber.Map{
			"name": ch.CheckName, "score": ch.Score,
			"status": ch.Status, "severity": ch.Severity,
			"cwe": ch.CWE, "cwe_name": ch.CWEName,
		})
	}

	// Calculate compliance percentages
	var results []OWASPCompliance
	totalCompliant := 0
	totalChecks := 0

	for _, entry := range owaspMap {
		if entry.TotalChecks > 0 {
			entry.Compliance = float64(entry.PassedChecks) / float64(entry.TotalChecks) * 100
		}
		if entry.FailedChecks > 0 {
			entry.Severity = "high"
		}
		if entry.PassedChecks == entry.TotalChecks {
			entry.Severity = "low"
		}

		totalCompliant += entry.PassedChecks
		totalChecks += entry.TotalChecks
		results = append(results, *entry)
	}

	overallCompliance := 0.0
	if totalChecks > 0 {
		overallCompliance = float64(totalCompliant) / float64(totalChecks) * 100
	}

	return c.JSON(fiber.Map{
		"overall_compliance": overallCompliance,
		"total_checks":      totalChecks,
		"total_passed":      totalCompliant,
		"owasp_categories":  results,
	})
}

// --- Remediation Guide ---

func GetRemediationGuide(c *fiber.Ctx) error {
	checkName := c.Query("check")
	serverType := c.Query("server", "all")

	if checkName == "" {
		// Return list of all available remediations
		var keys []string
		for k := range scanner.RemediationDB {
			keys = append(keys, k)
		}
		return c.JSON(fiber.Map{"available_checks": keys})
	}

	guide, exists := scanner.RemediationDB[checkName]
	if !exists {
		// Fuzzy match: try partial matching (e.g., "DMARC Record (Email Security)" → "DMARC Record")
		checkLower := strings.ToLower(checkName)
		for key, g := range scanner.RemediationDB {
			keyLower := strings.ToLower(key)
			if strings.Contains(checkLower, keyLower) || strings.Contains(keyLower, checkLower) {
				guide = g
				exists = true
				break
			}
		}
		if !exists {
			// Try matching just the first two words
			parts := strings.Fields(checkName)
			if len(parts) >= 2 {
				prefix := strings.ToLower(parts[0] + " " + parts[1])
				for key, g := range scanner.RemediationDB {
					if strings.HasPrefix(strings.ToLower(key), prefix) {
						guide = g
						exists = true
						break
					}
				}
			}
		}
		if !exists {
			return c.Status(404).JSON(fiber.Map{"error": "No remediation guide found for this check"})
		}
	}

	if serverType != "all" {
		if specific, ok := guide.Guides[serverType]; ok {
			guide.Guides = map[string]string{serverType: specific}
		}
	}

	return c.JSON(guide)
}

// --- Cancel Scan ---

func CancelScan(c *fiber.Ctx) error {
	id := c.Params("id")
	jobID, _ := strconv.ParseUint(id, 10, 64)

	var job models.ScanJob
	if err := config.DB.First(&job, jobID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan job not found"})
	}

	if job.Status != "running" && job.Status != "pending" {
		return c.Status(400).JSON(fiber.Map{"error": "Scan is not running"})
	}

	if scanner.ActiveScans.Cancel(uint(jobID)) {
		return c.JSON(fiber.Map{"message": "Scan cancellation requested", "job_id": jobID})
	}

	// If not in active scans, just mark as cancelled in DB
	now := time.Now()
	job.Status = "cancelled"
	job.EndedAt = &now
	config.DB.Save(&job)
	return c.JSON(fiber.Map{"message": "Scan marked as cancelled", "job_id": jobID})
}

// --- Enhanced Dashboard Stats ---

func GetDashboardEnhanced(c *fiber.Ctx) error {
	orgID := GetUserOrgID(c)
	role, _ := c.Locals("role").(string)
	isAdmin := role == "admin"

	// Most common vulnerabilities (top 10 failed checks)
	type VulnCount struct {
		CheckName string `json:"check_name"`
		Category  string `json:"category"`
		Count     int64  `json:"count"`
		Severity  string `json:"severity"`
	}
	var topVulns []VulnCount
	vulnQuery := config.DB.Table("check_results").
		Select("check_name, category, COUNT(*) as count, severity").
		Where("status = 'fail'").
		Group("check_name, category, severity").
		Order("count DESC").
		Limit(10)
	if !isAdmin {
		vulnQuery = vulnQuery.Where("scan_result_id IN (SELECT id FROM scan_results WHERE scan_target_id IN (SELECT id FROM scan_targets WHERE organization_id = ?))", orgID)
	}
	vulnQuery.Scan(&topVulns)

	// Category average scores
	type CategoryAvg struct {
		Category string  `json:"category"`
		AvgScore float64 `json:"avg_score"`
	}
	var catAvgs []CategoryAvg
	catQuery := config.DB.Table("check_results").
		Select("category, AVG(score) as avg_score").
		Group("category").
		Order("avg_score ASC")
	if !isAdmin {
		catQuery = catQuery.Where("scan_result_id IN (SELECT id FROM scan_results WHERE scan_target_id IN (SELECT id FROM scan_targets WHERE organization_id = ?))", orgID)
	}
	catQuery.Scan(&catAvgs)

	// Score trend over time (last 12 months)
	type MonthlyTrend struct {
		Month    string  `json:"month"`
		AvgScore float64 `json:"avg_score"`
		Count    int64   `json:"count"`
	}
	var trend []MonthlyTrend
	cutoff := time.Now().AddDate(-1, 0, 0).Format("2006-01-02")
	if !isAdmin {
		config.DB.Raw(`
			SELECT strftime('%Y-%m', sr.ended_at) AS month, AVG(sr.overall_score) AS avg_score, COUNT(*) AS count
			FROM scan_results sr
			WHERE sr.status = 'completed' AND sr.ended_at >= ?
			AND sr.scan_target_id IN (SELECT id FROM scan_targets WHERE organization_id = ?)
			GROUP BY strftime('%Y-%m', sr.ended_at) ORDER BY month ASC
		`, cutoff, orgID).Scan(&trend)
	} else {
		config.DB.Raw(`
			SELECT strftime('%Y-%m', sr.ended_at) AS month, AVG(sr.overall_score) AS avg_score, COUNT(*) AS count
			FROM scan_results sr
			WHERE sr.status = 'completed' AND sr.ended_at >= ?
			GROUP BY strftime('%Y-%m', sr.ended_at) ORDER BY month ASC
		`, cutoff).Scan(&trend)
	}

	// Severity distribution
	type SeverityCount struct {
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}
	var sevDist []SeverityCount
	sevQuery := config.DB.Table("check_results").
		Select("severity, COUNT(*) as count").
		Where("status = 'fail'").
		Group("severity")
	if !isAdmin {
		sevQuery = sevQuery.Where("scan_result_id IN (SELECT id FROM scan_results WHERE scan_target_id IN (SELECT id FROM scan_targets WHERE organization_id = ?))", orgID)
	}
	sevQuery.Scan(&sevDist)

	return c.JSON(fiber.Map{
		"top_vulnerabilities":   topVulns,
		"category_averages":     catAvgs,
		"score_trend":           trend,
		"severity_distribution": sevDist,
	})
}

// --- Timeline Comparison: all scans for a target over time ---

func GetTimelineComparison(c *fiber.Ctx) error {
	targetID := c.Params("id")

	type TimelineEntry struct {
		ResultID   uint    `json:"result_id"`
		Score      float64 `json:"score"`
		Grade      string  `json:"grade"`
		ScannedAt  string  `json:"scanned_at"`
		Status     string  `json:"status"`
		CheckCount int     `json:"check_count"`
		FailCount  int     `json:"fail_count"`
		WarnCount  int     `json:"warn_count"`
		PassCount  int     `json:"pass_count"`
	}

	var results []models.ScanResult
	config.DB.Where("scan_target_id = ? AND status = 'completed'", targetID).
		Order("created_at ASC").
		Find(&results)

	var timeline []TimelineEntry
	for _, r := range results {
		var checks []models.CheckResult
		config.DB.Where("scan_result_id = ?", r.ID).Find(&checks)

		failCount, warnCount, passCount := 0, 0, 0
		for _, ch := range checks {
			switch ch.Status {
			case "fail":
				failCount++
			case "warn", "warning":
				warnCount++
			case "pass":
				passCount++
			}
		}

		scannedAt := ""
		if r.EndedAt != nil {
			scannedAt = r.EndedAt.Format("2006-01-02 15:04")
		}

		timeline = append(timeline, TimelineEntry{
			ResultID:   r.ID,
			Score:      r.OverallScore,
			Grade:      scoreToGrade(r.OverallScore),
			ScannedAt:  scannedAt,
			Status:     r.Status,
			CheckCount: len(checks),
			FailCount:  failCount,
			WarnCount:  warnCount,
			PassCount:  passCount,
		})
	}

	// Category comparison between first and last scan
	var catComparison []fiber.Map
	if len(results) >= 2 {
		first := results[0]
		last := results[len(results)-1]

		var firstChecks, lastChecks []models.CheckResult
		config.DB.Where("scan_result_id = ?", first.ID).Find(&firstChecks)
		config.DB.Where("scan_result_id = ?", last.ID).Find(&lastChecks)

		calcCatScore := func(checks []models.CheckResult) map[string]float64 {
			t := map[string]float64{}
			w := map[string]float64{}
			for _, ch := range checks {
				t[ch.Category] += ch.Score * ch.Weight
				w[ch.Category] += ch.Weight
			}
			result := map[string]float64{}
			for cat, total := range t {
				if w[cat] > 0 {
					result[cat] = total / w[cat]
				}
			}
			return result
		}

		firstScores := calcCatScore(firstChecks)
		lastScores := calcCatScore(lastChecks)

		allCats := map[string]bool{}
		for c := range firstScores {
			allCats[c] = true
		}
		for c := range lastScores {
			allCats[c] = true
		}

		for cat := range allCats {
			change := lastScores[cat] - firstScores[cat]
			status := "unchanged"
			if change > 10 {
				status = "improved"
			} else if change < -10 {
				status = "declined"
			}
			catComparison = append(catComparison, fiber.Map{
				"category":    cat,
				"first_score": firstScores[cat],
				"last_score":  lastScores[cat],
				"change":      change,
				"status":      status,
			})
		}
	}

	return c.JSON(fiber.Map{
		"timeline":            timeline,
		"total_scans":         len(timeline),
		"category_comparison": catComparison,
	})
}

// --- Fix Priority Recommendations ---

func GetFixPriority(c *fiber.Ctx) error {
	resultID := c.Params("id")

	var checks []models.CheckResult
	config.DB.Where("scan_result_id = ? AND (status = 'fail' OR status = 'warn')", resultID).
		Order("score ASC, cvss_score DESC").
		Find(&checks)

	type FixRecommendation struct {
		Priority      int     `json:"priority"`
		CheckName     string  `json:"check_name"`
		Category      string  `json:"category"`
		CurrentScore  float64 `json:"current_score"`
		Impact        float64 `json:"impact"`
		Severity      string  `json:"severity"`
		CVSSScore     float64 `json:"cvss_score"`
		Effort        string  `json:"effort"` // easy, medium, hard
		OWASP         string  `json:"owasp"`
		CWE           string  `json:"cwe"`
		Recommendation string `json:"recommendation"`
	}

	var recommendations []FixRecommendation

	for i, ch := range checks {
		impact := (maxScore - ch.Score) * ch.Weight
		effort := estimateEffort(ch.CheckName, ch.Category)
		rec := getFixRecommendation(ch.CheckName)

		recommendations = append(recommendations, FixRecommendation{
			Priority:       i + 1,
			CheckName:      ch.CheckName,
			Category:       ch.Category,
			CurrentScore:   ch.Score,
			Impact:         impact,
			Severity:       ch.Severity,
			CVSSScore:      ch.CVSSScore,
			Effort:         effort,
			OWASP:          ch.OWASP,
			CWE:            ch.CWE,
			Recommendation: rec,
		})
	}

	// Calculate potential score improvement
	totalImpact := 0.0
	for _, r := range recommendations {
		totalImpact += r.Impact
	}

	quickWins := 0
	for _, r := range recommendations {
		if r.Effort == "easy" {
			quickWins++
		}
	}

	return c.JSON(fiber.Map{
		"recommendations":        recommendations,
		"total_issues":           len(recommendations),
		"total_potential_impact":  totalImpact,
		"quick_wins":             quickWins,
	})
}

const maxScore = 1000.0

func estimateEffort(checkName, category string) string {
	easyCategories := map[string]bool{
		"headers": true, "cookies": true, "mixed_content": true, "seo": true,
	}
	hardCategories := map[string]bool{
		"sqli": true, "xss": true, "advanced_security": true, "malware": true,
	}

	if easyCategories[category] {
		return "easy"
	}
	if hardCategories[category] {
		return "hard"
	}

	lowerName := strings.ToLower(checkName)
	if strings.Contains(lowerName, "header") || strings.Contains(lowerName, "hsts") ||
		strings.Contains(lowerName, "x-frame") || strings.Contains(lowerName, "x-content") {
		return "easy"
	}
	return "medium"
}

func getFixRecommendation(checkName string) string {
	recommendations := map[string]string{
		"Strict-Transport-Security (HSTS)": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header to your web server configuration",
		"Content-Security-Policy":          "Define a Content-Security-Policy header to prevent XSS and data injection attacks",
		"X-Frame-Options":                  "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header to prevent clickjacking",
		"X-Content-Type-Options":           "Add 'X-Content-Type-Options: nosniff' header to prevent MIME type sniffing",
		"SQL Injection Test":               "Use parameterized queries/prepared statements. Never concatenate user input into SQL queries",
		"Open Port Detection":              "Close unnecessary ports. Restrict database and admin ports to internal networks using firewall rules",
		"Database Error Disclosure":        "Configure custom error pages. Disable verbose error output in production",
	}

	if rec, ok := recommendations[checkName]; ok {
		return rec
	}
	return "Review and fix this security issue based on industry best practices"
}

// --- CVE Search ---

func SearchCVEs(c *fiber.Ctx) error {
	keyword := c.Query("keyword", "")
	if keyword == "" {
		return c.Status(400).JSON(fiber.Map{"error": "keyword query parameter is required"})
	}

	entries, err := services.FetchCVEsForProduct(keyword)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch CVE data: " + err.Error()})
	}

	return c.JSON(fiber.Map{
		"keyword":      keyword,
		"total":        len(entries),
		"last_updated": services.CVECache.LastUpdated(),
		"cves":         entries,
	})
}

// --- Domain Discovery: search the internet for websites by domain extension ---

func DiscoverDomains(c *fiber.Ctx) error {
	domain := c.Query("domain", "")
	if domain == "" {
		return c.Status(400).JSON(fiber.Map{"error": "domain query parameter is required (e.g., .edu.iq)"})
	}
	if domain[0] != '.' {
		domain = "." + domain
	}

	// Search crt.sh (Certificate Transparency) for real domains on the internet
	crtDomains, err := services.DiscoverDomainsFromCT(domain)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Discovery failed: " + err.Error()})
	}

	// Check which ones are already in our targets
	var existingURLs []string
	config.DB.Model(&models.ScanTarget{}).Pluck("url", &existingURLs)

	existingMap := map[string]bool{}
	for _, u := range existingURLs {
		// Normalize: strip protocol and trailing slash
		clean := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
		clean = strings.TrimRight(clean, "/")
		existingMap[strings.ToLower(clean)] = true
	}

	type DiscoveredSite struct {
		Domain     string `json:"domain"`
		URL        string `json:"url"`
		AlreadyAdded bool `json:"already_added"`
	}

	var results []DiscoveredSite
	newCount := 0
	for _, d := range crtDomains {
		clean := strings.ToLower(strings.TrimRight(d, "/"))
		added := existingMap[clean]
		results = append(results, DiscoveredSite{
			Domain:       d,
			URL:          "https://" + d,
			AlreadyAdded: added,
		})
		if !added {
			newCount++
		}
	}

	return c.JSON(fiber.Map{
		"domain":        domain,
		"total_found":   len(results),
		"new_sites":     newCount,
		"already_added": len(results) - newCount,
		"results":       results,
	})
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
