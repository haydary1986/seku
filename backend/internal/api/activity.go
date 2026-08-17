package api

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
)

// firstNonBlank returns a if non-empty (trimmed), else b.
func firstNonBlank(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// GetScanActivity returns a chronological log of scans with the user who ran
// each — an admin view of "what did users scan". Admin-only (mounted under the
// admin group). Includes a per-user summary.
func GetScanActivity(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 300)
	if limit < 1 || limit > 1000 {
		limit = 300
	}

	var jobs []models.ScanJob
	config.DB.Preload("Results.ScanTarget").Order("created_at desc").Limit(limit).Find(&jobs)

	// Resolve usernames in one query.
	userIDs := map[uint]bool{}
	for _, j := range jobs {
		if j.UserID != 0 {
			userIDs[j.UserID] = true
		}
	}
	ids := make([]uint, 0, len(userIDs))
	for id := range userIDs {
		ids = append(ids, id)
	}
	users := map[uint]models.User{}
	if len(ids) > 0 {
		var us []models.User
		config.DB.Where("id IN ?", ids).Find(&us)
		for _, u := range us {
			users[u.ID] = u
		}
	}

	type activityRow struct {
		JobID       uint     `json:"job_id"`
		UserID      uint     `json:"user_id"`
		Username    string   `json:"username"`
		FullName    string   `json:"full_name"`
		Name        string   `json:"name"`
		Policy      string   `json:"policy"`
		Status      string   `json:"status"`
		Source      string   `json:"source"`      // web | desktop | agent
		DeviceInfo  string   `json:"device_info"` // machine, for desktop/agent scans
		CreatedAt   string   `json:"created_at"`
		EndedAt     string   `json:"ended_at"`
		Targets     []string `json:"targets"`
		TargetCount int      `json:"target_count"`
		ResultCount int      `json:"result_count"`
	}
	type userSummary struct {
		UserID    uint   `json:"user_id"`
		Username  string `json:"username"`
		FullName  string `json:"full_name"`
		ScanCount int    `json:"scan_count"`
		LastScan  string `json:"last_scan"`
	}

	rows := make([]activityRow, 0, len(jobs))
	summary := map[uint]*userSummary{}

	for _, j := range jobs {
		u := users[j.UserID]
		var targets []string
		for _, r := range j.Results {
			if r.ScanTarget.URL != "" {
				targets = append(targets, r.ScanTarget.URL)
			}
		}
		created, ended := "", ""
		created = j.CreatedAt.Format("2006-01-02 15:04")
		if j.EndedAt != nil {
			ended = j.EndedAt.Format("2006-01-02 15:04")
		}
		rows = append(rows, activityRow{
			JobID: j.ID, UserID: j.UserID, Username: u.Username, FullName: u.FullName,
			Name: j.Name, Policy: j.Policy, Status: j.Status,
			Source: firstNonBlank(j.Source, "web"), DeviceInfo: j.DeviceInfo,
			CreatedAt: created, EndedAt: ended,
			Targets: targets, TargetCount: len(targets), ResultCount: len(j.Results),
		})

		s := summary[j.UserID]
		if s == nil {
			s = &userSummary{UserID: j.UserID, Username: u.Username, FullName: u.FullName}
			summary[j.UserID] = s
		}
		s.ScanCount++
		if s.LastScan == "" {
			s.LastScan = created // jobs are newest-first, so first seen = latest
		}
	}

	summaries := make([]userSummary, 0, len(summary))
	for _, s := range summary {
		summaries = append(summaries, *s)
	}

	return c.JSON(fiber.Map{
		"activity": rows,
		"by_user":  summaries,
		"total":    len(rows),
	})
}
