package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
	"seku/internal/scanner"
	"seku/internal/services"
)

func GeneratePDFReport(c *fiber.Ctx) error {
	id := c.Params("id")

	var result models.ScanResult
	if err := config.DB.Preload("ScanTarget").Preload("Checks").First(&result, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan result not found"})
	}

	pdfBytes, err := services.GenerateScanReport(&result, result.Checks)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate PDF report"})
	}

	// Use website name or URL as filename
	name := result.ScanTarget.Name
	if name == "" {
		name = result.ScanTarget.URL
	}
	// Sanitize filename - replace spaces and special chars
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, "/", "-")
	safeName := url.PathEscape(name)

	filename := fmt.Sprintf("Seku-Report-%s.pdf", safeName)

	c.Set("Content-Type", "application/pdf")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"; filename*=UTF-8''%s", filename, safeName+".pdf"))

	return c.Send(pdfBytes)
}

// ExportSARIF generates a SARIF v2.1.0 JSON report for a scan result.
func ExportSARIF(c *fiber.Ctx) error {
	id := c.Params("id")

	var result models.ScanResult
	if err := config.DB.Preload("ScanTarget").First(&result, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Result not found"})
	}

	var checks []models.CheckResult
	config.DB.Where("scan_result_id = ?", result.ID).Find(&checks)

	data, err := services.GenerateSARIF(&result, checks)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate SARIF"})
	}

	// Sanitize URL for filename
	name := result.ScanTarget.URL
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, ":", "-")
	safeName := url.PathEscape(name)
	filename := fmt.Sprintf("vscan-%s.sarif", safeName)

	c.Set("Content-Type", "application/sarif+json")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	return c.Send(data)
}

// GetUpgradeSuggestions returns smart upgrade suggestions for libraries found in a scan.
func GetUpgradeSuggestions(c *fiber.Ctx) error {
	resultID := c.Params("id")

	var checks []models.CheckResult
	config.DB.Where("scan_result_id = ?", resultID).Find(&checks)

	suggestions := scanner.GetUpgradeSuggestions(checks)
	return c.JSON(suggestions)
}

// ExportCSV generates a CSV report for a scan result.
func ExportCSV(c *fiber.Ctx) error {
	id := c.Params("id")
	var result models.ScanResult
	if err := config.DB.Preload("ScanTarget").First(&result, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Result not found"})
	}
	var checks []models.CheckResult
	config.DB.Where("scan_result_id = ?", result.ID).Order("category, check_name").Find(&checks)

	var buf bytes.Buffer
	// BOM for Excel UTF-8 support
	buf.Write([]byte{0xEF, 0xBB, 0xBF})

	buf.WriteString("Category,Check Name,Status,Score,Severity,Confidence,OWASP,CWE,Details\n")

	for _, ch := range checks {
		details := ""
		if ch.Details != "" {
			var d map[string]interface{}
			if json.Unmarshal([]byte(ch.Details), &d) == nil {
				if msg, ok := d["message"].(string); ok {
					details = msg
				}
			}
		}
		line := fmt.Sprintf("%s,%s,%s,%.0f,%s,%d,%s,%s,%s\n",
			csvEscape(ch.Category),
			csvEscape(ch.CheckName),
			csvEscape(ch.Status),
			ch.Score,
			csvEscape(ch.Severity),
			ch.Confidence,
			csvEscape(ch.OWASP),
			csvEscape(ch.CWE),
			csvEscape(details),
		)
		buf.WriteString(line)
	}

	buf.WriteString(fmt.Sprintf("\nOverall Score,%.0f/1000,,,,,,\n", result.OverallScore))
	buf.WriteString(fmt.Sprintf("Website,%s,,,,,,\n", csvEscape(result.ScanTarget.URL)))
	if result.EndedAt != nil {
		buf.WriteString(fmt.Sprintf("Scan Date,%s,,,,,,\n", result.EndedAt.Format("2006-01-02 15:04:05")))
	}

	name := result.ScanTarget.URL
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, ":", "-")
	safeName := url.PathEscape(name)
	filename := fmt.Sprintf("vscan-%s.csv", safeName)

	c.Set("Content-Type", "text/csv; charset=utf-8")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	return c.Send(buf.Bytes())
}

// ExportLeaderboardCSV generates a CSV export of the leaderboard rankings.
func ExportLeaderboardCSV(c *fiber.Ctx) error {
	orgID := GetUserOrgID(c)
	role, _ := c.Locals("role").(string)
	isAdmin := role == "admin"

	type RankedSite struct {
		ScanTargetID uint    `json:"scan_target_id"`
		URL          string  `json:"url"`
		Name         string  `json:"name"`
		Institution  string  `json:"institution"`
		LatestScore  float64 `json:"latest_score"`
		ScanResultID uint    `json:"scan_result_id"`
	}

	var ranked []RankedSite
	if isAdmin {
		config.DB.Raw(`
			SELECT sr.scan_target_id, st.url, st.name, st.institution,
				   sr.overall_score AS latest_score, sr.id AS scan_result_id
			FROM scan_results sr
			INNER JOIN scan_targets st ON st.id = sr.scan_target_id
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results WHERE status = 'completed'
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			ORDER BY sr.overall_score DESC
		`).Scan(&ranked)
	} else {
		config.DB.Raw(`
			SELECT sr.scan_target_id, st.url, st.name, st.institution,
				   sr.overall_score AS latest_score, sr.id AS scan_result_id
			FROM scan_results sr
			INNER JOIN scan_targets st ON st.id = sr.scan_target_id
			INNER JOIN (
				SELECT scan_target_id, MAX(id) AS max_id
				FROM scan_results WHERE status = 'completed'
				GROUP BY scan_target_id
			) latest ON sr.id = latest.max_id
			WHERE st.organization_id = ?
			ORDER BY sr.overall_score DESC
		`, orgID).Scan(&ranked)
	}

	var buf bytes.Buffer
	buf.Write([]byte{0xEF, 0xBB, 0xBF})
	buf.WriteString("Rank,URL,Name,Institution,Score,Grade\n")

	for i, site := range ranked {
		grade := scoreToGrade(site.LatestScore)
		line := fmt.Sprintf("%d,%s,%s,%s,%.0f,%s\n",
			i+1,
			csvEscape(site.URL),
			csvEscape(site.Name),
			csvEscape(site.Institution),
			site.LatestScore,
			grade,
		)
		buf.WriteString(line)
	}

	c.Set("Content-Type", "text/csv; charset=utf-8")
	c.Set("Content-Disposition", "attachment; filename=\"vscan-leaderboard.csv\"")
	return c.Send(buf.Bytes())
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
