package api

import (
	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
)

var validTriage = map[string]bool{
	"": true, "open": true, "confirmed": true, "false_positive": true, "fixed": true, "accepted": true,
}

// UpdateCheckTriage sets the triage status/note on a single finding (CheckResult).
// Any authenticated user may triage findings within their own organization.
func UpdateCheckTriage(c *fiber.Ctx) error {
	var body struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid body"})
	}
	if !validTriage[body.Status] {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid triage status"})
	}

	var check models.CheckResult
	if err := config.DB.First(&check, c.Params("id")).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Finding not found"})
	}

	// Non-admins may only triage findings that belong to their organization.
	if role, _ := c.Locals("role").(string); role != "admin" {
		orgID := GetUserOrgID(c)
		var count int64
		config.DB.Table("scan_results").
			Joins("JOIN scan_targets ON scan_targets.id = scan_results.scan_target_id").
			Where("scan_results.id = ? AND scan_targets.organization_id = ?", check.ScanResultID, orgID).
			Count(&count)
		if count == 0 {
			return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
		}
	}

	config.DB.Model(&check).Updates(map[string]interface{}{
		"triage_status": body.Status,
		"triage_note":   body.Note,
	})
	return c.JSON(fiber.Map{"id": check.ID, "triage_status": body.Status, "triage_note": body.Note})
}
