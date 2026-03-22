package api

import (
	"github.com/gofiber/fiber/v2"

	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/models"
)

// Plan limits mapping
var planLimits = map[string]struct {
	MaxTargets int
	MaxScans   int
}{
	"free":       {MaxTargets: 5, MaxScans: 10},
	"basic":      {MaxTargets: 25, MaxScans: 50},
	"pro":        {MaxTargets: 100, MaxScans: 200},
	"enterprise": {MaxTargets: 9999, MaxScans: 9999},
}

type UpgradeRequestPayload struct {
	RequestedPlan string `json:"requested_plan"`
	ContactName   string `json:"contact_name"`
	ContactEmail  string `json:"contact_email"`
	ContactPhone  string `json:"contact_phone"`
	Message       string `json:"message"`
}

// RequestUpgrade - user submits an upgrade request
func RequestUpgrade(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)

	var req UpgradeRequestPayload
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate requested plan
	validPlans := map[string]bool{"basic": true, "pro": true, "enterprise": true}
	if !validPlans[req.RequestedPlan] {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid plan. Choose: basic, pro, or enterprise"})
	}

	if req.ContactName == "" || req.ContactEmail == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Contact name and email are required"})
	}

	// Get user's organization
	var membership models.OrgMembership
	if err := config.DB.Where("user_id = ?", userID).First(&membership).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "No organization found"})
	}

	// Check if there's already a pending request
	var pendingCount int64
	config.DB.Model(&models.UpgradeRequest{}).
		Where("organization_id = ? AND status = ?", membership.OrganizationID, "pending").
		Count(&pendingCount)
	if pendingCount > 0 {
		return c.Status(409).JSON(fiber.Map{"error": "You already have a pending upgrade request"})
	}

	upgradeReq := models.UpgradeRequest{
		OrganizationID: membership.OrganizationID,
		RequestedPlan:  req.RequestedPlan,
		ContactName:    req.ContactName,
		ContactEmail:   req.ContactEmail,
		ContactPhone:   req.ContactPhone,
		Message:        req.Message,
		Status:         "pending",
	}

	if err := config.DB.Create(&upgradeReq).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create upgrade request"})
	}

	return c.Status(201).JSON(upgradeReq)
}

// GetMyUpgradeRequests - user sees their requests
func GetMyUpgradeRequests(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)

	var membership models.OrgMembership
	if err := config.DB.Where("user_id = ?", userID).First(&membership).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "No organization found"})
	}

	var requests []models.UpgradeRequest
	config.DB.Where("organization_id = ?", membership.OrganizationID).
		Order("created_at desc").
		Find(&requests)

	return c.JSON(requests)
}

// GetAllUpgradeRequests - admin sees all requests
func GetAllUpgradeRequests(c *fiber.Ctx) error {
	var requests []models.UpgradeRequest
	config.DB.Preload("Organization").Order("created_at desc").Find(&requests)
	return c.JSON(requests)
}

// ApproveUpgrade - admin approves an upgrade request
func ApproveUpgrade(c *fiber.Ctx) error {
	id := c.Params("id")

	var req struct {
		AdminNotes string `json:"admin_notes"`
	}
	c.BodyParser(&req)

	var upgradeReq models.UpgradeRequest
	if err := config.DB.First(&upgradeReq, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Upgrade request not found"})
	}

	if upgradeReq.Status != "pending" {
		return c.Status(400).JSON(fiber.Map{"error": "This request has already been processed"})
	}

	// Get plan limits
	limits, ok := planLimits[upgradeReq.RequestedPlan]
	if !ok {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid plan in request"})
	}

	// Update Organization
	config.DB.Model(&models.Organization{}).
		Where("id = ?", upgradeReq.OrganizationID).
		Updates(map[string]interface{}{
			"plan":        upgradeReq.RequestedPlan,
			"max_targets": limits.MaxTargets,
			"max_scans":   limits.MaxScans,
		})

	// Update UpgradeRequest
	upgradeReq.Status = "approved"
	upgradeReq.AdminNotes = req.AdminNotes
	config.DB.Save(&upgradeReq)

	return c.JSON(fiber.Map{
		"message": "Upgrade approved successfully",
		"request": upgradeReq,
	})
}

// RejectUpgrade - admin rejects an upgrade request
func RejectUpgrade(c *fiber.Ctx) error {
	id := c.Params("id")

	var req struct {
		AdminNotes string `json:"admin_notes"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.AdminNotes == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Please provide a reason for rejection"})
	}

	var upgradeReq models.UpgradeRequest
	if err := config.DB.First(&upgradeReq, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Upgrade request not found"})
	}

	if upgradeReq.Status != "pending" {
		return c.Status(400).JSON(fiber.Map{"error": "This request has already been processed"})
	}

	upgradeReq.Status = "rejected"
	upgradeReq.AdminNotes = req.AdminNotes
	config.DB.Save(&upgradeReq)

	return c.JSON(fiber.Map{
		"message": "Upgrade request rejected",
		"request": upgradeReq,
	})
}
