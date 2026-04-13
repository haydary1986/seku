package api

import (
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"seku/internal/config"
	"seku/internal/models"
)

// GetUserOrgID looks up the organization ID for the authenticated user
func GetUserOrgID(c *fiber.Ctx) uint {
	userID, ok := c.Locals("user_id").(uint)
	if !ok || userID == 0 {
		return 0
	}

	var membership models.OrgMembership
	if err := config.DB.Where("user_id = ?", userID).First(&membership).Error; err != nil {
		return 0
	}
	return membership.OrganizationID
}

// GetUserOrg returns the full organization for the authenticated user
func GetUserOrg(c *fiber.Ctx) *models.Organization {
	orgID := GetUserOrgID(c)
	if orgID == 0 {
		return nil
	}
	var org models.Organization
	if err := config.DB.First(&org, orgID).Error; err != nil {
		return nil
	}
	return &org
}

// ScopedDB returns a GORM DB instance scoped to the current user's organization
// System admins (role=admin) see all data
func ScopedDB(c *fiber.Ctx) *gorm.DB {
	role, _ := c.Locals("role").(string)
	if role == "admin" {
		return config.DB
	}
	orgID := GetUserOrgID(c)
	if orgID == 0 {
		return config.DB.Where("1 = 0") // return empty - no org found
	}
	return config.DB.Where("organization_id = ?", orgID)
}

// OrgID extracts current org ID from context
func OrgID(c *fiber.Ctx) uint {
	return GetUserOrgID(c)
}

// UserID extracts current user ID from context
func UserID(c *fiber.Ctx) uint {
	userID, _ := c.Locals("user_id").(uint)
	return userID
}

// LogAction creates an audit log entry
func LogAction(c *fiber.Ctx, action, resourceType string, resourceID uint, details string) {
	log := struct {
		OrganizationID uint
		UserID         uint
		Action         string
		ResourceType   string
		ResourceID     uint
		Details        string
		IPAddress      string
		UserAgent      string
	}{
		OrganizationID: OrgID(c),
		UserID:         UserID(c),
		Action:         action,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		Details:        details,
		IPAddress:      c.IP(),
		UserAgent:      c.Get("User-Agent"),
	}
	config.DB.Table("audit_logs").Create(&log)
}

// HealthCheck returns server status
func HealthCheck(c *fiber.Ctx) error {
	sqlDB, err := config.DB.DB()
	if err != nil {
		return c.Status(503).JSON(fiber.Map{"status": "unhealthy", "error": "database unavailable"})
	}
	if err := sqlDB.Ping(); err != nil {
		return c.Status(503).JSON(fiber.Map{"status": "unhealthy", "error": "database unreachable"})
	}
	return c.JSON(fiber.Map{"status": "healthy", "service": "seku"})
}
