package api

import (
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"vscan-mohesr/internal/config"
)

// ScopedDB returns a GORM DB instance scoped to the current organization
func ScopedDB(c *fiber.Ctx) *gorm.DB {
	orgID, ok := c.Locals("org_id").(uint)
	if !ok || orgID == 0 {
		return config.DB
	}
	return config.DB.Where("organization_id = ?", orgID)
}

// OrgID extracts current org ID from context
func OrgID(c *fiber.Ctx) uint {
	orgID, _ := c.Locals("org_id").(uint)
	return orgID
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
	return c.JSON(fiber.Map{"status": "healthy", "service": "vscan-mohesr"})
}
