package api

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
	"seku/internal/services"
	"seku/internal/utils"
)

// GetEmailConfig returns the current SMTP configuration (admin only).
// The password is masked for security.
func GetEmailConfig(c *fiber.Ctx) error {
	var cfg models.EmailConfig
	if err := config.DB.First(&cfg).Error; err != nil {
		// Return empty config if none exists
		return c.JSON(models.EmailConfig{})
	}

	// Mask password
	if cfg.SMTPPass != "" {
		cfg.SMTPPass = "********"
	}

	return c.JSON(cfg)
}

// UpdateEmailConfig creates or updates the SMTP configuration (admin only).
func UpdateEmailConfig(c *fiber.Ctx) error {
	var input models.EmailConfig
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	var existing models.EmailConfig
	err := config.DB.First(&existing).Error

	if err != nil {
		// Create new config — encrypt password
		if input.SMTPPass != "" {
			if enc, encErr := utils.Encrypt(input.SMTPPass); encErr == nil {
				input.SMTPPass = enc
			}
		}
		input.IsConfigured = input.SMTPHost != "" && input.SMTPUser != "" && input.FromEmail != ""
		config.DB.Create(&input)
		input.SMTPPass = "********"
		return c.JSON(input)
	}

	// Update existing
	existing.SMTPHost = input.SMTPHost
	existing.SMTPPort = input.SMTPPort
	existing.SMTPUser = input.SMTPUser
	if input.SMTPPass != "" && input.SMTPPass != "********" {
		encrypted, err := utils.Encrypt(input.SMTPPass)
		if err == nil {
			existing.SMTPPass = encrypted
		} else {
			existing.SMTPPass = input.SMTPPass
		}
	}
	existing.FromEmail = input.FromEmail
	existing.FromName = input.FromName
	existing.IsConfigured = existing.SMTPHost != "" && existing.SMTPUser != "" && existing.FromEmail != ""

	config.DB.Save(&existing)

	// Mask password in response
	existing.SMTPPass = "********"
	return c.JSON(existing)
}

// TestEmailConfig sends a test email using the current SMTP configuration (admin only).
func TestEmailConfig(c *fiber.Ctx) error {
	var body struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&body); err != nil || body.Email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Email address is required"})
	}

	var cfg models.EmailConfig
	if err := config.DB.First(&cfg).Error; err != nil || !cfg.IsConfigured {
		return c.Status(400).JSON(fiber.Map{"error": "Email is not configured. Save SMTP settings first."})
	}

	if err := services.SendTestEmail(cfg, body.Email); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to send test email: " + err.Error()})
	}

	return c.JSON(fiber.Map{"message": "Test email sent successfully"})
}

// GetMyAlerts returns the current user's email alert preferences.
func GetMyAlerts(c *fiber.Ctx) error {
	userID, _ := c.Locals("user_id").(uint)
	orgID := GetUserOrgID(c)

	var alert models.EmailAlert
	err := config.DB.Where("user_id = ? AND organization_id = ?", userID, orgID).First(&alert).Error
	if err != nil {
		// Return defaults
		return c.JSON(models.EmailAlert{
			UserID:          userID,
			OrganizationID:  orgID,
			Events:          "scan_completed,score_drop",
			MinSeverity:     "all",
			IsActive:        false,
			DigestFrequency: "immediate",
		})
	}
	return c.JSON(alert)
}

// UpdateMyAlerts creates or updates the current user's email alert preferences.
func UpdateMyAlerts(c *fiber.Ctx) error {
	userID, _ := c.Locals("user_id").(uint)
	orgID := GetUserOrgID(c)

	var input struct {
		Email           string `json:"email"`
		Events          string `json:"events"`
		MinSeverity     string `json:"min_severity"`
		IsActive        bool   `json:"is_active"`
		DigestFrequency string `json:"digest_frequency"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if input.IsActive && input.Email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Email is required when alerts are active"})
	}

	// Validate events
	validEvents := map[string]bool{
		"scan_completed": true,
		"score_drop":     true,
		"critical_found": true,
	}
	if input.Events != "" {
		for _, e := range strings.Split(input.Events, ",") {
			if !validEvents[strings.TrimSpace(e)] {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid event: " + strings.TrimSpace(e)})
			}
		}
	}

	var alert models.EmailAlert
	err := config.DB.Where("user_id = ? AND organization_id = ?", userID, orgID).First(&alert).Error

	if err != nil {
		// Create new
		alert = models.EmailAlert{
			UserID:          userID,
			OrganizationID:  orgID,
			Email:           input.Email,
			Events:          input.Events,
			MinSeverity:     input.MinSeverity,
			IsActive:        input.IsActive,
			DigestFrequency: input.DigestFrequency,
		}
		config.DB.Create(&alert)
	} else {
		// Update existing
		alert.Email = input.Email
		alert.Events = input.Events
		alert.MinSeverity = input.MinSeverity
		alert.IsActive = input.IsActive
		alert.DigestFrequency = input.DigestFrequency
		config.DB.Save(&alert)
	}

	return c.JSON(alert)
}
