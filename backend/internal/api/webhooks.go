package api

import (
	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
	"seku/internal/services"
)

// GetWebhooks lists all webhooks for the user's organization.
func GetWebhooks(c *fiber.Ctx) error {
	var webhooks []models.Webhook
	ScopedDB(c).Order("created_at desc").Find(&webhooks)
	return c.JSON(webhooks)
}

// CreateWebhook creates a new webhook for the user's organization.
func CreateWebhook(c *fiber.Ctx) error {
	var req struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		URL         string `json:"url"`
		Secret      string `json:"secret"`
		Events      string `json:"events"`
		MinSeverity string `json:"min_severity"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.Name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Name is required"})
	}
	if req.Type == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Type is required"})
	}
	validTypes := map[string]bool{"slack": true, "telegram": true, "discord": true, "custom": true}
	if !validTypes[req.Type] {
		return c.Status(400).JSON(fiber.Map{"error": "Type must be slack, telegram, discord, or custom"})
	}
	if req.URL == "" {
		return c.Status(400).JSON(fiber.Map{"error": "URL is required"})
	}

	if req.Events == "" {
		req.Events = "scan_completed"
	}
	if req.MinSeverity == "" {
		req.MinSeverity = "all"
	}

	webhook := models.Webhook{
		OrganizationID: GetUserOrgID(c),
		Name:           req.Name,
		Type:           req.Type,
		URL:            req.URL,
		Secret:         req.Secret,
		Events:         req.Events,
		MinSeverity:    req.MinSeverity,
		IsActive:       true,
	}
	config.DB.Create(&webhook)
	return c.Status(201).JSON(webhook)
}

// UpdateWebhook updates an existing webhook.
func UpdateWebhook(c *fiber.Ctx) error {
	id := c.Params("id")
	var webhook models.Webhook
	if err := ScopedDB(c).First(&webhook, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Webhook not found"})
	}

	var req struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		URL         string `json:"url"`
		Secret      string `json:"secret"`
		Events      string `json:"events"`
		MinSeverity string `json:"min_severity"`
		IsActive    *bool  `json:"is_active"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.Name != "" {
		webhook.Name = req.Name
	}
	if req.Type != "" {
		validTypes := map[string]bool{"slack": true, "telegram": true, "discord": true, "custom": true}
		if !validTypes[req.Type] {
			return c.Status(400).JSON(fiber.Map{"error": "Type must be slack, telegram, discord, or custom"})
		}
		webhook.Type = req.Type
	}
	if req.URL != "" {
		webhook.URL = req.URL
	}
	if req.Secret != "" {
		webhook.Secret = req.Secret
	}
	if req.Events != "" {
		webhook.Events = req.Events
	}
	if req.MinSeverity != "" {
		webhook.MinSeverity = req.MinSeverity
	}
	if req.IsActive != nil {
		webhook.IsActive = *req.IsActive
	}

	config.DB.Save(&webhook)
	return c.JSON(webhook)
}

// DeleteWebhook removes a webhook.
func DeleteWebhook(c *fiber.Ctx) error {
	id := c.Params("id")
	var webhook models.Webhook
	if err := ScopedDB(c).First(&webhook, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Webhook not found"})
	}
	config.DB.Delete(&webhook)
	return c.JSON(fiber.Map{"message": "Webhook deleted"})
}

// TestWebhook sends a test notification to a webhook.
func TestWebhook(c *fiber.Ctx) error {
	id := c.Params("id")
	var webhook models.Webhook
	if err := ScopedDB(c).First(&webhook, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Webhook not found"})
	}

	if err := services.SendTestWebhook(webhook); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to send test webhook"})
	}

	return c.JSON(fiber.Map{"message": "Test notification sent"})
}
