package api

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"

	"seku/internal/config"
	"seku/internal/models"
)

// GenerateAPIKey creates a new API key for the user
// POST /api-keys
func GenerateAPIKey(c *fiber.Ctx) error {
	userID := UserID(c)
	orgID := GetUserOrgID(c)

	// Check plan allows API access (pro or enterprise)
	org := GetUserOrg(c)
	if org == nil {
		return c.Status(404).JSON(fiber.Map{"error": "Organization not found"})
	}
	if org.Plan != "pro" && org.Plan != "enterprise" {
		return c.Status(403).JSON(fiber.Map{
			"error": "API key access requires a Pro or Enterprise plan. Please upgrade.",
			"plan":  org.Plan,
		})
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&req); err != nil {
		req.Name = "API Key"
	}
	if req.Name == "" {
		req.Name = "API Key"
	}

	// Generate random key: vsk_ + 32 hex chars
	randomBytes := make([]byte, 16)
	_, _ = rand.Read(randomBytes)
	plainKey := "vsk_" + hex.EncodeToString(randomBytes)

	// Hash the key with bcrypt
	keyHash, err := bcrypt.GenerateFromPassword([]byte(plainKey), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate API key"})
	}

	// Store with prefix (first 12 chars) for lookup
	prefix := plainKey[:12]

	apiKey := models.APIKey{
		OrganizationID: orgID,
		UserID:         userID,
		Name:           req.Name,
		KeyPrefix:      prefix,
		KeyHash:        string(keyHash),
	}
	config.DB.Create(&apiKey)

	return c.Status(201).JSON(fiber.Map{
		"id":      apiKey.ID,
		"name":    apiKey.Name,
		"key":     plainKey,
		"prefix":  prefix,
		"message": "Save this key now. You won't be able to see it again!",
	})
}

// ListAPIKeys returns the user's API keys (prefix only)
// GET /api-keys
func ListAPIKeys(c *fiber.Ctx) error {
	userID := UserID(c)

	var keys []models.APIKey
	config.DB.Where("user_id = ?", userID).Order("created_at desc").Find(&keys)

	// Return only safe fields (no hash)
	var result []fiber.Map
	for _, key := range keys {
		result = append(result, fiber.Map{
			"id":           key.ID,
			"name":         key.Name,
			"key_prefix":   key.KeyPrefix + "...",
			"created_at":   key.CreatedAt,
			"last_used_at": key.LastUsedAt,
			"expires_at":   key.ExpiresAt,
		})
	}

	return c.JSON(result)
}

// RevokeAPIKey deletes an API key
// DELETE /api-keys/:id
func RevokeAPIKey(c *fiber.Ctx) error {
	keyID := c.Params("id")
	userID := UserID(c)

	var key models.APIKey
	if err := config.DB.Where("id = ? AND user_id = ?", keyID, userID).First(&key).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "API key not found"})
	}

	config.DB.Delete(&key)
	return c.JSON(fiber.Map{"message": "API key revoked successfully"})
}

// AuthenticateAPIKey attempts to authenticate a request using an API key
// Returns the user ID if successful, 0 otherwise
func AuthenticateAPIKey(apiKeyHeader string) uint {
	if len(apiKeyHeader) < 12 {
		return 0
	}

	prefix := apiKeyHeader[:12]

	// Find all keys matching the prefix
	var keys []models.APIKey
	config.DB.Where("key_prefix = ?", prefix).Find(&keys)

	for _, key := range keys {
		// Check if expired
		if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
			continue
		}

		// Compare the full key against the hash
		if err := bcrypt.CompareHashAndPassword([]byte(key.KeyHash), []byte(apiKeyHeader)); err == nil {
			// Update last used
			now := time.Now()
			config.DB.Model(&key).Update("last_used_at", &now)
			return key.UserID
		}
	}

	return 0
}
