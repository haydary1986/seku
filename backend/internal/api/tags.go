package api

import (
	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
)

// GetTags lists all tags for the user's organization
func GetTags(c *fiber.Ctx) error {
	orgID := GetUserOrgID(c)
	var tags []models.ScanTag
	config.DB.Where("organization_id = ?", orgID).Order("name asc").Find(&tags)
	return c.JSON(tags)
}

// CreateTag creates a new tag for the organization
func CreateTag(c *fiber.Ctx) error {
	var tag models.ScanTag
	if err := c.BodyParser(&tag); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if tag.Name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Tag name is required"})
	}
	tag.OrganizationID = GetUserOrgID(c)

	// Check for duplicate name within org
	var existing models.ScanTag
	if err := config.DB.Where("organization_id = ? AND name = ?", tag.OrganizationID, tag.Name).First(&existing).Error; err == nil {
		return c.Status(409).JSON(fiber.Map{"error": "Tag with this name already exists"})
	}

	config.DB.Create(&tag)
	return c.Status(201).JSON(tag)
}

// DeleteTag removes a tag and all its associations
func DeleteTag(c *fiber.Ctx) error {
	id := c.Params("id")
	orgID := GetUserOrgID(c)

	var tag models.ScanTag
	if err := config.DB.Where("id = ? AND organization_id = ?", id, orgID).First(&tag).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Tag not found"})
	}

	// Remove all target-tag associations
	config.DB.Where("scan_tag_id = ?", tag.ID).Delete(&models.TargetTag{})
	config.DB.Delete(&tag)

	return c.JSON(fiber.Map{"message": "Tag deleted"})
}

// TagTarget assigns a tag to a target
func TagTarget(c *fiber.Ctx) error {
	var req struct {
		TargetID uint `json:"target_id"`
		TagID    uint `json:"tag_id"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.TargetID == 0 || req.TagID == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "target_id and tag_id are required"})
	}

	orgID := GetUserOrgID(c)

	// Verify target belongs to org
	var target models.ScanTarget
	if err := config.DB.Where("id = ? AND organization_id = ?", req.TargetID, orgID).First(&target).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Target not found"})
	}

	// Verify tag belongs to org
	var tag models.ScanTag
	if err := config.DB.Where("id = ? AND organization_id = ?", req.TagID, orgID).First(&tag).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Tag not found"})
	}

	// Check if already assigned
	var existing models.TargetTag
	if err := config.DB.Where("scan_target_id = ? AND scan_tag_id = ?", req.TargetID, req.TagID).First(&existing).Error; err == nil {
		return c.Status(409).JSON(fiber.Map{"error": "Tag already assigned to this target"})
	}

	tt := models.TargetTag{
		ScanTargetID: req.TargetID,
		ScanTagID:    req.TagID,
	}
	config.DB.Create(&tt)

	// Return with tag info
	config.DB.Preload("ScanTag").First(&tt, tt.ID)
	return c.Status(201).JSON(tt)
}

// UntagTarget removes a tag from a target
func UntagTarget(c *fiber.Ctx) error {
	targetID := c.Params("target_id")
	tagID := c.Params("tag_id")

	var tt models.TargetTag
	if err := config.DB.Where("scan_target_id = ? AND scan_tag_id = ?", targetID, tagID).First(&tt).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Tag assignment not found"})
	}

	config.DB.Delete(&tt)
	return c.JSON(fiber.Map{"message": "Tag removed from target"})
}

// GetTargetsByTag lists all targets with a specific tag
func GetTargetsByTag(c *fiber.Ctx) error {
	tagID := c.Params("id")
	orgID := GetUserOrgID(c)

	// Verify tag belongs to org
	var tag models.ScanTag
	if err := config.DB.Where("id = ? AND organization_id = ?", tagID, orgID).First(&tag).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Tag not found"})
	}

	var targetTags []models.TargetTag
	config.DB.Where("scan_tag_id = ?", tagID).Preload("ScanTag").Find(&targetTags)

	var targetIDs []uint
	for _, tt := range targetTags {
		targetIDs = append(targetIDs, tt.ScanTargetID)
	}

	var targets []models.ScanTarget
	if len(targetIDs) > 0 {
		config.DB.Where("id IN ? AND organization_id = ?", targetIDs, orgID).Find(&targets)
	}

	return c.JSON(fiber.Map{
		"tag":     tag,
		"targets": targets,
	})
}

// GetTargetTags returns all tags for a specific target
func GetTargetTags(c *fiber.Ctx) error {
	targetID := c.Params("id")

	var targetTags []models.TargetTag
	config.DB.Where("scan_target_id = ?", targetID).Preload("ScanTag").Find(&targetTags)

	var tags []models.ScanTag
	for _, tt := range targetTags {
		tags = append(tags, tt.ScanTag)
	}

	return c.JSON(tags)
}
