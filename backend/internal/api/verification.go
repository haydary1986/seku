package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"seku/internal/config"
	"seku/internal/models"
)

// GenerateVerificationKey generates a random hex key for domain verification
func GenerateVerificationKey() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// InitiateVerification creates a DomainVerification record with a random key
// POST /targets/:id/verify
func InitiateVerification(c *fiber.Ctx) error {
	targetID := c.Params("id")
	orgID := GetUserOrgID(c)

	// Find the target
	var target models.ScanTarget
	if err := ScopedDB(c).First(&target, targetID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Target not found"})
	}

	// Check if verification already exists for this target
	var existing models.DomainVerification
	if err := config.DB.Where("scan_target_id = ? AND organization_id = ?", target.ID, orgID).First(&existing).Error; err == nil {
		// Already exists, return existing record
		return c.JSON(fiber.Map{
			"verification":  existing,
			"txt_record":    fmt.Sprintf("vscan-verify=%s", existing.VerificationKey),
			"domain":        existing.Domain,
			"instructions": []string{
				fmt.Sprintf("1. Log in to your DNS provider for %s", existing.Domain),
				"2. Add a new TXT record",
				fmt.Sprintf("3. Set the value to: vscan-verify=%s", existing.VerificationKey),
				"4. Wait for DNS propagation (may take up to 24 hours)",
				"5. Click 'Verify' to check the TXT record",
			},
		})
	}

	// Extract domain from URL
	domain := extractDomain(target.URL)

	// Generate verification key
	key := GenerateVerificationKey()

	verification := models.DomainVerification{
		OrganizationID:  orgID,
		ScanTargetID:    target.ID,
		Domain:          domain,
		VerificationKey: key,
		IsVerified:      false,
	}
	config.DB.Create(&verification)

	return c.Status(201).JSON(fiber.Map{
		"verification":  verification,
		"txt_record":    fmt.Sprintf("vscan-verify=%s", key),
		"domain":        domain,
		"instructions": []string{
			fmt.Sprintf("1. Log in to your DNS provider for %s", domain),
			"2. Add a new TXT record",
			fmt.Sprintf("3. Set the value to: vscan-verify=%s", key),
			"4. Wait for DNS propagation (may take up to 24 hours)",
			"5. Click 'Verify' to check the TXT record",
		},
	})
}

// GetVerificationStatus returns verification status and the TXT record value to add
// GET /targets/:id/verify
func GetVerificationStatus(c *fiber.Ctx) error {
	targetID := c.Params("id")
	orgID := GetUserOrgID(c)

	var verification models.DomainVerification
	if err := config.DB.Where("scan_target_id = ? AND organization_id = ?", targetID, orgID).First(&verification).Error; err != nil {
		return c.JSON(fiber.Map{
			"verified":    false,
			"initiated":   false,
			"message":     "Verification not initiated. Send POST to initiate.",
		})
	}

	return c.JSON(fiber.Map{
		"verified":    verification.IsVerified,
		"initiated":   true,
		"verification": verification,
		"txt_record":  fmt.Sprintf("vscan-verify=%s", verification.VerificationKey),
		"domain":      verification.Domain,
	})
}

// CheckVerification does DNS TXT lookup for the domain and marks as verified if key found
// PUT /targets/:id/verify
func CheckVerification(c *fiber.Ctx) error {
	targetID := c.Params("id")
	orgID := GetUserOrgID(c)

	var verification models.DomainVerification
	if err := config.DB.Where("scan_target_id = ? AND organization_id = ?", targetID, orgID).First(&verification).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Verification not initiated. Send POST first."})
	}

	if verification.IsVerified {
		return c.JSON(fiber.Map{
			"verified": true,
			"message":  "Domain already verified",
		})
	}

	// Perform DNS TXT lookup
	expectedValue := fmt.Sprintf("vscan-verify=%s", verification.VerificationKey)
	txtRecords, err := net.LookupTXT(verification.Domain)
	if err != nil {
		return c.JSON(fiber.Map{
			"verified": false,
			"message":  fmt.Sprintf("DNS lookup failed: %v. Please ensure the TXT record is added and DNS has propagated.", err),
		})
	}

	// Check if any TXT record contains the verification key
	found := false
	for _, record := range txtRecords {
		if strings.Contains(record, expectedValue) {
			found = true
			break
		}
	}

	if !found {
		return c.JSON(fiber.Map{
			"verified":       false,
			"message":        "TXT record not found. Please ensure you added the correct record and wait for DNS propagation.",
			"expected_value": expectedValue,
			"found_records":  txtRecords,
		})
	}

	// Mark as verified
	now := time.Now()
	verification.IsVerified = true
	verification.VerifiedAt = &now
	config.DB.Save(&verification)

	return c.JSON(fiber.Map{
		"verified":    true,
		"message":     "Domain verified successfully!",
		"verified_at": now,
	})
}

// extractDomain extracts the domain from a URL string
func extractDomain(url string) string {
	domain := url
	// Remove protocol
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	// Remove path
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	// Remove port
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}
