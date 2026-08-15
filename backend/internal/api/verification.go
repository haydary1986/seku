package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"seku/internal/config"
	"seku/internal/models"
)

// verifyFilePath is the well-known path users upload to prove domain ownership.
const verifyFilePath = "/.well-known/seku-verify.txt"

// GenerateVerificationKey generates a random hex key for domain verification
func GenerateVerificationKey() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// verificationPayload builds the response describing BOTH verification methods
// (DNS TXT record and uploaded file) so the UI can offer either.
func verificationPayload(v models.DomainVerification) fiber.Map {
	expected := fmt.Sprintf("vscan-verify=%s", v.VerificationKey)
	return fiber.Map{
		"verification": v,
		"domain":       v.Domain,
		"verified":     v.IsVerified,
		"method":       v.Method,
		// Method 1 — DNS TXT record
		"txt_record": expected,
		"txt_instructions": []string{
			fmt.Sprintf("1. سجّل الدخول إلى مزوّد DNS الخاص بـ %s", v.Domain),
			"2. أضف سجل TXT جديد على النطاق الجذر (@)",
			fmt.Sprintf("3. اجعل القيمة: %s", expected),
			"4. انتظر انتشار DNS (قد يصل إلى 24 ساعة)",
			"5. اضغط \"تحقّق\"",
		},
		// Method 2 — uploaded file (works even without DNS access)
		"file_path":    verifyFilePath,
		"file_url":     fmt.Sprintf("https://%s%s", v.Domain, verifyFilePath),
		"file_content": expected,
		"file_instructions": []string{
			fmt.Sprintf("1. أنشئ ملفاً باسم seku-verify.txt محتواه: %s", expected),
			fmt.Sprintf("2. ارفعه على موقعك في المسار: %s", verifyFilePath),
			fmt.Sprintf("3. تأكد أنه يفتح على: https://%s%s", v.Domain, verifyFilePath),
			"4. اضغط \"تحقّق\"",
		},
	}
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
		return c.JSON(verificationPayload(existing))
	}

	verification := models.DomainVerification{
		OrganizationID:  orgID,
		ScanTargetID:    target.ID,
		Domain:          extractDomain(target.URL),
		VerificationKey: GenerateVerificationKey(),
		IsVerified:      false,
	}
	config.DB.Create(&verification)

	return c.Status(201).JSON(verificationPayload(verification))
}

// GetVerificationStatus returns verification status and instructions for both methods
// GET /targets/:id/verify
func GetVerificationStatus(c *fiber.Ctx) error {
	targetID := c.Params("id")
	orgID := GetUserOrgID(c)

	var verification models.DomainVerification
	if err := config.DB.Where("scan_target_id = ? AND organization_id = ?", targetID, orgID).First(&verification).Error; err != nil {
		return c.JSON(fiber.Map{
			"verified":  false,
			"initiated": false,
			"message":   "Verification not initiated. Send POST to initiate.",
		})
	}

	payload := verificationPayload(verification)
	payload["initiated"] = true
	return c.JSON(payload)
}

// CheckVerification tries DNS TXT lookup then the uploaded file, marking the
// domain verified as soon as either method proves ownership.
// PUT /targets/:id/verify
func CheckVerification(c *fiber.Ctx) error {
	targetID := c.Params("id")
	orgID := GetUserOrgID(c)

	var verification models.DomainVerification
	if err := config.DB.Where("scan_target_id = ? AND organization_id = ?", targetID, orgID).First(&verification).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Verification not initiated. Send POST first."})
	}

	if verification.IsVerified {
		return c.JSON(fiber.Map{"verified": true, "message": "Domain already verified"})
	}

	expectedValue := fmt.Sprintf("vscan-verify=%s", verification.VerificationKey)

	// --- Method 1: DNS TXT record ---
	var txtRecords []string
	if recs, err := net.LookupTXT(verification.Domain); err == nil {
		txtRecords = recs
		for _, record := range recs {
			if strings.Contains(record, expectedValue) {
				return markVerified(c, &verification, "dns_txt")
			}
		}
	}

	// --- Method 2: uploaded file at /.well-known/seku-verify.txt ---
	if checkFileVerification(verification.Domain, verification.VerificationKey) {
		return markVerified(c, &verification, "file")
	}

	return c.JSON(fiber.Map{
		"verified":       false,
		"message":        "لم نجد الإثبات بعد. تأكّد من إضافة سجل TXT (وانتظر انتشار DNS) أو رفع الملف على المسار الصحيح، ثم أعد المحاولة.",
		"expected_value": expectedValue,
		"file_url":       fmt.Sprintf("https://%s%s", verification.Domain, verifyFilePath),
		"found_records":  txtRecords,
	})
}

// markVerified persists the verified state and records which method proved it.
func markVerified(c *fiber.Ctx, v *models.DomainVerification, method string) error {
	now := time.Now()
	v.IsVerified = true
	v.Method = method
	v.VerifiedAt = &now
	config.DB.Save(v)
	return c.JSON(fiber.Map{
		"verified":    true,
		"method":      method,
		"message":     "تم التحقق من ملكية النطاق بنجاح!",
		"verified_at": now,
	})
}

// checkFileVerification fetches the well-known file over HTTPS (then HTTP) and
// reports whether it contains the expected verification key.
func checkFileVerification(domain, key string) bool {
	expected := fmt.Sprintf("vscan-verify=%s", key)
	client := &http.Client{Timeout: 8 * time.Second}
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s%s", scheme, domain, verifyFilePath)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Seku-DomainVerification/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			content := strings.TrimSpace(string(body))
			if strings.Contains(content, expected) || strings.Contains(content, key) {
				return true
			}
		}
	}
	return false
}

// extractDomain extracts the domain from a URL string
func extractDomain(url string) string {
	domain := url
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}
