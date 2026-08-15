package api

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"seku/internal/config"
	"seku/internal/models"
)

// defaultDeepScanPriceIQD is used when the admin hasn't set a price yet.
const defaultDeepScanPriceIQD = 25000

// getDeepScanPrice reads the admin-configured deep-scan price (IQD).
func getDeepScanPrice() int {
	if v := getSetting("deep_scan_price_iqd"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultDeepScanPriceIQD
}

// GetPublicPricing exposes ONLY the deep-scan price (no account/instructions)
// for the public marketing/pricing page.
// GET /pricing
func GetPublicPricing(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"deep_scan_price_iqd": getDeepScanPrice(), "currency": "IQD"})
}

// GetPaymentInfo returns the deep-scan price and manual-transfer instructions.
// These are admin-configurable (Settings) so no payment details live in code.
// GET /payment-info
func GetPaymentInfo(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"deep_scan_price_iqd":     getDeepScanPrice(),
		"currency":                "IQD",
		"payment_instructions_ar": getSetting("payment_instructions_ar"),
		"payment_instructions_en": getSetting("payment_instructions_en"),
		"payment_account":         getSetting("payment_account"),
		"payment_method":          getSetting("payment_method"),
	})
}

// CreateDeepScanOrder opens a pending pay-per-scan order for one verified target.
// POST /orders  body: {target_id, contact_name, contact_phone}
func CreateDeepScanOrder(c *fiber.Ctx) error {
	var req struct {
		TargetID     uint   `json:"target_id"`
		ContactName  string `json:"contact_name"`
		ContactPhone string `json:"contact_phone"`
	}
	if err := c.BodyParser(&req); err != nil || req.TargetID == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "target_id is required"})
	}

	orgID := GetUserOrgID(c)
	userID, _ := c.Locals("user_id").(uint)

	// Target must belong to the caller's org.
	var target models.ScanTarget
	if err := ScopedDB(c).First(&target, req.TargetID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Target not found"})
	}

	// Domain ownership must be verified before buying a scan.
	var verification models.DomainVerification
	if err := config.DB.Where("scan_target_id = ? AND is_verified = ?", target.ID, true).First(&verification).Error; err != nil {
		return c.Status(403).JSON(fiber.Map{"error": "verify_domain_first", "message": "يجب التحقق من ملكية النطاق قبل شراء فحص عميق."})
	}

	// Reuse an existing unpaid credit for this target instead of stacking duplicates.
	var open models.DeepScanOrder
	if err := config.DB.Where("scan_target_id = ? AND organization_id = ? AND status IN ?", target.ID, orgID, []string{"pending", "paid"}).First(&open).Error; err == nil {
		return c.Status(409).JSON(fiber.Map{"error": "order_exists", "message": "يوجد طلب فحص عميق قائم لهذا النطاق.", "order": open})
	}

	order := models.DeepScanOrder{
		OrganizationID: orgID,
		UserID:         userID,
		ScanTargetID:   target.ID,
		Domain:         verification.Domain,
		AmountIQD:      getDeepScanPrice(),
		Status:         "pending",
		ContactName:    req.ContactName,
		ContactPhone:   req.ContactPhone,
	}
	config.DB.Create(&order)

	return c.Status(201).JSON(fiber.Map{
		"order":        order,
		"payment_info": paymentInfoMap(),
	})
}

// SubmitPayment lets the user attach the transfer reference after paying.
// PUT /orders/:id/payment  body: {payment_ref}
func SubmitPayment(c *fiber.Ctx) error {
	var req struct {
		PaymentRef string `json:"payment_ref"`
	}
	if err := c.BodyParser(&req); err != nil || req.PaymentRef == "" {
		return c.Status(400).JSON(fiber.Map{"error": "payment_ref is required"})
	}

	orgID := GetUserOrgID(c)
	var order models.DeepScanOrder
	if err := config.DB.Where("id = ? AND organization_id = ?", c.Params("id"), orgID).First(&order).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Order not found"})
	}
	if order.Status != "pending" {
		return c.Status(400).JSON(fiber.Map{"error": "This order can no longer be updated"})
	}

	order.PaymentRef = req.PaymentRef
	config.DB.Save(&order)
	return c.JSON(order)
}

// GetMyOrders lists the caller's deep-scan orders.
// GET /orders
func GetMyOrders(c *fiber.Ctx) error {
	orgID := GetUserOrgID(c)
	var orders []models.DeepScanOrder
	config.DB.Where("organization_id = ?", orgID).Order("created_at DESC").Find(&orders)
	return c.JSON(orders)
}

// --- Admin ---

// ListAllOrders returns every deep-scan order for admin review.
// GET /orders/all
func ListAllOrders(c *fiber.Ctx) error {
	var orders []models.DeepScanOrder
	q := config.DB.Preload("Organization").Order("created_at DESC")
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	}
	q.Find(&orders)
	return c.JSON(orders)
}

// MarkOrderPaid confirms an internal transfer was received, granting one credit.
// PUT /orders/:id/approve  body: {admin_notes}
func MarkOrderPaid(c *fiber.Ctx) error {
	var req struct {
		AdminNotes string `json:"admin_notes"`
	}
	_ = c.BodyParser(&req)

	var order models.DeepScanOrder
	if err := config.DB.First(&order, c.Params("id")).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Order not found"})
	}
	if order.Status != "pending" {
		return c.Status(400).JSON(fiber.Map{"error": "This order has already been processed"})
	}

	adminID, _ := c.Locals("user_id").(uint)
	now := time.Now()
	order.Status = "paid"
	order.AdminNotes = req.AdminNotes
	order.ApprovedBy = adminID
	order.ApprovedAt = &now
	config.DB.Save(&order)
	return c.JSON(order)
}

// RejectOrder declines an order (e.g. transfer not found).
// PUT /orders/:id/reject  body: {admin_notes}
func RejectOrder(c *fiber.Ctx) error {
	var req struct {
		AdminNotes string `json:"admin_notes"`
	}
	if err := c.BodyParser(&req); err != nil || req.AdminNotes == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Please provide a reason"})
	}

	var order models.DeepScanOrder
	if err := config.DB.First(&order, c.Params("id")).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Order not found"})
	}
	if order.Status != "pending" {
		return c.Status(400).JSON(fiber.Map{"error": "This order has already been processed"})
	}

	order.Status = "rejected"
	order.AdminNotes = req.AdminNotes
	config.DB.Save(&order)
	return c.JSON(order)
}

// paymentInfoMap is the shared payment-info shape used by several handlers.
func paymentInfoMap() fiber.Map {
	return fiber.Map{
		"deep_scan_price_iqd":     getDeepScanPrice(),
		"currency":                "IQD",
		"payment_instructions_ar": getSetting("payment_instructions_ar"),
		"payment_instructions_en": getSetting("payment_instructions_en"),
		"payment_account":         getSetting("payment_account"),
		"payment_method":          getSetting("payment_method"),
	}
}

// hasPaidDeepScanCredit reports whether the org holds an unused paid credit for a target.
func hasPaidDeepScanCredit(orgID, targetID uint) bool {
	var count int64
	config.DB.Model(&models.DeepScanOrder{}).
		Where("organization_id = ? AND scan_target_id = ? AND status = ?", orgID, targetID, "paid").
		Count(&count)
	return count > 0
}

// consumeDeepScanCredit marks one paid credit for the target as used by a scan job.
func consumeDeepScanCredit(orgID, targetID, scanJobID uint) bool {
	var order models.DeepScanOrder
	if err := config.DB.Where("organization_id = ? AND scan_target_id = ? AND status = ?", orgID, targetID, "paid").
		Order("created_at ASC").First(&order).Error; err != nil {
		return false
	}
	now := time.Now()
	order.Status = "used"
	order.UsedByScanJob = scanJobID
	order.UsedAt = &now
	config.DB.Save(&order)
	return true
}
