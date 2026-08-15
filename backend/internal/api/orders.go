package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"seku/internal/config"
	"seku/internal/models"
	"seku/internal/services"
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
	go notifyOrderCreated(order)

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
	go notifyPaymentSubmitted(order)
	return c.JSON(order)
}

// UploadPaymentProof attaches a transfer screenshot/receipt to a pending order.
// POST /orders/:id/proof  (multipart form field "proof")
func UploadPaymentProof(c *fiber.Ctx) error {
	orgID := GetUserOrgID(c)
	var order models.DeepScanOrder
	if err := config.DB.Where("id = ? AND organization_id = ?", c.Params("id"), orgID).First(&order).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Order not found"})
	}
	if order.Status != "pending" {
		return c.Status(400).JSON(fiber.Map{"error": "This order can no longer be updated"})
	}
	file, err := c.FormFile("proof")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "No file provided"})
	}
	if file.Size > 5*1024*1024 {
		return c.Status(400).JSON(fiber.Map{"error": "File too large (max 5MB)"})
	}
	name := strings.ToLower(file.Filename)
	ext := ""
	for _, e := range []string{".png", ".jpg", ".jpeg", ".webp", ".pdf"} {
		if strings.HasSuffix(name, e) {
			ext = e
			break
		}
	}
	if ext == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid format. Use PNG, JPG, WebP, or PDF."})
	}
	dir := "uploads/proofs"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create upload directory"})
	}
	saved := fmt.Sprintf("proof-%d-%d%s", order.ID, time.Now().Unix(), ext)
	if err := c.SaveFile(file, filepath.Join(dir, saved)); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save file"})
	}
	order.PaymentProofURL = "/uploads/proofs/" + saved
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
	go notifyOrderPaid(order)
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
	go notifyOrderRejected(order)
	return c.JSON(order)
}

// --- Order notification emails (fire-and-forget) ---

func userEmailByID(id uint) string {
	var u models.User
	if err := config.DB.First(&u, id).Error; err != nil {
		return ""
	}
	return u.Email
}

func notifyOrderCreated(o models.DeepScanOrder) {
	services.SendSimpleEmail(userEmailByID(o.UserID),
		"تم استلام طلب فحص عميق — Seku",
		services.EmailShell("طلب فحص عميق جديد", fmt.Sprintf(
			"<p>استلمنا طلبك لفحص عميق للنطاق <b>%s</b> بمبلغ <b>%d د.ع</b>.</p><p>حوّل المبلغ عبر الحوالة الداخلية ثم أدخل رقم الإشعار في صفحة \"الفحوص المدفوعة\". يُفعّل فحصك بعد تأكيد الحوالة.</p>",
			o.Domain, o.AmountIQD)))
	services.SendSimpleEmail(services.AdminNotifyEmail(),
		fmt.Sprintf("طلب فحص عميق جديد #%d — %s", o.ID, o.Domain),
		services.EmailShell("طلب جديد بانتظار المراجعة", fmt.Sprintf(
			"<p>طلب #%d للنطاق <b>%s</b> بمبلغ <b>%d د.ع</b>.</p><p>راجع صفحة إدارة الطلبات لتأكيد الحوالة.</p>",
			o.ID, o.Domain, o.AmountIQD)))
}

func notifyPaymentSubmitted(o models.DeepScanOrder) {
	services.SendSimpleEmail(services.AdminNotifyEmail(),
		fmt.Sprintf("حوالة مُرسلة للطلب #%d — %s", o.ID, o.Domain),
		services.EmailShell("رقم حوالة بانتظار التأكيد", fmt.Sprintf(
			"<p>أدخل العميل رقم الحوالة <b>%s</b> للطلب #%d (%s).</p><p>راجع صفحة إدارة الطلبات لتأكيد الاستلام.</p>",
			o.PaymentRef, o.ID, o.Domain)))
}

func notifyOrderPaid(o models.DeepScanOrder) {
	services.SendSimpleEmail(userEmailByID(o.UserID),
		"تم تأكيد دفعتك — ابدأ فحصك العميق",
		services.EmailShell("رصيدك جاهز", fmt.Sprintf(
			"<p>تم تأكيد دفعتك للنطاق <b>%s</b>. رصيد فحص عميق واحد جاهز الآن.</p><p>افتح صفحة الفحوص وابدأ الفحص العميق.</p>",
			o.Domain)))
}

func notifyOrderRejected(o models.DeepScanOrder) {
	services.SendSimpleEmail(userEmailByID(o.UserID),
		"تحديث بخصوص طلبك — Seku",
		services.EmailShell("طلب مرفوض", fmt.Sprintf(
			"<p>عذراً، لم نتمكّن من تأكيد طلبك للنطاق <b>%s</b>.</p><p>السبب: %s</p><p>يمكنك إنشاء طلب جديد أو التواصل معنا.</p>",
			o.Domain, o.AdminNotes)))
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

// consumeDeepScanCredits atomically claims one paid credit per target within a
// single transaction. If ANY target lacks a consumable credit, the whole
// transaction rolls back and it returns false — preventing the check-then-use
// race that could otherwise grant a free deep scan.
func consumeDeepScanCredits(orgID uint, targetIDs []uint, scanJobID uint) bool {
	if len(targetIDs) == 0 {
		return true
	}
	err := config.DB.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		for _, tid := range targetIDs {
			var order models.DeepScanOrder
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Where("organization_id = ? AND scan_target_id = ? AND status = ?", orgID, tid, "paid").
				Order("created_at ASC").First(&order).Error; err != nil {
				return fmt.Errorf("no paid credit for target %d", tid)
			}
			// Conditional update: only succeeds if the credit is still 'paid'.
			res := tx.Model(&models.DeepScanOrder{}).
				Where("id = ? AND status = ?", order.ID, "paid").
				Updates(map[string]interface{}{"status": "used", "used_by_scan_job": scanJobID, "used_at": &now})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				return fmt.Errorf("credit for target %d already consumed", tid)
			}
		}
		return nil
	})
	return err == nil
}
