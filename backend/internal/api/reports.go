package api

import (
	"fmt"

	"github.com/gofiber/fiber/v2"

	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/models"
	"vscan-mohesr/internal/services"
)

// GeneratePDFReport generates a downloadable PDF security report for a scan result.
func GeneratePDFReport(c *fiber.Ctx) error {
	id := c.Params("id")

	var result models.ScanResult
	if err := config.DB.Preload("ScanTarget").Preload("Checks").First(&result, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan result not found"})
	}

	pdfBytes, err := services.GenerateScanReport(&result, result.Checks)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate PDF report"})
	}

	filename := fmt.Sprintf("vscan-report-%s.pdf", result.ScanTarget.URL)

	c.Set("Content-Type", "application/pdf")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))

	return c.Send(pdfBytes)
}
