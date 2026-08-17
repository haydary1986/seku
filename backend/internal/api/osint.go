package api

import (
	"github.com/gofiber/fiber/v2"

	"seku/internal/scanner"
)

// RunOSINTReport performs passive OSINT reconnaissance on a domain.
// GET /osint?domain=example.com  (authenticated; rate-limited at the route)
func RunOSINTReport(c *fiber.Ctx) error {
	domain := c.Query("domain", "")
	if domain == "" {
		domain = c.Query("target", "")
	}
	if domain == "" {
		return c.Status(400).JSON(fiber.Map{"error": "domain is required"})
	}
	report := scanner.RunOSINT(domain)
	if report.Domain == "" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid domain"})
	}
	return c.JSON(report)
}
