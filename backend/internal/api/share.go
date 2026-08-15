package api

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"seku/internal/config"
	"seku/internal/models"
)

// ShareResult creates (or returns) a public share token for a scan result, so it
// can be shown on a public page and embedded as a "Scanned by Seku" badge.
// POST /results/:id/share  (org-scoped)
func ShareResult(c *fiber.Ctx) error {
	id := c.Params("id")
	if !CanAccessResult(c, id) {
		return c.Status(404).JSON(fiber.Map{"error": "Result not found"})
	}
	var result models.ScanResult
	if err := config.DB.First(&result, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Result not found"})
	}
	if result.ShareToken == "" {
		result.ShareToken = GenerateVerificationKey()
		config.DB.Model(&result).Update("share_token", result.ShareToken)
	}
	return c.JSON(fiber.Map{
		"token":     result.ShareToken,
		"share_url": "/r/" + result.ShareToken,
		"badge_url": "/api/public/badge/" + result.ShareToken,
	})
}

// UnshareResult revokes a share token.
// DELETE /results/:id/share
func UnshareResult(c *fiber.Ctx) error {
	id := c.Params("id")
	if !CanAccessResult(c, id) {
		return c.Status(404).JSON(fiber.Map{"error": "Result not found"})
	}
	config.DB.Model(&models.ScanResult{}).Where("id = ?", id).Update("share_token", "")
	return c.JSON(fiber.Map{"message": "Sharing disabled"})
}

// resultByToken loads a shared result with its checks and target.
func resultByToken(token string) (*models.ScanResult, bool) {
	if strings.TrimSpace(token) == "" {
		return nil, false
	}
	var result models.ScanResult
	if err := config.DB.Preload("ScanTarget").Preload("Checks").
		Where("share_token = ?", token).First(&result).Error; err != nil {
		return nil, false
	}
	return &result, true
}

// GetPublicReport returns a SANITIZED summary for a shared result — score, grade,
// severity counts, and per-category pass/fail. It deliberately omits finding
// details so a public link never leaks exploit specifics.
// GET /public/report/:token
func GetPublicReport(c *fiber.Ctx) error {
	result, ok := resultByToken(c.Params("token"))
	if !ok {
		return c.Status(404).JSON(fiber.Map{"error": "Report not found"})
	}

	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "passed": 0}
	catStatus := map[string]string{} // category -> worst status
	for _, ch := range result.Checks {
		if ch.Status == "fail" || ch.Status == "warn" {
			sev := strings.ToLower(ch.Severity)
			if _, k := counts[sev]; k {
				counts[sev]++
			}
			if catStatus[ch.Category] != "fail" {
				catStatus[ch.Category] = "fail"
			}
		} else {
			counts["passed"]++
			if catStatus[ch.Category] == "" {
				catStatus[ch.Category] = "pass"
			}
		}
	}
	categories := make([]fiber.Map, 0, len(catStatus))
	for cat, st := range catStatus {
		categories = append(categories, fiber.Map{"category": cat, "status": st})
	}

	grade := result.SecurityGrade
	if grade == "" {
		grade = scoreToGrade(result.OverallScore)
	}
	return c.JSON(fiber.Map{
		"domain":     result.ScanTarget.URL,
		"score":      result.OverallScore,
		"grade":      grade,
		"scanned_at": result.EndedAt,
		"summary":    counts,
		"categories": categories,
	})
}

// GetPublicBadge renders an embeddable SVG badge ("Seku | A") for a shared result.
// GET /public/badge/:token
func GetPublicBadge(c *fiber.Ctx) error {
	result, ok := resultByToken(c.Params("token"))
	grade := "?"
	if ok {
		grade = result.SecurityGrade
		if grade == "" {
			grade = scoreToGrade(result.OverallScore)
		}
	}
	color := gradeBadgeColor(grade)

	// shields-style two-part badge, self-contained SVG.
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="132" height="20" role="img" aria-label="Seku: %s">
<linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="132" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">
<rect width="95" height="20" fill="#0b1220"/>
<rect x="95" width="37" height="20" fill="%s"/>
<rect width="132" height="20" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="16" y="14" fill="#0f9d6c" font-weight="bold">🛡</text>
<text x="58" y="14">Scanned by Seku</text>
<text x="113" y="14" font-weight="bold">%s</text>
</g></svg>`, grade, color, grade)

	c.Set("Content-Type", "image/svg+xml")
	c.Set("Cache-Control", "max-age=300, public")
	return c.SendString(svg)
}

func gradeBadgeColor(grade string) string {
	switch {
	case strings.HasPrefix(grade, "A"):
		return "#2ea043" // green
	case strings.HasPrefix(grade, "B"):
		return "#7bb32e"
	case strings.HasPrefix(grade, "C"):
		return "#d4a017"
	case strings.HasPrefix(grade, "D"):
		return "#e0731a"
	default:
		return "#d6293e" // F / unknown
	}
}
