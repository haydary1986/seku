package services

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"vscan-mohesr/internal/models"
)

// scoreToGrade converts a numeric score (0-1000) into a letter grade.
func scoreToGrade(score float64) string {
	switch {
	case score >= 900:
		return "A+"
	case score >= 800:
		return "A"
	case score >= 700:
		return "B"
	case score >= 600:
		return "C"
	case score >= 500:
		return "D"
	default:
		return "F"
	}
}

// scoreColor returns r, g, b values based on score thresholds.
func scoreColor(score float64) (int, int, int) {
	if score >= 900 {
		return 0, 150, 50
	}
	if score >= 500 {
		return 230, 150, 0
	}
	return 200, 30, 30
}

// statusLabel returns a display string for a check status.
func statusLabel(status string) string {
	switch strings.ToLower(status) {
	case "pass":
		return "PASS"
	case "warning", "warn":
		return "WARN"
	case "fail":
		return "FAIL"
	default:
		return strings.ToUpper(status)
	}
}

// categoryDisplayName returns a human-readable name for a category key.
func categoryDisplayName(key string) string {
	names := map[string]string{
		"ssl":               "SSL/TLS",
		"headers":           "Security Headers",
		"cookies":           "Cookies",
		"server_info":       "Server Info",
		"directory":         "Directory & Files",
		"performance":       "Performance",
		"ddos":              "DDoS Protection",
		"cors":              "CORS",
		"http_methods":      "HTTP Methods",
		"dns":               "DNS Security",
		"mixed_content":     "Mixed Content",
		"info_disclosure":   "Information Disclosure",
		"hosting":           "Hosting Quality",
		"content":           "Content Optimization",
		"advanced_security": "Advanced Security",
		"malware":           "Malware & Threats",
		"threat_intel":      "Threat Intelligence",
	}
	if name, ok := names[key]; ok {
		return name
	}
	return key
}

// categoryInfo holds aggregated data for a single category.
type categoryInfo struct {
	Name       string
	Key        string
	Score      float64
	Total      int
	Passed     int
	Warned     int
	Failed     int
	Checks     []models.CheckResult
}

// buildCategories groups checks by category and computes per-category stats.
func buildCategories(checks []models.CheckResult) []categoryInfo {
	catMap := map[string]*categoryInfo{}
	var order []string

	for _, ch := range checks {
		ci, exists := catMap[ch.Category]
		if !exists {
			ci = &categoryInfo{
				Key:  ch.Category,
				Name: categoryDisplayName(ch.Category),
			}
			catMap[ch.Category] = ci
			order = append(order, ch.Category)
		}
		ci.Total++
		ci.Checks = append(ci.Checks, ch)

		switch strings.ToLower(ch.Status) {
		case "pass":
			ci.Passed++
		case "warning", "warn":
			ci.Warned++
		default:
			ci.Failed++
		}
	}

	// Compute weighted average score per category
	for _, ci := range catMap {
		totalWeighted := 0.0
		totalWeight := 0.0
		for _, ch := range ci.Checks {
			totalWeighted += ch.Score * ch.Weight
			totalWeight += ch.Weight
		}
		if totalWeight > 0 {
			ci.Score = totalWeighted / totalWeight
		}
	}

	// Sort by the order they appeared
	sort.Slice(order, func(i, j int) bool {
		return order[i] < order[j]
	})

	var result []categoryInfo
	for _, key := range order {
		result = append(result, *catMap[key])
	}
	return result
}

// GenerateScanReport creates a PDF security report and returns its bytes.
func GenerateScanReport(result *models.ScanResult, checks []models.CheckResult) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 20)

	// Header/footer
	pdf.SetHeaderFuncMode(func() {
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(0, 8, "VScan-MOHESR", "", 0, "L", false, 0, "")
		pdf.Ln(4)
		pdf.SetDrawColor(200, 200, 200)
		pdf.Line(15, pdf.GetY(), 195, pdf.GetY())
		pdf.Ln(4)
	}, true)

	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(150, 150, 150)
		pdf.CellFormat(0, 10, fmt.Sprintf("Page %d/{nb}", pdf.PageNo()), "", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("")

	cats := buildCategories(checks)

	// Count totals
	totalPassed := 0
	totalWarned := 0
	totalFailed := 0
	for _, ci := range cats {
		totalPassed += ci.Passed
		totalWarned += ci.Warned
		totalFailed += ci.Failed
	}
	totalChecks := totalPassed + totalWarned + totalFailed

	// =====================================================================
	// PAGE 1: Cover
	// =====================================================================
	pdf.AddPage()

	// Title area
	pdf.Ln(30)
	pdf.SetFont("Helvetica", "B", 28)
	pdf.SetTextColor(30, 30, 60)
	pdf.CellFormat(0, 14, "VScan Security Report", "", 1, "C", false, 0, "")
	pdf.Ln(6)

	// Subtitle
	pdf.SetFont("Helvetica", "", 14)
	pdf.SetTextColor(80, 80, 80)
	pdf.CellFormat(0, 8, "Website Security Assessment", "", 1, "C", false, 0, "")
	pdf.Ln(12)

	// Website info
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(30, 30, 60)
	name := result.ScanTarget.Name
	if name == "" {
		name = result.ScanTarget.URL
	}
	pdf.CellFormat(0, 8, name, "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(60, 60, 180)
	pdf.CellFormat(0, 7, result.ScanTarget.URL, "", 1, "C", false, 0, "")
	pdf.Ln(4)

	// Scan date
	scanDate := "N/A"
	if result.EndedAt != nil {
		scanDate = result.EndedAt.Format("2006-01-02 15:04 MST")
	} else {
		scanDate = time.Now().Format("2006-01-02 15:04 MST")
	}
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(120, 120, 120)
	pdf.CellFormat(0, 6, "Scan Date: "+scanDate, "", 1, "C", false, 0, "")
	pdf.Ln(16)

	// Overall score box
	overallScore := math.Round(result.OverallScore)
	grade := scoreToGrade(result.OverallScore)
	r, g, b := scoreColor(result.OverallScore)

	boxW := 80.0
	boxH := 80.0
	boxX := (210 - boxW) / 2
	boxY := pdf.GetY()

	pdf.SetFillColor(r, g, b)
	pdf.Rect(boxX, boxY, boxW, boxH, "F")

	// Score number
	pdf.SetY(boxY + 12)
	pdf.SetFont("Helvetica", "B", 48)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(0, 24, fmt.Sprintf("%.0f", overallScore), "", 1, "C", false, 0, "")

	// /1000
	pdf.SetFont("Helvetica", "", 14)
	pdf.CellFormat(0, 8, "/1000", "", 1, "C", false, 0, "")

	// Grade
	pdf.SetFont("Helvetica", "B", 28)
	pdf.CellFormat(0, 16, "Grade: "+grade, "", 1, "C", false, 0, "")

	pdf.SetY(boxY + boxH + 10)

	// =====================================================================
	// PAGE 2: Executive Summary
	// =====================================================================
	pdf.AddPage()

	pdf.SetFont("Helvetica", "B", 20)
	pdf.SetTextColor(30, 30, 60)
	pdf.CellFormat(0, 12, "Executive Summary", "", 1, "L", false, 0, "")
	pdf.Ln(6)

	// Overall score bar
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(50, 50, 50)
	pdf.CellFormat(0, 8, fmt.Sprintf("Overall Score: %.0f / 1000  (%s)", overallScore, grade), "", 1, "L", false, 0, "")
	pdf.Ln(2)

	barY := pdf.GetY()
	barW := 170.0
	barH := 10.0
	// Background
	pdf.SetFillColor(230, 230, 230)
	pdf.Rect(15, barY, barW, barH, "F")
	// Filled portion
	fillW := barW * (result.OverallScore / 1000.0)
	pdf.SetFillColor(r, g, b)
	pdf.Rect(15, barY, fillW, barH, "F")

	pdf.SetY(barY + barH + 8)

	// Totals
	pdf.SetFont("Helvetica", "", 12)
	pdf.SetTextColor(50, 50, 50)
	pdf.CellFormat(0, 7, fmt.Sprintf("Total Checks: %d", totalChecks), "", 1, "L", false, 0, "")
	pdf.Ln(2)

	// Pass count
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(0, 150, 50)
	pdf.CellFormat(60, 7, fmt.Sprintf("Passed: %d", totalPassed), "", 0, "L", false, 0, "")
	// Warn count
	pdf.SetTextColor(230, 150, 0)
	pdf.CellFormat(60, 7, fmt.Sprintf("Warnings: %d", totalWarned), "", 0, "L", false, 0, "")
	// Fail count
	pdf.SetTextColor(200, 30, 30)
	pdf.CellFormat(60, 7, fmt.Sprintf("Failed: %d", totalFailed), "", 1, "L", false, 0, "")
	pdf.Ln(10)

	// =====================================================================
	// Category Breakdown Table
	// =====================================================================
	pdf.SetFont("Helvetica", "B", 16)
	pdf.SetTextColor(30, 30, 60)
	pdf.CellFormat(0, 10, "Category Breakdown", "", 1, "L", false, 0, "")
	pdf.Ln(4)

	// Table header
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetFillColor(50, 50, 80)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(60, 8, "Category", "1", 0, "L", true, 0, "")
	pdf.CellFormat(25, 8, "Score", "1", 0, "C", true, 0, "")
	pdf.CellFormat(25, 8, "Checks", "1", 0, "C", true, 0, "")
	pdf.CellFormat(25, 8, "Passed", "1", 0, "C", true, 0, "")
	pdf.CellFormat(25, 8, "Warned", "1", 0, "C", true, 0, "")
	pdf.CellFormat(20, 8, "Failed", "1", 1, "C", true, 0, "")

	// Table rows
	for i, ci := range cats {
		pdf.SetFont("Helvetica", "", 9)

		if i%2 == 0 {
			pdf.SetFillColor(245, 245, 250)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}

		pdf.SetTextColor(30, 30, 30)
		pdf.CellFormat(60, 7, ci.Name, "1", 0, "L", true, 0, "")

		cr, cg, cb := scoreColor(ci.Score)
		pdf.SetTextColor(cr, cg, cb)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(25, 7, fmt.Sprintf("%.0f", math.Round(ci.Score)), "1", 0, "C", true, 0, "")

		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(30, 30, 30)
		pdf.CellFormat(25, 7, fmt.Sprintf("%d", ci.Total), "1", 0, "C", true, 0, "")

		pdf.SetTextColor(0, 150, 50)
		pdf.CellFormat(25, 7, fmt.Sprintf("%d", ci.Passed), "1", 0, "C", true, 0, "")

		pdf.SetTextColor(230, 150, 0)
		pdf.CellFormat(25, 7, fmt.Sprintf("%d", ci.Warned), "1", 0, "C", true, 0, "")

		pdf.SetTextColor(200, 30, 30)
		pdf.CellFormat(20, 7, fmt.Sprintf("%d", ci.Failed), "1", 1, "C", true, 0, "")
	}

	pdf.Ln(4)

	// =====================================================================
	// Detailed Findings (one section per category)
	// =====================================================================
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 20)
	pdf.SetTextColor(30, 30, 60)
	pdf.CellFormat(0, 12, "Detailed Findings", "", 1, "L", false, 0, "")
	pdf.Ln(6)

	for _, ci := range cats {
		// Check if we need a new page (leave room for header + at least one check)
		if pdf.GetY() > 240 {
			pdf.AddPage()
		}

		// Category header
		cr, cg, cb := scoreColor(ci.Score)
		pdf.SetFillColor(cr, cg, cb)
		pdf.Rect(15, pdf.GetY(), 3, 8, "F")
		pdf.SetX(20)
		pdf.SetFont("Helvetica", "B", 13)
		pdf.SetTextColor(30, 30, 60)
		pdf.CellFormat(120, 8, ci.Name, "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "B", 13)
		pdf.SetTextColor(cr, cg, cb)
		pdf.CellFormat(0, 8, fmt.Sprintf("%.0f / 1000", math.Round(ci.Score)), "", 1, "R", false, 0, "")
		pdf.Ln(3)

		for _, ch := range ci.Checks {
			if pdf.GetY() > 255 {
				pdf.AddPage()
			}

			// Check row
			pdf.SetFont("Helvetica", "B", 9)

			// Status badge
			sr, sg, sb := scoreColor(ch.Score)
			pdf.SetTextColor(sr, sg, sb)
			label := statusLabel(ch.Status)
			pdf.CellFormat(16, 6, label, "", 0, "L", false, 0, "")

			// Check name
			pdf.SetTextColor(30, 30, 30)
			pdf.SetFont("Helvetica", "", 9)
			pdf.CellFormat(90, 6, ch.CheckName, "", 0, "L", false, 0, "")

			// Score
			pdf.SetFont("Helvetica", "B", 9)
			pdf.SetTextColor(sr, sg, sb)
			pdf.CellFormat(30, 6, fmt.Sprintf("%.0f/1000", math.Round(ch.Score)), "", 0, "C", false, 0, "")

			// Severity
			pdf.SetFont("Helvetica", "", 8)
			pdf.SetTextColor(100, 100, 100)
			sev := ch.Severity
			if sev == "" {
				sev = "-"
			}
			pdf.CellFormat(0, 6, sev, "", 1, "R", false, 0, "")

			// Details
			if ch.Details != "" {
				pdf.SetFont("Helvetica", "", 8)
				pdf.SetTextColor(100, 100, 100)
				pdf.SetX(31)
				// Truncate very long details for the PDF
				details := ch.Details
				if len(details) > 300 {
					details = details[:300] + "..."
				}
				pdf.MultiCell(154, 4, details, "", "L", false)
			}
			pdf.Ln(2)
		}

		pdf.Ln(4)
	}

	// Write to buffer
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	return buf.Bytes(), nil
}
