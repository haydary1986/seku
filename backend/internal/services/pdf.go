package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"vscan-mohesr/internal/models"
)

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

func gradeLabel(grade string) string {
	labels := map[string]string{
		"A+": "Excellent", "A": "Very Good", "B": "Good",
		"C": "Average", "D": "Below Average", "F": "Failing",
	}
	return labels[grade]
}

var categoryNames = map[string]string{
	"ssl": "SSL/TLS Encryption", "headers": "Security Headers", "cookies": "Cookie Security",
	"server_info": "Server Information", "directory": "Directory & Files", "performance": "Performance",
	"ddos": "DDoS Protection", "cors": "CORS Configuration", "http_methods": "HTTP Methods",
	"dns": "DNS Security", "mixed_content": "Mixed Content", "info_disclosure": "Information Disclosure",
	"content": "Content Optimization", "hosting": "Hosting Quality", "advanced_security": "Advanced Security",
	"malware": "Malware & Threats", "threat_intel": "Threat Intelligence",
	"seo": "SEO & Technical Health", "third_party": "Third-Party Scripts", "js_libraries": "JavaScript Libraries",
}

// findFontDir locates the fonts directory
func findFontDir() string {
	// Check relative to working directory
	paths := []string{
		"assets/fonts",
		"backend/assets/fonts",
		"../assets/fonts",
		"/app/assets/fonts",
	}
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(p, "NotoSans.ttf")); err == nil {
			return p
		}
	}
	return "assets/fonts" // fallback
}

func GenerateScanReport(result *models.ScanResult, checks []models.CheckResult) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)

	// Try to load UTF-8 fonts for Arabic support
	fontDir := findFontDir()
	hasUTF8 := false
	hasArabic := false
	notoPath := filepath.Join(fontDir, "NotoSans.ttf")
	arabicPath := filepath.Join(fontDir, "NotoSansArabic.ttf")

	if _, err := os.Stat(notoPath); err == nil {
		pdf.AddUTF8Font("NotoSans", "", notoPath)
		pdf.AddUTF8Font("NotoSans", "B", notoPath)
		if pdf.Err() {
			pdf.ClearError()
		} else {
			hasUTF8 = true
		}
	}
	if _, err := os.Stat(arabicPath); err == nil {
		pdf.AddUTF8Font("NotoArabic", "", arabicPath)
		pdf.AddUTF8Font("NotoArabic", "B", arabicPath)
		if pdf.Err() {
			pdf.ClearError()
		} else {
			hasArabic = true
		}
	}

	// Helper to set font (with fallback to built-in Helvetica)
	setFont := func(style string, size float64) {
		if hasUTF8 {
			pdf.SetFont("NotoSans", style, size)
			if pdf.Err() {
				pdf.ClearError()
				pdf.SetFont("Helvetica", style, size)
			}
		} else {
			pdf.SetFont("Helvetica", style, size)
		}
	}

	setArabicFont := func(style string, size float64) {
		if hasArabic {
			pdf.SetFont("NotoArabic", style, size)
			if pdf.Err() {
				pdf.ClearError()
				pdf.SetFont("Helvetica", style, size)
			}
		} else {
			setFont(style, size)
		}
	}

	_ = setArabicFont // ensure used

	// Colors
	white := [3]int{255, 255, 255}
	darkBg := [3]int{30, 41, 59}
	indigo := [3]int{79, 70, 229}
	green := [3]int{16, 185, 129}
	orange := [3]int{245, 158, 11}
	red := [3]int{239, 68, 68}
	gray := [3]int{107, 114, 128}
	lightGray := [3]int{243, 244, 246}

	scoreColor := func(score float64) [3]int {
		if score >= 800 {
			return green
		} else if score >= 500 {
			return orange
		}
		return red
	}

	grade := scoreToGrade(result.OverallScore)
	scanDate := ""
	if result.EndedAt != nil {
		scanDate = result.EndedAt.Format("2006-01-02 15:04")
	} else {
		scanDate = time.Now().Format("2006-01-02 15:04")
	}

	siteName := result.ScanTarget.Name
	if siteName == "" {
		siteName = result.ScanTarget.URL
	}
	// Shape Arabic text for PDF rendering (joining + RTL)
	siteNameShaped := ShapeArabic(siteName)

	// ============================================
	// PAGE 1: COVER
	// ============================================
	pdf.AddPage()

	// Dark header background
	pdf.SetFillColor(darkBg[0], darkBg[1], darkBg[2])
	pdf.Rect(0, 0, 210, 120, "F")

	// VScan logo text
	pdf.SetTextColor(white[0], white[1], white[2])
	setFont("B", 14)
	pdf.SetXY(15, 15)
	pdf.Cell(0, 8, "VScan-MOHESR")

	setFont("", 9)
	pdf.SetTextColor(180, 180, 200)
	pdf.SetXY(15, 24)
	pdf.Cell(0, 6, "Website Security Assessment Platform")

	// Title
	pdf.SetTextColor(white[0], white[1], white[2])
	setFont("B", 28)
	pdf.SetXY(15, 50)
	pdf.Cell(0, 12, "Security Scan Report")

	// Website name (Arabic support)
	setArabicFont("B", 18)
	pdf.SetXY(15, 68)
	pdf.Cell(0, 10, siteNameShaped)

	// URL
	setFont("", 11)
	pdf.SetTextColor(160, 170, 220)
	pdf.SetXY(15, 82)
	pdf.Cell(0, 7, result.ScanTarget.URL)

	// Date
	pdf.SetXY(15, 92)
	pdf.Cell(0, 7, "Scan Date: "+scanDate)

	// Score box on cover
	sc := scoreColor(result.OverallScore)
	pdf.SetFillColor(sc[0], sc[1], sc[2])
	pdf.RoundedRect(140, 45, 55, 55, 5, "1234", "F")
	pdf.SetTextColor(white[0], white[1], white[2])
	setFont("B", 36)
	scoreStr := fmt.Sprintf("%.0f", result.OverallScore)
	pdf.SetXY(140, 52)
	pdf.CellFormat(55, 18, scoreStr, "", 0, "C", false, 0, "")
	setFont("", 10)
	pdf.SetXY(140, 72)
	pdf.CellFormat(55, 7, "/1000", "", 0, "C", false, 0, "")
	setFont("B", 16)
	pdf.SetXY(140, 82)
	pdf.CellFormat(55, 10, grade+" - "+gradeLabel(grade), "", 0, "C", false, 0, "")

	// Summary section below dark area
	pdf.SetTextColor(0, 0, 0)

	// Count results
	passed, warned, failed := 0, 0, 0
	for _, c := range checks {
		if c.Score >= 900 {
			passed++
		} else if c.Score >= 500 {
			warned++
		} else {
			failed++
		}
	}

	// Summary boxes
	y := 130.0
	setFont("B", 14)
	pdf.SetXY(15, y)
	pdf.Cell(0, 8, "Executive Summary")
	y += 12

	// Three stat boxes
	boxW := 56.0
	for i, stat := range []struct {
		label string
		value string
		color [3]int
	}{
		{"Passed", fmt.Sprintf("%d", passed), green},
		{"Warnings", fmt.Sprintf("%d", warned), orange},
		{"Failed", fmt.Sprintf("%d", failed), red},
	} {
		x := 15 + float64(i)*(boxW+4)
		pdf.SetFillColor(stat.color[0], stat.color[1], stat.color[2])
		pdf.RoundedRect(x, y, boxW, 25, 3, "1234", "F")
		pdf.SetTextColor(white[0], white[1], white[2])
		setFont("B", 20)
		pdf.SetXY(x, y+3)
		pdf.CellFormat(boxW, 10, stat.value, "", 0, "C", false, 0, "")
		setFont("", 9)
		pdf.SetXY(x, y+14)
		pdf.CellFormat(boxW, 7, stat.label, "", 0, "C", false, 0, "")
	}

	y += 35
	setFont("", 9)
	pdf.SetTextColor(gray[0], gray[1], gray[2])
	pdf.SetXY(15, y)
	pdf.Cell(0, 6, fmt.Sprintf("Total Checks: %d  |  Categories: %d  |  Score: %.0f/1000  |  Grade: %s",
		len(checks), countCategories(checks), result.OverallScore, grade))

	// ============================================
	// PAGE 2: CATEGORY BREAKDOWN
	// ============================================
	pdf.AddPage()

	// Header
	pdf.SetFillColor(indigo[0], indigo[1], indigo[2])
	pdf.Rect(0, 0, 210, 18, "F")
	pdf.SetTextColor(white[0], white[1], white[2])
	setFont("B", 11)
	pdf.SetXY(15, 5)
	pdf.Cell(0, 8, "VScan-MOHESR  |  Security Report  |  "+result.ScanTarget.URL)

	y = 25.0
	pdf.SetTextColor(0, 0, 0)
	setFont("B", 16)
	pdf.SetXY(15, y)
	pdf.Cell(0, 8, "Category Breakdown")
	y += 14

	// Group checks by category
	catGroups := map[string][]models.CheckResult{}
	for _, c := range checks {
		catGroups[c.Category] = append(catGroups[c.Category], c)
	}

	// Sort categories by score (worst first for attention)
	type catScore struct {
		cat   string
		score float64
	}
	var sortedCats []catScore
	for cat, cks := range catGroups {
		ts, tw := 0.0, 0.0
		for _, c := range cks {
			ts += c.Score * c.Weight
			tw += c.Weight
		}
		s := 0.0
		if tw > 0 {
			s = ts / tw
		}
		sortedCats = append(sortedCats, catScore{cat, s})
	}
	sort.Slice(sortedCats, func(i, j int) bool {
		return sortedCats[i].score > sortedCats[j].score
	})

	// Table header
	pdf.SetFillColor(lightGray[0], lightGray[1], lightGray[2])
	pdf.RoundedRect(15, y, 180, 8, 1, "1234", "F")
	setFont("B", 8)
	pdf.SetTextColor(gray[0], gray[1], gray[2])
	pdf.SetXY(17, y+1)
	pdf.Cell(85, 6, "CATEGORY")
	pdf.SetXY(105, y+1)
	pdf.CellFormat(25, 6, "SCORE", "", 0, "C", false, 0, "")
	pdf.SetXY(133, y+1)
	pdf.CellFormat(20, 6, "GRADE", "", 0, "C", false, 0, "")
	pdf.SetXY(155, y+1)
	pdf.CellFormat(20, 6, "CHECKS", "", 0, "C", false, 0, "")
	pdf.SetXY(175, y+1)
	pdf.CellFormat(18, 6, "STATUS", "", 0, "C", false, 0, "")
	y += 10

	for _, cs := range sortedCats {
		if y > 270 {
			pdf.AddPage()
			addReportHeader(pdf, setFont, indigo, white, result.ScanTarget.URL)
			y = 25
		}

		name := categoryNames[cs.cat]
		if name == "" {
			name = cs.cat
		}
		g := scoreToGrade(cs.score)
		cks := catGroups[cs.cat]

		p, w, f := 0, 0, 0
		for _, c := range cks {
			if c.Score >= 900 {
				p++
			} else if c.Score >= 500 {
				w++
			} else {
				f++
			}
		}

		// Score bar background
		pdf.SetFillColor(240, 240, 240)
		pdf.Rect(15, y, 180, 9, "F")

		// Score bar colored portion
		barWidth := cs.score / 1000 * 180
		sc := scoreColor(cs.score)
		pdf.SetFillColor(sc[0], sc[1], sc[2])
		pdf.Rect(15, y, barWidth, 9, "F")

		// Text on bar
		pdf.SetTextColor(0, 0, 0)
		setFont("B", 8)
		pdf.SetXY(17, y+1.5)
		pdf.Cell(85, 6, name)

		pdf.SetTextColor(50, 50, 50)
		setFont("B", 9)
		pdf.SetXY(105, y+1.5)
		pdf.CellFormat(25, 6, fmt.Sprintf("%.0f", cs.score), "", 0, "C", false, 0, "")

		setFont("B", 8)
		pdf.SetXY(133, y+1.5)
		pdf.CellFormat(20, 6, g, "", 0, "C", false, 0, "")

		setFont("", 8)
		pdf.SetXY(155, y+1.5)
		pdf.CellFormat(20, 6, fmt.Sprintf("%d", len(cks)), "", 0, "C", false, 0, "")

		status := fmt.Sprintf("%dP %dW %dF", p, w, f)
		pdf.SetXY(175, y+1.5)
		pdf.CellFormat(18, 6, status, "", 0, "C", false, 0, "")

		y += 11
	}

	// ============================================
	// DETAILED FINDINGS PAGES
	// ============================================
	for _, cs := range sortedCats {
		pdf.AddPage()
		addReportHeader(pdf, setFont, indigo, white, result.ScanTarget.URL)

		name := categoryNames[cs.cat]
		if name == "" {
			name = cs.cat
		}
		g := scoreToGrade(cs.score)
		sc := scoreColor(cs.score)

		y = 25.0

		// Category title with score badge
		pdf.SetFillColor(sc[0], sc[1], sc[2])
		pdf.RoundedRect(15, y, 180, 14, 3, "1234", "F")
		pdf.SetTextColor(white[0], white[1], white[2])
		setFont("B", 11)
		pdf.SetXY(20, y+3)
		pdf.Cell(120, 8, name)
		setFont("B", 12)
		pdf.SetXY(150, y+3)
		pdf.CellFormat(40, 8, fmt.Sprintf("%.0f/1000 (%s)", cs.score, g), "", 0, "R", false, 0, "")
		y += 20

		cks := catGroups[cs.cat]
		sort.Slice(cks, func(i, j int) bool {
			return cks[i].Score < cks[j].Score // worst first
		})

		for _, check := range cks {
			if y > 260 {
				pdf.AddPage()
				addReportHeader(pdf, setFont, indigo, white, result.ScanTarget.URL)
				y = 25
			}

			// Check row
			chkColor := scoreColor(check.Score)

			// Status indicator
			pdf.SetFillColor(chkColor[0], chkColor[1], chkColor[2])
			pdf.RoundedRect(15, y, 3, 16, 1, "1234", "F")

			// Check name
			pdf.SetTextColor(0, 0, 0)
			setFont("B", 9)
			pdf.SetXY(22, y)
			pdf.Cell(100, 6, check.CheckName)

			// Score + status
			setFont("B", 9)
			pdf.SetTextColor(chkColor[0], chkColor[1], chkColor[2])
			pdf.SetXY(140, y)
			statusLabel := "PASS"
			if check.Score < 500 {
				statusLabel = "FAIL"
			} else if check.Score < 900 {
				statusLabel = "WARN"
			}
			pdf.CellFormat(55, 6, fmt.Sprintf("%.0f/1000  [%s]", check.Score, statusLabel), "", 0, "R", false, 0, "")

			// Severity
			pdf.SetTextColor(gray[0], gray[1], gray[2])
			setFont("", 7)
			pdf.SetXY(22, y+6)
			pdf.Cell(30, 5, "Severity: "+strings.ToUpper(check.Severity))

			// Details
			if check.Details != "" {
				var details map[string]interface{}
				if json.Unmarshal([]byte(check.Details), &details) == nil {
					if msg, ok := details["message"].(string); ok && msg != "" {
						pdf.SetTextColor(80, 80, 80)
						setFont("", 7)
						pdf.SetXY(22, y+11)
						if len(msg) > 120 {
							msg = msg[:120] + "..."
						}
						pdf.Cell(170, 4, msg)
					}
				}
			}

			y += 20
		}
	}

	// ============================================
	// FOOTER PAGE
	// ============================================
	pdf.AddPage()
	addReportHeader(pdf, setFont, indigo, white, result.ScanTarget.URL)

	y = 40.0
	pdf.SetTextColor(0, 0, 0)
	setFont("B", 16)
	pdf.SetXY(15, y)
	pdf.Cell(0, 8, "Grading Scale")
	y += 14

	grades := []struct {
		grade, label, range_ string
		color                [3]int
	}{
		{"A+", "Excellent", "900 - 1000", [3]int{16, 185, 129}},
		{"A", "Very Good", "800 - 899", [3]int{34, 197, 94}},
		{"B", "Good", "700 - 799", [3]int{59, 130, 246}},
		{"C", "Average", "600 - 699", [3]int{245, 158, 11}},
		{"D", "Below Average", "500 - 599", [3]int{249, 115, 22}},
		{"F", "Failing", "0 - 499", [3]int{239, 68, 68}},
	}

	for _, g := range grades {
		pdf.SetFillColor(g.color[0], g.color[1], g.color[2])
		pdf.RoundedRect(15, y, 25, 10, 2, "1234", "F")
		pdf.SetTextColor(white[0], white[1], white[2])
		setFont("B", 11)
		pdf.SetXY(15, y+2)
		pdf.CellFormat(25, 6, g.grade, "", 0, "C", false, 0, "")

		pdf.SetTextColor(0, 0, 0)
		setFont("B", 9)
		pdf.SetXY(45, y+2)
		pdf.Cell(50, 6, g.label)

		pdf.SetTextColor(gray[0], gray[1], gray[2])
		setFont("", 9)
		pdf.SetXY(100, y+2)
		pdf.Cell(40, 6, g.range_)
		y += 13
	}

	y += 15
	pdf.SetTextColor(gray[0], gray[1], gray[2])
	setFont("", 8)
	pdf.SetXY(15, y)
	pdf.MultiCell(180, 5,
		"This report was generated by VScan-MOHESR Security Assessment Platform. "+
			"The scores reflect the security posture at the time of scanning and may change "+
			"as the website configuration is updated. For the full scoring methodology, "+
			"visit the public methodology page.", "", "L", false)

	y += 20
	setFont("", 7)
	pdf.SetXY(15, y)
	pdf.Cell(0, 5, fmt.Sprintf("Generated: %s  |  VScan-MOHESR v1.0  |  https://sec.erticaz.com", time.Now().Format("2006-01-02 15:04:05")))

	// Output
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	return buf.Bytes(), nil
}

func addReportHeader(pdf *fpdf.Fpdf, setFont func(string, float64), indigo, white [3]int, url string) {
	pdf.SetFillColor(indigo[0], indigo[1], indigo[2])
	pdf.Rect(0, 0, 210, 18, "F")
	pdf.SetTextColor(white[0], white[1], white[2])
	setFont("B", 11)
	pdf.SetXY(15, 5)
	pdf.Cell(0, 8, "VScan-MOHESR  |  Security Report  |  "+url)
}

func countCategories(checks []models.CheckResult) int {
	cats := map[string]bool{}
	for _, c := range checks {
		cats[c.Category] = true
	}
	return len(cats)
}

// Ensure math is used
var _ = math.Round
