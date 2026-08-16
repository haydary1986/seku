package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"seku/internal/models"
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
	"wordpress": "WordPress Security", "xss": "XSS Vulnerabilities", "secrets": "Secrets Detection",
	"subdomains": "Subdomain Discovery", "tech_stack": "Technology Detection",
	"sqli": "SQL Injection", "ports": "Port Scanner",
	"open_redirect": "Open Redirect", "ssrf": "SSRF Detection",
	"email_security": "Email Security", "waf": "WAF Detection", "zone_transfer": "DNS Zone Transfer",
	"data_leak": "Data Leak Detection", "graphql": "GraphQL Security", "jwt_security": "JWT Security",
	"access_control": "Access Control (IDOR/BOLA)", "passive_urls": "Passive URL Discovery",
	"dast": "Active Fuzzing (DAST)", "backup_files": "Backup Files", "cms_cve": "CMS Vulnerabilities",
	"js_secrets": "JS Secrets", "wp_deep": "WordPress Deep Scan", "login": "Login Security",
}

// qualityCats are non-security (informational) domains, reported separately so a
// security report never mixes "SEO" or "Performance" in with real risk.
var qualityCats = map[string]bool{
	"seo": true, "content": true, "performance": true, "hosting": true,
	"tech_stack": true, "passive_urls": true, "third_party": true, "server_info": true,
}

// --- shared palette (emerald brand, matches the web app; no indigo/purple) ---
var (
	pdfWhite   = [3]int{255, 255, 255}
	pdfDarkBg  = [3]int{15, 23, 41}   // slate-950-ish
	pdfBrand   = [3]int{5, 150, 105}  // emerald-600
	pdfGreen   = [3]int{16, 185, 129} // pass
	pdfGray    = [3]int{107, 114, 128}
	pdfLight   = [3]int{243, 244, 246}
	pdfInk     = [3]int{17, 23, 41}
	sevCrit    = [3]int{225, 29, 72}  // rose-600
	sevHigh    = [3]int{234, 88, 12}  // orange-600
	sevMed     = [3]int{217, 119, 6}  // amber-600
	sevLow     = [3]int{2, 132, 199}  // sky-600
	sevInfo    = [3]int{100, 116, 139}
)

func severityRankPDF(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

func severityColorPDF(sev string) [3]int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return sevCrit
	case "high":
		return sevHigh
	case "medium":
		return sevMed
	case "low":
		return sevLow
	}
	return sevInfo
}

func scoreColorPDF(score float64) [3]int {
	switch {
	case score >= 800:
		return pdfGreen
	case score >= 600:
		return sevMed
	case score >= 500:
		return sevHigh
	default:
		return sevCrit
	}
}

// isFinding reports whether a check is a failing/warning finding worth listing.
func isFinding(c models.CheckResult) bool {
	switch strings.ToLower(c.Status) {
	case "fail", "warn":
		return true
	case "pass", "info", "error", "pending", "running":
		return false
	}
	return c.Score < 900 // fallback for legacy rows without a status
}

func statusLabelPDF(c models.CheckResult) string {
	switch strings.ToLower(c.Status) {
	case "fail":
		return "FAIL"
	case "warn":
		return "WARN"
	case "pass":
		return "PASS"
	}
	if c.Score < 500 {
		return "FAIL"
	} else if c.Score < 900 {
		return "WARN"
	}
	return "PASS"
}

func detailMessage(c models.CheckResult) string {
	if c.Details == "" {
		return ""
	}
	var d map[string]interface{}
	if json.Unmarshal([]byte(c.Details), &d) != nil {
		return ""
	}
	if m, ok := d["message"].(string); ok {
		return strings.TrimSpace(m)
	}
	return ""
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// findFontDir locates the fonts directory
func findFontDir() string {
	paths := []string{"assets/fonts", "backend/assets/fonts", "../assets/fonts", "/app/assets/fonts"}
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(p, "NotoSans.ttf")); err == nil {
			return p
		}
	}
	return "assets/fonts"
}

func GenerateScanReport(result *models.ScanResult, checks []models.CheckResult) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 18)

	fontDir := findFontDir()
	hasUTF8, hasArabic := false, false
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

	fill := func(c [3]int) { pdf.SetFillColor(c[0], c[1], c[2]) }
	ink := func(c [3]int) { pdf.SetTextColor(c[0], c[1], c[2]) }

	grade := scoreToGrade(result.OverallScore)
	scanDate := time.Now().Format("2006-01-02 15:04")
	if result.EndedAt != nil {
		scanDate = result.EndedAt.Format("2006-01-02 15:04")
	}
	siteName := result.ScanTarget.Name
	if siteName == "" {
		siteName = result.ScanTarget.URL
	}
	siteNameShaped := ShapeArabic(siteName)

	// --- tally severities (findings only) + pass count ---
	sevCounts := map[string]int{}
	passed := 0
	var findings []models.CheckResult
	for _, c := range checks {
		if strings.ToLower(c.Status) == "error" {
			continue
		}
		if isFinding(c) {
			sev := strings.ToLower(strings.TrimSpace(c.Severity))
			if sev == "" || sev == "info" {
				sev = "low"
			}
			sevCounts[sev]++
			findings = append(findings, c)
		} else {
			passed++
		}
	}
	// order findings: severity desc, then score asc (worst first)
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := severityRankPDF(findings[i].Severity), severityRankPDF(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return findings[i].Score < findings[j].Score
	})

	// ============================ PAGE 1: COVER ============================
	pdf.AddPage()
	fill(pdfDarkBg)
	pdf.Rect(0, 0, 210, 118, "F")
	// brand accent stripe
	fill(pdfBrand)
	pdf.Rect(0, 118, 210, 2, "F")

	ink(pdfWhite)
	setFont("B", 15)
	pdf.SetXY(15, 14)
	pdf.Cell(0, 8, "Seku")
	setFont("", 9)
	ink([3]int{148, 163, 184})
	pdf.SetXY(15, 23)
	pdf.Cell(0, 6, "Website Security Assessment")

	ink(pdfWhite)
	setFont("B", 26)
	pdf.SetXY(15, 46)
	pdf.Cell(0, 12, "Security Report")
	setArabicFont("B", 17)
	pdf.SetXY(15, 64)
	pdf.Cell(120, 10, siteNameShaped)
	setFont("", 10)
	ink([3]int{148, 170, 200})
	pdf.SetXY(15, 78)
	pdf.Cell(0, 6, result.ScanTarget.URL)
	pdf.SetXY(15, 86)
	pdf.Cell(0, 6, "Scan date: "+scanDate)

	// Score badge
	sc := scoreColorPDF(result.OverallScore)
	fill(sc)
	pdf.RoundedRect(142, 40, 53, 53, 5, "1234", "F")
	ink(pdfWhite)
	setFont("B", 34)
	pdf.SetXY(142, 47)
	pdf.CellFormat(53, 17, fmt.Sprintf("%.0f", result.OverallScore), "", 0, "C", false, 0, "")
	setFont("", 9)
	pdf.SetXY(142, 65)
	pdf.CellFormat(53, 6, "/ 1000", "", 0, "C", false, 0, "")
	setFont("B", 15)
	pdf.SetXY(142, 74)
	pdf.CellFormat(53, 9, grade+" · "+gradeLabel(grade), "", 0, "C", false, 0, "")

	// Executive summary — severity breakdown
	ink(pdfInk)
	setFont("B", 14)
	pdf.SetXY(15, 132)
	pdf.Cell(0, 8, "Executive Summary")

	y := 145.0
	sevBoxes := []struct {
		label string
		key   string
		color [3]int
	}{
		{"Critical", "critical", sevCrit},
		{"High", "high", sevHigh},
		{"Medium", "medium", sevMed},
		{"Low", "low", sevLow},
		{"Passed", "passed", pdfGreen},
	}
	boxW, gap := 34.0, 2.5
	for i, b := range sevBoxes {
		x := 15 + float64(i)*(boxW+gap)
		val := sevCounts[b.key]
		if b.key == "passed" {
			val = passed
		}
		fill(b.color)
		pdf.RoundedRect(x, y, boxW, 24, 3, "1234", "F")
		ink(pdfWhite)
		setFont("B", 19)
		pdf.SetXY(x, y+3)
		pdf.CellFormat(boxW, 10, fmt.Sprintf("%d", val), "", 0, "C", false, 0, "")
		setFont("", 8)
		pdf.SetXY(x, y+15)
		pdf.CellFormat(boxW, 6, b.label, "", 0, "C", false, 0, "")
	}

	y += 33
	ink(pdfGray)
	setFont("", 9)
	pdf.SetXY(15, y)
	pdf.Cell(0, 6, fmt.Sprintf("%d findings across %d checks  ·  %d categories  ·  Overall grade: %s",
		len(findings), len(checks), countCategories(checks), grade))
	y += 8
	if result.GradeCapReason != "" {
		ink(sevCrit)
		setFont("B", 9)
		pdf.SetXY(15, y)
		pdf.MultiCell(180, 5, "Grade capped: "+trunc(result.GradeCapReason, 150), "", "L", false)
		y = pdf.GetY()
	}
	// one-line posture statement
	posture := "No failing or warning findings were detected — a clean result at scan time."
	if len(findings) > 0 {
		top := findings[0]
		posture = fmt.Sprintf("Highest-priority issue: [%s] %s. Address findings in severity order (this report is sorted worst-first).",
			strings.ToUpper(firstNonEmpty(top.Severity, "low")), trunc(top.CheckName, 70))
	}
	ink([3]int{80, 80, 90})
	setFont("", 8.5)
	pdf.SetXY(15, y+2)
	pdf.MultiCell(180, 5, posture, "", "L", false)

	// ====================== PRIORITY FINDINGS ======================
	pdf.AddPage()
	addReportHeader(pdf, setFont, result.ScanTarget.URL)
	y = 26
	ink(pdfInk)
	setFont("B", 16)
	pdf.SetXY(15, y)
	pdf.Cell(0, 8, "Priority Findings")
	ink(pdfGray)
	setFont("", 8.5)
	pdf.SetXY(15, y+9)
	pdf.Cell(0, 5, "Failing and warning checks, ordered by severity (most critical first).")
	y += 20

	if len(findings) == 0 {
		fill(pdfLight)
		pdf.RoundedRect(15, y, 180, 20, 3, "1234", "F")
		ink(pdfGreen)
		setFont("B", 11)
		pdf.SetXY(20, y+6)
		pdf.Cell(0, 8, "No failing or warning findings at scan time.")
	}

	for _, ck := range findings {
		if y > 258 {
			pdf.AddPage()
			addReportHeader(pdf, setFont, result.ScanTarget.URL)
			y = 26
		}
		startY := y
		sev := strings.ToLower(strings.TrimSpace(ck.Severity))
		if sev == "" {
			sev = "low"
		}
		col := severityColorPDF(sev)

		// severity chip
		fill(col)
		pdf.RoundedRect(20, y, 22, 6, 1, "1234", "F")
		ink(pdfWhite)
		setFont("B", 6.5)
		pdf.SetXY(20, y+0.7)
		pdf.CellFormat(22, 5, strings.ToUpper(sev), "", 0, "C", false, 0, "")

		// check name
		ink(pdfInk)
		setFont("B", 9.5)
		pdf.SetXY(45, y)
		pdf.Cell(105, 6, trunc(ck.CheckName, 58))

		// score + status (right)
		ink(col)
		setFont("B", 8)
		pdf.SetXY(150, y)
		pdf.CellFormat(45, 6, fmt.Sprintf("%.0f · %s", ck.Score, statusLabelPDF(ck)), "", 0, "R", false, 0, "")

		// meta line: category · CVSS · CWE
		y += 6.5
		catName := categoryNames[ck.Category]
		if catName == "" {
			catName = ck.Category
		}
		meta := catName
		if ck.CVSSScore > 0 {
			meta += fmt.Sprintf("   ·   CVSS %.1f", ck.CVSSScore)
		}
		if ck.CWE != "" {
			meta += "   ·   " + ck.CWE
		}
		ink(pdfGray)
		setFont("", 7)
		pdf.SetXY(45, y)
		pdf.Cell(150, 4, meta)
		y += 5

		// message
		if msg := detailMessage(ck); msg != "" {
			ink([3]int{90, 90, 98})
			setFont("", 7.5)
			pdf.SetXY(45, y)
			pdf.MultiCell(150, 4, trunc(msg, 260), "", "L", false)
			y = pdf.GetY()
		}

		// left severity stripe spanning the block
		fill(col)
		h := y - startY - 1
		if h < 6 {
			h = 6
		}
		pdf.RoundedRect(15, startY, 2.5, h, 1, "1234", "F")

		// divider
		y += 3
		pdf.SetDrawColor(228, 230, 236)
		pdf.Line(15, y, 195, y)
		y += 4
	}

	// ====================== CATEGORY SCORES ======================
	catGroups := map[string][]models.CheckResult{}
	for _, c := range checks {
		catGroups[c.Category] = append(catGroups[c.Category], c)
	}
	type catScore struct {
		cat   string
		score float64
		n     int
	}
	var secCats, qualCats []catScore
	for cat, cks := range catGroups {
		ts, tw := 0.0, 0.0
		for _, c := range cks {
			ts += c.Score * c.Weight
			tw += c.Weight
		}
		s := 1000.0
		if tw > 0 {
			s = ts / tw
		}
		cscore := catScore{cat, s, len(cks)}
		if qualityCats[cat] {
			qualCats = append(qualCats, cscore)
		} else {
			secCats = append(secCats, cscore)
		}
	}
	worstFirst := func(a []catScore) { sort.Slice(a, func(i, j int) bool { return a[i].score < a[j].score }) }
	worstFirst(secCats)
	worstFirst(qualCats)

	pdf.AddPage()
	addReportHeader(pdf, setFont, result.ScanTarget.URL)
	y = 26
	ink(pdfInk)
	setFont("B", 16)
	pdf.SetXY(15, y)
	pdf.Cell(0, 8, "Category Scores")
	y += 14

	drawCatTable := func(title string, rows []catScore) {
		if len(rows) == 0 {
			return
		}
		if y > 250 {
			pdf.AddPage()
			addReportHeader(pdf, setFont, result.ScanTarget.URL)
			y = 26
		}
		ink(pdfBrand)
		setFont("B", 11)
		pdf.SetXY(15, y)
		pdf.Cell(0, 7, title)
		y += 10
		for _, cs := range rows {
			if y > 275 {
				pdf.AddPage()
				addReportHeader(pdf, setFont, result.ScanTarget.URL)
				y = 26
			}
			name := categoryNames[cs.cat]
			if name == "" {
				name = cs.cat
			}
			g := scoreToGrade(cs.score)
			// track background
			pdf.SetFillColor(238, 240, 244)
			pdf.RoundedRect(15, y, 180, 8, 1, "1234", "F")
			// colored proportion
			bw := cs.score / 1000 * 180
			if bw < 2 {
				bw = 2
			}
			bc := scoreColorPDF(cs.score)
			pdf.SetFillColor(bc[0], bc[1], bc[2])
			pdf.RoundedRect(15, y, bw, 8, 1, "1234", "F")
			ink(pdfInk)
			setFont("B", 8)
			pdf.SetXY(18, y+1.3)
			pdf.Cell(110, 5, name)
			setFont("B", 8)
			pdf.SetXY(150, y+1.3)
			pdf.CellFormat(20, 5, fmt.Sprintf("%.0f", cs.score), "", 0, "R", false, 0, "")
			pdf.SetXY(172, y+1.3)
			pdf.CellFormat(10, 5, g, "", 0, "C", false, 0, "")
			pdf.SetXY(184, y+1.3)
			pdf.CellFormat(9, 5, fmt.Sprintf("%d", cs.n), "", 0, "C", false, 0, "")
			y += 10
		}
		y += 4
	}
	drawCatTable("Security", secCats)
	drawCatTable("Quality & Performance (informational)", qualCats)

	// ====================== GRADING SCALE + FOOTER ======================
	if y > 210 {
		pdf.AddPage()
		addReportHeader(pdf, setFont, result.ScanTarget.URL)
		y = 26
	} else {
		y += 6
	}
	ink(pdfInk)
	setFont("B", 13)
	pdf.SetXY(15, y)
	pdf.Cell(0, 8, "Grading Scale")
	y += 12
	for _, g := range []struct {
		grade, label, rng string
		color             [3]int
	}{
		{"A+", "Excellent", "900 - 1000", pdfGreen},
		{"A", "Very Good", "800 - 899", [3]int{34, 197, 94}},
		{"B", "Good", "700 - 799", sevLow},
		{"C", "Average", "600 - 699", sevMed},
		{"D", "Below Average", "500 - 599", sevHigh},
		{"F", "Failing", "0 - 499", sevCrit},
	} {
		fill(g.color)
		pdf.RoundedRect(15, y, 22, 9, 2, "1234", "F")
		ink(pdfWhite)
		setFont("B", 10)
		pdf.SetXY(15, y+1.6)
		pdf.CellFormat(22, 6, g.grade, "", 0, "C", false, 0, "")
		ink(pdfInk)
		setFont("B", 9)
		pdf.SetXY(42, y+1.6)
		pdf.Cell(50, 6, g.label)
		ink(pdfGray)
		setFont("", 9)
		pdf.SetXY(95, y+1.6)
		pdf.Cell(40, 6, g.rng)
		y += 12
	}

	y += 8
	ink(pdfGray)
	setFont("", 8)
	pdf.SetXY(15, y)
	pdf.MultiCell(180, 5,
		"Generated by Seku Website Security Assessment. Scores reflect the security posture at scan time and "+
			"change as configuration is updated. Severity ratings follow CVSS v3.1 bands. See the public methodology page for the full scoring model.",
		"", "L", false)
	y = pdf.GetY() + 6
	setFont("", 7)
	pdf.SetXY(15, y)
	pdf.Cell(0, 5, fmt.Sprintf("Generated: %s  ·  https://sec.erticaz.com", time.Now().Format("2006-01-02 15:04:05")))

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}
	return buf.Bytes(), nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func addReportHeader(pdf *fpdf.Fpdf, setFont func(string, float64), url string) {
	pdf.SetFillColor(pdfBrand[0], pdfBrand[1], pdfBrand[2])
	pdf.Rect(0, 0, 210, 16, "F")
	pdf.SetTextColor(255, 255, 255)
	setFont("B", 10)
	pdf.SetXY(15, 4)
	pdf.Cell(0, 8, "Seku  ·  Security Report  ·  "+trunc(url, 70))
}

func countCategories(checks []models.CheckResult) int {
	cats := map[string]bool{}
	for _, c := range checks {
		cats[c.Category] = true
	}
	return len(cats)
}
