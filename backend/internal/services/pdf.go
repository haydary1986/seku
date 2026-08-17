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

// qualityCats are non-security (informational) domains, reported separately.
var qualityCats = map[string]bool{
	"seo": true, "content": true, "performance": true, "hosting": true,
	"tech_stack": true, "passive_urls": true, "third_party": true, "server_info": true,
}

// --- palette (emerald brand; CVSS-band severity colors; no indigo/purple) ---
var (
	pdfWhite  = [3]int{255, 255, 255}
	pdfDarkBg = [3]int{15, 23, 41}
	pdfBrand  = [3]int{5, 150, 105}
	pdfGreen  = [3]int{16, 185, 129}
	pdfGray   = [3]int{107, 114, 128}
	pdfMute   = [3]int{148, 163, 184}
	pdfLight  = [3]int{243, 244, 246}
	pdfInk    = [3]int{17, 23, 41}
	sevCrit   = [3]int{225, 29, 72}
	sevHigh   = [3]int{234, 88, 12}
	sevMed    = [3]int{217, 119, 6}
	sevLow    = [3]int{2, 132, 199}
	sevInfo   = [3]int{100, 116, 139}
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

func isFinding(c models.CheckResult) bool {
	switch strings.ToLower(c.Status) {
	case "fail", "warn":
		return true
	case "pass", "info", "error", "pending", "running":
		return false
	}
	return c.Score < 900
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

// impactStatement returns a business-impact narrative for a severity level.
func impactStatement(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "Successful exploitation could lead to full compromise of the application or its data — for example remote code execution, injection of arbitrary queries/commands, exposure of secrets, or authentication bypass. Immediate remediation is required."
	case "high":
		return "This weakness materially degrades the application's security posture and can be leveraged as part of an attack chain to reach sensitive data or functionality. It should be remediated promptly."
	case "medium":
		return "This is a hardening gap that widens the attack surface or assists an attacker during exploitation of other weaknesses. Remediation is recommended in the normal maintenance cycle."
	default:
		return "This is a minor hardening or best-practice gap with limited direct impact. Addressing it improves defence-in-depth."
	}
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func findFontDir() string {
	paths := []string{"assets/fonts", "backend/assets/fonts", "../assets/fonts", "/app/assets/fonts"}
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(p, "NotoSans.ttf")); err == nil {
			return p
		}
	}
	return "assets/fonts"
}

// GenerateScanReport renders a professional, pentest-style PDF assessment report.
// `remediations` maps a check name to a remediation paragraph (supplied by the
// API layer from the remediation knowledge base; may be nil).
func GenerateScanReport(result *models.ScanResult, checks []models.CheckResult, remediations map[string]string) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)

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
	scanDate := time.Now().Format("2006-01-02 15:04 MST")
	if result.EndedAt != nil {
		scanDate = result.EndedAt.Format("2006-01-02 15:04 MST")
	}
	reportID := fmt.Sprintf("SEKU-%d-%s", result.ID, time.Now().Format("20060102"))
	siteName := result.ScanTarget.Name
	if siteName == "" {
		siteName = result.ScanTarget.URL
	}
	siteNameShaped := ShapeArabic(siteName)

	// Tally severities + collect findings (ordered worst-first).
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
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := severityRankPDF(findings[i].Severity), severityRankPDF(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return findings[i].Score < findings[j].Score
	})

	overallRisk := "Informational"
	switch {
	case sevCounts["critical"] > 0:
		overallRisk = "Critical"
	case sevCounts["high"] > 0:
		overallRisk = "High"
	case sevCounts["medium"] > 0:
		overallRisk = "Medium"
	case sevCounts["low"] > 0:
		overallRisk = "Low"
	}
	riskColor := severityColorPDF(overallRisk)

	// --- confidential, page-numbered footer on every page ---
	pdf.AliasNbPages("{nb}")
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		setFont("", 7)
		ink(pdfMute)
		pdf.SetX(15)
		pdf.CellFormat(90, 6, "CONFIDENTIAL  ·  "+reportID, "", 0, "L", false, 0, "")
		pdf.SetX(105)
		pdf.CellFormat(90, 6, fmt.Sprintf("Page %d / {nb}", pdf.PageNo()), "", 0, "R", false, 0, "")
	})

	// running header for content pages (set after the cover)
	runningHeader := false
	pdf.SetHeaderFunc(func() {
		if !runningHeader {
			return
		}
		fill(pdfBrand)
		pdf.Rect(0, 0, 210, 15, "F")
		ink(pdfWhite)
		setFont("B", 9)
		pdf.SetXY(15, 4)
		pdf.CellFormat(120, 7, "Seku  ·  Security Assessment", "", 0, "L", false, 0, "")
		setFont("", 8)
		pdf.SetXY(75, 4)
		pdf.CellFormat(120, 7, trunc(result.ScanTarget.URL, 60), "", 0, "R", false, 0, "")
	})

	// ============================ COVER ============================
	pdf.AddPage()
	fill(pdfDarkBg)
	pdf.Rect(0, 0, 210, 150, "F")
	fill(pdfBrand)
	pdf.Rect(0, 150, 210, 2.5, "F")

	// brand + confidential badge
	ink(pdfWhite)
	setFont("B", 15)
	pdf.SetXY(15, 16)
	pdf.Cell(40, 8, "Seku")
	// CONFIDENTIAL badge (top-right)
	pdf.SetDrawColor(sevCrit[0], sevCrit[1], sevCrit[2])
	pdf.SetLineWidth(0.4)
	pdf.RoundedRect(150, 15, 45, 9, 1.5, "1234", "D")
	ink(sevCrit)
	setFont("B", 9)
	pdf.SetXY(150, 16.7)
	pdf.CellFormat(45, 6, "CONFIDENTIAL", "", 0, "C", false, 0, "")
	ink(pdfMute)
	setFont("", 9)
	pdf.SetXY(15, 25)
	pdf.Cell(0, 6, "Website Security Assessment")

	// title
	ink(pdfWhite)
	setFont("B", 30)
	pdf.SetXY(15, 52)
	pdf.Cell(0, 13, "Security Assessment")
	pdf.SetXY(15, 66)
	pdf.Cell(0, 13, "Report")

	setArabicFont("B", 16)
	ink([3]int{203, 213, 225})
	pdf.SetXY(15, 90)
	pdf.Cell(120, 9, siteNameShaped)
	setFont("", 10)
	ink([3]int{148, 170, 200})
	pdf.SetXY(15, 100)
	pdf.Cell(0, 6, result.ScanTarget.URL)

	// overall-risk badge (right)
	fill(riskColor)
	pdf.RoundedRect(140, 52, 55, 40, 4, "1234", "F")
	ink(pdfWhite)
	setFont("", 8)
	pdf.SetXY(140, 57)
	pdf.CellFormat(55, 5, "OVERALL RISK", "", 0, "C", false, 0, "")
	setFont("B", 18)
	pdf.SetXY(140, 63)
	pdf.CellFormat(55, 12, strings.ToUpper(overallRisk), "", 0, "C", false, 0, "")
	setFont("", 8)
	pdf.SetXY(140, 78)
	pdf.CellFormat(55, 6, fmt.Sprintf("Score %.0f/1000 · %s", result.OverallScore, grade), "", 0, "C", false, 0, "")

	// metadata block (light area under the dark band)
	ink(pdfInk)
	metaY := 162.0
	metaRows := [][2]string{
		{"Report ID", reportID},
		{"Target", result.ScanTarget.URL},
		{"Assessment date", scanDate},
		{"Assessment type", "Automated external web application scan"},
		{"Prepared by", "Seku Security Assessment Platform"},
		{"Overall risk", overallRisk + "  (Grade " + grade + " — " + gradeLabel(grade) + ")"},
	}
	for _, r := range metaRows {
		setFont("B", 9)
		ink(pdfGray)
		pdf.SetXY(15, metaY)
		pdf.Cell(45, 6, r[0])
		setFont("", 9)
		ink(pdfInk)
		pdf.SetXY(62, metaY)
		pdf.Cell(133, 6, trunc(r[1], 78))
		metaY += 8
	}

	// confidentiality notice
	metaY += 4
	pdf.SetDrawColor(225, 227, 233)
	pdf.Line(15, metaY, 195, metaY)
	metaY += 5
	ink(pdfGray)
	setFont("", 7.5)
	pdf.SetXY(15, metaY)
	pdf.MultiCell(180, 4.5,
		"This document contains confidential information about the security posture of the assessed system and is intended solely "+
			"for the recipient. It must not be distributed or disclosed without authorisation. Findings reflect the state of the target "+
			"at the time of assessment; severity ratings follow the CVSS v3.1 model.", "", "L", false)

	// From here on, every new page gets the running brand header.
	runningHeader = true

	// ============================ 1. EXECUTIVE SUMMARY ============================
	pdf.AddPage()
	y := 24.0
	y = sectionTitle(pdf, setFont, ink, "1. Executive Summary", y)

	// narrative
	ink([3]int{60, 64, 74})
	setFont("", 9.5)
	pdf.SetXY(15, y)
	narrative := fmt.Sprintf(
		"An automated external security assessment of %s was performed on %s. The application achieved an overall "+
			"security score of %.0f/1000 (grade %s), corresponding to an overall risk rating of %s. "+
			"The assessment identified %d finding(s) requiring attention across %d checks.",
		result.ScanTarget.URL, scanDate, result.OverallScore, grade, overallRisk, len(findings), len(checks))
	if sevCounts["critical"] > 0 || sevCounts["high"] > 0 {
		narrative += fmt.Sprintf(" Of these, %d are critical and %d are high severity and should be prioritised for immediate remediation.",
			sevCounts["critical"], sevCounts["high"])
	} else if len(findings) == 0 {
		narrative += " No failing or warning findings were detected at scan time."
	}
	pdf.MultiCell(180, 5, narrative, "", "L", false)
	y = pdf.GetY() + 4

	// Coverage caveat — never let a shallow scan read as "fully secure".
	if strings.TrimSpace(result.CoverageNote) != "" {
		fill([3]int{254, 243, 199}) // amber wash
		startY := y
		pdf.SetXY(19, y+2)
		ink([3]int{146, 64, 14})
		setFont("B", 8.5)
		pdf.MultiCell(172, 4.6, "LIMITED COVERAGE — "+result.CoverageNote, "", "L", false)
		endY := pdf.GetY() + 2
		// draw the wash behind the text we just wrote
		pdf.SetFillColor(254, 243, 199)
		pdf.RoundedRect(15, startY, 180, endY-startY, 2, "1234", "F")
		pdf.SetXY(19, startY+2)
		ink([3]int{146, 64, 14})
		setFont("B", 8.5)
		pdf.MultiCell(172, 4.6, "LIMITED COVERAGE — "+result.CoverageNote, "", "L", false)
		y = pdf.GetY() + 4
	} else {
		y += 2
	}

	// risk-summary table
	y = subTitle(pdf, setFont, ink, "Risk Summary", y)
	rows := []struct {
		label string
		count int
		color [3]int
	}{
		{"Critical", sevCounts["critical"], sevCrit},
		{"High", sevCounts["high"], sevHigh},
		{"Medium", sevCounts["medium"], sevMed},
		{"Low", sevCounts["low"], sevLow},
		{"Passed checks", passed, pdfGreen},
	}
	for _, r := range rows {
		fill(r.color)
		pdf.RoundedRect(15, y, 4, 7, 1, "1234", "F")
		ink(pdfInk)
		setFont("B", 9)
		pdf.SetXY(22, y+0.5)
		pdf.Cell(120, 6, r.label)
		setFont("B", 10)
		ink(r.color)
		pdf.SetXY(150, y+0.5)
		pdf.CellFormat(45, 6, fmt.Sprintf("%d", r.count), "", 0, "R", false, 0, "")
		y += 9
	}

	// ============================ 2. SCOPE & METHODOLOGY ============================
	y += 6
	if y > 230 {
		pdf.AddPage()
		y = 24
	}
	y = sectionTitle(pdf, setFont, ink, "2. Scope & Methodology", y)
	ink([3]int{60, 64, 74})
	setFont("", 9)
	pdf.SetXY(15, y)
	pdf.MultiCell(180, 5,
		"Scope: "+result.ScanTarget.URL+" (single external web target). The assessment was conducted as a non-intrusive, "+
			"automated black-box scan from the public internet. Testing covered transport security, HTTP security headers, "+
			"cookie flags, content-injection surfaces (XSS/SQLi/SSRF/redirects where enabled), exposed files and directories, "+
			"DNS/e-mail security, CMS exposure, and information disclosure.\n\n"+
			"Methodology: checks are aligned with the OWASP Top 10 and CWE taxonomy. Each finding is rated using the CVSS v3.1 "+
			"base metric bands (Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9). Findings are confirmed by the "+
			"scanner where possible; low-confidence checks are reported as advisory. Active exploitation, denial-of-service, and "+
			"intrusive fuzzing are out of scope for this automated pass.", "", "L", false)
	y = pdf.GetY() + 4

	// ============================ 3. FINDINGS OVERVIEW ============================
	pdf.AddPage()
	y = 24
	y = sectionTitle(pdf, setFont, ink, "3. Findings Overview", y)

	if len(findings) == 0 {
		fill(pdfLight)
		pdf.RoundedRect(15, y, 180, 18, 3, "1234", "F")
		ink(pdfGreen)
		setFont("B", 11)
		pdf.SetXY(20, y+5)
		pdf.Cell(0, 8, "No failing or warning findings were identified at scan time.")
	} else {
		// table header
		fill([3]int{237, 239, 243})
		pdf.RoundedRect(15, y, 180, 8, 1, "1234", "F")
		ink(pdfGray)
		setFont("B", 8)
		pdf.SetXY(18, y+1.5)
		pdf.Cell(20, 5, "ID")
		pdf.SetXY(40, y+1.5)
		pdf.Cell(95, 5, "FINDING")
		pdf.SetXY(140, y+1.5)
		pdf.CellFormat(24, 5, "SEVERITY", "", 0, "C", false, 0, "")
		pdf.SetXY(166, y+1.5)
		pdf.CellFormat(27, 5, "CVSS", "", 0, "C", false, 0, "")
		y += 10
		for i, ck := range findings {
			if y > 268 {
				pdf.AddPage()
				y = 24
			}
			sev := firstNonEmpty(strings.ToLower(ck.Severity), "low")
			col := severityColorPDF(sev)
			ink(pdfInk)
			setFont("B", 8)
			pdf.SetXY(18, y)
			pdf.Cell(22, 5, fmt.Sprintf("SEKU-%03d", i+1))
			setFont("", 8)
			pdf.SetXY(40, y)
			pdf.Cell(98, 5, trunc(ck.CheckName, 58))
			ink(col)
			setFont("B", 8)
			pdf.SetXY(140, y)
			pdf.CellFormat(24, 5, strings.ToUpper(sev), "", 0, "C", false, 0, "")
			ink(pdfGray)
			setFont("", 8)
			cvss := "—"
			if ck.CVSSScore > 0 {
				cvss = fmt.Sprintf("%.1f", ck.CVSSScore)
			}
			pdf.SetXY(166, y)
			pdf.CellFormat(27, 5, cvss, "", 0, "C", false, 0, "")
			y += 6.5
			pdf.SetDrawColor(235, 236, 240)
			pdf.Line(15, y-1, 195, y-1)
		}
	}

	// ============================ 4. DETAILED FINDINGS ============================
	if len(findings) > 0 {
		pdf.AddPage()
		y = 24
		y = sectionTitle(pdf, setFont, ink, "4. Detailed Findings", y)

		for i, ck := range findings {
			sev := firstNonEmpty(strings.ToLower(ck.Severity), "low")
			col := severityColorPDF(sev)
			// keep a finding header from splitting awkwardly
			if y > 240 {
				pdf.AddPage()
				y = 24
			}

			// finding title band
			fill([3]int{247, 248, 250})
			pdf.RoundedRect(15, y, 180, 12, 2, "1234", "F")
			fill(col)
			pdf.RoundedRect(15, y, 3, 12, 1, "1234", "F")
			ink(pdfInk)
			setFont("B", 10.5)
			pdf.SetXY(21, y+1.3)
			pdf.Cell(120, 6, fmt.Sprintf("SEKU-%03d  %s", i+1, trunc(ck.CheckName, 52)))
			// severity chip
			fill(col)
			pdf.RoundedRect(163, y+2.5, 27, 7, 1.5, "1234", "F")
			ink(pdfWhite)
			setFont("B", 7.5)
			pdf.SetXY(163, y+3.4)
			pdf.CellFormat(27, 5, strings.ToUpper(sev), "", 0, "C", false, 0, "")
			y += 15

			// metadata grid
			cvss := "N/A"
			if ck.CVSSScore > 0 {
				cvss = fmt.Sprintf("%.1f (%s)", ck.CVSSScore, firstNonEmpty(ck.CVSSRating, strings.Title(sev)))
			}
			owasp := firstNonEmpty(strings.TrimSpace(ck.OWASP+" "+ck.OWASPName), "—")
			cwe := firstNonEmpty(strings.TrimSpace(ck.CWE+" "+ck.CWEName), "—")
			catName := categoryNames[ck.Category]
			if catName == "" {
				catName = ck.Category
			}
			metaPairs := [][2]string{
				{"CVSS score", cvss},
				{"Category", catName},
				{"OWASP", owasp},
				{"CWE", cwe},
				{"Affected", result.ScanTarget.URL},
				{"Confidence", fmt.Sprintf("%d%%", ck.Confidence)},
			}
			for r := 0; r < len(metaPairs); r += 2 {
				ink(pdfGray)
				setFont("B", 7.5)
				pdf.SetXY(21, y)
				pdf.Cell(22, 5, metaPairs[r][0])
				ink(pdfInk)
				setFont("", 7.5)
				pdf.SetXY(44, y)
				pdf.Cell(58, 5, trunc(metaPairs[r][1], 34))
				if r+1 < len(metaPairs) {
					ink(pdfGray)
					setFont("B", 7.5)
					pdf.SetXY(108, y)
					pdf.Cell(22, 5, metaPairs[r+1][0])
					ink(pdfInk)
					setFont("", 7.5)
					pdf.SetXY(131, y)
					pdf.Cell(64, 5, trunc(metaPairs[r+1][1], 34))
				}
				y += 5.5
			}
			// CVSS vector (mono-ish, full width) if present
			if strings.TrimSpace(ck.CVSSVector) != "" {
				ink(pdfGray)
				setFont("B", 7.5)
				pdf.SetXY(21, y)
				pdf.Cell(22, 5, "Vector")
				ink([3]int{60, 64, 74})
				setFont("", 7.5)
				pdf.SetXY(44, y)
				pdf.Cell(151, 5, ck.CVSSVector)
				y += 6
			}
			y += 1

			blockLabel := func(label string) {
				if y > 262 {
					pdf.AddPage()
					y = 24
				}
				ink(col)
				setFont("B", 8.5)
				pdf.SetXY(21, y)
				pdf.Cell(0, 5, label)
				y += 5.5
			}
			blockBody := func(text string) {
				ink([3]int{70, 74, 84})
				setFont("", 8.5)
				pdf.SetXY(21, y)
				pdf.MultiCell(174, 4.6, text, "", "L", false)
				y = pdf.GetY() + 2
			}

			if msg := detailMessage(ck); msg != "" {
				blockLabel("Description")
				blockBody(trunc(msg, 600))
			}
			blockLabel("Impact")
			blockBody(impactStatement(sev))

			rem := ""
			if remediations != nil {
				rem = strings.TrimSpace(remediations[ck.CheckName])
			}
			if rem == "" {
				rem = "Review the affected configuration and apply the vendor-recommended hardening for this control. Re-scan after applying the change to confirm the finding is resolved."
			}
			blockLabel("Remediation")
			blockBody(trunc(rem, 700))

			// separator between findings
			y += 2
			pdf.SetDrawColor(225, 227, 233)
			pdf.SetLineWidth(0.3)
			pdf.Line(15, y, 195, y)
			y += 6
		}
	}

	// ============================ 5. CATEGORY SCORES ============================
	catGroups := map[string][]models.CheckResult{}
	for _, c := range checks {
		catGroups[c.Category] = append(catGroups[c.Category], c)
	}
	type catScore struct {
		cat   string
		score float64
		n     int
	}
	var secCats, qCats []catScore
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
		row := catScore{cat, s, len(cks)}
		if qualityCats[cat] {
			qCats = append(qCats, row)
		} else {
			secCats = append(secCats, row)
		}
	}
	worst := func(a []catScore) { sort.Slice(a, func(i, j int) bool { return a[i].score < a[j].score }) }
	worst(secCats)
	worst(qCats)

	pdf.AddPage()
	y = 24
	y = sectionTitle(pdf, setFont, ink, "5. Category Scores", y)

	drawTable := func(title string, rowsIn []catScore) {
		if len(rowsIn) == 0 {
			return
		}
		if y > 250 {
			pdf.AddPage()
			y = 24
		}
		y = subTitle(pdf, setFont, ink, title, y)
		for _, cs := range rowsIn {
			if y > 275 {
				pdf.AddPage()
				y = 24
			}
			name := categoryNames[cs.cat]
			if name == "" {
				name = cs.cat
			}
			pdf.SetFillColor(238, 240, 244)
			pdf.RoundedRect(15, y, 180, 8, 1, "1234", "F")
			bw := cs.score / 1000 * 180
			if bw < 2 {
				bw = 2
			}
			bc := scoreColorPDF(cs.score)
			pdf.SetFillColor(bc[0], bc[1], bc[2])
			pdf.RoundedRect(15, y, bw, 8, 1, "1234", "F")
			ink(pdfInk)
			setFont("B", 8)
			pdf.SetXY(18, y+1.4)
			pdf.Cell(110, 5, name)
			pdf.SetXY(150, y+1.4)
			pdf.CellFormat(20, 5, fmt.Sprintf("%.0f", cs.score), "", 0, "R", false, 0, "")
			pdf.SetXY(172, y+1.4)
			pdf.CellFormat(11, 5, scoreToGrade(cs.score), "", 0, "C", false, 0, "")
			pdf.SetXY(184, y+1.4)
			pdf.CellFormat(9, 5, fmt.Sprintf("%d", cs.n), "", 0, "C", false, 0, "")
			y += 10
		}
		y += 4
	}
	drawTable("Security domains", secCats)
	drawTable("Quality & performance (informational)", qCats)

	// ============================ 6. RISK RATING METHODOLOGY ============================
	if y > 200 {
		pdf.AddPage()
		y = 24
	} else {
		y += 4
	}
	y = sectionTitle(pdf, setFont, ink, "6. Risk Rating & Grading", y)
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
	y += 6
	ink(pdfGray)
	setFont("", 8)
	pdf.SetXY(15, y)
	pdf.MultiCell(180, 5,
		"Severity is derived from CVSS v3.1 base scores. The overall grade reflects a penalty model: the score starts at 1000 and "+
			"is reduced per finding by its severity and confidence, with a confirmed critical finding capping the grade at F. "+
			"Quality/performance domains are scored separately and never affect the security grade.", "", "L", false)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}
	return buf.Bytes(), nil
}

// sectionTitle draws a numbered section heading with an accent underline.
func sectionTitle(pdf *fpdf.Fpdf, setFont func(string, float64), ink func([3]int), title string, y float64) float64 {
	ink(pdfInk)
	setFont("B", 15)
	pdf.SetXY(15, y)
	pdf.Cell(0, 8, title)
	pdf.SetFillColor(pdfBrand[0], pdfBrand[1], pdfBrand[2])
	pdf.RoundedRect(15, y+9.5, 26, 1.4, 0.7, "1234", "F")
	return y + 15
}

func subTitle(pdf *fpdf.Fpdf, setFont func(string, float64), ink func([3]int), title string, y float64) float64 {
	ink(pdfBrand)
	setFont("B", 10.5)
	pdf.SetXY(15, y)
	pdf.Cell(0, 6, title)
	return y + 9
}

func countCategories(checks []models.CheckResult) int {
	cats := map[string]bool{}
	for _, c := range checks {
		cats[c.Category] = true
	}
	return len(cats)
}
