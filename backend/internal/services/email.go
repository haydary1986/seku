package services

import (
	"bytes"
	"fmt"
	"log"
	"net/smtp"
	"strings"

	"seku/internal/config"
	"seku/internal/models"
)

// SendScanCompletedEmail dispatches email notifications for a completed scan job.
func SendScanCompletedEmail(job *models.ScanJob, results []models.ScanResult) {
	var emailConfig models.EmailConfig
	if err := config.DB.First(&emailConfig).Error; err != nil || !emailConfig.IsConfigured {
		return // Email not configured
	}

	var alerts []models.EmailAlert
	config.DB.Where("organization_id = ? AND is_active = ?", job.OrganizationID, true).Find(&alerts)

	for _, alert := range alerts {
		events := strings.Split(alert.Events, ",")
		for _, e := range events {
			if strings.TrimSpace(e) == "scan_completed" {
				go sendEmail(emailConfig, alert.Email, job, results)
				break
			}
		}
	}
}

func sendEmail(cfg models.EmailConfig, to string, job *models.ScanJob, results []models.ScanResult) {
	avgScore := 0.0
	for _, r := range results {
		avgScore += r.OverallScore
	}
	if len(results) > 0 {
		avgScore /= float64(len(results))
	}

	grade := scoreToGradeEmail(avgScore)

	subject := fmt.Sprintf("Seku Report: %s — Score %.0f/1000 (%s)", job.Name, avgScore, grade)

	var body bytes.Buffer
	body.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
<div style="background:linear-gradient(135deg,#4f46e5,#2563eb);color:white;padding:30px;border-radius:12px;text-align:center;">
    <h1 style="margin:0;">Seku Security Report</h1>
    <p style="margin:10px 0 0;opacity:0.8;">%s</p>
</div>
<div style="padding:20px;background:#f8fafc;border-radius:0 0 12px 12px;">
    <div style="text-align:center;margin:20px 0;">
        <span style="font-size:48px;font-weight:bold;color:%s;">%.0f</span>
        <span style="font-size:20px;color:#6b7280;">/1000</span>
        <div style="font-size:24px;font-weight:bold;color:%s;margin-top:5px;">Grade: %s</div>
    </div>
    <table style="width:100%%;border-collapse:collapse;margin:20px 0;">
        <tr style="background:#e5e7eb;"><th style="padding:8px;text-align:left;">Website</th><th style="padding:8px;text-align:right;">Score</th><th style="padding:8px;text-align:right;">Grade</th></tr>`,
		job.Name,
		gradeColor(grade), avgScore,
		gradeColor(grade), grade,
	))

	for _, r := range results {
		g := scoreToGradeEmail(r.OverallScore)
		body.WriteString(fmt.Sprintf(`
        <tr><td style="padding:8px;border-bottom:1px solid #e5e7eb;">%s</td>
        <td style="padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;font-weight:bold;">%.0f</td>
        <td style="padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;color:%s;font-weight:bold;">%s</td></tr>`,
			r.ScanTarget.URL, r.OverallScore, gradeColor(g), g))
	}

	body.WriteString(`
    </table>
    <div style="text-align:center;margin-top:20px;">
        <a href="https://sec.erticaz.com/dashboard" style="display:inline-block;padding:12px 30px;background:#4f46e5;color:white;border-radius:8px;text-decoration:none;font-weight:bold;">View Full Report</a>
    </div>
</div>
<p style="text-align:center;color:#9ca3af;font-size:12px;margin-top:20px;">
    Sent by Seku
</p>
</body></html>`)

	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)

	msg := fmt.Sprintf("From: %s <%s>\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s",
		cfg.FromName, cfg.FromEmail, to, subject, body.String())

	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	if err := smtp.SendMail(addr, auth, cfg.FromEmail, []string{to}, []byte(msg)); err != nil {
		log.Printf("[email] failed to send to %s: %v", to, err)
	}
}

// SendTestEmail sends a test email to verify SMTP configuration.
func SendTestEmail(cfg models.EmailConfig, to string) error {
	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)

	subject := "Seku: Test Email"
	htmlBody := `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
<div style="background:linear-gradient(135deg,#4f46e5,#2563eb);color:white;padding:30px;border-radius:12px;text-align:center;">
    <h1 style="margin:0;">Seku</h1>
    <p style="margin:10px 0 0;opacity:0.8;">Test Email</p>
</div>
<div style="padding:20px;background:#f8fafc;border-radius:0 0 12px 12px;text-align:center;">
    <p style="font-size:16px;color:#374151;">Your email configuration is working correctly.</p>
    <p style="color:#6b7280;">You will receive scan notifications at this address.</p>
</div>
</body></html>`

	msg := fmt.Sprintf("From: %s <%s>\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s",
		cfg.FromName, cfg.FromEmail, to, subject, htmlBody)

	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	return smtp.SendMail(addr, auth, cfg.FromEmail, []string{to}, []byte(msg))
}

func gradeColor(grade string) string {
	switch grade {
	case "A+", "A":
		return "#059669"
	case "B":
		return "#2563eb"
	case "C":
		return "#d97706"
	default:
		return "#dc2626"
	}
}

func scoreToGradeEmail(score float64) string {
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
