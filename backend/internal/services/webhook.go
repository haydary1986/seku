package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"seku/internal/config"
	"seku/internal/models"
)

// SendScanCompletedWebhooks dispatches webhook notifications for a completed scan job.
func SendScanCompletedWebhooks(job *models.ScanJob, results []models.ScanResult) {
	var webhooks []models.Webhook
	config.DB.Where("organization_id = ? AND is_active = ?", job.OrganizationID, true).Find(&webhooks)

	for _, wh := range webhooks {
		events := strings.Split(wh.Events, ",")
		shouldSend := false
		for _, e := range events {
			if strings.TrimSpace(e) == "scan_completed" {
				shouldSend = true
			}
		}
		if !shouldSend {
			continue
		}

		go sendWebhook(wh, job, results)
	}
}

func sendWebhook(wh models.Webhook, job *models.ScanJob, results []models.ScanResult) {
	switch wh.Type {
	case "slack":
		sendSlackWebhook(wh.URL, job, results)
	case "telegram":
		sendTelegramWebhook(wh.URL, wh.Secret, job, results)
	case "discord":
		sendDiscordWebhook(wh.URL, job, results)
	case "custom":
		sendCustomWebhook(wh.URL, wh.Secret, job, results)
	}
}

func sendSlackWebhook(url string, job *models.ScanJob, results []models.ScanResult) {
	avgScore := calcAvgScore(results)
	grade := scoreToGrade(avgScore)

	// Build per-site summary lines (max 10)
	var siteLines []string
	limit := len(results)
	if limit > 10 {
		limit = 10
	}
	for _, r := range results[:limit] {
		g := scoreToGrade(r.OverallScore)
		siteLines = append(siteLines, fmt.Sprintf("- %s: %.0f/1000 (%s)", r.ScanTarget.URL, r.OverallScore, g))
	}
	if len(results) > 10 {
		siteLines = append(siteLines, fmt.Sprintf("_...and %d more_", len(results)-10))
	}

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]string{
				"type": "plain_text",
				"text": fmt.Sprintf("Seku: %s completed", job.Name),
			},
		},
		{
			"type": "section",
			"fields": []map[string]string{
				{"type": "mrkdwn", "text": fmt.Sprintf("*Targets:* %d", len(results))},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Avg Score:* %.0f/1000 (%s)", avgScore, grade)},
			},
		},
	}

	if len(siteLines) > 0 {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": strings.Join(siteLines, "\n"),
			},
		})
	}

	payload := map[string]interface{}{
		"blocks": blocks,
	}

	postJSON(url, payload, nil)
}

func sendTelegramWebhook(chatID, botToken string, job *models.ScanJob, results []models.ScanResult) {
	avgScore := calcAvgScore(results)
	grade := scoreToGrade(avgScore)

	var lines []string
	lines = append(lines, fmt.Sprintf("*Seku: %s completed*", escapeMarkdown(job.Name)))
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("Targets: %d", len(results)))
	lines = append(lines, fmt.Sprintf("Avg Score: %.0f/1000 (%s)", avgScore, grade))
	lines = append(lines, "")

	limit := len(results)
	if limit > 10 {
		limit = 10
	}
	for _, r := range results[:limit] {
		g := scoreToGrade(r.OverallScore)
		lines = append(lines, fmt.Sprintf("- %s: %.0f (%s)", escapeMarkdown(r.ScanTarget.URL), r.OverallScore, g))
	}
	if len(results) > 10 {
		lines = append(lines, fmt.Sprintf("...and %d more", len(results)-10))
	}

	text := strings.Join(lines, "\n")

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}

	postJSON(apiURL, payload, nil)
}

func sendDiscordWebhook(url string, job *models.ScanJob, results []models.ScanResult) {
	avgScore := calcAvgScore(results)
	grade := scoreToGrade(avgScore)

	// Build description with per-site results
	var descLines []string
	limit := len(results)
	if limit > 10 {
		limit = 10
	}
	for _, r := range results[:limit] {
		g := scoreToGrade(r.OverallScore)
		descLines = append(descLines, fmt.Sprintf("- %s: %.0f/1000 (%s)", r.ScanTarget.URL, r.OverallScore, g))
	}
	if len(results) > 10 {
		descLines = append(descLines, fmt.Sprintf("...and %d more", len(results)-10))
	}

	color := 0x5865F2 // discord blurple
	if avgScore >= 800 {
		color = 0x57F287 // green
	} else if avgScore >= 600 {
		color = 0xFEE75C // yellow
	} else if avgScore >= 400 {
		color = 0xED4245 // red
	} else {
		color = 0xED4245
	}

	embed := map[string]interface{}{
		"title":       fmt.Sprintf("Seku: %s completed", job.Name),
		"description": strings.Join(descLines, "\n"),
		"color":       color,
		"fields": []map[string]interface{}{
			{"name": "Targets", "value": fmt.Sprintf("%d", len(results)), "inline": true},
			{"name": "Avg Score", "value": fmt.Sprintf("%.0f/1000 (%s)", avgScore, grade), "inline": true},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}

	postJSON(url, payload, nil)
}

func sendCustomWebhook(url, secret string, job *models.ScanJob, results []models.ScanResult) {
	avgScore := calcAvgScore(results)

	type ResultSummary struct {
		URL   string  `json:"url"`
		Name  string  `json:"name"`
		Score float64 `json:"score"`
		Grade string  `json:"grade"`
	}

	var summaries []ResultSummary
	for _, r := range results {
		summaries = append(summaries, ResultSummary{
			URL:   r.ScanTarget.URL,
			Name:  r.ScanTarget.Name,
			Score: r.OverallScore,
			Grade: scoreToGrade(r.OverallScore),
		})
	}

	payload := map[string]interface{}{
		"event":        "scan_completed",
		"job_id":       job.ID,
		"job_name":     job.Name,
		"total_targets": len(results),
		"avg_score":    avgScore,
		"avg_grade":    scoreToGrade(avgScore),
		"results":      summaries,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
	}

	headers := map[string]string{}
	if secret != "" {
		headers["Authorization"] = "Bearer " + secret
	}

	postJSON(url, payload, headers)
}

// SendTestWebhook sends a test notification to a webhook.
func SendTestWebhook(wh models.Webhook) error {
	testJob := &models.ScanJob{
		Name: "Test Notification",
	}
	testJob.ID = 0

	testResults := []models.ScanResult{
		{
			OverallScore: 850,
			ScanTarget: models.ScanTarget{
				URL:  "https://example.edu.iq",
				Name: "Example University",
			},
		},
		{
			OverallScore: 620,
			ScanTarget: models.ScanTarget{
				URL:  "https://test.edu.iq",
				Name: "Test University",
			},
		},
	}

	sendWebhook(wh, testJob, testResults)
	return nil
}

// --- helpers ---

func calcAvgScore(results []models.ScanResult) float64 {
	if len(results) == 0 {
		return 0
	}
	total := 0.0
	for _, r := range results {
		total += r.OverallScore
	}
	return total / float64(len(results))
}

func postJSON(url string, payload interface{}, headers map[string]string) {
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[webhook] failed to marshal payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[webhook] failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[webhook] failed to send to %s: %v", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("[webhook] non-OK response from %s: %d", url, resp.StatusCode)
	}
}

func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"`", "\\`",
	)
	return replacer.Replace(s)
}
