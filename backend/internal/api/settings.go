package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
	"seku/internal/scanner"
)

// --- Settings CRUD ---

func GetSettings(c *fiber.Ctx) error {
	var settings []models.Settings
	config.DB.Find(&settings)

	result := map[string]string{}
	for _, s := range settings {
		// Hide API keys partially
		if s.Key == "ai_api_key" && len(s.Value) > 8 {
			result[s.Key] = s.Value[:4] + "****" + s.Value[len(s.Value)-4:]
		} else {
			result[s.Key] = s.Value
		}
	}
	return c.JSON(result)
}

func UpdateSettings(c *fiber.Ctx) error {
	var req map[string]string
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	for key, value := range req {
		var setting models.Settings
		result := config.DB.Where("key = ?", key).First(&setting)
		if result.Error != nil {
			setting = models.Settings{Key: key, Value: value}
			config.DB.Create(&setting)
		} else {
			// Don't overwrite API key with masked value
			if key == "ai_api_key" && len(value) > 4 && value[4:8] == "****" {
				continue
			}
			config.DB.Model(&setting).Update("value", value)
		}

		// Sync proxy setting to pool
		if key == "proxy_enabled" {
			scanner.Pool.SetEnabled(value == "true")
		}
	}

	return c.JSON(fiber.Map{"message": "Settings updated successfully"})
}

func getSetting(key string) string {
	var setting models.Settings
	if err := config.DB.Where("key = ?", key).First(&setting).Error; err != nil {
		return ""
	}
	return setting.Value
}

// --- AI Analysis ---

func AnalyzeScanResult(c *fiber.Ctx) error {
	resultID := c.Params("id")
	if !CanAccessResult(c, resultID) {
		return c.Status(404).JSON(fiber.Map{"error": "Scan result not found"})
	}

	// Get scan result with checks
	var scanResult models.ScanResult
	if err := config.DB.Preload("ScanTarget").Preload("Checks").First(&scanResult, resultID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scan result not found"})
	}

	// Get AI settings
	aiProvider := getSetting("ai_provider")
	aiAPIKey := getSetting("ai_api_key")
	aiModel := getSetting("ai_model")
	aiBaseURL := getSetting("ai_base_url")

	if aiAPIKey == "" {
		return c.Status(400).JSON(fiber.Map{"error": "AI API key not configured. Go to Settings to configure."})
	}

	if aiProvider == "" {
		aiProvider = "deepseek"
	}
	if aiModel == "" {
		switch aiProvider {
		case "deepseek":
			aiModel = "deepseek-chat"
		case "openai":
			aiModel = "gpt-4o-mini"
		case "anthropic":
			aiModel = "claude-sonnet-4-6-20250514"
		case "google":
			aiModel = "gemini-2.0-flash"
		default:
			aiModel = "deepseek-chat"
		}
	}
	if aiBaseURL == "" {
		switch aiProvider {
		case "deepseek":
			aiBaseURL = "https://api.deepseek.com/v1"
		case "openai":
			aiBaseURL = "https://api.openai.com/v1"
		case "anthropic":
			aiBaseURL = "https://api.anthropic.com/v1"
		case "google":
			aiBaseURL = "https://generativelanguage.googleapis.com/v1beta"
		default:
			aiBaseURL = "https://api.deepseek.com/v1"
		}
	}

	// Build the prompt
	prompt := buildAnalysisPrompt(&scanResult)

	// Call AI API
	analysis, err := callAIAPI(aiBaseURL, aiAPIKey, aiModel, aiProvider, prompt)
	if err != nil {
		// Save failed analysis
		aiAnalysis := models.AIAnalysis{
			ScanResultID: scanResult.ID,
			Provider:     aiProvider,
			Analysis:     "Error: " + err.Error(),
			Status:       "failed",
		}
		config.DB.Create(&aiAnalysis)
		return c.Status(500).JSON(fiber.Map{"error": "AI analysis failed: " + err.Error()})
	}

	// Save successful analysis
	// Delete old analysis if exists
	config.DB.Where("scan_result_id = ?", scanResult.ID).Delete(&models.AIAnalysis{})

	aiAnalysis := models.AIAnalysis{
		ScanResultID: scanResult.ID,
		Provider:     aiProvider,
		Analysis:     analysis,
		Status:       "completed",
	}
	config.DB.Create(&aiAnalysis)

	return c.JSON(aiAnalysis)
}

func GetAIAnalysis(c *fiber.Ctx) error {
	resultID := c.Params("id")
	if !CanAccessResult(c, resultID) {
		return c.Status(404).JSON(fiber.Map{"error": "No AI analysis found for this result"})
	}

	var analysis models.AIAnalysis
	if err := config.DB.Where("scan_result_id = ? AND status = ?", resultID, "completed").
		Order("created_at desc").First(&analysis).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "No AI analysis found for this result"})
	}

	return c.JSON(analysis)
}

func buildAnalysisPrompt(result *models.ScanResult) string {
	// Separate real problems from already-secure checks so the model cannot
	// invent findings or report passing checks as issues (0–1000 score scale).
	var failing, passing strings.Builder
	for _, check := range result.Checks {
		line := fmt.Sprintf("- [%s] %s (Category: %s, Score: %.0f/1000, Severity: %s)\n  Details: %s\n",
			check.Status, check.CheckName, check.Category, check.Score, check.Severity, check.Details)
		if strings.EqualFold(check.Status, "pass") {
			passing.WriteString(line)
		} else {
			failing.WriteString(line)
		}
	}
	if failing.Len() == 0 {
		failing.WriteString("(none — every check passed)\n")
	}
	if passing.Len() == 0 {
		passing.WriteString("(none)\n")
	}

	return fmt.Sprintf(`You are a cybersecurity expert reviewing the REAL output of an automated scan for "%s" (%s). Overall score: %.0f/1000.

STRICT RULES — follow exactly, no exceptions:
- Base EVERY statement only on the scan data below. Never invent, assume, or add any finding, header, port, service, version, or CVE that is not explicitly present in the data.
- A check with status [pass] is CORRECTLY CONFIGURED. Never describe a passing check as missing, absent, weak, or an issue.
- Only items under "ISSUES TO ADDRESS" are problems. Never report anything from "ALREADY SECURE".
- If the data does not mention something, say nothing about it. Do not guess ports, headers, or software.
- Scores are on a 0–1000 scale; always write them as X/1000, never X/100.

ISSUES TO ADDRESS (status fail / warn / error):
%s
ALREADY SECURE (status pass — do NOT report these as issues):
%s

Respond in Markdown, based ONLY on the ISSUES above:
1. **Executive Summary** — 2–3 sentences on the actual posture; acknowledge what is already secure.
2. **Priority Issues** — for each item in "ISSUES TO ADDRESS", ordered by severity: what it is, why it matters, and an exact fix (config/code snippet). If there are none, state that the posture is strong and omit this section.
3. **Quick Wins** — the simplest of the fixes above.

Write in English, accessible to IT administrators. Do not fabricate issues, ports, or a "roadmap to 100" beyond what the data shows.`,
		result.ScanTarget.Name, result.ScanTarget.URL, result.OverallScore,
		failing.String(), passing.String())
}

func callAIAPI(baseURL, apiKey, model, provider, prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a cybersecurity expert specializing in web application security assessment. Provide detailed, actionable security recommendations.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"max_tokens":  4096,
		"temperature": 0.3,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := baseURL + "/chat/completions"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	switch provider {
	case "anthropic":
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	default:
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var aiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(body, &aiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(aiResp.Choices) == 0 {
		return "", fmt.Errorf("no response from AI")
	}

	return aiResp.Choices[0].Message.Content, nil
}

// --- Proxy Pool ---

func GetProxyStats(c *fiber.Ctx) error {
	return c.JSON(scanner.Pool.Stats())
}

func RefreshProxies(c *fiber.Ctx) error {
	go scanner.Pool.Refresh()
	return c.JSON(fiber.Map{"message": "Proxy refresh started"})
}

func callAIChatAPI(baseURL, apiKey, model, provider string, messages []map[string]string) (string, error) {
	reqBody := map[string]interface{}{
		"model":       model,
		"messages":    messages,
		"max_tokens":  4096,
		"temperature": 0.3,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := baseURL + "/chat/completions"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	switch provider {
	case "anthropic":
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	default:
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var aiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(body, &aiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(aiResp.Choices) == 0 {
		return "", fmt.Errorf("no response from AI")
	}

	return aiResp.Choices[0].Message.Content, nil
}
