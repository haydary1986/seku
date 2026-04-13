package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"

	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/models"
	"vscan-mohesr/internal/scanner"
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

	var analysis models.AIAnalysis
	if err := config.DB.Where("scan_result_id = ? AND status = ?", resultID, "completed").
		Order("created_at desc").First(&analysis).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "No AI analysis found for this result"})
	}

	return c.JSON(analysis)
}

func buildAnalysisPrompt(result *models.ScanResult) string {
	prompt := fmt.Sprintf(`You are a cybersecurity expert. Analyze the following security scan results for the website "%s" (%s).
The current overall security score is %.1f/100.

Security Check Results:
`, result.ScanTarget.Name, result.ScanTarget.URL, result.OverallScore)

	for _, check := range result.Checks {
		prompt += fmt.Sprintf("\n- [%s] %s (Category: %s, Score: %.0f/100, Severity: %s)\n  Details: %s\n",
			check.Status, check.CheckName, check.Category, check.Score, check.Severity, check.Details)
	}

	prompt += `

Please provide:
1. **Executive Summary** - A brief overview of the security posture in 2-3 sentences.
2. **Critical Issues** - List the most critical vulnerabilities that need immediate attention, with clear explanations of why they are dangerous.
3. **Detailed Recommendations** - For EACH failed or warning check, provide:
   - What the issue is
   - Why it's dangerous (with real attack examples)
   - Exact step-by-step fix instructions (with code/config examples where applicable)
   - Expected impact on the score after fixing
4. **Quick Wins** - Simple fixes that will immediately improve the score significantly.
5. **Roadmap to 100%** - A prioritized action plan to achieve a perfect security score.

Format your response in Markdown. Be specific and technical - include actual configuration snippets, commands, and code examples.
Write the analysis in English but make it accessible for IT administrators who may not be security specialists.`

	return prompt
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
