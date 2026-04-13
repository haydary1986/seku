package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
	"seku/internal/scanner"
)

// GetScanPolicies returns the available scan policy presets
func GetScanPolicies(c *fiber.Ctx) error {
	return c.JSON(scanner.ScanPolicies)
}

// CreateGitHubIssue creates a GitHub issue for a failed check
func CreateGitHubIssue(c *fiber.Ctx) error {
	var req struct {
		CheckID   uint   `json:"check_id"`
		RepoOwner string `json:"repo_owner"`
		RepoName  string `json:"repo_name"`
		Token     string `json:"token"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.CheckID == 0 || req.RepoOwner == "" || req.RepoName == "" || req.Token == "" {
		return c.Status(400).JSON(fiber.Map{"error": "check_id, repo_owner, repo_name, and token are required"})
	}

	var check models.CheckResult
	if err := config.DB.First(&check, req.CheckID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Check result not found"})
	}

	title := fmt.Sprintf("[Seku] %s: %s (%s)", check.Severity, check.CheckName, check.OWASP)
	body := fmt.Sprintf(
		"## Security Finding\n\n"+
			"**Check:** %s\n"+
			"**Category:** %s\n"+
			"**Score:** %.0f/1000\n"+
			"**Severity:** %s\n"+
			"**CVSS:** %.1f (%s)\n"+
			"**OWASP:** %s\n"+
			"**CWE:** %s\n\n"+
			"### Details\n%s\n\n"+
			"---\n*Created by Seku*",
		check.CheckName, check.Category, check.Score, check.Severity,
		check.CVSSScore, check.CVSSRating, check.OWASP, check.CWE, check.Details,
	)

	payload := map[string]interface{}{
		"title":  title,
		"body":   body,
		"labels": []string{"security", check.Severity},
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to marshal request"})
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", req.RepoOwner, req.RepoName)
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create HTTP request"})
	}
	httpReq.Header.Set("Authorization", "Bearer "+req.Token)
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to reach GitHub API: " + err.Error()})
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return c.Status(resp.StatusCode).JSON(fiber.Map{"error": fmt.Sprintf("GitHub API returned status %d", resp.StatusCode)})
	}

	var ghResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to parse GitHub response"})
	}

	return c.JSON(fiber.Map{
		"issue_url":    ghResp["html_url"],
		"issue_number": ghResp["number"],
	})
}

// CreateJiraIssue creates a Jira ticket for a failed check
func CreateJiraIssue(c *fiber.Ctx) error {
	var req struct {
		CheckID    uint   `json:"check_id"`
		JiraURL    string `json:"jira_url"`
		ProjectKey string `json:"project_key"`
		Token      string `json:"token"`
		Email      string `json:"email"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.CheckID == 0 || req.JiraURL == "" || req.ProjectKey == "" || req.Token == "" || req.Email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "check_id, jira_url, project_key, token, and email are required"})
	}

	var check models.CheckResult
	if err := config.DB.First(&check, req.CheckID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Check result not found"})
	}

	priority := "Medium"
	switch check.Severity {
	case "critical":
		priority = "Highest"
	case "high":
		priority = "High"
	case "low":
		priority = "Low"
	}

	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project":  map[string]string{"key": req.ProjectKey},
			"summary":  fmt.Sprintf("[Seku] %s: %s", check.Severity, check.CheckName),
			"description": fmt.Sprintf("h2. Security Finding\n\n*Check:* %s\n*Category:* %s\n*Score:* %.0f/1000\n*CVSS:* %.1f\n*OWASP:* %s\n*CWE:* %s\n\nh3. Details\n%s",
				check.CheckName, check.Category, check.Score, check.CVSSScore, check.OWASP, check.CWE, check.Details),
			"issuetype": map[string]string{"name": "Bug"},
			"priority":  map[string]string{"name": priority},
			"labels":    []string{"seku", "security", check.Severity},
		},
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to marshal request"})
	}

	httpReq, err := http.NewRequest("POST", req.JiraURL+"/rest/api/3/issue", bytes.NewBuffer(jsonBody))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create HTTP request"})
	}
	httpReq.SetBasicAuth(req.Email, req.Token)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to reach Jira API: " + err.Error()})
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return c.Status(resp.StatusCode).JSON(fiber.Map{"error": fmt.Sprintf("Jira API returned status %d", resp.StatusCode)})
	}

	var jiraResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jiraResp); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to parse Jira response"})
	}

	return c.JSON(fiber.Map{
		"issue_key": jiraResp["key"],
		"issue_url": fmt.Sprintf("%s/browse/%s", req.JiraURL, jiraResp["key"]),
	})
}
