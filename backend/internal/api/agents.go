package api

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
)

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// AgentAuthRequired authenticates a local agent via its X-Agent-Token header.
func AgentAuthRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tok := strings.TrimSpace(c.Get("X-Agent-Token"))
		if tok == "" {
			return c.Status(401).JSON(fiber.Map{"error": "agent token required"})
		}
		var agent models.Agent
		if err := config.DB.Where("token = ?", tok).First(&agent).Error; err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "invalid agent token"})
		}
		c.Locals("agent", &agent)
		return c.Next()
	}
}

// ---------------------------------------------------------------- agent-facing

func AgentHeartbeat(c *fiber.Ctx) error {
	agent := c.Locals("agent").(*models.Agent)
	var body struct {
		OS      string `json:"os"`
		Version string `json:"version"`
	}
	_ = c.BodyParser(&body)
	now := time.Now()
	config.DB.Model(&models.Agent{}).Where("id = ?", agent.ID).Updates(map[string]interface{}{
		"last_seen": &now, "os": body.OS, "version": body.Version,
	})
	return c.JSON(fiber.Map{"ok": true})
}

// AgentPollJob returns the next pending job for this agent (or 204 if none).
func AgentPollJob(c *fiber.Ctx) error {
	agent := c.Locals("agent").(*models.Agent)
	now := time.Now()
	config.DB.Model(&models.Agent{}).Where("id = ?", agent.ID).Update("last_seen", &now)

	var job models.AgentJob
	if err := config.DB.Where("agent_id = ? AND status = ?", agent.ID, "pending").
		Order("created_at asc").First(&job).Error; err != nil {
		return c.SendStatus(204)
	}
	config.DB.Model(&job).Updates(map[string]interface{}{"status": "running", "started_at": &now})
	return c.JSON(fiber.Map{"id": job.ID, "target": job.Target, "policy": job.Policy})
}

// AgentPostResult stores the results the agent produced for a job.
func AgentPostResult(c *fiber.Ctx) error {
	agent := c.Locals("agent").(*models.Agent)
	var body struct {
		Status      string `json:"status"`
		ResultsJSON string `json:"results_json"`
		Findings    int    `json:"findings"`
		DurationSec int    `json:"duration_sec"`
		Error       string `json:"error"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	var job models.AgentJob
	if err := config.DB.First(&job, c.Params("id")).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "job not found"})
	}
	if job.AgentID != agent.ID {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	status := body.Status
	if status == "" {
		status = "done"
	}
	fin := time.Now()
	config.DB.Model(&job).Updates(map[string]interface{}{
		"status": status, "finished_at": &fin, "duration_sec": body.DurationSec,
		"findings": body.Findings, "results_json": body.ResultsJSON, "error": body.Error,
	})
	return c.JSON(fiber.Map{"ok": true})
}

// ---------------------------------------------------------------- admin-facing

// CreateAgent creates an agent and returns its token ONCE.
func CreateAgent(c *fiber.Ctx) error {
	var body struct {
		Name string `json:"name"`
	}
	_ = c.BodyParser(&body)
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "agent"
	}
	tok := randToken()
	agent := models.Agent{OrganizationID: GetUserOrgID(c), Name: name, Token: tok}
	config.DB.Create(&agent)
	return c.Status(201).JSON(fiber.Map{"id": agent.ID, "name": agent.Name, "token": tok})
}

type agentRow struct {
	ID       uint       `json:"id"`
	Name     string     `json:"name"`
	OS       string     `json:"os"`
	Version  string     `json:"version"`
	LastSeen *time.Time `json:"last_seen"`
	Online   bool       `json:"online"`
}

func ListAgents(c *fiber.Ctx) error {
	var agents []models.Agent
	config.DB.Where("organization_id = ?", GetUserOrgID(c)).Order("created_at desc").Find(&agents)
	now := time.Now()
	out := make([]agentRow, 0, len(agents))
	for _, a := range agents {
		online := a.LastSeen != nil && now.Sub(*a.LastSeen) < 2*time.Minute
		out = append(out, agentRow{a.ID, a.Name, a.OS, a.Version, a.LastSeen, online})
	}
	return c.JSON(out)
}

func DeleteAgent(c *fiber.Ctx) error {
	config.DB.Where("id = ? AND organization_id = ?", c.Params("id"), GetUserOrgID(c)).Delete(&models.Agent{})
	return c.JSON(fiber.Map{"ok": true})
}

// EnqueueAgentScan queues a scan for a specific agent to run locally.
func EnqueueAgentScan(c *fiber.Ctx) error {
	var agent models.Agent
	if err := config.DB.Where("id = ? AND organization_id = ?", c.Params("id"), GetUserOrgID(c)).First(&agent).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "agent not found"})
	}
	var body struct {
		Target string `json:"target"`
		Policy string `json:"policy"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	target := strings.TrimSpace(body.Target)
	if target == "" || strings.ContainsAny(target, " \t\r\n") {
		return c.Status(400).JSON(fiber.Map{"error": "provide a valid target (URL or IP, no spaces)"})
	}
	policy := body.Policy
	if policy != "light" && policy != "standard" && policy != "deep" {
		policy = "standard"
	}
	job := models.AgentJob{
		AgentID: agent.ID, OrganizationID: GetUserOrgID(c),
		Target: target, Policy: policy, Status: "pending",
	}
	config.DB.Create(&job)
	return c.Status(201).JSON(job)
}

type agentJobRow struct {
	ID          uint      `json:"id"`
	AgentID     uint      `json:"agent_id"`
	Target      string    `json:"target"`
	Policy      string    `json:"policy"`
	Status      string    `json:"status"`
	DurationSec int       `json:"duration_sec"`
	Findings    int       `json:"findings"`
	CreatedAt   time.Time `json:"created_at"`
}

func ListAgentJobs(c *fiber.Ctx) error {
	var jobs []models.AgentJob
	config.DB.Where("organization_id = ?", GetUserOrgID(c)).Order("created_at desc").Limit(100).Find(&jobs)
	out := make([]agentJobRow, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, agentJobRow{j.ID, j.AgentID, j.Target, j.Policy, j.Status, j.DurationSec, j.Findings, j.CreatedAt})
	}
	return c.JSON(out)
}

func GetAgentJob(c *fiber.Ctx) error {
	var job models.AgentJob
	if err := config.DB.Where("id = ? AND organization_id = ?", c.Params("id"), GetUserOrgID(c)).First(&job).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	return c.JSON(job)
}
