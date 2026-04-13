package api

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
	"seku/internal/scheduler"
)

// GetSchedules lists all scheduled scans.
func GetSchedules(c *fiber.Ctx) error {
	var schedules []models.ScheduledScan
	config.DB.Order("created_at desc").Find(&schedules)
	return c.JSON(schedules)
}

// CreateSchedule creates a new scheduled scan.
func CreateSchedule(c *fiber.Ctx) error {
	var req struct {
		Name      string `json:"name"`
		TargetIDs []uint `json:"target_ids"`
		Schedule  string `json:"schedule"`
		DayOfWeek int    `json:"day_of_week"`
		HourUTC   int    `json:"hour_utc"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}
	if req.Name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Name is required"})
	}
	if len(req.TargetIDs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "At least one target is required"})
	}
	if req.Schedule != "daily" && req.Schedule != "weekly" && req.Schedule != "monthly" {
		return c.Status(400).JSON(fiber.Map{"error": "Schedule must be daily, weekly, or monthly"})
	}

	targetIDsJSON, _ := json.Marshal(req.TargetIDs)

	nextRun := scheduler.CalculateNextRun(req.Schedule, req.DayOfWeek, req.HourUTC)

	sched := models.ScheduledScan{
		Name:      req.Name,
		TargetIDs: string(targetIDsJSON),
		Schedule:  req.Schedule,
		DayOfWeek: req.DayOfWeek,
		HourUTC:   req.HourUTC,
		IsActive:  true,
		NextRunAt: &nextRun,
		CreatedBy: UserID(c),
	}
	config.DB.Create(&sched)
	return c.Status(201).JSON(sched)
}

// UpdateSchedule updates an existing scheduled scan.
func UpdateSchedule(c *fiber.Ctx) error {
	id := c.Params("id")
	var sched models.ScheduledScan
	if err := config.DB.First(&sched, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scheduled scan not found"})
	}

	var req struct {
		Name      string `json:"name"`
		TargetIDs []uint `json:"target_ids"`
		Schedule  string `json:"schedule"`
		DayOfWeek int    `json:"day_of_week"`
		HourUTC   int    `json:"hour_utc"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.Name != "" {
		sched.Name = req.Name
	}
	if len(req.TargetIDs) > 0 {
		targetIDsJSON, _ := json.Marshal(req.TargetIDs)
		sched.TargetIDs = string(targetIDsJSON)
	}
	if req.Schedule == "daily" || req.Schedule == "weekly" || req.Schedule == "monthly" {
		sched.Schedule = req.Schedule
	}
	sched.DayOfWeek = req.DayOfWeek
	sched.HourUTC = req.HourUTC

	nextRun := scheduler.CalculateNextRun(sched.Schedule, sched.DayOfWeek, sched.HourUTC)
	sched.NextRunAt = &nextRun

	config.DB.Save(&sched)
	return c.JSON(sched)
}

// DeleteSchedule removes a scheduled scan.
func DeleteSchedule(c *fiber.Ctx) error {
	id := c.Params("id")
	var sched models.ScheduledScan
	if err := config.DB.First(&sched, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scheduled scan not found"})
	}
	config.DB.Delete(&sched)
	return c.JSON(fiber.Map{"message": "Scheduled scan deleted"})
}

// ToggleSchedule toggles the is_active flag of a scheduled scan.
func ToggleSchedule(c *fiber.Ctx) error {
	id := c.Params("id")
	var sched models.ScheduledScan
	if err := config.DB.First(&sched, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Scheduled scan not found"})
	}

	sched.IsActive = !sched.IsActive

	// Recalculate next run when re-activating
	if sched.IsActive {
		nextRun := scheduler.CalculateNextRun(sched.Schedule, sched.DayOfWeek, sched.HourUTC)
		sched.NextRunAt = &nextRun
	} else {
		sched.NextRunAt = (*time.Time)(nil)
	}

	config.DB.Save(&sched)
	return c.JSON(sched)
}
