package api

import (
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func SetupRoutes(app *fiber.App) {
	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())

	allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
	if allowedOrigins == "" {
		allowedOrigins = "*"
	}
	app.Use(cors.New(cors.Config{
		AllowOrigins: allowedOrigins,
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
	}))

	// Health check (public)
	app.Get("/health", HealthCheck)

	// API routes
	api := app.Group("/api")

	// Public routes (no auth required)
	api.Post("/auth/login", Login)
	api.Get("/criteria", GetScanCriteria) // public page: scan criteria & scoring

	// Protected routes
	protected := api.Group("", AuthRequired())

	// Profile
	protected.Get("/auth/profile", GetProfile)
	protected.Put("/auth/password", ChangePassword)

	// Targets
	targets := protected.Group("/targets")
	targets.Get("/", GetTargets)
	targets.Post("/", CreateTarget)
	targets.Post("/bulk", CreateBulkTargets)
	targets.Put("/:id", UpdateTarget)
	targets.Delete("/:id", DeleteTarget)

	// Scan Jobs
	scans := protected.Group("/scans")
	scans.Get("/", GetScanJobs)
	scans.Get("/:id", GetScanJob)
	scans.Post("/start", StartScan)
	scans.Delete("/:id", DeleteScanJob)

	// Scan Results
	results := protected.Group("/results")
	results.Get("/:id", GetScanResult)

	// AI Analysis
	protected.Post("/ai/analyze/:id", AnalyzeScanResult)
	protected.Get("/ai/analysis/:id", GetAIAnalysis)

	// Dashboard & Leaderboard
	protected.Get("/dashboard", GetDashboardStats)
	protected.Get("/leaderboard", GetLeaderboard)

	// Admin-only routes
	admin := protected.Group("", AdminRequired())

	// User Management
	users := admin.Group("/users")
	users.Get("/", GetUsers)
	users.Post("/", CreateUser)
	users.Put("/:id", UpdateUser)
	users.Delete("/:id", DeleteUser)

	// Settings
	admin.Get("/settings", GetSettings)
	admin.Put("/settings", UpdateSettings)
}
