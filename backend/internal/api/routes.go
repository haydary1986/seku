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

	// CSRF Protection: validate Origin/Referer on state-changing requests
	app.Use(csrfProtection())

	// Audit logging for state-changing operations
	app.Use(auditMiddleware())

	allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
	if allowedOrigins == "" {
		allowedOrigins = "*"
	}
	app.Use(cors.New(cors.Config{
		AllowOrigins: allowedOrigins,
		AllowHeaders: "Origin, Content-Type, Accept, Authorization, X-API-Key",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
	}))

	// Health check (public)
	app.Get("/health", HealthCheck)

	// SEO: dynamic sitemap and robots
	app.Get("/sitemap.xml", GenerateSitemap)
	app.Get("/robots.txt", GenerateRobots)

	// API routes
	api := app.Group("/api")

	// Public routes (no auth required)
	api.Post("/auth/login", Login)
	api.Post("/auth/register", Register)
	api.Get("/criteria", GetScanCriteria) // public page: scan criteria & scoring
	api.Get("/plans", GetPlans)           // public: plan details with scan categories
	api.Get("/docs", GetAPIDocs)          // public: API documentation

	// Protected routes
	protected := api.Group("", AuthRequired())

	// Profile
	protected.Get("/auth/profile", GetProfile)
	protected.Put("/auth/profile", UpdateProfile)
	protected.Get("/auth/organization", GetMyOrganization)
	protected.Put("/auth/password", ChangePassword)

	// Upgrade Requests
	protected.Post("/upgrade/request", RequestUpgrade)
	protected.Get("/upgrade/requests", GetMyUpgradeRequests)

	// Targets
	targets := protected.Group("/targets")
	targets.Get("/", GetTargets)
	targets.Post("/", CreateTarget)
	targets.Post("/bulk", CreateBulkTargets)
	targets.Put("/:id", UpdateTarget)
	targets.Delete("/:id", DeleteTarget)
	targets.Post("/cleanup-dead", CleanupDeadTargets)

	// Score History & Timeline
	protected.Get("/targets/:id/history", GetScoreHistory)
	protected.Get("/targets/:id/timeline", GetTimelineComparison)

	// Domain Verification
	protected.Post("/targets/:id/verify", InitiateVerification)
	protected.Get("/targets/:id/verify", GetVerificationStatus)
	protected.Put("/targets/:id/verify", CheckVerification)

	// API Keys
	protected.Post("/api-keys", GenerateAPIKey)
	protected.Get("/api-keys", ListAPIKeys)
	protected.Delete("/api-keys/:id", RevokeAPIKey)

	// Scan Jobs
	scans := protected.Group("/scans")
	scans.Get("/", GetScanJobs)
	scans.Get("/:id", GetScanJob)
	scans.Post("/start", StartScan)
	scans.Post("/:id/cancel", CancelScan)
	scans.Delete("/:id", DeleteScanJob)

	// Scan Results
	results := protected.Group("/results")
	results.Get("/:id", GetScanResult)
	results.Get("/:id/pdf", GeneratePDFReport)
	results.Get("/:id/sarif", ExportSARIF)
	results.Get("/:id/compliance", GetComplianceReport)
	results.Get("/:id/upgrades", GetUpgradeSuggestions)
	results.Get("/:id/csv", ExportCSV)
	results.Get("/:id/fix-priority", GetFixPriority)

	// AI Analysis
	protected.Post("/ai/analyze/:id", AnalyzeScanResult)
	protected.Get("/ai/analysis/:id", GetAIAnalysis)

	// AI Chat
	protected.Post("/ai/chat", ChatWithAI)

	// Dashboard & Leaderboard
	protected.Get("/dashboard", GetDashboardStats)
	protected.Get("/dashboard/enhanced", GetDashboardEnhanced)
	protected.Get("/leaderboard", GetLeaderboard)
	protected.Get("/leaderboard/csv", ExportLeaderboardCSV)
	protected.Get("/compare", CompareScanResults)

	// Domain Discovery (internet search)
	protected.Get("/discover/domain", DiscoverDomains)

	// Data Leak Scanner (standalone — not part of main scan)
	protected.Post("/data-leak/scan", RunDataLeakScan)
	protected.Get("/data-leak/results", GetDataLeakResults)

	// Remediation Guides
	protected.Get("/remediation", GetRemediationGuide)

	// CVE Feed
	protected.Get("/cve/search", SearchCVEs)

	// Scan Policies
	protected.Get("/scan-policies", GetScanPolicies)

	// Integrations (GitHub / Jira issue creation)
	protected.Post("/integrations/github/issue", CreateGitHubIssue)
	protected.Post("/integrations/jira/issue", CreateJiraIssue)

	// Tags
	tags := protected.Group("/tags")
	tags.Get("/", GetTags)
	tags.Post("/", CreateTag)
	tags.Delete("/:id", DeleteTag)
	tags.Post("/assign", TagTarget)
	tags.Delete("/assign/:target_id/:tag_id", UntagTarget)
	tags.Get("/:id/targets", GetTargetsByTag)

	// Target Tags (per target)
	protected.Get("/targets/:id/tags", GetTargetTags)

	// Email Alerts (user)
	protected.Get("/alerts", GetMyAlerts)
	protected.Put("/alerts", UpdateMyAlerts)

	// Webhooks
	webhooks := protected.Group("/webhooks")
	webhooks.Get("/", GetWebhooks)
	webhooks.Post("/", CreateWebhook)
	webhooks.Put("/:id", UpdateWebhook)
	webhooks.Delete("/:id", DeleteWebhook)
	webhooks.Post("/:id/test", TestWebhook)

	// Scheduled Scans
	schedules := protected.Group("/schedules")
	schedules.Get("/", GetSchedules)
	schedules.Post("/", CreateSchedule)
	schedules.Put("/:id", UpdateSchedule)
	schedules.Delete("/:id", DeleteSchedule)
	schedules.Put("/:id/toggle", ToggleSchedule)

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

	// SEO settings (admin)
	admin.Get("/seo", GetSEOSettings)

	// Proxy Pool (admin)
	admin.Get("/proxy/stats", GetProxyStats)
	admin.Post("/proxy/refresh", RefreshProxies)

	// Email Config (admin)
	admin.Get("/email-config", GetEmailConfig)
	admin.Put("/email-config", UpdateEmailConfig)
	admin.Post("/email-config/test", TestEmailConfig)

	// Upgrade Request Management (admin)
	admin.Get("/upgrade/all", GetAllUpgradeRequests)
	admin.Put("/upgrade/:id/approve", ApproveUpgrade)
	admin.Put("/upgrade/:id/reject", RejectUpgrade)

	// Purge all scan data (admin)
	admin.Post("/purge-scans", PurgeAllScans)

	// Administrative Directives (admin)
	admin.Get("/directives", GenerateDirectives)
}
