package main

import (
	"log"
	"os"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"

	"seku/internal/api"
	"seku/internal/config"
	"seku/internal/scanner"
	"seku/internal/scheduler"
	"seku/internal/services"
	"seku/internal/ws"
)

func main() {
	// Initialize database
	config.InitDatabase()

	// Purge orphaned soft-deleted records (one-time cleanup per startup)
	config.PurgeSoftDeleted()

	// Seed universities
	config.SeedUniversities()

	// Start scheduler
	scheduler.Start()

	// Start CVE auto-updater (background, every 12 hours)
	services.StartCVEUpdater()

	// Start proxy pool updater (background, every 30 minutes)
	scanner.Pool.LoadSettingsFromDB()
	scanner.Pool.StartUpdater()

	// Resume any scan jobs that were interrupted by restart
	scanner.ResumeInterruptedJobs()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "Seku v1.0",
	})

	// Setup routes
	api.SetupRoutes(app)

	// WebSocket upgrade middleware
	app.Use("/ws", func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})
	app.Get("/ws/scan", websocket.New(ws.HandleWebSocket))

	// Start server (PORT env overrides default 8080)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Seku server starting on :%s", port)
	log.Fatal(app.Listen(":" + port))
}
