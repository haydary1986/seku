package main

import (
	"log"

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

	// Start server
	log.Println("Seku server starting on :8080")
	log.Fatal(app.Listen(":8080"))
}
