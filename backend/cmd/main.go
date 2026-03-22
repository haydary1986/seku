package main

import (
	"log"

	"github.com/gofiber/fiber/v2"

	"vscan-mohesr/internal/api"
	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/scheduler"
)

func main() {
	// Initialize database
	config.InitDatabase()

	// Seed universities from MOHESR list
	config.SeedUniversities()

	// Start scheduler
	scheduler.Start()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "VScan-MOHESR v1.0",
	})

	// Setup routes
	api.SetupRoutes(app)

	// Start server
	log.Println("VScan-MOHESR server starting on :8080")
	log.Fatal(app.Listen(":8080"))
}
