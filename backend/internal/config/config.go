package config

import (
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"seku/internal/models"
)

var DB *gorm.DB

func InitDatabase() {
	var err error
	DB, err = openDatabase()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	configurePool(DB)

	err = DB.AutoMigrate(
		&models.User{},
		&models.Organization{},
		&models.OrgMembership{},
		&models.Settings{},
		&models.AIAnalysis{},
		&models.ScanTarget{},
		&models.ScanJob{},
		&models.ScanResult{},
		&models.CheckResult{},
		&models.AuditLog{},
		&models.RefreshToken{},
		&models.APIKey{},
		&models.ScheduledScan{},
		&models.Subscription{},
		&models.NotificationPreference{},
		&models.UpgradeRequest{},
		&models.DomainVerification{},
		&models.ScanTag{},
		&models.TargetTag{},
		&models.Webhook{},
		&models.EmailConfig{},
		&models.EmailAlert{},
	)
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Create default org if none exists
	var orgCount int64
	DB.Model(&models.Organization{}).Count(&orgCount)
	if orgCount == 0 {
		org := models.Organization{
			Name:       "Seku",
			Slug:       "seku",
			Plan:       "enterprise",
			MaxTargets: 9999,
			MaxScans:   9999,
			IsActive:   true,
		}
		DB.Create(&org)
		log.Println("Default organization created: Seku")
	}

	// Create default admin if no users exist
	var userCount int64
	DB.Model(&models.User{}).Count(&userCount)
	if userCount == 0 {
		// Read from env vars or use defaults
		username := os.Getenv("SEKU_ADMIN_USER")
		password := os.Getenv("SEKU_ADMIN_PASSWORD")
		if username == "" {
			username = "haydary1986"
		}
		if password == "" {
			password = "Sakina1990"
		}

		hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		// Get default org
		var org models.Organization
		DB.First(&org)

		admin := models.User{
			Username: username,
			Password: string(hashed),
			FullName: "System Administrator",
			Email:    "admin@seku.dev",
			Role:     "admin",
			IsActive: true,
		}
		DB.Create(&admin)

		// Create membership
		membership := models.OrgMembership{
			UserID:         admin.ID,
			OrganizationID: org.ID,
			Role:           "owner",
		}
		DB.Create(&membership)

		log.Printf("Default admin user created (username: %s)", username)
	}

	log.Println("Database initialized successfully")
}
