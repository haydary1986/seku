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

	// Ensure the configured admin user exists with role="admin".
	// Runs on every startup so redeployments onto an existing DB still
	// guarantee there is a working system administrator.
	username := os.Getenv("SEKU_ADMIN_USER")
	password := os.Getenv("SEKU_ADMIN_PASSWORD")
	if username == "" {
		username = "haydary1986"
	}
	if password == "" {
		password = "Sakina1990"
	}

	// Get default org (must exist — created above)
	var org models.Organization
	DB.First(&org)

	var admin models.User
	err = DB.Where("username = ?", username).First(&admin).Error
	if err != nil {
		// User doesn't exist → create
		hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		admin = models.User{
			Username: username,
			Password: string(hashed),
			FullName: "System Administrator",
			Email:    "admin@seku.dev",
			Role:     "admin",
			IsActive: true,
		}
		DB.Create(&admin)

		DB.Create(&models.OrgMembership{
			UserID:         admin.ID,
			OrganizationID: org.ID,
			Role:           "owner",
		})
		log.Printf("Default admin user created (username: %s)", username)
	} else {
		// User exists → ensure role=admin + active (self-heal)
		needsUpdate := false
		if admin.Role != "admin" {
			admin.Role = "admin"
			needsUpdate = true
		}
		if !admin.IsActive {
			admin.IsActive = true
			needsUpdate = true
		}
		if needsUpdate {
			DB.Save(&admin)
			log.Printf("Admin user %s self-healed: role=admin, active=true", username)
		}

		// Ensure org membership exists
		var membership models.OrgMembership
		if err := DB.Where("user_id = ? AND organization_id = ?", admin.ID, org.ID).First(&membership).Error; err != nil {
			DB.Create(&models.OrgMembership{
				UserID:         admin.ID,
				OrganizationID: org.ID,
				Role:           "owner",
			})
			log.Printf("Admin user %s: org membership created", username)
		}
	}

	log.Println("Database initialized successfully")
}
