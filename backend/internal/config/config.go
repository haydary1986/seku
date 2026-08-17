package config

import (
	crand "crypto/rand"
	"encoding/base64"
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
		&models.NucleiRun{},
		&models.Agent{},
		&models.AgentJob{},
		&models.DownloadStat{},
		&models.DeepScanOrder{},
		&models.ScanChange{},
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

	// --- System administrator bootstrap (hardened) --------------------------
	// SECURITY: earlier builds shipped a hardcoded admin password. That is a
	// full-takeover backdoor (admin bypasses org scoping, domain verification,
	// the SSRF host guard, and payment). We NEVER ship a usable default:
	//   • username may come from SEKU_ADMIN_USER (a username is not a secret);
	//   • the password MUST come from SEKU_ADMIN_PASSWORD, else a strong random
	//     one is generated and logged ONCE;
	//   • any admin still using the old shipped password is force-rotated on boot.
	username := os.Getenv("SEKU_ADMIN_USER")
	if username == "" {
		username = "haydary1986" // username only — not a secret
	}
	envPassword := os.Getenv("SEKU_ADMIN_PASSWORD")

	// The password that shipped hardcoded in earlier builds. Kept ONLY to detect
	// and rotate away from it; it is already public and unusable once rotated.
	const compromisedDefault = "Sakina1990"

	newRandomPassword := func() string {
		b := make([]byte, 18)
		if _, e := crand.Read(b); e != nil {
			return "CHANGE-ME-" + base64.RawURLEncoding.EncodeToString([]byte(username))
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}

	var org models.Organization
	DB.First(&org)

	var admin models.User
	err = DB.Where("username = ?", username).First(&admin).Error
	if err != nil {
		// First run → create the admin (env password, or a generated one).
		pw, generated := envPassword, false
		if pw == "" {
			pw, generated = newRandomPassword(), true
		}
		hashed, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		admin = models.User{
			Username: username, Password: string(hashed),
			FullName: "System Administrator", Email: "admin@seku.dev",
			Role: "admin", IsActive: true,
		}
		DB.Create(&admin)
		DB.Create(&models.OrgMembership{UserID: admin.ID, OrganizationID: org.ID, Role: "owner"})
		if generated {
			log.Printf("SECURITY: admin %q created with a GENERATED password: %s — store it now and set SEKU_ADMIN_PASSWORD.", username, pw)
		} else {
			log.Printf("Admin user %q created from SEKU_ADMIN_PASSWORD.", username)
		}
	} else {
		needsUpdate := false
		if admin.Role != "admin" {
			admin.Role = "admin"
			needsUpdate = true
		}
		if !admin.IsActive {
			admin.IsActive = true
			needsUpdate = true
		}
		// Force-rotate off the compromised shipped password (auto-remediation).
		// A password the operator already changed in-app is left untouched.
		if bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(compromisedDefault)) == nil {
			pw, generated := envPassword, false
			if pw == "" {
				pw, generated = newRandomPassword(), true
			}
			hashed, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
			admin.Password = string(hashed)
			needsUpdate = true
			if generated {
				log.Printf("SECURITY: admin %q used the compromised built-in password; rotated to a GENERATED password: %s — store it and set SEKU_ADMIN_PASSWORD.", username, pw)
			} else {
				log.Printf("SECURITY: admin %q rotated off the compromised built-in password using SEKU_ADMIN_PASSWORD.", username)
			}
		}
		if needsUpdate {
			DB.Save(&admin)
		}

		// Ensure org membership exists
		var membership models.OrgMembership
		if err := DB.Where("user_id = ? AND organization_id = ?", admin.ID, org.ID).First(&membership).Error; err != nil {
			DB.Create(&models.OrgMembership{UserID: admin.ID, OrganizationID: org.ID, Role: "owner"})
			log.Printf("Admin user %s: org membership created", username)
		}
	}

	log.Println("Database initialized successfully")
}
