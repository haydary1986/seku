package config

import (
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openDatabase() (*gorm.DB, error) {
	driver := os.Getenv("DB_DRIVER")
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	}

	switch driver {
	case "postgres":
		dsn := os.Getenv("DATABASE_URL")
		if dsn == "" {
			dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
				getEnvDefault("DB_HOST", "localhost"),
				getEnvDefault("DB_PORT", "5432"),
				getEnvDefault("DB_USER", "vscan"),
				getEnvDefault("DB_PASS", "vscan"),
				getEnvDefault("DB_NAME", "vscan"),
			)
		}
		db, err := gorm.Open(postgres.Open(dsn), gormConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
		}
		log.Println("Connected to PostgreSQL")
		return db, nil

	default:
		dbPath := os.Getenv("DB_PATH")
		if dbPath == "" {
			dbPath = "vscan.db"
		}
		db, err := gorm.Open(sqlite.Open(dbPath), gormConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to SQLite: %w", err)
		}
		log.Println("Connected to SQLite:", dbPath)
		return db, nil
	}
}

func configurePool(db *gorm.DB) {
	sqlDB, err := db.DB()
	if err != nil {
		return
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
}

func getEnvDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// PurgeSoftDeleted permanently removes any records that were previously
// soft-deleted (deleted_at IS NOT NULL). Runs once at startup to clean
// up phantom scan_targets / scan_results / check_results / ai_analyses
// that still linger from older deletes before hard-delete was introduced.
func PurgeSoftDeleted() {
	if DB == nil {
		return
	}
	tables := []string{
		"check_results",
		"ai_analyses",
		"scan_results",
		"scan_jobs",
		"scan_targets",
	}
	for _, t := range tables {
		if err := DB.Exec(fmt.Sprintf("DELETE FROM %s WHERE deleted_at IS NOT NULL", t)).Error; err != nil {
			log.Printf("PurgeSoftDeleted: %s: %v", t, err)
		}
	}
	log.Println("PurgeSoftDeleted: orphaned soft-deleted records removed")
}
