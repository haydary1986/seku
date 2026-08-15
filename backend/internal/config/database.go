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
		// WAL + busy_timeout are essential for concurrent scans: they turn most
		// "database is locked" errors into short waits and allow readers during writes.
		dsn := dbPath + "?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=on"
		db, err := gorm.Open(sqlite.Open(dsn), gormConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to SQLite: %w", err)
		}
		driverIsSQLite = true
		log.Println("Connected to SQLite (WAL):", dbPath)
		return db, nil
	}
}

// driverIsSQLite records whether the active driver is SQLite, so the pool can be
// limited to a single writer (SQLite has one writer regardless of connections).
var driverIsSQLite bool

func configurePool(db *gorm.DB) {
	sqlDB, err := db.DB()
	if err != nil {
		return
	}
	if driverIsSQLite {
		// SQLite has a single writer; one open connection avoids lock contention.
		sqlDB.SetMaxOpenConns(1)
	} else {
		sqlDB.SetMaxOpenConns(25)
	}
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
