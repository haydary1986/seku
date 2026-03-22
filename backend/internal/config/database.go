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
