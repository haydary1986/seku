package models

import (
	"time"

	"gorm.io/gorm"
)

// --- Auth & Organization ---

type User struct {
	gorm.Model
	Username string `json:"username" gorm:"uniqueIndex;not null"`
	Password string `json:"-" gorm:"not null"`
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Role     string `json:"role" gorm:"default:user"` // admin, user
	IsActive bool   `json:"is_active" gorm:"default:true"`
}

type Organization struct {
	gorm.Model
	Name       string `json:"name" gorm:"not null"`
	Slug       string `json:"slug" gorm:"uniqueIndex;not null"`
	LogoURL    string `json:"logo_url"`
	Plan       string `json:"plan" gorm:"default:free"` // free, basic, pro, enterprise
	MaxTargets int    `json:"max_targets" gorm:"default:5"`
	MaxScans   int    `json:"max_scans" gorm:"default:10"`
	IsActive   bool   `json:"is_active" gorm:"default:true"`
}

type OrgMembership struct {
	gorm.Model
	UserID         uint   `json:"user_id" gorm:"not null"`
	OrganizationID uint   `json:"organization_id" gorm:"not null"`
	Role           string `json:"role" gorm:"default:member"` // owner, admin, member, viewer
	User           User   `json:"user" gorm:"foreignKey:UserID"`
}

type RefreshToken struct {
	gorm.Model
	Token     string    `json:"-" gorm:"uniqueIndex;not null"`
	UserID    uint      `json:"user_id" gorm:"not null"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked" gorm:"default:false"`
}

type APIKey struct {
	gorm.Model
	OrganizationID uint       `json:"organization_id" gorm:"not null"`
	UserID         uint       `json:"user_id" gorm:"not null"`
	Name           string     `json:"name" gorm:"not null"`
	KeyPrefix      string     `json:"key_prefix"` // first 8 chars
	KeyHash        string     `json:"-"`           // bcrypt hash
	LastUsedAt     *time.Time `json:"last_used_at"`
	ExpiresAt      *time.Time `json:"expires_at"`
	Scopes         string     `json:"scopes"` // JSON array
}

type AuditLog struct {
	gorm.Model
	OrganizationID uint   `json:"organization_id"`
	UserID         uint   `json:"user_id"`
	Action         string `json:"action"`        // scan.create, target.delete, etc.
	ResourceType   string `json:"resource_type"`
	ResourceID     uint   `json:"resource_id"`
	Details        string `json:"details"`
	IPAddress      string `json:"ip_address"`
	UserAgent      string `json:"user_agent"`
}

// --- Billing ---

type Subscription struct {
	gorm.Model
	OrganizationID     uint       `json:"organization_id" gorm:"not null"`
	Plan               string     `json:"plan" gorm:"default:free"`
	Status             string     `json:"status" gorm:"default:active"` // active, canceled, past_due, trialing
	StripeCustomerID   string     `json:"stripe_customer_id"`
	StripeSubID        string     `json:"stripe_sub_id"`
	CurrentPeriodStart *time.Time `json:"current_period_start"`
	CurrentPeriodEnd   *time.Time `json:"current_period_end"`
	MonthlyScansUsed   int        `json:"monthly_scans_used" gorm:"default:0"`
	MonthlyAIUsed      int        `json:"monthly_ai_used" gorm:"default:0"`
}

// --- Settings & AI ---

type Settings struct {
	gorm.Model
	OrganizationID uint   `json:"organization_id"`
	Key            string `json:"key" gorm:"not null"`
	Value          string `json:"value"`
}

type AIAnalysis struct {
	gorm.Model
	ScanResultID uint   `json:"scan_result_id" gorm:"not null"`
	Provider     string `json:"provider"`
	Analysis     string `json:"analysis"`
	Status       string `json:"status" gorm:"default:pending"`
}

// --- Scanning ---

type ScanTarget struct {
	gorm.Model
	OrganizationID uint   `json:"organization_id"`
	URL            string `json:"url" gorm:"not null"`
	Name           string `json:"name"`
	Institution    string `json:"institution"`
}

type ScanJob struct {
	gorm.Model
	OrganizationID uint         `json:"organization_id"`
	Name           string       `json:"name"`
	Status         string       `json:"status" gorm:"default:pending"`
	StartedAt      *time.Time   `json:"started_at"`
	EndedAt        *time.Time   `json:"ended_at"`
	UserID         uint         `json:"user_id"`
	Results        []ScanResult `json:"results" gorm:"foreignKey:ScanJobID"`
}

type ScanResult struct {
	gorm.Model
	ScanJobID    uint          `json:"scan_job_id" gorm:"not null"`
	ScanTargetID uint          `json:"scan_target_id" gorm:"not null"`
	ScanTarget   ScanTarget    `json:"scan_target" gorm:"foreignKey:ScanTargetID"`
	OverallScore float64       `json:"overall_score"` // 0-1000
	Status       string        `json:"status" gorm:"default:pending"`
	StartedAt    *time.Time    `json:"started_at"`
	EndedAt      *time.Time    `json:"ended_at"`
	Checks       []CheckResult `json:"checks" gorm:"foreignKey:ScanResultID"`
	AIAnalysis   *AIAnalysis   `json:"ai_analysis,omitempty" gorm:"foreignKey:ScanResultID"`
}

type CheckResult struct {
	gorm.Model
	ScanResultID uint    `json:"scan_result_id" gorm:"not null"`
	Category     string  `json:"category"`
	CheckName    string  `json:"check_name"`
	Status       string  `json:"status"`
	Score        float64 `json:"score"`    // 0-1000
	Weight       float64 `json:"weight"`
	Details      string  `json:"details"`
	Severity     string  `json:"severity"`
}

// --- Upgrade Requests ---

type UpgradeRequest struct {
	gorm.Model
	OrganizationID uint   `json:"organization_id"`
	RequestedPlan  string `json:"requested_plan"` // basic, pro, enterprise
	ContactName    string `json:"contact_name"`
	ContactEmail   string `json:"contact_email"`
	ContactPhone   string `json:"contact_phone"`
	Message        string `json:"message"`
	Status         string `json:"status" gorm:"default:pending"` // pending, approved, rejected
	AdminNotes     string `json:"admin_notes"`
	Organization   Organization `json:"organization,omitempty" gorm:"foreignKey:OrganizationID"`
}

// --- Automation ---

type ScheduledScan struct {
	gorm.Model
	OrganizationID uint       `json:"organization_id" gorm:"not null"`
	Name           string     `json:"name"`
	TargetIDs      string     `json:"target_ids"` // JSON array
	Schedule       string     `json:"schedule"`   // daily, weekly, monthly
	DayOfWeek      int        `json:"day_of_week"`
	HourUTC        int        `json:"hour_utc"`
	IsActive       bool       `json:"is_active" gorm:"default:true"`
	LastRunAt      *time.Time `json:"last_run_at"`
	NextRunAt      *time.Time `json:"next_run_at"`
	CreatedBy      uint       `json:"created_by"`
}

type NotificationPreference struct {
	gorm.Model
	UserID            uint `json:"user_id" gorm:"not null"`
	OrganizationID    uint `json:"organization_id" gorm:"not null"`
	ScanComplete      bool `json:"scan_complete" gorm:"default:true"`
	CriticalVulnFound bool `json:"critical_vuln_found" gorm:"default:true"`
	WeeklySummary     bool `json:"weekly_summary" gorm:"default:false"`
}
