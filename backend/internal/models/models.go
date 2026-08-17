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
	MaxTargets int    `json:"max_targets" gorm:"default:1"`
	MaxScans   int    `json:"max_scans" gorm:"default:5"`
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
	KeyHash        string     `json:"-"`          // bcrypt hash
	LastUsedAt     *time.Time `json:"last_used_at"`
	ExpiresAt      *time.Time `json:"expires_at"`
	Scopes         string     `json:"scopes"` // JSON array
}

type AuditLog struct {
	gorm.Model
	OrganizationID uint   `json:"organization_id"`
	UserID         uint   `json:"user_id"`
	Action         string `json:"action"` // scan.create, target.delete, etc.
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
	// Adhoc marks a target created by an instant "scan a domain" run. Adhoc
	// targets are hidden from the main targets list and don't count toward the
	// plan's target quota, so a quick one-off scan never clutters the workspace.
	Adhoc bool `json:"adhoc" gorm:"default:false;index"`
}

type ScanJob struct {
	gorm.Model
	OrganizationID uint       `json:"organization_id"`
	Name           string     `json:"name"`
	Status         string     `json:"status" gorm:"default:pending"`
	StartedAt      *time.Time `json:"started_at"`
	EndedAt        *time.Time `json:"ended_at"`
	UserID         uint       `json:"user_id"`
	// Scan configuration persisted so an interrupted job resumes with the SAME
	// policy/tools it was started with (not always "deep").
	Policy           string       `json:"policy"`
	EnableLogin      bool         `json:"enable_login"`
	EnableNuclei     bool         `json:"enable_nuclei"`
	EnableCrawl      bool         `json:"enable_crawl"`
	EnableOOB        bool         `json:"enable_oob"`
	EnableDalfox     bool         `json:"enable_dalfox"`
	EnableFFUF       bool         `json:"enable_ffuf"`
	EnableNucleiDast bool         `json:"enable_nuclei_dast"`
	// Source records HOW the scan was launched (web, desktop, agent) and, for
	// desktop/agent runs, which machine ran it — so activity shows who + from where.
	Source           string       `json:"source"`      // web | desktop | agent
	DeviceInfo       string       `json:"device_info"` // e.g. "MacBook-Pro · darwin/arm64"
	Authorized       bool         `json:"authorized"`
	AuthCookie       string       `json:"auth_cookie"`
	AuthHeader       string       `json:"auth_header"`
	AuthCookieB      string       `json:"auth_cookie_b"`
	Results          []ScanResult `json:"results" gorm:"foreignKey:ScanJobID"`
}

type ScanResult struct {
	gorm.Model
	ScanJobID      uint          `json:"scan_job_id" gorm:"not null"`
	ScanTargetID   uint          `json:"scan_target_id" gorm:"not null"`
	ScanTarget     ScanTarget    `json:"scan_target" gorm:"foreignKey:ScanTargetID"`
	OverallScore   float64       `json:"overall_score"`    // 0-1000 — headline SECURITY score (capped)
	QualityScore   float64       `json:"quality_score"`    // 0-1000 — separate performance/quality score
	RawScore       float64       `json:"raw_score"`        // security score before severity caps (transparency)
	SecurityGrade  string        `json:"security_grade"`   // A+..F derived from OverallScore
	GradeCapReason string        `json:"grade_cap_reason"` // finding that capped the grade, "" if uncapped
	CoverageNote   string        `json:"coverage_note"`    // caveat when active vuln testing didn't run ("" if it did)
	Status         string        `json:"status" gorm:"default:pending"`
	StartedAt      *time.Time    `json:"started_at"`
	EndedAt        *time.Time    `json:"ended_at"`
	ShareToken     string        `json:"share_token" gorm:"index"` // public shareable-report token (opt-in)
	Checks         []CheckResult `json:"checks" gorm:"foreignKey:ScanResultID"`
	AIAnalysis     *AIAnalysis   `json:"ai_analysis,omitempty" gorm:"foreignKey:ScanResultID"`
}

type CheckResult struct {
	gorm.Model
	ScanResultID uint    `json:"scan_result_id" gorm:"not null"`
	Category     string  `json:"category"`
	CheckName    string  `json:"check_name"`
	Status       string  `json:"status"`
	Score        float64 `json:"score"` // 0-1000
	Weight       float64 `json:"weight"`
	Details      string  `json:"details"`
	Severity     string  `json:"severity"`
	OWASP        string  `json:"owasp"`
	OWASPName    string  `json:"owasp_name"`
	CWE          string  `json:"cwe"`
	CWEName      string  `json:"cwe_name"`
	Confidence   int     `json:"confidence" gorm:"default:80"` // 0-100 confidence level
	CVSSScore    float64 `json:"cvss_score"`
	CVSSVector   string  `json:"cvss_vector"`
	CVSSRating   string  `json:"cvss_rating"`
	// Triage: "" (open) | confirmed | false_positive | fixed | accepted
	TriageStatus string `json:"triage_status"`
	TriageNote   string `json:"triage_note"`
}

// --- Upgrade Requests ---

type UpgradeRequest struct {
	gorm.Model
	OrganizationID uint         `json:"organization_id"`
	RequestedPlan  string       `json:"requested_plan"` // basic, pro, enterprise
	ContactName    string       `json:"contact_name"`
	ContactEmail   string       `json:"contact_email"`
	ContactPhone   string       `json:"contact_phone"`
	Message        string       `json:"message"`
	Status         string       `json:"status" gorm:"default:pending"` // pending, approved, rejected
	AdminNotes     string       `json:"admin_notes"`
	Organization   Organization `json:"organization,omitempty" gorm:"foreignKey:OrganizationID"`
}

// --- Domain Verification ---

type DomainVerification struct {
	gorm.Model
	OrganizationID  uint       `json:"organization_id" gorm:"not null"`
	ScanTargetID    uint       `json:"scan_target_id" gorm:"not null"`
	Domain          string     `json:"domain" gorm:"not null"`
	VerificationKey string     `json:"verification_key" gorm:"not null"` // e.g., vscan-verify=abc123
	IsVerified      bool       `json:"is_verified" gorm:"default:false"`
	Method          string     `json:"method"` // dns_txt | file — how it was verified
	VerifiedAt      *time.Time `json:"verified_at"`
}

// DeepScanOrder is a pay-per-scan purchase for a single deep scan on one target.
// Payment is a manual internal transfer: the user creates a pending order, pays
// via the transfer method shown in payment settings, submits the transfer ref,
// an admin marks it paid, then the user consumes it by running one deep scan.
type DeepScanOrder struct {
	gorm.Model
	OrganizationID  uint         `json:"organization_id" gorm:"not null;index"`
	UserID          uint         `json:"user_id" gorm:"not null"`
	ScanTargetID    uint         `json:"scan_target_id" gorm:"not null;index"`
	Domain          string       `json:"domain"`
	AmountIQD       int          `json:"amount_iqd"`                    // price at time of order
	Status          string       `json:"status" gorm:"default:pending"` // pending | paid | rejected | used
	PaymentRef      string       `json:"payment_ref"`                   // transfer reference entered by user
	PaymentProofURL string       `json:"payment_proof_url"`             // uploaded transfer screenshot
	ContactName     string       `json:"contact_name"`
	ContactPhone    string       `json:"contact_phone"`
	AdminNotes      string       `json:"admin_notes"`
	ApprovedBy      uint         `json:"approved_by"`
	ApprovedAt      *time.Time   `json:"approved_at"`
	UsedByScanJob   uint         `json:"used_by_scan_job"` // ScanJob that consumed this credit
	UsedAt          *time.Time   `json:"used_at"`
	ScanTarget      ScanTarget   `json:"scan_target,omitempty" gorm:"foreignKey:ScanTargetID"`
	Organization    Organization `json:"organization,omitempty" gorm:"foreignKey:OrganizationID"`
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

// ScanChange records the delta between a target's newest completed scan and its
// previous one — the core of continuous monitoring. A row is written on every
// re-scan that has a baseline, giving a durable change history (new/fixed
// findings, score movement) and driving change alerts.
type ScanChange struct {
	gorm.Model
	OrganizationID uint    `json:"organization_id" gorm:"index"`
	ScanTargetID   uint    `json:"scan_target_id" gorm:"index"`
	OldResultID    uint    `json:"old_result_id"`
	NewResultID    uint    `json:"new_result_id"`
	OldScore       float64 `json:"old_score"`
	NewScore       float64 `json:"new_score"`
	OldGrade       string  `json:"old_grade"`
	NewGrade       string  `json:"new_grade"`
	NewFindings    int     `json:"new_findings"`   // findings that appeared (regressions)
	FixedFindings  int     `json:"fixed_findings"` // findings that were resolved
	Regressed      bool    `json:"regressed"`      // score dropped past the threshold
	Details        string  `json:"details"`        // JSON {new:[...], fixed:[...]}
}

type NotificationPreference struct {
	gorm.Model
	UserID            uint `json:"user_id" gorm:"not null"`
	OrganizationID    uint `json:"organization_id" gorm:"not null"`
	ScanComplete      bool `json:"scan_complete" gorm:"default:true"`
	CriticalVulnFound bool `json:"critical_vuln_found" gorm:"default:true"`
	WeeklySummary     bool `json:"weekly_summary" gorm:"default:false"`
}

// --- Scan Tags ---

type ScanTag struct {
	gorm.Model
	OrganizationID uint   `json:"organization_id"`
	Name           string `json:"name" gorm:"not null"`
	Color          string `json:"color" gorm:"default:#6366f1"` // hex color
}

type TargetTag struct {
	ID           uint    `json:"id" gorm:"primarykey;autoIncrement"`
	ScanTargetID uint    `json:"scan_target_id"`
	ScanTagID    uint    `json:"scan_tag_id"`
	ScanTag      ScanTag `json:"scan_tag" gorm:"foreignKey:ScanTagID"`
}

// --- Webhooks ---

type Webhook struct {
	gorm.Model
	OrganizationID uint   `json:"organization_id"`
	Name           string `json:"name" gorm:"not null"`
	Type           string `json:"type" gorm:"not null"` // slack, telegram, discord, teams, custom
	URL            string `json:"url" gorm:"not null"`
	Secret         string `json:"secret"` // for telegram bot token or custom auth
	IsActive       bool   `json:"is_active" gorm:"default:true"`
	Events         string `json:"events" gorm:"default:scan_completed"` // comma-separated: scan_completed, score_drop, critical_found
	MinSeverity    string `json:"min_severity" gorm:"default:all"`      // all, critical, high, medium
}

// --- Email ---

type EmailConfig struct {
	gorm.Model
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port" gorm:"default:587"`
	SMTPUser     string `json:"smtp_user"`
	SMTPPass     string `json:"smtp_pass"`
	FromEmail    string `json:"from_email"`
	FromName     string `json:"from_name" gorm:"default:Seku"`
	IsConfigured bool   `json:"is_configured" gorm:"default:false"`
}

type EmailAlert struct {
	gorm.Model
	OrganizationID  uint   `json:"organization_id"`
	UserID          uint   `json:"user_id"`
	Email           string `json:"email" gorm:"not null"`
	Events          string `json:"events" gorm:"default:scan_completed,score_drop"` // comma-separated
	MinSeverity     string `json:"min_severity" gorm:"default:all"`
	IsActive        bool   `json:"is_active" gorm:"default:true"`
	DigestFrequency string `json:"digest_frequency" gorm:"default:immediate"` // immediate, daily, weekly
}

// --- Single-target tools ---

// NucleiRun is one async nuclei tool run with a live, detailed log.
type NucleiRun struct {
	gorm.Model
	UserID      uint       `json:"user_id"`
	Target      string     `json:"target"`
	Severity    string     `json:"severity"`
	Tags        string     `json:"tags"`
	Status      string     `json:"status" gorm:"default:running"` // running, finished, failed
	StartedAt   *time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	DurationSec int        `json:"duration_sec"`
	Findings    int        `json:"findings"`
	ResultsJSON string     `json:"results_json" gorm:"type:text"`
	Log         string     `json:"log" gorm:"type:text"`
}

// --- Local scan agents (internal-network scanning) ---

// Agent is a local scanner installed inside a network. It polls the server for
// jobs and runs scans locally (reaching internal IPs), reporting results back.
type Agent struct {
	gorm.Model
	OrganizationID uint       `json:"organization_id"`
	Name           string     `json:"name"`
	Token          string     `json:"-" gorm:"index"` // secret enrollment/auth token
	OS             string     `json:"os"`
	Version        string     `json:"version"`
	LastSeen       *time.Time `json:"last_seen"`
}

// AgentJob is a scan assigned to a specific agent, executed locally by it.
type AgentJob struct {
	gorm.Model
	AgentID        uint       `json:"agent_id"`
	OrganizationID uint       `json:"organization_id"`
	Target         string     `json:"target"`
	Policy         string     `json:"policy" gorm:"default:standard"`
	Status         string     `json:"status" gorm:"default:pending"` // pending, running, done, failed
	StartedAt      *time.Time `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at"`
	DurationSec    int        `json:"duration_sec"`
	Findings       int        `json:"findings"`
	ResultsJSON    string     `json:"results_json" gorm:"type:text"`
	Error          string     `json:"error"`
}

// DownloadStat counts agent-binary downloads per platform.
type DownloadStat struct {
	gorm.Model
	Platform string `json:"platform" gorm:"uniqueIndex"`
	Count    int64  `json:"count"`
}
