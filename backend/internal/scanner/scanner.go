package scanner

import (
	"context"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"seku/internal/config"
	"seku/internal/models"
	"seku/internal/services"
	"seku/internal/ws"
)

// ActiveScans tracks running scan jobs so they can be cancelled.
var ActiveScans = &activeScanManager{scans: make(map[uint]context.CancelFunc)}

type activeScanManager struct {
	mu    sync.RWMutex
	scans map[uint]context.CancelFunc
}

func (m *activeScanManager) Register(jobID uint, cancel context.CancelFunc) {
	m.mu.Lock()
	m.scans[jobID] = cancel
	m.mu.Unlock()
}

func (m *activeScanManager) Cancel(jobID uint) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	cancel, ok := m.scans[jobID]
	if ok {
		cancel()
		delete(m.scans, jobID)
		return true
	}
	return false
}

func (m *activeScanManager) Remove(jobID uint) {
	m.mu.Lock()
	delete(m.scans, jobID)
	m.mu.Unlock()
}

// MaxScore is the maximum score for any check (1000-point scale)
const MaxScore = 1000.0

// Scanner interface that all security scanners must implement
type Scanner interface {
	Name() string
	Category() string
	Weight() float64
	Scan(url string) []models.CheckResult
}

// Plan tier scanner access
// Free: 5 categories (basic security)
// Basic: 13 categories (standard security)
// Pro: 22 categories (advanced security)
// Enterprise: 25 categories (full scan)
var PlanScanners = map[string][]string{
	"free": { // 5 categories - basic security
		"ssl",
		"headers",
		"cookies",
		"performance",
		"mixed_content",
	},
	"starter": { // 13 categories - standard security
		"ssl",
		"headers",
		"cookies",
		"server_info",
		"directory",
		"performance",
		"ddos",
		"cors",
		"http_methods",
		"dns",
		"mixed_content",
		"seo",
		"secrets",
	},
	"basic": { // 22 categories - extended security
		"ssl",
		"headers",
		"cookies",
		"server_info",
		"directory",
		"performance",
		"ddos",
		"cors",
		"http_methods",
		"dns",
		"mixed_content",
		"info_disclosure",
		"content",
		"hosting",
		"seo",
		"third_party",
		"js_libraries",
		"wordpress",
		"xss",
		"secrets",
		"subdomains",
		"tech_stack",
	},
	"pro": { // 28 categories - advanced security
		"ssl",
		"headers",
		"cookies",
		"server_info",
		"directory",
		"performance",
		"ddos",
		"cors",
		"http_methods",
		"dns",
		"mixed_content",
		"info_disclosure",
		"content",
		"hosting",
		"seo",
		"third_party",
		"js_libraries",
		"wordpress",
		"xss",
		"secrets",
		"subdomains",
		"tech_stack",
		"sqli",
		"ports",
		"open_redirect",
		"ssrf",
		"email_security",
		"waf",
	},
	"business": { // 32 categories - full scan
		"ssl",
		"headers",
		"cookies",
		"server_info",
		"directory",
		"performance",
		"ddos",
		"cors",
		"http_methods",
		"dns",
		"mixed_content",
		"info_disclosure",
		"content",
		"hosting",
		"advanced_security",
		"malware",
		"threat_intel",
		"seo",
		"third_party",
		"js_libraries",
		"wordpress",
		"xss",
		"secrets",
		"subdomains",
		"tech_stack",
		"sqli",
		"ports",
		"open_redirect",
		"ssrf",
		"email_security",
		"waf",
		"zone_transfer",
	},
	"enterprise": { // 32 categories - full scan
		"ssl",
		"headers",
		"cookies",
		"server_info",
		"directory",
		"performance",
		"ddos",
		"cors",
		"http_methods",
		"dns",
		"mixed_content",
		"info_disclosure",
		"content",
		"hosting",
		"advanced_security",
		"malware",
		"threat_intel",
		"seo",
		"third_party",
		"js_libraries",
		"wordpress",
		"xss",
		"secrets",
		"subdomains",
		"tech_stack",
		"sqli",
		"ports",
		"open_redirect",
		"ssrf",
		"email_security",
		"waf",
		"zone_transfer",
	},
}

// Engine manages and runs all scanners
type Engine struct {
	scanners []Scanner
	plan     string
}

// ScanPolicy defines preset scanning configurations
type ScanPolicy struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Categories  []string `json:"categories"`
	Timeout     int      `json:"timeout"` // seconds per target
}

// ScanPolicies contains the available scan policy presets
var ScanPolicies = map[string]ScanPolicy{
	"light": {
		Name:        "Light Scan",
		Description: "Quick security check — 8 basic categories, ~30 seconds per site",
		Categories:  []string{"ssl", "headers", "cookies", "mixed_content", "performance", "dns", "seo", "content"},
		Timeout:     30,
	},
	"standard": {
		Name:        "Standard Scan",
		Description: "Comprehensive security audit — 16 categories, ~60 seconds per site",
		Categories:  []string{"ssl", "headers", "cookies", "server_info", "directory", "performance", "ddos", "cors", "http_methods", "dns", "mixed_content", "info_disclosure", "hosting", "content", "seo", "secrets"},
		Timeout:     60,
	},
	"deep": {
		Name:        "Deep Scan",
		Description: "Full security assessment — 32 categories including SQLi, SSRF, WAF, port scanning, ~3 minutes per site",
		Categories:  []string{"ssl", "headers", "cookies", "server_info", "directory", "performance", "ddos", "cors", "http_methods", "dns", "mixed_content", "info_disclosure", "hosting", "content", "advanced_security", "malware", "threat_intel", "seo", "third_party", "js_libraries", "wordpress", "xss", "secrets", "subdomains", "tech_stack", "sqli", "ports", "open_redirect", "ssrf", "email_security", "waf", "zone_transfer"},
		Timeout:     180,
	},
}

// allScanners returns all registered scanners
func allScanners() []Scanner {
	return []Scanner{
		NewSSLScanner(),
		NewHeaderScanner(),
		NewCookieScanner(),
		NewServerInfoScanner(),
		NewDirectoryScanner(),
		NewPerformanceScanner(),
		NewDDoSScanner(),
		NewCORSScanner(),
		NewHTTPMethodsScanner(),
		NewDNSScanner(),
		NewMixedContentScanner(),
		NewInfoDisclosureScanner(),
		NewContentScanner(),
		NewHostingScanner(),
		NewAdvancedSecurityScanner(),
		NewMalwareScanner(),
		NewThreatIntelScanner(),
		NewSEOScanner(),
		NewThirdPartyScanner(),
		NewJSLibScanner(),
		NewWordPressScanner(),
		NewXSSScanner(),
		NewSecretsScanner(),
		NewSubdomainScanner(),
		NewTechDetectScanner(),
		NewSQLiScanner(),
		NewPortScanner(),
		NewBlindSQLiScanner(),
		NewRedirectScanner(),
		NewSSRFScanner(),
		NewEmailSecurityScanner(),
		NewWAFScanner(),
		NewZoneTransferScanner(),
	}
}

// NewEngineForPolicy creates a scan engine filtered by scan policy
func NewEngineForPolicy(policy string) *Engine {
	p, ok := ScanPolicies[policy]
	if !ok {
		p = ScanPolicies["standard"]
	}

	allowedMap := map[string]bool{}
	for _, cat := range p.Categories {
		allowedMap[cat] = true
	}

	var filtered []Scanner
	for _, s := range allScanners() {
		if allowedMap[s.Category()] {
			filtered = append(filtered, s)
		}
	}
	return &Engine{scanners: filtered, plan: "enterprise"}
}

// NewEngine creates a scan engine with all scanners (enterprise by default)
func NewEngine() *Engine {
	return &Engine{
		scanners: allScanners(),
		plan:     "enterprise",
	}
}

// NewEngineForPlan creates a scan engine filtered by plan
func NewEngineForPlan(plan string) *Engine {
	allowed, ok := PlanScanners[plan]
	if !ok {
		allowed = PlanScanners["enterprise"]
	}

	allowedMap := map[string]bool{}
	for _, cat := range allowed {
		allowedMap[cat] = true
	}

	var filtered []Scanner
	for _, s := range allScanners() {
		if allowedMap[s.Category()] {
			filtered = append(filtered, s)
		}
	}

	return &Engine{
		scanners: filtered,
		plan:     plan,
	}
}

// ResumeInterruptedJobs finds jobs that were "running" when the server stopped
// and restarts them in the background. Called at server startup.
func ResumeInterruptedJobs() {
	var jobs []models.ScanJob
	config.DB.Where("status IN ?", []string{"running", "pending"}).Find(&jobs)

	if len(jobs) == 0 {
		return
	}

	fmt.Printf("[Scanner] Resuming %d interrupted scan jobs...\n", len(jobs))

	for i := range jobs {
		job := jobs[i]

		// Reset any "running" child results back to "pending"
		config.DB.Model(&models.ScanResult{}).
			Where("scan_job_id = ? AND status = ?", job.ID, "running").
			Update("status", "pending")

		// Launch scan in background — scanTarget skips already-completed results
		go func(j models.ScanJob) {
			engine := NewEngineForPolicy("deep") // use deep by default for resumed jobs
			engine.RunScan(&j)
		}(job)
	}
}

// RunScan executes all scanners against a target. Supports cancellation via ActiveScans.
// If the scan is resumed after server restart, it skips already-completed targets.
func (e *Engine) RunScan(job *models.ScanJob) {
	ctx, cancel := context.WithCancel(context.Background())
	ActiveScans.Register(job.ID, cancel)
	defer ActiveScans.Remove(job.ID)

	now := time.Now()
	job.Status = "running"
	if job.StartedAt == nil {
		job.StartedAt = &now
	}
	config.DB.Save(job)

	// Load all results — will skip completed/failed ones during scan
	var results []models.ScanResult
	config.DB.Where("scan_job_id = ?", job.ID).Preload("ScanTarget").Find(&results)

	// Reset "running" targets to "pending" — they were interrupted by restart
	for i := range results {
		if results[i].Status == "running" {
			results[i].Status = "pending"
			config.DB.Model(&results[i]).Update("status", "pending")
		}
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	var completedCount int64

	// Count already-completed results to include in progress
	for _, r := range results {
		if r.Status == "completed" {
			atomic.AddInt64(&completedCount, 1)
		}
	}

	for i := range results {
		// Skip already-completed or failed targets (resumption)
		if results[i].Status == "completed" || results[i].Status == "failed" {
			continue
		}

		// Check for cancellation before starting next target
		select {
		case <-ctx.Done():
			goto scanDone
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(result *models.ScanResult) {
			defer wg.Done()
			defer func() { <-sem }()

			// Check cancellation before scanning
			select {
			case <-ctx.Done():
				result.Status = "cancelled"
				config.DB.Save(result)
				return
			default:
			}

			e.scanTarget(result)

			current := atomic.AddInt64(&completedCount, 1)
			ws.DefaultHub.Broadcast(ws.ScanProgress{
				Type:       "job",
				JobID:      job.ID,
				Status:     "running",
				Total:      len(results),
				Completed:  int(current),
				Percent:    float64(current) / float64(len(results)) * 100,
				CurrentURL: result.ScanTarget.URL,
				Message:    fmt.Sprintf("Completed %d/%d", current, len(results)),
			})
		}(&results[i])
	}

	wg.Wait()

scanDone:
	// Determine final status
	finalStatus := "completed"
	select {
	case <-ctx.Done():
		finalStatus = "cancelled"
	default:
	}

	ws.DefaultHub.Broadcast(ws.ScanProgress{
		Type:      "job",
		JobID:     job.ID,
		Status:    finalStatus,
		Total:     len(results),
		Completed: int(atomic.LoadInt64(&completedCount)),
		Percent:   100,
		Message:   fmt.Sprintf("Scan %s", finalStatus),
	})

	ended := time.Now()
	job.Status = finalStatus
	job.EndedAt = &ended
	config.DB.Save(job)

	if finalStatus == "completed" {
		// Send webhook notifications
		var completedResults []models.ScanResult
		config.DB.Where("scan_job_id = ?", job.ID).Preload("ScanTarget").Find(&completedResults)
		services.SendScanCompletedWebhooks(job, completedResults)

		// Send email notifications
		services.SendScanCompletedEmail(job, completedResults)
	}
}

func (e *Engine) scanTarget(result *models.ScanResult) {
	now := time.Now()
	result.Status = "running"
	result.StartedAt = &now
	config.DB.Save(result)

	var allChecks []models.CheckResult
	var totalScore, totalWeight float64
	totalScanners := len(e.scanners)

	for idx, s := range e.scanners {
		// Broadcast per-scanner sub-progress
		ws.DefaultHub.Broadcast(ws.ScanProgress{
			Type:          "target",
			JobID:         result.ScanJobID,
			TargetID:      result.ScanTargetID,
			TargetURL:     result.ScanTarget.URL,
			ScannerName:   s.Name(),
			ScannerIndex:  idx + 1,
			TotalScanners: totalScanners,
			TargetPercent: float64(idx) / float64(totalScanners) * 100,
			Status:        "scanning",
			Message:       fmt.Sprintf("[%d/%d] %s", idx+1, totalScanners, s.Name()),
		})

		checks := s.Scan(result.ScanTarget.URL)
		for i := range checks {
			checks[i].ScanResultID = result.ID
		}
		allChecks = append(allChecks, checks...)
	}

	// Populate OWASP/CWE mappings
	for i := range allChecks {
		if m := GetOWASPMapping(allChecks[i].CheckName); m != nil {
			allChecks[i].OWASP = m.OWASP
			allChecks[i].OWASPName = m.OWASPName
			allChecks[i].CWE = m.CWE
			allChecks[i].CWEName = m.CWEName
		}
	}

	// Populate confidence scores
	for i := range allChecks {
		allChecks[i].Confidence = GetConfidence(allChecks[i].CheckName)
	}

	// Populate CVSS v3.1 scores for failed checks
	for i := range allChecks {
		if m := GetCVSSMapping(allChecks[i].CheckName); m != nil && allChecks[i].Status == "fail" {
			allChecks[i].CVSSScore = m.Score
			allChecks[i].CVSSVector = m.Vector
			allChecks[i].CVSSRating = m.Rating
		}
	}

	// Save all checks
	if len(allChecks) > 0 {
		config.DB.Create(&allChecks)
	}

	// Calculate overall score (0-1000)
	for _, check := range allChecks {
		if check.Weight > 0 {
			totalScore += check.Score * check.Weight
			totalWeight += check.Weight
		}
	}

	if totalWeight > 0 {
		result.OverallScore = math.Round(totalScore / totalWeight)
	}

	ended := time.Now()
	result.Status = "completed"
	result.EndedAt = &ended
	config.DB.Save(result)

	// Broadcast target completion
	ws.DefaultHub.Broadcast(ws.ScanProgress{
		Type:          "target",
		JobID:         result.ScanJobID,
		TargetID:      result.ScanTargetID,
		TargetURL:     result.ScanTarget.URL,
		ScannerName:   "Complete",
		ScannerIndex:  totalScanners,
		TotalScanners: totalScanners,
		TargetPercent: 100,
		Status:        "completed",
		Message:       fmt.Sprintf("Scan complete — Score: %.0f", result.OverallScore),
	})
}

// GetScanners returns the list of scanners in this engine
func (e *Engine) GetScanners() []Scanner {
	return e.scanners
}

// GetPlanCategories returns the allowed categories for a plan
func GetPlanCategories(plan string) []string {
	if cats, ok := PlanScanners[plan]; ok {
		return cats
	}
	return PlanScanners["enterprise"]
}

// GetPlanCategoryCount returns how many categories a plan can scan
func GetPlanCategoryCount(plan string) int {
	return len(GetPlanCategories(plan))
}
