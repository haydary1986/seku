package scanner

import (
	"math"
	"sync"
	"time"

	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/models"
)

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
// Basic: 10 categories (standard security)
// Pro: 14 categories (advanced security)
// Enterprise: 17 categories (full scan)
var PlanScanners = map[string][]string{
	"free": { // 5 categories - basic security
		"ssl",
		"headers",
		"cookies",
		"performance",
		"mixed_content",
	},
	"basic": { // 12 categories - standard security
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
	},
	"pro": { // 17 categories - advanced security
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
	},
	"enterprise": { // 20 categories - full scan
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
	},
}

// Engine manages and runs all scanners
type Engine struct {
	scanners []Scanner
	plan     string
}

// allScanners returns all 20 registered scanners
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
	}
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

// RunScan executes all scanners against a target
func (e *Engine) RunScan(job *models.ScanJob) {
	now := time.Now()
	job.Status = "running"
	job.StartedAt = &now
	config.DB.Save(job)

	var results []models.ScanResult
	config.DB.Where("scan_job_id = ?", job.ID).Preload("ScanTarget").Find(&results)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for i := range results {
		wg.Add(1)
		sem <- struct{}{}
		go func(result *models.ScanResult) {
			defer wg.Done()
			defer func() { <-sem }()
			e.scanTarget(result)
		}(&results[i])
	}

	wg.Wait()

	ended := time.Now()
	job.Status = "completed"
	job.EndedAt = &ended
	config.DB.Save(job)
}

func (e *Engine) scanTarget(result *models.ScanResult) {
	now := time.Now()
	result.Status = "running"
	result.StartedAt = &now
	config.DB.Save(result)

	var allChecks []models.CheckResult
	var totalScore, totalWeight float64

	for _, s := range e.scanners {
		checks := s.Scan(result.ScanTarget.URL)
		for i := range checks {
			checks[i].ScanResultID = result.ID
		}
		allChecks = append(allChecks, checks...)
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
