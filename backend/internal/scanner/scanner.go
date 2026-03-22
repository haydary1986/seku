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

// Engine manages and runs all scanners
type Engine struct {
	scanners []Scanner
}

// NewEngine creates a new scan engine with all registered scanners
func NewEngine() *Engine {
	return &Engine{
		scanners: []Scanner{
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
		},
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
