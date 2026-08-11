package scanner

import "seku/internal/models"

// ScanConfig carries per-scan options for the advanced / intrusive scanners
// (login, nuclei, crawl, oob). A nil *ScanConfig means "use environment
// defaults only" — so existing callers and resumed jobs behave unchanged.
type ScanConfig struct {
	EnableLogin  bool `json:"enable_login"`
	EnableNuclei bool `json:"enable_nuclei"`
	EnableCrawl  bool `json:"enable_crawl"`
	EnableOOB    bool `json:"enable_oob"`
	EnableDalfox bool `json:"enable_dalfox"`
	EnableFFUF   bool `json:"enable_ffuf"`
	// Authorized is the user's explicit acknowledgement that they are permitted
	// to actively test the target. Required to enable credential brute-forcing.
	Authorized bool `json:"authorized"`
}

// ConfigurableScanner is optionally implemented by scanners that accept
// per-scan configuration. The engine prefers ScanWithConfig when a scanner
// implements it; otherwise it falls back to Scan(url). This keeps the 37
// passive scanners untouched.
type ConfigurableScanner interface {
	ScanWithConfig(url string, cfg *ScanConfig) []models.CheckResult
}

// WithConfig attaches per-scan configuration and returns the engine for chaining.
func (e *Engine) WithConfig(cfg *ScanConfig) *Engine {
	e.config = cfg
	return e
}
