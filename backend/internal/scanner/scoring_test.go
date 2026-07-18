package scanner

import "testing"

import "seku/internal/models"

func chk(cat, name, status string, score float64, conf int) models.CheckResult {
	// Severity mirrors the real pipeline (derived from score) so cap logic that
	// keys off the finding's own severity is exercised realistically.
	return models.CheckResult{
		Category: cat, CheckName: name, Status: status, Score: score,
		Confidence: conf, Severity: severityFromScore(score),
	}
}

// A site that passes every security domain earns a top grade.
func TestComputeScores_CleanSiteGetsTopGrade(t *testing.T) {
	checks := []models.CheckResult{
		chk("ssl", "TLS Version", "pass", 1000, 100),
		chk("headers", "HSTS", "pass", 1000, 100),
		chk("xss", "Reflected XSS Detection", "pass", 1000, 80),
		chk("sqli", "SQL Injection Test", "pass", 1000, 70),
		chk("secrets", "API Key Exposure", "pass", 1000, 100),
	}
	r := ComputeScores(checks)
	if r.Security < 900 {
		t.Errorf("clean site should score A+ (>=900), got %.0f", r.Security)
	}
	if SecurityGrade(r.Security) != "A+" {
		t.Errorf("expected A+, got %s", SecurityGrade(r.Security))
	}
	if r.CapReason != "" {
		t.Errorf("clean site must not be capped, got %q", r.CapReason)
	}
}

// THE MANARA PARADOX: a confident critical failure caps the grade at F, even
// when many other checks pass. This is the core fix.
func TestComputeScores_CriticalFailCapsGrade(t *testing.T) {
	checks := []models.CheckResult{
		chk("ssl", "TLS Version", "pass", 1000, 100),
		chk("headers", "HSTS", "pass", 1000, 100),
		chk("cookies", "Cookie Security", "pass", 1000, 100),
		chk("cors", "CORS Wildcard Origin", "pass", 1000, 100),
		chk("directory", "Directory Listing", "pass", 1000, 100),
		// one confident critical failure:
		chk("xss", "Reflected XSS Detection", "fail", 50, 80),
	}
	r := ComputeScores(checks)
	if r.Security > capCriticalFail {
		t.Errorf("a confident critical fail must cap at F (<=%d), got %.0f", capCriticalFail, r.Security)
	}
	if SecurityGrade(r.Security) != "F" {
		t.Errorf("expected F, got %s (score %.0f)", SecurityGrade(r.Security), r.Security)
	}
	if r.RawSecurity <= r.Security {
		t.Errorf("raw (uncapped) score should exceed capped score; raw=%.0f capped=%.0f", r.RawSecurity, r.Security)
	}
}

// A confident HIGH failure lowers the score via the weighted average but must
// NOT hard-cap the grade — otherwise every site with a missing header collapses
// to the same value and the ranking loses all variance.
func TestComputeScores_HighFailDoesNotHardCap(t *testing.T) {
	checks := []models.CheckResult{
		chk("xss", "Reflected XSS Detection", "pass", 1000, 80),
		chk("sqli", "SQL Injection Test", "pass", 1000, 70),
		chk("ssl", "TLS Version", "pass", 1000, 100),
		// one confident high failure (a missing header):
		chk("headers", "HSTS", "fail", 0, 100),
	}
	r := ComputeScores(checks)
	if r.CapReason != "" {
		t.Errorf("a high-severity fail must not cap; got cap %q", r.CapReason)
	}
	// It should reduce the score below a clean site but not floor it to a fixed cap.
	if r.Security < 700 {
		t.Errorf("one high fail among strong checks should stay well above C, got %.0f", r.Security)
	}
}

// Two sites that differ only in how many headers they miss must get DIFFERENT
// scores (variance preserved) rather than both collapsing to one capped value.
func TestComputeScores_HighFailsPreserveVariance(t *testing.T) {
	base := []models.CheckResult{
		chk("xss", "Reflected XSS Detection", "pass", 1000, 80),
		chk("sqli", "SQL Injection Test", "pass", 1000, 70),
		chk("ssl", "TLS Version", "pass", 1000, 100),
	}
	oneGap := append(append([]models.CheckResult{}, base...), chk("headers", "HSTS", "fail", 0, 100))
	manyGaps := append(append([]models.CheckResult{}, base...),
		chk("headers", "HSTS", "fail", 0, 100),
		chk("cookies", "Cookie Security", "fail", 0, 100),
		chk("cors", "CORS Wildcard Origin", "fail", 0, 100),
	)
	a := ComputeScores(oneGap).Security
	b := ComputeScores(manyGaps).Security
	if !(a > b) {
		t.Errorf("more high-severity gaps must score lower (variance), got one-gap=%.0f many-gaps=%.0f", a, b)
	}
}

// A LOW-CONFIDENCE critical fail is advisory only — it must NOT cap the grade.
func TestComputeScores_LowConfidenceDoesNotCap(t *testing.T) {
	checks := []models.CheckResult{
		chk("ssl", "TLS Version", "pass", 1000, 100),
		chk("headers", "HSTS", "pass", 1000, 100),
		chk("xss", "Speculative XSS", "fail", 300, 40), // below capConfidence
	}
	r := ComputeScores(checks)
	if r.CapReason != "" {
		t.Errorf("low-confidence finding must not cap, got %q", r.CapReason)
	}
}

// Security and quality are independent: perfect security + terrible performance
// yields a high security score and a low quality score.
func TestComputeScores_SecurityAndQualitySeparated(t *testing.T) {
	checks := []models.CheckResult{
		chk("ssl", "TLS Version", "pass", 1000, 100),
		chk("headers", "HSTS", "pass", 1000, 100),
		chk("xss", "Reflected XSS Detection", "pass", 1000, 80),
		// poor performance/quality:
		chk("performance", "Time to First Byte (TTFB)", "warn", 300, 80),
		chk("content", "Page Size", "warn", 250, 80),
	}
	r := ComputeScores(checks)
	if r.Security < 900 {
		t.Errorf("security should be unaffected by performance, got %.0f", r.Security)
	}
	if r.Quality > 400 {
		t.Errorf("quality should reflect poor performance, got %.0f", r.Quality)
	}
}

// Two-level aggregation: 50 passing subdomain checks must not drown out a single
// failing SQLi domain. The critical fail still caps the grade.
func TestComputeScores_ManyChecksDoNotDominate(t *testing.T) {
	var checks []models.CheckResult
	for i := 0; i < 50; i++ {
		checks = append(checks, chk("subdomains", "Subdomain Probe", "pass", 1000, 80))
	}
	checks = append(checks, chk("sqli", "SQL Injection Test", "fail", 50, 90))
	r := ComputeScores(checks)
	if r.Security > capCriticalFail {
		t.Errorf("50 passing subdomain checks must not outweigh a critical SQLi fail; got %.0f", r.Security)
	}
}

// Errored checks (e.g. scanner timed out on flaky DNS) are excluded and never
// distort the score.
func TestComputeScores_ErrorsExcluded(t *testing.T) {
	checks := []models.CheckResult{
		chk("ssl", "TLS Version", "pass", 1000, 100),
		chk("dns", "DNS Security Scanner (timeout)", "error", 0, 80),
		chk("email_security", "Email Security Scanner (timeout)", "error", 0, 80),
	}
	r := ComputeScores(checks)
	if r.Security < 900 {
		t.Errorf("errored scanners must not lower the score, got %.0f", r.Security)
	}
}
