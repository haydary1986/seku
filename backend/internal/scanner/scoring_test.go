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
		// one confident HIGH failure (a missing header): score 250 → "high"
		// (score 0 would be "critical" per severityFromScore).
		chk("headers", "HSTS", "fail", 250, 100),
	}
	r := ComputeScores(checks)
	if r.CapReason != "" {
		t.Errorf("a high-severity fail must not cap; got cap %q", r.CapReason)
	}
	// A single high fail deducts a bounded penalty (not a hard cap) → stays high.
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

// NormalizeSeverities makes displayed severity credible: a mapped security check
// adopts its canonical CVSS rating (HSTS = Medium, not "critical" from a low
// score), a confirmed injection stays Critical, and SEO/quality nits are capped
// to Low. Because scoring reads Severity, this also de-inflates penalties.
func TestNormalizeSeverities_CanonicalImpact(t *testing.T) {
	checks := []models.CheckResult{
		// score-derived severity would be "critical" for all three fails:
		chk("headers", "HSTS", "fail", 0, 100),           // CVSS map → Medium
		chk("sqli", "SQL Injection Test", "fail", 0, 90), // CVSS map → Critical
		chk("seo", "Robots.txt Quality", "fail", 0, 100), // quality → capped Low
		chk("content", "Cache Headers", "warn", 300, 80), // quality → capped Low
	}
	if got := checks[0].Severity; got != "critical" {
		// sanity: the pipeline starts from the (inflated) score-derived value
		t.Logf("pre-normalize HSTS severity = %q", got)
	}
	NormalizeSeverities(checks)
	want := map[string]string{
		"HSTS":               "medium",
		"SQL Injection Test": "critical",
		"Robots.txt Quality": "low",
		"Cache Headers":      "low",
	}
	for _, c := range checks {
		if w, ok := want[c.CheckName]; ok && c.Severity != w {
			t.Errorf("%s: severity = %q, want %q", c.CheckName, c.Severity, w)
		}
	}
	// HSTS must also carry its CVSS metrics after normalization.
	if checks[0].CVSSScore == 0 || checks[0].CVSSVector == "" {
		t.Errorf("HSTS should be CVSS-enriched, got score=%.1f vector=%q", checks[0].CVSSScore, checks[0].CVSSVector)
	}
}

// De-inflating a missing HSTS from critical→medium must RAISE the score (penalty
// drops from critical to medium), proving the fix flows into scoring.
func TestNormalizeSeverities_DeinflatesScore(t *testing.T) {
	mk := func() []models.CheckResult {
		return []models.CheckResult{
			chk("ssl", "TLS Version", "pass", 1000, 100),
			chk("sqli", "SQL Injection Test", "pass", 1000, 70), // injection ran → no coverage cap masks the delta
			chk("headers", "HSTS", "fail", 0, 100),
		}
	}
	before := ComputeScores(mk()).Security
	norm := mk()
	NormalizeSeverities(norm)
	after := ComputeScores(norm).Security
	if !(after > before) {
		t.Errorf("normalizing HSTS to medium should raise the score, got before=%.0f after=%.0f", before, after)
	}
}

// A missing X-Content-Type-Options / X-XSS-Protection header (an "xss"-category
// hardening check) must normalize to Low and must NEVER floor the grade to F —
// the false positive that wrongly F-graded 19 sites.
func TestNormalizeSeverities_HardeningHeaderNeverCaps(t *testing.T) {
	checks := []models.CheckResult{
		chk("ssl", "TLS Version", "pass", 1000, 100),
		chk("xss", "Content-Type & X-XSS-Protection Headers", "fail", 0, 100),
	}
	NormalizeSeverities(checks)
	if checks[1].Severity != "low" {
		t.Errorf("hardening header must normalize to low, got %q", checks[1].Severity)
	}
	if r := ComputeScores(checks); r.CapReason != "" {
		t.Errorf("a missing hardening header must not floor the grade, got cap %q", r.CapReason)
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
		chk("sqli", "SQL Injection Test", "pass", 1000, 70), // injection ran → no coverage cap
		chk("dns", "DNS Security Scanner (timeout)", "error", 0, 80),
		chk("email_security", "Email Security Scanner (timeout)", "error", 0, 80),
	}
	r := ComputeScores(checks)
	if r.Security < 900 {
		t.Errorf("errored scanners must not lower the score, got %.0f", r.Security)
	}
}

// A scan that never performed active vulnerability testing (no injection domains
// ran) is capped at grade B — "not tested" must never read as "excellent".
func TestComputeScores_CoverageCapLimitsGrade(t *testing.T) {
	checks := []models.CheckResult{
		chk("ssl", "TLS Version", "pass", 1000, 100),
		chk("headers", "HSTS", "pass", 1000, 100),
		chk("cookies", "Cookie Security", "pass", 1000, 100),
		// no sqli/xss/ssrf/secrets/etc. → limited coverage
	}
	r := ComputeScores(checks)
	if r.Security > 790 {
		t.Errorf("a limited-coverage scan must be capped at B (<=790), got %.0f", r.Security)
	}
	if SecurityGrade(r.Security) == "A" || SecurityGrade(r.Security) == "A+" {
		t.Errorf("limited coverage must not earn A/A+, got %s", SecurityGrade(r.Security))
	}
	if r.CapReason == "" {
		t.Errorf("coverage cap should set a CapReason")
	}
}

// The injection/exploit multiplier: a confirmed HIGH finding in an injection
// domain must deduct more than the same-severity finding in a low domain.
func TestComputeScores_InjectionWeightedHeavier(t *testing.T) {
	withInjectionFail := []models.CheckResult{
		chk("sqli", "SQL Injection Test", "pass", 1000, 70),
		chk("ssrf", "SSRF Detection", "fail", 250, 90), // high sev, injection domain
	}
	withLowFail := []models.CheckResult{
		chk("sqli", "SQL Injection Test", "pass", 1000, 70),
		chk("server_info", "Server Header", "fail", 250, 90), // same score, low domain
	}
	inj := ComputeScores(withInjectionFail).Security
	low := ComputeScores(withLowFail).Security
	if !(inj < low) {
		t.Errorf("an injection-domain failure should deduct more than a low-domain one, got inj=%.0f low=%.0f", inj, low)
	}
}
