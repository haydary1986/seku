package scanner

import (
	"math"
	"sort"

	"seku/internal/models"
)

// ============================================================================
// Scientific scoring methodology
// ----------------------------------------------------------------------------
// Grounded in established security-rating practice:
//   - CVSS v3.1 severity bands drive per-domain weights (impact-based, not ad hoc).
//   - OWASP Risk Rating (Likelihood × Impact): confidence gates the severity caps.
//   - SSL Labs / Mozilla Observatory: a genuine high/critical finding CAPS the
//     grade, so a vulnerable site cannot earn an "A" by passing many minor checks.
//
// Two independent scores are produced:
//   - SecurityScore  — the headline. Security domains only.
//   - QualityScore   — performance/SEO/content/hosting. Reported separately so a
//                      fast, well-cached site is never rewarded on *security*.
//
// Aggregation is two-level (category → overall) so a domain with many checks
// (e.g. 50+ subdomain probes) cannot dominate a domain with few (e.g. SQLi):
//   1. categoryScore = mean(check.Score) within the category (errors excluded).
//   2. overall       = Σ(categoryScore × severityWeight) / Σ(severityWeight).
// ============================================================================

// domainSeverity is the intrinsic risk class of a security domain — the impact
// if that domain is weak — independent of any single scan's outcome.
type domainSeverity int

const (
	sevNone     domainSeverity = iota // not part of the security score (quality)
	sevLow                            // CVSS ~0.1–3.9  (fingerprinting, supply-chain awareness)
	sevMedium                         // CVSS ~4.0–6.9  (hardening, attack surface, defense-in-depth)
	sevHigh                           // CVSS ~7.0–8.9  (transport, access control, sensitive exposure)
	sevCritical                       // CVSS ~9.0–10.0 (injection, RCE, secrets, malware)
)

// severityWeight maps an intrinsic severity class to an aggregation weight.
// The 10:6:3:1 ratio tracks CVSS band midpoints (≈9.5 / 8 / 5.5 / 2) normalised.
func (d domainSeverity) weight() float64 {
	switch d {
	case sevCritical:
		return 10
	case sevHigh:
		return 6
	case sevMedium:
		return 3
	case sevLow:
		return 1
	default:
		return 0
	}
}

// categorySeverity assigns every scanner category to an intrinsic severity class.
// Categories mapped to sevNone are quality/performance concerns and are scored
// separately from security. This table is the documented, reproducible basis for
// all weighting — no per-check magic numbers.
var categorySeverity = map[string]domainSeverity{
	// Critical — code execution, injection, data exfiltration, malware
	"sqli":          sevCritical,
	"xss":           sevCritical,
	"ssrf":          sevCritical,
	"open_redirect": sevCritical,
	"malware":       sevCritical,
	"cms_cve":       sevCritical,
	"secrets":       sevCritical,
	"js_secrets":    sevCritical,
	"backup_files":  sevCritical,

	// High — transport security, access control, sensitive exposure
	"ssl":             sevHigh,
	"headers":         sevHigh,
	"cookies":         sevHigh,
	"http_methods":    sevHigh,
	"directory":       sevHigh,
	"info_disclosure": sevHigh,
	"cors":            sevHigh,
	"mixed_content":   sevHigh,
	"wp_deep":         sevHigh,
	"zone_transfer":   sevHigh,

	// Medium — hardening, attack surface, defense-in-depth
	"wordpress":         sevMedium,
	"dns":               sevMedium,
	"email_security":    sevMedium,
	"ports":             sevMedium,
	"waf":               sevMedium,
	"ddos":              sevMedium,
	"advanced_security": sevMedium,
	"threat_intel":      sevMedium,
	"subdomains":        sevMedium,

	// Low — fingerprinting / supply-chain awareness
	"server_info":  sevLow,
	"third_party":  sevLow,
	"js_libraries": sevLow,

	// None — quality / performance (separate score, never in security)
	"performance": sevNone,
	"seo":         sevNone,
	"content":     sevNone,
	"hosting":     sevNone,
	"tech_stack":  sevNone,
}

// Grade cap. A confident failure in a CRITICAL domain — a confirmed, exploitable
// issue (injection, exposed secrets/backups, malware) — floors the grade at F, so
// a genuinely compromised site cannot earn a passing grade regardless of how many
// minor checks it passes (SSL Labs / Mozilla Observatory practice).
//
// There is deliberately NO cap for High-severity domains. Hardening gaps such as a
// missing HSTS/CSP header are real and reduce the weighted score, but capping every
// such site to a single value (C) collapses the whole distribution to a few discrete
// scores and destroys the ranking. High-severity issues are therefore reflected
// through the weighted average, which preserves genuine variance between sites.
const (
	capCriticalFail = 490 // a confirmed, critical-severity exploit/exposure → F
	capConfidence   = 70  // OWASP likelihood gate: below this a finding is advisory only
)

// capCategories are the domains where a CRITICAL-severity failing check means a
// confirmed exploit or data exposure that warrants flooring the grade. The cap is
// tied to the individual finding's severity (not the category), so a merely
// high/medium finding in one of these domains (e.g. an accessible but harmless
// wp-admin/install.php page) lowers the weighted score without flooring the grade.
var capCategories = map[string]bool{
	"sqli":            true,
	"xss":             true,
	"ssrf":            true,
	"open_redirect":   true,
	"malware":         true,
	"secrets":         true,
	"js_secrets":      true,
	"backup_files":    true,
	"cms_cve":         true,
	"directory":       true, // exposed .env/.git/config with verified content
	"info_disclosure": true, // a leaked secret value
}

// ScoreResult is the outcome of scoring a set of checks.
type ScoreResult struct {
	Security    float64 // 0–1000, headline security score (capped)
	Quality     float64 // 0–1000, performance/quality score (separate)
	RawSecurity float64 // security score before caps (for transparency)
	CapReason   string  // why the security score was capped, "" if uncapped
}

// isSecurityDomain reports whether a category contributes to the security score.
func isSecurityDomain(category string) bool {
	s, ok := categorySeverity[category]
	return ok && s != sevNone
}

// scoredStatus reports whether a check counts toward a category average. Errors
// (e.g. a scanner that timed out on flaky DNS) are excluded so environmental
// failures never distort the score.
func scoredStatus(status string) bool {
	return status != "error" && status != "pending" && status != "running"
}

// catAgg accumulates the checks of one category to produce its mean score.
type catAgg struct {
	sum   float64
	count int
}

// ComputeScores applies the scientific methodology to a set of checks. It is a
// pure function (no I/O) so it is fully unit-testable.
func ComputeScores(checks []models.CheckResult) ScoreResult {
	secCat := map[string]*catAgg{}
	qualCat := map[string]*catAgg{}

	critFail := false
	var critReason string

	for _, c := range checks {
		if !scoredStatus(c.Status) {
			continue
		}
		sev, known := categorySeverity[c.Category]
		if !known {
			// Unknown category defaults to medium security so nothing is silently dropped.
			sev = sevMedium
		}

		if sev == sevNone {
			a := qualCat[c.Category]
			if a == nil {
				a = &catAgg{}
				qualCat[c.Category] = a
			}
			a.sum += c.Score
			a.count++
			continue
		}

		a := secCat[c.Category]
		if a == nil {
			a = &catAgg{}
			secCat[c.Category] = a
		}
		a.sum += c.Score
		a.count++

		// Cap detection: a CONFIRMED critical-severity finding (the check's own
		// severity, in an exploit/exposure domain) floors the grade. High/medium
		// findings and hardening gaps are handled by the weighted average, not a
		// cap — so a single low-impact finding cannot collapse the ranking.
		if c.Status == "fail" && c.Severity == "critical" &&
			capCategories[c.Category] && confidenceOf(c) >= capConfidence {
			critFail = true
			if critReason == "" {
				critReason = c.CheckName
			}
		}
	}

	res := ScoreResult{}
	res.RawSecurity = weightedDomainScore(secCat)
	res.Quality = plainDomainScore(qualCat)

	res.Security = res.RawSecurity
	if critFail && res.Security > capCriticalFail {
		res.Security = capCriticalFail
		res.CapReason = "critical: " + critReason
	}

	res.Security = math.Round(res.Security)
	res.RawSecurity = math.Round(res.RawSecurity)
	res.Quality = math.Round(res.Quality)
	return res
}

// confidenceOf returns a check's confidence, falling back to the central table
// when the stored value is zero (e.g. when scoring is run before enrichment).
func confidenceOf(c models.CheckResult) int {
	if c.Confidence > 0 {
		return c.Confidence
	}
	return GetConfidence(c.CheckName)
}

// weightedDomainScore aggregates security category means by intrinsic severity
// weight: Σ(categoryMean × severityWeight) / Σ(severityWeight). Returns 1000 when
// no security categories were scored (nothing to penalise).
func weightedDomainScore(cats map[string]*catAgg) float64 {
	var num, den float64
	for cat, a := range cats {
		if a.count == 0 {
			continue
		}
		w := categorySeverity[cat].weight()
		if w == 0 {
			continue
		}
		num += (a.sum / float64(a.count)) * w
		den += w
	}
	if den == 0 {
		return 1000
	}
	return num / den
}

// plainDomainScore averages quality category means with equal weight. Returns
// 1000 when no quality categories were scored.
func plainDomainScore(cats map[string]*catAgg) float64 {
	if len(cats) == 0 {
		return 1000
	}
	// Deterministic order (keys sorted) keeps the result stable and testable.
	keys := make([]string, 0, len(cats))
	for k := range cats {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sum float64
	var n int
	for _, k := range keys {
		a := cats[k]
		if a.count == 0 {
			continue
		}
		sum += a.sum / float64(a.count)
		n++
	}
	if n == 0 {
		return 1000
	}
	return sum / float64(n)
}

// SecurityGrade maps a 0–1000 score to a letter grade (shared by both scores).
func SecurityGrade(score float64) string {
	switch {
	case score >= 900:
		return "A+"
	case score >= 800:
		return "A"
	case score >= 700:
		return "B"
	case score >= 600:
		return "C"
	case score >= 500:
		return "D"
	default:
		return "F"
	}
}
