package scanner

import "seku/internal/models"

// RunPolicy runs all scanners for a policy against a single URL and returns
// fully-enriched CheckResults WITHOUT any database dependency. This is what the
// standalone local agent (and CLI tools) use — it mirrors the enrichment the
// server applies in RunScan, but keeps the scan path DB-free so it can be
// cross-compiled (CGO-free) and run inside a customer's network.
func RunPolicy(policy, url string, cfg *ScanConfig) []models.CheckResult {
	e := NewEngineForPolicy(policy)

	var all []models.CheckResult
	for _, s := range e.scanners {
		all = append(all, runScannerBounded(s, url, cfg)...)
	}

	for i := range all {
		if m := GetOWASPMapping(all[i].CheckName); m != nil {
			all[i].OWASP = m.OWASP
			all[i].OWASPName = m.OWASPName
			all[i].CWE = m.CWE
			all[i].CWEName = m.CWEName
		}
		all[i].Confidence = GetConfidence(all[i].CheckName)
		if m := GetCVSSMapping(all[i].CheckName); m != nil && all[i].Status == "fail" {
			all[i].CVSSScore = m.Score
			all[i].CVSSVector = m.Vector
			all[i].CVSSRating = m.Rating
		}
	}
	// Pin each finding's severity to its CVSS-map rating so hardcoded per-scanner
	// severities can't inflate a finding on the standalone path (matches the
	// server path, which calls this after scanning).
	NormalizeSeverities(all)
	return all
}
