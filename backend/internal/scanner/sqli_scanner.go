package scanner

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"seku/internal/models"
)

type SQLiScanner struct{}

func NewSQLiScanner() *SQLiScanner { return &SQLiScanner{} }

func (s *SQLiScanner) Name() string     { return "SQL Injection Scanner" }
func (s *SQLiScanner) Category() string { return "sqli" }
func (s *SQLiScanner) Weight() float64  { return 15.0 }

// sqliPayloads — minimal, low-noise payloads that detect error-based SQLi
// without triggering most WAF signature rules.
var sqliPayloads = []string{
	"'",         // single quote — triggers syntax error if unescaped
	"1 AND 1=1", // tautology — harmless if properly parameterized
	"1'\"",      // mixed quotes — triggers error in bad parsers
}

// sqliErrorSignatures are database error strings that indicate SQL injection vulnerability.
var sqliErrorSignatures = []string{
	// MySQL
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark",
	"mysql_fetch",
	"mysql_num_rows",
	"mysql_query",
	// PostgreSQL
	"pg_query",
	"pg_exec",
	"psql error",
	"unterminated quoted string",
	"syntax error at or near",
	// MSSQL
	"microsoft ole db provider",
	"microsoft sql native client",
	"unclosed quotation mark after the character string",
	"mssql_query",
	// SQLite
	"sqlite_error",
	"sqlite3::query",
	"near \":\": syntax error",
	"unrecognized token",
	// Oracle
	"ora-00933",
	"ora-00921",
	"ora-01756",
	"oracle error",
	// Generic
	"sql syntax",
	"sql error",
	"database error",
	"odbc driver",
	"jdbc error",
	"pdo exception",
	"sqlstate",
}

// commonParams — focused set of parameters most likely to be vulnerable.
var commonParams = []string{
	"id", "page", "cat", "search", "q", "lang", "type",
}

func (s *SQLiScanner) Scan(targetURL string) []models.CheckResult {
	return []models.CheckResult{
		s.checkSQLiVulnerability(targetURL),
		s.checkErrorBasedSQLi(targetURL),
	}
}

// checkSQLiVulnerability tests common URL parameters for SQL injection.
func (s *SQLiScanner) checkSQLiVulnerability(targetURL string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "SQL Injection Test",
		Weight:    10.0,
	}

	client := NewScanClient(10 * time.Second)

	baseURL := ensureHTTPS(targetURL)
	var vulnerableParams []map[string]string
	testedCount := 0

	for _, param := range commonParams {
		// Benign baseline for this parameter. Any error signature already present
		// here (site content, a soft-404, or a WAF block page) is NOT evidence of
		// injection and must be excluded from the payload comparison.
		baseBody, _, baseOK := fetchLowerBody(client, fmt.Sprintf("%s?%s=1", baseURL, param), 100*1024)
		baselineSigs := map[string]bool{}
		if baseOK {
			baselineSigs = signaturesIn(baseBody, sqliErrorSignatures)
		}

		for _, payload := range sqliPayloads {
			testURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
			testedCount++

			body, status, ok := fetchLowerBody(client, testURL, 100*1024)
			if !ok {
				continue
			}
			// A WAF/edge block is not the application returning a DB error.
			if isBlockedStatus(status) {
				continue
			}

			for _, sig := range sqliErrorSignatures {
				// Only count a signature that appears BECAUSE of the payload.
				if baselineSigs[sig] {
					continue
				}
				if strings.Contains(body, sig) {
					vulnerableParams = append(vulnerableParams, map[string]string{
						"parameter": param,
						"payload":   payload,
						"evidence":  sig,
					})
					break
				}
			}

			if len(vulnerableParams) > 0 {
				break // Move to next param once vulnerability found
			}
		}
		if len(vulnerableParams) > 0 {
			break
		}
	}

	details := map[string]interface{}{
		"parameters_tested": testedCount,
	}

	if len(vulnerableParams) > 0 {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["message"] = fmt.Sprintf("SQL Injection vulnerability detected in %d parameter(s)", len(vulnerableParams))
		details["vulnerable_parameters"] = vulnerableParams
	} else {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = fmt.Sprintf("No SQL injection detected in %d tests", testedCount)
	}

	check.Details = toJSON(details)
	return check
}

// checkErrorBasedSQLi checks if the application reveals database errors.
func (s *SQLiScanner) checkErrorBasedSQLi(targetURL string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Database Error Disclosure",
		Weight:    5.0,
	}

	client := NewScanClientNoRedirect(10 * time.Second)

	base := ensureHTTPS(targetURL)

	// Baseline (benign) response — signatures already here are page content or a
	// WAF block page, not disclosure caused by the payload.
	baseBody, _, baseOK := fetchLowerBody(client, base+"?id=1", 100*1024)

	// Payload response.
	bodyLower, status, ok := fetchLowerBody(client, base+"?id=1'", 100*1024)
	if !ok {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Could not reach target for error disclosure test"})
		return check
	}
	if isBlockedStatus(status) {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Error-probe request was blocked by a WAF/edge (no disclosure)"})
		return check
	}

	// Verbose DB/framework error signatures. Only specific patterns — generic
	// words like "exception" (matches "exceptional"), "warning:", "notice:",
	// "debug" produced false positives on ordinary pages, so they are excluded.
	errorPatterns := []string{
		"stack trace", "traceback (most recent call last)",
		"fatal error:", "call stack", "server error in '",
		"whoops, looks like something went wrong",
	}
	allPatterns := append(append([]string{}, sqliErrorSignatures...), errorPatterns...)

	baselineSigs := map[string]bool{}
	if baseOK {
		baselineSigs = signaturesIn(baseBody, allPatterns)
	}

	var foundErrors []string
	for _, sig := range allPatterns {
		if baselineSigs[sig] {
			continue // present without the payload → not disclosure
		}
		if strings.Contains(bodyLower, sig) {
			foundErrors = append(foundErrors, sig)
		}
	}

	details := map[string]interface{}{}

	if len(foundErrors) > 0 {
		check.Status = "fail"
		check.Score = 200
		check.Severity = "high"
		details["message"] = "Application reveals database/server error details to users"
		details["errors_found"] = foundErrors
		details["recommendation"] = "Configure custom error pages and disable verbose error output in production"
	} else {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No database error disclosure detected"
	}

	check.Details = toJSON(details)
	return check
}
