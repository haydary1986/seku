package scanner

import (
	"fmt"
	"io"
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
	"'",           // single quote — triggers syntax error if unescaped
	"1 AND 1=1",   // tautology — harmless if properly parameterized
	"1'\"",        // mixed quotes — triggers error in bad parsers
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
		for _, payload := range sqliPayloads {
			testURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
			testedCount++

			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}

			body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024)) // 100KB limit
			resp.Body.Close()
			if err != nil {
				continue
			}

			bodyLower := strings.ToLower(string(body))

			for _, sig := range sqliErrorSignatures {
				if strings.Contains(bodyLower, sig) {
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

	// Test with a simple quote to trigger error
	testURL := ensureHTTPS(targetURL) + "?id=1'"
	resp, err := client.Get(testURL)
	if err != nil {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Could not reach target for error disclosure test"})
		return check
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	resp.Body.Close()
	if err != nil {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		check.Details = toJSON(map[string]string{"message": "Could not read response body"})
		return check
	}

	bodyLower := strings.ToLower(string(body))
	var foundErrors []string

	// Check for verbose database error messages
	errorPatterns := []string{
		"stack trace", "exception", "traceback",
		"fatal error", "warning:", "notice:",
		"debug", "server error in",
	}
	allPatterns := append(sqliErrorSignatures, errorPatterns...)

	for _, sig := range allPatterns {
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
