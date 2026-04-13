package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"vscan-mohesr/internal/models"
)

type DataLeakScanner struct{}

func NewDataLeakScanner() *DataLeakScanner { return &DataLeakScanner{} }

func (s *DataLeakScanner) Name() string     { return "Data Leak Scanner" }
func (s *DataLeakScanner) Category() string { return "data_leak" }
func (s *DataLeakScanner) Weight() float64  { return 12.0 }

// breachInfo represents a data breach from HIBP
type breachInfo struct {
	Name         string   `json:"Name"`
	Title        string   `json:"Title"`
	Domain       string   `json:"Domain"`
	BreachDate   string   `json:"BreachDate"`
	PwnCount     int      `json:"PwnCount"`
	Description  string   `json:"Description"`
	DataClasses  []string `json:"DataClasses"`
	IsVerified   bool     `json:"IsVerified"`
	IsSensitive  bool     `json:"IsSensitive"`
}

// pasteInfo represents a paste from HIBP
type pasteInfo struct {
	Source string `json:"Source"`
	Title  string `json:"Title"`
	Date   string `json:"Date"`
}

// Common email prefixes to check for university domains
var emailPrefixes = []string{
	"admin", "info", "contact", "support", "webmaster",
	"it", "helpdesk", "security", "hr", "dean",
	"registrar", "admission", "library", "president",
	"test", "user", "mail", "noreply", "postmaster",
}

func (s *DataLeakScanner) Scan(targetURL string) []models.CheckResult {
	domain := extractHost(targetURL)

	return []models.CheckResult{
		s.checkDomainBreaches(domain),
		s.checkEmailBreaches(domain),
		s.checkPasteExposure(domain),
	}
}

// checkDomainBreaches searches for breaches associated with the domain
func (s *DataLeakScanner) checkDomainBreaches(domain string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Domain Breach History",
		Weight:    5.0,
	}

	// Search HIBP for domain breaches
	breaches := s.searchHIBPDomain(domain)

	details := map[string]interface{}{
		"domain": domain,
	}

	if len(breaches) == 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No known data breaches found for this domain"
		details["breaches_found"] = 0
	} else {
		totalPwned := 0
		var breachList []map[string]interface{}
		var allDataClasses []string
		dataClassSet := map[string]bool{}

		for _, b := range breaches {
			totalPwned += b.PwnCount
			for _, dc := range b.DataClasses {
				if !dataClassSet[dc] {
					dataClassSet[dc] = true
					allDataClasses = append(allDataClasses, dc)
				}
			}
			breachList = append(breachList, map[string]interface{}{
				"name":         b.Name,
				"title":        b.Title,
				"date":         b.BreachDate,
				"records":      b.PwnCount,
				"data_classes": b.DataClasses,
				"verified":     b.IsVerified,
				"description":  truncateStr(b.Description, 200),
			})
		}

		details["breaches_found"] = len(breaches)
		details["total_records_exposed"] = totalPwned
		details["data_types_leaked"] = allDataClasses
		details["breaches"] = breachList

		switch {
		case totalPwned > 100000:
			check.Status = "fail"
			check.Score = 100
			check.Severity = "critical"
			details["message"] = fmt.Sprintf("CRITICAL: %d records exposed across %d breaches. Leaked data includes: %s",
				totalPwned, len(breaches), strings.Join(allDataClasses, ", "))
		case totalPwned > 10000:
			check.Status = "fail"
			check.Score = 300
			check.Severity = "high"
			details["message"] = fmt.Sprintf("HIGH RISK: %d records exposed across %d breaches", totalPwned, len(breaches))
		case totalPwned > 1000:
			check.Status = "warn"
			check.Score = 500
			check.Severity = "medium"
			details["message"] = fmt.Sprintf("%d records exposed across %d breaches", totalPwned, len(breaches))
		default:
			check.Status = "warn"
			check.Score = 700
			check.Severity = "low"
			details["message"] = fmt.Sprintf("%d records exposed in %d breach(es)", totalPwned, len(breaches))
		}

		details["recommendation"] = "1. Force password reset for all affected accounts\n2. Enable 2FA/MFA for all users\n3. Monitor for credential stuffing attacks\n4. Notify affected users per data protection regulations"
	}

	check.Details = toJSON(details)
	return check
}

// checkEmailBreaches checks common email addresses for breaches
func (s *DataLeakScanner) checkEmailBreaches(domain string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Email Breach Detection",
		Weight:    5.0,
	}

	var (
		mu             sync.Mutex
		exposedEmails  []map[string]interface{}
		wg             sync.WaitGroup
		sem            = make(chan struct{}, 3) // HIBP rate limit: max 3 concurrent
	)

	for _, prefix := range emailPrefixes {
		wg.Add(1)
		sem <- struct{}{}
		go func(email string) {
			defer wg.Done()
			defer func() { <-sem }()

			breaches := s.searchHIBPEmail(email)
			if len(breaches) > 0 {
				var breachNames []string
				var dataTypes []string
				dataSet := map[string]bool{}
				for _, b := range breaches {
					breachNames = append(breachNames, b.Name+" ("+b.BreachDate+")")
					for _, dc := range b.DataClasses {
						if !dataSet[dc] {
							dataSet[dc] = true
							dataTypes = append(dataTypes, dc)
						}
					}
				}
				mu.Lock()
				exposedEmails = append(exposedEmails, map[string]interface{}{
					"email":       email,
					"breach_count": len(breaches),
					"breaches":    breachNames,
					"data_leaked": dataTypes,
				})
				mu.Unlock()
			}

			// HIBP rate limit: 1.5s between requests
			time.Sleep(1600 * time.Millisecond)
		}(prefix + "@" + domain)
	}

	wg.Wait()

	details := map[string]interface{}{
		"domain":         domain,
		"emails_checked": len(emailPrefixes),
	}

	if len(exposedEmails) == 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = fmt.Sprintf("No breached emails found (checked %d common addresses)", len(emailPrefixes))
		details["exposed_count"] = 0
	} else {
		details["exposed_count"] = len(exposedEmails)
		details["exposed_emails"] = exposedEmails

		switch {
		case len(exposedEmails) > 10:
			check.Status = "fail"
			check.Score = 100
			check.Severity = "critical"
			details["message"] = fmt.Sprintf("CRITICAL: %d university email addresses found in data breaches", len(exposedEmails))
		case len(exposedEmails) > 5:
			check.Status = "fail"
			check.Score = 300
			check.Severity = "high"
			details["message"] = fmt.Sprintf("%d university emails found in breaches", len(exposedEmails))
		default:
			check.Status = "warn"
			check.Score = 600
			check.Severity = "medium"
			details["message"] = fmt.Sprintf("%d university email(s) found in breaches", len(exposedEmails))
		}

		details["recommendation"] = "1. Immediately change passwords for exposed accounts\n2. Check if these credentials were reused on other systems\n3. Enable Multi-Factor Authentication (MFA)\n4. Train staff on phishing awareness"
	}

	check.Details = toJSON(details)
	return check
}

// checkPasteExposure checks if domain emails appear in public pastes
func (s *DataLeakScanner) checkPasteExposure(domain string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Paste Site Exposure",
		Weight:    2.0,
	}

	// Check a few key emails for paste exposure
	keyEmails := []string{"admin@" + domain, "info@" + domain, "it@" + domain}
	var exposedPastes []map[string]interface{}

	for _, email := range keyEmails {
		pastes := s.searchHIBPPastes(email)
		if len(pastes) > 0 {
			for _, p := range pastes {
				exposedPastes = append(exposedPastes, map[string]interface{}{
					"email":  email,
					"source": p.Source,
					"title":  p.Title,
					"date":   p.Date,
				})
			}
		}
		time.Sleep(1600 * time.Millisecond) // HIBP rate limit
	}

	details := map[string]interface{}{"domain": domain}

	if len(exposedPastes) == 0 {
		check.Status = "pass"
		check.Score = MaxScore
		check.Severity = "info"
		details["message"] = "No university emails found in public paste sites"
	} else {
		check.Status = "fail"
		check.Score = 300
		check.Severity = "high"
		details["message"] = fmt.Sprintf("%d paste(s) found containing university email addresses", len(exposedPastes))
		details["pastes"] = exposedPastes
		details["recommendation"] = "Paste sites often contain leaked credentials. Investigate each paste and force password resets for affected accounts."
	}

	check.Details = toJSON(details)
	return check
}

// --- HIBP API calls ---

func (s *DataLeakScanner) searchHIBPDomain(domain string) []breachInfo {
	// Use the public breaches endpoint filtered by domain
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://haveibeenpwned.com/api/v3/breaches", nil)
	req.Header.Set("User-Agent", "Seku-Scanner")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	var allBreaches []breachInfo
	json.Unmarshal(body, &allBreaches)

	// Filter breaches that match the domain
	var matched []breachInfo
	domainLower := strings.ToLower(domain)
	for _, b := range allBreaches {
		if strings.Contains(strings.ToLower(b.Domain), domainLower) {
			matched = append(matched, b)
		}
	}
	return matched
}

func (s *DataLeakScanner) searchHIBPEmail(email string) []breachInfo {
	// HIBP v3 API (public, no key needed for breach check via alternative)
	// Use breach directory search as fallback
	client := &http.Client{Timeout: 10 * time.Second}

	// Try the free breach search API
	url := "https://haveibeenpwned.com/api/v3/breachedaccount/" + email + "?truncateResponse=false"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Seku-Scanner")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil // Not found = not breached
	}
	if resp.StatusCode == 401 {
		// API key required — use alternative: check breachdirectory.org
		return s.searchBreachDirectory(email)
	}
	if resp.StatusCode != 200 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	var breaches []breachInfo
	json.Unmarshal(body, &breaches)
	return breaches
}

func (s *DataLeakScanner) searchBreachDirectory(email string) []breachInfo {
	// Alternative free API: breachdirectory.org (no key needed)
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://breachdirectory.org/api/search?email="+email, nil)
	req.Header.Set("User-Agent", "Seku-Scanner")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))

	var result struct {
		Success bool `json:"success"`
		Result  []struct {
			Sources  []string `json:"sources"`
			Password string   `json:"password"`
			Sha1     string   `json:"sha1"`
		} `json:"result"`
	}

	if json.Unmarshal(body, &result) != nil || !result.Success {
		return nil
	}

	if len(result.Result) == 0 {
		return nil
	}

	// Convert to breachInfo format
	sourceSet := map[string]bool{}
	var sources []string
	hasPassword := false
	for _, r := range result.Result {
		for _, src := range r.Sources {
			if !sourceSet[src] {
				sourceSet[src] = true
				sources = append(sources, src)
			}
		}
		if r.Password != "" || r.Sha1 != "" {
			hasPassword = true
		}
	}

	dataClasses := []string{"Email addresses"}
	if hasPassword {
		dataClasses = append(dataClasses, "Passwords")
	}

	return []breachInfo{{
		Name:        strings.Join(sources, ", "),
		Title:       fmt.Sprintf("Found in %d breach source(s)", len(sources)),
		BreachDate:  "Unknown",
		PwnCount:    len(result.Result),
		DataClasses: dataClasses,
		IsVerified:  true,
	}}
}

func (s *DataLeakScanner) searchHIBPPastes(email string) []pasteInfo {
	client := &http.Client{Timeout: 10 * time.Second}
	url := "https://haveibeenpwned.com/api/v3/pasteaccount/" + email
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Seku-Scanner")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	var pastes []pasteInfo
	json.Unmarshal(body, &pastes)
	return pastes
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
