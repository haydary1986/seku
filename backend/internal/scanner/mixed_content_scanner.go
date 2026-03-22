package scanner

import (
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type MixedContentScanner struct{}

func NewMixedContentScanner() *MixedContentScanner {
	return &MixedContentScanner{}
}

func (s *MixedContentScanner) Name() string     { return "Mixed Content Scanner" }
func (s *MixedContentScanner) Category() string { return "mixed_content" }
func (s *MixedContentScanner) Weight() float64  { return 7.0 }

func (s *MixedContentScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	targetURL := ensureHTTPS(url)
	resp, err := client.Get(targetURL)
	if err != nil {
		return []models.CheckResult{{
			Category:  s.Category(),
			CheckName: "Mixed Content",
			Status:    "error",
			Score:     0,
			Weight:    s.Weight(),
			Severity:  "medium",
			Details:   toJSON(map[string]string{"error": "Cannot reach website via HTTPS"}),
		}}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // Read up to 512KB
	bodyStr := string(body)

	// Check for HTTP resources in HTTPS page
	results = append(results, s.checkMixedScripts(bodyStr))
	results = append(results, s.checkMixedImages(bodyStr))
	results = append(results, s.checkMixedForms(bodyStr))

	return results
}

func (s *MixedContentScanner) checkMixedScripts(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Mixed Active Content (Scripts/CSS)",
		Weight:    3.0,
	}

	// Match http:// in src= or href= for scripts and CSS
	scriptPattern := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']http://[^"']+\.(js|css)["']`)
	matches := scriptPattern.FindAllString(body, -1)

	if len(matches) > 5 {
		// Many mixed active content resources - extremely dangerous
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		check.Details = toJSON(map[string]interface{}{
			"message":  "Extensive mixed active content found - many HTTP scripts/CSS loaded on HTTPS page",
			"count":    len(matches),
			"examples": matches[:min(len(matches), 5)],
		})
	} else if len(matches) > 2 {
		// Several mixed active content resources
		check.Status = "fail"
		check.Score = 75
		check.Severity = "critical"
		check.Details = toJSON(map[string]interface{}{
			"message":  "Multiple mixed active content resources found - HTTP scripts/CSS loaded on HTTPS page",
			"count":    len(matches),
			"examples": matches[:min(len(matches), 5)],
		})
	} else if len(matches) > 0 {
		// A few mixed active content resources
		check.Status = "fail"
		check.Score = 150
		check.Severity = "high"
		check.Details = toJSON(map[string]interface{}{
			"message":  "Mixed active content found - HTTP scripts/CSS loaded on HTTPS page",
			"count":    len(matches),
			"examples": matches[:min(len(matches), 5)],
		})
	} else {
		check.Status = "pass"
		check.Score = 1000
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No mixed active content (scripts/CSS) detected",
		})
	}

	return check
}

func (s *MixedContentScanner) checkMixedImages(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Mixed Passive Content (Images/Media)",
		Weight:    2.0,
	}

	imgPattern := regexp.MustCompile(`(?i)(src)\s*=\s*["']http://[^"']+\.(jpg|jpeg|png|gif|svg|webp|mp4|mp3)["']`)
	matches := imgPattern.FindAllString(body, -1)

	if len(matches) > 10 {
		// Many mixed passive resources
		check.Status = "warn"
		check.Score = 275
		check.Severity = "high"
		check.Details = toJSON(map[string]interface{}{
			"message":  "Extensive mixed passive content - many HTTP images/media on HTTPS page",
			"count":    len(matches),
			"examples": matches[:min(len(matches), 5)],
		})
	} else if len(matches) > 3 {
		// Several mixed passive resources
		check.Status = "warn"
		check.Score = 375
		check.Severity = "medium"
		check.Details = toJSON(map[string]interface{}{
			"message":  "Multiple mixed passive content found - HTTP images/media on HTTPS page",
			"count":    len(matches),
			"examples": matches[:min(len(matches), 5)],
		})
	} else if len(matches) > 0 {
		// A few mixed passive resources - less severe than active content
		check.Status = "warn"
		check.Score = 475
		check.Severity = "medium"
		check.Details = toJSON(map[string]interface{}{
			"message":  "Mixed passive content found - HTTP images/media on HTTPS page",
			"count":    len(matches),
			"examples": matches[:min(len(matches), 5)],
		})
	} else {
		check.Status = "pass"
		check.Score = 1000
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No mixed passive content detected",
		})
	}

	return check
}

func (s *MixedContentScanner) checkMixedForms(body string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Insecure Form Actions",
		Weight:    2.0,
	}

	formPattern := regexp.MustCompile(`(?i)action\s*=\s*["']http://[^"']+["']`)
	matches := formPattern.FindAllString(body, -1)

	// Also check for password fields with http action
	hasPasswordField := strings.Contains(strings.ToLower(body), `type="password"`) || strings.Contains(strings.ToLower(body), `type='password'`)

	if len(matches) > 0 {
		if hasPasswordField {
			// Insecure form with password field - critical vulnerability
			check.Status = "fail"
			check.Score = 0
			check.Severity = "critical"
			check.Details = toJSON(map[string]interface{}{
				"message":            "Forms with password fields submit data over insecure HTTP",
				"count":              len(matches),
				"has_password_field": hasPasswordField,
				"examples":           matches[:min(len(matches), 3)],
			})
		} else if len(matches) > 3 {
			// Many insecure forms without passwords
			check.Status = "fail"
			check.Score = 75
			check.Severity = "critical"
			check.Details = toJSON(map[string]interface{}{
				"message":            "Many forms submit data over insecure HTTP",
				"count":              len(matches),
				"has_password_field": hasPasswordField,
				"examples":           matches[:min(len(matches), 3)],
			})
		} else {
			// A few insecure forms without passwords
			check.Status = "fail"
			check.Score = 150
			check.Severity = "high"
			check.Details = toJSON(map[string]interface{}{
				"message":            "Forms submit data over insecure HTTP",
				"count":              len(matches),
				"has_password_field": hasPasswordField,
				"examples":           matches[:min(len(matches), 3)],
			})
		}
	} else {
		check.Status = "pass"
		check.Score = 1000
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "No insecure form actions detected",
		})
	}

	return check
}

