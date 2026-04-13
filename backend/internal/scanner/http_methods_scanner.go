package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"seku/internal/models"
)

type HTTPMethodsScanner struct{}

func NewHTTPMethodsScanner() *HTTPMethodsScanner {
	return &HTTPMethodsScanner{}
}

func (s *HTTPMethodsScanner) Name() string     { return "HTTP Methods Scanner" }
func (s *HTTPMethodsScanner) Category() string { return "http_methods" }
func (s *HTTPMethodsScanner) Weight() float64  { return 8.0 }

func (s *HTTPMethodsScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: ScanTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	targetURL := ensureHTTPS(url)

	// Check dangerous HTTP methods
	dangerousMethods := []string{"TRACE", "DELETE", "PUT", "PATCH"}
	allowedDangerous := []string{}

	for _, method := range dangerousMethods {
		req, err := http.NewRequest(method, targetURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 405 && resp.StatusCode != 501 && resp.StatusCode != 403 {
			allowedDangerous = append(allowedDangerous, fmt.Sprintf("%s (HTTP %d)", method, resp.StatusCode))
		}
	}

	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Dangerous HTTP Methods",
		Weight:    4.0,
	}

	if len(allowedDangerous) == 0 {
		check.Status = "pass"
		check.Score = 1000
		check.Severity = "info"
		check.Details = toJSON(map[string]string{
			"message": "Dangerous HTTP methods (TRACE, DELETE, PUT, PATCH) are properly disabled",
		})
	} else if len(allowedDangerous) == 1 {
		// Single dangerous method enabled - bad but not catastrophic
		check.Status = "fail"
		check.Score = 275
		check.Severity = "high"
		check.Details = toJSON(map[string]interface{}{
			"message":         "A dangerous HTTP method is enabled",
			"allowed_methods": allowedDangerous,
		})
	} else if len(allowedDangerous) == 2 {
		check.Status = "fail"
		check.Score = 175
		check.Severity = "high"
		check.Details = toJSON(map[string]interface{}{
			"message":         "Multiple dangerous HTTP methods are enabled",
			"allowed_methods": allowedDangerous,
		})
	} else {
		// 3 or more dangerous methods
		check.Status = "fail"
		check.Score = 75
		check.Severity = "critical"
		check.Details = toJSON(map[string]interface{}{
			"message":         "Many dangerous HTTP methods are enabled",
			"allowed_methods": allowedDangerous,
		})
	}
	results = append(results, check)

	// Check OPTIONS response
	optCheck := models.CheckResult{
		Category:  s.Category(),
		CheckName: "OPTIONS Method Disclosure",
		Weight:    4.0,
	}

	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			allow := resp.Header.Get("Allow")
			if allow != "" {
				hasDangerous := strings.Contains(allow, "TRACE") || strings.Contains(allow, "DELETE")
				hasPut := strings.Contains(allow, "PUT") || strings.Contains(allow, "PATCH")

				if hasDangerous && hasPut {
					// Discloses multiple dangerous methods
					optCheck.Status = "fail"
					optCheck.Score = 225
					optCheck.Severity = "high"
					optCheck.Details = toJSON(map[string]string{
						"message":         "OPTIONS response discloses many dangerous methods",
						"allowed_methods": allow,
					})
				} else if hasDangerous {
					// Discloses TRACE or DELETE
					optCheck.Status = "warn"
					optCheck.Score = 375
					optCheck.Severity = "medium"
					optCheck.Details = toJSON(map[string]string{
						"message":         "OPTIONS response discloses dangerous methods including TRACE/DELETE",
						"allowed_methods": allow,
					})
				} else if hasPut {
					// Discloses PUT/PATCH only
					optCheck.Status = "warn"
					optCheck.Score = 450
					optCheck.Severity = "medium"
					optCheck.Details = toJSON(map[string]string{
						"message":         "OPTIONS response discloses PUT/PATCH methods",
						"allowed_methods": allow,
					})
				} else {
					// OPTIONS responds with Allow header but only safe methods
					optCheck.Status = "pass"
					optCheck.Score = 925
					optCheck.Severity = "info"
					optCheck.Details = toJSON(map[string]string{
						"message": "OPTIONS response lists only safe methods",
						"allow":   allow,
					})
				}
			} else {
				// OPTIONS accessible but no Allow header
				optCheck.Status = "pass"
				optCheck.Score = 1000
				optCheck.Severity = "info"
				optCheck.Details = toJSON(map[string]string{
					"message": "OPTIONS method properly configured",
					"allow":   allow,
				})
			}
		} else {
			optCheck.Status = "pass"
			optCheck.Score = 1000
			optCheck.Severity = "info"
			optCheck.Details = toJSON(map[string]string{"message": "OPTIONS method not accessible"})
		}
	}
	results = append(results, optCheck)

	return results
}
