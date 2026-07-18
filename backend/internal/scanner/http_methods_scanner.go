package scanner

import (
	"fmt"
	"io"
	"net/http"
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
		Timeout:   10 * time.Second,
		Transport: ScanTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	targetURL := ensureHTTPS(url)

	// GET baseline. Many origins (WordPress/Apache/cPanel) serve the homepage with
	// a 200 for ANY method without processing it — so a 2xx alone is a false
	// positive. We only flag a method whose response shows it was actually handled
	// (201/204, a substantially different body, or a TRACE that echoes the request).
	getBody, _, _ := fetchLowerBody(client, targetURL, 64*1024)
	getLen := len(getBody)

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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if httpMethodProcessed(method, resp.StatusCode, len(body), getLen, string(body)) {
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
				// Advertising methods (including PUT/DELETE/PATCH) in the Allow
				// header is standard, correct REST behaviour — not a vulnerability.
				// Whether those methods are actually exploitable is verified by the
				// "Dangerous HTTP Methods" check above, so OPTIONS disclosure is
				// purely informational and never caps the grade.
				optCheck.Status = "pass"
				optCheck.Score = 1000
				optCheck.Severity = "info"
				optCheck.Details = toJSON(map[string]string{
					"message": "OPTIONS advertises supported methods (informational; exploitability tested separately)",
					"allow":   allow,
				})
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
