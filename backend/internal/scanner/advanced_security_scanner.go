package scanner

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

// Sub-check weights for the Advanced Security Scanner.
const (
	weightCOEP        = 12.0
	weightCOOP        = 12.0
	weightCORP        = 12.0
	weightOCSPStapling = 15.0
)

type AdvancedSecurityScanner struct{}

func NewAdvancedSecurityScanner() *AdvancedSecurityScanner {
	return &AdvancedSecurityScanner{}
}

func (s *AdvancedSecurityScanner) Name() string     { return "Advanced Security Scanner" }
func (s *AdvancedSecurityScanner) Category() string { return "advanced_security" }
func (s *AdvancedSecurityScanner) Weight() float64  { return 5.0 }

func (s *AdvancedSecurityScanner) Scan(url string) []models.CheckResult {
	results := make([]models.CheckResult, 0, 4)

	// -----------------------------------------------------------------------
	// Single HTTP request for the three Cross-Origin headers (COEP, COOP, CORP)
	// -----------------------------------------------------------------------
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(ensureHTTPS(url))
	if err != nil {
		// Fall back to HTTP if HTTPS fails.
		resp, err = client.Get(ensureHTTP(url))
	}

	if err != nil {
		errDetail := toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()})
		results = append(results,
			models.CheckResult{
				Category:  s.Category(),
				CheckName: "Cross-Origin-Embedder-Policy",
				Status:    "error",
				Score:     0,
				Weight:    weightCOEP,
				Severity:  "critical",
				Details:   errDetail,
			},
			models.CheckResult{
				Category:  s.Category(),
				CheckName: "Cross-Origin-Opener-Policy",
				Status:    "error",
				Score:     0,
				Weight:    weightCOOP,
				Severity:  "critical",
				Details:   errDetail,
			},
			models.CheckResult{
				Category:  s.Category(),
				CheckName: "Cross-Origin-Resource-Policy",
				Status:    "error",
				Score:     0,
				Weight:    weightCORP,
				Severity:  "critical",
				Details:   errDetail,
			},
		)
	} else {
		defer resp.Body.Close()
		headers := resp.Header

		results = append(results,
			s.checkCOEP(headers),
			s.checkCOOP(headers),
			s.checkCORP(headers),
		)
	}

	// -----------------------------------------------------------------------
	// Separate TLS connection for OCSP Stapling
	// -----------------------------------------------------------------------
	results = append(results, s.checkOCSPStapling(url))

	return results
}

// ---------------------------------------------------------------------------
// Cross-Origin-Embedder-Policy (COEP)  (Weight: 12)
// ---------------------------------------------------------------------------

func (s *AdvancedSecurityScanner) checkCOEP(headers http.Header) models.CheckResult {
	headerName := "Cross-Origin-Embedder-Policy"
	value := headers.Get(headerName)

	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: headerName,
		Weight:    weightCOEP,
	}

	if value == "" {
		result.Score = 500
		result.Status = "warn"
		result.Severity = "low"
		result.Details = toJSON(map[string]string{
			"header":      headerName,
			"description": "Controls whether a document can load cross-origin resources that have not granted permission",
			"message":     "Cross-Origin-Embedder-Policy header is missing (optional advanced header, not practical for sites using external resources)",
		})
		return result
	}

	lower := strings.ToLower(strings.TrimSpace(value))

	var score float64
	var message string

	switch lower {
	case "require-corp":
		score = 1000
		message = "COEP set to require-corp (strongest protection)"
	case "credentialless":
		score = 850
		message = "COEP set to credentialless (good protection)"
	case "unsafe-none":
		score = 400
		message = "COEP set to unsafe-none (no protection)"
	default:
		score = 400
		message = "COEP present but with unrecognized value: " + value
	}

	result.Score = score
	result.Status = statusFromScore(score)
	result.Severity = severityFromScore(score)
	result.Details = toJSON(map[string]string{
		"header":      headerName,
		"value":       value,
		"description": "Controls whether a document can load cross-origin resources that have not granted permission",
		"message":     message,
	})
	return result
}

// ---------------------------------------------------------------------------
// Cross-Origin-Opener-Policy (COOP)  (Weight: 12)
// ---------------------------------------------------------------------------

func (s *AdvancedSecurityScanner) checkCOOP(headers http.Header) models.CheckResult {
	headerName := "Cross-Origin-Opener-Policy"
	value := headers.Get(headerName)

	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: headerName,
		Weight:    weightCOOP,
	}

	if value == "" {
		result.Score = 500
		result.Status = "warn"
		result.Severity = "low"
		result.Details = toJSON(map[string]string{
			"header":      headerName,
			"description": "Isolates the browsing context to prevent cross-origin attacks like Spectre",
			"message":     "Cross-Origin-Opener-Policy header is missing (optional advanced header, not practical for sites using external resources)",
		})
		return result
	}

	lower := strings.ToLower(strings.TrimSpace(value))

	var score float64
	var message string

	switch lower {
	case "same-origin":
		score = 1000
		message = "COOP set to same-origin (strongest isolation)"
	case "same-origin-allow-popups":
		score = 800
		message = "COOP set to same-origin-allow-popups (good isolation, allows popups)"
	case "unsafe-none":
		score = 400
		message = "COOP set to unsafe-none (no isolation)"
	default:
		score = 400
		message = "COOP present but with unrecognized value: " + value
	}

	result.Score = score
	result.Status = statusFromScore(score)
	result.Severity = severityFromScore(score)
	result.Details = toJSON(map[string]string{
		"header":      headerName,
		"value":       value,
		"description": "Isolates the browsing context to prevent cross-origin attacks like Spectre",
		"message":     message,
	})
	return result
}

// ---------------------------------------------------------------------------
// Cross-Origin-Resource-Policy (CORP)  (Weight: 12)
// ---------------------------------------------------------------------------

func (s *AdvancedSecurityScanner) checkCORP(headers http.Header) models.CheckResult {
	headerName := "Cross-Origin-Resource-Policy"
	value := headers.Get(headerName)

	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: headerName,
		Weight:    weightCORP,
	}

	if value == "" {
		result.Score = 500
		result.Status = "warn"
		result.Severity = "low"
		result.Details = toJSON(map[string]string{
			"header":      headerName,
			"description": "Restricts which origins can load this resource",
			"message":     "Cross-Origin-Resource-Policy header is missing (optional advanced header, not practical for sites using external resources)",
		})
		return result
	}

	lower := strings.ToLower(strings.TrimSpace(value))

	var score float64
	var message string

	switch lower {
	case "same-origin":
		score = 1000
		message = "CORP set to same-origin (strictest policy)"
	case "same-site":
		score = 850
		message = "CORP set to same-site (good restriction)"
	case "cross-origin":
		score = 500
		message = "CORP set to cross-origin (allows any origin to load resources)"
	default:
		score = 500
		message = "CORP present but with unrecognized value: " + value
	}

	result.Score = score
	result.Status = statusFromScore(score)
	result.Severity = severityFromScore(score)
	result.Details = toJSON(map[string]string{
		"header":      headerName,
		"value":       value,
		"description": "Restricts which origins can load this resource",
		"message":     message,
	})
	return result
}

// ---------------------------------------------------------------------------
// OCSP Stapling  (Weight: 15)
// ---------------------------------------------------------------------------

func (s *AdvancedSecurityScanner) checkOCSPStapling(url string) models.CheckResult {
	result := models.CheckResult{
		Category:  s.Category(),
		CheckName: "OCSP Stapling",
		Weight:    weightOCSPStapling,
	}

	host := extractHost(url)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		host+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		result.Score = 0
		result.Status = statusFromScore(result.Score)
		result.Severity = severityFromScore(result.Score)
		result.Details = toJSON(map[string]string{
			"description": "OCSP Stapling improves TLS performance and privacy by attaching certificate revocation status",
			"message":     "TLS connection failed",
			"error":       err.Error(),
		})
		return result
	}
	defer conn.Close()

	ocspResponse := conn.ConnectionState().OCSPResponse

	if len(ocspResponse) > 0 {
		result.Score = 1000
		result.Status = statusFromScore(result.Score)
		result.Severity = severityFromScore(result.Score)
		result.Details = toJSON(map[string]string{
			"description": "OCSP Stapling improves TLS performance and privacy by attaching certificate revocation status",
			"message":     "OCSP Stapling is enabled",
		})
	} else {
		result.Score = 350
		result.Status = statusFromScore(result.Score)
		result.Severity = severityFromScore(result.Score)
		result.Details = toJSON(map[string]string{
			"description": "OCSP Stapling improves TLS performance and privacy by attaching certificate revocation status",
			"message":     "OCSP Stapling is not enabled",
		})
	}

	return result
}
