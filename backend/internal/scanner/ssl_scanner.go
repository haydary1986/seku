package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

// strongCipherSuites lists TLS 1.2 cipher suites considered strong.
// These use AEAD ciphers (AES-GCM, ChaCha20-Poly1305) with ECDHE key exchange.
var strongCipherSuites = map[uint16]bool{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:     true,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:   true,
}

type SSLScanner struct{}

func NewSSLScanner() *SSLScanner {
	return &SSLScanner{}
}

func (s *SSLScanner) Name() string     { return "SSL/TLS Scanner" }
func (s *SSLScanner) Category() string { return "ssl" }
func (s *SSLScanner) Weight() float64  { return 20.0 }

func (s *SSLScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	// Check HTTPS availability
	results = append(results, s.checkHTTPS(url))

	// Check certificate validity
	results = append(results, s.checkCertificate(url))

	// Check TLS version
	results = append(results, s.checkTLSVersion(url))

	// Check HTTPS redirect
	results = append(results, s.checkHTTPSRedirect(url))

	return results
}

func (s *SSLScanner) checkHTTPS(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "HTTPS Enabled",
		Weight:    50,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: ScanTransport,
	}

	httpsURL := ensureHTTPS(url)

	start := time.Now()
	resp, err := client.Get(httpsURL)
	elapsed := time.Since(start)

	if err != nil {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{
			"error": "HTTPS not available: " + err.Error(),
		})
		return check
	}
	defer resp.Body.Close()

	details := map[string]interface{}{
		"response_time_ms": elapsed.Milliseconds(),
	}

	if elapsed > 5*time.Second {
		check.Status = "warning"
		check.Score = 800
		check.Severity = "low"
		details["message"] = fmt.Sprintf("HTTPS is available but slow (%dms)", elapsed.Milliseconds())
	} else {
		check.Status = "pass"
		check.Score = 1000
		check.Severity = "info"
		details["message"] = fmt.Sprintf("HTTPS is available (%dms)", elapsed.Milliseconds())
	}

	check.Details = toJSON(details)
	return check
}

func (s *SSLScanner) checkCertificate(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Certificate Validity",
		Weight:    50,
	}

	host := extractHost(url)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		host+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{
			"error": "Cannot establish TLS connection: " + err.Error(),
		})
		return check
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		check.Details = toJSON(map[string]string{
			"error": "No certificates found",
		})
		return check
	}

	cert := certs[0]
	now := time.Now()

	details := map[string]interface{}{
		"issuer":     cert.Issuer.CommonName,
		"subject":    cert.Subject.CommonName,
		"not_before": cert.NotBefore.Format(time.RFC3339),
		"not_after":  cert.NotAfter.Format(time.RFC3339),
		"dns_names":  cert.DNSNames,
	}

	// Check if the certificate is expired or not yet valid
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["message"] = "Certificate is expired or not yet valid"
		check.Details = toJSON(details)
		return check
	}

	// Check if the certificate is self-signed
	selfSigned := isSelfSigned(cert)
	details["self_signed"] = selfSigned

	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
	details["days_until_expiry"] = daysUntilExpiry

	if selfSigned {
		check.Status = "warning"
		check.Score = 400
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Self-signed certificate, valid for %d more days", daysUntilExpiry)
		check.Details = toJSON(details)
		return check
	}

	// Score based on days until expiry
	switch {
	case daysUntilExpiry > 90:
		check.Status = "pass"
		check.Score = 1000
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Certificate valid for %d more days", daysUntilExpiry)
	case daysUntilExpiry > 60:
		check.Status = "pass"
		check.Score = 900
		check.Severity = "info"
		details["message"] = fmt.Sprintf("Certificate valid for %d more days", daysUntilExpiry)
	case daysUntilExpiry > 30:
		check.Status = "pass"
		check.Score = 750
		check.Severity = "low"
		details["message"] = fmt.Sprintf("Certificate expires in %d days", daysUntilExpiry)
	case daysUntilExpiry > 14:
		check.Status = "warning"
		check.Score = 500
		check.Severity = "medium"
		details["message"] = fmt.Sprintf("Certificate expires in %d days - renew soon", daysUntilExpiry)
	case daysUntilExpiry > 7:
		check.Status = "warning"
		check.Score = 300
		check.Severity = "high"
		details["message"] = fmt.Sprintf("Certificate expires in %d days - renew immediately", daysUntilExpiry)
	default:
		check.Status = "warning"
		check.Score = 150
		check.Severity = "high"
		details["message"] = fmt.Sprintf("Certificate expires in %d days - critical", daysUntilExpiry)
	}

	check.Details = toJSON(details)
	return check
}

func (s *SSLScanner) checkTLSVersion(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "TLS Version",
		Weight:    50,
	}

	host := extractHost(url)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		host+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "high"
		check.Details = toJSON(map[string]string{"error": err.Error()})
		return check
	}
	defer conn.Close()

	state := conn.ConnectionState()
	version := state.Version
	cipherSuite := state.CipherSuite
	details := map[string]interface{}{}

	switch version {
	case tls.VersionTLS13:
		check.Status = "pass"
		check.Score = 1000
		check.Severity = "info"
		details["version"] = "TLS 1.3"
		details["message"] = "Excellent - using latest TLS version"
	case tls.VersionTLS12:
		if strongCipherSuites[cipherSuite] {
			check.Status = "pass"
			check.Score = 850
			check.Severity = "info"
			details["version"] = "TLS 1.2"
			details["cipher_suite"] = tls.CipherSuiteName(cipherSuite)
			details["strong_cipher"] = true
			details["message"] = "Good - TLS 1.2 with strong cipher suite"
		} else {
			check.Status = "pass"
			check.Score = 700
			check.Severity = "low"
			details["version"] = "TLS 1.2"
			details["cipher_suite"] = tls.CipherSuiteName(cipherSuite)
			details["strong_cipher"] = false
			details["message"] = "Acceptable - TLS 1.2 but cipher suite could be stronger"
		}
	case tls.VersionTLS11:
		check.Status = "warning"
		check.Score = 200
		check.Severity = "high"
		details["version"] = "TLS 1.1"
		details["message"] = "TLS 1.1 is deprecated and insecure"
	default:
		check.Status = "fail"
		check.Score = 0
		check.Severity = "critical"
		details["version"] = "TLS 1.0 or older"
		details["message"] = "Very old TLS version - highly insecure"
	}

	check.Details = toJSON(details)
	return check
}

func (s *SSLScanner) checkHTTPSRedirect(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "HTTP to HTTPS Redirect",
		Weight:    50,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	httpURL := ensureHTTP(url)
	resp, err := client.Get(httpURL)
	if err != nil {
		// Cannot reach HTTP version - check if HTTPS works directly
		httpsClient := &http.Client{
			Timeout: 10 * time.Second,
			Transport: ScanTransport,
		}
		httpsURL := ensureHTTPS(url)
		httpsResp, httpsErr := httpsClient.Get(httpsURL)
		if httpsErr != nil {
			check.Status = "fail"
			check.Score = 0
			check.Severity = "high"
			check.Details = toJSON(map[string]string{
				"message": "Neither HTTP nor HTTPS reachable",
				"error":   err.Error(),
			})
			return check
		}
		defer httpsResp.Body.Close()

		check.Status = "warning"
		check.Score = 400
		check.Severity = "medium"
		check.Details = toJSON(map[string]string{
			"message": "HTTP not reachable but HTTPS works directly",
		})
		return check
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	isRedirectToHTTPS := resp.StatusCode >= 300 && resp.StatusCode < 400 &&
		len(location) > 4 && strings.HasPrefix(location, "https")

	if isRedirectToHTTPS {
		details := map[string]string{
			"redirect_to": location,
			"status_code": fmt.Sprintf("%d", resp.StatusCode),
		}

		switch resp.StatusCode {
		case 301:
			check.Status = "pass"
			check.Score = 1000
			check.Severity = "info"
			details["message"] = "HTTP correctly redirects to HTTPS with 301 (permanent)"
		case 302:
			check.Status = "pass"
			check.Score = 850
			check.Severity = "low"
			details["message"] = "HTTP redirects to HTTPS with 302 (temporary) - consider using 301"
		default:
			check.Status = "pass"
			check.Score = 700
			check.Severity = "low"
			details["message"] = fmt.Sprintf("HTTP redirects to HTTPS with status %d", resp.StatusCode)
		}

		check.Details = toJSON(details)
		return check
	}

	// No redirect to HTTPS - check if HTTPS is available separately
	httpsClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: ScanTransport,
	}
	httpsURL := ensureHTTPS(url)
	httpsResp, httpsErr := httpsClient.Get(httpsURL)
	if httpsErr == nil {
		defer httpsResp.Body.Close()
		check.Status = "warning"
		check.Score = 400
		check.Severity = "medium"
		check.Details = toJSON(map[string]string{
			"message":     "No HTTP to HTTPS redirect, but HTTPS is available",
			"status_code": fmt.Sprintf("%d", resp.StatusCode),
		})
		return check
	}

	check.Status = "fail"
	check.Score = 0
	check.Severity = "high"
	check.Details = toJSON(map[string]string{
		"message":     "HTTP does not redirect to HTTPS and HTTPS is not available",
		"status_code": fmt.Sprintf("%d", resp.StatusCode),
	})
	return check
}

// isSelfSigned returns true if the certificate appears to be self-signed.
func isSelfSigned(cert *x509.Certificate) bool {
	// A self-signed cert has the same issuer and subject
	if cert.Issuer.CommonName != cert.Subject.CommonName {
		return false
	}
	// Verify the signature against its own public key
	err := cert.CheckSignatureFrom(cert)
	return err == nil
}
