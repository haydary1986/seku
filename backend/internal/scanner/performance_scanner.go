package scanner

import (
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"seku/internal/models"
)

type PerformanceScanner struct{}

func NewPerformanceScanner() *PerformanceScanner {
	return &PerformanceScanner{}
}

func (s *PerformanceScanner) Name() string     { return "Performance Scanner" }
func (s *PerformanceScanner) Category() string { return "performance" }
func (s *PerformanceScanner) Weight() float64  { return 15.0 }

// linearScore calculates a linearly interpolated score between two score boundaries
// based on where value falls within the [minVal, maxVal] range.
// When value == minVal, returns maxScore. When value == maxVal, returns minScore.
func linearScore(value, minVal, maxVal float64, maxScore, minScore float64) float64 {
	if maxVal == minVal {
		return maxScore
	}
	t := (value - minVal) / (maxVal - minVal)
	return maxScore + t*(minScore-maxScore)
}

// scoreResponseTime returns a 0-1000 score for total response time using
// piecewise linear decay across defined brackets.
func scoreResponseTime(ms float64) float64 {
	switch {
	case ms <= 200:
		return 1000
	case ms <= 500:
		return linearScore(ms, 200, 500, 1000, 900)
	case ms <= 1000:
		return linearScore(ms, 500, 1000, 900, 750)
	case ms <= 2000:
		return linearScore(ms, 1000, 2000, 750, 500)
	case ms <= 5000:
		return linearScore(ms, 2000, 5000, 500, 200)
	case ms <= 10000:
		return linearScore(ms, 5000, 10000, 200, 50)
	default:
		return 0
	}
}

// scoreTTFB returns a 0-1000 score for time-to-first-byte using
// piecewise linear decay across defined brackets.
func scoreTTFB(ms float64) float64 {
	switch {
	case ms <= 100:
		return 1000
	case ms <= 200:
		return linearScore(ms, 100, 200, 1000, 920)
	case ms <= 500:
		return linearScore(ms, 200, 500, 920, 750)
	case ms <= 1000:
		return linearScore(ms, 500, 1000, 750, 450)
	case ms <= 2000:
		return linearScore(ms, 1000, 2000, 450, 200)
	case ms <= 5000:
		return linearScore(ms, 2000, 5000, 200, 50)
	default:
		return 0
	}
}

// scoreTLSHandshake returns a 0-1000 score for TLS handshake duration using
// piecewise linear decay across defined brackets.
func scoreTLSHandshake(ms float64) float64 {
	switch {
	case ms <= 50:
		return 1000
	case ms <= 100:
		return linearScore(ms, 50, 100, 1000, 920)
	case ms <= 300:
		return linearScore(ms, 100, 300, 920, 750)
	case ms <= 700:
		return linearScore(ms, 300, 700, 750, 450)
	case ms <= 1500:
		return linearScore(ms, 700, 1500, 450, 150)
	default:
		return 50
	}
}

// gradeFromScore returns a letter grade and severity from a 0-1000 score.
func gradeFromScore(score float64) (grade string, status string, severity string) {
	switch {
	case score >= 900:
		return "A", "pass", "info"
	case score >= 750:
		return "B", "pass", "info"
	case score >= 500:
		return "C", "warning", "low"
	case score >= 200:
		return "D", "warning", "medium"
	default:
		return "F", "fail", "high"
	}
}

func (s *PerformanceScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	results = append(results, s.checkResponseTime(url))
	results = append(results, s.checkTTFB(url))
	results = append(results, s.checkTLSHandshake(url))

	return results
}

func (s *PerformanceScanner) checkResponseTime(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Response Time",
		Weight:    50.0,
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: ScanTransport,
	}

	targetURL := ensureHTTPS(url)
	start := time.Now()
	resp, err := client.Get(targetURL)
	elapsed := time.Since(start)

	if err != nil {
		// Try HTTP
		targetURL = ensureHTTP(url)
		start = time.Now()
		resp, err = client.Get(targetURL)
		elapsed = time.Since(start)
		if err != nil {
			check.Status = "error"
			check.Score = 0
			check.Severity = "critical"
			check.Details = toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()})
			return check
		}
	}
	defer resp.Body.Close()

	ms := float64(elapsed.Milliseconds())
	score := math.Round(scoreResponseTime(ms))
	grade, status, severity := gradeFromScore(score)

	check.Score = score
	check.Status = status
	check.Severity = severity
	check.Details = toJSON(map[string]interface{}{
		"response_time_ms": int64(ms),
		"status_code":      resp.StatusCode,
		"message":          fmt.Sprintf("Response time: %dms (score: %.0f/1000)", int64(ms), score),
		"grade":            grade,
	})

	return check
}

func (s *PerformanceScanner) checkTTFB(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Time to First Byte (TTFB)",
		Weight:    50.0,
	}

	var ttfb time.Duration
	var dnsTime time.Duration
	var connectTime time.Duration

	var dnsStart, connectStart, gotFirstByte time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			dnsTime = time.Since(dnsStart)
		},
		ConnectStart: func(_, _ string) {
			connectStart = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) {
			connectTime = time.Since(connectStart)
		},
		GotFirstResponseByte: func() {
			gotFirstByte = time.Now()
		},
	}

	targetURL := ensureHTTPS(url)
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "high"
		check.Details = toJSON(map[string]string{"error": err.Error()})
		return check
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: ScanTransport,
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "high"
		check.Details = toJSON(map[string]string{"error": "Cannot measure TTFB: " + err.Error()})
		return check
	}
	defer resp.Body.Close()

	if !gotFirstByte.IsZero() {
		ttfb = gotFirstByte.Sub(start)
	}

	ms := float64(ttfb.Milliseconds())
	score := math.Round(scoreTTFB(ms))
	grade, status, severity := gradeFromScore(score)

	check.Score = score
	check.Status = status
	check.Severity = severity
	check.Details = toJSON(map[string]interface{}{
		"ttfb_ms":         int64(ms),
		"dns_time_ms":     dnsTime.Milliseconds(),
		"connect_time_ms": connectTime.Milliseconds(),
		"message":         fmt.Sprintf("TTFB: %dms (score: %.0f/1000)", int64(ms), score),
		"grade":           grade,
	})

	return check
}

func (s *PerformanceScanner) checkTLSHandshake(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "TLS Handshake Time",
		Weight:    50.0,
	}

	host := extractHost(url)

	start := time.Now()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		host+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	elapsed := time.Since(start)

	if err != nil {
		check.Status = "warning"
		check.Score = 50
		check.Severity = "medium"
		check.Details = toJSON(map[string]string{
			"error":   "Cannot measure TLS handshake: " + err.Error(),
			"message": "TLS connection failed - HTTPS may not be available",
		})
		return check
	}
	defer conn.Close()

	ms := float64(elapsed.Milliseconds())
	score := math.Round(scoreTLSHandshake(ms))
	grade, status, severity := gradeFromScore(score)

	check.Score = score
	check.Status = status
	check.Severity = severity
	check.Details = toJSON(map[string]interface{}{
		"tls_handshake_ms": int64(ms),
		"message":          fmt.Sprintf("TLS handshake: %dms (score: %.0f/1000)", int64(ms), score),
		"grade":            grade,
	})

	return check
}
