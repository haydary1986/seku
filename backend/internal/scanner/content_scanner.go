package scanner

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
)

type ContentScanner struct{}

func NewContentScanner() *ContentScanner {
	return &ContentScanner{}
}

func (s *ContentScanner) Name() string     { return "Content Optimization Scanner" }
func (s *ContentScanner) Category() string { return "content" }
func (s *ContentScanner) Weight() float64  { return 8.0 }

func (s *ContentScanner) Scan(url string) []models.CheckResult {
	var results []models.CheckResult

	results = append(results, s.checkCacheHeaders(url))
	results = append(results, s.checkPageSize(url))
	results = append(results, s.checkCompressionRatio(url))

	return results
}

// ---------------------------------------------------------------------------
// Cache Headers  (Weight: 40)
// ---------------------------------------------------------------------------

func (s *ContentScanner) checkCacheHeaders(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Cache Headers",
		Weight:    40.0,
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: ScanTransport,
	}

	targetURL := ensureHTTPS(url)
	resp, err := client.Get(targetURL)
	if err != nil {
		targetURL = ensureHTTP(url)
		resp, err = client.Get(targetURL)
		if err != nil {
			check.Status = "error"
			check.Score = 0
			check.Severity = "critical"
			check.Details = toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()})
			return check
		}
	}
	defer resp.Body.Close()

	cacheControl := resp.Header.Get("Cache-Control")
	etag := resp.Header.Get("ETag")
	lastModified := resp.Header.Get("Last-Modified")
	expires := resp.Header.Get("Expires")

	ccLower := strings.ToLower(cacheControl)

	var score float64
	var message string

	switch {
	case cacheControl != "" && extractMaxAge(ccLower) > 86400 && (etag != "" || lastModified != ""):
		score = 1000
		message = fmt.Sprintf("Excellent caching: Cache-Control with max-age > 86400 and %s present",
			validationHeader(etag, lastModified))

	case cacheControl != "" && extractMaxAge(ccLower) > 86400:
		score = 850
		message = "Good caching: Cache-Control with max-age > 86400 but no ETag or Last-Modified"

	case cacheControl != "" && extractMaxAge(ccLower) > 3600:
		score = 700
		message = fmt.Sprintf("Moderate caching: Cache-Control with max-age=%d (> 3600)", extractMaxAge(ccLower))

	case cacheControl != "" && extractMaxAge(ccLower) > 0:
		score = 550
		message = fmt.Sprintf("Minimal caching: Cache-Control with max-age=%d", extractMaxAge(ccLower))

	case cacheControl != "" && (strings.Contains(ccLower, "no-cache") || strings.Contains(ccLower, "no-store")):
		score = 800
		message = "Cache-Control set to no-cache/no-store (acceptable for HTML documents)"

	case expires != "" && cacheControl == "":
		score = 500
		message = "Legacy caching: Expires header present but no Cache-Control header"

	default:
		score = 150
		message = "No caching headers found"
	}

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"cache_control": cacheControl,
		"etag":          etag,
		"last_modified": lastModified,
		"expires":       expires,
		"message":       message,
	})

	return check
}

// extractMaxAge parses the max-age value from a lowercased Cache-Control header.
func extractMaxAge(ccLower string) int64 {
	idx := strings.Index(ccLower, "max-age")
	if idx == -1 {
		return 0
	}
	rest := ccLower[idx+len("max-age"):]
	rest = strings.TrimLeft(rest, " \t")
	if len(rest) == 0 || rest[0] != '=' {
		return 0
	}
	rest = rest[1:]
	rest = strings.TrimLeft(rest, " \t")

	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.ParseInt(rest[:end], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// validationHeader returns a description of which validation headers are present.
func validationHeader(etag, lastModified string) string {
	if etag != "" && lastModified != "" {
		return "ETag and Last-Modified"
	}
	if etag != "" {
		return "ETag"
	}
	return "Last-Modified"
}

// ---------------------------------------------------------------------------
// Page Size  (Weight: 30)
// ---------------------------------------------------------------------------

func (s *ContentScanner) checkPageSize(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Page Size",
		Weight:    30.0,
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: ScanTransport,
	}

	targetURL := ensureHTTPS(url)
	resp, err := client.Get(targetURL)
	if err != nil {
		targetURL = ensureHTTP(url)
		resp, err = client.Get(targetURL)
		if err != nil {
			check.Status = "error"
			check.Score = 0
			check.Severity = "critical"
			check.Details = toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()})
			return check
		}
	}
	defer resp.Body.Close()

	// Read body with 10MB limit
	const maxRead = 10 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "high"
		check.Details = toJSON(map[string]string{"error": "Failed to read response body: " + err.Error()})
		return check
	}

	sizeBytes := float64(len(body))
	sizeKB := sizeBytes / 1024.0

	score := scorePageSize(sizeKB)
	score = math.Round(score)

	check.Score = score
	check.Status = statusFromScore(score)
	check.Severity = severityFromScore(score)
	check.Details = toJSON(map[string]interface{}{
		"size_bytes": len(body),
		"size_kb":    math.Round(sizeKB*100) / 100,
		"message":    fmt.Sprintf("Page size: %.1f KB (score: %.0f/1000)", sizeKB, score),
	})

	return check
}

// scorePageSize returns a 0-1000 score for page size in KB.
func scorePageSize(kb float64) float64 {
	switch {
	case kb < 50:
		return 1000
	case kb <= 100:
		return linearScore(kb, 50, 100, 1000, 900)
	case kb <= 250:
		return linearScore(kb, 100, 250, 900, 750)
	case kb <= 500:
		return linearScore(kb, 250, 500, 750, 550)
	case kb <= 1024:
		return linearScore(kb, 500, 1024, 550, 300)
	case kb <= 3072:
		return linearScore(kb, 1024, 3072, 300, 100)
	default:
		return 50
	}
}

// ---------------------------------------------------------------------------
// Compression Ratio  (Weight: 30)
// ---------------------------------------------------------------------------

func (s *ContentScanner) checkCompressionRatio(url string) models.CheckResult {
	check := models.CheckResult{
		Category:  s.Category(),
		CheckName: "Compression Ratio",
		Weight:    30.0,
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: ScanTransport,
	}

	targetURL := ensureHTTPS(url)

	// Request with compression
	compReq, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "high"
		check.Details = toJSON(map[string]string{"error": err.Error()})
		return check
	}
	compReq.Header.Set("Accept-Encoding", "gzip, deflate, br")

	compResp, err := client.Do(compReq)
	if err != nil {
		// Try HTTP
		targetURL = ensureHTTP(url)
		compReq, _ = http.NewRequest("GET", targetURL, nil)
		compReq.Header.Set("Accept-Encoding", "gzip, deflate, br")
		compResp, err = client.Do(compReq)
		if err != nil {
			check.Status = "error"
			check.Score = 0
			check.Severity = "critical"
			check.Details = toJSON(map[string]string{"error": "Cannot reach website: " + err.Error()})
			return check
		}
	}

	compContentEncoding := compResp.Header.Get("Content-Encoding")
	compContentLength := compResp.Header.Get("Content-Length")

	// Read compressed body to get actual size if no Content-Length
	var compressedSize int64
	if compContentLength != "" {
		compressedSize, _ = strconv.ParseInt(compContentLength, 10, 64)
	}
	if compressedSize == 0 {
		const maxRead = 10 * 1024 * 1024
		body, _ := io.ReadAll(io.LimitReader(compResp.Body, maxRead))
		compressedSize = int64(len(body))
	}
	compResp.Body.Close()

	// Request without compression
	plainReq, _ := http.NewRequest("GET", targetURL, nil)
	// Explicitly do not set Accept-Encoding

	plainResp, err := client.Do(plainReq)
	if err != nil {
		check.Status = "error"
		check.Score = 0
		check.Severity = "high"
		check.Details = toJSON(map[string]string{"error": "Failed uncompressed request: " + err.Error()})
		return check
	}

	plainContentLength := plainResp.Header.Get("Content-Length")

	var uncompressedSize int64
	if plainContentLength != "" {
		uncompressedSize, _ = strconv.ParseInt(plainContentLength, 10, 64)
	}
	if uncompressedSize == 0 {
		const maxRead = 10 * 1024 * 1024
		body, _ := io.ReadAll(io.LimitReader(plainResp.Body, maxRead))
		uncompressedSize = int64(len(body))
	}
	plainResp.Body.Close()

	var score float64
	var message string

	if compressedSize > 0 && uncompressedSize > 0 && compContentEncoding != "" {
		ratio := float64(compressedSize) / float64(uncompressedSize)
		score = scoreCompressionRatio(ratio)
		score = math.Round(score)
		savings := (1 - ratio) * 100

		message = fmt.Sprintf("Compression ratio: %.2f (%.1f%% savings, %s encoding, compressed: %d bytes, uncompressed: %d bytes)",
			ratio, savings, compContentEncoding, compressedSize, uncompressedSize)

		check.Score = score
		check.Status = statusFromScore(score)
		check.Severity = severityFromScore(score)
		check.Details = toJSON(map[string]interface{}{
			"ratio":              math.Round(ratio*1000) / 1000,
			"savings_percent":    math.Round(savings*10) / 10,
			"compressed_size":    compressedSize,
			"uncompressed_size":  uncompressedSize,
			"content_encoding":   compContentEncoding,
			"message":            message,
		})
	} else if compContentEncoding != "" {
		// Can't determine sizes but encoding is present
		score = 800
		message = fmt.Sprintf("Compression detected (%s) but unable to determine exact ratio", compContentEncoding)

		check.Score = score
		check.Status = statusFromScore(score)
		check.Severity = severityFromScore(score)
		check.Details = toJSON(map[string]interface{}{
			"content_encoding": compContentEncoding,
			"message":          message,
		})
	} else {
		// No compression detected
		score = 200
		message = "No compression detected (no Content-Encoding header in response)"

		check.Score = score
		check.Status = statusFromScore(score)
		check.Severity = severityFromScore(score)
		check.Details = toJSON(map[string]interface{}{
			"message": message,
		})
	}

	return check
}

// scoreCompressionRatio returns a 0-1000 score based on compressed/uncompressed ratio.
func scoreCompressionRatio(ratio float64) float64 {
	switch {
	case ratio < 0.3:
		return 1000
	case ratio <= 0.5:
		return linearScore(ratio, 0.3, 0.5, 1000, 750)
	case ratio <= 0.7:
		return linearScore(ratio, 0.5, 0.7, 750, 500)
	case ratio <= 0.9:
		return linearScore(ratio, 0.7, 0.9, 500, 250)
	default:
		return 100
	}
}
