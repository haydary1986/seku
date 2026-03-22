package scanner

import (
	"encoding/json"
	"net/url"
	"strings"
)

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func extractHost(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return parsed.Hostname()
}

func ensureHTTPS(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	rawURL = strings.TrimRight(rawURL, "/")
	if strings.HasPrefix(rawURL, "https://") {
		return rawURL
	}
	if strings.HasPrefix(rawURL, "http://") {
		return "https://" + rawURL[7:]
	}
	return "https://" + rawURL
}

func ensureHTTP(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	rawURL = strings.TrimRight(rawURL, "/")
	if strings.HasPrefix(rawURL, "http://") {
		return rawURL
	}
	if strings.HasPrefix(rawURL, "https://") {
		return "http://" + rawURL[8:]
	}
	return "http://" + rawURL
}

// statusFromScore maps a 0-1000 score to a human-readable status.
func statusFromScore(score float64) string {
	switch {
	case score >= 900:
		return "pass"
	case score >= 500:
		return "warn"
	default:
		return "fail"
	}
}

// severityFromScore maps a 0-1000 score to a severity label.
func severityFromScore(score float64) string {
	switch {
	case score >= 900:
		return "info"
	case score >= 700:
		return "low"
	case score >= 400:
		return "medium"
	case score >= 200:
		return "high"
	default:
		return "critical"
	}
}
