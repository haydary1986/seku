package api

import (
	"net/http"
	"time"

	"seku/internal/safehttp"
)

// safeHTTPClient returns an SSRF-hardened HTTP client (see internal/safehttp).
func safeHTTPClient(timeout time.Duration) *http.Client {
	return safehttp.Client(timeout)
}

// isSafeOutboundHost reports whether a host/URL resolves entirely to public IPs.
func isSafeOutboundHost(hostOrURL string) bool {
	return safehttp.IsSafeHost(hostOrURL)
}
