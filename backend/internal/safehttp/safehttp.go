// Package safehttp provides an SSRF-hardened HTTP client and host validation
// shared by any code that fetches user-controlled URLs (domain verification,
// webhooks, Jira integration, etc.).
package safehttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// isDisallowedIP reports whether an IP sits in a range we must never fetch —
// loopback, private, link-local (incl. cloud metadata 169.254.169.254), CGNAT,
// unspecified, multicast.
func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return true // CGNAT 100.64.0.0/10
	}
	return false
}

// safeControl runs at dial time for every connection (each redirect hop and the
// post-DNS address), defeating DNS rebinding and redirect-to-internal.
func safeControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || isDisallowedIP(ip) {
		return fmt.Errorf("blocked connection to disallowed address: %s", address)
	}
	return nil
}

// Client returns an HTTP client that refuses to connect to internal/reserved IP
// ranges and caps redirects. Use it for ANY server-side fetch of a user URL.
func Client(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, Control: safeControl}
	transport := &http.Transport{
		DialContext:         func(ctx context.Context, network, addr string) (net.Conn, error) { return dialer.DialContext(ctx, network, addr) },
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// hostOnly extracts the bare host from a URL or host string.
func hostOnly(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			return u.Hostname()
		}
	}
	// strip path/port if a bare host:port/path was passed
	if i := strings.IndexAny(s, "/"); i != -1 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

// IsSafeHost resolves a host/URL and reports whether ALL its IPs are allowed.
func IsSafeHost(hostOrURL string) bool {
	host := hostOnly(hostOrURL)
	if host == "" {
		return false
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if isDisallowedIP(ip) {
			return false
		}
	}
	return true
}
