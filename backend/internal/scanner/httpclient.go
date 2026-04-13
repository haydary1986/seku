package scanner

import (
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"
)

// userAgents contains realistic browser User-Agent strings to avoid WAF detection.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
}

// RandomUA returns a random browser User-Agent string.
func RandomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// ScanTransport is a shared http.RoundTripper used by all scanners.
// It injects realistic browser headers and rate-limits requests per host.
// All scanner HTTP clients should use this instead of creating inline transports.
var ScanTransport http.RoundTripper = &stealthTransport{
	base: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:      50,
		IdleConnTimeout:   30 * time.Second,
		DisableKeepAlives: false,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	},
	ua: RandomUA(),
}

type stealthTransport struct {
	base http.RoundTripper
	ua   string
}

func (t *stealthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rate-limit: wait between requests to same host
	rateLimiter.Wait(req.URL.Hostname())

	// Inject realistic headers if not set
	if ua := req.Header.Get("User-Agent"); ua == "" || ua == "Go-http-client/1.1" || ua == "Go-http-client/2.0" {
		req.Header.Set("User-Agent", t.ua)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9,ar;q=0.8")
	}

	// Select transport: proxy (if enabled) or direct
	transport := t.base
	proxyURL := Pool.NextProxy()
	if proxyURL != nil {
		if pt := TransportForProxy(proxyURL.String()); pt != nil {
			transport = pt
		}
	}

	resp, err := transport.RoundTrip(req)

	// Handle proxy failure: fallback to direct connection
	if proxyURL != nil && (err != nil || (resp != nil && (resp.StatusCode == 407 || resp.StatusCode == 502 || resp.StatusCode == 503))) {
		Pool.ReportFailure(proxyURL.String())
		if resp != nil {
			resp.Body.Close()
		}
		// Retry without proxy
		resp, err = t.base.RoundTrip(req)
	} else if proxyURL != nil && err == nil {
		Pool.ReportSuccess(proxyURL.String())
	}

	if err != nil {
		return nil, err
	}

	// Auto-retry once on 429 (rate-limited)
	if resp.StatusCode == 429 {
		resp.Body.Close()
		delay := 1*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
		time.Sleep(delay)
		resp, err = t.base.RoundTrip(req)
	}

	return resp, err
}

// rateLimiter controls the pace of outgoing HTTP requests per host.
var rateLimiter = &hostRateLimiter{
	lastRequest: make(map[string]time.Time),
}

type hostRateLimiter struct {
	mu          sync.Mutex
	lastRequest map[string]time.Time
}

// Wait ensures minimum 50-150ms between requests to the same host.
func (rl *hostRateLimiter) Wait(host string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	minDelay := 50*time.Millisecond + time.Duration(rand.Intn(100))*time.Millisecond
	if last, ok := rl.lastRequest[host]; ok {
		elapsed := time.Since(last)
		if elapsed < minDelay {
			time.Sleep(minDelay - elapsed)
		}
	}
	rl.lastRequest[host] = time.Now()
}

// NewScanClient creates an HTTP client using the shared stealth transport.
func NewScanClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: ScanTransport}
}

// NewScanClientNoRedirect creates a client that does not follow redirects.
func NewScanClientNoRedirect(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: ScanTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ScanGet performs a GET with the given client (headers/rate-limit handled by transport).
func ScanGet(client *http.Client, url string) (*http.Response, error) {
	return client.Get(url)
}

// ScanDo performs a request with the given client.
func ScanDo(client *http.Client, req *http.Request) (*http.Response, error) {
	return client.Do(req)
}
