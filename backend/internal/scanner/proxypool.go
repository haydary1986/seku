package scanner

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"seku/internal/config"
	"seku/internal/models"
)

// ProxyEntry represents a single proxy with health tracking.
type ProxyEntry struct {
	URL         string        `json:"url"`
	Type        string        `json:"type"` // "http" or "socks5"
	FailCount   int           `json:"fail_count"`
	Alive       bool          `json:"alive"`
	Latency     time.Duration `json:"latency"`
	LastChecked time.Time     `json:"last_checked"`
}

// ProxyStats holds pool statistics for the API.
type ProxyStats struct {
	Enabled       bool      `json:"enabled"`
	TotalProxies  int       `json:"total_proxies"`
	HealthyCount  int       `json:"healthy_count"`
	DeadCount     int       `json:"dead_count"`
	LastRefresh   time.Time `json:"last_refresh"`
	Mode          string    `json:"mode"`
}

// ProxyPool manages the rotating proxy pool.
type ProxyPool struct {
	mu          sync.RWMutex
	proxies     []ProxyEntry
	healthy     []*ProxyEntry
	index       atomic.Uint64
	enabled     bool
	maxFails    int
	lastRefresh time.Time
	sources     []string
}

// Pool is the singleton proxy pool.
var Pool = &ProxyPool{
	maxFails: 3,
	sources: []string{
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
		"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
		"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
	},
}

// NextProxy returns the next healthy proxy URL, or nil if disabled/empty.
func (p *ProxyPool) NextProxy() *url.URL {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.enabled || len(p.healthy) == 0 {
		return nil
	}

	idx := p.index.Add(1) - 1
	entry := p.healthy[idx%uint64(len(p.healthy))]

	parsed, err := url.Parse(entry.URL)
	if err != nil {
		return nil
	}
	return parsed
}

// ReportSuccess marks a proxy as successful.
func (p *ProxyPool) ReportSuccess(proxyURL string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.proxies {
		if p.proxies[i].URL == proxyURL {
			p.proxies[i].FailCount = 0
			return
		}
	}
}

// ReportFailure increments fail count; marks dead if threshold exceeded.
func (p *ProxyPool) ReportFailure(proxyURL string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.proxies {
		if p.proxies[i].URL == proxyURL {
			p.proxies[i].FailCount++
			if p.proxies[i].FailCount >= p.maxFails {
				p.proxies[i].Alive = false
				p.rebuildHealthyLocked()
			}
			return
		}
	}
}

// Stats returns current pool statistics.
func (p *ProxyPool) Stats() ProxyStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	dead := 0
	for _, px := range p.proxies {
		if !px.Alive {
			dead++
		}
	}
	return ProxyStats{
		Enabled:      p.enabled,
		TotalProxies: len(p.proxies),
		HealthyCount: len(p.healthy),
		DeadCount:    dead,
		LastRefresh:  p.lastRefresh,
		Mode:         "round_robin",
	}
}

// SetEnabled enables or disables proxy rotation.
func (p *ProxyPool) SetEnabled(enabled bool) {
	p.mu.Lock()
	p.enabled = enabled
	p.mu.Unlock()
	if enabled && len(p.proxies) == 0 {
		go p.Refresh()
	}
}

// LoadSettingsFromDB reads proxy_enabled from the settings table.
func (p *ProxyPool) LoadSettingsFromDB() {
	var setting models.Settings
	if err := config.DB.Where("key = ?", "proxy_enabled").First(&setting).Error; err == nil {
		p.SetEnabled(setting.Value == "true")
	}
}

// Refresh fetches fresh proxy lists from all sources.
func (p *ProxyPool) Refresh() {
	log.Println("[ProxyPool] Refreshing proxy lists...")

	var mu sync.Mutex
	var wg sync.WaitGroup
	newProxies := make(map[string]ProxyEntry)

	client := &http.Client{Timeout: 15 * time.Second}

	for _, src := range p.sources {
		wg.Add(1)
		go func(sourceURL string) {
			defer wg.Done()

			proxyType := "http"
			if strings.Contains(sourceURL, "socks5") {
				proxyType = "socks5"
			}

			resp, err := client.Get(sourceURL)
			if err != nil {
				log.Printf("[ProxyPool] Failed to fetch %s: %v", sourceURL, err)
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
			count := 0
			for _, line := range strings.Split(string(body), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				// Validate IP:PORT format
				host, port, err := net.SplitHostPort(line)
				if err != nil || host == "" || port == "" {
					continue
				}

				proxyURL := proxyType + "://" + line
				mu.Lock()
				if _, exists := newProxies[proxyURL]; !exists {
					newProxies[proxyURL] = ProxyEntry{
						URL:   proxyURL,
						Type:  proxyType,
						Alive: true,
					}
					count++
				}
				mu.Unlock()
			}
			log.Printf("[ProxyPool] Fetched %d proxies from %s", count, sourceURL)
		}(src)
	}

	wg.Wait()

	// Store
	p.mu.Lock()
	var list []ProxyEntry
	for _, entry := range newProxies {
		list = append(list, entry)
	}
	p.proxies = list
	p.lastRefresh = time.Now()
	p.mu.Unlock()

	log.Printf("[ProxyPool] Total: %d proxies. Starting health check...", len(list))

	// Clear cached transports since proxy list changed
	ClearTransportCache()

	// Health check
	p.HealthCheck()
}

// HealthCheck tests proxies concurrently (max 300 to keep it fast).
func (p *ProxyPool) HealthCheck() {
	p.mu.RLock()
	total := len(p.proxies)
	p.mu.RUnlock()

	if total == 0 {
		return
	}
	// Limit to 300 proxies for speed — check a random sample if more
	if total > 300 {
		total = 300
	}

	sem := make(chan struct{}, 100) // 100 concurrent health checks
	var wg sync.WaitGroup

	for i := 0; i < total; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			p.mu.RLock()
			entry := p.proxies[idx]
			p.mu.RUnlock()

			alive, latency := p.testProxy(entry)

			p.mu.Lock()
			p.proxies[idx].Alive = alive
			p.proxies[idx].Latency = latency
			p.proxies[idx].LastChecked = time.Now()
			if alive {
				p.proxies[idx].FailCount = 0
			}
			p.mu.Unlock()
		}(i)
	}

	wg.Wait()

	p.mu.Lock()
	p.rebuildHealthyLocked()
	p.mu.Unlock()

	stats := p.Stats()
	log.Printf("[ProxyPool] Health check done: %d healthy / %d total", stats.HealthyCount, stats.TotalProxies)
}

func (p *ProxyPool) testProxy(entry ProxyEntry) (bool, time.Duration) {
	transport := TransportForProxy(entry.URL)
	if transport == nil {
		return false, 0
	}

	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
	}

	start := time.Now()
	resp, err := client.Get("https://httpbin.org/ip")
	latency := time.Since(start)

	if err != nil {
		return false, latency
	}
	resp.Body.Close()
	return resp.StatusCode == 200, latency
}

func (p *ProxyPool) rebuildHealthyLocked() {
	p.healthy = nil
	for i := range p.proxies {
		if p.proxies[i].Alive {
			p.healthy = append(p.healthy, &p.proxies[i])
		}
	}
}

// StartUpdater runs a background goroutine that refreshes every 30 min.
func (p *ProxyPool) StartUpdater() {
	go func() {
		// Initial refresh if enabled
		p.mu.RLock()
		enabled := p.enabled
		p.mu.RUnlock()
		if enabled {
			p.Refresh()
		}

		ticker := time.NewTicker(30 * time.Minute)
		for range ticker.C {
			p.LoadSettingsFromDB()
			p.mu.RLock()
			enabled := p.enabled
			p.mu.RUnlock()
			if enabled {
				p.Refresh()
			}
		}
	}()
}

// transportCache caches http.RoundTripper instances per proxy URL to avoid
// creating a new Transport (and TCP connection pool) on every request.
var transportCache = struct {
	sync.RWMutex
	m map[string]http.RoundTripper
}{m: make(map[string]http.RoundTripper)}

// TransportForProxy returns a cached http.RoundTripper for the given proxy URL.
// Transports are created once and reused for all subsequent requests through
// the same proxy, enabling connection pooling and TLS session reuse.
func TransportForProxy(proxyURL string) http.RoundTripper {
	// Fast path: check cache with read lock
	transportCache.RLock()
	if t, ok := transportCache.m[proxyURL]; ok {
		transportCache.RUnlock()
		return t
	}
	transportCache.RUnlock()

	// Slow path: create and cache
	transportCache.Lock()
	defer transportCache.Unlock()

	// Double-check after acquiring write lock
	if t, ok := transportCache.m[proxyURL]; ok {
		return t
	}

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil
	}

	var t http.RoundTripper

	if parsed.Scheme == "socks5" {
		dialer, err := proxy.FromURL(parsed, proxy.Direct)
		if err != nil {
			return nil
		}
		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil
		}
		t = &http.Transport{
			DialContext:        contextDialer.DialContext,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:       20,
			IdleConnTimeout:    30 * time.Second,
			DisableKeepAlives:  false,
		}
	} else {
		// HTTP/HTTPS proxy
		t = &http.Transport{
			Proxy:              http.ProxyURL(parsed),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:       20,
			IdleConnTimeout:    30 * time.Second,
			DisableKeepAlives:  false,
		}
	}

	transportCache.m[proxyURL] = t
	return t
}

// ClearTransportCache removes all cached transports (called on proxy pool refresh).
func ClearTransportCache() {
	transportCache.Lock()
	defer transportCache.Unlock()
	// Close idle connections on old transports before discarding
	for _, t := range transportCache.m {
		if tr, ok := t.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	transportCache.m = make(map[string]http.RoundTripper)
}
