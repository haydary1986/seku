package scanner

import (
	"net/http"
	"strings"

	"seku/internal/models"
)

// ScanConfig carries per-scan options for the advanced / intrusive scanners
// (login, nuclei, crawl, oob). A nil *ScanConfig means "use environment
// defaults only" — so existing callers and resumed jobs behave unchanged.
type ScanConfig struct {
	EnableLogin  bool `json:"enable_login"`
	EnableNuclei bool `json:"enable_nuclei"`
	EnableCrawl  bool `json:"enable_crawl"`
	EnableOOB    bool `json:"enable_oob"`
	EnableDalfox bool `json:"enable_dalfox"`
	EnableFFUF   bool `json:"enable_ffuf"`
	// Authorized is the user's explicit acknowledgement that they are permitted
	// to actively test the target. Required to enable credential brute-forcing.
	Authorized bool `json:"authorized"`
	// Authenticated scanning: inject a real session so scanners reach pages
	// behind login. AuthCookie/AuthHeader are the primary identity (A);
	// AuthCookieB is a SECOND identity used by the access-control (IDOR/BOLA)
	// scanner to check whether one user's objects are reachable by another.
	AuthCookie  string `json:"auth_cookie"`   // raw Cookie header value
	AuthHeader  string `json:"auth_header"`   // one extra header "Name: value" (e.g. Authorization: Bearer ...)
	AuthCookieB string `json:"auth_cookie_b"` // second identity's Cookie (IDOR/BOLA)
}

// HasAuth reports whether a primary authenticated session was supplied.
func (c *ScanConfig) HasAuth() bool {
	return c != nil && (strings.TrimSpace(c.AuthCookie) != "" || strings.TrimSpace(c.AuthHeader) != "")
}

// authToolArgs returns "-H" flag pairs for the CLI tools (katana/nuclei/ffuf/
// dalfox all accept -H "Header: value"), injecting the primary session.
func (c *ScanConfig) authToolArgs() []string {
	if c == nil {
		return nil
	}
	var a []string
	if strings.TrimSpace(c.AuthCookie) != "" {
		a = append(a, "-H", "Cookie: "+c.AuthCookie)
	}
	if strings.TrimSpace(c.AuthHeader) != "" {
		a = append(a, "-H", c.AuthHeader)
	}
	return a
}

// applyAuth sets the primary session's credentials on an outgoing request.
func (c *ScanConfig) applyAuth(req *http.Request) {
	if c == nil {
		return
	}
	if strings.TrimSpace(c.AuthCookie) != "" {
		req.Header.Set("Cookie", c.AuthCookie)
	}
	if strings.TrimSpace(c.AuthHeader) != "" {
		if k, v, ok := strings.Cut(c.AuthHeader, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
}

// applyAuthB sets the SECOND identity's cookie (falls back to no auth = anonymous).
func (c *ScanConfig) applyAuthB(req *http.Request) {
	if c == nil {
		return
	}
	if strings.TrimSpace(c.AuthCookieB) != "" {
		req.Header.Set("Cookie", c.AuthCookieB)
	}
}

// ConfigurableScanner is optionally implemented by scanners that accept
// per-scan configuration. The engine prefers ScanWithConfig when a scanner
// implements it; otherwise it falls back to Scan(url). This keeps the 37
// passive scanners untouched.
type ConfigurableScanner interface {
	ScanWithConfig(url string, cfg *ScanConfig) []models.CheckResult
}

// WithConfig attaches per-scan configuration and returns the engine for chaining.
func (e *Engine) WithConfig(cfg *ScanConfig) *Engine {
	e.config = cfg
	return e
}
