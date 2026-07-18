package scanner

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Shared helpers that keep active checks from misreading benign responses as
// vulnerabilities. Two recurring false-positive sources motivated these:
//   1. A WAF/edge block (403/406/429/…) is a *successful* HTTP response whose
//      body often echoes the payload or a rule reason ("SQL syntax not allowed"),
//      which naive signature matching reads as the app's own output.
//   2. A signature that is also present in the site's normal/baseline response
//      (marketing copy, a soft-404, framework markup) is not evidence that the
//      payload caused anything — only signatures that APPEAR because of the
//      payload matter.

// isBlockedStatus reports whether a status code indicates the request was
// blocked or refused rather than processed by the application.
func isBlockedStatus(code int) bool {
	switch code {
	case http.StatusForbidden, // 403
		http.StatusNotAcceptable,      // 406
		http.StatusTooManyRequests,    // 429
		http.StatusNotImplemented,     // 501
		http.StatusServiceUnavailable: // 503
		return true
	}
	return false
}

// fetchLowerBody GETs a URL and returns (lowercased body, status code, ok).
func fetchLowerBody(client *http.Client, u string, limit int64) (string, int, bool) {
	resp, err := client.Get(u)
	if err != nil {
		return "", 0, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	resp.Body.Close()
	if err != nil {
		return "", resp.StatusCode, false
	}
	return strings.ToLower(string(body)), resp.StatusCode, true
}

// signaturesIn returns the set of sigs found in body (sigs must be lowercase).
func signaturesIn(body string, sigs []string) map[string]bool {
	found := map[string]bool{}
	for _, sig := range sigs {
		if strings.Contains(body, sig) {
			found[sig] = true
		}
	}
	return found
}

// httpMethodProcessed decides whether a dangerous HTTP method was actually
// handled by the server, versus the server simply serving its normal page in
// response to any method (a soft response that is NOT a vulnerability — e.g. a
// WordPress/Apache origin that returns 200 + the homepage for PUT/DELETE).
func httpMethodProcessed(method string, status, bodyLen, getLen int, body string) bool {
	// Explicit accepted/created responses indicate real processing.
	switch status {
	case 201, 204, 207:
		return true
	}
	if method == "TRACE" {
		// TRACE is only dangerous (Cross-Site Tracing) if it echoes the request.
		return status == 200 && strings.Contains(strings.ToUpper(body), "TRACE /")
	}
	// A 2xx that returns essentially the same page as GET means the method was
	// ignored; only flag when the body differs substantially (method changed state).
	if status >= 200 && status < 300 && getLen > 0 {
		return float64(absInt(bodyLen-getLen))/float64(getLen) > 0.30
	}
	return false
}

// soft404Baseline probes a random, certainly-nonexistent path. If the site
// answers 200 with a body, it serves soft-404s (200 for everything) — so a 200
// on a "sensitive" path proves nothing. Returns (baselineBodyLen, isSoft404).
func soft404Baseline(client *http.Client, baseURL string) (int, bool) {
	u := strings.TrimRight(baseURL, "/") + "/vscan-404-probe-a8f3x9q2z7t1/"
	body, status, ok := fetchLowerBody(client, u, 64*1024)
	if ok && status == 200 && len(body) > 0 {
		return len(body), true
	}
	return 0, false
}

// similarSize reports whether two body lengths are within 15% of each other —
// used to recognise a soft-404 response returned for a sensitive path.
func similarSize(a, b int) bool {
	if a == 0 && b == 0 {
		return true
	}
	base := a
	if b > base {
		base = b
	}
	return float64(absInt(a-b))/float64(base) < 0.15
}

// absInt returns the absolute value of an int.
func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// redirectTargetsHost reports whether a Location header, resolved against the
// request base, actually navigates to evilHost. This distinguishes a true open
// redirect from a same-origin URL that merely contains the attacker host as a
// query parameter (e.g. /login?next=https://evil.example.com stays same-origin).
func redirectTargetsHost(base, location, evilHost string) bool {
	if strings.TrimSpace(location) == "" {
		return false
	}
	b, err := url.Parse(base)
	if err != nil {
		return false
	}
	loc, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return false
	}
	return strings.EqualFold(b.ResolveReference(loc).Hostname(), evilHost)
}

// bodyLooksLikeHTML reports whether a body is an HTML document — used to reject
// soft-404s where a site serves its normal page (200 + HTML) for a path that is
// supposed to be a raw .sql/.zip/.env/etc. file.
func bodyLooksLikeHTML(body string) bool {
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	l := strings.ToLower(head)
	return strings.Contains(l, "<!doctype html") ||
		strings.Contains(l, "<html") ||
		strings.Contains(l, "<head") ||
		strings.Contains(l, "<body")
}
