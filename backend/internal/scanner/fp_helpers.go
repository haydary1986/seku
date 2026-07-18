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
