package scanner

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newXSSServer builds a test server whose "s"/"q" params are rendered into a
// <script> block using the supplied render function, letting us simulate raw,
// encoded, and WAF-blocked reflections.
func newXSSServer(render func(param string) (status int, body string)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("s")
		if v == "" {
			v = r.URL.Query().Get("q")
		}
		status, body := render(v)
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
}

func TestVerifyExploitable_RawReflectionIsExploitable(t *testing.T) {
	srv := newXSSServer(func(p string) (int, string) {
		// Reflected verbatim into a script context — genuinely exploitable.
		return 200, `<html><script>var loc="` + p + `";</script></html>`
	})
	defer srv.Close()
	s := NewXSSScanner()
	if !s.verifyExploitable(http.DefaultClient, srv.URL, "s") {
		t.Error("raw unescaped reflection must be reported as exploitable")
	}
}

func TestVerifyExploitable_EncodedReflectionIsSafe(t *testing.T) {
	srv := newXSSServer(func(p string) (int, string) {
		// HTML-entity encoded — the Turath / MonsterInsights case. NOT exploitable.
		return 200, `<html><script>var loc="` + html.EscapeString(p) + `";</script></html>`
	})
	defer srv.Close()
	s := NewXSSScanner()
	if s.verifyExploitable(http.DefaultClient, srv.URL, "s") {
		t.Error("entity-encoded reflection must NOT be reported as exploitable (false positive)")
	}
}

func TestVerifyExploitable_WAFBlockedIsSafe(t *testing.T) {
	srv := newXSSServer(func(p string) (int, string) {
		if strings.ContainsAny(p, `"<>`) {
			return 403, "Forbidden" // WAF blocks breakout payloads (Cloudflare behaviour)
		}
		return 200, `<html><script>var loc="` + p + `";</script></html>`
	})
	defer srv.Close()
	s := NewXSSScanner()
	if s.verifyExploitable(http.DefaultClient, srv.URL, "s") {
		t.Error("WAF-blocked breakout (403) must NOT be reported as exploitable")
	}
}

// End-to-end: an encoded reflection must produce a PASS (no cap), a raw one a FAIL.
func TestCheckURLParamReflection_EncodedPassesRawFails(t *testing.T) {
	s := NewXSSScanner()

	encoded := newXSSServer(func(p string) (int, string) {
		return 200, `<html><script>var l="` + html.EscapeString(p) + `";</script></html>`
	})
	defer encoded.Close()
	r := s.checkURLParamReflection(http.DefaultClient, encoded.URL)
	if r.Status != "pass" {
		t.Errorf("encoded reflection should PASS, got status=%s score=%.0f", r.Status, r.Score)
	}

	raw := newXSSServer(func(p string) (int, string) {
		return 200, `<html><script>var l="` + p + `";</script></html>`
	})
	defer raw.Close()
	r2 := s.checkURLParamReflection(http.DefaultClient, raw.URL)
	if r2.Status != "fail" || r2.Score > 200 {
		t.Errorf("raw unescaped reflection should FAIL as critical, got status=%s score=%.0f", r2.Status, r2.Score)
	}
}
