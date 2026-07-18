package scanner

import "testing"

func TestVersionDefinitelyAffected(t *testing.T) {
	cases := []struct {
		version, maxAffected string
		want                 bool
		why                  string
	}{
		{"6.4", "6.5.1", true, "6.4 is definitely below 6.5.1"},
		{"6.5.0", "6.5.1", true, "6.5.0 < 6.5.1"},
		{"6.5", "6.5.1", false, "patch unknown within 6.5.x — could be 6.5.9 (patched)"},
		{"", "6.5.1", false, "hidden/empty version must not match every CVE"},
		{"6.5", "6.5", true, "6.5 <= 6.5 (fixed in >6.5)"},
		{"7.0", "6.5.1", false, "7.0 is newer, not affected"},
		{"6.6", "6.5.1", false, "6.6 > 6.5.1"},
	}
	for _, c := range cases {
		if got := versionDefinitelyAffected(c.version, c.maxAffected); got != c.want {
			t.Errorf("versionDefinitelyAffected(%q,%q)=%v want %v — %s", c.version, c.maxAffected, got, c.want, c.why)
		}
	}
}

func TestRedirectTargetsHost(t *testing.T) {
	base := "https://victim.edu/page"
	cases := []struct {
		location string
		want     bool
		why      string
	}{
		{"https://evil.example.com", true, "absolute redirect to attacker host"},
		{"//evil.example.com", true, "protocol-relative to attacker host"},
		{"https://victim.edu/login?next=https://evil.example.com", false, "same-origin gate that merely echoes the URL"},
		{"/dashboard", false, "same-origin relative path"},
		{"", false, "no Location"},
	}
	for _, c := range cases {
		if got := redirectTargetsHost(base, c.location, "evil.example.com"); got != c.want {
			t.Errorf("redirectTargetsHost(%q)=%v want %v — %s", c.location, got, c.want, c.why)
		}
	}
}

func TestIsBlockedStatus(t *testing.T) {
	for _, code := range []int{403, 406, 429, 501, 503} {
		if !isBlockedStatus(code) {
			t.Errorf("status %d should be treated as blocked", code)
		}
	}
	for _, code := range []int{200, 301, 404, 500} {
		if isBlockedStatus(code) {
			t.Errorf("status %d should NOT be treated as blocked", code)
		}
	}
}
