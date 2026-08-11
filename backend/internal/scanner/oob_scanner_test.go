package scanner

import "testing"

func TestOOBDisabledByDefault(t *testing.T) {
	t.Setenv("SEKU_ENABLE_OOB", "")
	res := NewOOBScanner().Scan("https://example.com/path?a=1")
	if len(res) != 1 || res[0].Status != "info" {
		t.Fatalf("expected single skipped info result, got %+v", res)
	}
}

func TestStripURLQuery(t *testing.T) {
	cases := map[string]string{
		"https://ex.com/a?b=1#f": "https://ex.com/a",
		"https://ex.com/a":       "https://ex.com/a",
		"https://ex.com":         "https://ex.com",
	}
	for in, want := range cases {
		if got := stripURLQuery(in); got != want {
			t.Fatalf("stripURLQuery(%q)=%q want %q", in, got, want)
		}
	}
}
