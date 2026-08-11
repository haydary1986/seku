package scanner

import "testing"

func TestExtractCrawlURL(t *testing.T) {
	cases := map[string]string{
		`{"url":"https://ex.com/a"}`:                   "https://ex.com/a",
		`{"request":{"endpoint":"https://ex.com/b"}}`:  "https://ex.com/b",
		`{"request":{"url":"https://ex.com/c"}}`:       "https://ex.com/c",
		`https://ex.com/plain`:                         "https://ex.com/plain",
		`http://ex.com/plain2`:                         "http://ex.com/plain2",
		`not-a-url`:                                    "",
		``:                                             "",
		`{"other":"x"}`:                                "",
	}
	for in, want := range cases {
		if got := extractCrawlURL(in); got != want {
			t.Fatalf("extractCrawlURL(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCrawlDisabledByDefault(t *testing.T) {
	t.Setenv("SEKU_ENABLE_KATANA", "")
	res := NewCrawlScanner().Scan("https://example.com")
	if len(res) != 1 || res[0].Status != "info" {
		t.Fatalf("expected single skipped info result, got %+v", res)
	}
}

func TestEndpointSeverityOrder(t *testing.T) {
	sevOf := map[string]string{"a": "low", "b": "critical", "c": "medium"}
	if w := worstEndpointSeverity(sevOf); w != "critical" {
		t.Fatalf("worst=%q want critical", w)
	}
}
