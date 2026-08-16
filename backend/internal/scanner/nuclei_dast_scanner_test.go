package scanner

import (
	"strings"
	"testing"
)

// DAST is intrusive and must be OFF unless explicitly enabled. With no config it
// returns a single informational "disabled" result and sends NO traffic.
func TestNucleiDast_DisabledByDefault(t *testing.T) {
	s := NewNucleiDastScanner()
	res := s.Scan("https://example.com")
	if len(res) != 1 {
		t.Fatalf("disabled DAST should return exactly one info result, got %d", len(res))
	}
	if res[0].Status != "info" || res[0].Severity != "info" {
		t.Errorf("disabled DAST must be informational, got status=%q severity=%q", res[0].Status, res[0].Severity)
	}
	if res[0].Category != "dast" {
		t.Errorf("category should be dast, got %q", res[0].Category)
	}
	if !strings.Contains(res[0].Details, "disabled") {
		t.Errorf("details should explain it is disabled, got %q", res[0].Details)
	}
}

// The scanner satisfies the ConfigurableScanner interface so the engine passes
// the per-scan toggle through.
func TestNucleiDast_IsConfigurable(t *testing.T) {
	var _ ConfigurableScanner = NewNucleiDastScanner()
	if NewNucleiDastScanner().Category() != "dast" {
		t.Errorf("expected category dast")
	}
}
