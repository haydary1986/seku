package services

import "testing"

func set(refs ...findingRef) map[string]findingRef {
	m := map[string]findingRef{}
	for _, r := range refs {
		m[r.Category+"::"+r.CheckName] = r
	}
	return m
}

func TestDiffFindings_NewAndFixed(t *testing.T) {
	old := set(
		findingRef{"headers", "HSTS", "medium"},
		findingRef{"ssl", "TLS Version", "high"},
	)
	// HSTS fixed, TLS still failing, a new critical SQLi appeared.
	newer := set(
		findingRef{"ssl", "TLS Version", "high"},
		findingRef{"sqli", "SQL Injection Test", "critical"},
	)
	ch := diffFindings(old, newer, 800, 780)
	if ch == nil {
		t.Fatal("expected a change, got nil")
	}
	if ch.NewFindings != 1 {
		t.Errorf("new findings = %d, want 1 (SQLi)", ch.NewFindings)
	}
	if ch.FixedFindings != 1 {
		t.Errorf("fixed findings = %d, want 1 (HSTS)", ch.FixedFindings)
	}
}

func TestDiffFindings_Regression(t *testing.T) {
	same := set(findingRef{"headers", "HSTS", "medium"})
	// no finding delta, but score dropped past threshold → regression.
	ch := diffFindings(same, same, 820, 700)
	if ch == nil || !ch.Regressed {
		t.Fatalf("a >40pt score drop must be a regression, got %#v", ch)
	}
}

func TestDiffFindings_NoNoise(t *testing.T) {
	same := set(findingRef{"headers", "HSTS", "medium"})
	// identical findings, tiny score wobble → no change recorded.
	if ch := diffFindings(same, same, 800, 785); ch != nil {
		t.Errorf("a 15pt wobble with no finding change must NOT record a change, got %#v", ch)
	}
}
