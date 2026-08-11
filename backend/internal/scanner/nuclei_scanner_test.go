package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// verifies our JSONL struct maps nuclei's documented field names correctly.
func TestNucleiFindingParse(t *testing.T) {
	line := `{"template-id":"tech-detect","matched-at":"https://ex.com","info":{"name":"Nginx Detection","severity":"high","description":"detects nginx","tags":["tech","nginx"],"classification":{"cvss-score":7.5,"cvss-metrics":"CVSS:3.1/AV:N"}}}`
	var f nucleiFinding
	if err := json.Unmarshal([]byte(line), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.Info.Name != "Nginx Detection" || f.Info.Severity != "high" {
		t.Fatalf("bad parse: %+v", f.Info)
	}
	if len(f.Info.Tags) != 2 || f.Info.Classification == nil || f.Info.Classification.CVSSScore != 7.5 {
		t.Fatalf("bad classification/tags: %+v", f.Info)
	}

	cr := NewNucleiScanner().findingResult(f)
	if cr.Category != "nuclei" || !strings.HasPrefix(cr.CheckName, "Nuclei: ") {
		t.Fatalf("bad check result: %+v", cr)
	}
	if cr.CVSSScore != 7.5 || cr.Severity != "high" || cr.Status != "fail" {
		t.Fatalf("severity/cvss not mapped: %+v", cr)
	}
}

func TestNucleiSeverityMap(t *testing.T) {
	if sc, sev, st := nucleiSeverity("critical"); sc != 0 || sev != "critical" || st != "fail" {
		t.Fatalf("critical map wrong: %v %v %v", sc, sev, st)
	}
	if sc, _, st := nucleiSeverity("info"); sc != 1000 || st != "info" {
		t.Fatalf("info map wrong: %v %v", sc, st)
	}
}

// disabled by default → returns a single skipped info result (no exec).
func TestNucleiDisabledByDefault(t *testing.T) {
	t.Setenv("SEKU_ENABLE_NUCLEI", "")
	res := NewNucleiScanner().Scan("https://example.com")
	if len(res) != 1 || res[0].Status != "info" {
		t.Fatalf("expected single skipped info result, got %+v", res)
	}
}
