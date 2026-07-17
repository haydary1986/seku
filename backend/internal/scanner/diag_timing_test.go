package scanner

import (
	"flag"
	"fmt"
	"sort"
	"testing"
	"time"
)

var diagURL string

func init() { flag.StringVar(&diagURL, "diagurl", "", "live target URL for timing diagnostic") }

// TestDiagScannerTiming times every scanner against a live target to find which
// one stalls. Diagnostic only — run explicitly:
//
//	go test ./internal/scanner/ -run TestDiagScannerTiming -v -timeout 600s -diagurl https://uoturath.edu.iq
//
// Skipped unless -diagurl is set so normal test runs stay offline/fast.
func TestDiagScannerTiming(t *testing.T) {
	url := diagURL
	if url == "" {
		t.Skip("set -diagurl to run the live timing diagnostic")
	}

	type result struct {
		name    string
		dur     time.Duration
		checks  int
		timeout bool
	}
	const perScanner = 45 * time.Second

	var results []result
	for _, s := range allScanners() {
		done := make(chan int, 1)
		start := time.Now()
		go func(sc Scanner) {
			checks := sc.Scan(url)
			done <- len(checks)
		}(s)

		select {
		case n := <-done:
			results = append(results, result{s.Name(), time.Since(start), n, false})
		case <-time.After(perScanner):
			results = append(results, result{s.Name(), time.Since(start), 0, true})
			t.Logf("!! TIMEOUT (>%s): %s", perScanner, s.Name())
		}
	}

	sort.Slice(results, func(i, j int) bool { return results[i].dur > results[j].dur })
	fmt.Println("\n==== SCANNER TIMING (slowest first) ====")
	for _, r := range results {
		flag := ""
		if r.timeout {
			flag = "  <-- TIMED OUT / STALLING"
		}
		fmt.Printf("%7.1fs  %-38s checks=%d%s\n", r.dur.Seconds(), r.name, r.checks, flag)
	}
}
