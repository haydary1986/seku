// Seku local scan agent.
//
// Runs INSIDE a network, polls the Seku server for scan jobs, executes them
// locally (so it can reach internal IPs / routers), and reports results back.
// It only ever runs the built-in scanner engine on a given target — it never
// executes arbitrary commands, so it is not a remote-command backdoor.
//
// Build (cross-compile, no CGO):
//
//	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o seku-agent.exe ./cmd/agent
//	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o seku-agent-mac ./cmd/agent
//
// Run:
//
//	seku-agent -server https://sec.erticaz.com -token <AGENT_TOKEN>
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"seku/internal/models"
	"seku/internal/scanner"
)

const agentVersion = "1.0.0"

type job struct {
	ID     uint   `json:"id"`
	Target string `json:"target"`
	Policy string `json:"policy"`
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	server := flag.String("server", env("SEKU_SERVER", "https://sec.erticaz.com"), "Seku server URL")
	token := flag.String("token", env("SEKU_AGENT_TOKEN", ""), "Agent token (from the Seku dashboard → Agents)")
	interval := flag.Int("interval", 8, "seconds between job polls")
	flag.Parse()

	if *token == "" {
		fmt.Println("Seku Agent — runs security scans inside your network.")
		fmt.Println("Usage: seku-agent -server https://sec.erticaz.com -token <AGENT_TOKEN>")
		fmt.Println("   or: set SEKU_SERVER and SEKU_AGENT_TOKEN environment variables.")
		os.Exit(1)
	}

	base := strings.TrimRight(*server, "/")
	client := &http.Client{Timeout: 5 * time.Minute}

	heartbeat(client, base, *token)
	fmt.Printf("Seku agent v%s connected to %s (os=%s/%s). Waiting for jobs...\n",
		agentVersion, base, runtime.GOOS, runtime.GOARCH)

	lastBeat := time.Now()
	for {
		j, ok := pollJob(client, base, *token)
		if !ok {
			if time.Since(lastBeat) > 60*time.Second {
				heartbeat(client, base, *token)
				lastBeat = time.Now()
			}
			time.Sleep(time.Duration(*interval) * time.Second)
			continue
		}

		fmt.Printf("[job %d] scanning %s (policy=%s)...\n", j.ID, j.Target, j.Policy)
		start := time.Now()
		results := scanner.RunPolicy(j.Policy, j.Target, &scanner.ScanConfig{})
		dur := int(time.Since(start).Seconds())
		findings := 0
		for _, r := range results {
			if r.Status == "fail" {
				findings++
			}
		}
		postResult(client, base, *token, j.ID, results, findings, dur)
		fmt.Printf("[job %d] done: %d checks, %d findings, %ds\n", j.ID, len(results), findings, dur)
		lastBeat = time.Now()
	}
}

func heartbeat(client *http.Client, base, token string) {
	body, _ := json.Marshal(map[string]string{
		"os": runtime.GOOS + "/" + runtime.GOARCH, "version": agentVersion,
	})
	req, _ := http.NewRequest("POST", base+"/api/agent/heartbeat", bytes.NewReader(body))
	req.Header.Set("X-Agent-Token", token)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}
}

func pollJob(client *http.Client, base, token string) (job, bool) {
	req, _ := http.NewRequest("GET", base+"/api/agent/jobs", nil)
	req.Header.Set("X-Agent-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("poll error:", err)
		return job{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		fmt.Println("error: invalid agent token — check -token")
		time.Sleep(15 * time.Second)
		return job{}, false
	}
	if resp.StatusCode != 200 {
		return job{}, false // 204 = no pending job
	}
	var j job
	if json.NewDecoder(resp.Body).Decode(&j) != nil || j.ID == 0 {
		return job{}, false
	}
	return j, true
}

func postResult(client *http.Client, base, token string, id uint, results []models.CheckResult, findings, dur int) {
	rj, _ := json.Marshal(results)
	body, _ := json.Marshal(map[string]interface{}{
		"status": "done", "results_json": string(rj), "findings": findings, "duration_sec": dur,
	})
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/agent/jobs/%d/result", base, id), bytes.NewReader(body))
	req.Header.Set("X-Agent-Token", token)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	} else {
		fmt.Println("post error:", err)
	}
}
