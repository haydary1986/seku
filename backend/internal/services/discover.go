package services

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// DiscoverDomainsFromCT searches multiple sources to find domains matching an extension.
// Uses crt.sh, HackerTarget, RapidDNS, and Web Archive as fallbacks.
func DiscoverDomainsFromCT(domainExt string) ([]string, error) {
	seen := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sources := []struct {
		name string
		fn   func(string) []string
	}{
		{"crt.sh", fetchFromCrtSh},
		{"HackerTarget", fetchFromHackerTarget},
		{"RapidDNS", fetchFromRapidDNS},
		{"WebArchive", fetchFromWebArchive},
	}

	for _, src := range sources {
		wg.Add(1)
		go func(name string, fn func(string) []string) {
			defer wg.Done()
			results := fn(domainExt)
			mu.Lock()
			for _, d := range results {
				root := extractRootDomain(d, domainExt)
				if root != "" {
					seen[root] = true
				}
			}
			mu.Unlock()
			log.Printf("[Discovery] %s: found %d domains for %s", name, len(results), domainExt)
		}(src.name, src.fn)
	}

	wg.Wait()

	if len(seen) == 0 {
		return nil, fmt.Errorf("no domains found — all sources returned empty for %s", domainExt)
	}

	var domains []string
	for d := range seen {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return domains, nil
}

// --- Source 1: crt.sh (Certificate Transparency) ---
func fetchFromCrtSh(domainExt string) []string {
	client := &http.Client{Timeout: 90 * time.Second}
	url := fmt.Sprintf("https://crt.sh/?q=%%25%s&output=json", domainExt)

	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if json.Unmarshal(body, &entries) != nil {
		return nil
	}

	var results []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name != "" && strings.HasSuffix(name, domainExt) {
				results = append(results, name)
			}
		}
	}
	return results
}

// --- Source 2: HackerTarget ---
func fetchFromHackerTarget(domainExt string) []string {
	// HackerTarget needs a base domain, not extension — use a wildcard search
	client := &http.Client{Timeout: 30 * time.Second}

	// Search for known TLDs
	searchDomain := strings.TrimPrefix(domainExt, ".")
	resp, err := client.Get("https://api.hackertarget.com/hostsearch/?q=" + searchDomain)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	var results []string
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ",", 2)
		if len(parts) == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		if name != "" && strings.HasSuffix(name, domainExt) {
			results = append(results, name)
		}
	}
	return results
}

// --- Source 3: RapidDNS ---
func fetchFromRapidDNS(domainExt string) []string {
	client := &http.Client{Timeout: 30 * time.Second}
	searchDomain := strings.TrimPrefix(domainExt, ".")

	req, _ := http.NewRequest("GET", "https://rapiddns.io/sameip/"+searchDomain+"?full=1", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Seku/1.0)")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 3*1024*1024))
	content := string(body)

	var results []string
	seen := map[string]bool{}
	for _, word := range strings.Fields(content) {
		// Strip HTML tags
		if idx := strings.Index(word, ">"); idx >= 0 {
			word = word[idx+1:]
		}
		if idx := strings.Index(word, "<"); idx >= 0 {
			word = word[:idx]
		}
		word = strings.ToLower(strings.TrimSpace(word))
		if !strings.HasSuffix(word, domainExt) {
			continue
		}
		// Basic validation
		valid := true
		for _, ch := range word {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
				valid = false
				break
			}
		}
		if valid && !seen[word] {
			seen[word] = true
			results = append(results, word)
		}
	}
	return results
}

// --- Source 4: Web Archive ---
func fetchFromWebArchive(domainExt string) []string {
	client := &http.Client{Timeout: 30 * time.Second}
	searchDomain := strings.TrimPrefix(domainExt, ".")

	resp, err := client.Get("https://web.archive.org/cdx/search/cdx?url=*." + searchDomain + "&output=json&fl=original&collapse=urlkey&limit=500")
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 3*1024*1024))

	var rows [][]string
	if json.Unmarshal(body, &rows) != nil {
		return nil
	}

	var results []string
	seen := map[string]bool{}
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		rawURL := strings.ToLower(row[0])
		rawURL = strings.TrimPrefix(rawURL, "https://")
		rawURL = strings.TrimPrefix(rawURL, "http://")
		host := strings.SplitN(rawURL, "/", 2)[0]
		host = strings.SplitN(host, ":", 2)[0]

		if host != "" && strings.HasSuffix(host, domainExt) && !seen[host] {
			seen[host] = true
			results = append(results, host)
		}
	}
	return results
}

// extractRootDomain gets the root domain from a full hostname.
func extractRootDomain(hostname, ext string) string {
	prefix := strings.TrimSuffix(hostname, ext)
	prefix = strings.TrimRight(prefix, ".")
	if prefix == "" {
		return ""
	}
	parts := strings.Split(prefix, ".")
	orgName := parts[len(parts)-1]
	if orgName == "" {
		return ""
	}
	return orgName + ext
}
