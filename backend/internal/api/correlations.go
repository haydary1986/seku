package api

import (
	"context"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
)

var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// domains that are noise, not real target/admin emails
var boringEmailDomains = map[string]bool{
	"example.com": true, "example.org": true, "example.invalid": true,
	"w3.org": true, "schema.org": true, "sentry.io": true, "cloudflare.com": true,
	"googleapis.com": true, "gstatic.com": true, "wordpress.org": true,
}

// two-level public suffixes so we resolve NS/MX at the registrable domain.
var twoLevelTLDs = map[string]bool{
	"edu.iq": true, "gov.iq": true, "com.iq": true, "org.iq": true, "net.iq": true,
	"co.uk": true, "ac.uk": true, "gov.uk": true, "org.uk": true,
	"com.tr": true, "edu.tr": true, "gov.tr": true,
	"com.sa": true, "edu.sa": true, "gov.sa": true, "org.sa": true,
	"com.eg": true, "edu.eg": true, "gov.eg": true,
}

type corrGroup struct {
	Value   string   `json:"value"`
	Targets []string `json:"targets"`
}

var (
	corrCacheMu sync.Mutex
	corrCache   = map[uint]struct {
		at   time.Time
		data fiber.Map
	}{}
)

// GetCorrelations finds attributes shared across the org's scan targets
// (same IP, nameserver, mail server, or exposed email) and returns them as a
// tree grouped by attribute type.
func GetCorrelations(c *fiber.Ctx) error {
	orgID := GetUserOrgID(c)

	if c.Query("refresh") != "1" {
		corrCacheMu.Lock()
		if cached, ok := corrCache[orgID]; ok && time.Since(cached.at) < 5*time.Minute {
			corrCacheMu.Unlock()
			return c.JSON(cached.data)
		}
		corrCacheMu.Unlock()
	}

	var targets []models.ScanTarget
	config.DB.Where("organization_id = ?", orgID).Find(&targets)

	hosts := []string{}
	hostSet := map[string]bool{}
	targetIDToHost := map[uint]string{}
	targetIDs := []uint{}
	for _, t := range targets {
		h := hostOf(t.URL)
		targetIDToHost[t.ID] = h
		targetIDs = append(targetIDs, t.ID)
		if h == "" || hostSet[h] {
			continue
		}
		hostSet[h] = true
		hosts = append(hosts, h)
	}
	if len(hosts) > 400 {
		hosts = hosts[:400]
	}

	ipMap := map[string]map[string]bool{}
	nsMap := map[string]map[string]bool{}
	mxMap := map[string]map[string]bool{}
	var mu sync.Mutex
	resolver := net.DefaultResolver

	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			apex := apexOf(h)

			if ips, err := resolver.LookupHost(ctx, h); err == nil {
				mu.Lock()
				for _, ip := range ips {
					addTo(ipMap, ip, h)
				}
				mu.Unlock()
			}
			if ns, err := resolver.LookupNS(ctx, apex); err == nil {
				mu.Lock()
				for _, n := range ns {
					addTo(nsMap, cleanHost(n.Host), h)
				}
				mu.Unlock()
			}
			if mx, err := resolver.LookupMX(ctx, apex); err == nil {
				mu.Lock()
				for _, m := range mx {
					addTo(mxMap, cleanHost(m.Host), h)
				}
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()

	// Emails from each target's latest scan result.
	emailMap := map[string]map[string]bool{}
	if len(targetIDs) > 0 {
		var results []models.ScanResult
		config.DB.Where("scan_target_id IN ?", targetIDs).Order("created_at desc").Find(&results)
		resultToHost := map[uint]string{}
		seen := map[uint]bool{}
		resultIDs := []uint{}
		for _, r := range results {
			if seen[r.ScanTargetID] {
				continue
			}
			seen[r.ScanTargetID] = true
			resultToHost[r.ID] = targetIDToHost[r.ScanTargetID]
			resultIDs = append(resultIDs, r.ID)
		}
		if len(resultIDs) > 0 {
			var checks []models.CheckResult
			config.DB.Where("scan_result_id IN ?", resultIDs).Select("scan_result_id, details").Find(&checks)
			for _, ck := range checks {
				host := resultToHost[ck.ScanResultID]
				for _, em := range emailRe.FindAllString(ck.Details, -1) {
					em = strings.ToLower(em)
					dom := em[strings.LastIndex(em, "@")+1:]
					if boringEmailDomains[dom] || strings.Contains(em, "seku_") || strings.HasSuffix(dom, ".invalid") {
						continue
					}
					addTo(emailMap, em, host)
				}
			}
		}
	}

	data := fiber.Map{
		"ip":         sharedGroups(ipMap),
		"nameserver": sharedGroups(nsMap),
		"mail":       sharedGroups(mxMap),
		"email":      sharedGroups(emailMap),
		"targets":    len(hosts),
	}

	corrCacheMu.Lock()
	corrCache[orgID] = struct {
		at   time.Time
		data fiber.Map
	}{time.Now(), data}
	corrCacheMu.Unlock()

	return c.JSON(data)
}

func addTo(m map[string]map[string]bool, value, host string) {
	if value == "" || host == "" {
		return
	}
	if m[value] == nil {
		m[value] = map[string]bool{}
	}
	m[value][host] = true
}

// sharedGroups keeps only values shared by 2+ targets, sorted by count desc.
func sharedGroups(m map[string]map[string]bool) []corrGroup {
	out := []corrGroup{}
	for value, hostSet := range m {
		if len(hostSet) < 2 {
			continue
		}
		hosts := make([]string, 0, len(hostSet))
		for h := range hostSet {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		out = append(out, corrGroup{Value: value, Targets: hosts})
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Targets) != len(out[j].Targets) {
			return len(out[i].Targets) > len(out[j].Targets)
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func hostOf(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func cleanHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func apexOf(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	last2 := strings.Join(parts[len(parts)-2:], ".")
	if len(parts) >= 3 && twoLevelTLDs[last2] {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return last2
}
