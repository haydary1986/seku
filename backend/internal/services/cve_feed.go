package services

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CVEEntry represents a vulnerability from the NVD feed.
type CVEEntry struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Published   string   `json:"published"`
	References  []string `json:"references"`
	Products    []string `json:"products"`
}

// CVECache holds the latest CVE data in memory.
var CVECache = &cveCache{
	entries: make(map[string][]CVEEntry),
}

type cveCache struct {
	mu        sync.RWMutex
	entries   map[string][]CVEEntry // keyed by product/keyword
	updatedAt time.Time
}

// GetCVEs returns cached CVEs for a product keyword.
func (c *cveCache) GetCVEs(keyword string) []CVEEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[strings.ToLower(keyword)]
}

// SetCVEs stores CVEs for a product keyword.
func (c *cveCache) SetCVEs(keyword string, entries []CVEEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[strings.ToLower(keyword)] = entries
	c.updatedAt = time.Now()
}

// LastUpdated returns when the cache was last updated.
func (c *cveCache) LastUpdated() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.updatedAt
}

// FetchCVEsForProduct queries the NVD API for recent CVEs related to a product.
func FetchCVEsForProduct(keyword string) ([]CVEEntry, error) {
	// Check cache first
	if cached := CVECache.GetCVEs(keyword); len(cached) > 0 {
		return cached, nil
	}

	client := &http.Client{Timeout: 15 * time.Second}
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=20", keyword)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Seku-Scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}

	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Published   string `json:"published"`
				Description struct {
					Descriptions []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"descriptions"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, err
	}

	var entries []CVEEntry
	for _, v := range nvdResp.Vulnerabilities {
		entry := CVEEntry{
			ID:        v.CVE.ID,
			Published: v.CVE.Published,
			Products:  []string{keyword},
		}

		// Get English description
		for _, desc := range v.CVE.Description.Descriptions {
			if desc.Lang == "en" {
				entry.Description = desc.Value
				break
			}
		}

		// Get CVSS score
		if len(v.CVE.Metrics.CvssMetricV31) > 0 {
			entry.Score = v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore
			entry.Severity = v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		}

		// Get references
		for _, ref := range v.CVE.References {
			entry.References = append(entry.References, ref.URL)
		}

		entries = append(entries, entry)
	}

	// Cache for 12 hours
	CVECache.SetCVEs(keyword, entries)

	return entries, nil
}

// StartCVEUpdater runs a background job that refreshes CVE data every 12 hours
// for commonly detected technologies.
func StartCVEUpdater() {
	commonProducts := []string{
		"apache", "nginx", "iis", "wordpress", "jquery",
		"php", "openssl", "tomcat", "nodejs", "mysql",
		"postgresql", "redis", "mongodb", "elasticsearch",
		"drupal", "joomla", "react", "angular", "vue",
	}

	// Initial fetch
	go func() {
		for _, product := range commonProducts {
			FetchCVEsForProduct(product)
			time.Sleep(6 * time.Second) // Rate limit: NVD allows ~5 req/30s without API key
		}
		log.Println("[CVE Updater] Initial CVE data loaded")
	}()

	// Periodic refresh every 12 hours
	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		for range ticker.C {
			for _, product := range commonProducts {
				FetchCVEsForProduct(product)
				time.Sleep(6 * time.Second)
			}
			log.Println("[CVE Updater] CVE data refreshed")
		}
	}()
}
