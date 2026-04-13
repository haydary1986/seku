package scanner

import (
	"encoding/json"
	"strings"

	"seku/internal/models"
)

// UpgradeSuggestion represents a recommendation to upgrade a vulnerable library.
type UpgradeSuggestion struct {
	Library        string   `json:"library"`
	CurrentVersion string   `json:"current_version"`
	SafeVersion    string   `json:"safe_version"`
	LatestVersion  string   `json:"latest_version"`
	CVEs           []string `json:"cves"`
	Breaking       bool     `json:"breaking"`
	Severity       string   `json:"severity"`
	Description    string   `json:"description"`
}

// KnownVulnerableLibraries maps library@version patterns to upgrade info.
var KnownVulnerableLibraries = map[string]UpgradeSuggestion{
	"jquery<1.12.0": {
		Library: "jQuery", SafeVersion: "3.7.1", LatestVersion: "3.7.1",
		CVEs:     []string{"CVE-2015-9251", "CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"},
		Breaking: true, Severity: "critical",
		Description: "Multiple XSS vulnerabilities including prototype pollution and HTML injection",
	},
	"jquery<2.2.0": {
		Library: "jQuery", SafeVersion: "3.7.1", LatestVersion: "3.7.1",
		CVEs:     []string{"CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"},
		Breaking: true, Severity: "high",
		Description: "XSS via cross-site scripting in htmlPrefilter and prototype pollution",
	},
	"jquery<3.5.0": {
		Library: "jQuery", SafeVersion: "3.7.1", LatestVersion: "3.7.1",
		CVEs:     []string{"CVE-2020-11022", "CVE-2020-11023"},
		Breaking: false, Severity: "high",
		Description: "XSS vulnerability in jQuery.htmlPrefilter regex",
	},
	"jquery<3.7.0": {
		Library: "jQuery", SafeVersion: "3.7.1", LatestVersion: "3.7.1",
		CVEs:     []string{},
		Breaking: false, Severity: "low",
		Description: "Minor version behind latest. Upgrade recommended for bug fixes.",
	},
	"bootstrap<3.4.1": {
		Library: "Bootstrap", SafeVersion: "3.4.1", LatestVersion: "5.3.3",
		CVEs:     []string{"CVE-2019-8331", "CVE-2018-14041", "CVE-2018-14042"},
		Breaking: true, Severity: "high",
		Description: "XSS vulnerabilities in tooltip, popover, and collapse plugins",
	},
	"bootstrap<4.3.1": {
		Library: "Bootstrap", SafeVersion: "4.6.2", LatestVersion: "5.3.3",
		CVEs:     []string{"CVE-2019-8331"},
		Breaking: false, Severity: "medium",
		Description: "XSS in tooltip/popover data-template attribute",
	},
	"angular<1.8.0": {
		Library: "AngularJS", SafeVersion: "1.8.3", LatestVersion: "1.8.3",
		CVEs:     []string{"CVE-2022-25869", "CVE-2023-26116", "CVE-2023-26117", "CVE-2023-26118"},
		Breaking: false, Severity: "critical",
		Description: "AngularJS is EOL. Multiple XSS and ReDoS vulnerabilities. Migrate to Angular 17+.",
	},
	"lodash<4.17.21": {
		Library: "Lodash", SafeVersion: "4.17.21", LatestVersion: "4.17.21",
		CVEs:     []string{"CVE-2021-23337", "CVE-2020-28500", "CVE-2020-8203"},
		Breaking: false, Severity: "high",
		Description: "Prototype pollution and command injection vulnerabilities",
	},
	"moment<2.29.4": {
		Library: "Moment.js", SafeVersion: "2.30.1", LatestVersion: "2.30.1",
		CVEs:     []string{"CVE-2022-31129", "CVE-2022-24785"},
		Breaking: false, Severity: "medium",
		Description: "ReDoS and path traversal vulnerabilities. Consider migrating to dayjs or date-fns.",
	},
	"vue<2.7.0": {
		Library: "Vue.js", SafeVersion: "2.7.16", LatestVersion: "3.4.38",
		CVEs:     []string{"CVE-2024-6783"},
		Breaking: false, Severity: "medium",
		Description: "XSS vulnerability in template compiler. Upgrade to 2.7.16+ or migrate to Vue 3.",
	},
	"react<16.14.0": {
		Library: "React", SafeVersion: "16.14.0", LatestVersion: "18.3.1",
		CVEs:     []string{"CVE-2021-24032"},
		Breaking: false, Severity: "medium",
		Description: "XSS vulnerability in dangerouslySetInnerHTML. Upgrade recommended.",
	},
	"wordpress<6.4": {
		Library: "WordPress", SafeVersion: "6.8.1", LatestVersion: "6.8.1",
		CVEs:     []string{"CVE-2024-31210", "CVE-2024-2087"},
		Breaking: false, Severity: "high",
		Description: "Multiple security fixes including PHP object injection and XSS",
	},
	"wordpress<6.6": {
		Library: "WordPress", SafeVersion: "6.8.1", LatestVersion: "6.8.1",
		CVEs:     []string{"CVE-2024-6307"},
		Breaking: false, Severity: "medium",
		Description: "Security improvements and bug fixes. Update recommended.",
	},
	"elementor<3.20": {
		Library: "Elementor", SafeVersion: "3.24.0", LatestVersion: "3.24.0",
		CVEs:     []string{"CVE-2024-2117", "CVE-2024-0506"},
		Breaking: false, Severity: "high",
		Description: "Stored XSS and broken access control vulnerabilities",
	},
}

// GetUpgradeSuggestions analyzes check results and returns upgrade suggestions
// for libraries with known vulnerabilities.
func GetUpgradeSuggestions(checkResults []models.CheckResult) []UpgradeSuggestion {
	var suggestions []UpgradeSuggestion
	seen := map[string]bool{}

	for _, ch := range checkResults {
		if ch.Category != "js_libraries" && ch.Category != "wordpress" {
			continue
		}
		if ch.Score >= 900 {
			continue // already good
		}

		detectedVersion := extractVersionFromCheck(ch)

		for key, suggestion := range KnownVulnerableLibraries {
			if seen[suggestion.Library] {
				continue
			}
			if containsLibraryHint(ch, key) {
				// Skip if version is unknown — can't confirm vulnerability
				if detectedVersion == "unknown" || detectedVersion == "" {
					s := suggestion
					s.CurrentVersion = "unknown"
					s.Severity = "low"
					s.Description = "Version could not be detected. Verify manually and update if needed."
					suggestions = append(suggestions, s)
					seen[suggestion.Library] = true
					continue
				}
				s := suggestion
				s.CurrentVersion = detectedVersion
				suggestions = append(suggestions, s)
				seen[suggestion.Library] = true
			}
		}
	}

	return suggestions
}

// containsLibraryHint checks whether a CheckResult relates to the given library key.
// The key format is "libname<version", e.g. "jquery<3.5.0".
func containsLibraryHint(ch models.CheckResult, key string) bool {
	parts := strings.SplitN(key, "<", 2)
	if len(parts) < 1 {
		return false
	}
	libName := strings.ToLower(parts[0])

	// Check in check_name (case-insensitive)
	checkNameLower := strings.ToLower(ch.CheckName)
	if strings.Contains(checkNameLower, libName) {
		return true
	}

	// Check in details JSON
	if ch.Details != "" {
		var details map[string]interface{}
		if json.Unmarshal([]byte(ch.Details), &details) == nil {
			// Check library field
			if lib, ok := details["library"].(string); ok {
				if strings.Contains(strings.ToLower(lib), libName) {
					return true
				}
			}
			// Check name field
			if name, ok := details["name"].(string); ok {
				if strings.Contains(strings.ToLower(name), libName) {
					return true
				}
			}
			// Check message field
			if msg, ok := details["message"].(string); ok {
				if strings.Contains(strings.ToLower(msg), libName) {
					return true
				}
			}
		}
	}

	return false
}

// extractVersionFromCheck parses version info from check details.
func extractVersionFromCheck(ch models.CheckResult) string {
	if ch.Details == "" {
		return "unknown"
	}

	var details map[string]interface{}
	if json.Unmarshal([]byte(ch.Details), &details) != nil {
		return "unknown"
	}

	// Try common version field names
	for _, field := range []string{"version", "current_version", "detected_version"} {
		if v, ok := details[field].(string); ok && v != "" {
			return v
		}
	}

	return "unknown"
}
