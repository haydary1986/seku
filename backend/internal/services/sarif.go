package services

import (
	"encoding/json"
	"fmt"
	"strings"

	"seku/internal/models"
)

// SARIF v2.1.0 schema types
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription SARIFMessage    `json:"shortDescription"`
	HelpURI          string          `json:"helpUri,omitempty"`
	Properties       SARIFProperties `json:"properties,omitempty"`
}

type SARIFProperties struct {
	Tags     []string      `json:"tags,omitempty"`
	Security SARIFSecurity `json:"security-severity,omitempty"`
}

type SARIFSecurity = string

type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"` // error, warning, note, none
	Message             SARIFMessage      `json:"message"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Locations           []SARIFLocation   `json:"locations,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation  `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// GenerateSARIF produces a SARIF v2.1.0 JSON report from scan results.
func GenerateSARIF(result *models.ScanResult, checks []models.CheckResult) ([]byte, error) {
	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}

	// SARIF `results` are FINDINGS — only failing/warning checks. Emitting passing
	// checks as `note` results floods GitHub code-scanning / DefectDojo with
	// non-findings. Rules are built only for the findings actually emitted.
	relURI := sarifRelURI(result.ScanTarget.URL)
	ruleMap := map[string]bool{}
	rules := []SARIFRule{}
	results := []SARIFResult{}

	for _, ch := range checks {
		if !sarifIsFinding(ch.Status, ch.Score) {
			continue
		}
		ruleID := fmt.Sprintf("seku/%s/%s", ch.Category, sanitizeRuleID(ch.CheckName))
		if !ruleMap[ruleID] {
			ruleMap[ruleID] = true
			tags := []string{ch.Category}
			if ch.OWASP != "" {
				tags = append(tags, ch.OWASP)
			}
			if ch.CWE != "" {
				tags = append(tags, ch.CWE)
			}
			secSeverity := "5.0"
			switch strings.ToLower(ch.Severity) {
			case "critical":
				secSeverity = "9.5"
			case "high":
				secSeverity = "8.0"
			case "medium":
				secSeverity = "5.0"
			case "low":
				secSeverity = "3.0"
			case "info":
				secSeverity = "1.0"
			}
			rules = append(rules, SARIFRule{
				ID:               ruleID,
				Name:             ch.CheckName,
				ShortDescription: SARIFMessage{Text: ch.CheckName},
				HelpURI:          "https://sec.erticaz.com/methodology",
				Properties:       SARIFProperties{Tags: tags, Security: secSeverity},
			})
		}

		msg := ch.CheckName
		if ch.Details != "" {
			var details map[string]interface{}
			if json.Unmarshal([]byte(ch.Details), &details) == nil {
				if m, ok := details["message"].(string); ok && m != "" {
					msg = m
				}
			}
		}

		results = append(results, SARIFResult{
			RuleID:  ruleID,
			Level:   sarifLevel(ch.Severity), // level from SEVERITY, not status
			Message: SARIFMessage{Text: msg},
			// Stable dedup key so re-scans don't churn alerts.
			PartialFingerprints: map[string]string{
				"sekuFindingV1": sanitizeRuleID(ch.Category) + "-" + sanitizeRuleID(ch.CheckName),
			},
			Locations: []SARIFLocation{{
				// A web target has no repo file; use a relative synthetic path
				// (host+path) so ingestors anchor the alert, plus a logical location.
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: relURI},
				},
				LogicalLocations: []SARIFLogicalLocation{{
					Name: firstNonEmpty(categoryNames[ch.Category], ch.Category),
					Kind: "namespace",
				}},
			}},
		})
	}

	report.Runs = []SARIFRun{{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:           "Seku",
				Version:        "1.0.0",
				InformationURI: "https://sec.erticaz.com",
				Rules:          rules,
			},
		},
		Results: results,
	}}

	return json.MarshalIndent(report, "", "  ")
}

// sarifIsFinding reports whether a check is a failing/warning finding.
func sarifIsFinding(status string, score float64) bool {
	switch strings.ToLower(status) {
	case "fail", "warn", "warning":
		return true
	case "pass", "info", "error", "pending", "running":
		return false
	}
	return score < 900
}

// sarifLevel maps a finding severity to a SARIF level.
func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// sarifRelURI turns a target URL into a stable relative path so ingestors can
// anchor the result (an absolute https:// URI matches no repo file and GitHub
// silently drops such alerts).
func sarifRelURI(rawURL string) string {
	u := strings.TrimPrefix(rawURL, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimSuffix(u, "/")
	if u == "" {
		return "target"
	}
	return u
}

func sanitizeRuleID(name string) string {
	result := ""
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			result += string(c)
		} else {
			result += "-"
		}
	}
	return result
}
