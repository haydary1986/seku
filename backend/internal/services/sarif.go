package services

import (
	"encoding/json"
	"fmt"
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
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"` // error, warning, note, none
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
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

	// Build rules from unique check names
	ruleMap := map[string]SARIFRule{}
	for _, ch := range checks {
		ruleID := fmt.Sprintf("vscan/%s/%s", ch.Category, sanitizeRuleID(ch.CheckName))
		if _, exists := ruleMap[ruleID]; !exists {
			tags := []string{ch.Category}
			if ch.OWASP != "" {
				tags = append(tags, ch.OWASP)
			}
			if ch.CWE != "" {
				tags = append(tags, ch.CWE)
			}

			secSeverity := "5.0" // medium default
			switch ch.Severity {
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

			ruleMap[ruleID] = SARIFRule{
				ID:               ruleID,
				Name:             ch.CheckName,
				ShortDescription: SARIFMessage{Text: ch.CheckName},
				Properties:       SARIFProperties{Tags: tags, Security: secSeverity},
			}
		}
	}

	var rules []SARIFRule
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	// Build results
	var results []SARIFResult
	for _, ch := range checks {
		ruleID := fmt.Sprintf("vscan/%s/%s", ch.Category, sanitizeRuleID(ch.CheckName))

		level := "none"
		switch ch.Status {
		case "fail":
			level = "error"
		case "warn", "warning":
			level = "warning"
		case "pass":
			level = "note"
		case "info":
			level = "note"
		}

		// Parse details for message
		msg := ch.CheckName
		if ch.Details != "" {
			var details map[string]interface{}
			if json.Unmarshal([]byte(ch.Details), &details) == nil {
				if m, ok := details["message"].(string); ok {
					msg = m
				}
			}
		}

		sarifResult := SARIFResult{
			RuleID:  ruleID,
			Level:   level,
			Message: SARIFMessage{Text: msg},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: result.ScanTarget.URL,
					},
				},
				LogicalLocations: []SARIFLogicalLocation{{
					Name: ch.Category,
					Kind: "module",
				}},
			}},
		}
		results = append(results, sarifResult)
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
