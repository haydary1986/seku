package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"vscan-mohesr/internal/models"
	"vscan-mohesr/internal/scanner"
)

const version = "1.0.0"

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"

	bgRed    = "\033[41m"
	bgGreen  = "\033[42m"
	bgYellow = "\033[43m"
	bgBlue   = "\033[44m"
	bgCyan   = "\033[46m"
)

// ScanOutput holds results for one target
type ScanOutput struct {
	URL        string             `json:"url"`
	Score      float64            `json:"score"`
	Grade      string             `json:"grade"`
	Categories map[string]float64 `json:"categories"`
	Checks     []models.CheckResult `json:"checks"`
	Duration   string             `json:"duration"`
	ScannedAt  time.Time          `json:"scanned_at"`
}

func main() {
	urlFlag := flag.String("url", "", "URL to scan")
	urlsFlag := flag.String("urls", "", "Comma-separated URLs to scan")
	fileFlag := flag.String("file", "", "File with URLs (one per line)")
	outputFlag := flag.String("output", "table", "Output format: table, json, sarif")
	outFileFlag := flag.String("o", "", "Output file path (default: stdout)")
	severityFlag := flag.String("severity", "all", "Minimum severity: all, critical, high, medium, low")
	planFlag := flag.String("plan", "enterprise", "Scan plan: free, basic, pro, enterprise")
	silentFlag := flag.Bool("silent", false, "Silent mode - only output results")
	noColorFlag := flag.Bool("no-color", false, "Disable colored output")
	versionFlag := flag.Bool("version", false, "Show version")
	helpFlag := flag.Bool("help", false, "Show detailed help with examples")
	listScannersFlag := flag.Bool("list-scanners", false, "List all available scanners")

	flag.Usage = func() { printHelp(false) }
	flag.Parse()

	if *helpFlag {
		printHelp(true)
		os.Exit(0)
	}

	if *listScannersFlag {
		printScannerList()
		os.Exit(0)
	}

	// Support positional argument: vscan example.com
	if *urlFlag == "" && flag.NArg() > 0 {
		u := flag.Arg(0)
		urlFlag = &u
	}

	if *versionFlag {
		fmt.Printf("vscan v%s\n", version)
		os.Exit(0)
	}

	// Collect URLs
	targets := collectTargets(*urlFlag, *urlsFlag, *fileFlag)
	if len(targets) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	useColor := !*noColorFlag

	if !*silentFlag {
		printBanner(useColor)
		fmt.Printf("Scanning %d target(s) with %s plan...\n\n", len(targets), *planFlag)
	}

	// Create scan engine
	engine := scanner.NewEngineForPlan(*planFlag)

	var allOutputs []ScanOutput

	for i, target := range targets {
		if !*silentFlag {
			prefix := colorize(useColor, colorCyan, fmt.Sprintf("[%d/%d]", i+1, len(targets)))
			fmt.Printf("%s Scanning %s ...\n", prefix, target)
		}

		startTime := time.Now()

		// Run all scanners directly (no DB needed)
		var allChecks []models.CheckResult
		scanners := engine.GetScanners()
		for _, s := range scanners {
			checks := s.Scan(target)
			allChecks = append(allChecks, checks...)
		}

		// Populate OWASP/CWE mappings
		for j := range allChecks {
			if m := scanner.GetOWASPMapping(allChecks[j].CheckName); m != nil {
				allChecks[j].OWASP = m.OWASP
				allChecks[j].OWASPName = m.OWASPName
				allChecks[j].CWE = m.CWE
				allChecks[j].CWEName = m.CWEName
			}
			allChecks[j].Confidence = scanner.GetConfidence(allChecks[j].CheckName)
		}

		// Calculate scores
		var totalScore, totalWeight float64
		catScores := map[string]struct{ total, weight float64 }{}
		for _, ch := range allChecks {
			if ch.Weight > 0 {
				totalScore += ch.Score * ch.Weight
				totalWeight += ch.Weight
				cs := catScores[ch.Category]
				cs.total += ch.Score * ch.Weight
				cs.weight += ch.Weight
				catScores[ch.Category] = cs
			}
		}

		overallScore := 0.0
		if totalWeight > 0 {
			overallScore = math.Round(totalScore / totalWeight)
		}

		categories := map[string]float64{}
		for cat, cs := range catScores {
			if cs.weight > 0 {
				categories[cat] = math.Round(cs.total / cs.weight)
			}
		}

		duration := time.Since(startTime)

		output := ScanOutput{
			URL:        target,
			Score:      overallScore,
			Grade:      scoreToGrade(overallScore),
			Categories: categories,
			Checks:     allChecks,
			Duration:   duration.Round(time.Millisecond).String(),
			ScannedAt:  time.Now(),
		}
		allOutputs = append(allOutputs, output)

		if !*silentFlag && *outputFlag == "table" {
			printResult(output, duration, useColor, *severityFlag)
		}
	}

	// Final output
	switch *outputFlag {
	case "json":
		data, err := json.MarshalIndent(allOutputs, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}
		writeOutput(*outFileFlag, data)
	case "sarif":
		sarifData := generateSARIF(allOutputs)
		data, err := json.MarshalIndent(sarifData, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling SARIF: %v\n", err)
			os.Exit(1)
		}
		writeOutput(*outFileFlag, data)
	case "table":
		if len(targets) > 1 && !*silentFlag {
			printSummary(allOutputs, useColor)
		}
	}
}

// collectTargets gathers scan targets from the three input sources.
func collectTargets(url, urls, file string) []string {
	var targets []string

	if url != "" {
		targets = append(targets, url)
	}
	if urls != "" {
		for _, u := range strings.Split(urls, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				targets = append(targets, u)
			}
		}
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}

	return targets
}

// colorize wraps text with ANSI color if enabled.
func colorize(enabled bool, color, text string) string {
	if !enabled {
		return text
	}
	return color + text + colorReset
}

// printBanner prints the ASCII art banner.
func printBanner(useColor bool) {
	banner := `
 ███████╗███████╗██╗  ██╗██╗   ██╗
 ██╔════╝██╔════╝██║ ██╔╝██║   ██║
 ███████╗█████╗  █████╔╝ ██║   ██║
 ╚════██║██╔══╝  ██╔═██╗ ██║   ██║
 ███████║███████╗██║  ██╗╚██████╔╝
 ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝
`
	fmt.Print(colorize(useColor, colorCyan, banner))
	fmt.Println(colorize(useColor, colorDim, "  Seku — Web Security Scanner v"+version))
	fmt.Println(colorize(useColor, colorDim, "  32 Security Categories | OWASP Top 10 Mapped"))
	fmt.Println()
}

// scoreToGrade converts a 0-1000 score to a letter grade.
func scoreToGrade(score float64) string {
	switch {
	case score >= 950:
		return "A+"
	case score >= 900:
		return "A"
	case score >= 850:
		return "A-"
	case score >= 800:
		return "B+"
	case score >= 750:
		return "B"
	case score >= 700:
		return "B-"
	case score >= 650:
		return "C+"
	case score >= 600:
		return "C"
	case score >= 550:
		return "C-"
	case score >= 500:
		return "D+"
	case score >= 450:
		return "D"
	case score >= 400:
		return "D-"
	default:
		return "F"
	}
}

// gradeColor returns the ANSI color for a letter grade.
func gradeColor(grade string) string {
	switch {
	case strings.HasPrefix(grade, "A"):
		return colorGreen
	case strings.HasPrefix(grade, "B"):
		return colorCyan
	case strings.HasPrefix(grade, "C"):
		return colorYellow
	case strings.HasPrefix(grade, "D"):
		return colorRed
	default:
		return colorRed
	}
}

// scoreColor returns the ANSI color for a numeric score.
func scoreColor(score float64) string {
	switch {
	case score >= 800:
		return colorGreen
	case score >= 600:
		return colorCyan
	case score >= 400:
		return colorYellow
	default:
		return colorRed
	}
}

// severityColor returns the ANSI color for a severity level.
func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return colorRed + colorBold
	case "high":
		return colorRed
	case "medium":
		return colorYellow
	case "low":
		return colorCyan
	default:
		return colorGreen
	}
}

// severityRank returns a numeric rank for filtering (lower = more severe).
func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}

// minSeverityRank returns the rank threshold for the severity filter.
func minSeverityRank(filter string) int {
	switch strings.ToLower(filter) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default: // "all"
		return 5
	}
}

// scoreBar generates a colored progress bar for a score.
func scoreBar(score float64, width int, useColor bool) string {
	filled := int(math.Round(score / 1000.0 * float64(width)))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return colorize(useColor, scoreColor(score), bar)
}

// printResult prints the scan result for one target in table format.
func printResult(output ScanOutput, duration time.Duration, useColor bool, severityFilter string) {
	fmt.Println()
	fmt.Println(colorize(useColor, colorBold, "═══════════════════════════════════════════════════════════════"))
	fmt.Printf("  %s  %s\n",
		colorize(useColor, colorBold, "Target:"),
		colorize(useColor, colorWhite+colorBold, output.URL))
	fmt.Printf("  %s  %s   %s  %s   %s  %s\n",
		colorize(useColor, colorBold, "Score:"),
		colorize(useColor, scoreColor(output.Score)+colorBold, fmt.Sprintf("%.0f/1000", output.Score)),
		colorize(useColor, colorBold, "Grade:"),
		colorize(useColor, gradeColor(output.Grade)+colorBold, output.Grade),
		colorize(useColor, colorBold, "Time:"),
		colorize(useColor, colorDim, duration.Round(time.Millisecond).String()))
	fmt.Println(colorize(useColor, colorBold, "═══════════════════════════════════════════════════════════════"))

	// Category scores
	fmt.Println()
	fmt.Println(colorize(useColor, colorBold+colorCyan, "  Category Scores:"))
	fmt.Println(colorize(useColor, colorDim, "  ─────────────────────────────────────────────────────────"))

	type catEntry struct {
		name  string
		score float64
	}

	var cats []catEntry
	for cat, score := range output.Categories {
		cats = append(cats, catEntry{name: cat, score: score})
	}
	sort.Slice(cats, func(i, j int) bool {
		return cats[i].score < cats[j].score // worst first
	})

	for _, c := range cats {
		name := fmt.Sprintf("%-25s", c.name)
		bar := scoreBar(c.score, 20, useColor)
		scoreStr := colorize(useColor, scoreColor(c.score), fmt.Sprintf("%4.0f", c.score))
		fmt.Printf("  %s %s %s\n", name, bar, scoreStr)
	}

	// Failed / warning checks
	fmt.Println()
	fmt.Println(colorize(useColor, colorBold+colorCyan, "  Check Results:"))
	fmt.Println(colorize(useColor, colorDim, "  ─────────────────────────────────────────────────────────"))

	minRank := minSeverityRank(severityFilter)

	// Group checks by category
	type checkGroup struct {
		category string
		checks   []models.CheckResult
	}
	groupMap := map[string]*checkGroup{}
	var groupOrder []string

	for _, ch := range output.Checks {
		if severityRank(ch.Severity) > minRank {
			continue
		}
		g, exists := groupMap[ch.Category]
		if !exists {
			g = &checkGroup{category: ch.Category}
			groupMap[ch.Category] = g
			groupOrder = append(groupOrder, ch.Category)
		}
		g.checks = append(g.checks, ch)
	}

	sort.Strings(groupOrder)

	for _, catName := range groupOrder {
		g := groupMap[catName]
		fmt.Printf("\n  %s\n", colorize(useColor, colorBold, "  ["+g.category+"]"))

		for _, ch := range g.checks {
			statusIcon := "  ✓"
			statusColor := colorGreen
			if ch.Status == "fail" {
				statusIcon = "  ✗"
				statusColor = colorRed
			} else if ch.Status == "warn" {
				statusIcon = "  !"
				statusColor = colorYellow
			}

			sevStr := fmt.Sprintf("[%-8s]", ch.Severity)
			sevCol := severityColor(ch.Severity)

			fmt.Printf("    %s %-30s %s %s\n",
				colorize(useColor, statusColor, statusIcon),
				ch.CheckName,
				colorize(useColor, sevCol, sevStr),
				colorize(useColor, scoreColor(ch.Score), fmt.Sprintf("%4.0f", ch.Score)))

			if ch.Status == "fail" || ch.Status == "warn" {
				// Print details for failed/warning checks (truncated)
				detail := ch.Details
				if len(detail) > 120 {
					detail = detail[:117] + "..."
				}
				if detail != "" {
					fmt.Printf("      %s\n", colorize(useColor, colorDim, detail))
				}
				if ch.OWASP != "" {
					fmt.Printf("      %s %s\n",
						colorize(useColor, colorYellow, ch.OWASP),
						colorize(useColor, colorDim, ch.OWASPName))
				}
			}
		}
	}

	// Summary counts
	var passed, warned, failed int
	for _, ch := range output.Checks {
		switch ch.Status {
		case "pass":
			passed++
		case "warn":
			warned++
		case "fail":
			failed++
		}
	}

	fmt.Println()
	fmt.Println(colorize(useColor, colorDim, "  ─────────────────────────────────────────────────────────"))
	fmt.Printf("  %s %s   %s %s   %s %s   %s %d\n",
		colorize(useColor, colorGreen, "✓ Passed:"), colorize(useColor, colorGreen, fmt.Sprintf("%d", passed)),
		colorize(useColor, colorYellow, "! Warnings:"), colorize(useColor, colorYellow, fmt.Sprintf("%d", warned)),
		colorize(useColor, colorRed, "✗ Failed:"), colorize(useColor, colorRed, fmt.Sprintf("%d", failed)),
		colorize(useColor, colorDim, "Total:"), len(output.Checks))
	fmt.Println()
}

// printSummary prints a summary table for multi-target scans.
func printSummary(outputs []ScanOutput, useColor bool) {
	fmt.Println()
	fmt.Println(colorize(useColor, colorBold+colorCyan, "╔═══════════════════════════════════════════════════════════════╗"))
	fmt.Println(colorize(useColor, colorBold+colorCyan, "║                     SCAN SUMMARY                              ║"))
	fmt.Println(colorize(useColor, colorBold+colorCyan, "╚═══════════════════════════════════════════════════════════════╝"))
	fmt.Println()

	// Header
	fmt.Printf("  %-40s %8s %6s %8s %8s %8s\n",
		colorize(useColor, colorBold, "URL"),
		colorize(useColor, colorBold, "Score"),
		colorize(useColor, colorBold, "Grade"),
		colorize(useColor, colorBold, "Passed"),
		colorize(useColor, colorBold, "Failed"),
		colorize(useColor, colorBold, "Time"))
	fmt.Println(colorize(useColor, colorDim, "  "+strings.Repeat("─", 80)))

	var totalScore float64
	for _, o := range outputs {
		var passed, failed int
		for _, ch := range o.Checks {
			if ch.Status == "pass" {
				passed++
			} else if ch.Status == "fail" {
				failed++
			}
		}

		urlDisplay := o.URL
		if len(urlDisplay) > 38 {
			urlDisplay = urlDisplay[:35] + "..."
		}

		fmt.Printf("  %-40s %s %s %8d %8d %8s\n",
			urlDisplay,
			colorize(useColor, scoreColor(o.Score), fmt.Sprintf("%8.0f", o.Score)),
			colorize(useColor, gradeColor(o.Grade)+colorBold, fmt.Sprintf("%6s", o.Grade)),
			passed,
			failed,
			o.Duration)

		totalScore += o.Score
	}

	avg := totalScore / float64(len(outputs))
	fmt.Println(colorize(useColor, colorDim, "  "+strings.Repeat("─", 80)))
	fmt.Printf("  %-40s %s %s\n",
		colorize(useColor, colorBold, fmt.Sprintf("Average (%d sites)", len(outputs))),
		colorize(useColor, scoreColor(avg)+colorBold, fmt.Sprintf("%8.0f", avg)),
		colorize(useColor, gradeColor(scoreToGrade(avg))+colorBold, fmt.Sprintf("%6s", scoreToGrade(avg))))
	fmt.Println()
}

// writeOutput writes data to a file or stdout.
func writeOutput(path string, data []byte) {
	if path == "" {
		fmt.Println(string(data))
		return
	}
	err := os.WriteFile(path, data, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file %s: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Results written to %s\n", path)
}

// --- SARIF output ---

// SARIFReport represents a minimal SARIF 2.1.0 report.
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
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription SARIFMessage   `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type SARIFResult struct {
	RuleID  string          `json:"ruleId"`
	Level   string          `json:"level"`
	Message SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
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

func generateSARIF(outputs []ScanOutput) SARIFReport {
	var allResults []SARIFResult
	rulesMap := map[string]SARIFRule{}

	for _, o := range outputs {
		for _, ch := range o.Checks {
			if ch.Status == "pass" {
				continue
			}

			ruleID := strings.ReplaceAll(ch.CheckName, " ", "-")
			ruleID = strings.ToLower(ruleID)

			if _, exists := rulesMap[ruleID]; !exists {
				rule := SARIFRule{
					ID:               ruleID,
					Name:             ch.CheckName,
					ShortDescription: SARIFMessage{Text: ch.CheckName + " (" + ch.Category + ")"},
				}
				if ch.CWE != "" {
					rule.Properties = map[string]any{
						"cwe": ch.CWE,
					}
				}
				rulesMap[ruleID] = rule
			}

			level := "note"
			switch strings.ToLower(ch.Severity) {
			case "critical", "high":
				level = "error"
			case "medium":
				level = "warning"
			}

			result := SARIFResult{
				RuleID:  ruleID,
				Level:   level,
				Message: SARIFMessage{Text: ch.Details},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: &SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{URI: o.URL},
						},
						LogicalLocations: []SARIFLogicalLocation{
							{Name: ch.Category, Kind: "module"},
						},
					},
				},
				Properties: map[string]any{
					"score":      ch.Score,
					"severity":   ch.Severity,
					"owasp":      ch.OWASP,
					"owasp_name": ch.OWASPName,
					"cwe":        ch.CWE,
					"confidence": ch.Confidence,
				},
			}
			allResults = append(allResults, result)
		}
	}

	var rules []SARIFRule
	for _, r := range rulesMap {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	return SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:    "seku",
						Version: version,
						Rules:   rules,
					},
				},
				Results: allResults,
			},
		},
	}
}

// printHelp prints usage information. If detailed is true, includes examples and scanner info.
func printHelp(detailed bool) {
	fmt.Fprintf(os.Stderr, `
%s%s╔═══════════════════════════════════════════════════════════╗
║              Seku CLI v%s                                ║
║         Web Security Scanner — 32 Categories              ║
║         https://github.com/haydary1986/vscan-mohesr       ║
╚═══════════════════════════════════════════════════════════╝%s

%sUSAGE:%s
  vscan [flags] [url]
  vscan example.com
  vscan -url https://example.com
  vscan -urls "site1.com,site2.com"
  vscan -file urls.txt -output json -o results.json

%sFLAGS:%s
  -url string         URL to scan
  -urls string        Comma-separated URLs to scan
  -file string        File with URLs to scan (one per line)
  -output string      Output format: table, json, sarif (default: table)
  -o string           Output file path (default: stdout)
  -severity string    Minimum severity: all, critical, high, medium, low (default: all)
  -plan string        Scan plan: free, basic, pro, enterprise (default: enterprise)
  -silent             Silent mode — only output results, no banner
  -no-color           Disable colored output
  -list-scanners      List all available security scanners
  -version            Show version number
  -help               Show this detailed help
`, colorBold, colorCyan, version, colorReset,
		colorBold+colorYellow, colorReset,
		colorBold+colorYellow, colorReset)

	if !detailed {
		fmt.Fprintln(os.Stderr)
		return
	}

	fmt.Fprintf(os.Stderr, `
%sEXAMPLES:%s

  %s# Quick scan with table output%s
  vscan example.com

  %s# Scan multiple sites%s
  vscan -urls "university.edu,college.edu,school.edu"

  %s# Scan from a file with one URL per line%s
  vscan -file urls.txt

  %s# JSON output saved to file%s
  vscan example.com -output json -o results.json

  %s# SARIF output for GitHub Security%s
  vscan example.com -output sarif -o results.sarif

  %s# Show only critical and high severity findings%s
  vscan example.com -severity high

  %s# Light scan (8 categories, faster)%s
  vscan example.com -plan free

  %s# Full deep scan (32 categories)%s
  vscan example.com -plan enterprise

  %s# Silent mode for CI/CD pipelines%s
  vscan example.com -output json -silent

  %s# Pipe-friendly: no colors%s
  vscan example.com -no-color > report.txt

%sSCAN PLANS:%s

  %-12s  %s5 categories%s   — SSL, Headers, Cookies, Performance, Mixed Content
  %-12s  %s13 categories%s  — + Server Info, Directory, DDoS, CORS, DNS, Secrets, SEO
  %-12s  %s22 categories%s  — + Info Disclosure, Hosting, Content, WordPress, XSS, JS Libs
  %-12s  %s32 categories%s  — + Advanced Security, Malware, Threat Intel, SQLi, Ports, and more

%sGRADING SCALE:%s

  %s%s A+ %s  900–1000   Excellent security posture
  %s%s A  %s  800–899    Strong security
  %s%s B  %s  700–799    Good with minor issues
  %s%s C  %s  600–699    Average — needs improvement
  %s%s D  %s  500–599    Below average — significant gaps
  %s%s F  %s  0–499      Failing — critical issues found

%sOUTPUT FORMATS:%s

  table   Human-readable colored table (default)
  json    JSON array of scan results
  sarif   SARIF v2.1.0 for GitHub Advanced Security / VS Code

%sDOCUMENTATION:%s
  Full docs:   https://github.com/haydary1986/vscan-mohesr/blob/main/docs/SCANNERS.md
  Arabic docs: https://github.com/haydary1986/vscan-mohesr/blob/main/docs/SCANNERS-AR.md
  Web app:     https://sec.erticaz.com

`,
		colorBold+colorYellow, colorReset,
		colorDim, colorReset,
		colorDim, colorReset,
		colorDim, colorReset,
		colorDim, colorReset,
		colorDim, colorReset,
		colorDim, colorReset,
		colorDim, colorReset,
		colorDim, colorReset,
		colorDim, colorReset,
		colorDim, colorReset,
		colorBold+colorYellow, colorReset,
		colorGreen+"free"+colorReset, colorDim, colorReset,
		colorCyan+"basic"+colorReset, colorDim, colorReset,
		colorBlue+"pro"+colorReset, colorDim, colorReset,
		colorYellow+"enterprise"+colorReset, colorDim, colorReset,
		colorBold+colorYellow, colorReset,
		bgGreen+colorBold, " ", colorReset,
		bgGreen, " ", colorReset,
		bgCyan, " ", colorReset,
		bgYellow, " ", colorReset,
		bgRed, " ", colorReset,
		bgRed+colorBold, " ", colorReset,
		colorBold+colorYellow, colorReset,
		colorBold+colorYellow, colorReset,
	)
}

// printScannerList lists all available scanners with their details.
func printScannerList() {
	fmt.Printf("\n%s%s Seku — 32 Security Scanners%s\n\n", colorBold, colorCyan, colorReset)

	type scannerInfo struct {
		category string
		name     string
		weight   float64
		checks   int
		plans    string
	}

	scanners := []scannerInfo{
		{"ssl", "SSL/TLS", 20.0, 4, "free basic pro enterprise"},
		{"headers", "Security Headers", 20.0, 7, "free basic pro enterprise"},
		{"cookies", "Cookie Security", 10.0, 1, "free basic pro enterprise"},
		{"server_info", "Server Information", 15.0, 3, "basic pro enterprise"},
		{"directory", "Directory & Files", 10.0, 9, "basic pro enterprise"},
		{"performance", "Performance", 15.0, 3, "free basic pro enterprise"},
		{"ddos", "DDoS Protection", 10.0, 3, "basic pro enterprise"},
		{"cors", "CORS Configuration", 10.0, 2, "basic pro enterprise"},
		{"http_methods", "HTTP Methods", 8.0, 2, "basic pro enterprise"},
		{"dns", "DNS Security", 8.0, 3, "basic pro enterprise"},
		{"mixed_content", "Mixed Content", 7.0, 3, "free basic pro enterprise"},
		{"info_disclosure", "Information Disclosure", 7.0, 3, "pro enterprise"},
		{"hosting", "Hosting Quality", 12.0, 6, "pro enterprise"},
		{"content", "Content Optimization", 8.0, 3, "pro enterprise"},
		{"advanced_security", "Advanced Security", 5.0, 4, "enterprise"},
		{"malware", "Malware & Threats", 10.0, 6, "enterprise"},
		{"threat_intel", "Threat Intelligence", 8.0, 4, "enterprise"},
		{"seo", "SEO & Technical Health", 7.0, 6, "basic pro enterprise"},
		{"third_party", "Third-Party Scripts", 6.0, 4, "pro enterprise"},
		{"js_libraries", "JS Library Vulnerabilities", 6.0, 3, "pro enterprise"},
		{"wordpress", "WordPress Security", 8.0, 6, "pro enterprise"},
		{"xss", "XSS Vulnerabilities", 9.0, 5, "pro enterprise"},
		{"secrets", "Secrets Detection", 8.0, 4, "basic pro enterprise"},
		{"subdomains", "Subdomain Discovery", 5.0, 3, "pro enterprise"},
		{"tech_stack", "Technology Detection", 4.0, 3, "pro enterprise"},
		{"sqli", "SQL Injection", 15.0, 3, "pro enterprise"},
		{"ports", "Port Scanner", 8.0, 1, "pro enterprise"},
		{"open_redirect", "Open Redirect", 7.0, 1, "pro enterprise"},
		{"ssrf", "SSRF Detection", 8.0, 1, "pro enterprise"},
		{"email_security", "Email Security", 8.0, 3, "pro enterprise"},
		{"waf", "WAF Detection", 5.0, 1, "pro enterprise"},
		{"zone_transfer", "DNS Zone Transfer", 6.0, 1, "enterprise"},
	}

	fmt.Printf("  %s%-3s %-16s %-28s %6s %6s  %-30s%s\n",
		colorBold, "#", "CATEGORY", "NAME", "WEIGHT", "CHECKS", "AVAILABLE IN", colorReset)
	fmt.Printf("  %s%s%s\n", colorDim, strings.Repeat("─", 95), colorReset)

	totalChecks := 0
	for i, s := range scanners {
		totalChecks += s.checks

		planBadges := ""
		if strings.Contains(s.plans, "free") {
			planBadges += colorGreen + "free " + colorReset
		}
		if strings.Contains(s.plans, "basic") {
			planBadges += colorCyan + "basic " + colorReset
		}
		if strings.Contains(s.plans, "pro") {
			planBadges += colorBlue + "pro " + colorReset
		}
		if strings.Contains(s.plans, "enterprise") {
			planBadges += colorYellow + "enterprise" + colorReset
		}

		fmt.Printf("  %-3d %-16s %-28s %6.1f %6d  %s\n",
			i+1, s.category, s.name, s.weight, s.checks, planBadges)
	}

	fmt.Printf("  %s%s%s\n", colorDim, strings.Repeat("─", 95), colorReset)
	fmt.Printf("  %s%d scanners, %d total checks%s\n\n", colorBold, len(scanners), totalChecks, colorReset)
}
