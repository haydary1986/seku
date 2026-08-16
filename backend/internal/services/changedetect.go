package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"seku/internal/config"
	"seku/internal/models"
)

// changeScoreDropThreshold is how many points the security score must fall for a
// re-scan to count as a regression worth alerting on (small dips are noise).
const changeScoreDropThreshold = 40

// findingKey identifies a finding across scans (a category+check that is failing
// or warning). Passing checks are not findings.
type findingRef struct {
	Category  string `json:"category"`
	CheckName string `json:"check_name"`
	Severity  string `json:"severity"`
}

// DetectAndAlertChanges compares each result in a completed job against the
// target's PREVIOUS completed scan, persists a ScanChange (the change history),
// and fires change alerts when new findings appear or the score regresses.
// First-ever scans (no baseline) are skipped silently.
func DetectAndAlertChanges(job *models.ScanJob, results []models.ScanResult) {
	for i := range results {
		r := results[i]
		var prev models.ScanResult
		err := config.DB.
			Where("scan_target_id = ? AND status = ? AND id < ?", r.ScanTargetID, "completed", r.ID).
			Order("id desc").First(&prev).Error
		if err != nil {
			continue // no baseline yet — this is the first scan of the target
		}

		change := computeChange(&prev, &r)
		if change == nil {
			continue
		}
		change.OrganizationID = job.OrganizationID
		config.DB.Create(change)

		if change.NewFindings > 0 || change.Regressed {
			dispatchChangeAlerts(job, &r, change)
		}
	}
}

// computeChange diffs the failing/warning findings and scores of two results.
// It loads each result's findings, then delegates to the pure diffFindings.
func computeChange(oldR, newR *models.ScanResult) *models.ScanChange {
	ch := diffFindings(failingSet(oldR.ID), failingSet(newR.ID), oldR.OverallScore, newR.OverallScore)
	if ch == nil {
		return nil
	}
	ch.ScanTargetID = newR.ScanTargetID
	ch.OldResultID = oldR.ID
	ch.NewResultID = newR.ID
	return ch
}

// diffFindings is the pure core (no I/O): given the old/new failing-finding sets
// and scores, it returns a ScanChange, or nil when nothing material changed.
func diffFindings(oldSet, newSet map[string]findingRef, oldScore, newScore float64) *models.ScanChange {
	var added, fixed []findingRef
	for k, f := range newSet {
		if _, ok := oldSet[k]; !ok {
			added = append(added, f)
		}
	}
	for k, f := range oldSet {
		if _, ok := newSet[k]; !ok {
			fixed = append(fixed, f)
		}
	}

	regressed := newScore <= oldScore-changeScoreDropThreshold

	// Nothing material changed → don't record noise.
	if len(added) == 0 && len(fixed) == 0 && !regressed {
		return nil
	}

	details, _ := json.Marshal(map[string]interface{}{"new": added, "fixed": fixed})
	return &models.ScanChange{
		OldScore:      oldScore,
		NewScore:      newScore,
		OldGrade:      scoreToGrade(oldScore),
		NewGrade:      scoreToGrade(newScore),
		NewFindings:   len(added),
		FixedFindings: len(fixed),
		Regressed:     regressed,
		Details:       string(details),
	}
}

// failingSet returns the failing/warning findings of a result keyed by identity.
func failingSet(resultID uint) map[string]findingRef {
	var checks []models.CheckResult
	config.DB.Where("scan_result_id = ?", resultID).Find(&checks)
	set := map[string]findingRef{}
	for _, c := range checks {
		if c.Status != "fail" && c.Status != "warn" {
			continue
		}
		key := c.Category + "::" + c.CheckName
		set[key] = findingRef{Category: c.Category, CheckName: c.CheckName, Severity: c.Severity}
	}
	return set
}

// dispatchChangeAlerts posts a concise change summary to every active webhook of
// the org that is subscribed to the "change_detected" event (or, for backward
// compatibility, to "scan_completed").
func dispatchChangeAlerts(job *models.ScanJob, r *models.ScanResult, ch *models.ScanChange) {
	var webhooks []models.Webhook
	config.DB.Where("organization_id = ? AND is_active = ?", job.OrganizationID, true).Find(&webhooks)

	target := r.ScanTarget.URL
	if target == "" {
		var t models.ScanTarget
		if config.DB.First(&t, r.ScanTargetID).Error == nil {
			target = t.URL
		}
	}
	msg := formatChangeMessage(target, ch)

	for _, wh := range webhooks {
		if !subscribed(wh.Events, "change_detected") && !subscribed(wh.Events, "scan_completed") {
			continue
		}
		go sendChangeWebhook(wh, msg, target, ch)
	}
}

func subscribed(events, want string) bool {
	for _, e := range strings.Split(events, ",") {
		if strings.TrimSpace(e) == want {
			return true
		}
	}
	return false
}

func formatChangeMessage(target string, ch *models.ScanChange) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🔔 Seku change detected on %s\n", target)
	if ch.Regressed {
		fmt.Fprintf(&b, "Score regressed: %.0f (%s) → %.0f (%s)\n", ch.OldScore, ch.OldGrade, ch.NewScore, ch.NewGrade)
	} else {
		fmt.Fprintf(&b, "Score: %.0f (%s) → %.0f (%s)\n", ch.OldScore, ch.OldGrade, ch.NewScore, ch.NewGrade)
	}
	fmt.Fprintf(&b, "New findings: %d · Fixed: %d", ch.NewFindings, ch.FixedFindings)

	// list up to 5 new findings for context
	var d struct {
		New []findingRef `json:"new"`
	}
	if json.Unmarshal([]byte(ch.Details), &d) == nil && len(d.New) > 0 {
		b.WriteString("\nNew:")
		for i, f := range d.New {
			if i >= 5 {
				fmt.Fprintf(&b, "\n…and %d more", len(d.New)-5)
				break
			}
			fmt.Fprintf(&b, "\n- [%s] %s (%s)", strings.ToUpper(f.Severity), f.CheckName, f.Category)
		}
	}
	return b.String()
}

// sendChangeWebhook delivers the change message using each provider's simplest
// text payload (reusing the SSRF-guarded postJSON transport).
func sendChangeWebhook(wh models.Webhook, msg, target string, ch *models.ScanChange) {
	switch wh.Type {
	case "slack":
		postJSON(wh.URL, map[string]interface{}{"text": msg}, nil)
	case "discord":
		postJSON(wh.URL, map[string]interface{}{"content": msg}, nil)
	case "telegram":
		apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", wh.Secret)
		postJSON(apiURL, map[string]interface{}{"chat_id": wh.URL, "text": msg}, nil)
	case "teams":
		postJSON(wh.URL, map[string]interface{}{
			"@type": "MessageCard", "@context": "http://schema.org/extensions",
			"themeColor": "E11D48", "summary": "Seku change detected",
			"title": "Seku: change detected on " + target, "text": msg,
		}, nil)
	case "custom":
		headers := map[string]string{}
		if wh.Secret != "" {
			headers["Authorization"] = "Bearer " + wh.Secret
		}
		postJSON(wh.URL, map[string]interface{}{
			"event":          "change_detected",
			"target":         target,
			"old_score":      ch.OldScore,
			"new_score":      ch.NewScore,
			"new_findings":   ch.NewFindings,
			"fixed_findings": ch.FixedFindings,
			"regressed":      ch.Regressed,
			"details":        json.RawMessage(ch.Details),
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		}, headers)
	}
}
