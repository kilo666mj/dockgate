package vulns

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	tintwire "go.michaelspost.com/tintwire-go"

	"go.michaelspost.com/dockgate/internal/store"
)

// Publisher sends a notification card; *tintwire.Client satisfies it.
type Publisher interface {
	Publish(ctx context.Context, card tintwire.Card) (tintwire.Result, error)
}

// Alerter notifies once per repository, vulnerability and package when a
// fixable finding at an alerting severity first appears on a running image.
type Alerter struct {
	Store     *store.Store
	Publisher Publisher // nil disables alerts
	Channel   string
	Logger    *slog.Logger
	// Severities that alert, upper case, e.g. CRITICAL and HIGH.
	Severities []string
}

const baselineKey = "vuln_alert_baseline"

// maxRows bounds the findings listed on one card.
const maxRows = 12

// Check alerts on new findings. The first run records every current finding
// as a baseline and sends one summary, rather than one alert per finding the
// fleet already had.
func (a *Alerter) Check(ctx context.Context) {
	if a.Publisher == nil {
		return
	}
	if err := a.check(ctx); err != nil {
		a.Logger.Error("vulnerability alerts", "err", err)
	}
}

func (a *Alerter) check(ctx context.Context) error {
	now := time.Now()
	if err := a.Store.ClearSuppressedAlerts(ctx, now); err != nil {
		return err
	}
	findings, err := a.Store.ActiveFindings(ctx, "", now)
	if err != nil {
		return err
	}
	alerted, err := a.Store.Alerted(ctx)
	if err != nil {
		return err
	}
	baseline, err := a.Store.Setting(ctx, baselineKey)
	if err != nil {
		return err
	}

	byHost := map[string][]store.HostFinding{}
	var keys []store.AlertKey
	seen := map[store.AlertKey]bool{}
	for _, f := range findings {
		if !f.Fixable() || !a.alerting(f.Severity) {
			continue
		}
		k := store.AlertKey{Repository: store.Repository(f.Image), VulnID: f.VulnID, Pkg: f.Pkg}
		if alerted[k] {
			continue
		}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
		byHost[f.Host] = append(byHost[f.Host], f)
	}
	if len(keys) == 0 {
		if baseline == "" {
			return a.Store.SetSetting(ctx, baselineKey, now.UTC().Format(time.RFC3339))
		}
		return nil
	}

	if baseline == "" {
		card := tintwire.Card{
			Channel: a.Channel, Source: "dockgate", Severity: tintwire.SeverityInfo,
			Title:   "Vulnerability alerting baseline",
			Summary: fmt.Sprintf("%d fixable %s findings already present across %d hosts were recorded as the baseline. New ones will alert.", len(keys), strings.Join(a.Severities, "/"), len(byHost)),
			Metrics: []tintwire.Metric{{Label: "Findings", Value: len(keys)}, {Label: "Hosts", Value: len(byHost)}},
		}
		if _, err := a.Publisher.Publish(ctx, card); err != nil {
			return fmt.Errorf("publish baseline: %w", err)
		}
		a.Logger.Info("vulnerability alert baseline sent", "findings", len(keys), "hosts", len(byHost))
		if err := a.Store.MarkAlerted(ctx, keys, now); err != nil {
			return err
		}
		return a.Store.SetSetting(ctx, baselineKey, now.UTC().Format(time.RFC3339))
	}

	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		card := a.card(host, byHost[host])
		if _, err := a.Publisher.Publish(ctx, card); err != nil {
			return fmt.Errorf("publish alert for %s: %w", host, err)
		}
		a.Logger.Info("vulnerability alert sent", "host", host, "findings", len(byHost[host]))
		var hostKeys []store.AlertKey
		for _, f := range byHost[host] {
			hostKeys = append(hostKeys, store.AlertKey{Repository: store.Repository(f.Image), VulnID: f.VulnID, Pkg: f.Pkg})
		}
		if err := a.Store.MarkAlerted(ctx, hostKeys, now); err != nil {
			return err
		}
	}
	return nil
}

func (a *Alerter) alerting(severity string) bool {
	for _, s := range a.Severities {
		if s == severity {
			return true
		}
	}
	return false
}

func (a *Alerter) card(host string, fs []store.HostFinding) tintwire.Card {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity == "CRITICAL"
		}
		return fs[i].VulnID < fs[j].VulnID
	})
	sev := tintwire.SeverityWarning
	crit := 0
	containers := map[string]bool{}
	for _, f := range fs {
		if f.Severity == "CRITICAL" {
			crit++
			sev = tintwire.SeverityCritical
		}
		containers[f.Container] = true
	}
	card := tintwire.Card{
		Channel: a.Channel, Source: "dockgate", Severity: sev,
		Title:   fmt.Sprintf("New fixable vulnerabilities on %s", host),
		Summary: fmt.Sprintf("%d new fixable findings (%d critical) in %d containers. Updating the images should clear them.", len(fs), crit, len(containers)),
		Metrics: []tintwire.Metric{{Label: "Findings", Value: len(fs)}, {Label: "Critical", Value: crit}, {Label: "Containers", Value: len(containers)}},
	}
	for i, f := range fs {
		if i == maxRows {
			card.Rows = append(card.Rows, tintwire.Row{Primary: fmt.Sprintf("… and %d more", len(fs)-maxRows)})
			break
		}
		row := tintwire.Row{
			Primary: fmt.Sprintf("%s %s %s → %s (%s)", f.VulnID, f.Pkg, f.Installed, f.Fixed, f.Container),
			Tags:    []string{strings.ToLower(f.Severity)},
		}
		if f.Severity == "CRITICAL" {
			row.Emphasis = tintwire.EmphasisStrong
		}
		card.Rows = append(card.Rows, row)
	}
	return card
}
