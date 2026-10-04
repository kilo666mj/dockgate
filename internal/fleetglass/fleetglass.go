// Package fleetglass exports per-host summary checks to a Fleetglass
// instance's ingest API, so dockgate's findings appear alongside the rest of
// the fleet's monitoring.
package fleetglass

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/store"
)

// Source is the collector name the checks are filed under.
const Source = "dockgate"

// Check is one Fleetglass check record.
type Check struct {
	Source     string         `json:"source"`
	Host       string         `json:"host"`
	Kind       string         `json:"kind"`
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	Summary    string         `json:"summary"`
	ObservedAt string         `json:"observed_at"`
	Data       map[string]any `json:"data"`
}

// Exporter posts checks on a schedule.
type Exporter struct {
	URL    string
	Token  string
	Store  *store.Store
	Logger *slog.Logger
	// StaleAfter marks an agent's check-in bad when its last report is older.
	StaleAfter time.Duration
	Client     *http.Client
}

// Run exports every interval until ctx ends.
func (e *Exporter) Run(ctx context.Context, interval time.Duration) {
	for {
		if err := e.ExportOnce(ctx); err != nil && ctx.Err() == nil {
			e.Logger.Error("fleetglass export", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// ExportOnce builds and posts the current checks.
func (e *Exporter) ExportOnce(ctx context.Context) error {
	checks, err := BuildChecks(ctx, e.Store, e.StaleAfter, time.Now())
	if err != nil {
		return err
	}
	if len(checks) == 0 {
		return nil
	}
	body, err := json.Marshal(checks)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(e.URL, "/")+"/api/ingest/checks", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.Token != "" {
		req.Header.Set("Authorization", "Bearer "+e.Token)
	}
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("fleetglass: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	e.Logger.Debug("fleetglass export", "checks", len(checks))
	return nil
}

// BuildChecks returns four checks per active agent: check-in freshness,
// pending image updates, container health and fixable vulnerabilities.
func BuildChecks(ctx context.Context, st *store.Store, staleAfter time.Duration, now time.Time) ([]Check, error) {
	agents, err := st.Agents(ctx)
	if err != nil {
		return nil, err
	}
	observed := now.UTC().Format(time.RFC3339)
	findings, err := st.ActiveFindings(ctx, "", now)
	if err != nil {
		return nil, err
	}
	byHost := map[string][]store.HostFinding{}
	for _, f := range findings {
		byHost[f.Host] = append(byHost[f.Host], f)
	}
	coverage, err := st.Coverage(ctx)
	if err != nil {
		return nil, err
	}
	var out []Check
	for _, a := range agents {
		if !a.RevokedAt.IsZero() {
			continue
		}
		out = append(out, checkinCheck(a, staleAfter, now, observed))
		if a.LastReportAt.IsZero() {
			continue
		}
		containers, err := st.Containers(ctx, a.ID)
		if err != nil {
			return nil, fmt.Errorf("agent %s: %w", a.Name, err)
		}
		out = append(out, updatesCheck(a, containers, observed), healthCheck(a, containers, observed),
			vulnCheck(a, byHost[a.Name], coverage[a.Name], observed))
	}
	return out, nil
}

func checkinCheck(a store.Agent, staleAfter time.Duration, now time.Time, observed string) Check {
	c := Check{
		Source: Source, Host: a.Name, Kind: "agent_health", Name: "checkin", ObservedAt: observed,
		Data: map[string]any{
			"agent_id": a.ID, "agent_version": a.AgentVersion, "docker_version": a.Docker.Version,
			"cert_not_after": a.CertNotAfter.UTC().Format(time.RFC3339),
		},
	}
	switch {
	case a.LastReportAt.IsZero():
		c.Status, c.Summary = "warn", "enrolled but has not reported yet"
	case now.Sub(a.LastReportAt) > staleAfter:
		c.Status = "bad"
		c.Summary = fmt.Sprintf("no report for %s", now.Sub(a.LastReportAt).Round(time.Minute))
	case len(a.ReportErrors) > 0:
		c.Status = "warn"
		c.Summary = fmt.Sprintf("reporting with %d collection errors", len(a.ReportErrors))
		c.Data["errors"] = a.ReportErrors
	default:
		c.Status, c.Summary = "ok", "reporting"
	}
	if !a.LastReportAt.IsZero() {
		c.Data["last_report_at"] = a.LastReportAt.UTC().Format(time.RFC3339)
	}
	return c
}

func updatesCheck(a store.Agent, containers []protocol.Container, observed string) Check {
	type pending struct {
		Container    string `json:"container"`
		Image        string `json:"image"`
		RemoteDigest string `json:"remote_digest"`
	}
	var available []pending
	var unknown []string
	for _, c := range containers {
		if c.Update == nil {
			continue
		}
		switch c.Update.Status {
		case protocol.UpdateAvailable:
			available = append(available, pending{Container: c.Name, Image: c.Update.Reference, RemoteDigest: c.Update.RemoteDigest})
		case protocol.UpdateUnknown:
			unknown = append(unknown, c.Name)
		}
	}
	c := Check{
		Source: Source, Host: a.Name, Kind: "container_updates", Name: "pending_updates", ObservedAt: observed,
		Status: "ok", Summary: fmt.Sprintf("%d container updates pending", len(available)),
		Data: map[string]any{"update_count": len(available), "containers": nonNil(available), "unknown": nonNil(unknown)},
	}
	if len(available) > 0 {
		c.Status = "warn"
	}
	return c
}

func healthCheck(a store.Agent, containers []protocol.Container, observed string) Check {
	states := map[string]int{}
	var unhealthy, restarting []string
	for _, c := range containers {
		states[c.State]++
		switch {
		case c.Health == "unhealthy":
			unhealthy = append(unhealthy, c.Name)
		case c.State == "restarting":
			restarting = append(restarting, c.Name)
		}
	}
	c := Check{
		Source: Source, Host: a.Name, Kind: "container_health", Name: "containers", ObservedAt: observed,
		Status: "ok", Summary: fmt.Sprintf("%d containers, %d running", len(containers), states["running"]),
		Data: map[string]any{"states": states, "unhealthy": nonNil(unhealthy), "restarting": nonNil(restarting)},
	}
	if n := len(unhealthy) + len(restarting); n > 0 {
		c.Status = "bad"
		c.Summary = fmt.Sprintf("%d unhealthy or restarting containers", n)
	}
	return c
}

// maxListed bounds the findings included in a check's data.
const maxListed = 25

func vulnCheck(a store.Agent, fs []store.HostFinding, cov store.ScanCoverage, observed string) Check {
	type listed struct {
		Container string `json:"container"`
		Image     string `json:"image"`
		Vuln      string `json:"vuln"`
		Package   string `json:"package"`
		Installed string `json:"installed"`
		Fixed     string `json:"fixed"`
		Severity  string `json:"severity"`
	}
	// Count distinct vulnerability/package pairs per severity; the same CVE
	// in several containers sharing an image counts once.
	fixable := map[string]map[string]bool{}
	all := map[string]int{}
	var rows []listed
	for _, f := range fs {
		all[f.Severity]++
		if !f.Fixable() {
			continue
		}
		key := f.VulnID + "|" + f.Pkg
		if fixable[f.Severity] == nil {
			fixable[f.Severity] = map[string]bool{}
		}
		if fixable[f.Severity][key] {
			continue
		}
		fixable[f.Severity][key] = true
		if (f.Severity == "CRITICAL" || f.Severity == "HIGH") && len(rows) < maxListed {
			rows = append(rows, listed{f.Container, f.Image, f.VulnID, f.Pkg, f.Installed, f.Fixed, f.Severity})
		}
	}
	crit, high := len(fixable["CRITICAL"]), len(fixable["HIGH"])
	c := Check{
		Source: Source, Host: a.Name, Kind: "container_vulnerabilities", Name: "fixable", ObservedAt: observed,
		Status: "ok", Summary: fmt.Sprintf("%d critical, %d high fixable vulnerabilities", crit, high),
		Data: map[string]any{
			"fixable_critical": crit, "fixable_high": high,
			"fixable_medium": len(fixable["MEDIUM"]), "fixable_low": len(fixable["LOW"]),
			"findings_by_severity": all, "listed": nonNil(rows),
			"containers": cov.Containers, "scanned": cov.Scanned, "pending": cov.Pending, "failed": cov.Failed,
		},
	}
	// Fixable criticals warn rather than fail: almost every image has some,
	// and Fleetglass "bad" is kept for things that need attention now.
	if crit > 0 || high > 0 {
		c.Status = "warn"
	}
	// Zero findings mean nothing unless the images were scanned: with
	// scanning stalled or disabled, a host must not look clean.
	switch {
	case cov.Containers > 0 && cov.Scanned == 0:
		c.Status = "unknown"
		c.Summary = fmt.Sprintf("not scanned yet (0/%d containers)", cov.Containers)
	case cov.Scanned < cov.Containers:
		c.Status = "warn"
		c.Summary += fmt.Sprintf("; scanned %d/%d containers", cov.Scanned, cov.Containers)
		if cov.Failed > 0 {
			c.Summary += fmt.Sprintf(", %d could not be scanned", cov.Failed)
		}
	}
	return c
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
