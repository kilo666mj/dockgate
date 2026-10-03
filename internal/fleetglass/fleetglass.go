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

// BuildChecks returns three checks per active agent: check-in freshness,
// pending image updates, and container health.
func BuildChecks(ctx context.Context, st *store.Store, staleAfter time.Duration, now time.Time) ([]Check, error) {
	agents, err := st.Agents(ctx)
	if err != nil {
		return nil, err
	}
	observed := now.UTC().Format(time.RFC3339)
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
		out = append(out, updatesCheck(a, containers, observed), healthCheck(a, containers, observed))
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

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
