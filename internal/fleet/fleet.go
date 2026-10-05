// Package fleet summarises what the hosts report: one line per host and one
// per container. The MCP tools and the web UI show the same numbers from it.
package fleet

import (
	"context"
	"time"

	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/store"
)

// StaleAfter matches the Fleetglass check-in threshold for one-minute reports.
const StaleAfter = 5 * time.Minute

// LabelComposeWorkDir is where a compose project lives on the host, which
// tells an agent which checkout or deploy directory defines a container.
const LabelComposeWorkDir = "com.docker.compose.project.working_dir"

// Host summarises one Docker host.
type Host struct {
	Host             string `json:"host"`
	Reporting        string `json:"reporting" jsonschema:"ok, stale or never"`
	LastReportAgeSec int64  `json:"last_report_age_seconds,omitempty"`
	AgentVersion     string `json:"agent_version"`
	DockerVersion    string `json:"docker_version"`
	Containers       int    `json:"containers"`
	Running          int    `json:"running"`
	Unhealthy        int    `json:"unhealthy"`
	Restarting       int    `json:"restarting"`
	UpdatesAvailable int    `json:"updates_available"`
	FixableCritical  int    `json:"fixable_critical"`
	FixableHigh      int    `json:"fixable_high"`
	Scanned          int    `json:"scanned_containers"`
	ScanPending      int    `json:"scan_pending_containers"`
	ScanFailed       int    `json:"scan_failed_containers"`
	// LastReportAt is the agent's last report, for display; zero if never.
	LastReportAt time.Time `json:"-"`
}

// Container describes one container on a host.
type Container struct {
	Name            string                `json:"name"`
	Image           string                `json:"image"`
	ImageID         string                `json:"image_id"`
	State           string                `json:"state"`
	Status          string                `json:"status"`
	Health          string                `json:"health,omitempty"`
	RestartCount    int                   `json:"restart_count"`
	StartedAt       string                `json:"started_at,omitempty"`
	ComposeProject  string                `json:"compose_project,omitempty"`
	ComposeService  string                `json:"compose_service,omitempty"`
	ComposeWorkDir  string                `json:"compose_working_dir,omitempty"`
	Update          *protocol.UpdateCheck `json:"update,omitempty"`
	FixableCritical int                   `json:"fixable_critical"`
	FixableHigh     int                   `json:"fixable_high"`
	// Scan is the image's vulnerability scan state; fixable counts mean
	// nothing until it is "scanned".
	Scan string `json:"scan" jsonschema:"scanned, pending or failed"`
}

// Hosts summarises every active (not revoked) host, in name order.
func Hosts(ctx context.Context, st *store.Store, now time.Time) ([]Host, error) {
	agents, err := st.Agents(ctx)
	if err != nil {
		return nil, err
	}
	findings, err := st.ActiveFindings(ctx, "", now)
	if err != nil {
		return nil, err
	}
	coverage, err := st.Coverage(ctx)
	if err != nil {
		return nil, err
	}
	crit, high := fixableCounts(findings)
	out := []Host{}
	for _, a := range agents {
		if !a.RevokedAt.IsZero() {
			continue
		}
		hs := Host{Host: a.Name, AgentVersion: a.AgentVersion, DockerVersion: a.Docker.Version, Reporting: "never",
			FixableCritical: crit[a.Name], FixableHigh: high[a.Name], LastReportAt: a.LastReportAt}
		if !a.LastReportAt.IsZero() {
			hs.LastReportAgeSec = int64(now.Sub(a.LastReportAt).Seconds())
			hs.Reporting = "ok"
			if now.Sub(a.LastReportAt) > StaleAfter {
				hs.Reporting = "stale"
			}
		}
		containers, err := st.Containers(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		for _, c := range containers {
			hs.Containers++
			switch {
			case c.State == "running" && c.Health == "unhealthy":
				hs.Running++
				hs.Unhealthy++
			case c.State == "running":
				hs.Running++
			case c.State == "restarting":
				hs.Restarting++
			}
			if c.Update != nil && c.Update.Status == protocol.UpdateAvailable {
				hs.UpdatesAvailable++
			}
		}
		cov := coverage[a.Name]
		hs.Scanned, hs.ScanPending, hs.ScanFailed = cov.Scanned, cov.Pending, cov.Failed
		out = append(out, hs)
	}
	return out, nil
}

// Containers describes the containers an agent last reported.
func Containers(ctx context.Context, st *store.Store, a store.Agent, now time.Time) ([]Container, error) {
	containers, err := st.Containers(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	findings, err := st.ActiveFindings(ctx, a.Name, now)
	if err != nil {
		return nil, err
	}
	type counts struct{ crit, high int }
	per := map[string]counts{}
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.Container + "|" + f.VulnID + "|" + f.Pkg
		if !f.Fixable() || seen[key] {
			continue
		}
		seen[key] = true
		c := per[f.Container]
		switch f.Severity {
		case "CRITICAL":
			c.crit++
		case "HIGH":
			c.high++
		}
		per[f.Container] = c
	}
	scans, err := st.ContainerScanStates(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	out := []Container{}
	for _, c := range containers {
		ci := Container{
			Name: c.Name, Image: c.Image, ImageID: c.ImageID, State: c.State, Status: c.Status, Health: c.Health,
			RestartCount: c.RestartCount, ComposeProject: c.ComposeProject, ComposeService: c.ComposeService,
			ComposeWorkDir: c.Labels[LabelComposeWorkDir], Update: c.Update,
			FixableCritical: per[c.Name].crit, FixableHigh: per[c.Name].high, Scan: scans[c.ID],
		}
		if !c.StartedAt.IsZero() {
			ci.StartedAt = c.StartedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, ci)
	}
	return out, nil
}

// fixableCounts counts distinct fixable critical and high vulnerability and
// package pairs per host.
func fixableCounts(fs []store.HostFinding) (crit, high map[string]int) {
	crit, high = map[string]int{}, map[string]int{}
	seen := map[string]bool{}
	for _, f := range fs {
		if !f.Fixable() || (f.Severity != "CRITICAL" && f.Severity != "HIGH") {
			continue
		}
		key := f.Host + "|" + f.VulnID + "|" + f.Pkg
		if seen[key] {
			continue
		}
		seen[key] = true
		if f.Severity == "CRITICAL" {
			crit[f.Host]++
		} else {
			high[f.Host]++
		}
	}
	return crit, high
}
