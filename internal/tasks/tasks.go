// Package tasks files Taskboard work for actionable container updates and
// keeps it current. dockgate is the producer: it creates one task per host
// and container, refreshes or cancels it while nobody has claimed it, and
// leaves claimed work entirely to the agent that took it.
package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"go.michaelspost.com/dockgate/internal/store"
)

// Task is the part of a Taskboard task dockgate reads.
type Task struct {
	ID      string
	Version int64
	Status  string
	Owner   string
}

// CreateRequest is a new agent-lane task.
type CreateRequest struct {
	Title          string
	Summary        string
	Project        string
	Priority       string
	Checklist      []string
	Requirements   []string
	IdempotencyKey string
}

// API is the Taskboard surface dockgate uses.
type API interface {
	Create(ctx context.Context, r CreateRequest) (Task, error)
	Get(ctx context.Context, id string) (Task, error)
	// Refresh updates summary and priority of an unclaimed task.
	Refresh(ctx context.Context, id string, version int64, summary, priority string) (Task, error)
	// Cancel cancels an unclaimed task with a note.
	Cancel(ctx context.Context, id string, version int64, note string) (Task, error)
}

// Taskboard statuses dockgate cares about.
const (
	statusQueued    = "queued"
	statusDone      = "done"
	statusCancelled = "cancelled"
)

// Syncer files and maintains update tasks.
type Syncer struct {
	Store  *store.Store
	API    API
	Logger *slog.Logger
	// MaxOpen caps tasks dockgate has filed and not yet seen close.
	MaxOpen int
	// Requirements route the tasks, e.g. runner:local.
	Requirements []string
	Project      string
	// OwnImagePrefixes mark images built from the operator's own
	// repositories: their fix is a pull request, not a pull and recreate.
	OwnImagePrefixes []string
	now              func() time.Time
}

// Run syncs every interval until ctx ends.
func (s *Syncer) Run(ctx context.Context, interval time.Duration) {
	for {
		if err := s.Sync(ctx); err != nil && ctx.Err() == nil {
			s.Logger.Error("taskboard sync", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (s *Syncer) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func key(host, container string) string { return host + "|" + container }

// Sync reconciles filed tasks with the current actionable updates.
func (s *Syncer) Sync(ctx context.Context) error {
	now := s.clock()
	impacts, err := s.Store.UpdateImpacts(ctx, "", now)
	if err != nil {
		return err
	}
	actionable := map[string]store.UpdateImpact{}
	// Exited one-shot/init containers are inventory, not running services to
	// recreate automatically. Findings remain visible in the vulnerability UI.
	stopped := map[string]bool{}
	agents, err := s.Store.Agents(ctx)
	if err != nil {
		return err
	}
	for _, agent := range agents {
		containers, err := s.Store.Containers(ctx, agent.ID)
		if err != nil {
			return err
		}
		for _, container := range containers {
			if container.State == "exited" || container.State == "dead" || container.State == "created" {
				stopped[key(agent.Name, container.Name)] = true
			}
		}
	}
	for _, u := range impacts {
		if u.Actionable && store.UpdateExempt(u.Container) == "" && !stopped[key(u.Host, u.Container)] {
			actionable[key(u.Host, u.Container)] = u
		}
	}

	open, err := s.Store.OpenUpdateTasks(ctx)
	if err != nil {
		return err
	}
	tracked := map[string]bool{}
	stillOpen := 0
	for _, rec := range open {
		k := key(rec.Host, rec.Container)
		tracked[k] = true
		closed, err := s.maintain(ctx, rec, actionable[k], actionable[k].Host != "", now)
		if err != nil {
			s.Logger.Error("maintain task", "task_id", rec.TaskID, "host", rec.Host, "container", rec.Container, "err", err)
			stillOpen++
			continue
		}
		if !closed {
			stillOpen++
		}
	}

	var candidates []store.UpdateImpact
	for k, u := range actionable {
		if tracked[k] {
			continue
		}
		last, err := s.Store.LastUpdateTask(ctx, u.Host, u.Container)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return err
		case last.ClosedReason == "closed in Taskboard: cancelled":
			// A moving latest tag is not permission to undo a dismissal.
			// Reopening the original task explicitly resumes this container.
			task, err := s.API.Get(ctx, last.TaskID)
			if err != nil {
				return err
			}
			if task.Status != statusCancelled && task.Status != statusDone {
				if err := s.Store.ReopenUpdateTask(ctx, last.TaskID, now); err != nil {
					return err
				}
				stillOpen++
			}
			continue
		case last.RemoteDigest == u.RemoteDigest:
			// Already filed for this candidate and closed by a person or
			// worker; only a newer image warrants a new task.
			continue
		}
		candidates = append(candidates, u)
	}
	sort.Slice(candidates, func(i, j int) bool {
		ci, cj := critical(candidates[i].Fixes), critical(candidates[j].Fixes)
		if ci != cj {
			return ci > cj
		}
		if len(candidates[i].Fixes) != len(candidates[j].Fixes) {
			return len(candidates[i].Fixes) > len(candidates[j].Fixes)
		}
		return key(candidates[i].Host, candidates[i].Container) < key(candidates[j].Host, candidates[j].Container)
	})
	for _, u := range candidates {
		if stillOpen >= s.MaxOpen {
			break
		}
		summary := s.summary(u)
		t, err := s.API.Create(ctx, CreateRequest{
			Title:          fmt.Sprintf("Update %s on %s", u.Container, u.Host),
			Summary:        summary,
			Project:        s.Project,
			Priority:       priority(u),
			Checklist:      checklist,
			Requirements:   s.Requirements,
			IdempotencyKey: "dockgate-update-" + shortHash(u.Host, u.Container, u.RemoteDigest),
		})
		if err != nil {
			return fmt.Errorf("create task for %s on %s: %w", u.Container, u.Host, err)
		}
		if err := s.Store.RecordUpdateTask(ctx, store.UpdateTask{
			Host: u.Host, Container: u.Container, TaskID: t.ID, RemoteDigest: u.RemoteDigest, SummaryHash: shortHash(summary),
		}, now); err != nil {
			return err
		}
		s.Logger.Info("update task filed", "task_id", t.ID, "host", u.Host, "container", u.Container,
			"fixes", len(u.Fixes), "critical", critical(u.Fixes))
		stillOpen++
	}
	return nil
}

// maintain reconciles one filed task. It reports whether the task is closed.
func (s *Syncer) maintain(ctx context.Context, rec store.UpdateTask, u store.UpdateImpact, isActionable bool, now time.Time) (bool, error) {
	t, err := s.API.Get(ctx, rec.TaskID)
	if err != nil {
		return false, err
	}
	switch {
	case t.Status == statusDone || t.Status == statusCancelled:
		return true, s.Store.CloseUpdateTask(ctx, rec.TaskID, "closed in Taskboard: "+t.Status, now)
	case t.Status != statusQueued || t.Owner != "":
		// Claimed or in progress: the worker owns it now.
		return false, nil
	case !isActionable:
		note := "Resolved: the update is no longer needed or no longer clears findings (applied, superseded, or container removed)."
		if _, err := s.API.Cancel(ctx, rec.TaskID, t.Version, note); err != nil {
			return false, err
		}
		s.Logger.Info("update task cancelled", "task_id", rec.TaskID, "host", rec.Host, "container", rec.Container)
		return true, s.Store.CloseUpdateTask(ctx, rec.TaskID, "cancelled by dockgate: resolved", now)
	default:
		summary := s.summary(u)
		if shortHash(summary) == rec.SummaryHash {
			return false, nil
		}
		if _, err := s.API.Refresh(ctx, rec.TaskID, t.Version, summary, priority(u)); err != nil {
			return false, err
		}
		s.Logger.Info("update task refreshed", "task_id", rec.TaskID, "host", rec.Host, "container", rec.Container)
		return false, s.Store.RefreshUpdateTask(ctx, rec.TaskID, u.RemoteDigest, shortHash(summary), now)
	}
}

var checklist = []string{
	"Re-check the impact and the release notes",
	"Request the update job (own-repository images need a pull request instead)",
	"Wait for approval in dockgate and the job result",
	"Verify the findings cleared",
}

func priority(u store.UpdateImpact) string {
	if critical(u.Fixes) > 0 {
		return "high"
	}
	return "normal"
}

func critical(fs []store.ImpactFinding) int {
	n := 0
	for _, f := range fs {
		if f.Severity == "CRITICAL" {
			n++
		}
	}
	return n
}

// maxListed bounds findings listed in a task summary; the agent reads the
// rest from dockgate_update_impact.
const maxListed = 12

func (s *Syncer) summary(u store.UpdateImpact) string {
	var b strings.Builder
	fmt.Fprintf(&b, "dockgate found an image update for %s on %s that fixes %d critical/high vulnerabilities (%d critical) and introduces %d.\n\n",
		u.Container, u.Host, len(u.Fixes), critical(u.Fixes), len(u.Introduces))
	fmt.Fprintf(&b, "Image: %s\nCurrent digest: %s\nCandidate digest: %s\nPlatform: %s\nStill present after the update: %d\n\n",
		u.Image, orDash(u.CurrentDigest), u.RemoteDigest, u.Platform, u.Remaining)
	if s.ownImage(u.Image) {
		b.WriteString("Fix: this image is built from the operator's own repository. Open a pull request that rebuilds it on an updated base image; do not pull and recreate.\n\n")
	} else {
		b.WriteString("Fix: request the update with dockgate_update_request (host, container, reason, taskboard_task_id). It returns an approval_url; " +
			"the operator approves in the dockgate web UI, then the host's agent recreates the container with the scanned image and rolls back if it does not come up. " +
			"Follow it with dockgate_job_status. Do not run docker commands over SSH.\n\n")
	}
	b.WriteString("Before acting, re-check with dockgate_update_impact and dockgate_host_containers (compose project and working directory), " +
		"and read the release notes between the current and candidate versions for breaking changes. " +
		"The update job is the approval: nothing changes until the operator approves it in dockgate.\n\n")
	if len(u.Fixes) > 0 {
		b.WriteString("Fixes:\n")
		writeFindings(&b, u.Fixes)
	}
	if len(u.Introduces) > 0 {
		b.WriteString("\nIntroduces:\n")
		writeFindings(&b, u.Introduces)
	}
	// A machine-readable line for workers, so they need not parse the prose.
	meta, _ := json.Marshal(taskMeta{Version: 1, Host: u.Host, Container: u.Container, Image: u.Image,
		Digest: u.RemoteDigest, Fix: map[bool]string{true: "pull_request", false: "update_job"}[s.ownImage(u.Image)]})
	fmt.Fprintf(&b, "\n%s%s\n", MetaPrefix, meta)
	return b.String()
}

// MetaPrefix starts the summary line carrying taskMeta as JSON.
const MetaPrefix = "dockgate-task: "

// taskMeta identifies the update a task is about.
type taskMeta struct {
	Version   int    `json:"version"`
	Host      string `json:"host"`
	Container string `json:"container"`
	Image     string `json:"image"`
	Digest    string `json:"digest"`
	Fix       string `json:"fix"` // update_job or pull_request
}

func writeFindings(b *strings.Builder, fs []store.ImpactFinding) {
	for i, f := range fs {
		if i == maxListed {
			fmt.Fprintf(b, "- … and %d more\n", len(fs)-maxListed)
			return
		}
		fmt.Fprintf(b, "- %s %s (%s)\n", f.VulnID, f.Pkg, strings.ToLower(f.Severity))
	}
}

func (s *Syncer) ownImage(ref string) bool {
	for _, p := range s.OwnImagePrefixes {
		if p != "" && strings.HasPrefix(ref, p) {
			return true
		}
	}
	return false
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func shortHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])[:24]
}
