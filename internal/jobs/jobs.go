// Package jobs runs the update-job workflow on the server: it gates
// requests against the scanned candidate image, records human decisions,
// expires stale jobs and announces each step. Agents carry jobs out; nothing
// here touches a host.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	tintwire "go.michaelspost.com/tintwire-go"

	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/store"
)

// Publisher sends a notification card; *tintwire.Client satisfies it.
type Publisher interface {
	Publish(ctx context.Context, card tintwire.Card) (tintwire.Result, error)
}

// Service is the job workflow.
type Service struct {
	Store     *store.Store
	Logger    *slog.Logger
	Publisher Publisher // nil disables notifications
	Channel   string
	// BaseURL is the web UI origin used in links (https://dockgate.example).
	BaseURL string
	// OwnImagePrefixes mark images built from the operator's repositories;
	// they are fixed by a pull request, never by an update job.
	OwnImagePrefixes []string
	// Approvals, when set, looks for an operator's approval in the Taskboard
	// task a request names; nil means every job waits for approval here.
	Approvals Approvals
	now       func() time.Time
}

// Approvals finds who approved an update in a Taskboard task, if anyone.
type Approvals interface {
	ApprovedBy(ctx context.Context, taskID, host, container, digest string) (string, error)
}

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Request is an update request.
type Request struct {
	Host      string
	Container string
	Reason    string
	TaskID    string
	// Actor names who asked: an MCP client, an operator.
	Actor string
}

// ErrDenied wraps the gate's reason when a request is refused. The denied
// job is still recorded.
var ErrDenied = errors.New("update denied")

// RequestUpdate evaluates the update gate and records the job: pending
// approval when the update may proceed, denied otherwise.
func (s *Service) RequestUpdate(ctx context.Context, r Request) (store.Job, error) {
	now := s.clock()
	if strings.TrimSpace(r.Host) == "" || strings.TrimSpace(r.Container) == "" {
		return store.Job{}, errors.New("host and container are required")
	}
	agents, err := s.Store.Agents(ctx)
	if err != nil {
		return store.Job{}, err
	}
	var agent *store.Agent
	for i, a := range agents {
		if a.Name == r.Host && a.RevokedAt.IsZero() {
			agent = &agents[i]
		}
	}
	if agent == nil {
		return store.Job{}, fmt.Errorf("unknown host %q", r.Host)
	}
	containers, err := s.Store.Containers(ctx, agent.ID)
	if err != nil {
		return store.Job{}, err
	}
	var ctr *protocol.Container
	for i, c := range containers {
		if c.Name == r.Container {
			ctr = &containers[i]
		}
	}
	if ctr == nil {
		return store.Job{}, fmt.Errorf("no container %q on %s", r.Container, r.Host)
	}

	job := store.Job{
		ID: newJobID(), Kind: protocol.JobUpdate, AgentID: agent.ID, Host: agent.Name, ContainerID: ctr.ID,
		ContainerName: ctr.Name, Reference: ctr.Image, Reason: r.Reason, TaskID: r.TaskID, RequestedBy: r.Actor,
		Gate:      store.Gate{Fixes: []store.ImpactFinding{}, Introduces: []store.ImpactFinding{}},
		CreatedAt: now.Truncate(time.Second), UpdatedAt: now.Truncate(time.Second),
	}
	deny := func(reason string) (store.Job, error) {
		job.State, job.Gate.Denial = store.JobDenied, reason
		if err := s.Store.CreateJob(ctx, job, now); err != nil {
			return store.Job{}, err
		}
		s.Logger.Info("update job denied", "job_id", job.ID, "host", job.Host, "container", job.ContainerName, "reason", reason, "by", r.Actor)
		return job, fmt.Errorf("%w: %s", ErrDenied, reason)
	}

	u := ctr.Update
	if u == nil || u.Status != protocol.UpdateAvailable {
		return deny("no update is available for this container")
	}
	job.Reference = u.Reference
	if len(u.LocalDigests) > 0 {
		job.CurrentDigest = u.LocalDigests[0]
	}
	job.Digest = u.RemoteDigest
	if ctr.State != "running" {
		return deny(fmt.Sprintf("container is %s; only running containers are updated", ctr.State))
	}
	for _, p := range s.OwnImagePrefixes {
		if p != "" && strings.HasPrefix(u.Reference, p) {
			return deny("this image is built from your own repository; fix it with a pull request that rebuilds it")
		}
	}
	if why := store.UpdateExempt(ctr.Name); why != "" {
		return deny("not updated by jobs: " + why)
	}
	if ctr.Labels["dockgate.role"] != "" {
		return deny("dockgate's own containers are not updated by jobs")
	}
	impacts, err := s.Store.UpdateImpacts(ctx, agent.Name, now)
	if err != nil {
		return store.Job{}, err
	}
	var imp *store.UpdateImpact
	for i, x := range impacts {
		if x.Container == ctr.Name {
			imp = &impacts[i]
		}
	}
	if imp == nil || imp.RemoteDigest != u.RemoteDigest {
		return deny("the candidate image has not been assessed yet")
	}
	job.Platform = imp.Platform
	switch imp.Status {
	case "assessed":
	case "failed":
		return deny("the candidate image could not be scanned: " + imp.Error)
	default:
		return deny("the candidate image scan has not finished; try again later")
	}
	job.Gate.Fixes, job.Gate.Introduces, job.Gate.Remaining = imp.Fixes, imp.Introduces, imp.Remaining
	job.Gate.Hold = len(imp.Introduces) > 0
	job.State = store.JobPendingApproval
	if err := s.Store.CreateJob(ctx, job, now); err != nil {
		return store.Job{}, err
	}
	s.Logger.Info("update job requested", "job_id", job.ID, "host", job.Host, "container", job.ContainerName,
		"digest", job.Digest, "fixes", len(job.Gate.Fixes), "introduces", len(job.Gate.Introduces), "by", r.Actor)
	if approved, ok := s.approveFromTask(ctx, job); ok {
		return approved, nil
	}
	s.notifyPending(ctx, job)
	return job, nil
}

// approveFromTask approves a pending job when an operator already approved
// this exact update in the Taskboard task that requested it. A job that
// introduces findings, or any doubt about the approval, leaves it pending.
func (s *Service) approveFromTask(ctx context.Context, job store.Job) (store.Job, bool) {
	if s.Approvals == nil || job.TaskID == "" || job.Gate.Hold {
		return store.Job{}, false
	}
	person, err := s.Approvals.ApprovedBy(ctx, job.TaskID, job.Host, job.ContainerName, job.Digest)
	if err != nil {
		s.Logger.Warn("check Taskboard approval; the job waits for approval here", "job_id", job.ID, "task_id", job.TaskID, "err", err)
		return store.Job{}, false
	}
	if person == "" {
		return store.Job{}, false
	}
	decided, err := s.Decide(ctx, job.ID, true, "taskboard:"+person, "approved in Taskboard task "+job.TaskID)
	if err != nil {
		s.Logger.Error("approve job from Taskboard", "job_id", job.ID, "err", err)
		return store.Job{}, false
	}
	if decided.State != store.JobApproved {
		return decided, true
	}
	s.notifyApproved(ctx, decided, person)
	return decided, true
}

// Decide approves or rejects a pending job on behalf of actor, a person.
// Approval re-checks that the job's candidate is still the current one.
func (s *Service) Decide(ctx context.Context, id string, approve bool, actor, note string) (store.Job, error) {
	now := s.clock()
	job, err := s.Store.Job(ctx, id)
	if err != nil {
		return store.Job{}, err
	}
	if approve && job.State == store.JobPendingApproval {
		if why := s.stale(ctx, job); why != "" {
			if err := s.Store.SupersedeJob(ctx, id, why, now); err != nil {
				return store.Job{}, err
			}
			return s.Store.Job(ctx, id)
		}
	}
	if err := s.Store.DecideJob(ctx, id, approve, actor, note, now); err != nil {
		return store.Job{}, err
	}
	s.Logger.Info("update job decided", "job_id", id, "approved", approve, "by", actor)
	return s.Store.Job(ctx, id)
}

// stale explains why a pending job's candidate is no longer current, or
// returns "".
func (s *Service) stale(ctx context.Context, job store.Job) string {
	agents, err := s.Store.Agents(ctx)
	if err != nil {
		return ""
	}
	for _, a := range agents {
		if a.ID != job.AgentID {
			continue
		}
		containers, err := s.Store.Containers(ctx, a.ID)
		if err != nil {
			return ""
		}
		for _, c := range containers {
			if c.Name != job.ContainerName {
				continue
			}
			switch {
			case c.ID != job.ContainerID:
				return "the container was recreated since the request"
			case c.Update == nil || c.Update.Status != protocol.UpdateAvailable:
				return "the container no longer has an update available"
			case c.Update.RemoteDigest != job.Digest:
				return "a newer image (" + c.Update.RemoteDigest + ") replaced this candidate; request again to assess it"
			}
			return ""
		}
		return "the container no longer exists"
	}
	return "the host's agent is gone"
}

// Finished announces a job the agent completed.
func (s *Service) Finished(ctx context.Context, job store.Job) {
	s.Logger.Info("update job finished", "job_id", job.ID, "host", job.Host, "container", job.ContainerName, "state", job.State)
	s.notifyFinished(ctx, job)
}

// ExpireLoop closes stale jobs every interval until ctx ends.
func (s *Service) ExpireLoop(ctx context.Context, interval time.Duration) {
	for {
		closed, err := s.Store.ExpireJobs(ctx, s.clock())
		if err != nil && ctx.Err() == nil {
			s.Logger.Error("expire jobs", "err", err)
		}
		for _, j := range closed {
			s.Logger.Warn("update job closed", "job_id", j.ID, "host", j.Host, "container", j.ContainerName, "state", j.State)
			s.notifyFinished(ctx, j)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// URL returns the job's page in the web UI, or "" without a base URL.
func (s *Service) URL(id string) string {
	if s.BaseURL == "" {
		return ""
	}
	return strings.TrimRight(s.BaseURL, "/") + "/jobs/" + url.PathEscape(id)
}

func (s *Service) publish(ctx context.Context, card tintwire.Card) {
	if s.Publisher == nil {
		return
	}
	card.Channel, card.Source = s.Channel, "dockgate"
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := s.Publisher.Publish(ctx, card); err != nil {
		s.Logger.Error("publish job notification", "err", err)
	}
}

func (s *Service) notifyPending(ctx context.Context, j store.Job) {
	critical := 0
	for _, f := range j.Gate.Fixes {
		if f.Severity == "CRITICAL" {
			critical++
		}
	}
	card := tintwire.Card{
		Title:    fmt.Sprintf("Approve update: %s on %s", j.ContainerName, j.Host),
		Summary:  truncate(fmt.Sprintf("%s asks to update %s to the scanned candidate. %s", j.RequestedBy, j.Reference, j.Reason), 500),
		Severity: tintwire.SeverityWarning,
		Metrics: []tintwire.Metric{
			{Label: "Fixes", Value: len(j.Gate.Fixes)},
			{Label: "Critical fixed", Value: critical},
			{Label: "Introduces", Value: len(j.Gate.Introduces)},
			{Label: "Remaining", Value: j.Gate.Remaining},
		},
		Fields:       []tintwire.Field{{Label: "Candidate", Value: j.Digest}},
		State:        tintwire.StateFiring,
		LifecycleKey: "dockgate-job-" + j.ID,
	}
	if j.Gate.Hold {
		card.Badges = []tintwire.Badge{{Label: "introduces critical/high findings", Tone: tintwire.ToneCritical}}
	}
	if u := s.URL(j.ID); u != "" {
		card.Actions = []tintwire.Action{{Label: "Review", Type: tintwire.ActionLink, URL: u}}
	}
	s.publish(ctx, card)
}

func (s *Service) notifyApproved(ctx context.Context, j store.Job, person string) {
	card := tintwire.Card{
		Title:        fmt.Sprintf("Updating %s on %s", j.ContainerName, j.Host),
		Summary:      truncate(fmt.Sprintf("Approved in Taskboard by %s. The host's agent recreates %s with the scanned candidate at its next report. %s", person, j.ContainerName, j.Reason), 500),
		Severity:     tintwire.SeverityInfo,
		Metrics:      []tintwire.Metric{{Label: "Fixes", Value: len(j.Gate.Fixes)}, {Label: "Remaining", Value: j.Gate.Remaining}},
		Fields:       []tintwire.Field{{Label: "Candidate", Value: j.Digest}},
		State:        tintwire.StateFiring,
		LifecycleKey: "dockgate-job-" + j.ID,
	}
	if u := s.URL(j.ID); u != "" {
		card.Links = []tintwire.Link{{Label: "Job", URL: u}}
	}
	s.publish(ctx, card)
}

func (s *Service) notifyFinished(ctx context.Context, j store.Job) {
	sev, verb := tintwire.SeverityWarning, j.State
	switch j.State {
	case store.JobSucceeded:
		sev, verb = tintwire.SeveritySuccess, "updated"
	case store.JobFailed, store.JobLost:
		sev = tintwire.SeverityCritical
	case store.JobRolledBack:
		verb = "rolled back"
	}
	summary := fmt.Sprintf("Job %s: %s.", j.ID, strings.ReplaceAll(verb, "_", " "))
	if j.Result != nil && j.Result.Error != "" {
		summary += " " + j.Result.Error
	} else if len(j.Events) > 0 && j.Events[len(j.Events)-1].Note != "" {
		summary += " " + j.Events[len(j.Events)-1].Note
	}
	card := tintwire.Card{
		Title:        fmt.Sprintf("Update %s: %s on %s", strings.ReplaceAll(verb, "_", " "), j.ContainerName, j.Host),
		Summary:      truncate(summary, 500),
		Severity:     sev,
		State:        tintwire.StateResolved,
		LifecycleKey: "dockgate-job-" + j.ID,
	}
	if u := s.URL(j.ID); u != "" {
		card.Links = []tintwire.Link{{Label: "Job", URL: u}}
	}
	s.publish(ctx, card)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func newJobID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return "job_" + hex.EncodeToString(b)
}
