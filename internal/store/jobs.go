package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.michaelspost.com/dockgate/internal/protocol"
)

// Update jobs: requested by an assistant or operator, approved or rejected
// by a person, carried out once by the host's agent. Every transition is
// kept in job_events.
const schemaJobs = `
CREATE TABLE IF NOT EXISTS jobs (
	id              TEXT PRIMARY KEY,
	kind            TEXT NOT NULL,
	agent_id        TEXT NOT NULL,
	host            TEXT NOT NULL,
	container_id    TEXT NOT NULL,
	container_name  TEXT NOT NULL,
	reference       TEXT NOT NULL,
	current_digest  TEXT NOT NULL DEFAULT '',
	digest          TEXT NOT NULL,
	platform        TEXT NOT NULL DEFAULT '',
	state           TEXT NOT NULL,
	gate            TEXT NOT NULL DEFAULT '{}',
	reason          TEXT NOT NULL DEFAULT '',
	task_id         TEXT NOT NULL DEFAULT '',
	requested_by    TEXT NOT NULL,
	decided_by      TEXT NOT NULL DEFAULT '',
	note            TEXT NOT NULL DEFAULT '',
	result          TEXT NOT NULL DEFAULT '',
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL,
	decided_at      INTEGER,
	dispatched_at   INTEGER,
	held_at         INTEGER,
	finished_at     INTEGER
);
CREATE INDEX IF NOT EXISTS jobs_by_agent_state ON jobs (agent_id, state);
CREATE INDEX IF NOT EXISTS jobs_by_container ON jobs (host, container_name, created_at);
CREATE TABLE IF NOT EXISTS job_events (
	job_id  TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
	at      INTEGER NOT NULL,
	actor   TEXT NOT NULL,
	state   TEXT NOT NULL,
	note    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS job_events_by_job ON job_events (job_id, at);
`

// Job states.
const (
	JobDenied          = "denied"           // refused by the gate at request
	JobPendingApproval = "pending_approval" // waiting for a person
	JobApproved        = "approved"         // waiting for the agent
	JobDispatched      = "dispatched"       // sent to the agent
	JobSucceeded       = protocol.JobSucceeded
	JobFailed          = protocol.JobFailed
	JobRolledBack      = protocol.JobRolledBack
	JobRejected        = "rejected"   // a person said no
	JobExpired         = "expired"    // nobody decided, or no agent picked it up
	JobSuperseded      = "superseded" // a newer candidate replaced the approved one
	JobLost            = "lost"       // dispatched, but the agent stopped holding it
)

// OpenJobStates are states in which a job may still change the host.
var OpenJobStates = []string{JobPendingApproval, JobApproved, JobDispatched}

// Job errors.
var (
	// ErrJobState is returned for a transition the job's state does not allow.
	ErrJobState = errors.New("job is not in a state that allows this")
	// ErrJobUnknown is an agent result for a job not dispatched to it.
	ErrJobUnknown = errors.New("no dispatched job with this ID for this agent")
	// ErrJobResult is a malformed agent result.
	ErrJobResult = errors.New("invalid job result")
)

// Gate is the update gate's assessment stored with a job.
type Gate struct {
	Fixes      []ImpactFinding `json:"fixes"`
	Introduces []ImpactFinding `json:"introduces"`
	Remaining  int             `json:"remaining"`
	// Hold is set when the candidate introduces critical or high findings;
	// the job still needs approval, with this shown prominently.
	Hold   bool   `json:"hold,omitempty"`
	Denial string `json:"denial,omitempty"`
}

// Job is an update job.
type Job struct {
	ID            string              `json:"id"`
	Kind          string              `json:"kind"`
	AgentID       string              `json:"-"`
	Host          string              `json:"host"`
	ContainerID   string              `json:"container_id"`
	ContainerName string              `json:"container"`
	Reference     string              `json:"reference"`
	CurrentDigest string              `json:"current_digest,omitempty"`
	Digest        string              `json:"digest"`
	Platform      string              `json:"platform,omitempty"`
	State         string              `json:"state"`
	Gate          Gate                `json:"gate"`
	Reason        string              `json:"reason,omitempty"`
	TaskID        string              `json:"taskboard_task_id,omitempty"`
	RequestedBy   string              `json:"requested_by"`
	DecidedBy     string              `json:"decided_by,omitempty"`
	Note          string              `json:"note,omitempty"`
	Result        *protocol.JobResult `json:"result,omitempty"`
	CreatedAt     time.Time           `json:"created_at"`
	UpdatedAt     time.Time           `json:"updated_at"`
	DecidedAt     time.Time           `json:"decided_at,omitzero"`
	DispatchedAt  time.Time           `json:"dispatched_at,omitzero"`
	FinishedAt    time.Time           `json:"finished_at,omitzero"`
	Events        []JobEvent          `json:"events,omitempty"`
}

// Open reports whether the job may still change the host.
func (j Job) Open() bool {
	for _, s := range OpenJobStates {
		if j.State == s {
			return true
		}
	}
	return false
}

// JobEvent is one transition in a job's history.
type JobEvent struct {
	At    time.Time `json:"at"`
	Actor string    `json:"actor"`
	State string    `json:"state"`
	Note  string    `json:"note,omitempty"`
}

const jobColumns = `id, kind, agent_id, host, container_id, container_name, reference, current_digest, digest, platform,
	state, gate, reason, task_id, requested_by, decided_by, note, result, created_at, updated_at,
	decided_at, dispatched_at, finished_at`

func scanJob(row interface{ Scan(...any) error }) (Job, error) {
	var j Job
	var gate, result string
	var created, updated int64
	var decided, dispatched, finished sql.NullInt64
	err := row.Scan(&j.ID, &j.Kind, &j.AgentID, &j.Host, &j.ContainerID, &j.ContainerName, &j.Reference, &j.CurrentDigest,
		&j.Digest, &j.Platform, &j.State, &gate, &j.Reason, &j.TaskID, &j.RequestedBy, &j.DecidedBy, &j.Note, &result,
		&created, &updated, &decided, &dispatched, &finished)
	if err != nil {
		return Job{}, err
	}
	if err := json.Unmarshal([]byte(gate), &j.Gate); err != nil {
		return Job{}, fmt.Errorf("job %s gate: %w", j.ID, err)
	}
	if result != "" {
		var r protocol.JobResult
		if err := json.Unmarshal([]byte(result), &r); err != nil {
			return Job{}, fmt.Errorf("job %s result: %w", j.ID, err)
		}
		j.Result = &r
	}
	j.CreatedAt, j.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	j.DecidedAt, j.DispatchedAt, j.FinishedAt = unixOrZero(decided), unixOrZero(dispatched), unixOrZero(finished)
	return j, nil
}

func addEvent(ctx context.Context, tx *sql.Tx, id, actor, state, note string, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO job_events (job_id, at, actor, state, note) VALUES (?, ?, ?, ?, ?)`,
		id, now.Unix(), truncate(actor, 200), state, truncate(note, 2000))
	return err
}

// CreateJob stores a new job in its initial state (pending approval or
// denied). It refuses a second open job for the same container.
func (s *Store) CreateJob(ctx context.Context, j Job, now time.Time) (err error) {
	gate, err := json.Marshal(j.Gate)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if j.State != JobDenied {
		var open string
		err := tx.QueryRowContext(ctx, `SELECT id FROM jobs WHERE host = ? AND container_name = ? AND state IN (?, ?, ?)`,
			j.Host, j.ContainerName, JobPendingApproval, JobApproved, JobDispatched).Scan(&open)
		if err == nil {
			return fmt.Errorf("%w: %s on %s already has open job %s", ErrJobState, j.ContainerName, j.Host, open)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO jobs (id, kind, agent_id, host, container_id, container_name, reference,
		current_digest, digest, platform, state, gate, reason, task_id, requested_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		j.ID, j.Kind, j.AgentID, j.Host, j.ContainerID, j.ContainerName, j.Reference, j.CurrentDigest, j.Digest, j.Platform,
		j.State, string(gate), truncate(j.Reason, 2000), truncate(j.TaskID, 100), truncate(j.RequestedBy, 200), now.Unix(), now.Unix())
	if err != nil {
		return err
	}
	if err := addEvent(ctx, tx, j.ID, j.RequestedBy, j.State, firstNonEmpty(j.Gate.Denial, j.Reason), now); err != nil {
		return err
	}
	return tx.Commit()
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// Job returns a job with its history.
func (s *Store) Job(ctx context.Context, id string) (Job, error) {
	j, err := scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT at, actor, state, note FROM job_events WHERE job_id = ? ORDER BY at, rowid`, id)
	if err != nil {
		return Job{}, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var e JobEvent
		var at int64
		if err := rows.Scan(&at, &e.Actor, &e.State, &e.Note); err != nil {
			return Job{}, err
		}
		e.At = time.Unix(at, 0)
		j.Events = append(j.Events, e)
	}
	return j, rows.Err()
}

// JobFilter narrows Jobs. Empty fields match everything.
type JobFilter struct {
	Host   string
	States []string
	Limit  int
}

// Jobs lists jobs, newest first.
func (s *Store) Jobs(ctx context.Context, f JobFilter) ([]Job, error) {
	q := `SELECT ` + jobColumns + ` FROM jobs WHERE 1=1`
	var args []any
	if f.Host != "" {
		q += ` AND host = ?`
		args = append(args, f.Host)
	}
	if len(f.States) > 0 {
		q += ` AND state IN (` + strings.TrimSuffix(strings.Repeat("?,", len(f.States)), ",") + `)`
		for _, st := range f.States {
			args = append(args, st)
		}
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q += ` ORDER BY created_at DESC, rowid DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// transition moves a job from one of the states in from to state, recording
// the actor and note. It returns ErrJobState when the job is elsewhere.
func (s *Store) transition(ctx context.Context, id string, from []string, state, actor, note string, now time.Time, extra string, extraArgs ...any) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	q := `UPDATE jobs SET state = ?, updated_at = ?` + extra + ` WHERE id = ? AND state IN (` +
		strings.TrimSuffix(strings.Repeat("?,", len(from)), ",") + `)`
	args := append([]any{state, now.Unix()}, extraArgs...)
	args = append(args, id)
	for _, f := range from {
		args = append(args, f)
	}
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		var current string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM jobs WHERE id = ?`, id).Scan(&current); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		return fmt.Errorf("%w (job %s is %s)", ErrJobState, id, current)
	}
	if err := addEvent(ctx, tx, id, actor, state, note, now); err != nil {
		return err
	}
	return tx.Commit()
}

// DecideJob approves or rejects a pending job.
func (s *Store) DecideJob(ctx context.Context, id string, approve bool, actor, note string, now time.Time) error {
	state := JobRejected
	if approve {
		state = JobApproved
	}
	return s.transition(ctx, id, []string{JobPendingApproval}, state, actor, note, now,
		`, decided_by = ?, decided_at = ?, note = ?`, truncate(actor, 200), now.Unix(), truncate(note, 2000))
}

// SupersedeJob closes a pending or approved job whose candidate is no
// longer current.
func (s *Store) SupersedeJob(ctx context.Context, id, note string, now time.Time) error {
	return s.transition(ctx, id, []string{JobPendingApproval, JobApproved}, JobSuperseded, "dockgate", note, now, "")
}

// DispatchJobs hands an agent its approved jobs, marking each dispatched so
// it is sent exactly once, and records that the agent still holds the jobs
// listed in held.
func (s *Store) DispatchJobs(ctx context.Context, agentID string, held []string, now time.Time) (out []protocol.Job, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	for _, id := range held {
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET held_at = ? WHERE id = ? AND agent_id = ? AND state = ?`,
			now.Unix(), id, agentID, JobDispatched); err != nil {
			return nil, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, kind, container_id, container_name, reference, digest FROM jobs
		WHERE agent_id = ? AND state = ? ORDER BY decided_at`, agentID, JobApproved)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var j protocol.Job
		if err := rows.Scan(&j.ID, &j.Kind, &j.ContainerID, &j.ContainerName, &j.Reference, &j.Digest); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, j)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for _, j := range out {
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET state = ?, dispatched_at = ?, held_at = ?, updated_at = ? WHERE id = ?`,
			JobDispatched, now.Unix(), now.Unix(), now.Unix(), j.ID); err != nil {
			return nil, err
		}
		if err := addEvent(ctx, tx, j.ID, "dockgate", JobDispatched, "sent to the agent", now); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit()
}

// FinishJob records an agent's result for a job dispatched to it. A result
// for any other job is ErrJobUnknown.
func (s *Store) FinishJob(ctx context.Context, agentID string, r protocol.JobResult, now time.Time) (Job, error) {
	switch r.State {
	case JobSucceeded, JobFailed, JobRolledBack:
	default:
		return Job{}, fmt.Errorf("%w: unknown state %q", ErrJobResult, r.State)
	}
	var owner string
	err := s.db.QueryRowContext(ctx, `SELECT agent_id FROM jobs WHERE id = ?`, r.ID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && owner != agentID) {
		return Job{}, ErrJobUnknown
	}
	if err != nil {
		return Job{}, err
	}
	if len(r.Steps) > 100 {
		r.Steps = r.Steps[len(r.Steps)-100:]
	}
	for i, st := range r.Steps {
		r.Steps[i] = truncate(st, 4000)
	}
	r.Error = truncate(r.Error, 4000)
	result, err := json.Marshal(r)
	if err != nil {
		return Job{}, err
	}
	// A job marked lost may still report: the result is the truth.
	err = s.transition(ctx, r.ID, []string{JobDispatched, JobLost}, r.State, "agent", r.Error, now,
		`, result = ?, finished_at = ?`, string(result), now.Unix())
	if errors.Is(err, ErrJobState) {
		return Job{}, ErrJobUnknown
	}
	if err != nil {
		return Job{}, err
	}
	return s.Job(ctx, r.ID)
}

// Job timeouts.
const (
	PendingJobTTL  = 24 * time.Hour   // waiting for a decision
	ApprovedJobTTL = time.Hour        // waiting for the agent
	JobHoldTimeout = 10 * time.Minute // dispatched, not reported as held
)

// ExpireJobs closes jobs that waited too long and returns them.
func (s *Store) ExpireJobs(ctx context.Context, now time.Time) ([]Job, error) {
	type rule struct {
		state, next, cond, note string
		cutoff                  time.Time
	}
	rules := []rule{
		{JobPendingApproval, JobExpired, `created_at < ?`, "no decision within 24 hours", now.Add(-PendingJobTTL)},
		{JobApproved, JobExpired, `decided_at < ?`, "the agent did not pick the job up within an hour", now.Add(-ApprovedJobTTL)},
		{JobDispatched, JobLost, `COALESCE(held_at, dispatched_at) < ?`, "the agent stopped reporting the job; check the host", now.Add(-JobHoldTimeout)},
	}
	var closed []Job
	for _, r := range rules {
		rows, err := s.db.QueryContext(ctx, `SELECT id FROM jobs WHERE state = ? AND `+r.cond, r.state, r.cutoff.Unix())
		if err != nil {
			return nil, err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return nil, err
			}
			ids = append(ids, id)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, err
		}
		for _, id := range ids {
			if err := s.transition(ctx, id, []string{r.state}, r.next, "dockgate", r.note, now, ""); err != nil {
				if errors.Is(err, ErrJobState) {
					continue
				}
				return nil, err
			}
			j, err := s.Job(ctx, id)
			if err != nil {
				return nil, err
			}
			closed = append(closed, j)
		}
	}
	return closed, nil
}
