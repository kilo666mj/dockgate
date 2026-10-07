package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// dockgate files one Taskboard task per host and container with an
// actionable update and remembers it here, so it can refresh or cancel the
// task while it is unclaimed and never files a second one.
const schemaUpdateTasks = `
CREATE TABLE IF NOT EXISTS update_tasks (
	host           TEXT NOT NULL,
	container      TEXT NOT NULL,
	task_id        TEXT NOT NULL,
	remote_digest  TEXT NOT NULL,
	summary_hash   TEXT NOT NULL,
	created_at     INTEGER NOT NULL,
	updated_at     INTEGER NOT NULL,
	closed_at      INTEGER,
	closed_reason  TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (host, container, task_id)
);
`

// UpdateTask is dockgate's record of a Taskboard task it filed.
type UpdateTask struct {
	Host         string
	Container    string
	TaskID       string
	RemoteDigest string
	SummaryHash  string
	CreatedAt    time.Time
	ClosedAt     time.Time
	ClosedReason string
}

// OpenUpdateTasks lists filed tasks dockgate has not seen close.
func (s *Store) OpenUpdateTasks(ctx context.Context) ([]UpdateTask, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host, container, task_id, remote_digest, summary_hash, created_at
		FROM update_tasks WHERE closed_at IS NULL ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []UpdateTask
	for rows.Next() {
		var t UpdateTask
		var created int64
		if err := rows.Scan(&t.Host, &t.Container, &t.TaskID, &t.RemoteDigest, &t.SummaryHash, &created); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(created, 0)
		out = append(out, t)
	}
	return out, rows.Err()
}

// RecordUpdateTask stores a newly filed task.
func (s *Store) RecordUpdateTask(ctx context.Context, t UpdateTask, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO update_tasks
		(host, container, task_id, remote_digest, summary_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host, container, task_id) DO NOTHING`,
		t.Host, t.Container, t.TaskID, t.RemoteDigest, t.SummaryHash, now.Unix(), now.Unix())
	return err
}

// RefreshUpdateTask records that a task's description was updated.
func (s *Store) RefreshUpdateTask(ctx context.Context, taskID, remoteDigest, summaryHash string, now time.Time) error {
	return s.oneRow(s.db.ExecContext(ctx, `UPDATE update_tasks SET remote_digest = ?, summary_hash = ?, updated_at = ?
		WHERE task_id = ? AND closed_at IS NULL`, remoteDigest, summaryHash, now.Unix(), taskID))
}

// CloseUpdateTask records that a task closed, by dockgate or by its worker.
func (s *Store) CloseUpdateTask(ctx context.Context, taskID, reason string, now time.Time) error {
	return s.oneRow(s.db.ExecContext(ctx, `UPDATE update_tasks SET closed_at = ?, closed_reason = ?, updated_at = ?
		WHERE task_id = ? AND closed_at IS NULL`, now.Unix(), truncate(reason, 500), now.Unix(), taskID))
}

// ReopenUpdateTask resumes tracking when a person reopens a dismissed task.
func (s *Store) ReopenUpdateTask(ctx context.Context, taskID string, now time.Time) error {
	return s.oneRow(s.db.ExecContext(ctx, `UPDATE update_tasks SET closed_at = NULL, closed_reason = '', updated_at = ?
		WHERE task_id = ? AND closed_at IS NOT NULL`, now.Unix(), taskID))
}

func (s *Store) oneRow(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// LastUpdateTask returns the most recent task filed for a container, open
// or closed.
func (s *Store) LastUpdateTask(ctx context.Context, host, container string) (UpdateTask, error) {
	var t UpdateTask
	var created int64
	var closed sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT host, container, task_id, remote_digest, summary_hash, created_at, closed_at, closed_reason
		FROM update_tasks WHERE host = ? AND container = ? ORDER BY created_at DESC LIMIT 1`, host, container).
		Scan(&t.Host, &t.Container, &t.TaskID, &t.RemoteDigest, &t.SummaryHash, &created, &closed, &t.ClosedReason)
	if errors.Is(err, sql.ErrNoRows) {
		return UpdateTask{}, ErrNotFound
	}
	if err != nil {
		return UpdateTask{}, err
	}
	t.CreatedAt, t.ClosedAt = time.Unix(created, 0), unixOrZero(closed)
	return t, nil
}
