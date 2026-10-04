package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Browser sessions for the web UI. Only a hash of the session ID is stored.
const schemaSessions = `
CREATE TABLE IF NOT EXISTS web_sessions (
	id_hash     BLOB PRIMARY KEY,
	subject     TEXT NOT NULL,
	email       TEXT NOT NULL DEFAULT '',
	csrf        TEXT NOT NULL,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL
);
`

// WebSession is a signed-in browser.
type WebSession struct {
	Subject   string
	Email     string
	CSRF      string
	ExpiresAt time.Time
}

// CreateSession stores a session under the hash of id.
func (s *Store) CreateSession(ctx context.Context, id string, ws WebSession, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE expires_at < ?`, now.Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO web_sessions (id_hash, subject, email, csrf, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, hashSecret(id), ws.Subject, ws.Email, ws.CSRF, now.Unix(), ws.ExpiresAt.Unix())
	return err
}

// Session returns the unexpired session for id.
func (s *Store) Session(ctx context.Context, id string, now time.Time) (WebSession, error) {
	var ws WebSession
	var expires int64
	err := s.db.QueryRowContext(ctx, `SELECT subject, email, csrf, expires_at FROM web_sessions WHERE id_hash = ? AND expires_at >= ?`,
		hashSecret(id), now.Unix()).Scan(&ws.Subject, &ws.Email, &ws.CSRF, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return WebSession{}, ErrNotFound
	}
	ws.ExpiresAt = time.Unix(expires, 0)
	return ws, err
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE id_hash = ?`, hashSecret(id))
	return err
}
