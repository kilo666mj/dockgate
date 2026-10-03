// Package store keeps the dockgate server's state in SQLite.
package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.michaelspost.com/dockgate/internal/protocol"

	_ "modernc.org/sqlite" // database/sql driver
)

// Errors returned to callers that must distinguish them.
var (
	ErrNotFound     = errors.New("not found")
	ErrInvalidToken = errors.New("invalid, used or expired enrollment token")
	ErrNameTaken    = errors.New("an active agent already has this name")
	ErrRevoked      = errors.New("agent is revoked")
)

const schema = `
CREATE TABLE IF NOT EXISTS agents (
	id              TEXT PRIMARY KEY,
	name            TEXT NOT NULL UNIQUE,
	pin             TEXT NOT NULL UNIQUE,
	cert_serial     TEXT NOT NULL,
	cert_not_after  INTEGER NOT NULL,
	enrolled_at     INTEGER NOT NULL,
	last_seen_at    INTEGER,
	last_report_at  INTEGER,
	hostname        TEXT NOT NULL DEFAULT '',
	agent_version   TEXT NOT NULL DEFAULT '',
	docker          TEXT NOT NULL DEFAULT '{}',
	report_errors   TEXT NOT NULL DEFAULT '[]',
	revoked_at      INTEGER
);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
	id           TEXT PRIMARY KEY,
	secret_hash  BLOB NOT NULL,
	name         TEXT NOT NULL,
	replace      INTEGER NOT NULL DEFAULT 0,
	created_at   INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	used_at      INTEGER,
	used_by      TEXT
);
CREATE TABLE IF NOT EXISTS containers (
	agent_id        TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	id              TEXT NOT NULL,
	name            TEXT NOT NULL,
	image           TEXT NOT NULL,
	image_id        TEXT NOT NULL,
	state           TEXT NOT NULL,
	status          TEXT NOT NULL,
	health          TEXT NOT NULL DEFAULT '',
	restart_count   INTEGER NOT NULL DEFAULT 0,
	created         INTEGER NOT NULL,
	started_at      INTEGER,
	compose_project TEXT NOT NULL DEFAULT '',
	compose_service TEXT NOT NULL DEFAULT '',
	labels          TEXT NOT NULL DEFAULT '{}',
	update_check    TEXT,
	PRIMARY KEY (agent_id, id)
);
CREATE TABLE IF NOT EXISTS images (
	agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	id            TEXT NOT NULL,
	repo_tags     TEXT NOT NULL DEFAULT '[]',
	repo_digests  TEXT NOT NULL DEFAULT '[]',
	size_bytes    INTEGER NOT NULL,
	created       INTEGER NOT NULL,
	PRIMARY KEY (agent_id, id)
);
`

// Store is the server's database.
type Store struct {
	db *sql.DB
}

// Open opens or creates the database at path. The file must be on a local
// filesystem: SQLite's WAL mode does not work over network filesystems.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serialises writers and keeps pragmas consistent; the
	// server's load is a handful of agents reporting every minute.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema + schemaVulns); err != nil {
		return nil, errors.Join(fmt.Errorf("apply schema: %w", err), db.Close())
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Token is an enrollment token without its secret.
type Token struct {
	ID        string
	Name      string
	Replace   bool
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
	UsedBy    string
}

// CreateToken stores a new single-use enrollment token. Only a hash of the
// secret is kept.
func (s *Store) CreateToken(ctx context.Context, id, secret, name string, replace bool, ttl time.Duration) error {
	now := time.Now()
	if !replace {
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM agents WHERE name = ? AND revoked_at IS NULL`, name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrNameTaken
		}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO enrollment_tokens (id, secret_hash, name, replace, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, hashSecret(secret), name, replace, now.Unix(), now.Add(ttl).Unix())
	return err
}

// Tokens lists enrollment tokens, newest first.
func (s *Store) Tokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, replace, created_at, expires_at, used_at, COALESCE(used_by, '') FROM enrollment_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Token
	for rows.Next() {
		var t Token
		var created, expires int64
		var used sql.NullInt64
		if err := rows.Scan(&t.ID, &t.Name, &t.Replace, &created, &expires, &used, &t.UsedBy); err != nil {
			return nil, err
		}
		t.CreatedAt, t.ExpiresAt, t.UsedAt = time.Unix(created, 0), time.Unix(expires, 0), unixOrZero(used)
		out = append(out, t)
	}
	return out, rows.Err()
}

// Issued describes a certificate the CA signed for an agent.
type Issued struct {
	Serial   string
	NotAfter time.Time
	PEM      []byte
}

// Enroll consumes an enrollment token and registers or re-keys the agent it
// names. sign is called inside the transaction with the agent's ID so that a
// signing failure leaves the token unused.
func (s *Store) Enroll(ctx context.Context, tokenID, secret, pin, newID string, sign func(agentID string) (Issued, error)) (Agent, Issued, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Agent{}, Issued{}, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	var hash []byte
	var name string
	var replace bool
	var expires int64
	var used sql.NullInt64
	err = tx.QueryRowContext(ctx,
		`SELECT secret_hash, name, replace, expires_at, used_at FROM enrollment_tokens WHERE id = ?`, tokenID).
		Scan(&hash, &name, &replace, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, Issued{}, ErrInvalidToken
	}
	if err != nil {
		return Agent{}, Issued{}, err
	}
	if used.Valid || now.Unix() > expires || subtle.ConstantTimeCompare(hash, hashSecret(secret)) != 1 {
		return Agent{}, Issued{}, ErrInvalidToken
	}

	agentID := newID
	var existingID string
	var revoked sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT id, revoked_at FROM agents WHERE name = ?`, name).Scan(&existingID, &revoked)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return Agent{}, Issued{}, err
	case replace || revoked.Valid:
		agentID = existingID
	default:
		return Agent{}, Issued{}, ErrNameTaken
	}

	issued, err := sign(agentID)
	if err != nil {
		return Agent{}, Issued{}, err
	}
	if agentID == existingID {
		_, err = tx.ExecContext(ctx,
			`UPDATE agents SET pin = ?, cert_serial = ?, cert_not_after = ?, enrolled_at = ?, revoked_at = NULL WHERE id = ?`,
			pin, issued.Serial, issued.NotAfter.Unix(), now.Unix(), agentID)
	} else {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO agents (id, name, pin, cert_serial, cert_not_after, enrolled_at) VALUES (?, ?, ?, ?, ?, ?)`,
			agentID, name, pin, issued.Serial, issued.NotAfter.Unix(), now.Unix())
	}
	if err != nil {
		return Agent{}, Issued{}, fmt.Errorf("save agent: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE enrollment_tokens SET used_at = ?, used_by = ? WHERE id = ?`, now.Unix(), agentID, tokenID); err != nil {
		return Agent{}, Issued{}, err
	}
	if err := tx.Commit(); err != nil {
		return Agent{}, Issued{}, err
	}
	return Agent{ID: agentID, Name: name, Pin: pin, CertSerial: issued.Serial, CertNotAfter: issued.NotAfter, EnrolledAt: now}, issued, nil
}

// Agent is an enrolled agent.
type Agent struct {
	ID           string
	Name         string
	Pin          string
	CertSerial   string
	CertNotAfter time.Time
	EnrolledAt   time.Time
	LastSeenAt   time.Time
	LastReportAt time.Time
	Hostname     string
	AgentVersion string
	Docker       protocol.DockerInfo
	ReportErrors []string
	RevokedAt    time.Time
}

const agentColumns = `id, name, pin, cert_serial, cert_not_after, enrolled_at, last_seen_at, last_report_at,
	hostname, agent_version, docker, report_errors, revoked_at`

func scanAgent(row interface{ Scan(...any) error }) (Agent, error) {
	var a Agent
	var notAfter, enrolled int64
	var seen, reported, revoked sql.NullInt64
	var docker, errs string
	if err := row.Scan(&a.ID, &a.Name, &a.Pin, &a.CertSerial, &notAfter, &enrolled, &seen, &reported,
		&a.Hostname, &a.AgentVersion, &docker, &errs, &revoked); err != nil {
		return Agent{}, err
	}
	a.CertNotAfter, a.EnrolledAt = time.Unix(notAfter, 0), time.Unix(enrolled, 0)
	a.LastSeenAt, a.LastReportAt, a.RevokedAt = unixOrZero(seen), unixOrZero(reported), unixOrZero(revoked)
	if err := json.Unmarshal([]byte(docker), &a.Docker); err != nil {
		return Agent{}, fmt.Errorf("agent %s docker info: %w", a.ID, err)
	}
	if err := json.Unmarshal([]byte(errs), &a.ReportErrors); err != nil {
		return Agent{}, fmt.Errorf("agent %s report errors: %w", a.ID, err)
	}
	return a, nil
}

// AgentByPin returns the active agent whose key has the given pin.
func (s *Store) AgentByPin(ctx context.Context, pin string) (Agent, error) {
	a, err := scanAgent(s.db.QueryRowContext(ctx, `SELECT `+agentColumns+` FROM agents WHERE pin = ?`, pin))
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	if err != nil {
		return Agent{}, err
	}
	if !a.RevokedAt.IsZero() {
		return Agent{}, ErrRevoked
	}
	return a, nil
}

// Agents lists all agents by name.
func (s *Store) Agents(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RevokeAgent stops the named agent from authenticating. Its data is kept.
func (s *Store) RevokeAgent(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL`, time.Now().Unix(), name)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateAgentCert records a renewed certificate.
func (s *Store) UpdateAgentCert(ctx context.Context, agentID, serial string, notAfter time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET cert_serial = ?, cert_not_after = ? WHERE id = ?`, serial, notAfter.Unix(), agentID)
	return err
}

// SaveReport replaces the agent's inventory with the contents of a report.
func (s *Store) SaveReport(ctx context.Context, agentID string, r protocol.Report, received time.Time) (err error) {
	docker, err := json.Marshal(r.Docker)
	if err != nil {
		return err
	}
	errs, err := json.Marshal(nonNil(r.Errors))
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`UPDATE agents SET last_seen_at = ?, last_report_at = ?, hostname = ?, agent_version = ?, docker = ?, report_errors = ? WHERE id = ?`,
		received.Unix(), received.Unix(), r.Hostname, r.AgentVersion, string(docker), string(errs), agentID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM containers WHERE agent_id = ?`, agentID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM images WHERE agent_id = ?`, agentID); err != nil {
		return err
	}
	for _, c := range r.Containers {
		labels, err := json.Marshal(c.Labels)
		if err != nil {
			return err
		}
		var update sql.NullString
		if c.Update != nil {
			b, err := json.Marshal(c.Update)
			if err != nil {
				return err
			}
			update = sql.NullString{String: string(b), Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO containers
			(agent_id, id, name, image, image_id, state, status, health, restart_count, created, started_at,
			 compose_project, compose_service, labels, update_check)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			agentID, c.ID, c.Name, c.Image, c.ImageID, c.State, c.Status, c.Health, c.RestartCount,
			c.Created.Unix(), zeroOrUnix(c.StartedAt), c.ComposeProject, c.ComposeService, string(labels), update); err != nil {
			return fmt.Errorf("container %s: %w", c.Name, err)
		}
	}
	for _, img := range r.Images {
		tags, err := json.Marshal(nonNil(img.RepoTags))
		if err != nil {
			return err
		}
		digests, err := json.Marshal(nonNil(img.RepoDigests))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO images (agent_id, id, repo_tags, repo_digests, size_bytes, created)
			VALUES (?, ?, ?, ?, ?, ?)`,
			agentID, img.ID, string(tags), string(digests), img.SizeBytes, img.Created.Unix()); err != nil {
			return fmt.Errorf("image %s: %w", img.ID, err)
		}
	}
	return tx.Commit()
}

// Containers returns the agent's containers from its latest report.
func (s *Store) Containers(ctx context.Context, agentID string) ([]protocol.Container, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, image, image_id, state, status, health, restart_count,
		created, started_at, compose_project, compose_service, labels, update_check
		FROM containers WHERE agent_id = ? ORDER BY name`, agentID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []protocol.Container
	for rows.Next() {
		var c protocol.Container
		var created int64
		var started sql.NullInt64
		var labels string
		var update sql.NullString
		if err := rows.Scan(&c.ID, &c.Name, &c.Image, &c.ImageID, &c.State, &c.Status, &c.Health, &c.RestartCount,
			&created, &started, &c.ComposeProject, &c.ComposeService, &labels, &update); err != nil {
			return nil, err
		}
		c.Created, c.StartedAt = time.Unix(created, 0), unixOrZero(started)
		if err := json.Unmarshal([]byte(labels), &c.Labels); err != nil {
			return nil, fmt.Errorf("container %s labels: %w", c.Name, err)
		}
		if update.Valid {
			c.Update = new(protocol.UpdateCheck)
			if err := json.Unmarshal([]byte(update.String), c.Update); err != nil {
				return nil, fmt.Errorf("container %s update check: %w", c.Name, err)
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func hashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func unixOrZero(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.Unix(v.Int64, 0)
}

func zeroOrUnix(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.Unix(), Valid: true}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
