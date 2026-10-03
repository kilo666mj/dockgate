package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"io"
	"strings"
	"time"

	"go.michaelspost.com/dockgate/internal/protocol"
)

const schemaVulns = `
CREATE TABLE IF NOT EXISTS sboms (
	image_id    TEXT PRIMARY KEY,
	format      TEXT NOT NULL,
	generator   TEXT NOT NULL,
	size_bytes  INTEGER NOT NULL,
	document    BLOB NOT NULL,
	agent_id    TEXT NOT NULL,
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sbom_requests (
	image_id      TEXT PRIMARY KEY,
	agent_id      TEXT NOT NULL,
	requested_at  INTEGER NOT NULL,
	failed_at     INTEGER,
	error         TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scans (
	image_id    TEXT PRIMARY KEY,
	db_version  TEXT NOT NULL,
	scanned_at  INTEGER NOT NULL,
	error       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
	image_id   TEXT NOT NULL,
	vuln_id    TEXT NOT NULL,
	pkg        TEXT NOT NULL,
	installed  TEXT NOT NULL,
	fixed      TEXT NOT NULL DEFAULT '',
	status     TEXT NOT NULL DEFAULT '',
	severity   TEXT NOT NULL,
	title      TEXT NOT NULL DEFAULT '',
	url        TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (image_id, vuln_id, pkg, installed)
);
CREATE TABLE IF NOT EXISTS vuln_ignores (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	vuln_id     TEXT NOT NULL,
	pkg         TEXT NOT NULL DEFAULT '',
	repository  TEXT NOT NULL DEFAULT '',
	reason      TEXT NOT NULL,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vuln_alerts (
	repository  TEXT NOT NULL,
	vuln_id     TEXT NOT NULL,
	pkg         TEXT NOT NULL,
	alerted_at  INTEGER NOT NULL,
	PRIMARY KEY (repository, vuln_id, pkg)
);
CREATE TABLE IF NOT EXISTS settings (
	key    TEXT PRIMARY KEY,
	value  TEXT NOT NULL
);
`

// SBOM request pacing. A request the agent does not list as pending is
// treated as lost after sbomGrace (the agent may not have reported since);
// for agents that do not report their queue, after sbomInFlight. A failed
// image is not retried for sbomRetryAfter.
const (
	sbomGrace      = 2 * time.Minute
	sbomInFlight   = 45 * time.Minute
	sbomRetryAfter = 6 * time.Hour
)

// AgentQueue is what an agent reported about its SBOM work.
type AgentQueue struct {
	Reports bool // the agent reports its queue
	Pending map[string]bool
}

// RequestSBOMs picks up to limit images used by the agent's containers that
// have no SBOM and no outstanding or recently failed request, and records
// the request.
func (s *Store) RequestSBOMs(ctx context.Context, agentID string, limit int, queue AgentQueue, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT c.image_id, r.requested_at, r.failed_at FROM containers c
		LEFT JOIN sboms b ON b.image_id = c.image_id
		LEFT JOIN sbom_requests r ON r.image_id = c.image_id
		WHERE c.agent_id = ? AND c.image_id LIKE 'sha256:%' AND b.image_id IS NULL
		ORDER BY c.image_id`, agentID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		var requested, failed sql.NullInt64
		if err := rows.Scan(&id, &requested, &failed); err != nil {
			_ = rows.Close()
			return nil, err
		}
		switch {
		case len(ids) >= limit:
		case failed.Valid:
			if now.Sub(time.Unix(failed.Int64, 0)) >= sbomRetryAfter {
				ids = append(ids, id)
			}
		case !requested.Valid:
			ids = append(ids, id)
		case queue.Reports && queue.Pending[id]:
		case queue.Reports && now.Sub(time.Unix(requested.Int64, 0)) >= sbomGrace:
			ids = append(ids, id)
		case !queue.Reports && now.Sub(time.Unix(requested.Int64, 0)) >= sbomInFlight:
			ids = append(ids, id)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO sbom_requests (image_id, agent_id, requested_at) VALUES (?, ?, ?)
			ON CONFLICT(image_id) DO UPDATE SET agent_id = excluded.agent_id, requested_at = excluded.requested_at,
				failed_at = NULL, error = ''`, id, agentID, now.Unix()); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// SaveSBOM stores an uploaded SBOM, or records why the agent could not make
// one. A new SBOM invalidates the image's previous scan.
func (s *Store) SaveSBOM(ctx context.Context, agentID string, up protocol.SBOMUpload, now time.Time) error {
	if up.Error != "" {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO sbom_requests (image_id, agent_id, requested_at, failed_at, error) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(image_id) DO UPDATE SET failed_at = excluded.failed_at, error = excluded.error`,
			up.ImageID, agentID, now.Unix(), now.Unix(), truncate(up.Error, 2000))
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(up.Document); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO sboms (image_id, format, generator, size_bytes, document, agent_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(image_id) DO UPDATE SET format = excluded.format, generator = excluded.generator,
			size_bytes = excluded.size_bytes, document = excluded.document, agent_id = excluded.agent_id,
			created_at = excluded.created_at`,
		up.ImageID, up.Format, up.Generator, len(up.Document), buf.Bytes(), agentID, now.Unix()); err != nil {
		return err
	}
	for _, q := range []string{`DELETE FROM sbom_requests WHERE image_id = ?`, `DELETE FROM scans WHERE image_id = ?`} {
		if _, err := tx.ExecContext(ctx, q, up.ImageID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadSBOM returns an image's SBOM document.
func (s *Store) LoadSBOM(ctx context.Context, imageID string) ([]byte, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx, `SELECT document FROM sboms WHERE image_id = ?`, imageID).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	doc, err := io.ReadAll(zr)
	return doc, errors.Join(err, zr.Close())
}

// SBOMsToScan returns images with an SBOM but no scan against dbVersion,
// preferring images that have never been scanned.
func (s *Store) SBOMsToScan(ctx context.Context, dbVersion string, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT b.image_id FROM sboms b LEFT JOIN scans sc ON sc.image_id = b.image_id
		WHERE sc.image_id IS NULL OR sc.db_version != ?
		ORDER BY sc.image_id IS NOT NULL, b.created_at LIMIT ?`, dbVersion, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Finding is one vulnerability in one package of one image.
type Finding struct {
	VulnID    string
	Pkg       string
	Installed string
	Fixed     string
	Status    string
	Severity  string
	Title     string
	URL       string
}

// Fixable reports whether a fixed version exists.
func (f Finding) Fixable() bool { return f.Fixed != "" }

// SaveScan replaces an image's findings with the result of matching its SBOM
// against dbVersion. A non-empty scanErr records a failed match instead.
func (s *Store) SaveScan(ctx context.Context, imageID, dbVersion string, findings []Finding, scanErr string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO scans (image_id, db_version, scanned_at, error) VALUES (?, ?, ?, ?)
		ON CONFLICT(image_id) DO UPDATE SET db_version = excluded.db_version, scanned_at = excluded.scanned_at, error = excluded.error`,
		imageID, dbVersion, now.Unix(), truncate(scanErr, 2000)); err != nil {
		return err
	}
	if scanErr == "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE image_id = ?`, imageID); err != nil {
			return err
		}
		for _, f := range findings {
			if _, err := tx.ExecContext(ctx, `
				INSERT OR IGNORE INTO findings (image_id, vuln_id, pkg, installed, fixed, status, severity, title, url)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				imageID, f.VulnID, f.Pkg, f.Installed, f.Fixed, f.Status, f.Severity, truncate(f.Title, 300), f.URL); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// HostFinding is a finding in an image a container currently uses.
type HostFinding struct {
	Host      string
	Container string
	Image     string // the container's image reference
	ImageID   string
	Finding
}

// ScanCoverage counts an agent's containers by scan state.
type ScanCoverage struct {
	Containers int
	Scanned    int
	Pending    int // no SBOM or scan yet
	Failed     int // SBOM generation or matching failed
}

// ActiveFindings returns findings for images used by containers of active
// agents, with ignore rules applied. host may be empty for every agent.
func (s *Store) ActiveFindings(ctx context.Context, host string, now time.Time) ([]HostFinding, error) {
	ignores, err := s.Ignores(ctx, now)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.name, c.name, c.image, c.image_id, f.vuln_id, f.pkg, f.installed, f.fixed, f.status, f.severity, f.title, f.url
		FROM containers c
		JOIN agents a ON a.id = c.agent_id AND a.revoked_at IS NULL
		JOIN findings f ON f.image_id = c.image_id
		WHERE (? = '' OR a.name = ?)
		ORDER BY a.name, c.name, f.severity, f.vuln_id`, host, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []HostFinding
	for rows.Next() {
		var hf HostFinding
		if err := rows.Scan(&hf.Host, &hf.Container, &hf.Image, &hf.ImageID, &hf.VulnID, &hf.Pkg, &hf.Installed,
			&hf.Fixed, &hf.Status, &hf.Severity, &hf.Title, &hf.URL); err != nil {
			return nil, err
		}
		if !ignored(ignores, hf) {
			out = append(out, hf)
		}
	}
	return out, rows.Err()
}

// Coverage reports, per agent name, how many containers' images are scanned.
func (s *Store) Coverage(ctx context.Context) (map[string]ScanCoverage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.name,
			sc.image_id IS NOT NULL AND sc.error = '',
			(r.failed_at IS NOT NULL) OR (sc.image_id IS NOT NULL AND sc.error != '')
		FROM containers c
		JOIN agents a ON a.id = c.agent_id AND a.revoked_at IS NULL
		LEFT JOIN scans sc ON sc.image_id = c.image_id
		LEFT JOIN sbom_requests r ON r.image_id = c.image_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]ScanCoverage{}
	for rows.Next() {
		var name string
		var scanned, failed bool
		if err := rows.Scan(&name, &scanned, &failed); err != nil {
			return nil, err
		}
		cov := out[name]
		cov.Containers++
		switch {
		case scanned:
			cov.Scanned++
		case failed:
			cov.Failed++
		default:
			cov.Pending++
		}
		out[name] = cov
	}
	return out, rows.Err()
}

// Ignore suppresses a vulnerability, optionally only for one package or one
// image repository, until it expires.
type Ignore struct {
	ID         int64
	VulnID     string
	Pkg        string
	Repository string
	Reason     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// AddIgnore stores an ignore rule and returns its ID.
func (s *Store) AddIgnore(ctx context.Context, ig Ignore) (int64, error) {
	if ig.VulnID == "" || strings.TrimSpace(ig.Reason) == "" || ig.ExpiresAt.IsZero() {
		return 0, errors.New("an ignore needs a vulnerability ID, a reason and an expiry")
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO vuln_ignores (vuln_id, pkg, repository, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		ig.VulnID, ig.Pkg, ig.Repository, ig.Reason, time.Now().Unix(), ig.ExpiresAt.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Ignores lists rules that have not expired at now; a zero now lists all.
func (s *Store) Ignores(ctx context.Context, now time.Time) ([]Ignore, error) {
	after := int64(0)
	if !now.IsZero() {
		after = now.Unix()
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, vuln_id, pkg, repository, reason, created_at, expires_at FROM vuln_ignores
		WHERE expires_at > ? ORDER BY id`, after)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Ignore
	for rows.Next() {
		var ig Ignore
		var created, expires int64
		if err := rows.Scan(&ig.ID, &ig.VulnID, &ig.Pkg, &ig.Repository, &ig.Reason, &created, &expires); err != nil {
			return nil, err
		}
		ig.CreatedAt, ig.ExpiresAt = time.Unix(created, 0), time.Unix(expires, 0)
		out = append(out, ig)
	}
	return out, rows.Err()
}

// RemoveIgnore deletes an ignore rule.
func (s *Store) RemoveIgnore(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM vuln_ignores WHERE id = ?`, id)
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

func ignored(rules []Ignore, f HostFinding) bool {
	repo := Repository(f.Image)
	for _, r := range rules {
		if r.VulnID == f.VulnID && (r.Pkg == "" || r.Pkg == f.Pkg) && (r.Repository == "" || r.Repository == repo) {
			return true
		}
	}
	return false
}

// Repository returns an image reference without its tag or digest, for
// example "ghcr.io/example/app" for "ghcr.io/example/app:1.2@sha256:...".
func Repository(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}

// AlertKey identifies a finding for alert de-duplication. Keying on the
// repository rather than the image means an update that does not fix a
// vulnerability does not alert again.
type AlertKey struct {
	Repository, VulnID, Pkg string
}

// Alerted returns the set of keys already alerted on.
func (s *Store) Alerted(ctx context.Context) (map[AlertKey]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT repository, vuln_id, pkg FROM vuln_alerts`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[AlertKey]bool{}
	for rows.Next() {
		var k AlertKey
		if err := rows.Scan(&k.Repository, &k.VulnID, &k.Pkg); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}

// MarkAlerted records keys as alerted on.
func (s *Store) MarkAlerted(ctx context.Context, keys []AlertKey, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, k := range keys {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO vuln_alerts (repository, vuln_id, pkg, alerted_at) VALUES (?, ?, ?, ?)`,
			k.Repository, k.VulnID, k.Pkg, now.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Setting returns a stored setting, or "" when unset.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting stores a setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
