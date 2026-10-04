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

// schemaVulnsVersion changes when the SBOM, scan and findings tables change
// shape. Those tables hold only derived data, so a migration drops them and
// agents re-inventory; ignore rules and alert history are kept.
const schemaVulnsVersion = "2"

const schemaSettings = `
CREATE TABLE IF NOT EXISTS settings (
	key    TEXT PRIMARY KEY,
	value  TEXT NOT NULL
);
`

// SBOMs, scans and findings are keyed by agent as well as image: an agent's
// SBOM is trusted only for that agent's own containers, so a compromised
// agent cannot change another host's results.
const schemaVulns = `
CREATE TABLE IF NOT EXISTS sboms (
	agent_id    TEXT NOT NULL,
	image_id    TEXT NOT NULL,
	format      TEXT NOT NULL,
	generator   TEXT NOT NULL,
	size_bytes  INTEGER NOT NULL,
	document    BLOB NOT NULL,
	created_at  INTEGER NOT NULL,
	PRIMARY KEY (agent_id, image_id)
);
CREATE TABLE IF NOT EXISTS sbom_requests (
	agent_id      TEXT NOT NULL,
	image_id      TEXT NOT NULL,
	requested_at  INTEGER NOT NULL,
	failed_at     INTEGER,
	error         TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (agent_id, image_id)
);
CREATE TABLE IF NOT EXISTS scans (
	agent_id    TEXT NOT NULL,
	image_id    TEXT NOT NULL,
	db_version  TEXT NOT NULL,
	scanned_at  INTEGER NOT NULL,
	error       TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (agent_id, image_id)
);
CREATE TABLE IF NOT EXISTS findings (
	agent_id   TEXT NOT NULL,
	image_id   TEXT NOT NULL,
	vuln_id    TEXT NOT NULL,
	pkg        TEXT NOT NULL,
	installed  TEXT NOT NULL,
	fixed      TEXT NOT NULL DEFAULT '',
	status     TEXT NOT NULL DEFAULT '',
	severity   TEXT NOT NULL,
	title      TEXT NOT NULL DEFAULT '',
	url        TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (agent_id, image_id, vuln_id, pkg, installed)
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
`

// ErrUnsolicited rejects an SBOM upload the server did not ask this agent
// for.
var ErrUnsolicited = errors.New("no outstanding SBOM request for this agent and image")

func migrateVulns(db *sql.DB) error {
	if _, err := db.Exec(schemaSettings); err != nil {
		return err
	}
	var version string
	err := db.QueryRow(`SELECT value FROM settings WHERE key = 'schema_vulns'`).Scan(&version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if version != schemaVulnsVersion {
		for _, t := range []string{"sboms", "sbom_requests", "scans", "findings"} {
			if _, err := db.Exec(`DROP TABLE IF EXISTS ` + t); err != nil {
				return err
			}
		}
	}
	if _, err := db.Exec(schemaVulns + schemaRegistry); err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO settings (key, value) VALUES ('schema_vulns', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, schemaVulnsVersion)
	return err
}

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
		LEFT JOIN sboms b ON b.agent_id = c.agent_id AND b.image_id = c.image_id
		LEFT JOIN sbom_requests r ON r.agent_id = c.agent_id AND r.image_id = c.image_id
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
			INSERT INTO sbom_requests (agent_id, image_id, requested_at) VALUES (?, ?, ?)
			ON CONFLICT(agent_id, image_id) DO UPDATE SET requested_at = excluded.requested_at,
				failed_at = NULL, error = ''`, agentID, id, now.Unix()); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// SaveSBOM stores an uploaded SBOM, or records why the agent could not make
// one. It accepts only an image the server asked this agent for and still
// awaits, and consumes that request in the same transaction, so an agent can
// neither push unsolicited SBOMs nor replace one it already delivered. A new
// SBOM invalidates the image's previous scan for this agent.
func (s *Store) SaveSBOM(ctx context.Context, agentID string, up protocol.SBOMUpload, now time.Time) error {
	var doc []byte
	if up.Error == "" {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(up.Document); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		doc = buf.Bytes()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Claim the outstanding request; zero rows means none exists.
	var res sql.Result
	if up.Error != "" {
		res, err = tx.ExecContext(ctx, `UPDATE sbom_requests SET failed_at = ?, error = ?
			WHERE agent_id = ? AND image_id = ? AND failed_at IS NULL`,
			now.Unix(), truncate(up.Error, 2000), agentID, up.ImageID)
	} else {
		res, err = tx.ExecContext(ctx, `DELETE FROM sbom_requests
			WHERE agent_id = ? AND image_id = ? AND failed_at IS NULL`, agentID, up.ImageID)
	}
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return ErrUnsolicited
	}
	if up.Error == "" {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sboms (agent_id, image_id, format, generator, size_bytes, document, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(agent_id, image_id) DO UPDATE SET format = excluded.format, generator = excluded.generator,
				size_bytes = excluded.size_bytes, document = excluded.document, created_at = excluded.created_at`,
			agentID, up.ImageID, up.Format, up.Generator, len(up.Document), doc, now.Unix()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM scans WHERE agent_id = ? AND image_id = ?`, agentID, up.ImageID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SBOMKey identifies one agent's SBOM of one image.
type SBOMKey struct {
	AgentID, ImageID string
}

// LoadSBOM returns an SBOM document.
func (s *Store) LoadSBOM(ctx context.Context, key SBOMKey) ([]byte, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx, `SELECT document FROM sboms WHERE agent_id = ? AND image_id = ?`,
		key.AgentID, key.ImageID).Scan(&blob)
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

// SBOMsToScan returns SBOMs with no scan against dbVersion, preferring ones
// never scanned.
func (s *Store) SBOMsToScan(ctx context.Context, dbVersion string, limit int) ([]SBOMKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT b.agent_id, b.image_id FROM sboms b
		LEFT JOIN scans sc ON sc.agent_id = b.agent_id AND sc.image_id = b.image_id
		WHERE sc.image_id IS NULL OR sc.db_version != ?
		ORDER BY sc.image_id IS NOT NULL, b.created_at LIMIT ?`, dbVersion, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var keys []SBOMKey
	for rows.Next() {
		var k SBOMKey
		if err := rows.Scan(&k.AgentID, &k.ImageID); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
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
func (s *Store) SaveScan(ctx context.Context, key SBOMKey, dbVersion string, findings []Finding, scanErr string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO scans (agent_id, image_id, db_version, scanned_at, error) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(agent_id, image_id) DO UPDATE SET db_version = excluded.db_version, scanned_at = excluded.scanned_at, error = excluded.error`,
		key.AgentID, key.ImageID, dbVersion, now.Unix(), truncate(scanErr, 2000)); err != nil {
		return err
	}
	if scanErr == "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE agent_id = ? AND image_id = ?`, key.AgentID, key.ImageID); err != nil {
			return err
		}
		for _, f := range findings {
			if _, err := tx.ExecContext(ctx, `
				INSERT OR IGNORE INTO findings (agent_id, image_id, vuln_id, pkg, installed, fixed, status, severity, title, url)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				key.AgentID, key.ImageID, f.VulnID, f.Pkg, f.Installed, f.Fixed, f.Status, f.Severity, truncate(f.Title, 300), f.URL); err != nil {
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
		JOIN findings f ON f.agent_id = c.agent_id AND f.image_id = c.image_id
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
		LEFT JOIN scans sc ON sc.agent_id = c.agent_id AND sc.image_id = c.image_id
		LEFT JOIN sbom_requests r ON r.agent_id = c.agent_id AND r.image_id = c.image_id`)
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

// ScanFailure is a container whose image could not be inventoried or
// matched.
type ScanFailure struct {
	Host      string
	Container string
	Image     string
	ImageID   string
	Stage     string // "sbom" or "match"
	Error     string
	At        time.Time
}

// ScanFailures lists containers of active agents whose image's SBOM
// generation or matching failed.
func (s *Store) ScanFailures(ctx context.Context) ([]ScanFailure, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.name, c.name, c.image, c.image_id, 'sbom', r.error, r.failed_at
		FROM sbom_requests r
		JOIN agents a ON a.id = r.agent_id AND a.revoked_at IS NULL
		JOIN containers c ON c.agent_id = r.agent_id AND c.image_id = r.image_id
		WHERE r.failed_at IS NOT NULL
		UNION ALL
		SELECT a.name, c.name, c.image, c.image_id, 'match', sc.error, sc.scanned_at
		FROM scans sc
		JOIN agents a ON a.id = sc.agent_id AND a.revoked_at IS NULL
		JOIN containers c ON c.agent_id = sc.agent_id AND c.image_id = sc.image_id
		WHERE sc.error != ''
		ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ScanFailure
	for rows.Next() {
		var f ScanFailure
		var at int64
		if err := rows.Scan(&f.Host, &f.Container, &f.Image, &f.ImageID, &f.Stage, &f.Error, &at); err != nil {
			return nil, err
		}
		f.At = time.Unix(at, 0)
		out = append(out, f)
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

// ClearSuppressedAlerts forgets alerts for findings that an active ignore
// rule now covers, so they alert again if they are still present when the
// rule expires.
func (s *Store) ClearSuppressedAlerts(ctx context.Context, now time.Time) error {
	rules, err := s.Ignores(ctx, now)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM vuln_alerts
			WHERE vuln_id = ? AND (? = '' OR pkg = ?) AND (? = '' OR repository = ?)`,
			r.VulnID, r.Pkg, r.Pkg, r.Repository, r.Repository); err != nil {
			return err
		}
	}
	return nil
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
