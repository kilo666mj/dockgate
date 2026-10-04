package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"go.michaelspost.com/dockgate/internal/protocol"
)

// The server scans some images straight from their registry: update
// candidates (the image a tag now points to), and images an agent could not
// inventory. Candidate data is keyed by manifest digest and platform because
// it describes no running container.
const schemaRegistry = `
CREATE TABLE IF NOT EXISTS candidate_sboms (
	digest      TEXT NOT NULL,
	platform    TEXT NOT NULL,
	reference   TEXT NOT NULL,
	document    BLOB,
	created_at  INTEGER NOT NULL,
	failed_at   INTEGER,
	error       TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (digest, platform)
);
CREATE TABLE IF NOT EXISTS candidate_scans (
	digest      TEXT NOT NULL,
	platform    TEXT NOT NULL,
	db_version  TEXT NOT NULL,
	scanned_at  INTEGER NOT NULL,
	error       TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (digest, platform)
);
CREATE TABLE IF NOT EXISTS candidate_findings (
	digest     TEXT NOT NULL,
	platform   TEXT NOT NULL,
	vuln_id    TEXT NOT NULL,
	pkg        TEXT NOT NULL,
	installed  TEXT NOT NULL,
	fixed      TEXT NOT NULL DEFAULT '',
	status     TEXT NOT NULL DEFAULT '',
	severity   TEXT NOT NULL,
	title      TEXT NOT NULL DEFAULT '',
	url        TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (digest, platform, vuln_id, pkg, installed)
);
`

// registryRetryAfter paces retries of failed registry SBOMs.
const registryRetryAfter = 6 * time.Hour

// fallbackPrefix marks a failed registry fallback in sbom_requests.error.
const fallbackPrefix = "registry fallback: "

// RegistryTarget is an image the server should inventory from its registry.
type RegistryTarget struct {
	Reference string // repository@sha256:...
	Digest    string
	Platform  string // os/arch, e.g. linux/arm64
	// AgentID and ImageID are set for a fallback, naming the agent slot the
	// SBOM fills.
	AgentID string
	ImageID string
}

// CandidateKey identifies an update candidate image.
type CandidateKey struct {
	Digest, Platform string
}

func platformOf(a Agent) string {
	osName, arch := a.Docker.OS, a.Docker.Arch
	if osName == "" {
		osName = "linux"
	}
	if arch == "" {
		arch = "amd64"
	}
	return osName + "/" + arch
}

// CandidateTargets returns update candidates (containers whose tag points to
// a newer image) that have no candidate SBOM yet and no recent failure.
func (s *Store) CandidateTargets(ctx context.Context, limit int, now time.Time) ([]RegistryTarget, error) {
	agents, err := s.Agents(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[CandidateKey]bool{}
	var out []RegistryTarget
	for _, a := range agents {
		if !a.RevokedAt.IsZero() {
			continue
		}
		containers, err := s.Containers(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		for _, c := range containers {
			u := c.Update
			if u == nil || u.Status != protocol.UpdateAvailable || !strings.HasPrefix(u.RemoteDigest, "sha256:") {
				continue
			}
			key := CandidateKey{Digest: u.RemoteDigest, Platform: platformOf(a)}
			if seen[key] {
				continue
			}
			seen[key] = true
			var hasDoc bool
			var failed sql.NullInt64
			err := s.db.QueryRowContext(ctx, `SELECT document IS NOT NULL, failed_at FROM candidate_sboms WHERE digest = ? AND platform = ?`,
				key.Digest, key.Platform).Scan(&hasDoc, &failed)
			switch {
			case errors.Is(err, sql.ErrNoRows):
			case err != nil:
				return nil, err
			case hasDoc:
				continue
			case failed.Valid && now.Sub(time.Unix(failed.Int64, 0)) < registryRetryAfter:
				continue
			}
			out = append(out, RegistryTarget{Reference: Repository(u.Reference) + "@" + key.Digest, Digest: key.Digest, Platform: key.Platform})
			if len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}

// SaveCandidateSBOM stores a candidate's SBOM, or why it could not be made.
func (s *Store) SaveCandidateSBOM(ctx context.Context, t RegistryTarget, doc []byte, genErr string, now time.Time) error {
	if genErr != "" {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO candidate_sboms (digest, platform, reference, created_at, failed_at, error) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(digest, platform) DO UPDATE SET failed_at = excluded.failed_at, error = excluded.error`,
			t.Digest, t.Platform, t.Reference, now.Unix(), now.Unix(), truncate(genErr, 2000))
		return err
	}
	blob, err := gzipBytes(doc)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO candidate_sboms (digest, platform, reference, document, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(digest, platform) DO UPDATE SET reference = excluded.reference, document = excluded.document,
			created_at = excluded.created_at, failed_at = NULL, error = ''`,
		t.Digest, t.Platform, t.Reference, blob, now.Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM candidate_scans WHERE digest = ? AND platform = ?`, t.Digest, t.Platform); err != nil {
		return err
	}
	return tx.Commit()
}

// CandidatesToScan returns candidate SBOMs not yet matched against dbVersion.
func (s *Store) CandidatesToScan(ctx context.Context, dbVersion string, limit int) ([]CandidateKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT b.digest, b.platform FROM candidate_sboms b
		LEFT JOIN candidate_scans sc ON sc.digest = b.digest AND sc.platform = b.platform
		WHERE b.document IS NOT NULL AND (sc.digest IS NULL OR sc.db_version != ?)
		ORDER BY sc.digest IS NOT NULL, b.created_at LIMIT ?`, dbVersion, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []CandidateKey
	for rows.Next() {
		var k CandidateKey
		if err := rows.Scan(&k.Digest, &k.Platform); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// LoadCandidateSBOM returns a candidate's SBOM document.
func (s *Store) LoadCandidateSBOM(ctx context.Context, k CandidateKey) ([]byte, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx, `SELECT document FROM candidate_sboms WHERE digest = ? AND platform = ? AND document IS NOT NULL`,
		k.Digest, k.Platform).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return gunzipBytes(blob)
}

// SaveCandidateScan replaces a candidate's findings.
func (s *Store) SaveCandidateScan(ctx context.Context, k CandidateKey, dbVersion string, findings []Finding, scanErr string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO candidate_scans (digest, platform, db_version, scanned_at, error) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(digest, platform) DO UPDATE SET db_version = excluded.db_version, scanned_at = excluded.scanned_at, error = excluded.error`,
		k.Digest, k.Platform, dbVersion, now.Unix(), truncate(scanErr, 2000)); err != nil {
		return err
	}
	if scanErr == "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM candidate_findings WHERE digest = ? AND platform = ?`, k.Digest, k.Platform); err != nil {
			return err
		}
		for _, f := range findings {
			if _, err := tx.ExecContext(ctx, `
				INSERT OR IGNORE INTO candidate_findings (digest, platform, vuln_id, pkg, installed, fixed, status, severity, title, url)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				k.Digest, k.Platform, f.VulnID, f.Pkg, f.Installed, f.Fixed, f.Status, f.Severity, truncate(f.Title, 300), f.URL); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// FallbackTargets returns containers whose agent could not inventory the
// image, whose image has a registry digest, and that have no recent failed
// fallback. The server then inventories the image from the registry.
func (s *Store) FallbackTargets(ctx context.Context, limit int, now time.Time) ([]RegistryTarget, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.agent_id, r.image_id, r.error, r.failed_at FROM sbom_requests r
		JOIN agents a ON a.id = r.agent_id AND a.revoked_at IS NULL
		LEFT JOIN sboms b ON b.agent_id = r.agent_id AND b.image_id = r.image_id
		WHERE r.failed_at IS NOT NULL AND b.image_id IS NULL`)
	if err != nil {
		return nil, err
	}
	type cand struct {
		agentID, imageID string
	}
	var cands []cand
	for rows.Next() {
		var c cand
		var errText string
		var failed int64
		if err := rows.Scan(&c.agentID, &c.imageID, &errText, &failed); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if strings.HasPrefix(errText, fallbackPrefix) && now.Sub(time.Unix(failed, 0)) < registryRetryAfter {
			continue
		}
		cands = append(cands, c)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	agents, err := s.Agents(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[string]Agent{}
	for _, a := range agents {
		byID[a.ID] = a
	}
	var out []RegistryTarget
	for _, c := range cands {
		containers, err := s.Containers(ctx, c.agentID)
		if err != nil {
			return nil, err
		}
		for _, ctr := range containers {
			if ctr.ImageID != c.imageID || ctr.Update == nil || len(ctr.Update.LocalDigests) == 0 {
				continue
			}
			digest := ctr.Update.LocalDigests[0]
			out = append(out, RegistryTarget{
				Reference: Repository(ctr.Update.Reference) + "@" + digest, Digest: digest,
				Platform: platformOf(byID[c.agentID]), AgentID: c.agentID, ImageID: c.imageID,
			})
			break
		}
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// SaveFallbackSBOM fills an agent's SBOM slot with an SBOM the server made
// from the registry image the agent reported (by its local repository
// digest), or records why that failed. The server trusts its own registry
// fetch, so no agent request is involved.
func (s *Store) SaveFallbackSBOM(ctx context.Context, t RegistryTarget, doc []byte, generator, genErr string, now time.Time) error {
	if genErr != "" {
		_, err := s.db.ExecContext(ctx, `UPDATE sbom_requests SET failed_at = ?, error = ? WHERE agent_id = ? AND image_id = ?`,
			now.Unix(), truncate(fallbackPrefix+genErr, 2000), t.AgentID, t.ImageID)
		return err
	}
	blob, err := gzipBytes(doc)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO sboms (agent_id, image_id, format, generator, size_bytes, document, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(agent_id, image_id) DO UPDATE SET format = excluded.format, generator = excluded.generator,
			size_bytes = excluded.size_bytes, document = excluded.document, created_at = excluded.created_at`,
		t.AgentID, t.ImageID, protocol.FormatCycloneDXJSON, generator, len(doc), blob, now.Unix()); err != nil {
		return err
	}
	for _, q := range []string{`DELETE FROM sbom_requests WHERE agent_id = ? AND image_id = ?`, `DELETE FROM scans WHERE agent_id = ? AND image_id = ?`} {
		if _, err := tx.ExecContext(ctx, q, t.AgentID, t.ImageID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ImpactFinding is one critical or high vulnerability in an update
// comparison.
type ImpactFinding struct {
	VulnID   string `json:"vulnerability"`
	Pkg      string `json:"package"`
	Severity string `json:"severity"`
	Fixed    string `json:"fixed,omitempty"`
}

// UpdateImpact compares a container's current image with its update
// candidate on critical and high findings, after ignore rules.
type UpdateImpact struct {
	Host          string          `json:"host"`
	Container     string          `json:"container"`
	Image         string          `json:"image"`
	CurrentDigest string          `json:"current_digest,omitempty"`
	RemoteDigest  string          `json:"remote_digest"`
	Platform      string          `json:"platform"`
	Status        string          `json:"status"` // assessed, pending, failed
	Error         string          `json:"error,omitempty"`
	Fixes         []ImpactFinding `json:"fixes"`
	Introduces    []ImpactFinding `json:"introduces"`
	Remaining     int             `json:"remaining"`
	// Actionable means the update fixes critical or high findings without
	// introducing a new critical one.
	Actionable bool `json:"actionable"`
}

// UpdateImpacts assesses every container with an available update. host may
// be empty for every agent.
func (s *Store) UpdateImpacts(ctx context.Context, host string, now time.Time) ([]UpdateImpact, error) {
	agents, err := s.Agents(ctx)
	if err != nil {
		return nil, err
	}
	findings, err := s.ActiveFindings(ctx, host, now)
	if err != nil {
		return nil, err
	}
	rules, err := s.Ignores(ctx, now)
	if err != nil {
		return nil, err
	}
	current := map[string]map[string]ImpactFinding{} // host|container -> key -> finding
	for _, f := range findings {
		if f.Severity != "CRITICAL" && f.Severity != "HIGH" {
			continue
		}
		k := f.Host + "|" + f.Container
		if current[k] == nil {
			current[k] = map[string]ImpactFinding{}
		}
		current[k][f.VulnID+"|"+f.Pkg] = ImpactFinding{VulnID: f.VulnID, Pkg: f.Pkg, Severity: f.Severity, Fixed: f.Fixed}
	}
	var out []UpdateImpact
	for _, a := range agents {
		if !a.RevokedAt.IsZero() || (host != "" && a.Name != host) {
			continue
		}
		containers, err := s.Containers(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		for _, c := range containers {
			u := c.Update
			if u == nil || u.Status != protocol.UpdateAvailable {
				continue
			}
			imp := UpdateImpact{Host: a.Name, Container: c.Name, Image: u.Reference, RemoteDigest: u.RemoteDigest,
				Platform: platformOf(a), Fixes: []ImpactFinding{}, Introduces: []ImpactFinding{}}
			if len(u.LocalDigests) > 0 {
				imp.CurrentDigest = u.LocalDigests[0]
			}
			cand, status, errText, err := s.candidateFindings(ctx, CandidateKey{Digest: u.RemoteDigest, Platform: imp.Platform})
			if err != nil {
				return nil, err
			}
			imp.Status, imp.Error = status, errText
			if status == "assessed" {
				have := current[a.Name+"|"+c.Name]
				next := map[string]ImpactFinding{}
				for _, f := range cand {
					hf := HostFinding{Host: a.Name, Container: c.Name, Image: c.Image, ImageID: c.ImageID, Finding: f}
					if (f.Severity == "CRITICAL" || f.Severity == "HIGH") && !ignored(rules, hf) {
						next[f.VulnID+"|"+f.Pkg] = ImpactFinding{VulnID: f.VulnID, Pkg: f.Pkg, Severity: f.Severity, Fixed: f.Fixed}
					}
				}
				newCritical := false
				for k, f := range have {
					if _, ok := next[k]; ok {
						imp.Remaining++
					} else {
						imp.Fixes = append(imp.Fixes, f)
					}
				}
				for k, f := range next {
					if _, ok := have[k]; !ok {
						imp.Introduces = append(imp.Introduces, f)
						newCritical = newCritical || f.Severity == "CRITICAL"
					}
				}
				sortImpact(imp.Fixes)
				sortImpact(imp.Introduces)
				imp.Actionable = len(imp.Fixes) > 0 && !newCritical
			}
			out = append(out, imp)
		}
	}
	return out, nil
}

func (s *Store) candidateFindings(ctx context.Context, k CandidateKey) ([]Finding, string, string, error) {
	var sbomErr string
	var hasDoc bool
	err := s.db.QueryRowContext(ctx, `SELECT document IS NOT NULL, error FROM candidate_sboms WHERE digest = ? AND platform = ?`,
		k.Digest, k.Platform).Scan(&hasDoc, &sbomErr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "pending", "", nil
	}
	if err != nil {
		return nil, "", "", err
	}
	if !hasDoc {
		return nil, "failed", sbomErr, nil
	}
	var scanErr string
	err = s.db.QueryRowContext(ctx, `SELECT error FROM candidate_scans WHERE digest = ? AND platform = ?`, k.Digest, k.Platform).Scan(&scanErr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "pending", "", nil
	}
	if err != nil {
		return nil, "", "", err
	}
	if scanErr != "" {
		return nil, "failed", scanErr, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT vuln_id, pkg, installed, fixed, status, severity, title, url
		FROM candidate_findings WHERE digest = ? AND platform = ?`, k.Digest, k.Platform)
	if err != nil {
		return nil, "", "", err
	}
	defer func() { _ = rows.Close() }()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.VulnID, &f.Pkg, &f.Installed, &f.Fixed, &f.Status, &f.Severity, &f.Title, &f.URL); err != nil {
			return nil, "", "", err
		}
		out = append(out, f)
	}
	return out, "assessed", "", rows.Err()
}

func sortImpact(fs []ImpactFinding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity == "CRITICAL"
		}
		if fs[i].VulnID != fs[j].VulnID {
			return fs[i].VulnID < fs[j].VulnID
		}
		return fs[i].Pkg < fs[j].Pkg
	})
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzipBytes(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(zr)
	return out, errors.Join(err, zr.Close())
}
