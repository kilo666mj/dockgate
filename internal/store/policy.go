package store

import (
	"context"
	"time"
)

const schemaPolicy = `
CREATE TABLE IF NOT EXISTS policy_violations (
	agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	container   TEXT NOT NULL,
	rule        TEXT NOT NULL,
	detail      TEXT NOT NULL,
	first_seen  INTEGER NOT NULL,
	PRIMARY KEY (agent_id, container, rule)
);
`

// PolicyViolation is one policy rule a container breaks. Container is the
// container's name, so the violation survives the container being recreated.
type PolicyViolation struct {
	Container string
	Rule      string
	Detail    string
	FirstSeen time.Time
}

// SavePolicyViolations replaces the agent's violations with vs, keeping
// FirstSeen for those it already had.
func (s *Store) SavePolicyViolations(ctx context.Context, agentID string, vs []PolicyViolation, now time.Time) error {
	old, err := s.PolicyViolations(ctx, agentID)
	if err != nil {
		return err
	}
	first := map[[2]string]time.Time{}
	for _, v := range old {
		first[[2]string{v.Container, v.Rule}] = v.FirstSeen
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_violations WHERE agent_id = ?`, agentID); err != nil {
		return err
	}
	for _, v := range vs {
		seen, ok := first[[2]string{v.Container, v.Rule}]
		if !ok {
			seen = now
		}
		// Two containers cannot share a name, but a report is agent input.
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO policy_violations (agent_id, container, rule, detail, first_seen)
			VALUES (?, ?, ?, ?, ?)`, agentID, v.Container, v.Rule, v.Detail, seen.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PolicyViolations returns the agent's current violations by container and
// rule.
func (s *Store) PolicyViolations(ctx context.Context, agentID string) ([]PolicyViolation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT container, rule, detail, first_seen FROM policy_violations
		WHERE agent_id = ? ORDER BY container, rule`, agentID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PolicyViolation
	for rows.Next() {
		var v PolicyViolation
		var seen int64
		if err := rows.Scan(&v.Container, &v.Rule, &v.Detail, &seen); err != nil {
			return nil, err
		}
		v.FirstSeen = time.Unix(seen, 0)
		out = append(out, v)
	}
	return out, rows.Err()
}
