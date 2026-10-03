package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go.michaelspost.com/dockgate/internal/protocol"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func signer(serial string) func(string) (Issued, error) {
	return func(string) (Issued, error) {
		return Issued{Serial: serial, NotAfter: time.Now().Add(time.Hour), PEM: []byte("cert")}, nil
	}
}

func TestEnrollTokenRules(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.CreateToken(ctx, "t1", "secret", "bravo", false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, "t1", "wrong", "pin1", "agt_1", signer("1")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("wrong secret: err = %v", err)
	}
	a, _, err := s.Enroll(ctx, "t1", "secret", "pin1", "agt_1", signer("1"))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "agt_1" || a.Name != "bravo" {
		t.Fatalf("agent = %+v", a)
	}
	if _, _, err := s.Enroll(ctx, "t1", "secret", "pin2", "agt_2", signer("2")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("reused token: err = %v", err)
	}

	// A second agent with the same name needs a replace token.
	if err := s.CreateToken(ctx, "t2", "secret", "bravo", false, time.Hour); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("duplicate name token: err = %v", err)
	}
	if err := s.CreateToken(ctx, "t3", "secret", "bravo", true, time.Hour); err != nil {
		t.Fatal(err)
	}
	a, _, err = s.Enroll(ctx, "t3", "secret", "pin3", "agt_new", signer("3"))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "agt_1" || a.Pin != "pin3" {
		t.Fatalf("re-key kept id %s pin %s, want agt_1 pin3", a.ID, a.Pin)
	}
	if _, err := s.AgentByPin(ctx, "pin1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old pin after re-key: err = %v", err)
	}
}

func TestExpiredToken(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.CreateToken(ctx, "t1", "secret", "charlie", false, -time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, "t1", "secret", "pin", "agt_1", signer("1")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired token: err = %v", err)
	}
}

func TestSigningFailureLeavesTokenUnused(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.CreateToken(ctx, "t1", "secret", "charlie", false, time.Hour); err != nil {
		t.Fatal(err)
	}
	failing := func(string) (Issued, error) { return Issued{}, errors.New("CA unavailable") }
	if _, _, err := s.Enroll(ctx, "t1", "secret", "pin", "agt_1", failing); err == nil {
		t.Fatal("enroll succeeded with failing signer")
	}
	if _, _, err := s.Enroll(ctx, "t1", "secret", "pin", "agt_1", signer("1")); err != nil {
		t.Fatalf("retry after signing failure: %v", err)
	}
}

func TestRevokeAndReenroll(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.CreateToken(ctx, "t1", "secret", "alpha", false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, "t1", "secret", "pin1", "agt_1", signer("1")); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAgent(ctx, "alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AgentByPin(ctx, "pin1"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked agent: err = %v", err)
	}
	if err := s.RevokeAgent(ctx, "alpha"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: err = %v", err)
	}
	// A revoked name can be enrolled again without -replace.
	if err := s.CreateToken(ctx, "t2", "secret", "alpha", false, time.Hour); err != nil {
		t.Fatal(err)
	}
	a, _, err := s.Enroll(ctx, "t2", "secret", "pin2", "agt_2", signer("2"))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "agt_1" {
		t.Fatalf("re-enrolled id = %s, want agt_1", a.ID)
	}
	if _, err := s.AgentByPin(ctx, "pin2"); err != nil {
		t.Fatalf("re-enrolled agent: %v", err)
	}
}

func TestSaveReportReplacesInventory(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.CreateToken(ctx, "t1", "secret", "alpha", false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, "t1", "secret", "pin", "agt_1", signer("1")); err != nil {
		t.Fatal(err)
	}
	report := protocol.Report{
		Hostname: "alpha", AgentVersion: "v0.1.0", Docker: protocol.DockerInfo{Version: "29.1.0"},
		Containers: []protocol.Container{
			{ID: "c1", Name: "redis", Image: "valkey/valkey:latest", State: "running", Created: time.Unix(1, 0),
				Update: &protocol.UpdateCheck{Status: protocol.UpdateAvailable, Reference: "valkey/valkey:latest"}},
			{ID: "c2", Name: "searxng", Image: "searxng/searxng:latest", State: "exited", Created: time.Unix(1, 0)},
		},
		Images: []protocol.Image{{ID: "sha256:x", RepoTags: []string{"valkey/valkey:latest"}}},
		Errors: []string{"inspect c3: gone"},
	}
	if err := s.SaveReport(ctx, "agt_1", report, time.Now()); err != nil {
		t.Fatal(err)
	}
	report.Containers = report.Containers[:1]
	if err := s.SaveReport(ctx, "agt_1", report, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := s.Containers(ctx, "agt_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "redis" || got[0].Update == nil || got[0].Update.Status != protocol.UpdateAvailable {
		t.Fatalf("containers = %+v", got)
	}
	agents, err := s.Agents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a := agents[0]; a.AgentVersion != "v0.1.0" || a.Docker.Version != "29.1.0" || len(a.ReportErrors) != 1 || a.LastReportAt.IsZero() {
		t.Fatalf("agent = %+v", a)
	}
}
