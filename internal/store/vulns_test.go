package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go.michaelspost.com/dockgate/internal/protocol"
)

func enrolledWithContainers(t *testing.T, s *Store, name string, containers ...protocol.Container) string {
	t.Helper()
	ctx := context.Background()
	id := "agt_" + name
	if err := s.CreateToken(ctx, "t-"+name, "secret", name, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, "t-"+name, "secret", "pin-"+name, id, signer("1")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveReport(ctx, id, protocol.Report{Containers: containers}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRequestSBOMsPacing(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id := enrolledWithContainers(t, s, "alpha",
		protocol.Container{ID: "c1", Name: "a", Image: "x:1", ImageID: "sha256:aaa"},
		protocol.Container{ID: "c2", Name: "b", Image: "x:1", ImageID: "sha256:aaa"},
		protocol.Container{ID: "c3", Name: "c", Image: "y:1", ImageID: "sha256:bbb"},
	)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

	ids, err := s.RequestSBOMs(ctx, id, 5, AgentQueue{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("first request = %v, want both distinct images", ids)
	}
	if ids, _ := s.RequestSBOMs(ctx, id, 5, AgentQueue{}, now.Add(time.Minute)); len(ids) != 0 {
		t.Fatalf("in-flight images requested again: %v", ids)
	}
	if err := s.SaveSBOM(ctx, id, protocol.SBOMUpload{ImageID: "sha256:aaa", Format: protocol.FormatCycloneDXJSON, Document: []byte(`{"a":1}`)}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSBOM(ctx, id, protocol.SBOMUpload{ImageID: "sha256:bbb", Error: "scanner exited 1"}, now); err != nil {
		t.Fatal(err)
	}
	if ids, _ := s.RequestSBOMs(ctx, id, 5, AgentQueue{}, now.Add(time.Hour)); len(ids) != 0 {
		t.Fatalf("failed image retried too soon: %v", ids)
	}
	if ids, _ := s.RequestSBOMs(ctx, id, 5, AgentQueue{}, now.Add(7*time.Hour)); len(ids) != 1 || ids[0] != "sha256:bbb" {
		t.Fatalf("failed image not retried after backoff: %v", ids)
	}
	doc, err := s.LoadSBOM(ctx, SBOMKey{AgentID: id, ImageID: "sha256:aaa"})
	if err != nil || string(doc) != `{"a":1}` {
		t.Fatalf("LoadSBOM = %q, %v", doc, err)
	}
}

func TestRequestSBOMsResendsLostRequests(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id := enrolledWithContainers(t, s, "alpha",
		protocol.Container{ID: "c1", Name: "a", Image: "x:1", ImageID: "sha256:aaa"},
		protocol.Container{ID: "c2", Name: "b", Image: "y:1", ImageID: "sha256:bbb"},
	)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if ids, _ := s.RequestSBOMs(ctx, id, 5, AgentQueue{Reports: true}, now); len(ids) != 2 {
		t.Fatalf("first request = %v", ids)
	}
	// The agent restarted and lost its queue: it now reports only bbb.
	queue := AgentQueue{Reports: true, Pending: map[string]bool{"sha256:bbb": true}}
	if ids, _ := s.RequestSBOMs(ctx, id, 5, queue, now.Add(time.Minute)); len(ids) != 0 {
		t.Fatalf("re-requested within the grace period: %v", ids)
	}
	ids, _ := s.RequestSBOMs(ctx, id, 5, queue, now.Add(3*time.Minute))
	if len(ids) != 1 || ids[0] != "sha256:aaa" {
		t.Fatalf("lost request not resent: %v, want only aaa (bbb still pending)", ids)
	}
}

func TestScansFindingsIgnoresAndCoverage(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id := enrolledWithContainers(t, s, "alpha",
		protocol.Container{ID: "c1", Name: "db", Image: "postgres:16-alpine", ImageID: "sha256:pg"},
		protocol.Container{ID: "c2", Name: "web", Image: "ghcr.io/example/web:latest", ImageID: "sha256:web"},
	)
	now := time.Now()
	if _, err := s.RequestSBOMs(ctx, id, 5, AgentQueue{}, now); err != nil {
		t.Fatal(err)
	}
	for _, img := range []string{"sha256:pg", "sha256:web"} {
		if err := s.SaveSBOM(ctx, id, protocol.SBOMUpload{ImageID: img, Format: protocol.FormatCycloneDXJSON, Document: []byte(`{}`)}, now); err != nil {
			t.Fatal(err)
		}
	}
	if ids, _ := s.SBOMsToScan(ctx, "db1", 10); len(ids) != 2 {
		t.Fatalf("SBOMsToScan = %v, want 2", ids)
	}
	pg := []Finding{
		{VulnID: "CVE-1", Pkg: "libssl3", Installed: "3.0", Fixed: "3.1", Severity: "CRITICAL"},
		{VulnID: "CVE-2", Pkg: "zlib", Installed: "1.2", Severity: "HIGH"},
	}
	if err := s.SaveScan(ctx, SBOMKey{AgentID: id, ImageID: "sha256:pg"}, "db1", pg, "", now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveScan(ctx, SBOMKey{AgentID: id, ImageID: "sha256:web"}, "db1", nil, "trivy failed", now); err != nil {
		t.Fatal(err)
	}
	if ids, _ := s.SBOMsToScan(ctx, "db1", 10); len(ids) != 0 {
		t.Fatalf("rescan requested on same db: %v", ids)
	}
	if ids, _ := s.SBOMsToScan(ctx, "db2", 10); len(ids) != 2 {
		t.Fatalf("new db did not trigger rescans: %v", ids)
	}

	got, err := s.ActiveFindings(ctx, "", now)
	if err != nil || len(got) != 2 || got[0].Host != "alpha" {
		t.Fatalf("ActiveFindings = %+v, %v", got, err)
	}
	if _, err := s.AddIgnore(ctx, Ignore{VulnID: "CVE-1", Repository: "postgres", Reason: "not reachable", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddIgnore(ctx, Ignore{VulnID: "CVE-2", Reason: "expired", ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ActiveFindings(ctx, "alpha", now)
	if len(got) != 1 || got[0].VulnID != "CVE-2" {
		t.Fatalf("after ignores = %+v, want only CVE-2 (expired rule ignored)", got)
	}
	if _, err := s.AddIgnore(ctx, Ignore{VulnID: "CVE-3"}); err == nil {
		t.Fatal("ignore without reason or expiry accepted")
	}

	cov, err := s.Coverage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c := cov["alpha"]; c.Containers != 2 || c.Scanned != 1 || c.Failed != 1 {
		t.Fatalf("coverage = %+v", c)
	}
}

func TestSBOMUploadsMustBeRequested(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()
	alpha := enrolledWithContainers(t, s, "alpha", protocol.Container{ID: "c1", Name: "db", Image: "postgres:16", ImageID: "sha256:shared"})
	bravo := enrolledWithContainers(t, s, "bravo", protocol.Container{ID: "c2", Name: "db", Image: "postgres:16", ImageID: "sha256:shared"})
	doc := func(body string) protocol.SBOMUpload {
		return protocol.SBOMUpload{ImageID: "sha256:shared", Format: protocol.FormatCycloneDXJSON, Document: []byte(body)}
	}

	if err := s.SaveSBOM(ctx, alpha, doc(`{"v":"unsolicited"}`), now); !errors.Is(err, ErrUnsolicited) {
		t.Fatalf("unsolicited upload: err = %v, want ErrUnsolicited", err)
	}
	if _, err := s.RequestSBOMs(ctx, alpha, 5, AgentQueue{}, now); err != nil {
		t.Fatal(err)
	}
	// A request to alpha does not let bravo upload for the same image.
	if err := s.SaveSBOM(ctx, bravo, doc(`{"v":"bravo"}`), now); !errors.Is(err, ErrUnsolicited) {
		t.Fatalf("other agent's request accepted: err = %v", err)
	}
	if err := s.SaveSBOM(ctx, alpha, doc(`{"v":"alpha"}`), now); err != nil {
		t.Fatal(err)
	}
	// The request is consumed: a second upload cannot replace the SBOM.
	if err := s.SaveSBOM(ctx, alpha, doc(`{"v":"replaced"}`), now); !errors.Is(err, ErrUnsolicited) {
		t.Fatalf("replacement accepted: err = %v", err)
	}
	if got, _ := s.LoadSBOM(ctx, SBOMKey{AgentID: alpha, ImageID: "sha256:shared"}); string(got) != `{"v":"alpha"}` {
		t.Fatalf("alpha SBOM = %s", got)
	}
	// Bravo's results never come from alpha's SBOM.
	if _, err := s.LoadSBOM(ctx, SBOMKey{AgentID: bravo, ImageID: "sha256:shared"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bravo sees alpha's SBOM: err = %v", err)
	}
	// An error report also consumes the request.
	if _, err := s.RequestSBOMs(ctx, bravo, 5, AgentQueue{}, now); err != nil {
		t.Fatal(err)
	}
	failed := protocol.SBOMUpload{ImageID: "sha256:shared", Error: "scanner exited 1"}
	if err := s.SaveSBOM(ctx, bravo, failed, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSBOM(ctx, bravo, failed, now); !errors.Is(err, ErrUnsolicited) {
		t.Fatalf("repeated error report accepted: err = %v", err)
	}
}

func TestClearSuppressedAlerts(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()
	keys := []AlertKey{
		{Repository: "postgres", VulnID: "CVE-1", Pkg: "libssl3"},
		{Repository: "redis", VulnID: "CVE-1", Pkg: "libssl3"},
		{Repository: "postgres", VulnID: "CVE-2", Pkg: "zlib"},
	}
	if err := s.MarkAlerted(ctx, keys, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddIgnore(ctx, Ignore{VulnID: "CVE-1", Repository: "postgres", Reason: "r", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearSuppressedAlerts(ctx, now); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Alerted(ctx)
	if got[keys[0]] || !got[keys[1]] || !got[keys[2]] {
		t.Fatalf("alerted after clearing = %v, want only the ignored postgres CVE-1 removed", got)
	}
}

func TestMigrationDropsOldSBOMTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.SetSetting(ctx, "schema_vulns", "1"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkAlerted(ctx, []AlertKey{{Repository: "r", VulnID: "v", Pkg: "p"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if v, _ := s.Setting(ctx, "schema_vulns"); v != schemaVulnsVersion {
		t.Fatalf("schema_vulns = %q after migration", v)
	}
	if got, _ := s.Alerted(ctx); len(got) != 1 {
		t.Fatalf("alert history lost in migration: %v", got)
	}
}

func TestRepository(t *testing.T) {
	for in, want := range map[string]string{
		"postgres:16-alpine":               "postgres",
		"ghcr.io/example/app:1.2":          "ghcr.io/example/app",
		"registry.example.net:5000/app":    "registry.example.net:5000/app",
		"registry.example.net:5000/app:v1": "registry.example.net:5000/app",
		"valkey/valkey:8@sha256:" + "a":    "valkey/valkey",
		"alpha-web":                        "alpha-web",
	} {
		if got := Repository(in); got != want {
			t.Errorf("Repository(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAlertedAndSettings(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	k := AlertKey{Repository: "postgres", VulnID: "CVE-1", Pkg: "libssl3"}
	if err := s.MarkAlerted(ctx, []AlertKey{k, k}, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := s.Alerted(ctx)
	if err != nil || !got[k] || len(got) != 1 {
		t.Fatalf("Alerted = %v, %v", got, err)
	}
	if v, _ := s.Setting(ctx, "x"); v != "" {
		t.Fatalf("unset setting = %q", v)
	}
	if err := s.SetSetting(ctx, "x", "1"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Setting(ctx, "x"); v != "1" {
		t.Fatalf("setting = %q", v)
	}
}
