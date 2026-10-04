package vulns

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tintwire "go.michaelspost.com/tintwire-go"

	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/store"
)

type fakeMatcher struct {
	version   string
	findings  []store.Finding
	matched   int
	remote    []string
	remoteErr error
}

func (f *fakeMatcher) RefreshDB(context.Context) error { return nil }
func (f *fakeMatcher) DBVersion(context.Context) (string, error) {
	return f.version, nil
}
func (f *fakeMatcher) Match(context.Context, []byte) ([]store.Finding, error) {
	f.matched++
	return f.findings, nil
}
func (f *fakeMatcher) RemoteSBOM(_ context.Context, ref, platform string) ([]byte, error) {
	f.remote = append(f.remote, platform+" "+ref)
	if f.remoteErr != nil {
		return nil, f.remoteErr
	}
	return []byte(`{"bomFormat":"CycloneDX"}`), nil
}

type fakePublisher struct{ cards []tintwire.Card }

func (f *fakePublisher) Publish(_ context.Context, c tintwire.Card) (tintwire.Result, error) {
	f.cards = append(f.cards, c)
	return tintwire.Result{}, nil
}

func setup(t *testing.T) (*store.Store, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.CreateToken(ctx, "t", "s", "alpha", false, time.Hour); err != nil {
		t.Fatal(err)
	}
	sign := func(string) (store.Issued, error) {
		return store.Issued{Serial: "1", NotAfter: time.Now().Add(time.Hour)}, nil
	}
	if _, _, err := st.Enroll(ctx, "t", "s", "pin", "agt_a", sign); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveReport(ctx, "agt_a", protocol.Report{Containers: []protocol.Container{
		{ID: "c1", Name: "db", Image: "postgres:16", ImageID: "sha256:pg"},
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RequestSBOMs(ctx, "agt_a", 5, store.AgentQueue{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSBOM(ctx, "agt_a", protocol.SBOMUpload{ImageID: "sha256:pg", Format: protocol.FormatCycloneDXJSON, Document: []byte(`{}`)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return st, "agt_a"
}

func TestScannerRematchesOnDBChange(t *testing.T) {
	st, _ := setup(t)
	ctx := context.Background()
	m := &fakeMatcher{version: "db1", findings: []store.Finding{{VulnID: "CVE-1", Pkg: "libssl3", Installed: "3.0", Fixed: "3.1", Severity: "HIGH"}}}
	s := &Scanner{Store: st, Matcher: m, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	if n, err := s.Pass(ctx); err != nil || n != 1 {
		t.Fatalf("first pass = %d, %v", n, err)
	}
	if n, _ := s.Pass(ctx); n != 0 {
		t.Fatalf("second pass on same db scanned %d", n)
	}
	m.version = "db2"
	if n, _ := s.Pass(ctx); n != 1 {
		t.Fatalf("pass after db change scanned %d, want 1", n)
	}
	got, _ := st.ActiveFindings(ctx, "", time.Now())
	if len(got) != 1 || got[0].Container != "db" {
		t.Fatalf("findings = %+v", got)
	}
}

func TestAlerterBaselineThenNewFindings(t *testing.T) {
	st, _ := setup(t)
	ctx := context.Background()
	m := &fakeMatcher{version: "db1", findings: []store.Finding{
		{VulnID: "CVE-1", Pkg: "libssl3", Installed: "3.0", Fixed: "3.1", Severity: "HIGH"},
		{VulnID: "CVE-9", Pkg: "zlib", Installed: "1.2", Severity: "CRITICAL"}, // no fix: never alerts
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &Scanner{Store: st, Matcher: m, Logger: logger}
	pub := &fakePublisher{}
	a := &Alerter{Store: st, Publisher: pub, Channel: "dockgate", Logger: logger, Severities: []string{"CRITICAL", "HIGH"}}

	if _, err := s.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	a.Check(ctx)
	if len(pub.cards) != 1 || pub.cards[0].Title != "Vulnerability alerting baseline" {
		t.Fatalf("first check cards = %+v, want one baseline card", pub.cards)
	}
	a.Check(ctx)
	if len(pub.cards) != 1 {
		t.Fatalf("baseline findings alerted again: %d cards", len(pub.cards))
	}

	m.version = "db2"
	m.findings = append(m.findings, store.Finding{VulnID: "CVE-2", Pkg: "curl", Installed: "8.0", Fixed: "8.1", Severity: "CRITICAL"})
	if _, err := s.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	a.Check(ctx)
	if len(pub.cards) != 2 {
		t.Fatalf("new finding cards = %d, want 2", len(pub.cards))
	}
	c := pub.cards[1]
	if c.Severity != tintwire.SeverityCritical || len(c.Rows) != 1 || c.Validate() != nil {
		t.Fatalf("alert card = %+v (validate: %v)", c, c.Validate())
	}
	a.Check(ctx)
	if len(pub.cards) != 2 {
		t.Fatal("alerted twice for the same finding")
	}
}

func TestParseReport(t *testing.T) {
	report := []byte(`{"Results":[{"Target":"x","Vulnerabilities":[
		{"VulnerabilityID":"CVE-2026-1","PkgName":"libcrypto3","InstalledVersion":"3.5.7-r0","FixedVersion":"3.5.8-r0","Status":"fixed","Severity":"high","Title":"t","PrimaryURL":"https://example.net"},
		{"VulnerabilityID":"CVE-2026-2","PkgName":"busybox","InstalledVersion":"1.37","Status":"affected","Severity":"LOW"}]},
		{"Target":"y"}]}`)
	got, err := ParseReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Severity != "HIGH" || !got[0].Fixable() || got[1].Fixable() {
		t.Fatalf("ParseReport = %+v", got)
	}
	if _, err := ParseReport([]byte("not json")); err == nil {
		t.Fatal("ParseReport accepted garbage")
	}
}

func TestExpiredIgnoreAlertsAgainWithoutNewScans(t *testing.T) {
	st, _ := setup(t)
	ctx := context.Background()
	m := &fakeMatcher{version: "db1", findings: []store.Finding{{VulnID: "CVE-1", Pkg: "libssl3", Installed: "3.0", Fixed: "3.1", Severity: "CRITICAL"}}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &Scanner{Store: st, Matcher: m, Logger: logger}
	pub := &fakePublisher{}
	a := &Alerter{Store: st, Publisher: pub, Logger: logger, Severities: []string{"CRITICAL", "HIGH"}}
	if _, err := s.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	// Baseline, then a new finding alerts.
	if err := st.SetSetting(ctx, baselineKey, "set"); err != nil {
		t.Fatal(err)
	}
	a.Check(ctx)
	if len(pub.cards) != 1 {
		t.Fatalf("cards = %d, want the alert", len(pub.cards))
	}
	// A short ignore hides it; when the ignore expires the finding alerts
	// again, with no scan in between.
	if _, err := st.AddIgnore(ctx, store.Ignore{VulnID: "CVE-1", Reason: "temporary", ExpiresAt: time.Now().Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	a.Check(ctx)
	if len(pub.cards) != 1 {
		t.Fatalf("ignored finding alerted: %d cards", len(pub.cards))
	}
	time.Sleep(2 * time.Second)
	a.Check(ctx)
	if len(pub.cards) != 2 {
		t.Fatalf("expired ignore did not re-alert: %d cards", len(pub.cards))
	}
}

func TestRegistryPass(t *testing.T) {
	st, agentID := setup(t)
	ctx := context.Background()
	digest := "sha256:" + strings.Repeat("3", 64)
	if err := st.SaveReport(ctx, agentID, protocol.Report{
		Docker: protocol.DockerInfo{OS: "linux", Arch: "arm64"},
		Containers: []protocol.Container{{ID: "c1", Name: "db", Image: "postgres:16", ImageID: "sha256:pg",
			Update: &protocol.UpdateCheck{Status: protocol.UpdateAvailable, Reference: "postgres:16", RemoteDigest: digest}}},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	m := &fakeMatcher{version: "db1"}
	s := &Scanner{Store: st, Matcher: m, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	n, err := s.RegistryPass(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(m.remote) != 1 || m.remote[0] != "linux/arm64 postgres@"+digest {
		t.Fatalf("registry pass stored %d, remote calls %v; want the candidate inventoried and matched for arm64", n, m.remote)
	}
	if n, _ := s.RegistryPass(ctx); n != 0 {
		t.Fatalf("second pass stored %d, want nothing new", n)
	}
}
