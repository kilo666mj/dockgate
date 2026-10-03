package fleetglass

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/store"
)

func enrolled(t *testing.T, st *store.Store, name, id string) {
	t.Helper()
	ctx := context.Background()
	if err := st.CreateToken(ctx, "tok-"+name, "secret", name, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	sign := func(string) (store.Issued, error) {
		return store.Issued{Serial: "1", NotAfter: time.Now().Add(time.Hour)}, nil
	}
	if _, _, err := st.Enroll(ctx, "tok-"+name, "secret", "pin-"+name, id, sign); err != nil {
		t.Fatal(err)
	}
}

func TestBuildChecks(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	enrolled(t, st, "alpha", "agt_alpha")
	enrolled(t, st, "charlie", "agt_charlie")
	enrolled(t, st, "fresh", "agt_fresh")

	now := time.Now()
	if err := st.SaveReport(ctx, "agt_alpha", protocol.Report{Containers: []protocol.Container{
		{ID: "1", Name: "redis", State: "running", Update: &protocol.UpdateCheck{Status: protocol.UpdateAvailable, Reference: "valkey/valkey:latest"}},
		{ID: "2", Name: "db", State: "running", Health: "unhealthy", ImageID: "sha256:db"},
	}}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveReport(ctx, "agt_charlie", protocol.Report{}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A fixable critical in alpha's db image makes its vulnerability check bad.
	if err := st.SaveSBOM(ctx, "agt_alpha", protocol.SBOMUpload{ImageID: "sha256:db", Format: protocol.FormatCycloneDXJSON, Document: []byte(`{}`)}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveScan(ctx, "sha256:db", "db1", []store.Finding{{VulnID: "CVE-1", Pkg: "libssl3", Installed: "3.0", Fixed: "3.1", Severity: "CRITICAL"}}, "", now); err != nil {
		t.Fatal(err)
	}

	checks, err := BuildChecks(ctx, st, 5*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range checks {
		got[c.Host+"/"+c.Kind] = c.Status
	}
	want := map[string]string{
		"alpha/agent_health":                "ok",
		"alpha/container_updates":           "warn",
		"alpha/container_health":            "bad",
		"alpha/container_vulnerabilities":   "warn",
		"charlie/container_vulnerabilities": "ok",
		"charlie/agent_health":              "bad",
		"charlie/container_updates":         "ok",
		"charlie/container_health":          "ok",
		"fresh/agent_health":                "warn",
	}
	if len(got) != len(want) {
		t.Errorf("got %d checks %v, want %d", len(got), got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestExportOncePostsWithToken(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	enrolled(t, st, "alpha", "agt_alpha")

	var auth string
	var posted []Check
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest/checks" {
			http.NotFound(w, r)
			return
		}
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&posted)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	e := &Exporter{URL: srv.URL + "/", Token: "fg-token", Store: st, StaleAfter: time.Minute,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := e.ExportOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer fg-token" {
		t.Errorf("Authorization = %q", auth)
	}
	if len(posted) != 1 || posted[0].Source != Source || posted[0].Host != "alpha" {
		t.Errorf("posted = %+v", posted)
	}
}
