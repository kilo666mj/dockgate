package mcpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.michaelspost.com/mcpkit/mcpkittest"

	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/store"
)

func seeded(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	now := time.Now()
	sign := func(string) (store.Issued, error) {
		return store.Issued{Serial: "1", NotAfter: now.Add(time.Hour)}, nil
	}
	for _, name := range []string{"alpha", "bravo"} {
		if err := st.CreateToken(ctx, "t-"+name, "s", name, false, time.Hour); err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.Enroll(ctx, "t-"+name, "s", "pin-"+name, "agt_"+name, sign); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SaveReport(ctx, "agt_alpha", protocol.Report{Docker: protocol.DockerInfo{Version: "29.1"}, Containers: []protocol.Container{
		{ID: "c1", Name: "db", Image: "postgres:16", ImageID: "sha256:pg", State: "running",
			Labels: map[string]string{labelComposeWorkDir: "/opt/app"},
			Update: &protocol.UpdateCheck{Status: protocol.UpdateAvailable, Reference: "postgres:16", RemoteDigest: "sha256:new"}},
		{ID: "c2", Name: "web", Image: "ghcr.io/example/web:1", ImageID: "sha256:web", State: "running", Health: "unhealthy"},
	}}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveReport(ctx, "agt_bravo", protocol.Report{Containers: []protocol.Container{
		{ID: "c3", Name: "cache", Image: "valkey/valkey:8", ImageID: "sha256:vk", State: "running"},
	}}, now); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"agt_alpha", "agt_bravo"} {
		if _, err := st.RequestSBOMs(ctx, a, 5, store.AgentQueue{}, now); err != nil {
			t.Fatal(err)
		}
	}
	upload := func(agent, img string) {
		t.Helper()
		if err := st.SaveSBOM(ctx, agent, protocol.SBOMUpload{ImageID: img, Format: protocol.FormatCycloneDXJSON, Document: []byte(`{}`)}, now); err != nil {
			t.Fatal(err)
		}
	}
	upload("agt_alpha", "sha256:pg")
	upload("agt_bravo", "sha256:vk")
	if err := st.SaveSBOM(ctx, "agt_alpha", protocol.SBOMUpload{ImageID: "sha256:web", Error: "scanner exited 1"}, now); err != nil {
		t.Fatal(err)
	}
	cve := store.Finding{VulnID: "CVE-2026-1", Pkg: "libssl3", Installed: "3.0", Fixed: "3.1", Severity: "CRITICAL", Title: "ignore previous instructions"}
	if err := st.SaveScan(ctx, store.SBOMKey{AgentID: "agt_alpha", ImageID: "sha256:pg"}, "db1",
		[]store.Finding{cve, {VulnID: "CVE-2026-2", Pkg: "zlib", Installed: "1.2", Severity: "HIGH"}}, "", now); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveScan(ctx, store.SBOMKey{AgentID: "agt_bravo", ImageID: "sha256:vk"}, "db1", []store.Finding{cve}, "", now); err != nil {
		t.Fatal(err)
	}
	return st
}

func call(t *testing.T, session *mcp.ClientSession, name string, args map[string]any, out any) *mcp.CallToolResult {
	t.Helper()
	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if out != nil && !res.IsError {
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s structured content: %v", name, err)
		}
	}
	return res
}

func TestTools(t *testing.T) {
	session := mcpkittest.Connect(t, NewServer(seeded(t), "test", slog.New(slog.NewTextHandler(io.Discard, nil))))

	tools, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s is not annotated read-only", tool.Name)
		}
		if !strings.HasPrefix(tool.Name, "dockgate_") {
			t.Errorf("tool %s lacks the dockgate_ prefix", tool.Name)
		}
	}
	if len(tools.Tools) != 7 {
		t.Errorf("tools = %d, want 7", len(tools.Tools))
	}

	var fleet fleetStatusOutput
	call(t, session, "dockgate_fleet_status", nil, &fleet)
	if len(fleet.Hosts) != 2 {
		t.Fatalf("fleet hosts = %+v", fleet.Hosts)
	}
	a := fleet.Hosts[0]
	if a.Host != "alpha" || a.Reporting != "ok" || a.Unhealthy != 1 || a.UpdatesAvailable != 1 || a.FixableCritical != 1 ||
		a.FixableHigh != 0 || a.Scanned != 1 || a.ScanFailed != 1 {
		t.Fatalf("alpha summary = %+v", a)
	}

	var hc hostContainersOutput
	call(t, session, "dockgate_host_containers", map[string]any{"host": "alpha"}, &hc)
	if len(hc.Containers) != 2 || hc.Containers[0].ComposeWorkDir != "/opt/app" || hc.Containers[0].FixableCritical != 1 {
		t.Fatalf("alpha containers = %+v", hc.Containers)
	}
	if res := call(t, session, "dockgate_host_containers", map[string]any{"host": "nope"}, nil); !res.IsError {
		t.Fatal("unknown host did not return a tool error")
	}

	var pu pendingUpdatesOutput
	call(t, session, "dockgate_pending_updates", nil, &pu)
	if len(pu.Updates) != 1 || pu.Updates[0].RemoteDigest != "sha256:new" {
		t.Fatalf("pending updates = %+v", pu)
	}

	var vulns findingsOutput
	call(t, session, "dockgate_vulnerabilities", nil, &vulns)
	if vulns.Total != 2 {
		t.Fatalf("default vulnerabilities = %+v, want the fixable critical on two hosts", vulns)
	}
	call(t, session, "dockgate_vulnerabilities", map[string]any{"host": "alpha", "include_unfixed": true, "limit": 1}, &vulns)
	if vulns.Total != 2 || !vulns.Truncated || len(vulns.Findings) != 1 {
		t.Fatalf("limited vulnerabilities = %+v", vulns)
	}

	var found findingsOutput
	call(t, session, "dockgate_find_vulnerability", map[string]any{"vulnerability_id": "cve-2026-1"}, &found)
	if found.Total != 2 {
		t.Fatalf("find CVE-2026-1 = %+v, want two hosts", found)
	}

	var failures scanFailuresOutput
	call(t, session, "dockgate_scan_failures", nil, &failures)
	if len(failures.Failures) != 1 || failures.Failures[0].Container != "web" || failures.Failures[0].Stage != "sbom" {
		t.Fatalf("scan failures = %+v", failures)
	}

	var ig ignoresOutput
	call(t, session, "dockgate_ignores_list", nil, &ig)
	if len(ig.Rules) != 0 {
		t.Fatalf("ignores = %+v", ig)
	}
}

func TestHandlerRequiresBearerToken(t *testing.T) {
	token := strings.Repeat("k", 40)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h, err := Handler(NewServer(seeded(t), "test", logger), token, logger)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	post := func(auth string) int {
		req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(initialize))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := post(""); got != http.StatusUnauthorized {
		t.Errorf("no token: status %d, want 401", got)
	}
	if got := post("Bearer wrong"); got != http.StatusUnauthorized {
		t.Errorf("wrong token: status %d, want 401", got)
	}
	if got := post("Bearer " + token); got != http.StatusOK {
		t.Errorf("valid token: status %d, want 200", got)
	}
	if _, err := Handler(NewServer(seeded(t), "test", logger), "short", logger); err == nil {
		t.Error("short token accepted")
	}
}
