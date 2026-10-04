package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.michaelspost.com/mcpkit"

	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/store"
)

type fakeAPI struct {
	tasks   map[string]*Task
	created []CreateRequest
	cancels []string
	updates []string
	n       int
}

func newFake() *fakeAPI { return &fakeAPI{tasks: map[string]*Task{}} }

func (f *fakeAPI) Create(_ context.Context, r CreateRequest) (Task, error) {
	f.n++
	t := &Task{ID: fmt.Sprintf("T%d", f.n), Version: 1, Status: statusQueued}
	f.tasks[t.ID] = t
	f.created = append(f.created, r)
	return *t, nil
}
func (f *fakeAPI) Get(_ context.Context, id string) (Task, error) { return *f.tasks[id], nil }
func (f *fakeAPI) Refresh(_ context.Context, id string, v int64, summary, priority string) (Task, error) {
	f.updates = append(f.updates, id)
	f.tasks[id].Version++
	return *f.tasks[id], nil
}
func (f *fakeAPI) Cancel(_ context.Context, id string, v int64, note string) (Task, error) {
	f.cancels = append(f.cancels, id)
	f.tasks[id].Status = statusCancelled
	return *f.tasks[id], nil
}

const (
	curDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	newDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// fixture builds a store with containers whose candidates fix findings.
func fixture(t *testing.T, containers ...string) (*store.Store, string) {
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
	if err := st.CreateToken(ctx, "t", "s", "alpha", false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Enroll(ctx, "t", "s", "pin", "agt_a", sign); err != nil {
		t.Fatal(err)
	}
	report := protocol.Report{Docker: protocol.DockerInfo{OS: "linux", Arch: "amd64"}}
	for i, name := range containers {
		report.Containers = append(report.Containers, protocol.Container{
			ID: name, Name: name, Image: "example/" + name + ":latest", ImageID: fmt.Sprintf("sha256:img%d", i),
			Update: &protocol.UpdateCheck{Status: protocol.UpdateAvailable, Reference: "example/" + name + ":latest",
				LocalDigests: []string{curDigest}, RemoteDigest: newDigest},
		})
	}
	if err := st.SaveReport(ctx, "agt_a", report, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RequestSBOMs(ctx, "agt_a", 50, store.AgentQueue{}, now); err != nil {
		t.Fatal(err)
	}
	for i := range containers {
		img := fmt.Sprintf("sha256:img%d", i)
		if err := st.SaveSBOM(ctx, "agt_a", protocol.SBOMUpload{ImageID: img, Format: protocol.FormatCycloneDXJSON, Document: []byte(`{}`)}, now); err != nil {
			t.Fatal(err)
		}
		// Container i has i+1 fixable criticals the candidate fixes.
		var fs []store.Finding
		for j := 0; j <= i; j++ {
			fs = append(fs, store.Finding{VulnID: fmt.Sprintf("CVE-%d-%d", i, j), Pkg: "pkg", Installed: "1", Fixed: "2", Severity: "CRITICAL"})
		}
		if err := st.SaveScan(ctx, store.SBOMKey{AgentID: "agt_a", ImageID: img}, "db1", fs, "", now); err != nil {
			t.Fatal(err)
		}
	}
	key := store.CandidateKey{Digest: newDigest, Platform: "linux/amd64"}
	if err := st.SaveCandidateSBOM(ctx, store.RegistryTarget{Reference: "example/x@" + newDigest, Digest: newDigest, Platform: "linux/amd64"}, []byte(`{}`), "", now); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCandidateScan(ctx, key, "db1", nil, "", now); err != nil {
		t.Fatal(err)
	}
	return st, "agt_a"
}

func syncer(st *store.Store, api API) *Syncer {
	return &Syncer{Store: st, API: api, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), MaxOpen: 2,
		Requirements: []string{"runner:local"}, Project: "dockgate", OwnImagePrefixes: []string{"example/web"}}
}

func TestSyncFilesMostCriticalFirstWithinCap(t *testing.T) {
	st, _ := fixture(t, "db", "cache", "web")
	api := newFake()
	s := syncer(st, api)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(api.created) != 2 {
		t.Fatalf("created %d tasks, want the cap of 2", len(api.created))
	}
	// web has 3 criticals, cache 2, db 1.
	if api.created[0].Title != "Update web on alpha" || api.created[1].Title != "Update cache on alpha" {
		t.Fatalf("titles = %q, %q", api.created[0].Title, api.created[1].Title)
	}
	c := api.created[0]
	if c.Priority != "high" || c.Requirements[0] != "runner:local" || len(c.Checklist) != 4 || c.IdempotencyKey == "" {
		t.Fatalf("create request = %+v", c)
	}
	if !strings.Contains(c.Summary, "pull request") || strings.Contains(api.created[1].Summary, "pull request") {
		t.Fatal("own-image fix policy not applied to web only")
	}
	// A second sync files nothing new while the cap is full.
	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(api.created) != 2 {
		t.Fatalf("second sync created more tasks: %d", len(api.created))
	}
}

func TestSyncCancelsResolvedUnclaimedAndLeavesClaimed(t *testing.T) {
	st, agent := fixture(t, "db", "cache")
	api := newFake()
	s := syncer(st, api)
	ctx := context.Background()
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// cache (T1) gets claimed by a worker; then both updates are applied:
	// the containers report current images.
	api.tasks["T1"].Status, api.tasks["T1"].Owner = "active", "agent:worker"
	if err := st.SaveReport(ctx, agent, protocol.Report{Docker: protocol.DockerInfo{OS: "linux", Arch: "amd64"}, Containers: []protocol.Container{
		{ID: "db", Name: "db", Image: "example/db:latest", ImageID: "sha256:new0", Update: &protocol.UpdateCheck{Status: protocol.UpdateCurrent}},
		{ID: "cache", Name: "cache", Image: "example/cache:latest", ImageID: "sha256:new1", Update: &protocol.UpdateCheck{Status: protocol.UpdateCurrent}},
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(api.cancels) != 1 || api.cancels[0] != "T2" {
		t.Fatalf("cancels = %v, want only the unclaimed db task", api.cancels)
	}
	open, _ := st.OpenUpdateTasks(ctx)
	if len(open) != 1 || open[0].TaskID != "T1" {
		t.Fatalf("open after sync = %+v, want the claimed task still tracked", open)
	}
	// The worker finishes; dockgate records it and does not refile.
	api.tasks["T1"].Status = statusDone
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if open, _ := st.OpenUpdateTasks(ctx); len(open) != 0 {
		t.Fatalf("open after worker finished = %+v", open)
	}
}

func TestSyncDoesNotRefileForTheSameCandidate(t *testing.T) {
	st, _ := fixture(t, "db")
	api := newFake()
	s := syncer(st, api)
	ctx := context.Background()
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// A person cancels it in Taskboard although the update is still
	// actionable: dockgate records that and does not file it again.
	api.tasks["T1"].Status = statusCancelled
	for range 2 {
		if err := s.Sync(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(api.created) != 1 {
		t.Fatalf("refiled after a human cancel: %d creates", len(api.created))
	}
}

// TestClientAgainstMCPServer exercises the real client over HTTP against an
// MCP server exposing Taskboard's tool names and result shape.
func TestClientAgainstMCPServer(t *testing.T) {
	var gotAuth, gotForce string
	server := mcpkit.MustServer(mcpkit.ServerConfig{Name: "taskboard", Version: "test"})
	type out struct {
		Task struct {
			ID      string `json:"id"`
			Version int64  `json:"version"`
			Status  string `json:"status"`
			Owner   string `json:"owner,omitempty"`
		} `json:"task"`
	}
	mcp.AddTool(server, &mcp.Tool{Name: "task_create", Annotations: mcpkit.Mutating(false, false)},
		func(_ context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, out, error) {
			gotForce = fmt.Sprint(in["force_new"])
			var o out
			o.Task.ID, o.Task.Version, o.Task.Status = "01TASK", 1, "queued"
			return nil, o, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "task_update", Annotations: mcpkit.Mutating(false, false)},
		func(_ context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, out, error) {
			var o out
			o.Task.ID, o.Task.Version, o.Task.Status = fmt.Sprint(in["task_id"]), 2, fmt.Sprint(in["status"])
			return nil, o, nil
		})
	h, err := mcpkit.StatelessHTTP(func(*http.Request) *mcp.Server { return server }, mcpkit.HTTPOptions{DisableLocalhostProtection: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()

	c := &Client{Endpoint: srv.URL, Token: "tb_agent_test", Version: "test"}
	task, err := c.Create(context.Background(), CreateRequest{Title: "Update db on alpha", IdempotencyKey: "dockgate-update-x"})
	if err != nil {
		t.Fatal(err)
	}
	if task.ID != "01TASK" || task.Status != "queued" || gotAuth != "Bearer tb_agent_test" || gotForce != "true" {
		t.Fatalf("create: task %+v auth %q force_new %q", task, gotAuth, gotForce)
	}
	task, err = c.Cancel(context.Background(), "01TASK", 1, "Resolved")
	if err != nil || task.Status != "cancelled" {
		t.Fatalf("cancel = %+v, %v", task, err)
	}
}

func TestSummaryCarriesMetadataAndSkipsBuildx(t *testing.T) {
	st, _ := fixture(t, "db", "buildx_buildkit_builder0")
	api := newFake()
	s := syncer(st, api)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(api.created) != 1 || api.created[0].Title != "Update db on alpha" {
		t.Fatalf("created = %+v, want only db (buildx builders are exempt)", api.created)
	}
	var meta taskMeta
	for _, line := range strings.Split(api.created[0].Summary, "\n") {
		if rest, ok := strings.CutPrefix(line, MetaPrefix); ok {
			if err := json.Unmarshal([]byte(rest), &meta); err != nil {
				t.Fatal(err)
			}
		}
	}
	if meta.Version != 1 || meta.Host != "alpha" || meta.Container != "db" || meta.Digest != newDigest || meta.Fix != "update_job" || meta.Image != "example/db:latest" {
		t.Fatalf("meta = %+v", meta)
	}
}
