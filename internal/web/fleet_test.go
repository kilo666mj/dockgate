package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/store"
)

// enroll adds host alpha (agent agt_a, which job_1 belongs to) and its report.
func enroll(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	sign := func(string) (store.Issued, error) {
		return store.Issued{Serial: "1", NotAfter: now.Add(90 * 24 * time.Hour)}, nil
	}
	if err := st.CreateToken(ctx, "t", "s", "alpha", false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Enroll(ctx, "t", "s", "pin", "agt_a", sign); err != nil {
		t.Fatal(err)
	}
	rep := protocol.Report{AgentVersion: "v1.2.3", Docker: protocol.DockerInfo{Version: "28.1.0", OS: "linux", Arch: "amd64", CPUs: 4, MemoryBytes: 8 << 30},
		Containers: []protocol.Container{
			{ID: "c1", Name: "web", Image: "example/web:latest", ImageID: "sha256:img1", State: "running", Status: "Up 2 hours",
				ComposeProject: "shop", ComposeService: "web",
				Update: &protocol.UpdateCheck{Status: protocol.UpdateAvailable, Reference: "example/web:latest", RemoteDigest: "sha256:abcdef0123456789"}},
			{ID: "c2", Name: "worker", Image: "example/worker:1", ImageID: "sha256:img2", State: "restarting", Status: "Restarting (1)", RestartCount: 7},
			{ID: "c3", Name: "<b>init</b>", Image: "example/init:1", ImageID: "sha256:img3", State: "exited", Status: "Exited (0)"},
		}}
	if err := st.SaveReport(ctx, "agt_a", rep, now); err != nil {
		t.Fatal(err)
	}
}

func TestFleetAndHostPages(t *testing.T) {
	_, st, h := setup(t)
	enroll(t, st)

	w := do(h, "GET", "/fleet", nil, true, nil)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("fleet: %d\n%s", w.Code, body)
	}
	for _, want := range []string{`href="/hosts/alpha"`, "reporting", "agent v1.2.3", "Docker 28.1.0", "1/3 running", "1 restarting", "1 update", "1 open job", `aria-current="page">Fleet`} {
		if !strings.Contains(body, want) {
			t.Errorf("fleet page missing %q", want)
		}
	}

	w = do(h, "GET", "/hosts/alpha", nil, true, nil)
	body = w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("host: %d\n%s", w.Code, body)
	}
	for _, want := range []string{"linux/amd64", "4 CPUs", "8.0 GiB", "shop / web", "update available · abcdef012345", `href="/jobs/job_1"`, "7 restarts"} {
		if !strings.Contains(body, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	if strings.Index(body, "<strong>worker</strong>") > strings.Index(body, "<strong>web</strong>") {
		t.Error("the restarting container should be listed before the running one")
	}
	if strings.Contains(body, "<b>init</b>") || !strings.Contains(body, "&lt;b&gt;init&lt;/b&gt;") {
		t.Error("container name not escaped")
	}

	if w := do(h, "GET", "/hosts/nowhere", nil, true, nil); w.Code != http.StatusNotFound {
		t.Errorf("unknown host: %d", w.Code)
	}
	for _, p := range []string{"/fleet", "/hosts/alpha"} {
		if w := do(h, "GET", p, nil, false, nil); w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
			t.Errorf("%s without session: %d %s", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := do(h, "GET", "/", nil, true, nil); w.Code != http.StatusFound || w.Header().Get("Location") != "/fleet" {
		t.Errorf("root: %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestAgo(t *testing.T) {
	for d, want := range map[time.Duration]string{30 * time.Second: "just now", 5 * time.Minute: "5 min ago", 3 * time.Hour: "3 h ago", 72 * time.Hour: "3 days ago"} {
		if got := ago(d, false); got != want {
			t.Errorf("ago(%s) = %q, want %q", d, got, want)
		}
	}
	if ago(0, true) != "never" {
		t.Error("zero time should read never")
	}
}
