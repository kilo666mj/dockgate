package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.michaelspost.com/dockgate/internal/jobs"
	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/store"
)

func setup(t *testing.T) (*UI, *store.Store, http.Handler) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ui, err := New(Config{
		Store: st, Jobs: &jobs.Service{Store: st, Logger: logger}, Logger: logger, BaseURL: "https://dockgate.example",
		OIDC: OIDC{Issuer: "https://id.example", ClientID: "dockgate", ClientSecret: "s", AllowedEmails: []string{"me@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.CreateJob(context.Background(), store.Job{
		ID: "job_1", Kind: protocol.JobUpdate, AgentID: "agt_a", Host: "alpha", ContainerID: "c1", ContainerName: "web",
		Reference: "example/web:latest", Digest: "sha256:abcdef0123456789", State: store.JobPendingApproval, RequestedBy: "mcp:worker",
		Reason: "<script>alert(1)</script>",
		Gate:   store.Gate{Fixes: []store.ImpactFinding{{VulnID: "CVE-1", Pkg: "openssl", Severity: "CRITICAL"}}, Introduces: []store.ImpactFinding{}},
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(context.Background(), "sid", store.WebSession{Subject: "u1", Email: "me@example.com", CSRF: "tok", ExpiresAt: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	return ui, st, ui.Handler()
}

func do(h http.Handler, method, path string, form url.Values, cookie bool, headers map[string]string) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, "https://dockgate.example"+path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "sid"})
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestNewRefusesUnsafeConfig(t *testing.T) {
	base := Config{BaseURL: "https://dockgate.example", OIDC: OIDC{Issuer: "https://id.example", ClientID: "c", ClientSecret: "s", AllowedGroups: []string{"admins"}}}
	for name, mut := range map[string]func(*Config){
		"no allow list": func(c *Config) { c.OIDC.AllowedGroups = nil },
		"no secret":     func(c *Config) { c.OIDC.ClientSecret = "" },
		"http":          func(c *Config) { c.BaseURL = "http://dockgate.example" },
		"path":          func(c *Config) { c.BaseURL = "https://dockgate.example/ui" },
	} {
		cfg := base
		mut(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}

func TestPagesRequireSignIn(t *testing.T) {
	_, _, h := setup(t)
	for _, p := range []string{"/jobs", "/jobs/job_1"} {
		w := do(h, "GET", p, nil, false, nil)
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
			t.Errorf("%s without session: %d %s", p, w.Code, w.Header().Get("Location"))
		}
	}
	w := do(h, "POST", "/jobs/job_1/approve", url.Values{"csrf": {"tok"}}, false, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("approve without session: %d", w.Code)
	}
	if w := do(h, "GET", "/login", nil, false, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/auth/login") {
		t.Errorf("login page: %d", w.Code)
	}
}

func TestJobPageEscapesAndShowsDecision(t *testing.T) {
	_, _, h := setup(t)
	w := do(h, "GET", "/jobs/job_1", nil, true, nil)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Approve update") || !strings.Contains(body, `value="tok"`) {
		t.Fatalf("job page: %d\n%s", w.Code, body)
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("reason not escaped")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("headers = %v", w.Header())
	}
	if w := do(h, "GET", "/jobs", nil, true, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/jobs/job_1") {
		t.Fatalf("job list: %d", w.Code)
	}
}

func TestDecisionNeedsCSRFAndSameOrigin(t *testing.T) {
	_, st, h := setup(t)
	if w := do(h, "POST", "/jobs/job_1/approve", url.Values{"csrf": {"wrong"}}, true, nil); w.Code != http.StatusForbidden {
		t.Fatalf("wrong csrf: %d", w.Code)
	}
	if w := do(h, "POST", "/jobs/job_1/approve", url.Values{"csrf": {"tok"}}, true, map[string]string{"Origin": "https://evil.example"}); w.Code != http.StatusForbidden {
		t.Fatalf("cross origin: %d", w.Code)
	}
	if w := do(h, "POST", "/jobs/job_1/approve", url.Values{"csrf": {"tok"}}, true, map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != http.StatusForbidden {
		t.Fatalf("cross site: %d", w.Code)
	}
	if j, _ := st.Job(context.Background(), "job_1"); j.State != store.JobPendingApproval {
		t.Fatalf("job changed by a refused request: %s", j.State)
	}
	w := do(h, "POST", "/jobs/job_1/reject", url.Values{"csrf": {"tok"}, "note": {"not now"}}, true,
		map[string]string{"Origin": "https://dockgate.example", "Sec-Fetch-Site": "same-origin"})
	if w.Code != http.StatusSeeOther || !strings.HasSuffix(w.Header().Get("Location"), "?notice=rejected") {
		t.Fatalf("reject: %d %s", w.Code, w.Header().Get("Location"))
	}
	j, _ := st.Job(context.Background(), "job_1")
	if j.State != store.JobRejected || j.DecidedBy != "oidc:me@example.com" || j.Note != "not now" {
		t.Fatalf("job = %+v", j)
	}
	if w := do(h, "GET", "/jobs/job_1?notice=<b>hi</b>", nil, true, nil); strings.Contains(w.Body.String(), "hi</b>") {
		t.Fatal("arbitrary notice text rendered")
	}
}
