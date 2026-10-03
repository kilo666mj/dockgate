package hub_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"go.michaelspost.com/dockgate/internal/agent"
	"go.michaelspost.com/dockgate/internal/docker"
	"go.michaelspost.com/dockgate/internal/hub"
	"go.michaelspost.com/dockgate/internal/pki"
	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/store"
	"go.michaelspost.com/dockgate/internal/updates"
)

type env struct {
	url   string
	store *store.Store
	ca    *pki.CA
}

func startHub(t *testing.T) env {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "dockgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h, err := hub.New(hub.Config{Store: st, CA: ca, Logger: logger, ReportInterval: 30 * time.Second, CertDir: dir, Hosts: []string{"127.0.0.1"}, SBOMRequests: true})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h.Handler(), TLSConfig: h.TLSConfig(), ReadHeaderTimeout: 5 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return env{url: "https://" + ln.Addr().String(), store: st, ca: ca}
}

func (e env) token(t *testing.T, name string, replace bool) string {
	t.Helper()
	tok := protocol.JoinToken{ID: fmt.Sprintf("tok-%s-%d", name, time.Now().UnixNano()), Secret: "secret-" + name, CAPin: e.ca.Pin()}
	if err := e.store.CreateToken(context.Background(), tok.ID, tok.Secret, name, replace, time.Hour); err != nil {
		t.Fatal(err)
	}
	return tok.String()
}

// fakeDocker serves the handful of Engine API endpoints the collector uses.
func fakeDocker(t *testing.T) *docker.Client {
	t.Helper()
	responses := map[string]string{
		"/version": `{"Version":"29.1.0","ApiVersion":"1.52","Os":"linux","Arch":"amd64","KernelVersion":"6.12.0"}`,
		"/info":    `{"NCPU":4,"MemTotal":8589934592}`,
		"/images/json": `[
			{"Id":"sha256:img1","RepoTags":["valkey/valkey:latest"],"RepoDigests":["valkey/valkey@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"Size":100,"Created":1700000000},
			{"Id":"sha256:img2","RepoTags":["postgres:16-alpine"],"RepoDigests":["postgres@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],"Size":200,"Created":1700000000}]`,
		"/containers/json": `[
			{"Id":"c1","Names":["/redis"],"Image":"valkey/valkey:latest","ImageID":"sha256:img1","State":"running","Status":"Up 2 hours","Labels":{"com.docker.compose.project":"alpha","com.docker.compose.service":"redis"},"Created":1700000000},
			{"Id":"c3","Names":["/web"],"Image":"alpha-web","ImageID":"sha256:img3","State":"running","Status":"Up","Labels":{"com.docker.compose.project":"alpha","com.docker.compose.service":"web"},"Created":1700000000},
			{"Id":"c2","Names":["/db"],"Image":"postgres:16-alpine","ImageID":"sha256:img2","State":"running","Status":"Up 2 hours (unhealthy)","Labels":{},"Created":1700000000}]`,
		"/containers/c1/json": `{"RestartCount":0,"State":{"StartedAt":"2026-10-03T10:00:00Z"},"Config":{"Image":"valkey/valkey:latest"}}`,
		"/containers/c3/json": `{"RestartCount":0,"State":{"StartedAt":"2026-10-03T10:00:00Z"},"Config":{"Image":"alpha-web"}}`,
		"/containers/c2/json": `{"RestartCount":3,"State":{"StartedAt":"2026-10-03T10:00:00Z","Health":{"Status":"unhealthy"}},"Config":{"Image":"postgres:16-alpine"}}`,
	}
	scannerImage := "/images/" + agent.ScannerRepository + "@" + agent.ScannerDigest + "/json"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The scanner container: exists, then create, start, wait, logs, remove.
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/images/sha256:img") && strings.HasSuffix(r.URL.Path, "/json"):
			_, _ = io.WriteString(w, `{"Id":"`+strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/images/"), "/json")+`"}`)
			return
		case r.Method == http.MethodGet && r.URL.Path == scannerImage:
			_, _ = io.WriteString(w, `{"Id":"sha256:scanner"}`)
			return
		case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
			var spec struct {
				HostConfig struct{ NetworkMode string }
			}
			_ = json.NewDecoder(r.Body).Decode(&spec)
			if spec.HostConfig.NetworkMode != "none" {
				http.Error(w, `{"message":"scanner must have no network"}`, http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, `{"Id":"scan1"}`)
			return
		case r.Method == http.MethodPost && r.URL.Path == "/containers/scan1/start":
			w.WriteHeader(http.StatusNoContent)
			return
		case r.Method == http.MethodPost && r.URL.Path == "/containers/scan1/wait":
			_, _ = io.WriteString(w, `{"StatusCode":0}`)
			return
		case r.Method == http.MethodGet && r.URL.Path == "/containers/scan1/logs":
			_, _ = w.Write(frame(1, `{"bomFormat":"CycloneDX","components":[]}`))
			_, _ = w.Write(frame(2, "done"))
			return
		case r.Method == http.MethodDelete && r.URL.Path == "/containers/scan1":
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, ok := responses[r.URL.Path]
		if !ok {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return docker.NewWithHTTP(srv.Client(), srv.URL)
}

const (
	digestCurrent = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	digestNew     = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// frame encodes one Docker log stream frame.
func frame(stream byte, payload string) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = stream
	binary.BigEndian.PutUint32(b[4:], uint32(len(payload)))
	copy(b[8:], payload)
	return b
}

func fakeRegistry(_ context.Context, ref name.Reference) (string, error) {
	switch ref.Context().Name() {
	case "index.docker.io/valkey/valkey":
		return digestNew, nil
	case "index.docker.io/library/postgres":
		return digestCurrent, nil
	}
	return "", errors.New("unexpected reference " + ref.Name())
}

func TestEnrollReportAndRenew(t *testing.T) {
	e := startHub(t)
	ctx := context.Background()
	stateDir := filepath.Join(t.TempDir(), "agent")

	st, err := agent.Enroll(ctx, e.url, e.token(t, "alpha", false), "alpha-host", stateDir, false)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if st.Name != "alpha" {
		t.Fatalf("agent name = %q, want token name alpha", st.Name)
	}
	if info, err := os.Stat(filepath.Join(stateDir, "agent.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("agent key mode: %v %v", info.Mode(), err)
	}

	id, err := agent.LoadIdentity(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	dc := fakeDocker(t)
	collector := &agent.Collector{Docker: dc, Updates: updates.NewChecker(fakeRegistry, time.Hour), Version: "test"}
	sboms := agent.NewSBOMWorker(&agent.SBOMGenerator{Docker: dc, SocketPath: "/var/run/docker.sock"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	report := collector.Collect(ctx)
	if len(report.Errors) != 0 {
		t.Fatalf("collect errors: %v", report.Errors)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- agent.Run(runCtx, id, collector, sboms, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	waitFor(t, func() bool {
		agents, err := e.store.Agents(ctx)
		return err == nil && len(agents) == 1 && !agents[0].LastReportAt.IsZero()
	})
	// The first report reply asks for SBOMs of up to two images; the worker
	// runs the scanner container and uploads them.
	waitFor(t, func() bool {
		_, err1 := e.store.LoadSBOM(ctx, "sha256:img1")
		_, err2 := e.store.LoadSBOM(ctx, "sha256:img2")
		return err1 == nil && err2 == nil
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("agent run: %v", err)
	}

	containers, err := e.store.Containers(ctx, st.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]protocol.Container{}
	for _, c := range containers {
		got[c.Name] = c
	}
	if c := got["redis"]; c.Update == nil || c.Update.Status != protocol.UpdateAvailable || c.ComposeService != "redis" {
		t.Errorf("redis = %+v, want update available and compose service", c)
	}
	if c := got["web"]; c.Update == nil || c.Update.Status != protocol.UpdateUnsupported {
		t.Errorf("web = %+v, want compose-built image unsupported", c.Update)
	}
	if c := got["db"]; c.Update == nil || c.Update.Status != protocol.UpdateCurrent || c.Health != "unhealthy" || c.RestartCount != 3 {
		t.Errorf("db = %+v, want current, unhealthy, 3 restarts", c)
	}

	before := id.NotAfter()
	time.Sleep(1100 * time.Millisecond) // certificate times have second precision
	if err := id.Renew(ctx, id.HTTPClient()); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !id.NotAfter().After(before) {
		t.Errorf("renewed NotAfter %v not after %v", id.NotAfter(), before)
	}
}

func TestEnrollRejectsWrongPin(t *testing.T) {
	e := startHub(t)
	tok, err := protocol.ParseJoinToken(e.token(t, "bravo", false))
	if err != nil {
		t.Fatal(err)
	}
	tok.CAPin = strings.Repeat("0", 64)
	_, err = agent.Enroll(context.Background(), e.url, tok.String(), "bravo", t.TempDir(), false)
	if err == nil || !strings.Contains(err.Error(), "pinned CA") {
		t.Fatalf("enroll with wrong pin: err = %v, want pinned CA error", err)
	}
}

func TestTokenIsSingleUse(t *testing.T) {
	e := startHub(t)
	tok := e.token(t, "charlie", false)
	if _, err := agent.Enroll(context.Background(), e.url, tok, "charlie", t.TempDir(), false); err != nil {
		t.Fatal(err)
	}
	_, err := agent.Enroll(context.Background(), e.url, tok, "charlie", t.TempDir(), false)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("second enrollment: err = %v, want 401", err)
	}
}

func TestRevokedAgentIsRejected(t *testing.T) {
	e := startHub(t)
	ctx := context.Background()
	dir := t.TempDir()
	if _, err := agent.Enroll(ctx, e.url, e.token(t, "delta", false), "delta", dir, false); err != nil {
		t.Fatal(err)
	}
	id, err := agent.LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.RevokeAgent(ctx, "delta"); err != nil {
		t.Fatal(err)
	}
	err = id.Renew(ctx, id.HTTPClient())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("renew after revoke: err = %v, want 403", err)
	}
}

func TestReportRequiresClientCertificate(t *testing.T) {
	e := startHub(t)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.ca.Pool(), MinVersion: tls.VersionTLS13}}}
	resp, err := client.Post(e.url+protocol.PathReport, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body protocol.Error
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d (%s), want 401", resp.StatusCode, body.Error)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
