package jobs

import (
	"context"
	"errors"
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

const (
	curDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	newDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

type fakePublisher struct{ cards []tintwire.Card }

func (p *fakePublisher) Publish(_ context.Context, c tintwire.Card) (tintwire.Result, error) {
	p.cards = append(p.cards, c)
	return tintwire.Result{}, nil
}

type env struct {
	st    *store.Store
	svc   *Service
	pub   *fakePublisher
	now   time.Time
	agent string
}

// report saves a report with one container, web, whose update to newDigest
// (or remote) is available.
func (e *env) report(t *testing.T, containerID, remote, state string) {
	t.Helper()
	rep := protocol.Report{Docker: protocol.DockerInfo{OS: "linux", Arch: "amd64"}, Containers: []protocol.Container{{
		ID: containerID, Name: "web", Image: "example/web:latest", ImageID: "sha256:img0", State: state,
		Update: &protocol.UpdateCheck{Status: protocol.UpdateAvailable, Reference: "example/web:latest",
			LocalDigests: []string{curDigest}, RemoteDigest: remote},
	}}}
	if err := e.st.SaveReport(context.Background(), e.agent, rep, e.now); err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T, scanCandidate bool) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	sign := func(string) (store.Issued, error) {
		return store.Issued{Serial: "1", NotAfter: now.Add(time.Hour)}, nil
	}
	if err := st.CreateToken(ctx, "t", "s", "alpha", false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Enroll(ctx, "t", "s", "pin", "agt_a", sign); err != nil {
		t.Fatal(err)
	}
	pub := &fakePublisher{}
	e := &env{st: st, pub: pub, now: now, agent: "agt_a"}
	e.svc = &Service{Store: st, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Publisher: pub,
		BaseURL: "https://dockgate.example", OwnImagePrefixes: []string{"git.example/me/"}, now: func() time.Time { return e.now }}
	e.report(t, "c1", newDigest, "running")
	if _, err := st.RequestSBOMs(ctx, "agt_a", 5, store.AgentQueue{}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSBOM(ctx, "agt_a", protocol.SBOMUpload{ImageID: "sha256:img0", Format: protocol.FormatCycloneDXJSON, Document: []byte(`{}`)}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveScan(ctx, store.SBOMKey{AgentID: "agt_a", ImageID: "sha256:img0"}, "db1",
		[]store.Finding{{VulnID: "CVE-1", Pkg: "openssl", Installed: "1", Fixed: "2", Severity: "CRITICAL"}}, "", now); err != nil {
		t.Fatal(err)
	}
	if scanCandidate {
		key := store.CandidateKey{Digest: newDigest, Platform: "linux/amd64"}
		if err := st.SaveCandidateSBOM(ctx, store.RegistryTarget{Reference: "example/web@" + newDigest, Digest: newDigest, Platform: "linux/amd64"}, []byte(`{}`), "", now); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveCandidateScan(ctx, key, "db1", []store.Finding{{VulnID: "CVE-9", Pkg: "zlib", Installed: "1", Fixed: "2", Severity: "HIGH"}}, "", now); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func request(e *env) (store.Job, error) {
	return e.svc.RequestUpdate(context.Background(), Request{Host: "alpha", Container: "web", Reason: "fix CVE-1", TaskID: "01TASK", Actor: "mcp:agent"})
}

func TestRequestGatesAndRecordsPendingJob(t *testing.T) {
	e := setup(t, true)
	job, err := request(e)
	if err != nil {
		t.Fatal(err)
	}
	if job.CreatedAt.IsZero() || job.State != store.JobPendingApproval || job.Digest != newDigest || job.Reference != "example/web:latest" || job.ContainerID != "c1" {
		t.Fatalf("job = %+v", job)
	}
	if len(job.Gate.Fixes) != 1 || len(job.Gate.Introduces) != 1 || !job.Gate.Hold {
		t.Fatalf("gate = %+v, want CVE-1 fixed, CVE-9 introduced and held", job.Gate)
	}
	if len(e.pub.cards) != 1 || !strings.Contains(e.pub.cards[0].Title, "Approve update: web on alpha") ||
		e.pub.cards[0].Actions[0].URL != "https://dockgate.example/jobs/"+job.ID {
		t.Fatalf("cards = %+v", e.pub.cards)
	}
	if _, err := request(e); !errors.Is(err, store.ErrJobState) {
		t.Fatalf("second request: %v, want an open-job error", err)
	}
}

func TestRequestDenials(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*testing.T, *env)
		want string
	}{
		"not scanned": {func(*testing.T, *env) {}, "not finished"},
		"stopped":     {func(t *testing.T, e *env) { e.report(t, "c1", newDigest, "exited") }, "only running"},
		"own image": {func(t *testing.T, e *env) {
			e.svc.OwnImagePrefixes = []string{"example/"}
		}, "pull request"},
	} {
		t.Run(name, func(t *testing.T) {
			e := setup(t, name != "not scanned")
			tc.set(t, e)
			job, err := request(e)
			if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want denial containing %q", err, tc.want)
			}
			stored, err := e.st.Job(context.Background(), job.ID)
			if err != nil || stored.State != store.JobDenied {
				t.Fatalf("denied job not recorded: %+v, %v", stored, err)
			}
		})
	}
	e := setup(t, true)
	if _, err := e.svc.RequestUpdate(context.Background(), Request{Host: "alpha", Container: "nope", Actor: "x"}); err == nil || errors.Is(err, ErrDenied) {
		t.Fatalf("unknown container: %v", err)
	}
}

func TestRequestDeniesBuildxBuilders(t *testing.T) {
	e := setup(t, true)
	rep := protocol.Report{Docker: protocol.DockerInfo{OS: "linux", Arch: "amd64"}, Containers: []protocol.Container{{
		ID: "b1", Name: "buildx_buildkit_builder0", Image: "moby/buildkit:buildx-stable-1", ImageID: "sha256:bk", State: "running",
		Update: &protocol.UpdateCheck{Status: protocol.UpdateAvailable, Reference: "moby/buildkit:buildx-stable-1", RemoteDigest: newDigest},
	}}}
	if err := e.st.SaveReport(context.Background(), e.agent, rep, e.now); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.RequestUpdate(context.Background(), Request{Host: "alpha", Container: "buildx_buildkit_builder0", Actor: "x"})
	if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "buildx") {
		t.Fatalf("err = %v", err)
	}
}

func TestApproveDispatchFinish(t *testing.T) {
	e := setup(t, true)
	ctx := context.Background()
	job, err := request(e)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := e.st.DispatchJobs(ctx, e.agent, nil, e.now); len(got) != 0 {
		t.Fatal("dispatched an unapproved job")
	}
	job, err = e.svc.Decide(ctx, job.ID, true, "oidc:me@example.com", "")
	if err != nil || job.State != store.JobApproved || job.DecidedBy != "oidc:me@example.com" {
		t.Fatalf("approve = %+v, %v", job, err)
	}
	got, err := e.st.DispatchJobs(ctx, e.agent, nil, e.now)
	if err != nil || len(got) != 1 || got[0].Digest != newDigest || got[0].ContainerID != "c1" || got[0].Reference != "example/web:latest" {
		t.Fatalf("dispatch = %+v, %v", got, err)
	}
	if again, _ := e.st.DispatchJobs(ctx, e.agent, []string{job.ID}, e.now); len(again) != 0 {
		t.Fatal("job dispatched twice")
	}
	res := protocol.JobResult{ID: job.ID, State: protocol.JobSucceeded, Steps: []string{"ok"}}
	if _, err := e.st.FinishJob(ctx, "agt_other", res, e.now); !errors.Is(err, store.ErrJobUnknown) {
		t.Fatalf("result from another agent: %v", err)
	}
	done, err := e.st.FinishJob(ctx, e.agent, res, e.now)
	if err != nil || done.State != store.JobSucceeded || done.Result == nil || done.Result.Steps[0] != "ok" {
		t.Fatalf("finish = %+v, %v", done, err)
	}
	if _, err := e.st.FinishJob(ctx, e.agent, res, e.now); !errors.Is(err, store.ErrJobUnknown) {
		t.Fatalf("second result: %v", err)
	}
	if _, err := e.st.FinishJob(ctx, e.agent, protocol.JobResult{ID: job.ID, State: "exploded"}, e.now); !errors.Is(err, store.ErrJobResult) {
		t.Fatalf("bad state: %v", err)
	}
	e.svc.Finished(ctx, done)
	if last := e.pub.cards[len(e.pub.cards)-1]; last.Severity != tintwire.SeveritySuccess || last.LifecycleKey != "dockgate-job-"+job.ID {
		t.Fatalf("finished card = %+v", last)
	}
	states := []string{}
	for _, ev := range done.Events {
		states = append(states, ev.State)
	}
	if strings.Join(states, ",") != "pending_approval,approved,dispatched,succeeded" {
		t.Fatalf("history = %v", states)
	}
}

func TestApprovalSupersededByNewerImage(t *testing.T) {
	e := setup(t, true)
	job, err := request(e)
	if err != nil {
		t.Fatal(err)
	}
	e.report(t, "c1", "sha256:3333333333333333333333333333333333333333333333333333333333333333", "running")
	job, err = e.svc.Decide(context.Background(), job.ID, true, "oidc:me", "")
	if err != nil || job.State != store.JobSuperseded {
		t.Fatalf("approve after newer image = %+v, %v", job, err)
	}
}

func TestRejectAndDecideOnlyOnce(t *testing.T) {
	e := setup(t, true)
	ctx := context.Background()
	job, _ := request(e)
	if job, err := e.svc.Decide(ctx, job.ID, false, "oidc:me", "not now"); err != nil || job.State != store.JobRejected {
		t.Fatalf("reject = %+v, %v", job, err)
	}
	if _, err := e.svc.Decide(ctx, job.ID, true, "oidc:me", ""); !errors.Is(err, store.ErrJobState) {
		t.Fatalf("approve after reject: %v", err)
	}
	// A rejected job no longer blocks a new request.
	if _, err := request(e); err != nil {
		t.Fatalf("request after reject: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	e := setup(t, true)
	ctx := context.Background()
	pending, _ := request(e)
	e.now = e.now.Add(25 * time.Hour)
	closed, err := e.st.ExpireJobs(ctx, e.now)
	if err != nil || len(closed) != 1 || closed[0].State != store.JobExpired {
		t.Fatalf("expire pending = %+v, %v", closed, err)
	}
	_ = pending

	job, err := request(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Decide(ctx, job.ID, true, "oidc:me", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DispatchJobs(ctx, e.agent, nil, e.now); err != nil {
		t.Fatal(err)
	}
	// Held by the agent: stays dispatched.
	e.now = e.now.Add(8 * time.Minute)
	if _, err := e.st.DispatchJobs(ctx, e.agent, []string{job.ID}, e.now); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(8 * time.Minute)
	if closed, _ := e.st.ExpireJobs(ctx, e.now); len(closed) != 0 {
		t.Fatalf("held job closed: %+v", closed)
	}
	e.now = e.now.Add(3 * time.Minute)
	closed, err = e.st.ExpireJobs(ctx, e.now)
	if err != nil || len(closed) != 1 || closed[0].State != store.JobLost {
		t.Fatalf("expire unheld = %+v, %v", closed, err)
	}
	// A late result still lands.
	if j, err := e.st.FinishJob(ctx, e.agent, protocol.JobResult{ID: job.ID, State: protocol.JobRolledBack}, e.now); err != nil || j.State != store.JobRolledBack {
		t.Fatalf("late result = %+v, %v", j, err)
	}
}
