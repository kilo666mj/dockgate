package agent

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"go.michaelspost.com/dockgate/internal/docker"
)

// fakeScanner answers Run calls in order and records each spec.
type fakeScanner struct {
	results []docker.RunResult
	specs   []docker.RunSpec
}

func (f *fakeScanner) ImageExists(context.Context, string) (bool, error) { return true, nil }
func (f *fakeScanner) PullImage(context.Context, string, string) error   { return nil }
func (f *fakeScanner) RemoveLabeled(context.Context, string, string) (int, error) {
	return 0, nil
}
func (f *fakeScanner) Run(_ context.Context, spec docker.RunSpec) (docker.RunResult, error) {
	f.specs = append(f.specs, spec)
	if len(f.results) == 0 {
		return docker.RunResult{ExitCode: 99, Stderr: []byte("unexpected run")}, nil
	}
	r := f.results[0]
	f.results = f.results[1:]
	return r, nil
}

const imageID = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// The production failure: the Java DB error sits above the last line.
var javaDBFailure = docker.RunResult{ExitCode: 1, Stderr: []byte(
	"FATAL failed to download Java DB: failed to download artifact from mirror.gcr.io/aquasec/trivy-java-db:1: OCI repository error: 1 error occurred:\n" +
		"\t* Get \"https://mirror.gcr.io/v2/\": dial tcp: connect: network is unreachable\n")}

var sbomOK = docker.RunResult{Output: []byte(`{"bomFormat":"CycloneDX"}`)}

func hasJavaDBBind(spec docker.RunSpec, mode string) bool {
	want := JavaDBVolume + ":" + javaDBMount + mode
	return slices.Contains(spec.Binds, want)
}

func hasSocket(spec docker.RunSpec) bool {
	for _, b := range spec.Binds {
		if strings.Contains(b, "docker.sock") {
			return true
		}
	}
	return false
}

func TestSBOMFetchesJavaDBOnlyWhenNeeded(t *testing.T) {
	f := &fakeScanner{results: []docker.RunResult{javaDBFailure, {}, sbomOK, sbomOK}}
	g := &SBOMGenerator{Docker: f, SocketPath: "/var/run/docker.sock"}
	ctx := context.Background()

	doc, err := g.Generate(ctx, imageID)
	if err != nil || string(doc) != string(sbomOK.Output) {
		t.Fatalf("Generate = %s, %v", doc, err)
	}
	if len(f.specs) != 3 {
		t.Fatalf("runs = %d, want offline scan, fetch, scan with DB", len(f.specs))
	}
	first, fetch, retry := f.specs[0], f.specs[1], f.specs[2]
	if first.Network != "" || hasJavaDBBind(first, ":ro") || slices.Contains(first.Cmd, "--skip-java-db-update") {
		t.Fatalf("first scan should be plain and offline: %+v", first)
	}
	// The fetch is the only container with network, and it never sees the
	// Docker socket or an image.
	if fetch.Network != "bridge" || hasSocket(fetch) || !hasJavaDBBind(fetch, "") || !slices.Contains(fetch.Cmd, "--download-java-db-only") {
		t.Fatalf("fetch spec = %+v", fetch)
	}
	if slices.Contains(fetch.Cmd, imageID) {
		t.Fatalf("fetch must not name an image: %v", fetch.Cmd)
	}
	if retry.Network != "" || !hasJavaDBBind(retry, ":ro") || !slices.Contains(retry.Cmd, "--skip-java-db-update") || retry.Cmd[len(retry.Cmd)-1] != imageID {
		t.Fatalf("retry spec = %+v", retry)
	}

	// While the DB is fresh, scans mount it straight away: one run, no fetch.
	if _, err := g.Generate(ctx, imageID); err != nil {
		t.Fatal(err)
	}
	if len(f.specs) != 4 || !hasJavaDBBind(f.specs[3], ":ro") || f.specs[3].Network != "" {
		t.Fatalf("fresh-DB scan = %+v", f.specs[3:])
	}
}

func TestSBOMStaleJavaDBIsRefreshed(t *testing.T) {
	f := &fakeScanner{results: []docker.RunResult{javaDBFailure, {}, sbomOK}}
	g := &SBOMGenerator{Docker: f, SocketPath: "/s", javaDBAt: time.Now().Add(-2 * javaDBRefreshAfter)}
	if _, err := g.Generate(context.Background(), imageID); err != nil {
		t.Fatal(err)
	}
	if len(f.specs) != 3 || f.specs[1].Network != "bridge" {
		t.Fatalf("stale DB not refreshed: %+v", f.specs)
	}
	if time.Since(g.javaDBAt) > time.Minute {
		t.Fatal("fetch time not recorded")
	}
}

func TestSBOMFetchFailureKeepsBothErrors(t *testing.T) {
	f := &fakeScanner{results: []docker.RunResult{javaDBFailure, {ExitCode: 1, Stderr: []byte("no route to host")}}}
	g := &SBOMGenerator{Docker: f, SocketPath: "/s"}
	_, err := g.Generate(context.Background(), imageID)
	if err == nil || !strings.Contains(err.Error(), "network is unreachable") || !strings.Contains(err.Error(), "no route to host") {
		t.Fatalf("err = %v", err)
	}
	if !g.javaDBAt.IsZero() {
		t.Fatal("failed fetch recorded as success")
	}
}

func TestSBOMOtherFailuresDoNotFetch(t *testing.T) {
	f := &fakeScanner{results: []docker.RunResult{{ExitCode: 1, Stderr: []byte("FATAL image export failed")}}}
	g := &SBOMGenerator{Docker: f, SocketPath: "/s"}
	if _, err := g.Generate(context.Background(), imageID); err == nil {
		t.Fatal("want error")
	}
	if len(f.specs) != 1 {
		t.Fatalf("runs = %d, want 1 (no Java DB fetch)", len(f.specs))
	}
}
