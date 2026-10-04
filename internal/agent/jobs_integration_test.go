//go:build integration

// Integration test for the update executor against a real Docker daemon.
// It pulls alpine images, creates containers, networks and volumes named
// dgtest-*, and removes them afterwards. Run on a Docker host with
//
//	go test -tags integration -run TestIntegration ./internal/agent
package agent

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"go.michaelspost.com/dockgate/internal/docker"
	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/updates"
)

const testRef = "alpine:dgtest"

func socket() string {
	if s := os.Getenv("DOCKER_SOCKET"); s != "" {
		return s
	}
	return "/var/run/docker.sock"
}

// raw issues Engine API calls the client does not wrap.
func raw(t *testing.T, dc *docker.Client, method, path string, body any) {
	t.Helper()
	if err := dc.Raw(context.Background(), method, path, body); err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
}

func setupContainer(t *testing.T, dc *docker.Client, healthCmd string) (string, string) {
	t.Helper()
	ctx := context.Background()
	// The "old" image: alpine 3.19, tagged locally as the test reference.
	if err := dc.PullAuth(ctx, "alpine", "3.19", ""); err != nil {
		t.Fatal(err)
	}
	if err := dc.TagImage(ctx, "alpine:3.19", "alpine", "dgtest"); err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference("alpine:3.20")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := updates.RegistryHead(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(dc)
	t.Cleanup(func() { cleanup(dc) })
	raw(t, dc, "POST", "/networks/create", map[string]any{"Name": "dgtest-net"})
	raw(t, dc, "POST", "/networks/create", map[string]any{"Name": "dgtest-net2"})
	raw(t, dc, "POST", "/volumes/create", map[string]any{"Name": "dgtest-vol"})
	id, err := dc.CreateContainer(ctx, "dgtest-app", map[string]any{
		"Image": testRef, "Cmd": []string{"sleep", "1d"}, "Env": []string{"FOO=bar"},
		"Labels":      map[string]string{"dgtest": "1"},
		"Volumes":     map[string]any{"/anon": map[string]any{}},
		"Healthcheck": map[string]any{"Test": []string{"CMD-SHELL", healthCmd}, "Interval": int64(time.Second), "Retries": 2},
		"HostConfig": map[string]any{
			"NetworkMode": "dgtest-net", "Binds": []string{"dgtest-vol:/named"}, "RestartPolicy": map[string]any{"Name": "unless-stopped"},
		},
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{"dgtest-net": map[string]any{"Aliases": []string{"app"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dc.ConnectNetwork(ctx, "dgtest-net2", id, map[string]any{"Aliases": []string{"app2"}}); err != nil {
		t.Fatal(err)
	}
	if err := dc.StartContainer(ctx, id); err != nil {
		t.Fatal(err)
	}
	return id, digest
}

func cleanup(dc *docker.Client) {
	ctx := context.Background()
	modes, _ := dc.NetworkModes(ctx)
	for n := range modes {
		if strings.HasPrefix(n, "dgtest-") {
			_ = dc.Remove(ctx, n)
		}
	}
	for _, p := range []string{"/networks/dgtest-net", "/networks/dgtest-net2", "/volumes/dgtest-vol"} {
		_ = dc.Raw(ctx, "DELETE", p, nil)
	}
}

func TestIntegrationUpdate(t *testing.T) {
	dc := docker.New(socket())
	ctx := context.Background()
	id, digest := setupContainer(t, dc, "true")
	before, err := dc.InspectContainer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	var anon string
	for _, m := range before.Mounts {
		if m.Destination == "/anon" {
			anon = m.Name
		}
	}
	e := NewExecutor(dc)
	e.StableFor = 3 * time.Second
	res := e.Execute(ctx, protocol.Job{ID: "job_integration", Kind: protocol.JobUpdate, ContainerID: id, ContainerName: "dgtest-app", Reference: testRef, Digest: digest})
	t.Logf("steps:\n%s", strings.Join(res.Steps, "\n"))
	if res.State != protocol.JobSucceeded {
		t.Fatalf("result = %+v", res)
	}
	after, err := dc.InspectContainer(ctx, "dgtest-app")
	if err != nil {
		t.Fatal(err)
	}
	if after.ID == id || after.Image == before.Image || after.Health() != "healthy" {
		t.Fatalf("not replaced: id %s image %s health %s", after.ID[:12], after.Image, after.Health())
	}
	if env, _ := json.Marshal(after.Config["Env"]); !strings.Contains(string(env), "FOO=bar") {
		t.Errorf("env = %s", env)
	}
	if after.HostConfig["RestartPolicy"].(map[string]any)["Name"] != "unless-stopped" {
		t.Errorf("restart policy = %v", after.HostConfig["RestartPolicy"])
	}
	for net, alias := range map[string]string{"dgtest-net": "app", "dgtest-net2": "app2"} {
		ep, ok := after.NetworkSettings.Networks[net]
		if !ok {
			t.Errorf("not on %s", net)
			continue
		}
		b, _ := json.Marshal(ep["Aliases"])
		if !strings.Contains(string(b), `"`+alias+`"`) {
			t.Errorf("%s aliases = %s", net, b)
		}
	}
	var names []string
	for _, m := range after.Mounts {
		names = append(names, m.Destination+"="+m.Name)
	}
	if !slices.Contains(names, "/anon="+anon) || !slices.Contains(names, "/named=dgtest-vol") {
		t.Errorf("mounts = %v, want /anon=%s and /named=dgtest-vol", names, anon)
	}
	if _, err := dc.InspectContainer(ctx, id); !docker.IsNotFound(err) {
		t.Errorf("old container still present: %v", err)
	}
}

func TestIntegrationRollback(t *testing.T) {
	dc := docker.New(socket())
	ctx := context.Background()
	// Healthy only on alpine 3.19, so the 3.20 replacement turns unhealthy.
	id, digest := setupContainer(t, dc, "grep -q '^3.19' /etc/alpine-release")
	e := NewExecutor(dc)
	res := e.Execute(ctx, protocol.Job{ID: "job_integration2", Kind: protocol.JobUpdate, ContainerID: id, ContainerName: "dgtest-app", Reference: testRef, Digest: digest})
	t.Logf("steps:\n%s", strings.Join(res.Steps, "\n"))
	if res.State != protocol.JobRolledBack {
		t.Fatalf("result = %+v", res)
	}
	c, err := dc.InspectContainer(ctx, "dgtest-app")
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != id || !c.State.Running {
		t.Fatalf("old container not restored: %s running=%v", c.ID[:12], c.State.Running)
	}
}
