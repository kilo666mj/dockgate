package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"go.michaelspost.com/dockgate/internal/docker"
	"go.michaelspost.com/dockgate/internal/protocol"
)

const (
	oldID      = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111"
	jobDigest  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	jobRef     = "ghcr.io/example/app:release"
	jobRepo    = "ghcr.io/example/app"
	oldImageID = "sha256:old"
)

// decode parses JSON with numbers kept as json.Number, as the client does.
func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

type fakeDocker struct {
	t          *testing.T
	containers map[string]*docker.Inspect // by ID
	names      map[string]string          // name -> ID
	calls      []string
	created    map[string]any
	connected  []string
	digests    []string
	modes      map[string]string

	failStart   string // container ID whose start fails
	newHealth   string // health of the new container: "", healthy, unhealthy
	newExits    bool   // the new container stops right after start
	failRestore bool
}

func newFakeDocker(t *testing.T) *fakeDocker {
	old := &docker.Inspect{ID: oldID, Name: "/app", Image: oldImageID}
	old.State.Running, old.State.Status, old.State.StartedAt = true, "running", "t0"
	old.Config = decode(t, `{"Hostname":"aaaaaaaaaaaa","Image":"`+jobRef+`",
		"Env":["PATH=/usr/bin","APP_VERSION=1","MODE=prod"],
		"Cmd":["serve"],"Labels":{"com.docker.compose.project":"web","org.opencontainers.image.version":"1"},
		"ExposedPorts":{"8080/tcp":{}},"Volumes":{"/data":{},"/cache":{}}}`)
	old.HostConfig = decode(t, `{"NetworkMode":"web_default","Binds":["/srv/conf:/conf:ro"],"Memory":17179869184,
		"Links":["/db:/app/database"]}`)
	old.Mounts = []docker.Mount{
		{Type: "bind", Source: "/srv/conf", Destination: "/conf"},
		{Type: "volume", Name: "f00dcafe", Destination: "/data", RW: true},
		{Type: "volume", Name: "beefcafe", Destination: "/cache", RW: true},
	}
	old.NetworkSettings.Networks = map[string]map[string]any{
		"web_default": decode(t, `{"Aliases":["app","aaaaaaaaaaaa"],"IPAMConfig":null}`),
		"backend":     decode(t, `{"Aliases":["app"]}`),
	}
	return &fakeDocker{
		t: t, containers: map[string]*docker.Inspect{oldID: old}, names: map[string]string{"app": oldID},
		digests: []string{jobRepo + "@" + jobDigest}, modes: map[string]string{"app": "web_default", "db": "web_default"},
	}
}

func (f *fakeDocker) get(id string) (*docker.Inspect, error) {
	if c, ok := f.containers[id]; ok {
		return c, nil
	}
	if real, ok := f.names[id]; ok {
		return f.containers[real], nil
	}
	return nil, &docker.StatusError{Code: 404, Message: "no such container"}
}

func (f *fakeDocker) InspectContainer(_ context.Context, id string) (docker.Inspect, error) {
	c, err := f.get(id)
	if err != nil {
		return docker.Inspect{}, err
	}
	return *c, nil
}

func (f *fakeDocker) ImageConfig(_ context.Context, ref string) (map[string]any, error) {
	if ref != oldImageID {
		f.t.Fatalf("image config for %s", ref)
	}
	return decode(f.t, `{"Env":["PATH=/usr/bin","APP_VERSION=1"],"Cmd":["serve"],
		"Labels":{"org.opencontainers.image.version":"1"},"ExposedPorts":{"8080/tcp":{}},"Volumes":{"/data":{}}}`), nil
}

func (f *fakeDocker) ImageDigests(context.Context, string) ([]string, error) { return f.digests, nil }
func (f *fakeDocker) NetworkModes(context.Context) (map[string]string, error) {
	return f.modes, nil
}

func (f *fakeDocker) PullAuth(_ context.Context, repo, digest, auth string) error {
	f.calls = append(f.calls, "pull "+repo+"@"+digest+" auth="+auth)
	return nil
}

func (f *fakeDocker) TagImage(_ context.Context, ref, repo, tag string) error {
	f.calls = append(f.calls, "tag "+ref+" "+repo+":"+tag)
	return nil
}

func (f *fakeDocker) RenameContainer(_ context.Context, id, name string) error {
	f.calls = append(f.calls, "rename "+id[:4]+" "+name)
	if f.failRestore && name == "app" {
		return errors.New("rename failed")
	}
	c, err := f.get(id)
	if err != nil {
		return err
	}
	delete(f.names, strings.TrimPrefix(c.Name, "/"))
	c.Name = "/" + name
	f.names[name] = c.ID
	return nil
}

func (f *fakeDocker) StopContainer(_ context.Context, id string) error {
	f.calls = append(f.calls, "stop "+id[:4])
	c, err := f.get(id)
	if err != nil {
		return err
	}
	c.State.Running, c.State.Status = false, "exited"
	return nil
}

func (f *fakeDocker) StartContainer(_ context.Context, id string) error {
	f.calls = append(f.calls, "start "+id[:4])
	if id == f.failStart {
		return errors.New("port is already allocated")
	}
	c, err := f.get(id)
	if err != nil {
		return err
	}
	c.State.Running, c.State.Status, c.State.StartedAt = true, "running", "t1"
	if id != oldID {
		if f.newHealth != "" {
			c.State.Health = &struct {
				Status string `json:"Status"`
			}{f.newHealth}
		}
		if f.newExits {
			c.State.Running, c.State.Status = false, "exited"
		}
	}
	return nil
}

func (f *fakeDocker) CreateContainer(_ context.Context, name string, body map[string]any) (string, error) {
	if _, taken := f.names[name]; taken {
		return "", errors.New("name in use")
	}
	f.calls = append(f.calls, "create "+name)
	f.created = body
	id := "bbbbbbbbbbbb2222"
	c := &docker.Inspect{ID: id, Name: "/" + name}
	c.State.Status = "created"
	f.containers[id], f.names[name] = c, id
	return id, nil
}

func (f *fakeDocker) ConnectNetwork(_ context.Context, network, id string, ep map[string]any) error {
	f.connected = append(f.connected, network)
	return nil
}

func (f *fakeDocker) RemoveKeepVolumes(_ context.Context, id string) error {
	f.calls = append(f.calls, "remove "+id[:4])
	c, err := f.get(id)
	if err != nil {
		return err
	}
	delete(f.containers, c.ID)
	delete(f.names, strings.TrimPrefix(c.Name, "/"))
	return nil
}

func (f *fakeDocker) LogTail(context.Context, string, int) (string, error) {
	return "fatal: config missing\n", nil
}

func executor(f *fakeDocker) *Executor {
	now := time.Unix(0, 0)
	return &Executor{
		Docker: f, RegistryAuth: func(string) string { return "creds" },
		StableFor: 10 * time.Second, PollEvery: time.Second,
		now:   func() time.Time { return now },
		sleep: func(_ context.Context, d time.Duration) error { now = now.Add(d); return nil },
	}
}

func job() protocol.Job {
	return protocol.Job{ID: "job_0123456789", Kind: protocol.JobUpdate, ContainerID: oldID, ContainerName: "app", Reference: jobRef, Digest: jobDigest}
}

func TestUpdateSucceedsAndCarriesConfigOver(t *testing.T) {
	f := newFakeDocker(t)
	res := executor(f).Execute(context.Background(), job())
	if res.State != protocol.JobSucceeded {
		t.Fatalf("result = %+v", res)
	}
	want := []string{
		"pull " + jobRepo + "@" + jobDigest + " auth=creds",
		"tag " + jobRepo + "@" + jobDigest + " " + jobRepo + ":release",
		"rename aaaa app-dockgate-old-01234567",
		"stop aaaa",
		"create app",
		"start bbbb",
		"remove aaaa",
	}
	if !slices.Equal(f.calls, want) {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(f.calls, "\n"), strings.Join(want, "\n"))
	}
	b := f.created
	if _, ok := b["Hostname"]; ok {
		t.Error("default hostname carried over")
	}
	if _, ok := b["Cmd"]; ok {
		t.Error("image default Cmd carried over")
	}
	if env := b["Env"].([]any); len(env) != 1 || env[0] != "MODE=prod" {
		t.Errorf("env = %v, want only the container's own MODE=prod", env)
	}
	if labels := b["Labels"].(map[string]any); len(labels) != 1 || labels["com.docker.compose.project"] != "web" {
		t.Errorf("labels = %v", labels)
	}
	if b["Image"] != jobRef {
		t.Errorf("image = %v", b["Image"])
	}
	host := b["HostConfig"].(map[string]any)
	if host["Memory"] != json.Number("17179869184") {
		t.Errorf("memory = %#v", host["Memory"])
	}
	if links := host["Links"].([]any); links[0] != "db:database" {
		t.Errorf("links = %v", links)
	}
	mounts := host["Mounts"].([]any)
	if len(mounts) != 2 {
		t.Errorf("anonymous volumes not carried over: %v", mounts)
	}
	for _, m := range mounts {
		mm := m.(map[string]any)
		if (mm["Target"] == "/data") != (mm["Source"] == "f00dcafe") {
			t.Errorf("mount = %v", mm)
		}
	}
	if vols := b["Volumes"].(map[string]any); len(vols) != 0 {
		t.Errorf("volume declarations left beside their mounts: %v", vols)
	}
	eps := b["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)
	aliases := eps["web_default"].(map[string]any)["Aliases"].([]any)
	if len(eps) != 1 || len(aliases) != 1 || aliases[0] != "app" {
		t.Errorf("endpoints = %v", eps)
	}
	if !slices.Equal(f.connected, []string{"backend"}) {
		t.Errorf("connected = %v", f.connected)
	}
}

func TestUpdateRollsBackWhenNewContainerFailsToStart(t *testing.T) {
	f := newFakeDocker(t)
	f.failStart = "bbbbbbbbbbbb2222"
	res := executor(f).Execute(context.Background(), job())
	if res.State != protocol.JobRolledBack || !strings.Contains(res.Error, "port is already allocated") {
		t.Fatalf("result = %+v", res)
	}
	old := f.containers[oldID]
	if old.Name != "/app" || !old.State.Running {
		t.Fatalf("old container not restored: %s running=%v", old.Name, old.State.Running)
	}
	if _, ok := f.containers["bbbbbbbbbbbb2222"]; ok {
		t.Fatal("new container left behind")
	}
	if !strings.Contains(strings.Join(res.Steps, "\n"), "fatal: config missing") {
		t.Errorf("steps lack the new container's output: %v", res.Steps)
	}
}

func TestUpdateRollsBackUnhealthyAndExitingContainers(t *testing.T) {
	for name, set := range map[string]func(*fakeDocker){
		"unhealthy": func(f *fakeDocker) { f.newHealth = "unhealthy" },
		"exits":     func(f *fakeDocker) { f.newExits = true },
		"starting":  func(f *fakeDocker) { f.newHealth = "starting" }, // never becomes healthy
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeDocker(t)
			set(f)
			res := executor(f).Execute(context.Background(), job())
			if res.State != protocol.JobRolledBack {
				t.Fatalf("result = %+v", res)
			}
			if old := f.containers[oldID]; old.Name != "/app" || !old.State.Running {
				t.Fatal("old container not restored")
			}
		})
	}
}

func TestUpdateWaitsForHealthy(t *testing.T) {
	f := newFakeDocker(t)
	f.newHealth = "healthy"
	if res := executor(f).Execute(context.Background(), job()); res.State != protocol.JobSucceeded {
		t.Fatalf("result = %+v", res)
	}
}

func TestUpdateReportsFailedRollback(t *testing.T) {
	f := newFakeDocker(t)
	f.failStart, f.failRestore = "bbbbbbbbbbbb2222", true
	res := executor(f).Execute(context.Background(), job())
	if res.State != protocol.JobRolledBack || !strings.Contains(res.Error, "rollback failed") {
		t.Fatalf("result = %+v", res)
	}
}

func TestUpdateRefusesBeforeChangingAnything(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*fakeDocker, *protocol.Job)
		want string
	}{
		"renamed":       {func(f *fakeDocker, j *protocol.Job) { j.ContainerName = "other" }, "now named"},
		"image changed": {func(f *fakeDocker, j *protocol.Job) { j.Reference = "ghcr.io/example/app:v2" }, "now uses image"},
		"stopped":       {func(f *fakeDocker, j *protocol.Job) { f.containers[oldID].State.Running = false }, "not running"},
		"shared netns":  {func(f *fakeDocker, j *protocol.Job) { f.modes["vpn"] = "container:app" }, "network namespace"},
		"wrong digest":  {func(f *fakeDocker, j *protocol.Job) { f.digests = []string{jobRepo + "@sha256:other"} }, "does not carry digest"},
		"digest ref":    {func(f *fakeDocker, j *protocol.Job) { j.Reference = jobRepo + "@" + jobDigest }, "pinned by digest"},
		"kind":          {func(f *fakeDocker, j *protocol.Job) { j.Kind = "exec" }, "unknown job kind"},
		"dockgate label": {func(f *fakeDocker, j *protocol.Job) {
			f.containers[oldID].Config["Labels"].(map[string]any)["dockgate.role"] = "sbom"
		}, "dockgate label"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeDocker(t)
			j := job()
			tc.set(f, &j)
			res := executor(f).Execute(context.Background(), j)
			if res.State != protocol.JobFailed || !strings.Contains(res.Error, tc.want) {
				t.Fatalf("result = %+v, want failure containing %q", res, tc.want)
			}
			for _, c := range f.calls {
				if !strings.HasPrefix(c, "pull ") && !strings.HasPrefix(c, "tag ") {
					t.Fatalf("changed the container before refusing: %v", f.calls)
				}
			}
		})
	}
}

func TestSplitReference(t *testing.T) {
	for ref, want := range map[string][2]string{
		"redis":                      {"redis", "latest"},
		"redis:7":                    {"redis", "7"},
		"ghcr.io/a/b:release":        {"ghcr.io/a/b", "release"},
		"registry.example:5000/x:v1": {"registry.example:5000/x", "v1"},
		"registry.example:5000/x":    {"registry.example:5000/x", "latest"},
	} {
		repo, tag, err := splitReference(ref)
		if err != nil || repo != want[0] || tag != want[1] {
			t.Errorf("splitReference(%q) = %q, %q, %v; want %v", ref, repo, tag, err, want)
		}
	}
}

func TestHealthWait(t *testing.T) {
	body := map[string]any{"Healthcheck": map[string]any{
		"StartPeriod": json.Number("120000000000"), "Interval": json.Number("10000000000"),
		"Timeout": json.Number("5000000000"), "Retries": json.Number("5"),
	}}
	if got := healthWait(body, time.Minute); got != 120*time.Second+75*time.Second+30*time.Second {
		t.Errorf("healthWait = %s", got)
	}
	if got := healthWait(map[string]any{}, 0); got != 3*time.Minute {
		t.Errorf("default healthWait = %s", got)
	}
}
