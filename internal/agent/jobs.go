package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"go.michaelspost.com/dockgate/internal/docker"
	"go.michaelspost.com/dockgate/internal/protocol"
)

// Docker is the Engine API surface the job executor uses.
type Docker interface {
	InspectContainer(ctx context.Context, id string) (docker.Inspect, error)
	ImageConfig(ctx context.Context, ref string) (map[string]any, error)
	ImageDigests(ctx context.Context, ref string) ([]string, error)
	NetworkModes(ctx context.Context) (map[string]string, error)
	PullAuth(ctx context.Context, repository, digest, registryAuth string) error
	TagImage(ctx context.Context, ref, repository, tag string) error
	RenameContainer(ctx context.Context, id, name string) error
	StopContainer(ctx context.Context, id string) error
	StartContainer(ctx context.Context, id string) error
	CreateContainer(ctx context.Context, name string, body map[string]any) (string, error)
	ConnectNetwork(ctx context.Context, network, id string, endpoint map[string]any) error
	RemoveKeepVolumes(ctx context.Context, id string) error
	LogTail(ctx context.Context, id string, lines int) (string, error)
}

// Executor carries out update jobs.
type Executor struct {
	Docker Docker
	// RegistryAuth returns an X-Registry-Auth value for a repository, or ""
	// for anonymous pulls.
	RegistryAuth func(repository string) string
	// StableFor is how long a container without a health check must keep
	// running after start; HealthTimeout bounds waiting for healthy when
	// the image's health check does not imply a longer wait.
	StableFor     time.Duration
	HealthTimeout time.Duration
	PollEvery     time.Duration
	now           func() time.Time
	sleep         func(ctx context.Context, d time.Duration) error
}

func (e *Executor) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now()
}

func (e *Executor) wait(ctx context.Context, d time.Duration) error {
	if e.sleep != nil {
		return e.sleep(ctx, d)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// NewExecutor returns an executor for the daemon d that pulls with the
// registry credentials in the Docker client configuration.
func NewExecutor(d Docker) *Executor {
	return &Executor{Docker: d, RegistryAuth: registryAuth}
}

// run records an update job's steps.
type run struct {
	steps []string
}

func (r *run) logf(format string, args ...any) {
	r.steps = append(r.steps, fmt.Sprintf(format, args...))
}

// Execute runs one job and always returns a result for the server.
func (e *Executor) Execute(ctx context.Context, job protocol.Job) protocol.JobResult {
	start := e.clock()
	r := &run{}
	res := protocol.JobResult{ID: job.ID}
	if job.Kind != protocol.JobUpdate {
		res.State, res.Error = protocol.JobFailed, fmt.Sprintf("unknown job kind %q", job.Kind)
	} else {
		newID, rolledBack, err := e.update(ctx, job, r)
		res.NewContainerID = newID
		switch {
		case err == nil:
			res.State = protocol.JobSucceeded
		case rolledBack:
			res.State, res.Error = protocol.JobRolledBack, err.Error()
		default:
			res.State, res.Error = protocol.JobFailed, err.Error()
		}
	}
	res.Steps = r.steps
	res.DurationMS = e.clock().Sub(start).Milliseconds()
	return res
}

// splitReference returns the repository and tag a reference names, as
// written (so "redis" stays "redis"). Digest references are refused: they
// pin an image and are never updated.
func splitReference(ref string) (repository, tag string, err error) {
	parsed, err := name.ParseReference(ref, name.WeakValidation)
	if err != nil {
		return "", "", err
	}
	t, ok := parsed.(name.Tag)
	if !ok {
		return "", "", fmt.Errorf("%s is pinned by digest", ref)
	}
	tag = t.TagStr()
	repository = strings.TrimSuffix(ref, ":"+tag)
	if repository == ref && tag != "latest" {
		return "", "", fmt.Errorf("cannot split %s", ref)
	}
	return repository, tag, nil
}

// update recreates the container. It reports whether a failure was rolled
// back to the old container.
func (e *Executor) update(ctx context.Context, job protocol.Job, r *run) (string, bool, error) {
	if !strings.HasPrefix(job.Digest, "sha256:") {
		return "", false, fmt.Errorf("digest %q is not a sha256 digest", job.Digest)
	}
	repository, tag, err := splitReference(job.Reference)
	if err != nil {
		return "", false, fmt.Errorf("image reference: %w", err)
	}

	old, err := e.Docker.InspectContainer(ctx, job.ContainerID)
	if err != nil {
		return "", false, fmt.Errorf("inspect container: %w", err)
	}
	oldName := strings.TrimPrefix(old.Name, "/")
	if oldName != job.ContainerName {
		return "", false, fmt.Errorf("container %s is now named %s", job.ContainerID[:min(12, len(job.ContainerID))], oldName)
	}
	if ref, _ := old.Config["Image"].(string); ref != job.Reference {
		return "", false, fmt.Errorf("container now uses image %q, not %q", ref, job.Reference)
	}
	if !old.State.Running {
		return "", false, fmt.Errorf("container is %s, not running", old.State.Status)
	}
	if labels, _ := old.Config["Labels"].(map[string]any); labels != nil {
		for k := range labels {
			if strings.HasPrefix(k, "dockgate.") {
				return "", false, fmt.Errorf("container carries dockgate label %s", k)
			}
		}
	}
	modes, err := e.Docker.NetworkModes(ctx)
	if err != nil {
		return "", false, fmt.Errorf("list containers: %w", err)
	}
	for other, mode := range modes {
		if other == oldName {
			continue
		}
		if target, ok := strings.CutPrefix(mode, "container:"); ok && (target == oldName || target == old.ID || strings.HasPrefix(old.ID, target)) {
			return "", false, fmt.Errorf("container %s shares this container's network namespace; recreating would cut it off", other)
		}
	}
	oldImage, err := e.Docker.ImageConfig(ctx, old.Image)
	if err != nil {
		return "", false, fmt.Errorf("inspect current image: %w", err)
	}
	body, extraNetworks, err := recreateBody(old, oldImage)
	if err != nil {
		return "", false, err
	}
	r.logf("checked %s (%s), image %s", oldName, old.ID[:min(12, len(old.ID))], job.Reference)

	auth := ""
	if e.RegistryAuth != nil {
		auth = e.RegistryAuth(repository)
	}
	if err := e.Docker.PullAuth(ctx, repository, job.Digest, auth); err != nil {
		return "", false, err
	}
	pinned := repository + "@" + job.Digest
	digests, err := e.Docker.ImageDigests(ctx, pinned)
	if err != nil {
		return "", false, fmt.Errorf("inspect pulled image: %w", err)
	}
	if !hasDigest(digests, job.Digest) {
		return "", false, fmt.Errorf("pulled image does not carry digest %s", job.Digest)
	}
	if err := e.Docker.TagImage(ctx, pinned, repository, tag); err != nil {
		return "", false, fmt.Errorf("tag %s:%s: %w", repository, tag, err)
	}
	r.logf("pulled %s and tagged it %s:%s", pinned, repository, tag)

	// From here on the host changes. Rename first so the new container can
	// take the name; every failure below restores the old container.
	parked := fmt.Sprintf("%s-dockgate-old-%s", oldName, shortJobID(job.ID))
	if err := e.Docker.RenameContainer(ctx, old.ID, parked); err != nil {
		return "", false, fmt.Errorf("rename old container: %w", err)
	}
	r.logf("renamed old container to %s", parked)
	if err := e.Docker.StopContainer(ctx, old.ID); err != nil {
		return "", true, e.rollback(ctx, r, old.ID, oldName, "", fmt.Errorf("stop old container: %w", err))
	}
	r.logf("stopped old container")

	newID, err := e.Docker.CreateContainer(ctx, oldName, body)
	if err != nil {
		return "", true, e.rollback(ctx, r, old.ID, oldName, "", fmt.Errorf("create new container: %w", err))
	}
	r.logf("created %s (%s)", oldName, newID[:min(12, len(newID))])
	for _, n := range extraNetworks {
		if err := e.Docker.ConnectNetwork(ctx, n.name, newID, n.endpoint); err != nil {
			return newID, true, e.rollback(ctx, r, old.ID, oldName, newID, fmt.Errorf("connect network %s: %w", n.name, err))
		}
	}
	if err := e.Docker.StartContainer(ctx, newID); err != nil {
		return newID, true, e.rollback(ctx, r, old.ID, oldName, newID, fmt.Errorf("start new container: %w", err))
	}
	r.logf("started new container")
	if err := e.awaitHealthy(ctx, newID, r); err != nil {
		return newID, true, e.rollback(ctx, r, old.ID, oldName, newID, err)
	}
	if err := e.Docker.RemoveKeepVolumes(ctx, old.ID); err != nil {
		// The update worked; the parked container is only clutter.
		r.logf("could not remove old container %s: %v", parked, err)
	} else {
		r.logf("removed old container, kept its volumes")
	}
	return newID, false, nil
}

// rollback removes the new container (if any) and restores the old one. It
// returns cause, extended when the restore itself fails.
func (e *Executor) rollback(ctx context.Context, r *run, oldID, oldName, newID string, cause error) error {
	// Roll back even when the job's context was cancelled.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
	defer cancel()
	r.logf("failed: %v; rolling back", cause)
	if newID != "" {
		if logs, err := e.Docker.LogTail(ctx, newID, 20); err == nil && strings.TrimSpace(logs) != "" {
			r.logf("new container's last output:\n%s", strings.TrimRight(logs, "\n"))
		}
		if err := e.Docker.RemoveKeepVolumes(ctx, newID); err != nil {
			return fmt.Errorf("%w; rollback failed: remove new container: %v", cause, err)
		}
		r.logf("removed new container")
	}
	if err := e.Docker.RenameContainer(ctx, oldID, oldName); err != nil {
		return fmt.Errorf("%w; rollback failed: rename old container back to %s: %v", cause, oldName, err)
	}
	if err := e.Docker.StartContainer(ctx, oldID); err != nil {
		return fmt.Errorf("%w; rollback failed: start old container: %v", cause, err)
	}
	r.logf("restored and started old container %s", oldName)
	return cause
}

// awaitHealthy waits until the new container is healthy (with a health
// check) or has kept running without restarting for StableFor.
func (e *Executor) awaitHealthy(ctx context.Context, id string, r *run) error {
	poll := e.PollEvery
	if poll <= 0 {
		poll = 2 * time.Second
	}
	first, err := e.Docker.InspectContainer(ctx, id)
	if err != nil {
		return fmt.Errorf("inspect new container: %w", err)
	}
	if first.State.Health != nil {
		// The created container's config includes the image's health check.
		limit := healthWait(first.Config, e.HealthTimeout)
		deadline := e.clock().Add(limit)
		for {
			c, err := e.Docker.InspectContainer(ctx, id)
			if err != nil {
				return fmt.Errorf("inspect new container: %w", err)
			}
			switch {
			case !c.State.Running:
				return fmt.Errorf("new container stopped (%s)", c.State.Status)
			case c.Health() == "healthy":
				r.logf("new container is healthy")
				return nil
			case c.Health() == "unhealthy":
				return errors.New("new container is unhealthy")
			case !e.clock().Before(deadline):
				return fmt.Errorf("new container not healthy after %s (%s)", limit, c.Health())
			}
			if err := e.wait(ctx, poll); err != nil {
				return err
			}
		}
	}
	stable := e.StableFor
	if stable <= 0 {
		stable = 15 * time.Second
	}
	deadline := e.clock().Add(stable)
	for {
		c, err := e.Docker.InspectContainer(ctx, id)
		if err != nil {
			return fmt.Errorf("inspect new container: %w", err)
		}
		if !c.State.Running || c.State.Restarting || c.RestartCount != first.RestartCount || c.State.StartedAt != first.State.StartedAt {
			return fmt.Errorf("new container did not stay up (%s, %d restarts)", c.State.Status, c.RestartCount)
		}
		if !e.clock().Before(deadline) {
			r.logf("new container kept running for %s", stable)
			return nil
		}
		if err := e.wait(ctx, poll); err != nil {
			return err
		}
	}
}

// healthWait is how long to wait for healthy: the health check's start
// period plus its retries, with a floor of base and a ceiling of 10 minutes.
func healthWait(config map[string]any, base time.Duration) time.Duration {
	if base <= 0 {
		base = 3 * time.Minute
	}
	hc, _ := config["Healthcheck"].(map[string]any)
	if hc == nil {
		return base
	}
	ns := func(k string, def time.Duration) time.Duration {
		if v, ok := hc[k].(json.Number); ok {
			if n, err := v.Int64(); err == nil && n > 0 {
				return time.Duration(n)
			}
		}
		return def
	}
	retries := int64(3)
	if v, ok := hc["Retries"].(json.Number); ok {
		if n, err := v.Int64(); err == nil && n > 0 {
			retries = n
		}
	}
	d := ns("StartPeriod", 0) + time.Duration(retries)*(ns("Interval", 30*time.Second)+ns("Timeout", 30*time.Second)) + 30*time.Second
	return min(max(d, base), 10*time.Minute)
}

func hasDigest(repoDigests []string, digest string) bool {
	for _, d := range repoDigests {
		if strings.HasSuffix(d, "@"+digest) {
			return true
		}
	}
	return false
}

func shortJobID(id string) string {
	id = strings.TrimPrefix(id, "job_")
	return id[:min(8, len(id))]
}

type network struct {
	name     string
	endpoint map[string]any
}

// recreateBody builds the create request for the replacement container from
// the old container's inspect output. Settings that only echo the old
// image's defaults are dropped so the new image's defaults apply.
func recreateBody(old docker.Inspect, oldImage map[string]any) (map[string]any, []network, error) {
	cfg := make(map[string]any, len(old.Config))
	for k, v := range old.Config {
		cfg[k] = v
	}
	if h, _ := cfg["Hostname"].(string); h != "" && strings.HasPrefix(old.ID, h) {
		delete(cfg, "Hostname") // the default: the container's short ID
	}
	for _, k := range []string{"Cmd", "Entrypoint", "WorkingDir", "User", "Healthcheck", "StopSignal", "Shell"} {
		if v, ok := cfg[k]; ok && oldImage != nil && reflect.DeepEqual(v, oldImage[k]) {
			delete(cfg, k)
		}
	}
	delete(cfg, "OnBuild")
	if env, ok := cfg["Env"].([]any); ok {
		imageEnv := map[string]bool{}
		if ie, ok := oldImage["Env"].([]any); ok {
			for _, v := range ie {
				if s, ok := v.(string); ok {
					imageEnv[s] = true
				}
			}
		}
		var keep []any
		for _, v := range env {
			if s, ok := v.(string); ok && imageEnv[s] {
				continue
			}
			keep = append(keep, v)
		}
		cfg["Env"] = keep
	}
	for _, k := range []string{"Labels", "ExposedPorts", "Volumes"} {
		m, ok := cfg[k].(map[string]any)
		if !ok {
			continue
		}
		im, _ := oldImage[k].(map[string]any)
		kept := map[string]any{}
		for key, v := range m {
			if iv, ok := im[key]; ok && reflect.DeepEqual(iv, v) {
				continue
			}
			kept[key] = v
		}
		cfg[k] = kept
	}

	host := make(map[string]any, len(old.HostConfig))
	for k, v := range old.HostConfig {
		host[k] = v
	}
	if links, ok := host["Links"].([]any); ok && len(links) > 0 {
		var converted []any
		for _, l := range links {
			s, _ := l.(string)
			// Inspect reports "/target:/self/alias"; create wants
			// "target:alias".
			target, alias, ok := strings.Cut(s, ":")
			if !ok {
				return nil, nil, fmt.Errorf("cannot carry over link %q", s)
			}
			alias = alias[strings.LastIndex(alias, "/")+1:]
			converted = append(converted, strings.TrimPrefix(target, "/")+":"+alias)
		}
		host["Links"] = converted
	}
	// Anonymous volumes are not in Binds or Mounts; carry them over by name
	// so the new container keeps their data.
	declared := map[string]bool{}
	if binds, ok := host["Binds"].([]any); ok {
		for _, b := range binds {
			if s, ok := b.(string); ok {
				if parts := strings.Split(s, ":"); len(parts) >= 2 {
					declared[parts[1]] = true
				}
			}
		}
	}
	mounts, _ := host["Mounts"].([]any)
	for _, m := range mounts {
		if mm, ok := m.(map[string]any); ok {
			if t, ok := mm["Target"].(string); ok {
				declared[t] = true
			}
		}
	}
	vols, _ := cfg["Volumes"].(map[string]any)
	for _, m := range old.Mounts {
		if m.Type == "volume" && m.Name != "" && !declared[m.Destination] {
			mounts = append(mounts, map[string]any{"Type": "volume", "Source": m.Name, "Target": m.Destination, "ReadOnly": !m.RW})
			// The mount replaces the declaration, which would otherwise
			// create a second, empty anonymous volume at the same path.
			delete(vols, m.Destination)
		}
	}
	if len(mounts) > 0 {
		host["Mounts"] = mounts
	}

	mode, _ := host["NetworkMode"].(string)
	var primary map[string]any
	var extra []network
	for netName, ep := range old.NetworkSettings.Networks {
		endpoint := map[string]any{}
		for _, k := range []string{"IPAMConfig", "Links", "DriverOpts"} {
			if v, ok := ep[k]; ok && v != nil {
				endpoint[k] = v
			}
		}
		if aliases, ok := ep["Aliases"].([]any); ok {
			var keep []any
			for _, a := range aliases {
				if s, ok := a.(string); ok && strings.HasPrefix(old.ID, s) {
					continue // the old container's short ID
				}
				keep = append(keep, a)
			}
			if len(keep) > 0 {
				endpoint["Aliases"] = keep
			}
		}
		if netName == mode || (mode == "default" && netName == "bridge") {
			primary = map[string]any{netName: endpoint}
			continue
		}
		if strings.HasPrefix(mode, "container:") || mode == "host" || mode == "none" {
			continue
		}
		extra = append(extra, network{name: netName, endpoint: endpoint})
	}

	body := cfg
	body["HostConfig"] = host
	if primary != nil {
		body["NetworkingConfig"] = map[string]any{"EndpointsConfig": primary}
	}
	return body, extra, nil
}

// registryAuth returns an X-Registry-Auth header value from the Docker
// client configuration, or "" for anonymous access.
func registryAuth(repository string) string {
	repo, err := name.NewRepository(repository, name.WeakValidation)
	if err != nil {
		return ""
	}
	auth, err := (anonymousOnError{authn.DefaultKeychain}).Resolve(repo)
	if err != nil || auth == authn.Anonymous {
		return ""
	}
	cfg, err := auth.Authorization()
	if err != nil {
		return ""
	}
	v, err := json.Marshal(map[string]string{
		"username": cfg.Username, "password": cfg.Password,
		"identitytoken": cfg.IdentityToken, "serveraddress": repo.RegistryStr(),
	})
	if err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(v)
}

type anonymousOnError struct{ authn.Keychain }

func (k anonymousOnError) Resolve(target authn.Resource) (authn.Authenticator, error) {
	auth, err := k.Keychain.Resolve(target)
	if err != nil {
		return authn.Anonymous, nil
	}
	return auth, nil
}

// JobWorker runs jobs one at a time and delivers their results, keeping
// undelivered results until the server accepts them.
type JobWorker struct {
	Executor *Executor
	Logger   *slog.Logger

	mu      sync.Mutex
	queue   []protocol.Job
	held    map[string]bool
	results []protocol.JobResult
	wake    chan struct{}
}

// NewJobWorker returns a worker using e.
func NewJobWorker(e *Executor, logger *slog.Logger) *JobWorker {
	return &JobWorker{Executor: e, Logger: logger, held: map[string]bool{}, wake: make(chan struct{}, 1)}
}

// Enqueue adds jobs the worker does not already hold.
func (w *JobWorker) Enqueue(jobs []protocol.Job) {
	w.mu.Lock()
	for _, j := range jobs {
		if !w.held[j.ID] {
			w.held[j.ID] = true
			w.queue = append(w.queue, j)
		}
	}
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Held lists the jobs queued, running or awaiting delivery.
func (w *JobWorker) Held() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.held))
	for id := range w.held {
		out = append(out, id)
	}
	return out
}

// Run executes jobs and posts results to resultURL until ctx ends.
func (w *JobWorker) Run(ctx context.Context, client *http.Client, resultURL string) {
	for {
		w.deliver(ctx, client, resultURL)
		w.mu.Lock()
		var job *protocol.Job
		if len(w.queue) > 0 {
			j := w.queue[0]
			w.queue = w.queue[1:]
			job = &j
		}
		w.mu.Unlock()
		if job != nil {
			w.Logger.Info("job started", "job_id", job.ID, "kind", job.Kind, "container", job.ContainerName, "digest", job.Digest)
			res := w.Executor.Execute(ctx, *job)
			w.Logger.Info("job finished", "job_id", job.ID, "state", res.State, "err", res.Error, "duration_ms", res.DurationMS)
			w.mu.Lock()
			w.results = append(w.results, res)
			w.mu.Unlock()
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
		case <-time.After(30 * time.Second):
		}
	}
}

func (w *JobWorker) deliver(ctx context.Context, client *http.Client, resultURL string) {
	for {
		w.mu.Lock()
		if len(w.results) == 0 {
			w.mu.Unlock()
			return
		}
		res := w.results[0]
		w.mu.Unlock()
		var out struct{}
		if err := postJSON(ctx, client, resultURL, res, &out); err != nil && !rejected(err) {
			w.Logger.Error("deliver job result", "job_id", res.ID, "err", err)
			return
		} else if err != nil {
			// The server will never take this result (for example the job
			// is unknown); keep it in the log rather than retrying forever.
			w.Logger.Error("job result rejected", "job_id", res.ID, "state", res.State, "steps", strings.Join(res.Steps, "; "), "err", err)
		}
		w.mu.Lock()
		w.results = w.results[1:]
		delete(w.held, res.ID)
		w.mu.Unlock()
	}
}
