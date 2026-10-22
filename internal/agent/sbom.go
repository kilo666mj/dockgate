package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"go.michaelspost.com/dockgate/internal/docker"
	"go.michaelspost.com/dockgate/internal/protocol"
)

// Scanner image, pinned by digest: the scanner gets the Docker socket, so a
// moved tag must never change what runs. Bump deliberately.
const (
	ScannerRepository = "aquasec/trivy"
	ScannerDigest     = "sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969" // 0.74.0
	ScannerVersion    = "trivy 0.74.0"
)

// Label marking the agent's scanner containers.
const (
	LabelRole = "dockgate.role"
	RoleSBOM  = "sbom"
)

// Limits for one SBOM run. Large images take minutes because the scanner
// exports the whole image from the daemon.
const (
	sbomTimeout   = 20 * time.Minute
	maxSBOMBytes  = 48 << 20
	sbomQueueSize = 64
)

// Java index database. Trivy needs it to identify JAR files and cannot run
// without it. The agent fetches it only after a scan fails for lack of it,
// into a named volume that scans mount read-only.
const (
	JavaDBVolume       = "dockgate-trivy-java-db"
	javaDBMount        = "/work/cache/java-db"
	javaDBRefreshAfter = 24 * time.Hour
)

// scannerDocker is the part of the Docker client the generator uses.
type scannerDocker interface {
	ImageExists(ctx context.Context, ref string) (bool, error)
	PullImage(ctx context.Context, repository, digest string) error
	Run(ctx context.Context, spec docker.RunSpec) (docker.RunResult, error)
	RemoveLabeled(ctx context.Context, label, value string) (int, error)
}

// SBOMGenerator inventories local images with the pinned scanner container.
// It is used from one goroutine (SBOMWorker), so it needs no locking.
type SBOMGenerator struct {
	Docker     scannerDocker
	SocketPath string

	javaDBAt time.Time // last successful Java DB fetch by this process
}

// Generate returns a CycloneDX JSON SBOM for a local image ID.
func (g *SBOMGenerator) Generate(ctx context.Context, imageID string) ([]byte, error) {
	if !strings.HasPrefix(imageID, "sha256:") || strings.ContainsAny(imageID, " /") {
		return nil, fmt.Errorf("refusing image ID %q", imageID)
	}
	// A running container can outlive its image, for example after a compose
	// rebuild removes the old one. Say so plainly rather than letting the
	// scanner fall back to a registry it cannot reach.
	if present, err := g.Docker.ImageExists(ctx, imageID); err != nil {
		return nil, fmt.Errorf("check image: %w", err)
	} else if !present {
		return nil, errors.New("image is no longer on the host; a container still runs it, so recreate the container")
	}
	if err := g.ensureScanner(ctx); err != nil {
		return nil, err
	}
	fresh := !g.javaDBAt.IsZero() && time.Since(g.javaDBAt) < javaDBRefreshAfter
	doc, needsJavaDB, err := g.scan(ctx, imageID, fresh)
	if err == nil || !needsJavaDB || fresh {
		return doc, err
	}
	// The image has JAR files. Fetch the Java DB, then scan again offline.
	if ferr := g.fetchJavaDB(ctx); ferr != nil {
		return nil, fmt.Errorf("%w (fetching the Java DB also failed: %v)", err, ferr)
	}
	doc, _, err = g.scan(ctx, imageID, true)
	return doc, err
}

func (g *SBOMGenerator) ensureScanner(ctx context.Context) error {
	ok, err := g.Docker.ImageExists(ctx, ScannerRepository+"@"+ScannerDigest)
	if err != nil {
		return fmt.Errorf("check scanner image: %w", err)
	}
	if ok {
		return nil
	}
	return g.Docker.PullImage(ctx, ScannerRepository, ScannerDigest)
}

// scan runs the scanner with no network. needsJavaDB reports a failure that
// the Java DB would fix.
func (g *SBOMGenerator) scan(ctx context.Context, imageID string, withJavaDB bool) (doc []byte, needsJavaDB bool, err error) {
	// Packages only: no vulnerability scan here, so no database download
	// and no network, which the container does not have. Trivy copies the
	// exported image into TMPDIR, so that is the disk-backed work volume:
	// a tmpfs fills on large images and aborts the export mid-stream.
	cmd := []string{"image", "--quiet", "--format", "cyclonedx", "--cache-dir", "/work/cache",
		"--output", "/work/sbom.json"}
	binds := []string{g.SocketPath + ":/var/run/docker.sock:ro"}
	if withJavaDB {
		cmd = append(cmd, "--skip-java-db-update")
		binds = append(binds, JavaDBVolume+":"+javaDBMount+":ro")
	}
	res, err := g.Docker.Run(ctx, docker.RunSpec{
		Image:      ScannerRepository + "@" + ScannerDigest,
		Cmd:        append(cmd, imageID),
		Env:        []string{"TMPDIR=/work"},
		Binds:      binds,
		Labels:     map[string]string{LabelRole: RoleSBOM},
		WorkDir:    "/work",
		OutputFile: "/work/sbom.json",
		MaxOutput:  maxSBOMBytes,
	})
	if err != nil {
		return nil, false, err
	}
	if res.ExitCode != 0 {
		// The Java DB error is several lines above the last one.
		needsJavaDB = strings.Contains(string(res.Stderr), "Java DB")
		return nil, needsJavaDB, fmt.Errorf("scanner exited %d: %s", res.ExitCode, lastLine(res.Stderr))
	}
	if !json.Valid(res.Output) {
		return nil, false, fmt.Errorf("scanner output is not JSON: %s", lastLine(res.Stderr))
	}
	return res.Output, false, nil
}

// fetchJavaDB downloads or updates the Java DB in its volume. This container
// has network but no Docker socket and no image access: it can only write
// the database. Trivy skips the download while the stored copy is current.
func (g *SBOMGenerator) fetchJavaDB(ctx context.Context) error {
	res, err := g.Docker.Run(ctx, docker.RunSpec{
		Image:   ScannerRepository + "@" + ScannerDigest,
		Cmd:     []string{"image", "--quiet", "--download-java-db-only", "--cache-dir", "/work/cache"},
		Env:     []string{"TMPDIR=/work"},
		Binds:   []string{JavaDBVolume + ":" + javaDBMount},
		Labels:  map[string]string{LabelRole: RoleSBOM},
		WorkDir: "/work",
		Network: "bridge",
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("exited %d: %s", res.ExitCode, lastLine(res.Stderr))
	}
	g.javaDBAt = time.Now()
	return nil
}

// Cleanup removes scanner containers left behind when a previous agent
// process stopped in the middle of a run.
func (g *SBOMGenerator) Cleanup(ctx context.Context) (int, error) {
	return g.Docker.RemoveLabeled(ctx, LabelRole, RoleSBOM)
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// SBOMWorker generates requested SBOMs one at a time in the background, so
// slow scans never delay inventory reports.
type SBOMWorker struct {
	Generator *SBOMGenerator
	Logger    *slog.Logger

	queue   chan string
	mu      sync.Mutex
	pending map[string]bool
}

// NewSBOMWorker returns an idle worker.
func NewSBOMWorker(g *SBOMGenerator, logger *slog.Logger) *SBOMWorker {
	return &SBOMWorker{Generator: g, Logger: logger, queue: make(chan string, sbomQueueSize), pending: map[string]bool{}}
}

// Enqueue adds image IDs that are not already queued or in progress.
func (w *SBOMWorker) Enqueue(ids []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, id := range ids {
		if w.pending[id] {
			continue
		}
		select {
		case w.queue <- id:
			w.pending[id] = true
		default:
			return // full; the server asks again later
		}
	}
}

// Pending returns the images queued or in progress, which the agent reports
// so the server can tell a lost request from a slow one.
func (w *SBOMWorker) Pending() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.pending))
	for id := range w.pending {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Run processes the queue until ctx ends, uploading each result.
func (w *SBOMWorker) Run(ctx context.Context, client *http.Client, uploadURL string) {
	if n, err := w.Generator.Cleanup(ctx); err != nil {
		w.Logger.Warn("remove leftover scanner containers", "err", err)
	} else if n > 0 {
		w.Logger.Info("removed leftover scanner containers", "count", n)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-w.queue:
			w.process(ctx, client, uploadURL, id)
			w.mu.Lock()
			delete(w.pending, id)
			w.mu.Unlock()
		}
	}
}

func (w *SBOMWorker) process(ctx context.Context, client *http.Client, uploadURL, id string) {
	start := time.Now()
	runCtx, cancel := context.WithTimeout(ctx, sbomTimeout)
	doc, err := w.Generator.Generate(runCtx, id)
	cancel()
	if errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	up := protocol.SBOMUpload{ImageID: id, DurationMS: time.Since(start).Milliseconds()}
	if err != nil {
		up.Error = err.Error()
		w.Logger.Warn("sbom failed", "image_id", id, "err", err)
	} else {
		up.Format, up.Generator, up.Document = protocol.FormatCycloneDXJSON, ScannerVersion, doc
		w.Logger.Info("sbom generated", "image_id", id, "bytes", len(doc), "duration", time.Since(start).Round(time.Second))
	}
	var resp struct{}
	if err := postJSON(ctx, client, uploadURL, up, &resp); err != nil && ctx.Err() == nil {
		w.Logger.Error("upload sbom", "image_id", id, "err", err)
	}
}
