package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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

// Limits for one SBOM run. Large images take minutes because the scanner
// exports the whole image from the daemon.
const (
	sbomTimeout   = 20 * time.Minute
	maxSBOMBytes  = 48 << 20
	sbomQueueSize = 64
)

// SBOMGenerator inventories local images with the pinned scanner container.
type SBOMGenerator struct {
	Docker     *docker.Client
	SocketPath string
}

// Generate returns a CycloneDX JSON SBOM for a local image ID.
func (g *SBOMGenerator) Generate(ctx context.Context, imageID string) ([]byte, error) {
	if !strings.HasPrefix(imageID, "sha256:") || strings.ContainsAny(imageID, " /") {
		return nil, fmt.Errorf("refusing image ID %q", imageID)
	}
	ref := ScannerRepository + "@" + ScannerDigest
	ok, err := g.Docker.ImageExists(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("check scanner image: %w", err)
	}
	if !ok {
		if err := g.Docker.PullImage(ctx, ScannerRepository, ScannerDigest); err != nil {
			return nil, err
		}
	}
	res, err := g.Docker.Run(ctx, docker.RunSpec{
		Image: ref,
		// Packages only: no vulnerability scan here, so no database download
		// and no network, which the container does not have.
		Cmd:       []string{"image", "--quiet", "--format", "cyclonedx", "--cache-dir", "/tmp/trivy", imageID},
		Binds:     []string{g.SocketPath + ":/var/run/docker.sock:ro"},
		Labels:    map[string]string{"dockgate.role": "sbom"},
		MaxStdout: maxSBOMBytes,
	})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("scanner exited %d: %s", res.ExitCode, lastLine(res.Stderr))
	}
	if !json.Valid(res.Stdout) {
		return nil, fmt.Errorf("scanner output is not JSON: %s", lastLine(res.Stderr))
	}
	return res.Stdout, nil
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

// Run processes the queue until ctx ends, uploading each result.
func (w *SBOMWorker) Run(ctx context.Context, client *http.Client, uploadURL string) {
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
