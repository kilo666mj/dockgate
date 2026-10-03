package agent

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.michaelspost.com/dockgate/internal/docker"
	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/updates"
)

// Compose labels identify containers managed by docker compose.
const (
	labelComposeProject = "com.docker.compose.project"
	labelComposeService = "com.docker.compose.service"
)

// Collector gathers a report from the local Docker daemon.
type Collector struct {
	Docker  *docker.Client
	Updates *updates.Checker // nil disables update checks
	Version string
}

// Collect builds a report. Partial failures are recorded in Report.Errors
// so the server still sees whatever could be read.
func (c *Collector) Collect(ctx context.Context) protocol.Report {
	r := protocol.Report{AgentVersion: c.Version, CollectedAt: time.Now().UTC()}
	fail := func(format string, args ...any) { r.Errors = append(r.Errors, fmt.Sprintf(format, args...)) }

	if h, err := os.Hostname(); err == nil {
		r.Hostname = h
	}
	if v, err := c.Docker.Version(ctx); err != nil {
		fail("docker version: %v", err)
	} else {
		r.Docker = protocol.DockerInfo{Version: v.Version, APIVersion: v.APIVersion, OS: v.OS, Arch: v.Arch, KernelVersion: v.KernelVersion}
	}
	if info, err := c.Docker.Info(ctx); err != nil {
		fail("docker info: %v", err)
	} else {
		r.Docker.CPUs, r.Docker.MemoryBytes = info.NCPU, info.MemTotal
	}

	images, err := c.Docker.Images(ctx)
	if err != nil {
		fail("list images: %v", err)
	}
	digestsByImage := make(map[string][]string, len(images))
	for _, img := range images {
		digestsByImage[img.ID] = img.RepoDigests
		r.Images = append(r.Images, protocol.Image{
			ID: img.ID, RepoTags: img.RepoTags, RepoDigests: img.RepoDigests,
			SizeBytes: img.Size, Created: time.Unix(img.Created, 0).UTC(),
		})
	}

	containers, err := c.Docker.Containers(ctx)
	if err != nil {
		fail("list containers: %v", err)
	}
	for _, s := range containers {
		pc := protocol.Container{
			ID: s.ID, Name: s.Name(), Image: s.Image, ImageID: s.ImageID, State: s.State, Status: s.Status,
			Created: time.Unix(s.Created, 0).UTC(), Labels: s.Labels,
			ComposeProject: s.Labels[labelComposeProject], ComposeService: s.Labels[labelComposeService],
		}
		reference := s.Image
		if d, err := c.Docker.Container(ctx, s.ID); err != nil {
			fail("inspect %s: %v", pc.Name, err)
		} else {
			pc.RestartCount, pc.Health, pc.StartedAt = d.RestartCount, d.Health(), d.StartedAt()
			if d.Config.Image != "" {
				// The configured reference survives the tag moving to a
				// newer image, unlike the summary's Image field.
				reference = d.Config.Image
				pc.Image = reference
			}
		}
		if c.Updates != nil {
			pc.Update = c.Updates.Check(ctx, reference, digestsByImage[s.ImageID])
		}
		r.Containers = append(r.Containers, pc)
	}
	return r
}
