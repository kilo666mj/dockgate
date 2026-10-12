// Package policy evaluates audit rules against the containers a host
// reports. It only reports violations; nothing here blocks a container.
package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"go.michaelspost.com/dockgate/internal/protocol"
)

// LabelAllow is the container label that exempts a container from rules: a
// comma-separated list of rule names, for example "privileged,host-network".
const LabelAllow = "dockgate.policy.allow"

// Rule names, as reported and as used in LabelAllow.
const (
	RuleRegistry     = "registry"
	RuleUnpinnedTag  = "unpinned-tag"
	RulePrivileged   = "privileged"
	RuleDockerSocket = "docker-socket"
	RuleHostNetwork  = "host-network"
)

// Config holds the operator's settings for the rules.
type Config struct {
	// Registries is the registry allow list, for example "ghcr.io"; empty
	// turns the registry rule off.
	Registries []string
}

// Violation is one rule a container breaks.
type Violation struct {
	Rule   string
	Detail string
}

// Evaluate returns the rules a running container breaks and has no exception
// label for. Containers that are not running break none.
func Evaluate(cfg Config, c protocol.Container) []Violation {
	if c.State != "running" {
		return nil
	}
	var out []Violation
	add := func(rule, format string, args ...any) {
		out = append(out, Violation{Rule: rule, Detail: fmt.Sprintf(format, args...)})
	}
	// A locally built image has no registry or tag to hold to the image
	// rules; the agent's update check is what knows it is local.
	local := c.Update != nil && c.Update.Status == protocol.UpdateUnsupported && !strings.Contains(c.Image, "@")
	if ref, err := name.ParseReference(c.Image); err == nil && !local && !strings.HasPrefix(c.Image, "sha256:") {
		if reg := ref.Context().RegistryStr(); len(cfg.Registries) > 0 && !slices.ContainsFunc(cfg.Registries, func(allowed string) bool {
			return registry(allowed) == reg
		}) {
			add(RuleRegistry, "registry %s is not on the allow list", reg)
		}
		if tag, ok := ref.(name.Tag); ok && tag.TagStr() == name.DefaultTag {
			add(RuleUnpinnedTag, "image %s uses the latest tag", c.Image)
		}
	}
	if c.Privileged {
		add(RulePrivileged, "runs privileged")
	}
	if i := slices.IndexFunc(c.Binds, func(src string) bool { return strings.HasSuffix(src, "docker.sock") }); i >= 0 {
		add(RuleDockerSocket, "mounts %s", c.Binds[i])
	}
	if c.NetworkMode == "host" {
		add(RuleHostNetwork, "uses host networking")
	}

	var allowed []string
	for rule := range strings.SplitSeq(c.Labels[LabelAllow], ",") {
		allowed = append(allowed, strings.TrimSpace(rule))
	}
	return slices.DeleteFunc(out, func(v Violation) bool { return slices.Contains(allowed, v.Rule) })
}

// registry normalises an allow list entry the way image references are
// parsed, so "docker.io" matches Docker Hub images.
func registry(s string) string {
	if s = strings.TrimSpace(s); s == "docker.io" {
		return name.DefaultRegistry
	}
	return s
}
