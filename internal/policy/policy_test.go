package policy

import (
	"slices"
	"testing"

	"go.michaelspost.com/dockgate/internal/protocol"
)

func TestEvaluate(t *testing.T) {
	cfg := Config{Registries: []string{"docker.io", "ghcr.io"}}
	local := &protocol.UpdateCheck{Status: protocol.UpdateUnsupported}
	tests := []struct {
		name string
		c    protocol.Container
		want []string
	}{
		{"clean", protocol.Container{Image: "ghcr.io/example/app:1.2"}, nil},
		{"docker hub short name", protocol.Container{Image: "redis:7"}, nil},
		{"bare name is latest", protocol.Container{Image: "redis"}, []string{RuleUnpinnedTag}},
		{"explicit latest", protocol.Container{Image: "ghcr.io/example/app:latest"}, []string{RuleUnpinnedTag}},
		{"digest pins latest", protocol.Container{Image: "redis:latest@sha256:" + hex64, Update: local}, nil},
		{"other registry", protocol.Container{Image: "registry.example.net/app:1"}, []string{RuleRegistry}},
		{"other registry by digest", protocol.Container{Image: "registry.example.net/app@sha256:" + hex64, Update: local}, []string{RuleRegistry}},
		{"local build", protocol.Container{Image: "proj-web", Update: local}, nil},
		{"image id", protocol.Container{Image: "sha256:" + hex64}, nil},
		{"runtime rules", protocol.Container{Image: "redis:7", Privileged: true, NetworkMode: "host", Binds: []string{"/srv/data", "/var/run/docker.sock"}},
			[]string{RulePrivileged, RuleDockerSocket, RuleHostNetwork}},
		{"exception label", protocol.Container{Image: "redis", Privileged: true, NetworkMode: "host",
			Labels: map[string]string{LabelAllow: "privileged, unpinned-tag"}}, []string{RuleHostNetwork}},
		{"stopped", protocol.Container{Image: "redis", State: "exited", Privileged: true}, nil},
	}
	for _, tt := range tests {
		if tt.c.State == "" {
			tt.c.State = "running"
		}
		var got []string
		for _, v := range Evaluate(cfg, tt.c) {
			got = append(got, v.Rule)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
	if got := Evaluate(Config{}, protocol.Container{State: "running", Image: "registry.example.net/app:1"}); got != nil {
		t.Errorf("empty allow list: got %v, want no violations", got)
	}
}

const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
