package updates

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"go.michaelspost.com/dockgate/internal/protocol"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
)

func TestCheck(t *testing.T) {
	head := func(_ context.Context, ref name.Reference) (string, error) {
		switch ref.Context().Name() {
		case "index.docker.io/library/postgres":
			return digestA, nil
		case "ghcr.io/example/app":
			return digestB, nil
		}
		return "", errors.New("registry unavailable")
	}
	c := NewChecker(head, time.Hour)
	ctx := context.Background()

	tests := []struct {
		name, reference string
		repoDigests     []string
		want            string
	}{
		{"current", "postgres:16-alpine", []string{"postgres@" + digestA}, protocol.UpdateCurrent},
		{"fully qualified local digest", "postgres:16", []string{"docker.io/library/postgres@" + digestA}, protocol.UpdateCurrent},
		{"available", "ghcr.io/example/app:latest", []string{"ghcr.io/example/app@" + digestA}, protocol.UpdateAvailable},
		{"digest from another repository", "ghcr.io/example/app:1", []string{"ghcr.io/other/app@" + digestB}, protocol.UpdateUnsupported},
		{"locally built", "myapp:dev", nil, protocol.UpdateUnsupported},
		{"pinned", "postgres@" + digestA, []string{"postgres@" + digestA}, protocol.UpdateUnsupported},
		{"registry error", "quay.io/example/x:1", []string{"quay.io/example/x@" + digestA}, protocol.UpdateUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.Check(ctx, tt.reference, tt.repoDigests)
			if got.Status != tt.want {
				t.Fatalf("status = %s (%s), want %s", got.Status, got.Error, tt.want)
			}
		})
	}
}

func TestCheckCachesPerReference(t *testing.T) {
	calls := 0
	head := func(context.Context, name.Reference) (string, error) {
		calls++
		return digestA, nil
	}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	c := NewChecker(head, time.Hour)
	c.now = func() time.Time { return now }
	digests := []string{"postgres@" + digestA}

	c.Check(context.Background(), "postgres:16", digests)
	c.Check(context.Background(), "postgres:16", digests)
	if calls != 1 {
		t.Fatalf("calls within interval = %d, want 1", calls)
	}
	now = now.Add(61 * time.Minute)
	c.Check(context.Background(), "postgres:16", digests)
	if calls != 2 {
		t.Fatalf("calls after interval = %d, want 2", calls)
	}
}

func TestFailedLookupRetriesSooner(t *testing.T) {
	calls := 0
	head := func(context.Context, name.Reference) (string, error) {
		calls++
		return "", errors.New("timeout")
	}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	c := NewChecker(head, 6*time.Hour)
	c.now = func() time.Time { return now }
	digests := []string{"postgres@" + digestA}

	c.Check(context.Background(), "postgres:16", digests)
	now = now.Add(retryFailedAfter + time.Second)
	c.Check(context.Background(), "postgres:16", digests)
	if calls != 2 {
		t.Fatalf("calls = %d, want a retry after %s", calls, retryFailedAfter)
	}
}
