package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.michaelspost.com/dockgate/internal/protocol"
)

const (
	localDigest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	remoteDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func registryFixture(t *testing.T) (*Store, string) {
	t.Helper()
	s := openTest(t)
	id := enrolledWithContainers(t, s, "alpha",
		protocol.Container{ID: "c1", Name: "db", Image: "postgres:16", ImageID: "sha256:pg", Update: &protocol.UpdateCheck{
			Status: protocol.UpdateAvailable, Reference: "postgres:16", LocalDigests: []string{localDigest}, RemoteDigest: remoteDigest}},
		protocol.Container{ID: "c2", Name: "sogo", Image: "ghcr.io/example/sogo:5", ImageID: "sha256:sogo", Update: &protocol.UpdateCheck{
			Status: protocol.UpdateCurrent, Reference: "ghcr.io/example/sogo:5", LocalDigests: []string{localDigest}, RemoteDigest: localDigest}},
	)
	return s, id
}

func TestCandidateTargetsAndImpact(t *testing.T) {
	s, id := registryFixture(t)
	ctx := context.Background()
	now := time.Now()

	targets, err := s.CandidateTargets(ctx, 5, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Reference != "postgres@"+remoteDigest || targets[0].Platform != "linux/amd64" {
		t.Fatalf("candidate targets = %+v", targets)
	}
	imp, _ := s.UpdateImpacts(ctx, "", now)
	if len(imp) != 1 || imp[0].Status != "pending" {
		t.Fatalf("impact before scan = %+v", imp)
	}

	// Current image: one critical and one high.
	if _, err := s.RequestSBOMs(ctx, id, 5, AgentQueue{}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSBOM(ctx, id, protocol.SBOMUpload{ImageID: "sha256:pg", Format: protocol.FormatCycloneDXJSON, Document: []byte(`{}`)}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveScan(ctx, SBOMKey{AgentID: id, ImageID: "sha256:pg"}, "db1", []Finding{
		{VulnID: "CVE-1", Pkg: "libssl3", Installed: "3.0", Fixed: "3.1", Severity: "CRITICAL"},
		{VulnID: "CVE-2", Pkg: "zlib", Installed: "1.2", Fixed: "1.3", Severity: "HIGH"},
	}, "", now); err != nil {
		t.Fatal(err)
	}
	// Candidate: fixes CVE-1, keeps CVE-2, adds a high.
	if err := s.SaveCandidateSBOM(ctx, targets[0], []byte(`{"c":1}`), "", now); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.CandidateTargets(ctx, 5, now); len(again) != 0 {
		t.Fatalf("candidate with an SBOM targeted again: %+v", again)
	}
	key := CandidateKey{Digest: remoteDigest, Platform: "linux/amd64"}
	if keys, _ := s.CandidatesToScan(ctx, "db1", 5); len(keys) != 1 {
		t.Fatalf("candidates to scan = %v", keys)
	}
	if doc, err := s.LoadCandidateSBOM(ctx, key); err != nil || string(doc) != `{"c":1}` {
		t.Fatalf("candidate SBOM = %s, %v", doc, err)
	}
	if err := s.SaveCandidateScan(ctx, key, "db1", []Finding{
		{VulnID: "CVE-2", Pkg: "zlib", Installed: "1.2", Fixed: "1.3", Severity: "HIGH"},
		{VulnID: "CVE-3", Pkg: "curl", Installed: "8.0", Severity: "HIGH"},
	}, "", now); err != nil {
		t.Fatal(err)
	}
	imp, err = s.UpdateImpacts(ctx, "alpha", now)
	if err != nil {
		t.Fatal(err)
	}
	u := imp[0]
	if u.Status != "assessed" || len(u.Fixes) != 1 || u.Fixes[0].VulnID != "CVE-1" || len(u.Introduces) != 1 ||
		u.Introduces[0].VulnID != "CVE-3" || u.Remaining != 1 || !u.Actionable {
		t.Fatalf("impact = %+v", u)
	}
	if keys, _ := s.CandidatesToScan(ctx, "db2", 5); len(keys) != 1 {
		t.Fatalf("new db did not request a candidate re-match: %v", keys)
	}

	// A new critical in the candidate makes the update not actionable.
	if err := s.SaveCandidateScan(ctx, key, "db2", []Finding{{VulnID: "CVE-9", Pkg: "glibc", Installed: "2", Severity: "CRITICAL"}}, "", now); err != nil {
		t.Fatal(err)
	}
	imp, _ = s.UpdateImpacts(ctx, "", now)
	if imp[0].Actionable {
		t.Fatalf("update introducing a critical marked actionable: %+v", imp[0])
	}
}

func TestCandidateFailureBackoff(t *testing.T) {
	s, _ := registryFixture(t)
	ctx := context.Background()
	now := time.Now()
	targets, _ := s.CandidateTargets(ctx, 5, now)
	if err := s.SaveCandidateSBOM(ctx, targets[0], nil, "registry unreachable", now); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.CandidateTargets(ctx, 5, now.Add(time.Hour)); len(again) != 0 {
		t.Fatalf("failed candidate retried too soon: %+v", again)
	}
	if again, _ := s.CandidateTargets(ctx, 5, now.Add(7*time.Hour)); len(again) != 1 {
		t.Fatalf("failed candidate not retried after backoff: %+v", again)
	}
	imp, _ := s.UpdateImpacts(ctx, "", now)
	if imp[0].Status != "failed" || imp[0].Error == "" {
		t.Fatalf("impact after failure = %+v", imp[0])
	}
}

func TestRegistryFallbackFillsAgentSlot(t *testing.T) {
	s, id := registryFixture(t)
	ctx := context.Background()
	now := time.Now()
	if _, err := s.RequestSBOMs(ctx, id, 5, AgentQueue{}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSBOM(ctx, id, protocol.SBOMUpload{ImageID: "sha256:sogo", Error: "Java DB update failed"}, now); err != nil {
		t.Fatal(err)
	}
	targets, err := s.FallbackTargets(ctx, 5, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Reference != "ghcr.io/example/sogo@"+localDigest || targets[0].AgentID != id {
		t.Fatalf("fallback targets = %+v", targets)
	}
	// A failed fallback backs off.
	if err := s.SaveFallbackSBOM(ctx, targets[0], nil, "", "registry denied", now); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.FallbackTargets(ctx, 5, now.Add(time.Hour)); len(again) != 0 {
		t.Fatalf("failed fallback retried too soon: %+v", again)
	}
	// A successful one fills the agent's slot and clears the failure.
	if err := s.SaveFallbackSBOM(ctx, targets[0], []byte(`{"f":1}`), "registry: trivy", "", now); err != nil {
		t.Fatal(err)
	}
	doc, err := s.LoadSBOM(ctx, SBOMKey{AgentID: id, ImageID: "sha256:sogo"})
	if err != nil || string(doc) != `{"f":1}` {
		t.Fatalf("fallback SBOM = %s, %v", doc, err)
	}
	if fs, _ := s.ScanFailures(ctx); len(fs) != 0 {
		t.Fatalf("scan failures after fallback = %+v", fs)
	}
	if _, err := s.LoadCandidateSBOM(ctx, CandidateKey{Digest: "sha256:none", Platform: "linux/amd64"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing candidate: err = %v", err)
	}
}
