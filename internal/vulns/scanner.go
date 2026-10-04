package vulns

import (
	"context"
	"log/slog"
	"time"

	"go.michaelspost.com/dockgate/internal/store"
)

// Matcher abstracts Trivy for tests.
type Matcher interface {
	RefreshDB(ctx context.Context) error
	DBVersion(ctx context.Context) (string, error)
	Match(ctx context.Context, sbom []byte) ([]store.Finding, error)
	RemoteSBOM(ctx context.Context, ref, platform string) ([]byte, error)
}

// Scanner keeps every stored SBOM matched against the current database.
type Scanner struct {
	Store   *store.Store
	Matcher Matcher
	Logger  *slog.Logger
	// RefreshEvery is how often to look for a newer database.
	RefreshEvery time.Duration
	// AfterPass runs after every pass (alerts).
	AfterPass func(ctx context.Context)
}

const (
	scanPoll      = time.Minute
	scanBatch     = 20
	registryBatch = 2
	matchTimeout  = 10 * time.Minute
	remoteTimeout = 15 * time.Minute
)

// Run scans until ctx ends.
func (s *Scanner) Run(ctx context.Context) {
	var lastRefresh time.Time
	for {
		if time.Since(lastRefresh) >= s.RefreshEvery {
			if err := s.Matcher.RefreshDB(ctx); err != nil {
				s.Logger.Error("refresh vulnerability database", "err", err)
			} else {
				lastRefresh = time.Now()
			}
		}
		if _, err := s.Pass(ctx); err != nil && ctx.Err() == nil {
			s.Logger.Error("scan pass", "err", err)
		}
		if _, err := s.RegistryPass(ctx); err != nil && ctx.Err() == nil {
			s.Logger.Error("registry pass", "err", err)
		}
		// Alerts are checked every loop, not only after new scans: an expiring
		// ignore rule or a restart must not wait for the next new image.
		if s.AfterPass != nil {
			s.AfterPass(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(scanPoll):
		}
	}
}

// Pass matches up to one batch of SBOMs that are unscanned or were scanned
// against an older database, and returns how many it stored.
func (s *Scanner) Pass(ctx context.Context) (int, error) {
	version, err := s.Matcher.DBVersion(ctx)
	if err != nil {
		return 0, err
	}
	ids, err := s.Store.SBOMsToScan(ctx, version, scanBatch)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		doc, err := s.Store.LoadSBOM(ctx, id)
		if err != nil {
			return done, err
		}
		mctx, cancel := context.WithTimeout(ctx, matchTimeout)
		start := time.Now()
		findings, err := s.Matcher.Match(mctx, doc)
		cancel()
		scanErr := ""
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			scanErr = err.Error()
			s.Logger.Warn("match sbom", "agent_id", id.AgentID, "image_id", id.ImageID, "err", err)
		}
		if err := s.Store.SaveScan(ctx, id, version, findings, scanErr, time.Now()); err != nil {
			return done, err
		}
		s.Logger.Info("image scanned", "agent_id", id.AgentID, "image_id", id.ImageID, "findings", len(findings), "db", version, "duration", time.Since(start).Round(time.Millisecond))
		done++
	}
	return done, nil
}

// RegistryPass inventories a few images straight from their registries
// (update candidates, and images agents could not inventory), then matches
// candidate SBOMs that are unscanned or scanned against an older database.
// It returns how many results it stored.
func (s *Scanner) RegistryPass(ctx context.Context) (int, error) {
	now := time.Now()
	stored := 0
	candidates, err := s.Store.CandidateTargets(ctx, registryBatch, now)
	if err != nil {
		return stored, err
	}
	for _, t := range candidates {
		doc, genErr := s.remote(ctx, t)
		if ctx.Err() != nil {
			return stored, nil
		}
		if err := s.Store.SaveCandidateSBOM(ctx, t, doc, genErr, time.Now()); err != nil {
			return stored, err
		}
		stored++
	}
	fallbacks, err := s.Store.FallbackTargets(ctx, registryBatch, now)
	if err != nil {
		return stored, err
	}
	for _, t := range fallbacks {
		doc, genErr := s.remote(ctx, t)
		if ctx.Err() != nil {
			return stored, nil
		}
		if err := s.Store.SaveFallbackSBOM(ctx, t, doc, Generator, genErr, time.Now()); err != nil {
			return stored, err
		}
		stored++
	}

	version, err := s.Matcher.DBVersion(ctx)
	if err != nil {
		return stored, err
	}
	keys, err := s.Store.CandidatesToScan(ctx, version, scanBatch)
	if err != nil {
		return stored, err
	}
	for _, k := range keys {
		doc, err := s.Store.LoadCandidateSBOM(ctx, k)
		if err != nil {
			return stored, err
		}
		mctx, cancel := context.WithTimeout(ctx, matchTimeout)
		findings, err := s.Matcher.Match(mctx, doc)
		cancel()
		scanErr := ""
		if err != nil {
			if ctx.Err() != nil {
				return stored, nil
			}
			scanErr = err.Error()
		}
		if err := s.Store.SaveCandidateScan(ctx, k, version, findings, scanErr, time.Now()); err != nil {
			return stored, err
		}
		s.Logger.Info("candidate scanned", "digest", k.Digest, "platform", k.Platform, "findings", len(findings))
		stored++
	}
	return stored, nil
}

func (s *Scanner) remote(ctx context.Context, t store.RegistryTarget) ([]byte, string) {
	rctx, cancel := context.WithTimeout(ctx, remoteTimeout)
	defer cancel()
	start := time.Now()
	doc, err := s.Matcher.RemoteSBOM(rctx, t.Reference, t.Platform)
	kind := "candidate"
	if t.AgentID != "" {
		kind = "fallback"
	}
	if err != nil {
		s.Logger.Warn("registry sbom failed", "kind", kind, "reference", t.Reference, "platform", t.Platform, "err", err)
		return nil, err.Error()
	}
	s.Logger.Info("registry sbom", "kind", kind, "reference", t.Reference, "platform", t.Platform, "bytes", len(doc),
		"duration", time.Since(start).Round(time.Second))
	return doc, ""
}
