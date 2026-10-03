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
}

// Scanner keeps every stored SBOM matched against the current database.
type Scanner struct {
	Store   *store.Store
	Matcher Matcher
	Logger  *slog.Logger
	// RefreshEvery is how often to look for a newer database.
	RefreshEvery time.Duration
	// After a pass that stored results, AfterPass runs (alerts).
	AfterPass func(ctx context.Context)
}

const (
	scanPoll     = time.Minute
	scanBatch    = 20
	matchTimeout = 10 * time.Minute
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
		if n, err := s.Pass(ctx); err != nil && ctx.Err() == nil {
			s.Logger.Error("scan pass", "err", err)
		} else if n > 0 && s.AfterPass != nil {
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
			s.Logger.Warn("match sbom", "image_id", id, "err", err)
		}
		if err := s.Store.SaveScan(ctx, id, version, findings, scanErr, time.Now()); err != nil {
			return done, err
		}
		s.Logger.Info("image scanned", "image_id", id, "findings", len(findings), "db", version, "duration", time.Since(start).Round(time.Millisecond))
		done++
	}
	return done, nil
}
