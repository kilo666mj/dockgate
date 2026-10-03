// Package updates detects newer images by comparing a container's local
// repository digests with the digest its tag currently resolves to in the
// registry. It uses manifest HEAD requests, which do not pull layers and do
// not count against Docker Hub's pull rate limit.
package updates

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"go.michaelspost.com/dockgate/internal/protocol"
)

// retryFailedAfter bounds how long a failed lookup is cached, so a registry
// outage clears without waiting a full check interval.
const retryFailedAfter = 15 * time.Minute

// HeadFunc resolves a tag reference to its current manifest digest.
type HeadFunc func(ctx context.Context, ref name.Reference) (string, error)

// RegistryHead resolves references with registry credentials from the
// Docker client configuration ($DOCKER_CONFIG/config.json).
func RegistryHead(ctx context.Context, ref name.Reference) (string, error) {
	desc, err := remote.Head(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(anonymousOnError{authn.DefaultKeychain}))
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}

// anonymousOnError falls back to anonymous access when credentials cannot be
// resolved, for example when config.json names a credential helper that is
// not installed. Public images still check; private ones then fail with the
// registry's authorization error, which is more useful than the helper's.
type anonymousOnError struct{ authn.Keychain }

func (k anonymousOnError) Resolve(target authn.Resource) (authn.Authenticator, error) {
	auth, err := k.Keychain.Resolve(target)
	if err != nil {
		return authn.Anonymous, nil
	}
	return auth, nil
}

// Checker caches registry lookups per image reference so that many
// containers sharing an image cost one request per interval.
type Checker struct {
	head     HeadFunc
	interval time.Duration
	now      func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	digest  string
	err     error
	checked time.Time
}

// NewChecker returns a checker that asks the registry about each reference
// at most once per interval.
func NewChecker(head HeadFunc, interval time.Duration) *Checker {
	return &Checker{head: head, interval: interval, now: time.Now, cache: map[string]cached{}}
}

// Check compares one container's image with its registry tag. reference is
// the image as the container was created with it (for example
// "postgres:16-alpine"); repoDigests are the local image's RepoDigests.
func (c *Checker) Check(ctx context.Context, reference string, repoDigests []string) *protocol.UpdateCheck {
	result := &protocol.UpdateCheck{Reference: reference}
	if strings.HasPrefix(reference, "sha256:") || strings.Contains(reference, "@") {
		result.Status = protocol.UpdateUnsupported
		result.Error = "image is pinned by digest"
		result.CheckedAt = c.now()
		return result
	}
	tag, err := name.NewTag(reference)
	if err != nil {
		result.Status = protocol.UpdateUnsupported
		result.Error = fmt.Sprintf("parse reference: %v", err)
		result.CheckedAt = c.now()
		return result
	}
	result.LocalDigests = localDigests(tag.Context(), repoDigests)
	if len(result.LocalDigests) == 0 {
		result.Status = protocol.UpdateUnsupported
		result.Error = "image has no registry digest for this repository (built locally?)"
		result.CheckedAt = c.now()
		return result
	}

	entry := c.lookup(ctx, tag)
	result.CheckedAt = entry.checked
	if entry.err != nil {
		result.Status = protocol.UpdateUnknown
		result.Error = entry.err.Error()
		return result
	}
	result.RemoteDigest = entry.digest
	if slices.Contains(result.LocalDigests, entry.digest) {
		result.Status = protocol.UpdateCurrent
	} else {
		result.Status = protocol.UpdateAvailable
	}
	return result
}

func (c *Checker) lookup(ctx context.Context, tag name.Tag) cached {
	key := tag.Name()
	c.mu.Lock()
	entry, ok := c.cache[key]
	c.mu.Unlock()
	ttl := c.interval
	if entry.err != nil {
		ttl = min(ttl, retryFailedAfter)
	}
	if ok && c.now().Sub(entry.checked) < ttl {
		return entry
	}
	digest, err := c.head(ctx, tag)
	if err != nil && errors.Is(ctx.Err(), context.Canceled) {
		// Shutting down: keep the previous answer rather than caching the
		// cancellation as a registry failure.
		return entry
	}
	entry = cached{digest: digest, err: err, checked: c.now()}
	c.mu.Lock()
	c.cache[key] = entry
	c.mu.Unlock()
	return entry
}

// localDigests returns the digests from repoDigests that belong to repo.
func localDigests(repo name.Repository, repoDigests []string) []string {
	var out []string
	for _, rd := range repoDigests {
		d, err := name.NewDigest(rd)
		if err != nil {
			continue
		}
		if d.Context().Name() == repo.Name() {
			out = append(out, d.DigestStr())
		}
	}
	return out
}
