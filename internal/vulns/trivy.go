// Package vulns matches stored SBOMs against a vulnerability database held
// by the server, so agents never download it and the whole fleet can be
// re-checked when the database changes without touching any host.
package vulns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go.michaelspost.com/dockgate/internal/store"
)

// Trivy runs the Trivy binary with a private cache directory.
type Trivy struct {
	Binary   string
	CacheDir string
}

func (t *Trivy) command(ctx context.Context, args ...string) *exec.Cmd {
	args = append(args, "--cache-dir", t.CacheDir, "--quiet")
	cmd := exec.CommandContext(ctx, t.Binary, args...)
	cmd.Env = []string{"HOME=" + t.CacheDir, "PATH=/usr/local/bin:/usr/bin:/bin", "TRIVY_NO_PROGRESS=true"}
	return cmd
}

func run(cmd *exec.Cmd) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if i := strings.LastIndex(msg, "\n"); i >= 0 {
			msg = msg[i+1:]
		}
		return nil, fmt.Errorf("%s %s: %w: %s", filepath.Base(cmd.Path), cmd.Args[1], err, msg)
	}
	return stdout.Bytes(), nil
}

// RefreshDB downloads the vulnerability database if a newer one exists.
func (t *Trivy) RefreshDB(ctx context.Context) error {
	if err := os.MkdirAll(t.CacheDir, 0o700); err != nil {
		return err
	}
	_, err := run(t.command(ctx, "image", "--download-db-only"))
	return err
}

// DBVersion identifies the local database by its build time. It changes
// whenever a refresh downloads a new database.
func (t *Trivy) DBVersion(ctx context.Context) (string, error) {
	out, err := run(t.command(ctx, "version", "--format", "json"))
	if err != nil {
		return "", err
	}
	var v struct {
		Version         string
		VulnerabilityDB *struct {
			UpdatedAt string
		}
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return "", fmt.Errorf("parse trivy version: %w", err)
	}
	if v.VulnerabilityDB == nil || v.VulnerabilityDB.UpdatedAt == "" {
		return "", errors.New("no vulnerability database downloaded yet")
	}
	return v.VulnerabilityDB.UpdatedAt, nil
}

// Match finds vulnerabilities for an SBOM using the local database only.
func (t *Trivy) Match(ctx context.Context, sbom []byte) ([]store.Finding, error) {
	dir, err := os.MkdirTemp(t.CacheDir, "match-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	in, out := filepath.Join(dir, "sbom.cdx.json"), filepath.Join(dir, "result.json")
	if err := os.WriteFile(in, sbom, 0o600); err != nil {
		return nil, err
	}
	if _, err := run(t.command(ctx, "sbom", "--skip-db-update", "--format", "json", "--output", out, in)); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	return ParseReport(data)
}

// ParseReport extracts findings from a Trivy JSON report.
func ParseReport(data []byte) ([]store.Finding, error) {
	var report struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID  string
				PkgName          string
				InstalledVersion string
				FixedVersion     string
				Status           string
				Severity         string
				Title            string
				PrimaryURL       string
			}
		}
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse trivy report: %w", err)
	}
	var out []store.Finding
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			out = append(out, store.Finding{
				VulnID: v.VulnerabilityID, Pkg: v.PkgName, Installed: v.InstalledVersion, Fixed: v.FixedVersion,
				Status: v.Status, Severity: strings.ToUpper(v.Severity), Title: v.Title, URL: v.PrimaryURL,
			})
		}
	}
	return out, nil
}
