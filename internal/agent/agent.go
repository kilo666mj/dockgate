// Package agent runs on each Docker host: it enrolls with the server once,
// then reports the host's inventory over mutual TLS. It only ever makes
// outbound connections.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.michaelspost.com/dockgate/internal/pki"
	"go.michaelspost.com/dockgate/internal/protocol"
)

// Files in the agent's state directory.
const (
	keyFile   = "agent.key"
	certFile  = "agent.crt"
	caFile    = "ca.crt"
	stateFile = "agent.json"
)

// State identifies an enrolled agent.
type State struct {
	AgentID string `json:"agent_id"`
	Name    string `json:"name"`
	Server  string `json:"server"`
}

// Enroll exchanges a join token for a client certificate and writes the
// agent's key, certificate, CA and state into dir.
func Enroll(ctx context.Context, server, token, name, dir string, force bool) (State, error) {
	jt, err := protocol.ParseJoinToken(token)
	if err != nil {
		return State{}, err
	}
	base, err := serverURL(server)
	if err != nil {
		return State{}, err
	}
	if _, err := os.Stat(filepath.Join(dir, stateFile)); err == nil && !force {
		return State{}, fmt.Errorf("already enrolled (%s exists); use -force to enroll again", filepath.Join(dir, stateFile))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return State{}, err
	}

	key, err := pki.NewKey()
	if err != nil {
		return State{}, err
	}
	csr, err := pki.NewCSR(key, name)
	if err != nil {
		return State{}, err
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: pinnedTLSConfig(base.Hostname(), jt.CAPin)},
	}
	var resp protocol.EnrollResponse
	err = postJSON(ctx, client, base.JoinPath(protocol.PathEnroll).String(), protocol.EnrollRequest{
		TokenID: jt.ID, TokenSecret: jt.Secret, Name: name, CSR: string(csr),
	}, &resp)
	if err != nil {
		return State{}, fmt.Errorf("enroll: %w", err)
	}

	ca, err := pki.ParseCertificatePEM([]byte(resp.CA))
	if err != nil {
		return State{}, fmt.Errorf("enroll response CA: %w", err)
	}
	if pki.Pin(ca) != jt.CAPin {
		return State{}, errors.New("enroll response CA does not match the join token's pin")
	}
	cert, err := pki.ParseCertificatePEM([]byte(resp.Certificate))
	if err != nil {
		return State{}, fmt.Errorf("enroll response certificate: %w", err)
	}
	if err := cert.CheckSignatureFrom(ca); err != nil {
		return State{}, fmt.Errorf("enroll response certificate not issued by CA: %w", err)
	}

	state := State{AgentID: resp.AgentID, Name: resp.Name, Server: base.String()}
	stateJSON, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return State{}, err
	}
	// Write the state file last: its presence means enrollment completed.
	for _, f := range []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{caFile, []byte(resp.CA), 0o644},
		{certFile, []byte(resp.Certificate), 0o644},
	} {
		if err := pki.WriteFile(filepath.Join(dir, f.name), f.data, f.perm); err != nil {
			return State{}, err
		}
	}
	if err := pki.WriteKey(filepath.Join(dir, keyFile), key); err != nil {
		return State{}, err
	}
	if err := pki.WriteFile(filepath.Join(dir, stateFile), append(stateJSON, '\n'), 0o600); err != nil {
		return State{}, err
	}
	return state, nil
}

// pinnedTLSConfig trusts the server only if its chain contains a CA whose
// public key matches pin and that CA issued the server certificate for host.
// It is used once, before the agent has the CA certificate on disk.
func pinnedTLSConfig(host, pin string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Verification is replaced, not skipped: VerifyConnection below
		// checks the chain against the pinned CA.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			for _, candidate := range cs.PeerCertificates[1:] {
				if !candidate.IsCA || pki.Pin(candidate) != pin {
					continue
				}
				roots := x509.NewCertPool()
				roots.AddCert(candidate)
				_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
					DNSName:   host,
					Roots:     roots,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				})
				return err
			}
			return errors.New("server certificate chain does not contain the pinned CA")
		},
	}
}

func serverURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("server URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("server URL must be https://host[:port] without credentials")
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return u, nil
}

// Identity is a loaded, enrolled agent.
type Identity struct {
	State State
	dir   string
	roots *x509.CertPool

	mu   sync.Mutex
	cert tls.Certificate
}

// LoadIdentity reads an enrolled agent's files from dir.
func LoadIdentity(dir string) (*Identity, error) {
	data, err := os.ReadFile(filepath.Join(dir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("not enrolled: %s missing; run `dockgate agent enroll` first", filepath.Join(dir, stateFile))
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", stateFile, err)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s: no certificates", caFile)
	}
	id := &Identity{State: st, dir: dir, roots: roots}
	if err := id.reload(); err != nil {
		return nil, err
	}
	return id, nil
}

func (id *Identity) reload() error {
	cert, err := tls.LoadX509KeyPair(filepath.Join(id.dir, certFile), filepath.Join(id.dir, keyFile))
	if err != nil {
		return fmt.Errorf("agent certificate: %w", err)
	}
	id.mu.Lock()
	id.cert = cert
	id.mu.Unlock()
	return nil
}

// NotAfter returns the current certificate's expiry.
func (id *Identity) NotAfter() time.Time {
	id.mu.Lock()
	defer id.mu.Unlock()
	return id.cert.Leaf.NotAfter
}

// HTTPClient returns a client that authenticates with the agent certificate
// and trusts only the enrolled CA.
func (id *Identity) HTTPClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    id.roots,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				id.mu.Lock()
				defer id.mu.Unlock()
				return &id.cert, nil
			},
		}},
	}
}

// Renew replaces the certificate with a fresh one for the same key.
func (id *Identity) Renew(ctx context.Context, client *http.Client) error {
	key, err := pki.ReadKey(filepath.Join(id.dir, keyFile))
	if err != nil {
		return err
	}
	csr, err := pki.NewCSR(key, id.State.Name)
	if err != nil {
		return err
	}
	base, err := serverURL(id.State.Server)
	if err != nil {
		return err
	}
	var resp protocol.RenewResponse
	if err := postJSON(ctx, client, base.JoinPath(protocol.PathRenew).String(), protocol.RenewRequest{CSR: string(csr)}, &resp); err != nil {
		return err
	}
	if _, err := pki.ParseCertificatePEM([]byte(resp.Certificate)); err != nil {
		return fmt.Errorf("renewed certificate: %w", err)
	}
	if err := pki.WriteFile(filepath.Join(id.dir, certFile), []byte(resp.Certificate), 0o644); err != nil {
		return err
	}
	return id.reload()
}

// Run reports to the server until ctx ends.
func Run(ctx context.Context, id *Identity, collector *Collector, logger *slog.Logger) error {
	client := id.HTTPClient()
	base, err := serverURL(id.State.Server)
	if err != nil {
		return err
	}
	reportURL := base.JoinPath(protocol.PathReport).String()
	interval := time.Minute
	for {
		if time.Until(id.NotAfter()) < pki.RenewBefore {
			if err := id.Renew(ctx, client); err != nil {
				logger.Error("renew certificate", "err", err, "not_after", id.NotAfter())
			} else {
				logger.Info("certificate renewed", "not_after", id.NotAfter())
			}
		}

		report := collector.Collect(ctx)
		var resp protocol.ReportResponse
		if err := postJSON(ctx, client, reportURL, report, &resp); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Error("report", "err", err)
		} else {
			logger.Debug("reported", "containers", len(report.Containers), "images", len(report.Images))
			if resp.NextReportSeconds > 0 {
				interval = time.Duration(resp.NextReportSeconds) * time.Second
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

func postJSON(ctx context.Context, client *http.Client, url string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var e protocol.Error
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
		return fmt.Errorf("%s: %s", resp.Status, e.Error)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
