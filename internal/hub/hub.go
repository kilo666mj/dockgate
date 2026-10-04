// Package hub serves the agent-facing API: enrollment, certificate renewal
// and inventory reports. It runs on its own TLS listener because agent
// authentication is mutual TLS, which a TLS-terminating proxy would break.
package hub

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.michaelspost.com/dockgate/internal/pki"
	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/store"
)

const (
	maxEnrollBody = 64 << 10
	maxReportBody = 16 << 20
	maxSBOMBody   = 64 << 20
	// sbomRequestsPerReport bounds how many images one report asks for; the
	// agent works through them one at a time.
	sbomRequestsPerReport = 2
)

// Hub handles agent requests.
type Hub struct {
	store          *store.Store
	ca             *pki.CA
	logger         *slog.Logger
	reportInterval time.Duration
	certDir        string
	hosts          []string
	sbomRequests   bool

	mu   sync.Mutex
	cert tls.Certificate
}

// Config configures a Hub.
type Config struct {
	Store  *store.Store
	CA     *pki.CA
	Logger *slog.Logger
	// ReportInterval is how often agents are asked to report.
	ReportInterval time.Duration
	// CertDir holds the server certificate, reissued as needed.
	CertDir string
	// Hosts are the DNS names and IP addresses agents use to reach the hub.
	Hosts []string
	// SBOMRequests asks agents for SBOMs of images without one.
	SBOMRequests bool
}

// New returns a Hub and issues its server certificate.
func New(cfg Config) (*Hub, error) {
	if len(cfg.Hosts) == 0 {
		return nil, errors.New("hub: at least one agent-facing host name is required")
	}
	h := &Hub{
		store: cfg.Store, ca: cfg.CA, logger: cfg.Logger, reportInterval: cfg.ReportInterval,
		certDir: cfg.CertDir, hosts: cfg.Hosts, sbomRequests: cfg.SBOMRequests,
	}
	if err := h.refreshCertificate(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Hub) refreshCertificate() error {
	cert, err := h.ca.ServerCertificate(h.certDir, h.hosts)
	if err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}
	// Send the CA with the leaf so a new agent can match it against the
	// pin in its join token before it has the CA on disk.
	cert.Certificate = append(cert.Certificate, h.ca.Cert.Raw)
	h.mu.Lock()
	h.cert = cert
	h.mu.Unlock()
	return nil
}

// RenewLoop reissues the server certificate before it expires.
func (h *Hub) RenewLoop(ctx context.Context) {
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := h.refreshCertificate(); err != nil {
				h.logger.Error("renew server certificate", "err", err)
			}
		}
	}
}

// TLSConfig returns the listener's TLS configuration. Client certificates
// are optional at the handshake so that enrollment works without one; the
// handlers that need an agent identity insist on a verified certificate.
func (h *Hub) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  h.ca.Pool(),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return &h.cert, nil
		},
	}
}

// Handler returns the agent API routes.
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathEnroll, h.enroll)
	mux.HandleFunc("POST "+protocol.PathRenew, h.requireAgent(h.renew))
	mux.HandleFunc("POST "+protocol.PathReport, h.requireAgent(h.report))
	mux.HandleFunc("POST "+protocol.PathSBOM, h.requireAgent(h.sbom))
	return mux
}

func (h *Hub) enroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	if !h.decode(w, r, maxEnrollBody, &req) {
		return
	}
	csr, err := pki.ParseCSR([]byte(req.CSR))
	if err != nil {
		h.fail(w, http.StatusBadRequest, err)
		return
	}
	pin, err := pki.PublicKeyPin(csr.PublicKey)
	if err != nil {
		h.fail(w, http.StatusBadRequest, err)
		return
	}
	agent, issued, err := h.store.Enroll(r.Context(), req.TokenID, req.TokenSecret, pin, newAgentID(),
		func(agentID string) (store.Issued, error) {
			certPEM, cert, err := h.ca.SignAgent([]byte(req.CSR), agentID)
			if err != nil {
				return store.Issued{}, err
			}
			return store.Issued{Serial: cert.SerialNumber.Text(16), NotAfter: cert.NotAfter, PEM: certPEM}, nil
		})
	switch {
	case errors.Is(err, store.ErrInvalidToken):
		h.logger.Warn("enrollment rejected", "token_id", req.TokenID, "remote", r.RemoteAddr)
		h.fail(w, http.StatusUnauthorized, err)
		return
	case errors.Is(err, store.ErrNameTaken):
		h.fail(w, http.StatusConflict, err)
		return
	case err != nil:
		h.logger.Error("enroll", "err", err)
		h.fail(w, http.StatusInternalServerError, errors.New("enrollment failed"))
		return
	}
	h.logger.Info("agent enrolled", "agent", agent.Name, "agent_id", agent.ID, "pin", agent.Pin, "remote", r.RemoteAddr)
	h.writeJSON(w, http.StatusOK, protocol.EnrollResponse{
		AgentID: agent.ID, Name: agent.Name, Certificate: string(issued.PEM), CA: string(h.ca.PEM),
	})
}

type agentKey struct{}

// requireAgent admits only requests with a verified client certificate whose
// key is pinned to an active agent.
func (h *Hub) requireAgent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			h.fail(w, http.StatusUnauthorized, errors.New("client certificate required"))
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		agent, err := h.store.AgentByPin(r.Context(), pki.Pin(leaf))
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrRevoked) {
			h.logger.Warn("agent rejected", "reason", err, "cn", leaf.Subject.CommonName, "remote", r.RemoteAddr)
			h.fail(w, http.StatusForbidden, errors.New("unknown or revoked agent"))
			return
		}
		if err != nil {
			h.logger.Error("look up agent", "err", err)
			h.fail(w, http.StatusInternalServerError, errors.New("internal error"))
			return
		}
		if leaf.Subject.CommonName != agent.ID {
			h.fail(w, http.StatusForbidden, errors.New("certificate does not match agent"))
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), agentKey{}, agent)))
	}
}

func agentFrom(ctx context.Context) store.Agent {
	a, _ := ctx.Value(agentKey{}).(store.Agent)
	return a
}

func (h *Hub) renew(w http.ResponseWriter, r *http.Request) {
	agent := agentFrom(r.Context())
	var req protocol.RenewRequest
	if !h.decode(w, r, maxEnrollBody, &req) {
		return
	}
	csr, err := pki.ParseCSR([]byte(req.CSR))
	if err != nil {
		h.fail(w, http.StatusBadRequest, err)
		return
	}
	// Renewal keeps the pinned key; a new key needs a new enrollment.
	if pin, err := pki.PublicKeyPin(csr.PublicKey); err != nil || pin != agent.Pin {
		h.fail(w, http.StatusForbidden, errors.New("renewal must use the enrolled key"))
		return
	}
	certPEM, cert, err := h.ca.SignAgent([]byte(req.CSR), agent.ID)
	if err != nil {
		h.logger.Error("sign renewal", "agent", agent.Name, "err", err)
		h.fail(w, http.StatusInternalServerError, errors.New("renewal failed"))
		return
	}
	if err := h.store.UpdateAgentCert(r.Context(), agent.ID, cert.SerialNumber.Text(16), cert.NotAfter); err != nil {
		h.logger.Error("save renewal", "agent", agent.Name, "err", err)
		h.fail(w, http.StatusInternalServerError, errors.New("renewal failed"))
		return
	}
	h.logger.Info("agent certificate renewed", "agent", agent.Name, "not_after", cert.NotAfter)
	h.writeJSON(w, http.StatusOK, protocol.RenewResponse{Certificate: string(certPEM)})
}

func (h *Hub) report(w http.ResponseWriter, r *http.Request) {
	agent := agentFrom(r.Context())
	var rep protocol.Report
	if !h.decode(w, r, maxReportBody, &rep) {
		return
	}
	if err := h.store.SaveReport(r.Context(), agent.ID, rep, time.Now()); err != nil {
		h.logger.Error("save report", "agent", agent.Name, "err", err)
		h.fail(w, http.StatusInternalServerError, errors.New("could not save report"))
		return
	}
	resp := protocol.ReportResponse{NextReportSeconds: int(h.reportInterval / time.Second)}
	if h.sbomRequests {
		queue := store.AgentQueue{Reports: rep.Scanning, Pending: map[string]bool{}}
		for _, id := range rep.SBOMPending {
			queue.Pending[id] = true
		}
		ids, err := h.store.RequestSBOMs(r.Context(), agent.ID, sbomRequestsPerReport, queue, time.Now())
		if err != nil {
			h.logger.Error("pick sbom requests", "agent", agent.Name, "err", err)
		}
		resp.SBOMRequests = ids
	}
	h.logger.Debug("report", "agent", agent.Name, "containers", len(rep.Containers), "images", len(rep.Images), "sbom_requests", len(resp.SBOMRequests))
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Hub) sbom(w http.ResponseWriter, r *http.Request) {
	agent := agentFrom(r.Context())
	var up protocol.SBOMUpload
	if !h.decode(w, r, maxSBOMBody, &up) {
		return
	}
	if !strings.HasPrefix(up.ImageID, "sha256:") {
		h.fail(w, http.StatusBadRequest, errors.New("image_id must be a sha256 image ID"))
		return
	}
	if up.Error == "" && (up.Format != protocol.FormatCycloneDXJSON || len(up.Document) == 0) {
		h.fail(w, http.StatusBadRequest, errors.New("expected a cyclonedx-json document or an error"))
		return
	}
	if err := h.store.SaveSBOM(r.Context(), agent.ID, up, time.Now()); errors.Is(err, store.ErrUnsolicited) {
		h.logger.Warn("unsolicited sbom rejected", "agent", agent.Name, "image_id", up.ImageID, "remote", r.RemoteAddr)
		h.fail(w, http.StatusConflict, err)
		return
	} else if err != nil {
		h.logger.Error("save sbom", "agent", agent.Name, "err", err)
		h.fail(w, http.StatusInternalServerError, errors.New("could not save sbom"))
		return
	}
	if up.Error != "" {
		h.logger.Warn("agent could not generate sbom", "agent", agent.Name, "image_id", up.ImageID, "err", up.Error)
	} else {
		h.logger.Info("sbom received", "agent", agent.Name, "image_id", up.ImageID, "bytes", len(up.Document), "duration_ms", up.DurationMS)
	}
	h.writeJSON(w, http.StatusOK, struct{}{})
}

func (h *Hub) decode(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		h.fail(w, http.StatusUnsupportedMediaType, errors.New("content type must be application/json"))
		return false
	}
	// Unknown fields are ignored so a newer agent can report to an older
	// server.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit)).Decode(v); err != nil {
		h.fail(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return false
	}
	return true
}

func (h *Hub) fail(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, protocol.Error{Error: err.Error()})
}

func (h *Hub) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger.Warn("write response", "err", err)
	}
}

func newAgentID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return "agt_" + hex.EncodeToString(b)
}
