// Package server holds the HTTP handlers for dockgate.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
)

// Server serves the service's HTTP API.
type Server struct {
	logger  *slog.Logger
	version string
	ready   atomic.Bool
}

// New returns a Server that reports ready immediately. Services with
// dependencies should call SetReady(false) until those are reachable.
func New(logger *slog.Logger, version string) *Server {
	s := &Server{logger: logger, version: version}
	s.ready.Store(true)
	return s
}

// SetReady controls the /readyz response.
func (s *Server) SetReady(ready bool) { s.ready.Store(ready) }

// Handler returns the service's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /version", s.versionHandler)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) versionHandler(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"version": s.version})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.logger.Warn("write response", "err", err)
	}
}
