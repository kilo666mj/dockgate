// Command dockgate monitors Docker hosts: `dockgate agent` runs on each host
// and reports to `dockgate server`. See PLAN.md.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"go.michaelspost.com/dockgate/internal/agent"
	"go.michaelspost.com/dockgate/internal/docker"
	"go.michaelspost.com/dockgate/internal/fleetglass"
	"go.michaelspost.com/dockgate/internal/hub"
	"go.michaelspost.com/dockgate/internal/pki"
	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/server"
	"go.michaelspost.com/dockgate/internal/store"
	"go.michaelspost.com/dockgate/internal/updates"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage: dockgate <command> [flags]

Server commands (run on the central server):
  server run               serve the agent API and health endpoints
  server token -name NAME  create a single-use join token for an agent
  server tokens            list join tokens
  server agents            list enrolled agents
  server revoke NAME       stop an agent from authenticating

Agent commands (run on each Docker host):
  agent enroll -server URL -token TOKEN   enroll with the server once
  agent run                               report to the server

  version                  print the version

Run "dockgate <command> -h" for a command's flags.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dockgate:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := strings.Join(args[:min(2, len(args))], " ")
	switch {
	case len(args) == 0:
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	case args[0] == "version" || args[0] == "-version":
		fmt.Println(version)
		return nil
	case len(args) < 2:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
	rest := args[2:]
	switch cmd {
	case "server run":
		return serverRun(rest)
	case "server token":
		return serverToken(rest)
	case "server tokens":
		return serverTokens(rest)
	case "server agents":
		return serverAgents(rest)
	case "server revoke":
		return serverRevoke(rest)
	case "agent enroll":
		return agentEnroll(rest)
	case "agent run":
		return agentRun(rest)
	}
	fmt.Fprint(os.Stderr, usage)
	return fmt.Errorf("unknown command %q", cmd)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func dataDirFlag(fs *flag.FlagSet) *string {
	return fs.String("data-dir", envOr("DOCKGATE_DATA_DIR", "/var/lib/dockgate"), "server data directory (database and CA)")
}

func openServerState(dataDir string) (*store.Store, *pki.CA, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, nil, err
	}
	ca, err := pki.LoadOrCreateCA(dataDir)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(filepath.Join(dataDir, "dockgate.db"))
	if err != nil {
		return nil, nil, err
	}
	return st, ca, nil
}

func serverRun(args []string) error {
	fs := flag.NewFlagSet("server run", flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	listen := fs.String("listen", envOr("DOCKGATE_LISTEN", "127.0.0.1:8080"), "health and version HTTP listen address")
	agentListen := fs.String("agent-listen", envOr("DOCKGATE_AGENT_LISTEN", ":8443"), "agent API TLS listen address")
	agentHosts := fs.String("agent-hosts", os.Getenv("DOCKGATE_AGENT_HOSTS"), "comma-separated DNS names or IPs agents use to reach the server (required)")
	reportInterval := fs.Duration("report-interval", envDuration("DOCKGATE_REPORT_INTERVAL", time.Minute), "how often agents report")
	fgURL := fs.String("fleetglass-url", os.Getenv("DOCKGATE_FLEETGLASS_URL"), "Fleetglass base URL; empty disables export (token from DOCKGATE_FLEETGLASS_TOKEN)")
	fgInterval := fs.Duration("fleetglass-interval", envDuration("DOCKGATE_FLEETGLASS_INTERVAL", 5*time.Minute), "Fleetglass export interval")
	logLevel := fs.String("log-level", envOr("DOCKGATE_LOG_LEVEL", "info"), "log level")
	shutdownTimeout := fs.Duration("shutdown-timeout", 10*time.Second, "graceful shutdown timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger := newLogger(*logLevel)

	st, ca, err := openServerState(*dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	h, err := hub.New(hub.Config{
		Store: st, CA: ca, Logger: logger, ReportInterval: *reportInterval,
		CertDir: *dataDir, Hosts: splitList(*agentHosts),
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go h.RenewLoop(ctx)
	if *fgURL != "" {
		exp := &fleetglass.Exporter{
			URL: *fgURL, Token: os.Getenv("DOCKGATE_FLEETGLASS_TOKEN"), Store: st, Logger: logger,
			StaleAfter: 5 * *reportInterval,
		}
		go exp.Run(ctx, *fgInterval)
	}

	health := newHTTPServer(*listen, server.New(logger, version).Handler())
	agents := newHTTPServer(*agentListen, h.Handler())
	agents.TLSConfig = h.TLSConfig()

	errc := make(chan error, 2)
	go func() {
		logger.Info("listening", "addr", *listen, "version", version)
		errc <- health.ListenAndServe()
	}()
	go func() {
		logger.Info("agent API listening", "addr", *agentListen, "ca_pin", ca.Pin())
		errc <- agents.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			stop()
			return err
		}
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer cancel()
	return errors.Join(health.Shutdown(shutdownCtx), agents.Shutdown(shutdownCtx))
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func serverToken(args []string) error {
	fs := flag.NewFlagSet("server token", flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	name := fs.String("name", "", "agent name, usually the host name (required)")
	replace := fs.Bool("replace", false, "re-key an existing agent with this name")
	ttl := fs.Duration("ttl", time.Hour, "how long the token stays valid")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("-name is required")
	}
	st, ca, err := openServerState(*dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	idBytes, secretBytes := make([]byte, 8), make([]byte, 32)
	_, _ = rand.Read(idBytes) // crypto/rand.Read never returns an error
	_, _ = rand.Read(secretBytes)
	tok := protocol.JoinToken{
		ID:     hex.EncodeToString(idBytes),
		Secret: base64.RawURLEncoding.EncodeToString(secretBytes),
		CAPin:  ca.Pin(),
	}
	if err := st.CreateToken(context.Background(), tok.ID, tok.Secret, *name, *replace, *ttl); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Join token for %q, valid for %s and usable once:\n\n", *name, *ttl)
	fmt.Println(tok.String())
	fmt.Fprintf(os.Stderr, "\nOn the host, run:\n  dockgate agent enroll -server https://<server>:<agent-port> -token <token>\n")
	return nil
}

func serverTokens(args []string) error {
	fs := flag.NewFlagSet("server tokens", flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, _, err := openServerState(*dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	tokens, err := st.Tokens(context.Background())
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tREPLACE\tEXPIRES\tUSED BY")
	for _, t := range tokens {
		usedBy := t.UsedBy
		if usedBy == "" {
			usedBy = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%s\n", t.ID, t.Name, t.Replace, t.ExpiresAt.Format(time.RFC3339), usedBy)
	}
	return tw.Flush()
}

func serverAgents(args []string) error {
	fs := flag.NewFlagSet("server agents", flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, _, err := openServerState(*dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	agents, err := st.Agents(context.Background())
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tID\tLAST REPORT\tVERSION\tCERT EXPIRES\tSTATUS")
	for _, a := range agents {
		status, last := "active", "never"
		if !a.RevokedAt.IsZero() {
			status = "revoked"
		}
		if !a.LastReportAt.IsZero() {
			last = time.Since(a.LastReportAt).Round(time.Second).String() + " ago"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", a.Name, a.ID, last, a.AgentVersion,
			a.CertNotAfter.Format(time.DateOnly), status)
	}
	return tw.Flush()
}

func serverRevoke(args []string) error {
	fs := flag.NewFlagSet("server revoke", flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: dockgate server revoke NAME")
	}
	st, _, err := openServerState(*dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if err := st.RevokeAgent(context.Background(), fs.Arg(0)); err != nil {
		return fmt.Errorf("revoke %s: %w", fs.Arg(0), err)
	}
	fmt.Fprintf(os.Stderr, "Revoked %s. Its next request will be rejected.\n", fs.Arg(0))
	return nil
}

func stateDirFlag(fs *flag.FlagSet) *string {
	return fs.String("state-dir", envOr("DOCKGATE_STATE_DIR", "/var/lib/dockgate-agent"), "agent state directory (key, certificates)")
}

func agentEnroll(args []string) error {
	fs := flag.NewFlagSet("agent enroll", flag.ContinueOnError)
	stateDir := stateDirFlag(fs)
	serverURL := fs.String("server", os.Getenv("DOCKGATE_SERVER"), "server agent API URL, https://host:port (required)")
	token := fs.String("token", os.Getenv("DOCKGATE_JOIN_TOKEN"), "join token from `dockgate server token` (required)")
	force := fs.Bool("force", false, "enroll again, replacing existing credentials")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverURL == "" || *token == "" {
		return errors.New("-server and -token are required")
	}
	hostname, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := agent.Enroll(ctx, *serverURL, *token, hostname, *stateDir, *force)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Enrolled as %s (%s). Start the agent with `dockgate agent run`.\n", st.Name, st.AgentID)
	return nil
}

func agentRun(args []string) error {
	fs := flag.NewFlagSet("agent run", flag.ContinueOnError)
	stateDir := stateDirFlag(fs)
	socket := fs.String("docker-socket", envOr("DOCKGATE_DOCKER_SOCKET", "/var/run/docker.sock"), "Docker daemon socket")
	updateInterval := fs.Duration("update-interval", envDuration("DOCKGATE_UPDATE_INTERVAL", 6*time.Hour), "how often to ask registries about each image tag; 0 disables update checks")
	logLevel := fs.String("log-level", envOr("DOCKGATE_LOG_LEVEL", "info"), "log level")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger := newLogger(*logLevel)
	id, err := agent.LoadIdentity(*stateDir)
	if err != nil {
		return err
	}
	collector := &agent.Collector{Docker: docker.New(*socket), Version: version}
	if *updateInterval > 0 {
		collector.Updates = updates.NewChecker(updates.RegistryHead, *updateInterval)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("agent starting", "agent", id.State.Name, "agent_id", id.State.AgentID, "server", id.State.Server, "version", version)
	return agent.Run(ctx, id, collector, logger)
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
