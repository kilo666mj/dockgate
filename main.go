// Command dockgate monitors Docker hosts: `dockgate agent` runs on each host
// and reports to `dockgate server`. See PLAN.md.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"go.michaelspost.com/dockgate/internal/agent"
	"go.michaelspost.com/dockgate/internal/docker"
	"go.michaelspost.com/dockgate/internal/fleetglass"
	"go.michaelspost.com/dockgate/internal/hub"
	"go.michaelspost.com/dockgate/internal/jobs"
	"go.michaelspost.com/dockgate/internal/mcpapi"
	"go.michaelspost.com/dockgate/internal/pki"
	"go.michaelspost.com/dockgate/internal/protocol"
	"go.michaelspost.com/dockgate/internal/server"
	"go.michaelspost.com/dockgate/internal/store"
	"go.michaelspost.com/dockgate/internal/tasks"
	"go.michaelspost.com/dockgate/internal/updates"
	"go.michaelspost.com/dockgate/internal/vulns"
	"go.michaelspost.com/dockgate/internal/web"

	tintwire "go.michaelspost.com/tintwire-go"
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
  server vulns             list fixable vulnerabilities on running containers
  server ignore add|list|rm  manage vulnerability ignore rules
  server jobs list|show|request|approve|reject  manage update jobs

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
	case "server vulns":
		return serverVulns(rest)
	case "server ignore":
		return serverIgnore(rest)
	case "server jobs":
		return serverJobs(rest)
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
	trivyBin := fs.String("trivy", envOr("DOCKGATE_TRIVY", "/usr/local/bin/trivy"), "Trivy binary for vulnerability matching; empty disables scanning")
	dbRefresh := fs.Duration("db-refresh", envDuration("DOCKGATE_DB_REFRESH", 6*time.Hour), "how often to look for a newer vulnerability database")
	twURL := fs.String("tintwire-url", os.Getenv("DOCKGATE_TINTWIRE_URL"), "Tintwire origin for vulnerability alerts; empty disables alerts (token from DOCKGATE_TINTWIRE_TOKEN)")
	twChannel := fs.String("tintwire-channel", os.Getenv("DOCKGATE_TINTWIRE_CHANNEL"), "Tintwire channel for alerts; empty uses the token's own channel (required for hook tokens)")
	alertSev := fs.String("alert-severities", envOr("DOCKGATE_ALERT_SEVERITIES", "CRITICAL,HIGH"), "severities of new fixable findings that alert")
	tbURL := fs.String("taskboard-url", os.Getenv("DOCKGATE_TASKBOARD_URL"), "Taskboard MCP endpoint for filing actionable-update tasks, e.g. https://taskboard.example.net/mcp; empty disables it (token from DOCKGATE_TASKBOARD_TOKEN)")
	tbMaxOpen := fs.Int("taskboard-max-open", envInt("DOCKGATE_TASKBOARD_MAX_OPEN", 5), "maximum open update tasks dockgate keeps filed")
	tbRequirements := fs.String("taskboard-requirements", envOr("DOCKGATE_TASKBOARD_REQUIREMENTS", "runner:local"), "comma-separated requirement tokens routing the tasks")
	tbProject := fs.String("taskboard-project", envOr("DOCKGATE_TASKBOARD_PROJECT", "dockgate"), "Taskboard project for the tasks")
	ownPrefixes := fs.String("own-image-prefixes", os.Getenv("DOCKGATE_OWN_IMAGE_PREFIXES"), "comma-separated image reference prefixes built from your own repositories (fixed by pull request instead of pull and recreate)")
	mcpListen := fs.String("mcp-listen", os.Getenv("DOCKGATE_MCP_LISTEN"), "MCP (Streamable HTTP) listen address for agents via a TLS proxy, e.g. 127.0.0.1:8098; empty disables it")
	mcpTokenFile := fs.String("mcp-token-file", os.Getenv("DOCKGATE_MCP_TOKEN_FILE"), "file holding the MCP bearer token (required with -mcp-listen)")
	webListen := fs.String("web-listen", os.Getenv("DOCKGATE_WEB_LISTEN"), "web UI listen address behind a TLS proxy, e.g. 127.0.0.1:8099; empty disables it")
	webURL := fs.String("web-url", os.Getenv("DOCKGATE_WEB_URL"), "public https origin of the web UI, used for sign-in and in approval links")
	oidcIssuer := fs.String("oidc-issuer", os.Getenv("DOCKGATE_OIDC_ISSUER"), "OIDC issuer for web sign-in (client secret from DOCKGATE_OIDC_CLIENT_SECRET)")
	oidcClient := fs.String("oidc-client-id", os.Getenv("DOCKGATE_OIDC_CLIENT_ID"), "OIDC client ID for web sign-in")
	oidcEmails := fs.String("oidc-allowed-emails", os.Getenv("DOCKGATE_OIDC_ALLOWED_EMAILS"), "comma-separated emails allowed to sign in and approve jobs")
	oidcGroups := fs.String("oidc-allowed-groups", os.Getenv("DOCKGATE_OIDC_ALLOWED_GROUPS"), "comma-separated groups allowed to sign in and approve jobs")
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

	var tw *tintwire.Client
	if *twURL != "" {
		if tw, err = tintwire.New(*twURL, os.Getenv("DOCKGATE_TINTWIRE_TOKEN")); err != nil {
			return fmt.Errorf("tintwire: %w", err)
		}
	}
	jobSvc := &jobs.Service{Store: st, Logger: logger, Channel: *twChannel, BaseURL: *webURL, OwnImagePrefixes: splitList(*ownPrefixes)}
	if tw != nil {
		jobSvc.Publisher = tw
	}

	h, err := hub.New(hub.Config{
		Store: st, CA: ca, Logger: logger, ReportInterval: *reportInterval,
		CertDir: *dataDir, Hosts: splitList(*agentHosts), SBOMRequests: *trivyBin != "",
		JobFinished: jobSvc.Finished,
	})
	if err != nil {
		return err
	}

	var webSrv *http.Server
	if *webListen != "" {
		ui, err := web.New(web.Config{
			Store: st, Jobs: jobSvc, Logger: logger, BaseURL: *webURL, Version: version,
			OIDC: web.OIDC{
				Issuer: *oidcIssuer, ClientID: *oidcClient, ClientSecret: os.Getenv("DOCKGATE_OIDC_CLIENT_SECRET"),
				AllowedEmails: splitList(*oidcEmails), AllowedGroups: splitList(*oidcGroups),
			},
		})
		if err != nil {
			return err
		}
		webSrv = newHTTPServer(*webListen, ui.Handler())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go h.RenewLoop(ctx)
	go jobSvc.ExpireLoop(ctx, time.Minute)
	if *trivyBin != "" {
		alerter := &vulns.Alerter{Store: st, Logger: logger, Channel: *twChannel, Severities: splitList(strings.ToUpper(*alertSev))}
		if tw != nil {
			alerter.Publisher = tw
		}
		scanner := &vulns.Scanner{
			Store: st, Logger: logger, RefreshEvery: *dbRefresh, AfterPass: alerter.Check,
			Matcher: &vulns.Trivy{Binary: *trivyBin, CacheDir: filepath.Join(*dataDir, "trivy")},
		}
		go scanner.Run(ctx)
	}
	if *fgURL != "" {
		exp := &fleetglass.Exporter{
			URL: *fgURL, Token: os.Getenv("DOCKGATE_FLEETGLASS_TOKEN"), Store: st, Logger: logger,
			StaleAfter: 5 * *reportInterval,
		}
		go exp.Run(ctx, *fgInterval)
	}

	if *tbURL != "" {
		token := os.Getenv("DOCKGATE_TASKBOARD_TOKEN")
		if token == "" {
			return errors.New("DOCKGATE_TASKBOARD_TOKEN is required with -taskboard-url")
		}
		syncer := &tasks.Syncer{
			Store: st, Logger: logger, MaxOpen: *tbMaxOpen, Requirements: splitList(*tbRequirements),
			Project: *tbProject, OwnImagePrefixes: splitList(*ownPrefixes),
			API: &tasks.Client{Endpoint: *tbURL, Token: token, Version: version},
		}
		go syncer.Run(ctx, 10*time.Minute)
	}

	health := newHTTPServer(*listen, server.New(logger, version).Handler())
	agents := newHTTPServer(*agentListen, h.Handler())
	agents.TLSConfig = h.TLSConfig()

	var mcpSrv *http.Server
	if *mcpListen != "" {
		token, err := os.ReadFile(*mcpTokenFile)
		if err != nil {
			return fmt.Errorf("MCP token: %w", err)
		}
		handler, err := mcpapi.Handler(mcpapi.NewServer(st, jobSvc, version, logger), strings.TrimSpace(string(token)), logger)
		if err != nil {
			return err
		}
		mux := http.NewServeMux()
		mux.Handle("/mcp", handler)
		mcpSrv = newHTTPServer(*mcpListen, mux)
	}

	errc := make(chan error, 4)
	go func() {
		logger.Info("listening", "addr", *listen, "version", version)
		errc <- health.ListenAndServe()
	}()
	go func() {
		logger.Info("agent API listening", "addr", *agentListen, "ca_pin", ca.Pin())
		errc <- agents.ListenAndServeTLS("", "")
	}()
	if mcpSrv != nil {
		go func() {
			logger.Info("MCP listening", "addr", *mcpListen)
			errc <- mcpSrv.ListenAndServe()
		}()
	}
	if webSrv != nil {
		go func() {
			logger.Info("web UI listening", "addr", *webListen, "url", *webURL)
			errc <- webSrv.ListenAndServe()
		}()
	}

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
	err = errors.Join(health.Shutdown(shutdownCtx), agents.Shutdown(shutdownCtx))
	if mcpSrv != nil {
		err = errors.Join(err, mcpSrv.Shutdown(shutdownCtx))
	}
	if webSrv != nil {
		err = errors.Join(err, webSrv.Shutdown(shutdownCtx))
	}
	return err
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

func serverVulns(args []string) error {
	fs := flag.NewFlagSet("server vulns", flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	host := fs.String("host", "", "only this agent")
	all := fs.Bool("all", false, "include findings without a fix and low severities")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, _, err := openServerState(*dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	findings, err := st.ActiveFindings(context.Background(), *host, time.Now())
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "HOST\tCONTAINER\tSEVERITY\tVULNERABILITY\tPACKAGE\tINSTALLED\tFIXED")
	for _, f := range findings {
		if !*all && (!f.Fixable() || (f.Severity != "CRITICAL" && f.Severity != "HIGH")) {
			continue
		}
		fixed := f.Fixed
		if fixed == "" {
			fixed = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Host, f.Container, f.Severity, f.VulnID, f.Pkg, f.Installed, fixed)
	}
	return tw.Flush()
}

func serverIgnore(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: dockgate server ignore add|list|rm")
	}
	fs := flag.NewFlagSet("server ignore "+args[0], flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	vuln := fs.String("vuln", "", "vulnerability ID, e.g. CVE-2026-1234 (add)")
	pkg := fs.String("package", "", "only this package (add)")
	repo := fs.String("image", "", "only this image repository, e.g. postgres or ghcr.io/example/app (add)")
	reason := fs.String("reason", "", "why it is safe to ignore (add, required)")
	ttl := fs.Duration("ttl", 30*24*time.Hour, "how long the rule lasts (add)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	st, _, err := openServerState(*dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	switch args[0] {
	case "add":
		id, err := st.AddIgnore(ctx, store.Ignore{VulnID: *vuln, Pkg: *pkg, Repository: *repo, Reason: *reason, ExpiresAt: time.Now().Add(*ttl)})
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Added ignore %d for %s until %s.\n", id, *vuln, time.Now().Add(*ttl).Format(time.DateOnly))
		return nil
	case "list":
		rules, err := st.Ignores(ctx, time.Time{})
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "ID\tVULNERABILITY\tPACKAGE\tIMAGE\tEXPIRES\tREASON")
		for _, r := range rules {
			_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.VulnID, dash(r.Pkg), dash(r.Repository), r.ExpiresAt.Format(time.DateOnly), r.Reason)
		}
		return tw.Flush()
	case "rm":
		if fs.NArg() != 1 {
			return errors.New("usage: dockgate server ignore rm ID")
		}
		id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil {
			return fmt.Errorf("ignore ID: %w", err)
		}
		return st.RemoveIgnore(ctx, id)
	}
	return fmt.Errorf("unknown ignore command %q", args[0])
}

func serverJobs(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: dockgate server jobs list|show|request|approve|reject")
	}
	fs := flag.NewFlagSet("server jobs "+args[0], flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	host := fs.String("host", "", "host name (request)")
	container := fs.String("container", "", "container name (request)")
	reason := fs.String("reason", "", "why (request, required)")
	note := fs.String("note", "", "note recorded with the decision (approve, reject)")
	all := fs.Bool("all", false, "include finished jobs (list)")
	ownPrefixes := fs.String("own-image-prefixes", os.Getenv("DOCKGATE_OWN_IMAGE_PREFIXES"), "image prefixes fixed by pull request instead (request)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	st, _, err := openServerState(*dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	svc := &jobs.Service{Store: st, Logger: newLogger("warn"), OwnImagePrefixes: splitList(*ownPrefixes)}
	actor := "cli"
	if u, err := user.Current(); err == nil {
		actor += ":" + u.Username
	}
	if hn, err := os.Hostname(); err == nil {
		actor += "@" + hn
	}
	oneID := func() (string, error) {
		if fs.NArg() != 1 {
			return "", fmt.Errorf("usage: dockgate server jobs %s JOB_ID", args[0])
		}
		return fs.Arg(0), nil
	}
	switch args[0] {
	case "list":
		f := store.JobFilter{States: store.OpenJobStates, Limit: 100}
		if *all {
			f.States = nil
		}
		list, err := st.Jobs(ctx, f)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "JOB\tSTATE\tHOST\tCONTAINER\tFIXES\tINTRODUCES\tREQUESTED\tBY")
		for _, j := range list {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n", j.ID, j.State, j.Host, j.ContainerName,
				len(j.Gate.Fixes), len(j.Gate.Introduces), j.CreatedAt.Format("2006-01-02 15:04"), j.RequestedBy)
		}
		return tw.Flush()
	case "show":
		id, err := oneID()
		if err != nil {
			return err
		}
		j, err := st.Job(ctx, id)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(j)
	case "request":
		j, err := svc.RequestUpdate(ctx, jobs.Request{Host: *host, Container: *container, Reason: *reason, Actor: actor})
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Job %s is %s: fixes %d, introduces %d.\n", j.ID, j.State, len(j.Gate.Fixes), len(j.Gate.Introduces))
		return nil
	case "approve", "reject":
		id, err := oneID()
		if err != nil {
			return err
		}
		j, err := svc.Decide(ctx, id, args[0] == "approve", actor, *note)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Job %s is %s.\n", j.ID, j.State)
		return nil
	}
	return fmt.Errorf("unknown jobs command %q", args[0])
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
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
	scan := fs.Bool("scan", envOr("DOCKGATE_SCAN", "true") == "true", "generate SBOMs the server asks for, with a digest-pinned scanner container")
	jobsOn := fs.Bool("jobs", envOr("DOCKGATE_JOBS", "true") == "true", "carry out update jobs the server has approved")
	logLevel := fs.String("log-level", envOr("DOCKGATE_LOG_LEVEL", "info"), "log level")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger := newLogger(*logLevel)
	id, err := agent.LoadIdentity(*stateDir)
	if err != nil {
		return err
	}
	dc := docker.New(*socket)
	collector := &agent.Collector{Docker: dc, Version: version}
	if *updateInterval > 0 {
		collector.Updates = updates.NewChecker(updates.RegistryHead, *updateInterval)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("agent starting", "agent", id.State.Name, "agent_id", id.State.AgentID, "server", id.State.Server, "version", version)
	var sboms *agent.SBOMWorker
	if *scan {
		sboms = agent.NewSBOMWorker(&agent.SBOMGenerator{Docker: dc, SocketPath: *socket}, logger)
	}
	var jobs *agent.JobWorker
	if *jobsOn {
		jobs = agent.NewJobWorker(agent.NewExecutor(dc), logger)
	}
	return agent.Run(ctx, id, collector, sboms, jobs, logger)
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

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
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
