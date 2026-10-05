// Package web serves dockgate's browser UI: the fleet and each host's
// containers, read-only, and the update-job queue, where a signed-in person
// approves or rejects jobs. Sign-in is OIDC only; the UI refuses to start
// without it.
package web

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"go.michaelspost.com/oidcrp"

	"go.michaelspost.com/dockgate/internal/fleet"
	"go.michaelspost.com/dockgate/internal/jobs"
	"go.michaelspost.com/dockgate/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

const (
	sessionCookie = "dockgate_session"
	sessionTTL    = 12 * time.Hour
)

// Config configures the web UI.
type Config struct {
	Store  *store.Store
	Jobs   *jobs.Service
	Logger *slog.Logger
	// BaseURL is the UI's public origin, e.g. https://dockgate.example.
	BaseURL string
	OIDC    OIDC
	Version string
}

// OIDC is the identity provider client and who may sign in.
type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// AllowedEmails and AllowedGroups: a person matching either may sign
	// in. At least one must be set; there is no "anyone with an account".
	AllowedEmails []string
	AllowedGroups []string
}

// UI is the web UI.
type UI struct {
	store   *store.Store
	jobs    *jobs.Service
	logger  *slog.Logger
	auth    *oidcrp.Service
	base    *url.URL
	tmpl    map[string]*template.Template
	version string
	now     func() time.Time
}

// New validates the configuration and returns the UI.
func New(cfg Config) (*UI, error) {
	base, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || base.Scheme != "https" || base.Host == "" || base.Path != "" {
		return nil, errors.New("web: base URL must be an https origin without a path")
	}
	o := cfg.OIDC
	if o.Issuer == "" || o.ClientID == "" || o.ClientSecret == "" {
		return nil, errors.New("web: OIDC issuer, client ID and client secret are required")
	}
	if len(o.AllowedEmails) == 0 && len(o.AllowedGroups) == 0 {
		return nil, errors.New("web: set allowed emails or groups for sign-in")
	}
	u := &UI{store: cfg.Store, jobs: cfg.Jobs, logger: cfg.Logger, base: base, version: cfg.Version, now: time.Now}
	u.auth = oidcrp.New(oidcrp.Config{
		Issuer: o.Issuer, ClientID: o.ClientID, ClientSecret: o.ClientSecret,
		RedirectURL:   base.String() + "/auth/callback",
		AllowedEmails: o.AllowedEmails, AllowedGroups: o.AllowedGroups,
		StateCookieName: "dockgate_oidc", LoginPath: "/login", LoginStartPath: "/auth/login",
		CallbackPath: "/auth/callback", SuccessPath: "/jobs",
	}, sessions{u})
	if !u.auth.Enabled() {
		return nil, errors.New("web: OIDC is not fully configured")
	}
	if err := u.parseTemplates(); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *UI) parseTemplates() error {
	funcs := template.FuncMap{
		"short": func(d string) string {
			d = strings.TrimPrefix(d, "sha256:")
			return d[:min(12, len(d))]
		},
		"when": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.Local().Format("2006-01-02 15:04")
		},
		"label": func(s string) string { return strings.ReplaceAll(s, "_", " ") },
		"lower": strings.ToLower,
		"ago":   func(t time.Time) string { return ago(u.now().Sub(t), t.IsZero()) },
		"gib":   func(b int64) string { return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30)) },
	}
	u.tmpl = map[string]*template.Template{}
	for _, page := range []string{"login", "jobs", "job", "fleet", "host"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+page+".html")
		if err != nil {
			return fmt.Errorf("web: template %s: %w", page, err)
		}
		u.tmpl[page] = t
	}
	return nil
}

// Handler returns the UI's routes.
func (u *UI) Handler() http.Handler {
	mux := http.NewServeMux()
	u.auth.Register(mux)
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", u.login)
	mux.HandleFunc("POST /logout", u.requirePOST(u.logout))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/fleet", http.StatusFound) })
	mux.HandleFunc("GET /fleet", u.auth.Require(u.fleetPage))
	mux.HandleFunc("GET /hosts/{name}", u.auth.Require(u.hostPage))
	mux.HandleFunc("GET /jobs", u.auth.Require(u.jobList))
	mux.HandleFunc("GET /jobs/{id}", u.auth.Require(u.jobPage))
	mux.HandleFunc("POST /jobs/{id}/approve", u.auth.Require(u.requirePOST(u.decide(true))))
	mux.HandleFunc("POST /jobs/{id}/reject", u.auth.Require(u.requirePOST(u.decide(false))))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// sessions adapts the store to oidcrp's session interface.
type sessions struct{ u *UI }

func (s sessions) Valid(r *http.Request) bool {
	_, ok := s.u.session(r)
	return ok
}

func (s sessions) Issue(w http.ResponseWriter, r *http.Request, id oidcrp.Identity) error {
	sid, csrf := randToken(), randToken()
	now := s.u.now()
	if err := s.u.store.CreateSession(r.Context(), sid, store.WebSession{
		Subject: id.Subject, Email: id.Email, CSRF: csrf, ExpiresAt: now.Add(sessionTTL),
	}, now); err != nil {
		return err
	}
	// Lax, not Strict: the approval link arrives from a notification on
	// another site, and must open signed in. Writes need the CSRF token.
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sid, Path: "/", MaxAge: int(sessionTTL / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	s.u.logger.Info("web sign-in", "email", id.Email, "subject", id.Subject)
	return nil
}

func (s sessions) Clear(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.u.store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func (u *UI) session(r *http.Request) (store.WebSession, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return store.WebSession{}, false
	}
	ws, err := u.store.Session(r.Context(), c.Value, u.now())
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			u.logger.Error("read session", "err", err)
		}
		return store.WebSession{}, false
	}
	return ws, true
}

// actor names the signed-in person in the audit log.
func actor(ws store.WebSession) string {
	if ws.Email != "" {
		return "oidc:" + ws.Email
	}
	return "oidc-subject:" + ws.Subject
}

// requirePOST checks that a form post comes from this UI: same origin and
// carrying the session's CSRF token.
func (u *UI) requirePOST(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && origin != u.base.String() {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		ws, ok := u.session(r)
		if !ok {
			http.Error(w, "not signed in", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(ws.CSRF)) != 1 {
			http.Error(w, "stale or missing form token; reload the page", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (u *UI) render(w http.ResponseWriter, page string, data map[string]any) {
	data["Version"] = u.version
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := u.tmpl[page].Execute(w, data); err != nil {
		u.logger.Error("render", "page", page, "err", err)
	}
}

func (u *UI) login(w http.ResponseWriter, r *http.Request) {
	if _, ok := u.session(r); ok {
		http.Redirect(w, r, "/fleet", http.StatusFound)
		return
	}
	u.render(w, "login", map[string]any{"Title": "Sign in", "Error": r.URL.Query().Get("error")})
}

func (u *UI) logout(w http.ResponseWriter, r *http.Request) {
	u.auth.Logout(w, r)
}

func (u *UI) jobList(w http.ResponseWriter, r *http.Request) {
	ws, _ := u.session(r)
	ctx := r.Context()
	open, err := u.store.Jobs(ctx, store.JobFilter{States: store.OpenJobStates, Limit: 200})
	if err != nil {
		u.fail(w, err)
		return
	}
	recent, err := u.store.Jobs(ctx, store.JobFilter{Limit: 100})
	if err != nil {
		u.fail(w, err)
		return
	}
	var closed []store.Job
	for _, j := range recent {
		if !j.Open() {
			closed = append(closed, j)
		}
	}
	u.render(w, "jobs", map[string]any{"Title": "Update jobs", "Nav": "jobs", "Open": open, "Closed": closed, "Session": ws})
}

// openJobs maps host, then container name, to that container's open job.
func (u *UI) openJobs(r *http.Request) (map[string]map[string]store.Job, error) {
	open, err := u.store.Jobs(r.Context(), store.JobFilter{States: store.OpenJobStates, Limit: 500})
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]store.Job{}
	for _, j := range open {
		if out[j.Host] == nil {
			out[j.Host] = map[string]store.Job{}
		}
		if _, seen := out[j.Host][j.ContainerName]; !seen { // newest first
			out[j.Host][j.ContainerName] = j
		}
	}
	return out, nil
}

// fleetTotals adds up the hosts for the summary tiles.
type fleetTotals struct {
	Hosts, Reporting, Silent, Containers, Troubled, Updates, Critical, High, OpenJobs int
}

func (u *UI) fleetPage(w http.ResponseWriter, r *http.Request) {
	ws, _ := u.session(r)
	hosts, err := fleet.Hosts(r.Context(), u.store, u.now())
	if err != nil {
		u.fail(w, err)
		return
	}
	jobs, err := u.openJobs(r)
	if err != nil {
		u.fail(w, err)
		return
	}
	var t fleetTotals
	openByHost := map[string]int{}
	for _, h := range hosts {
		t.Hosts++
		if h.Reporting == "ok" {
			t.Reporting++
		} else {
			t.Silent++
		}
		t.Containers += h.Containers
		t.Troubled += h.Unhealthy + h.Restarting
		t.Updates += h.UpdatesAvailable
		t.Critical += h.FixableCritical
		t.High += h.FixableHigh
		openByHost[h.Host] = len(jobs[h.Host])
		t.OpenJobs += len(jobs[h.Host])
	}
	u.render(w, "fleet", map[string]any{"Title": "Fleet", "Nav": "fleet", "Hosts": hosts, "Totals": t, "OpenJobs": openByHost, "Session": ws})
}

// containerRow is one container on the host page, with its open job.
type containerRow struct {
	fleet.Container
	Job *store.Job
}

// trouble orders containers that need attention first: restarting, then
// unhealthy, then running, then everything else (stopped or one-shot).
func trouble(c fleet.Container) int {
	switch {
	case c.State == "restarting":
		return 0
	case c.State == "running" && c.Health == "unhealthy":
		return 1
	case c.State == "running":
		return 2
	default:
		return 3
	}
}

func (u *UI) hostPage(w http.ResponseWriter, r *http.Request) {
	ws, _ := u.session(r)
	ctx := r.Context()
	name := r.PathValue("name")
	agents, err := u.store.Agents(ctx)
	if err != nil {
		u.fail(w, err)
		return
	}
	var agent *store.Agent
	for i := range agents {
		if agents[i].Name == name && agents[i].RevokedAt.IsZero() {
			agent = &agents[i]
		}
	}
	if agent == nil {
		http.NotFound(w, r)
		return
	}
	hosts, err := fleet.Hosts(ctx, u.store, u.now())
	if err != nil {
		u.fail(w, err)
		return
	}
	var summary fleet.Host
	for _, h := range hosts {
		if h.Host == name {
			summary = h
		}
	}
	containers, err := fleet.Containers(ctx, u.store, *agent, u.now())
	if err != nil {
		u.fail(w, err)
		return
	}
	jobs, err := u.openJobs(r)
	if err != nil {
		u.fail(w, err)
		return
	}
	sort.SliceStable(containers, func(i, j int) bool {
		if a, b := trouble(containers[i]), trouble(containers[j]); a != b {
			return a < b
		}
		return containers[i].Name < containers[j].Name
	})
	rows := make([]containerRow, 0, len(containers))
	for _, c := range containers {
		row := containerRow{Container: c}
		if j, ok := jobs[name][c.Name]; ok {
			row.Job = &j
		}
		rows = append(rows, row)
	}
	u.render(w, "host", map[string]any{"Title": name, "Nav": "fleet", "Host": summary, "Agent": agent, "Containers": rows, "Session": ws})
}

// ago is a short, human duration for "last report 3 minutes ago".
func ago(d time.Duration, never bool) string {
	switch {
	case never:
		return "never"
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d/time.Hour))
	default:
		return fmt.Sprintf("%d days ago", int(d/(24*time.Hour)))
	}
}

func (u *UI) jobPage(w http.ResponseWriter, r *http.Request) {
	ws, _ := u.session(r)
	job, err := u.store.Job(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		u.fail(w, err)
		return
	}
	critical := 0
	for _, f := range job.Gate.Fixes {
		if f.Severity == "CRITICAL" {
			critical++
		}
	}
	u.render(w, "job", map[string]any{
		"Title": fmt.Sprintf("%s on %s", job.ContainerName, job.Host), "Nav": "jobs", "Job": job, "Session": ws,
		"CriticalFixed": critical, "Pending": job.State == store.JobPendingApproval, "Notice": notices[r.URL.Query().Get("notice")],
	})
}

// notices are the messages shown after a decision, chosen by a fixed key so
// a crafted link cannot put arbitrary text on the page.
var notices = map[string]string{
	"approved":   "Approved. The host's agent picks the job up at its next report.",
	"rejected":   "Rejected.",
	"superseded": "Not approved: the candidate image is no longer current. Request the update again.",
	"closed":     "This job was already decided or has closed.",
}

func (u *UI) decide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ws, _ := u.session(r)
		id := r.PathValue("id")
		job, err := u.jobs.Decide(r.Context(), id, approve, actor(ws), strings.TrimSpace(r.PostFormValue("note")))
		notice := ""
		switch {
		case errors.Is(err, store.ErrNotFound):
			http.NotFound(w, r)
			return
		case errors.Is(err, store.ErrJobState):
			notice = "closed"
		case err != nil:
			u.fail(w, err)
			return
		case job.State == store.JobSuperseded:
			notice = "superseded"
		case approve:
			u.logger.Info("job approved in web UI", "job_id", id, "by", actor(ws))
			notice = "approved"
		default:
			notice = "rejected"
		}
		http.Redirect(w, r, "/jobs/"+url.PathEscape(id)+"?notice="+notice, http.StatusSeeOther)
	}
}

func (u *UI) fail(w http.ResponseWriter, err error) {
	u.logger.Error("web", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return base64.RawURLEncoding.EncodeToString(b)
}
