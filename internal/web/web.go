// Package web serves the user interface and its authentication boundary.
package web

import (
	"bytes"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tokencrypt/internal/clock"
	"tokencrypt/internal/core"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Config holds the exact allowed Host headers and the cookie policy. The
// caller configures SecureCookies for HTTPS; forwarded headers are ignored.
type Config struct {
	AllowedHosts  []string
	SecureCookies bool
	IdleTimeout   time.Duration
	Clock         clock.Clock
	// OnUnlock takes ownership of NotifierToken and must zero it once it is
	// no longer needed. It is called after a successful unlock.
	OnUnlock func(core.UnlockResult)
	// EnvNotifier reports that environment credentials configure the notifier;
	// the notifier page then notes that they override saved settings.
	EnvNotifier bool
	// OnNotifier reconciles current independent settings after a save attempt
	// or an unlock error; unchanged credentials preserve the current transport.
	OnNotifier func()
	// InitParams overrides DefaultParams for controlled bootstrap tests.
	// Production callers leave it nil.
	InitParams *crypto.Params
}

type server struct {
	svc       *core.Service
	cfg       Config
	sessions  *sessionStore
	templates map[string]*template.Template
	static    http.Handler
}

type pageData struct {
	Title, CSRF, Message, Error string
	Authenticated               bool
	Candidates                  []grants.Grant
	Section                     string
	State                       core.Status
	Secret                      *vault.Meta
	GrantSecrets                []vault.Meta
	Choices                     []durationChoice
	Audit                       []auditRow
	ExpiryChoice, ExpiryDate    string
	ExpiryChoices               []expiryChoice
	NotifierState               string
	NotifierEnv                 bool
}

func newServer(svc *core.Service, cfg Config) *server {
	if cfg.Clock == nil {
		cfg.Clock = clock.Real{}
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 15 * time.Minute
	}
	cfg.AllowedHosts = append([]string(nil), cfg.AllowedHosts...)
	s := &server{svc: svc, cfg: cfg, sessions: &sessionStore{items: map[string]session{}, clk: cfg.Clock, timeout: cfg.IdleTimeout}, templates: map[string]*template.Template{}}
	for _, name := range []string{"login", "setup", "home", "unlock", "secrets", "edit", "grants", "requests", "notifier", "audit"} {
		funcs := template.FuncMap{"expiryDate": expiryDateLabel, "expiryRemaining": func(date string) string { return expiryRemaining(date, cfg.Clock.Wall()) }, "remaining": func(end time.Time) string {
			left := end.Sub(cfg.Clock.Wall().Round(0))
			if left <= 0 {
				return "Expired"
			}
			return left.Round(time.Second).String()
		}}
		s.templates[name] = template.Must(template.New("layout").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+name+".html"))
	}
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	s.static = http.StripPrefix("/static/", http.FileServer(http.FS(static)))
	return s
}

// Handler returns the authenticated web UI. An empty allow-list denies all hosts.
func Handler(svc *core.Service, cfg Config) http.Handler {
	s := newServer(svc, cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.boundary(w, r) {
			return
		}
		if r.URL.Path == "/login" {
			s.login(w, r)
			return
		}
		if len(r.URL.Path) >= 8 && r.URL.Path[:8] == "/static/" {
			if !method(w, r, "GET", "HEAD") {
				return
			}
			s.static.ServeHTTP(w, r)
			return
		}
		x, ok := s.sessions.get(r, true)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if r.Method != "POST" {
				method(w, r, "GET", "POST")
				return
			}
			if !checkCSRF(w, r, x) {
				return
			}
		}
		switch r.URL.Path {
		case "/", "/secrets":
			if !method(w, r, "GET") {
				return
			}
			s.page(w, "secrets", 200, x, "", "")
		case "/secrets/edit":
			s.edit(w, r, x)
		case "/grants":
			s.grantsPage(w, r, x)
		case "/grants/revoke":
			s.revoke(w, r, x)
		case "/requests":
			if !method(w, r, "GET") {
				return
			}
			s.page(w, "requests", 200, x, "", "")
		case "/requests/approve", "/requests/deny":
			s.requestAction(w, r, x)
		case "/notifier":
			s.notifier(w, r, x)
		case "/audit":
			s.auditPage(w, r, x)
		case "/logout":
			if !method(w, r, "POST") {
				return
			}
			s.sessions.remove(x.id)
			s.cookie(w, sessionCookie, "", true)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		case "/unlock":
			s.unlock(w, r, x)
		case "/restore":
			s.restore(w, r, x)
		default:
			if strings.HasPrefix(r.URL.Path, "/secrets/") {
				s.secretAction(w, r, x)
			} else {
				http.NotFound(w, r)
			}
		}
	})
}

func (s *server) boundary(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	for _, host := range s.cfg.AllowedHosts {
		if host != "" && r.Host == host {
			return true
		}
	}
	http.Error(w, "Host not allowed", http.StatusForbidden)
	return false
}

func method(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", joinMethods(allowed))
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	return false
}

func joinMethods(methods []string) string {
	var b bytes.Buffer
	for i, m := range methods {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(m)
	}
	return b.String()
}

func (s *server) render(w http.ResponseWriter, name string, status int, data pageData) {
	data.ExpiryChoices = expiryChoices
	if data.ExpiryChoice == "" {
		data.ExpiryChoice = "never"
		if data.Secret != nil && data.Secret.ExpiresOn != "" {
			data.ExpiryChoice, data.ExpiryDate = "custom", data.Secret.ExpiresOn
		}
	}
	var b bytes.Buffer
	if err := s.templates[name].ExecuteTemplate(&b, "layout", data); err != nil {
		http.Error(w, "Page unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}

func (s *server) preauth(w http.ResponseWriter, r *http.Request) (session, bool) {
	if x, ok := s.sessions.get(r, false); ok {
		return x, true
	}
	x, err := s.sessions.create(false)
	if err != nil {
		http.Error(w, "Please try again later", 503)
		return session{}, false
	}
	s.cookie(w, preauthCookie, x.id, false)
	return x, true
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	if r.Method == "GET" {
		if _, ok := s.sessions.get(r, true); ok {
			http.Redirect(w, r, "/", 303)
			return
		}
		x, ok := s.preauth(w, r)
		if !ok {
			return
		}
		s.render(w, "login", 200, pageData{Title: "Login", CSRF: x.csrf})
		return
	}
	x, ok := s.sessions.get(r, false)
	if !ok {
		http.Error(w, "Invalid form token", 403)
		return
	}
	if !checkCSRF(w, r, x) {
		return
	}
	pass, valid := passphrase(r)
	if !valid {
		s.render(w, "login", 400, pageData{Title: "Login", CSRF: x.csrf, Error: "Enter a passphrase of at most 4096 bytes."})
		return
	}
	defer crypto.Zero(pass)
	if err := s.svc.Verify(pass); err != nil {
		status, message := authError(err)
		s.render(w, "login", status, pageData{Title: "Login", CSRF: x.csrf, Error: message})
		return
	}
	auth, err := s.sessions.create(true)
	if err != nil {
		http.Error(w, "Please try again later", 503)
		return
	}
	s.sessions.remove(x.id)
	// Rotate any authenticated session supplied with the login request too.
	if old, ok := s.sessions.get(r, true); ok {
		s.sessions.remove(old.id)
	}
	s.cookie(w, preauthCookie, "", true)
	s.cookie(w, sessionCookie, auth.id, false)
	http.Redirect(w, r, "/", 303)
}

func passphrase(r *http.Request) ([]byte, bool) {
	values := r.PostForm["passphrase"]
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > maxPassphraseBytes {
		return nil, false
	}
	return []byte(values[0]), true
}

func authError(err error) (int, string) {
	if errors.Is(err, core.ErrThrottled) {
		return 429, "Too many attempts. Try again later."
	}
	if errors.Is(err, core.ErrWrongPassphrase) {
		return 200, "Passphrase not accepted."
	}
	return 500, "Operation could not be completed."
}

func (s *server) unlock(w http.ResponseWriter, r *http.Request, x session) {
	if !method(w, r, "GET", "POST") {
		return
	}
	d := pageData{Title: "Unlock", CSRF: x.csrf, Authenticated: true, Section: "unlock", Candidates: x.candidates}
	if r.Method == "GET" {
		s.render(w, "unlock", 200, d)
		return
	}
	pass, valid := passphrase(r)
	if !valid {
		d.Error = "Enter a passphrase of at most 4096 bytes."
		s.render(w, "unlock", 400, d)
		return
	}
	defer crypto.Zero(pass)
	res, err := s.svc.Unlock(pass)
	if err != nil {
		// Authenticated migration can stand despite its final sync or audit error.
		// Refresh only independent settings; a failed passphrase decrypts nothing.
		if s.cfg.OnNotifier != nil {
			s.cfg.OnNotifier()
		}
		status, message := authError(err)
		d.Error = message
		s.render(w, "unlock", status, d)
		return
	}
	d.Candidates = res.Candidates
	s.sessions.setCandidates(x.id, res.Candidates)
	d.Message = "Vault unlocked."
	if len(res.Candidates) > 0 {
		d.Message = "Confirm the saved grants to restore."
	}
	if res.GrantsErr != nil {
		d.Error = "Saved grants are unavailable. No grants were restored."
	}
	if res.NotifierErr != nil {
		d.Error += " Notifier credentials are unavailable."
	}
	if s.cfg.OnUnlock != nil {
		s.cfg.OnUnlock(res)
	} else {
		crypto.Zero(res.NotifierToken)
	}
	s.render(w, "unlock", 200, d)
}

func (s *server) restore(w http.ResponseWriter, r *http.Request, x session) {
	if !method(w, r, "POST") {
		return
	}
	d := pageData{Title: "Unlock", CSRF: x.csrf, Authenticated: true, Section: "unlock", Candidates: x.candidates}
	pass, valid := passphrase(r)
	if !valid {
		d.Error = "Enter a passphrase of at most 4096 bytes."
		s.render(w, "unlock", 400, d)
		return
	}
	defer crypto.Zero(pass)
	// Confirm only IDs shown to this session by its unlock step.
	ids := r.PostForm["grant"]
	for _, id := range ids {
		found := false
		for _, g := range x.candidates {
			if id == g.ID {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "Invalid grant selection", 400)
			return
		}
	}
	if _, err := s.svc.RestoreGrants(pass, ids); err != nil {
		status, message := authError(err)
		d.Error = message
		s.render(w, "unlock", status, d)
		return
	}
	s.sessions.setCandidates(x.id, nil)
	http.Redirect(w, r, "/", 303)
}

// SetupHandler initializes a new vault, then calls onReady once Init succeeds.
// Init provides the atomic existing-vault check; this handler cannot overwrite it.
func SetupHandler(dir string, cfg Config, onReady func()) http.Handler {
	s := newServer(nil, cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.boundary(w, r) {
			return
		}
		if len(r.URL.Path) >= 8 && r.URL.Path[:8] == "/static/" {
			if !method(w, r, "GET", "HEAD") {
				return
			}
			s.static.ServeHTTP(w, r)
			return
		}
		if r.URL.Path != "/" && r.URL.Path != "/setup" {
			http.NotFound(w, r)
			return
		}
		if !method(w, r, "GET", "POST") {
			return
		}
		if _, err := os.Stat(filepath.Join(dir, "header.json")); err == nil {
			http.Error(w, "Vault is already initialized", 409)
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			http.Error(w, "Setup unavailable", 500)
			return
		}
		if r.Method == "GET" {
			x, ok := s.preauth(w, r)
			if ok {
				s.render(w, "setup", 200, pageData{Title: "Setup", CSRF: x.csrf})
			}
			return
		}
		x, ok := s.sessions.get(r, false)
		if !ok {
			http.Error(w, "Invalid form token", 403)
			return
		}
		if !checkCSRF(w, r, x) {
			return
		}
		pass, valid := passphrase(r)
		defer crypto.Zero(pass)
		confirmation := r.PostForm["confirmation"]
		if !valid || len(confirmation) != 1 || confirmation[0] != string(pass) {
			s.render(w, "setup", 400, pageData{Title: "Setup", CSRF: x.csrf, Error: "Enter matching passphrases of at most 4096 bytes."})
			return
		}
		params := crypto.DefaultParams()
		if cfg.InitParams != nil {
			params = *cfg.InitParams
		}
		if err := vault.Init(dir, pass, params); err != nil {
			if errors.Is(err, vault.ErrInitialized) {
				http.Error(w, "Vault is already initialized", 409)
			} else {
				http.Error(w, "Setup could not be completed", 500)
			}
			return
		}
		s.sessions.remove(x.id)
		s.cookie(w, preauthCookie, "", true)
		if onReady != nil {
			onReady()
		}
		http.Redirect(w, r, "/login", 303)
	})
}
