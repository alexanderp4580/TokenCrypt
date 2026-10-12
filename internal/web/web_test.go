package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"tokencrypt/internal/audit"
	"tokencrypt/internal/clock"
	"tokencrypt/internal/core"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

var fastParams = crypto.Params{Time: 1, MemoryKiB: 64, Threads: 1}

const fakePass = "fake web passphrase"

func testService(t *testing.T) (*core.Service, *clock.Fake, string) {
	t.Helper()
	dir := t.TempDir()
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := vault.Init(dir, []byte(fakePass), fastParams); err != nil {
		t.Fatal(err)
	}
	v, err := vault.OpenWithClock(dir, clk)
	if err != nil {
		t.Fatal(err)
	}
	g := grants.New(clk, dir, core.NewChecker(v))
	a, err := audit.Open(filepath.Join(dir, "audit.jsonl"), clk)
	if err != nil {
		t.Fatal(err)
	}
	svc := core.New(v, g, a, clk, core.Config{})
	t.Cleanup(svc.Close)
	return svc, clk, dir
}

func request(h http.Handler, method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://crypt.local"+path, strings.NewReader(form.Encode()))
	r.Host = "crypt.local"
	if method == "POST" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func token(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(m) != 2 {
		t.Fatalf("no CSRF form token: %s", w.Body.String())
	}
	return m[1]
}

func formCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cs := w.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("expected one cookie, got %v", cs)
	}
	return cs[0]
}

func login(t *testing.T, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	get := request(h, "GET", "/login", nil)
	w := request(h, "POST", "/login", url.Values{"csrf": {token(t, get)}, "passphrase": {fakePass}}, formCookie(t, get))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login status %d: %s", w.Code, w.Body.String())
	}
	var auth *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.MaxAge >= 0 {
			auth = c
		}
	}
	if auth == nil {
		t.Fatal("login supplied no session cookie")
	}
	return auth, token(t, request(h, "GET", "/", nil, auth))
}

// Missing route protection, idle expiry, session rotation or cookie flags breaks these checks.
func TestLoginSessionLifecycle(t *testing.T) {
	svc, clk, _ := testService(t)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, SecureCookies: true, IdleTimeout: time.Minute, Clock: clk})
	w := request(h, "GET", "/", nil)
	if w.Code != 303 || w.Header().Get("Location") != "/login" {
		t.Fatalf("anonymous root: %d %v", w.Code, w.Header())
	}
	pre := request(h, "GET", "/login", nil)
	pc := formCookie(t, pre)
	w = request(h, "POST", "/login", url.Values{"csrf": {token(t, pre)}, "passphrase": {"fake wrong passphrase"}}, pc)
	if w.Code != 200 || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "fake wrong passphrase") {
		t.Fatalf("wrong login: %d %s", w.Code, w.Body.String())
	}
	auth, csrf := login(t, h)
	if !auth.HttpOnly || !auth.Secure || auth.SameSite != http.SameSiteStrictMode || auth.Path != "/" || auth.Value == pc.Value {
		t.Fatalf("unsafe session cookie: %v", auth)
	}
	clk.AdvanceMono(40 * time.Second)
	if w = request(h, "GET", "/", nil, auth); w.Code != 200 {
		t.Fatalf("live session: %d", w.Code)
	}
	clk.AdvanceMono(40 * time.Second)
	if w = request(h, "GET", "/", nil, auth); w.Code != 200 {
		t.Fatalf("idle refresh missing: %d", w.Code)
	}
	w = request(h, "POST", "/logout", url.Values{"csrf": {csrf}}, auth)
	if w.Code != 303 {
		t.Fatalf("logout: %d", w.Code)
	}
	if w = request(h, "GET", "/", nil, auth); w.Code != 303 {
		t.Fatalf("logged-out session usable: %d", w.Code)
	}
	auth, _ = login(t, h)
	clk.AdvanceMono(time.Minute)
	if w = request(h, "GET", "/", nil, auth); w.Code != 303 {
		t.Fatalf("expired session usable: %d", w.Code)
	}
	auth, _ = login(t, h)
	clk.AdvanceWall(time.Minute)
	if w = request(h, "GET", "/", nil, auth); w.Code != 303 {
		t.Fatalf("wall-expired session usable: %d", w.Code)
	}
}

// A CSRF bypass at login, cross-session logout or Host normalization breaks these checks.
func TestSecurityBoundaries(t *testing.T) {
	svc, clk, _ := testService(t)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	pre := request(h, "GET", "/login", nil)
	pc := formCookie(t, pre)
	for _, f := range []url.Values{{"passphrase": {fakePass}}, {"csrf": {"fake-token"}, "passphrase": {fakePass}}} {
		if w := request(h, "POST", "/login", f, pc); w.Code != 403 {
			t.Fatalf("login CSRF bypass: %d", w.Code)
		}
	}
	a, ac := login(t, h)
	b, bc := login(t, h)
	for _, csrf := range []string{"", bc} {
		if w := request(h, "POST", "/logout", url.Values{"csrf": {csrf}}, a); w.Code != 403 {
			t.Fatalf("logout CSRF bypass: %d", w.Code)
		}
	}
	if w := request(h, "GET", "/", nil, a); w.Code != 200 {
		t.Fatal("rejected logout ended session")
	}
	if w := request(h, "POST", "/logout?csrf="+ac, nil, a); w.Code != 403 {
		t.Fatalf("query CSRF accepted: %d", w.Code)
	}
	for _, host := range []string{"evil.local", "crypt.local.evil", "CRYPT.LOCAL", "crypt.local:443", "crypt.local."} {
		r := httptest.NewRequest("GET", "https://crypt.local/", nil)
		r.Host = host
		r.AddCookie(b)
		r.Header.Set("X-Forwarded-Host", "crypt.local")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("Host %q: %d %v", host, w.Code, w.Header())
		}
	}
	for _, path := range []string{"/", "/login", "/static/style.css", "/missing"} {
		if w := request(h, "GET", path, nil, a); w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("cached %s", path)
		}
	}
	if w := request(Handler(svc, Config{}), "GET", "/login", nil); w.Code != 403 {
		t.Fatalf("empty allowlist open: %d", w.Code)
	}
	if w := request(h, "GET", "/logout", nil, a); w.Code != 405 {
		t.Fatalf("GET logout mutates session: %d", w.Code)
	}
}

func TestLoginUsesDaemonThrottle(t *testing.T) {
	svc, clk, _ := testService(t)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	pre := request(h, "GET", "/login", nil)
	pc := formCookie(t, pre)
	for i := 0; i < 5; i++ {
		w := request(h, "POST", "/login", url.Values{"csrf": {token(t, pre)}, "passphrase": {"fake bad pass"}}, pc)
		if w.Code != 200 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := request(h, "POST", "/login", url.Values{"csrf": {token(t, pre)}, "passphrase": {fakePass}}, pc)
	if w.Code != 429 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("throttle: %d %v", w.Code, w.Header())
	}
}

func TestBoundedForms(t *testing.T) {
	svc, clk, _ := testService(t)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	pre := request(h, "GET", "/login", nil)
	w := request(h, "POST", "/login", url.Values{"csrf": {token(t, pre)}, "passphrase": {strings.Repeat("x", 5<<20)}}, formCookie(t, pre))
	if w.Code != 413 {
		t.Fatalf("oversized body: %d", w.Code)
	}
	if err := svc.Verify([]byte(fakePass)); err != nil {
		t.Fatal("oversized request reached throttle", err)
	}
}

// Setup must validate matching fields and reject repeated initialization without changing the vault.
func TestFirstRunSetup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	ready := 0
	h := SetupHandler(dir, Config{AllowedHosts: []string{"crypt.local"}, SecureCookies: true, InitParams: &fastParams}, func() { ready++ })
	get := request(h, "GET", "/", nil)
	pc := formCookie(t, get)
	csrf := token(t, get)
	if !pc.HttpOnly || !pc.Secure || pc.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe setup cookie %v", pc)
	}
	if w := request(h, "POST", "/setup", url.Values{"passphrase": {fakePass}, "confirmation": {fakePass}}, pc); w.Code != 403 {
		t.Fatalf("setup CSRF bypass: %d", w.Code)
	}
	for _, pair := range [][2]string{{"", ""}, {fakePass, "fake mismatch"}} {
		w := request(h, "POST", "/setup", url.Values{"csrf": {csrf}, "passphrase": {pair[0]}, "confirmation": {pair[1]}}, pc)
		if w.Code != 400 || strings.Contains(w.Body.String(), fakePass) || ready != 0 {
			t.Fatalf("invalid setup: %d %s", w.Code, w.Body.String())
		}
	}
	w := request(h, "POST", "/setup", url.Values{"csrf": {csrf}, "passphrase": {fakePass}, "confirmation": {fakePass}}, pc)
	if w.Code != 303 || ready != 1 {
		t.Fatalf("setup: %d ready=%d: %s", w.Code, ready, w.Body.String())
	}
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.Unlock([]byte(fakePass))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	header, err := os.ReadFile(filepath.Join(dir, "header.json"))
	if err != nil {
		t.Fatal(err)
	}
	get = request(h, "GET", "/setup", nil)
	if get.Code != 409 {
		t.Fatalf("initialized setup page: %d", get.Code)
	}
	w = request(h, "POST", "/setup", url.Values{"csrf": {csrf}, "passphrase": {"fake replacement"}, "confirmation": {"fake replacement"}}, pc)
	if w.Code != 409 || ready != 1 {
		t.Fatalf("reinitialization: %d ready=%d", w.Code, ready)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "header.json"))
	if string(header) != string(after) {
		t.Fatal("setup overwrote vault")
	}
}

func TestUnlockAndConfirmPersistedGrants(t *testing.T) {
	svc, clk, dir := testService(t)
	if err := svc.Create("fake_secret", "Fake description", []byte("fake saved value"), []byte(fakePass), "user"); err != nil {
		t.Fatal(err)
	}
	g, err := svc.Grant("fake_secret", 2*time.Hour, []byte(fakePass), "user", "")
	if err != nil {
		t.Fatal(err)
	}
	svc.Close()
	v, err := vault.OpenWithClock(dir, clk)
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.Open(filepath.Join(dir, "audit.jsonl"), clk)
	if err != nil {
		t.Fatal(err)
	}
	svc = core.New(v, grants.New(clk, dir, core.NewChecker(v)), auditLog, clk, core.Config{})
	t.Cleanup(svc.Close)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	w := request(h, "POST", "/unlock", url.Values{"csrf": {csrf}, "passphrase": {fakePass}}, a)
	if w.Code != 200 || !strings.Contains(w.Body.String(), g.ID) || !strings.Contains(w.Body.String(), "fake_secret") {
		t.Fatalf("candidate missing: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "fake saved value") {
		t.Fatal("candidate rendered value")
	}
	if _, err := svc.Read("fake_secret"); !errors.Is(err, core.ErrLocked) {
		t.Fatalf("restored before confirmation: %v", err)
	}
	other, otherCSRF := login(t, h)
	if w = request(h, "POST", "/restore", url.Values{"csrf": {otherCSRF}, "passphrase": {fakePass}, "grant": {g.ID}}, other); w.Code != 400 {
		t.Fatalf("other session confirmed unseen grant: %d", w.Code)
	}
	if w = request(h, "POST", "/restore", url.Values{"csrf": {csrf}, "passphrase": {fakePass}, "grant": {g.ID}}, a); w.Code != 303 {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	value, err := svc.Read("fake_secret")
	if err != nil || string(value) != "fake saved value" {
		t.Fatalf("grant not restored: %v", err)
	}
	crypto.Zero(value)
}

func TestUnlockRedactsCorruptStorage(t *testing.T) {
	svc, clk, dir := testService(t)
	bad := "fake corrupt grants content"
	if err := os.WriteFile(filepath.Join(dir, "grants.json"), []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	w := request(h, "POST", "/unlock", url.Values{"csrf": {csrf}, "passphrase": {fakePass}}, a)
	if w.Code != 200 || svc.Status().Locked || !strings.Contains(w.Body.String(), "Saved grants are unavailable") {
		t.Fatalf("unlock corrupt storage: %d %s", w.Code, w.Body.String())
	}
	for _, secret := range []string{bad, dir, fakePass} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("response leaked storage or passphrase")
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, "grants.json"))
	if err != nil || string(got) != bad {
		t.Fatal("web changed corrupt grants")
	}
}

func TestSetupSecurityAndExistingVault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	h := SetupHandler(dir, Config{AllowedHosts: []string{"crypt.local"}, InitParams: &fastParams}, nil)
	r := httptest.NewRequest("GET", "http://evil.local/setup", nil)
	r.Header.Set("X-Forwarded-Host", "crypt.local")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("setup host bypass: %d", w.Code)
	}
	get := request(h, "GET", "/setup", nil)
	pc := formCookie(t, get)
	if pc.Secure {
		t.Fatal("HTTP cookie requires HTTPS")
	}
	other := request(h, "GET", "/setup", nil)
	if w = request(h, "POST", "/setup", url.Values{"csrf": {token(t, other)}, "passphrase": {fakePass}, "confirmation": {fakePass}}, pc); w.Code != 403 {
		t.Fatalf("setup cross-browser CSRF bypass: %d", w.Code)
	}
	if w = request(h, "POST", "/setup", url.Values{"csrf": {token(t, get)}, "passphrase": {strings.Repeat("x", 5<<20)}, "confirmation": {fakePass}}, pc); w.Code != 413 {
		t.Fatalf("setup body unbounded: %d", w.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, "header.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected setup initialized vault")
	}
	if err := vault.Init(dir, []byte(fakePass), fastParams); err != nil {
		t.Fatal(err)
	}
	if w = request(h, "POST", "/setup", url.Values{"csrf": {token(t, get)}, "passphrase": {fakePass}, "confirmation": {fakePass}}, pc); w.Code != 409 {
		t.Fatalf("concurrent initializer overwritten: %d", w.Code)
	}
}
