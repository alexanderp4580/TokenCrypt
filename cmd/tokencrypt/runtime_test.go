package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"tokencrypt/internal/api"
	"tokencrypt/internal/audit"
	"tokencrypt/internal/clock"
	"tokencrypt/internal/core"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/daemon"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/notify"
	"tokencrypt/internal/vault"
	"tokencrypt/internal/web"
)

// A configured restart must deliver metadata without unlocking or granting a token.
func TestConfiguredNotifierStartsLockedAfterRestart(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("fake-startup-pass")
	if err := vault.Init(dir, pass, crypto.Params{Time: 1, MemoryKiB: 64, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	a, err := audit.Open(filepath.Join(dir, "fixture-audit"), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	svc := core.New(v, grants.New(clock.Real{}, dir, core.NewChecker(v)), a, clock.Real{}, core.Config{})
	if err := svc.CreateWithExpiry("alpha", "", []byte("fake-protected-value"), pass, "test", "2027-01-01"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetNotifier([]byte("fake-startup-bot"), "9000000018", pass); err != nil {
		t.Fatal(err)
	}
	svc.Close()
	notices := make(chan string, 4)
	telegram := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		notices <- body.Text
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer telegram.Close()
	opts := runtimeOptions(t, dir, telegram.URL)
	t.Setenv("TOKENCRYPT_SOCKET", opts.SocketPath)
	for i := 0; i < 2; i++ {
		stop, client := startRuntime(t, opts)
		status, err := client.Status()
		if err != nil || !status.Locked || len(status.Grants) != 0 || status.Secrets[0].ExpiresOn != "2027-01-01" {
			t.Fatal("startup changed protected state", err)
		}
		if value, err := client.Read("alpha"); !errors.Is(err, core.ErrLocked) || len(value) != 0 {
			t.Fatal("startup allowed protected read", err)
		}
		var stdout, stderr bytes.Buffer
		if code := run([]string{"request", "alpha", "--for", "1m", "--reason", "fake cold-start request"}, &stdout, &stderr); code != 0 {
			t.Fatal("CLI request failed", code, stderr.String())
		}
		select {
		case text := <-notices:
			if !strings.Contains(text, "Access request: alpha") || strings.Contains(text, "fake-protected-value") {
				t.Fatal("unexpected notice")
			}
		case <-time.After(time.Second):
			t.Fatal("locked cold-start request did not produce a Telegram notice")
		}
		if value, err := client.Read("alpha"); !errors.Is(err, core.ErrLocked) || len(value) != 0 {
			t.Fatal("notification allowed protected read", err)
		}
		if err := client.Flag("alpha", "invalid", "fake flag"); err != nil {
			t.Fatal(err)
		}
		select {
		case text := <-notices:
			if !strings.Contains(text, "Secret flagged: alpha") {
				t.Fatal("missing flag notice")
			}
		case <-time.After(time.Second):
			t.Fatal("locked flag did not produce a notice")
		}
		stop()
		if i == 0 {
			if err := v.ClearFlag("alpha"); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestNotifierSettingsActivateAndRotateWithoutUnlock(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("fake-settings-pass")
	if err := vault.Init(dir, pass, crypto.Params{Time: 1, MemoryKiB: 64, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := v.Unlock(pass)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		if err := sess.Create(name, "", []byte("fake-hidden-settings-value")); err != nil {
			t.Fatal(err)
		}
	}
	sess.Close()
	type notice struct{ path, chat, text string }
	notices := make(chan notice, 4)
	telegram := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Chat string `json:"chat_id"`
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		notices <- notice{r.URL.Path, body.Chat, body.Text}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer telegram.Close()
	opts := runtimeOptions(t, dir, telegram.URL)
	stop, client := startRuntime(t, opts)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, Timeout: 3 * time.Second}
	base := "http://" + opts.Listen
	page := func(path string) string {
		res, err := browser.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(res.Body)
		if err != nil || res.StatusCode != 200 {
			t.Fatal("page failed", err, res.StatusCode)
		}
		return string(raw)
	}
	csrf := func(html string) string {
		match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(html)
		if len(match) != 2 {
			t.Fatal("missing CSRF token")
		}
		return match[1]
	}
	post := func(path string, fields url.Values) *http.Response {
		res, err := browser.PostForm(base+path, fields)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	res := post("/login", url.Values{"csrf": {csrf(page("/login"))}, "passphrase": {string(pass)}})
	_ = res.Body.Close()
	if html := page("/notifier"); !strings.Contains(html, "Notifications are inactive") {
		t.Fatal("missing configuration not explained")
	}
	for i, row := range []struct{ token, chat, name string }{{"fake-settings-one", "-1009000000005", "alpha"}, {"fake-settings-two", "9000000006", "beta"}} {
		fields := url.Values{"csrf": {csrf(page("/notifier"))}, "token": {row.token}, "chat_id": {row.chat}, "passphrase": {string(pass)}}
		if i == 0 {
			fields.Set("passphrase", "fake-wrong-settings-pass")
			res = post("/notifier", fields)
			_ = res.Body.Close()
			if res.StatusCode != 400 {
				t.Fatal("unauthenticated save accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, "service", "notifier.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("wrong passphrase saved credentials")
			}
			fields.Set("passphrase", string(pass))
		}
		res = post("/notifier", fields)
		raw, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != 200 || !strings.Contains(string(raw), "Notifier configured") {
			t.Fatal("settings save failed")
		}
		for _, secret := range []string{row.token, row.chat, string(pass), "fake-hidden-settings-value"} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("settings response contains a credential")
			}
		}
		if _, err := client.Request(row.name, "fake immediate settings request", time.Minute, 0); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-notices:
			if got.path != "/bot"+row.token+"/sendMessage" || got.chat != row.chat || strings.Contains(got.text, "fake-hidden-settings-value") {
				t.Fatal("saved credentials not activated")
			}
		case <-time.After(time.Second):
			t.Fatal("settings required an unlock or restart")
		}
		status, err := client.Status()
		if err != nil || !status.Locked || len(status.Grants) != 0 {
			t.Fatal("settings changed authorization")
		}
		if value, err := client.Read(row.name); !errors.Is(err, core.ErrLocked) || len(value) != 0 {
			t.Fatal("settings allowed protected read")
		}
	}
	stop()
	stop, client = startRuntime(t, opts)
	if _, err := client.Request("alpha", "fake restart with rotated settings", time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-notices:
		if got.path != "/botfake-settings-two/sendMessage" || got.chat != "9000000006" {
			t.Fatal("restart did not use rotated credentials")
		}
	case <-time.After(time.Second):
		t.Fatal("rotated settings unavailable on restart")
	}
	stop()
}

func TestCorruptNotifierStartupReportsGenericDiagnosticWithoutUnlocking(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("fake-corrupt-start-pass")
	if err := vault.Init(dir, pass, crypto.Params{Time: 1, MemoryKiB: 64, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := v.Unlock(pass)
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Create("alpha", "", []byte("fake-corrupt-start-protected")); err != nil {
		t.Fatal(err)
	}
	sess.Close()
	if err := v.SetServiceNotifier([]byte("fake-corrupt-start-token"), "9000000008"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "service", "notifier.json"), []byte("fake-private-malformed-config"), 0600); err != nil {
		t.Fatal(err)
	}
	telegram := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("corrupt notifier attempted delivery")
		w.WriteHeader(500)
	}))
	defer telegram.Close()
	opts := runtimeOptions(t, dir, telegram.URL)
	stop, client := startRuntime(t, opts)
	status, err := client.Status()
	if err != nil || !status.Locked || len(status.Grants) != 0 {
		t.Fatal("corrupt notifier changed startup authorization")
	}
	if _, err := client.Request("alpha", "fake corrupt config request", time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	if value, err := client.Read("alpha"); !errors.Is(err, core.ErrLocked) || len(value) != 0 {
		t.Fatal("corrupt config allowed protected read")
	}
	stop()
	raw, err := os.ReadFile(filepath.Join(opts.StateDir, "audit.log"))
	if err != nil || !strings.Contains(string(raw), "notifier credentials unavailable") {
		t.Fatal("missing generic startup diagnostic", err)
	}
	for _, secret := range []string{"fake-private-malformed-config", "fake-corrupt-start-token", "9000000008", "fake-corrupt-start-protected", string(pass)} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("startup diagnostic disclosed private data")
		}
	}
}

func TestAppliedNotifierSettingsActivateDespiteAuditFailure(t *testing.T) {
	for _, operation := range []string{"save", "migration"} {
		t.Run(operation, func(t *testing.T) {
			dir := t.TempDir()
			pass := []byte("fake-audit-settings-pass")
			if err := vault.Init(dir, pass, crypto.Params{Time: 1, MemoryKiB: 64, Threads: 1}); err != nil {
				t.Fatal(err)
			}
			v, err := vault.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			sess, err := v.Unlock(pass)
			if err != nil {
				t.Fatal(err)
			}
			if err := sess.Create("alpha", "", []byte("fake-audit-protected")); err != nil {
				t.Fatal(err)
			}
			if operation == "migration" {
				if err := sess.SetNotifier([]byte("fake-audit-current"), "-1009000000001"); err != nil {
					t.Fatal(err)
				}
			} else if err := v.SetServiceNotifier([]byte("fake-audit-prior"), "9000000002"); err != nil {
				t.Fatal(err)
			}
			sess.Close()
			a, err := audit.Open(filepath.Join(dir, "audit.log"), clock.Real{})
			if err != nil {
				t.Fatal(err)
			}
			svc := core.New(v, grants.New(clock.Real{}, dir, core.NewChecker(v)), a, clock.Real{}, core.Config{})
			defer svc.Close()
			notices := make(chan string, 2)
			telegram := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				notices <- r.URL.Path
				_, _ = io.WriteString(w, `{"ok":true}`)
			}))
			defer telegram.Close()
			n := &notifierLifecycle{ctx: context.Background(), svc: svc, runner: notify.NewRunner(clock.Real{}), telegram: telegram.URL, base: "http://example.test"}
			defer n.close()
			n.refresh()
			h := web.Handler(svc, web.Config{AllowedHosts: []string{"crypt.local"}, OnNotifier: n.refresh, OnUnlock: func(r core.UnlockResult) { crypto.Zero(r.NotifierToken); n.refresh() }})
			request := func(method, path string, fields url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, "http://crypt.local"+path, strings.NewReader(fields.Encode()))
				if method == "POST" {
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				for _, cookie := range cookies {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			csrf := func(w *httptest.ResponseRecorder) string {
				match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
				if len(match) != 2 {
					t.Fatal("missing CSRF")
				}
				return match[1]
			}
			pre := request("GET", "/login", nil)
			login := request("POST", "/login", url.Values{"csrf": {csrf(pre)}, "passphrase": {string(pass)}}, pre.Result().Cookies()[0])
			if login.Code != 303 {
				t.Fatal("login failed")
			}
			var auth *http.Cookie
			for _, cookie := range login.Result().Cookies() {
				if cookie.MaxAge >= 0 {
					auth = cookie
				}
			}
			if auth == nil {
				t.Fatal("missing session")
			}
			formCSRF := csrf(request("GET", "/notifier", nil, auth))
			_ = a.Close()
			path := "/notifier"
			fields := url.Values{"csrf": {formCSRF}, "passphrase": {string(pass)}, "token": {"fake-audit-current"}, "chat_id": {"-1009000000001"}}
			if operation == "migration" {
				path = "/unlock"
			}
			fields.Set("passphrase", "fake-wrong-audit-settings-pass")
			wrong := request("POST", path, fields, auth)
			if operation == "save" && wrong.Code != 400 || operation == "migration" && wrong.Code != 200 {
				t.Fatal("wrong passphrase failure changed")
			}
			unchanged := svc.Notifier()
			if operation == "save" && string(unchanged.NotifierToken) != "fake-audit-prior" || operation == "migration" && len(unchanged.NotifierToken) != 0 {
				t.Fatal("wrong passphrase changed or migrated settings")
			}
			crypto.Zero(unchanged.NotifierToken)
			fields.Set("passphrase", string(pass))
			w := request("POST", path, fields, auth)
			if w.Code != 500 {
				t.Fatal("audit failure not reported")
			}
			current := svc.Notifier()
			if string(current.NotifierToken) != "fake-audit-current" {
				t.Fatal("settings did not stand after audit failure")
			}
			crypto.Zero(current.NotifierToken)
			if _, err := svc.Request("alpha", "fake audit failure notice", time.Minute); !errors.Is(err, core.ErrAudit) {
				t.Fatal(err)
			}
			select {
			case path := <-notices:
				if path != "/botfake-audit-current/sendMessage" {
					t.Fatal("transport uses stale applied settings")
				}
			case <-time.After(time.Second):
				t.Fatal("applied settings did not activate after audit failure")
			}
			if value, err := svc.Read("alpha"); err == nil || len(value) > 0 || len(svc.Status().Grants) > 0 {
				t.Fatal("failure reconciliation allowed a protected read")
			}
		})
	}
}

func runtimeOptions(t *testing.T, dir, telegram string) serveOptions {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return serveOptions{Config: daemon.Config{VaultDir: dir, StateDir: filepath.Join(dir, "state"), SocketPath: filepath.Join(dir, "runtime", "sock"), Listen: addr}, AllowedHosts: addr, ApprovalURL: "http://example.test", TelegramAPIBase: telegram}
}

func startRuntime(t *testing.T, opts serveOptions) (func(), *api.Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, opts) }()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("daemon shutdown hung")
		}
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			stop()
		}
	})
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if client, err := api.Dial(opts.SocketPath); err == nil {
			if _, err := client.Status(); err == nil {
				return func() { client.Close(); stop(); stopped = true }, client
			}
			client.Close()
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("daemon did not start")
	return nil, nil
}

// replace installs credentials under the lifecycle lock.
func (n *notifierLifecycle) replace(result core.UnlockResult) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.replaceLocked(result)
}

func TestNotifierReplacementCancelsPriorDeliveryAndZeroesCredentials(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("fake-runtime-pass")
	if err := vault.Init(dir, pass, crypto.Params{Time: 1, MemoryKiB: 64, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.Real{}
	a, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), clk)
	if err != nil {
		t.Fatal(err)
	}
	svc := core.New(v, grants.New(clk, dir, core.NewChecker(v)), a, clk, core.Config{})
	defer svc.Close()
	for _, name := range []string{"alpha", "beta"} {
		if err := svc.Create(name, "", []byte("fake-value"), pass, "test"); err != nil {
			t.Fatal(err)
		}
	}
	started := make(chan struct{})
	canceled := make(chan struct{})
	next := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/botfake-old/sendMessage" {
			close(started)
			<-r.Context().Done()
			close(canceled)
			return
		}
		next <- r.URL.Path
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()
	n := &notifierLifecycle{ctx: context.Background(), svc: svc, runner: notify.NewRunner(clk), telegram: server.URL, base: "https://example.test"}
	defer n.close()
	old := []byte("fake-old")
	n.replace(core.UnlockResult{NotifierToken: old, ChatID: "123"})
	if _, err := svc.Request("alpha", "fake request", time.Minute); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("old delivery did not start")
	}
	fresh := []byte("fake-new")
	replaced := make(chan struct{})
	go func() { n.replace(core.UnlockResult{NotifierToken: fresh, ChatID: "456"}); close(replaced) }()
	select {
	case <-replaced:
	case <-time.After(5 * time.Second):
		t.Fatal("replacement did not cancel and await delivery")
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("old HTTP request was not canceled")
	}
	if !bytes.Equal(old, make([]byte, len(old))) {
		t.Fatal("old credential buffer remains")
	}
	if _, err := svc.Request("beta", "fake second request", time.Minute); err != nil {
		t.Fatal(err)
	}
	select {
	case path := <-next:
		if path != "/botfake-new/sendMessage" {
			t.Fatal("replacement token not used")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("new delivery did not start")
	}
	n.close()
	if !bytes.Equal(fresh, make([]byte, len(fresh))) {
		t.Fatal("credential remains after shutdown")
	}
	rejected := []byte("fake-after-close")
	n.replace(core.UnlockResult{NotifierToken: rejected, ChatID: "789"})
	if !bytes.Equal(rejected, make([]byte, len(rejected))) {
		t.Fatal("closed lifecycle retained credentials")
	}
}

func TestRefreshKeepsRunningNotifierWhenServiceFileIsUnreadable(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("fake-runtime-pass")
	if err := vault.Init(dir, pass, crypto.Params{Time: 1, MemoryKiB: 64, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.Real{}
	a, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), clk)
	if err != nil {
		t.Fatal(err)
	}
	svc := core.New(v, grants.New(clk, dir, core.NewChecker(v)), a, clk, core.Config{})
	defer svc.Close()
	if err := svc.SetNotifier([]byte("fake-running-token"), "9000000100", pass); err != nil {
		t.Fatal(err)
	}
	n := &notifierLifecycle{ctx: context.Background(), svc: svc, runner: notify.NewRunner(clk), telegram: "http://127.0.0.1:1", base: "https://example.test"}
	defer n.close()
	n.refresh()
	running := func() bool { n.mu.Lock(); defer n.mu.Unlock(); return n.cancel != nil }
	if !running() {
		t.Fatal("notifier not started")
	}
	file := filepath.Join(dir, "service", "notifier.json")
	if err := os.WriteFile(file, []byte("fake corrupt content"), 0600); err != nil {
		t.Fatal(err)
	}
	n.refresh()
	if !running() {
		t.Fatal("unreadable settings stopped the running notifier")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	n.refresh()
	if running() {
		t.Fatal("notifier still running after settings were removed")
	}
	events, err := svc.AuditTail(20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range events {
		if ev.Type == "notifier.failed" {
			found = true
			for _, secret := range []string{"fake-running-token", "9000000100", dir} {
				if strings.Contains(ev.Detail, secret) {
					t.Fatalf("audit detail leaks %q", secret)
				}
			}
		}
	}
	if !found {
		t.Fatal("transition to no notifier not audited")
	}
}
