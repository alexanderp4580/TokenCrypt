package main

import (
	"encoding/json"
	"io"
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

	"tokencrypt/internal/crypto"
	"tokencrypt/internal/vault"
)

type envNotice struct{ path, chat, text string }

func envTelegram(t *testing.T) (*httptest.Server, chan envNotice) {
	t.Helper()
	notices := make(chan envNotice, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Chat string `json:"chat_id"`
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		notices <- envNotice{r.URL.Path, body.Chat, body.Text}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv, notices
}

func envVault(t *testing.T, pass []byte) string {
	t.Helper()
	dir := t.TempDir()
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
	if err := sess.Create("alpha", "", []byte("fake-env-protected-value")); err != nil {
		t.Fatal(err)
	}
	sess.Close()
	return dir
}

func writeEnvFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func auditLog(t *testing.T, opts serveOptions) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(opts.StateDir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestNotifierEnvFileWorksLockedAndHidesToken(t *testing.T) {
	pass := []byte("fake-env-pass")
	dir := envVault(t, pass)
	telegram, notices := envTelegram(t)
	opts := runtimeOptions(t, dir, telegram.URL)
	writeEnvFile(t, opts.EnvFile, "# fake credentials\r\nTELEGRAM_BOT_TOKEN = \"fake-env-token\"\r\nTELEGRAM_CHAT_ID=9000000010\r\nOTHER=ignored\r\n", 0o600)
	stop, client := startRuntime(t, opts)
	if _, err := client.Request("alpha", "fake env request", time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-notices:
		if got.path != "/botfake-env-token/sendMessage" || got.chat != "9000000010" || strings.Contains(got.text, "fake-env-protected-value") {
			t.Fatal("env file credentials not used", got.path, got.chat)
		}
	case <-time.After(time.Second):
		t.Fatal("notifier did not deliver on a locked daemon")
	}
	status, err := client.Status()
	if err != nil || !status.Locked || len(status.Grants) != 0 {
		t.Fatal("notifier changed authorization")
	}

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 3 * time.Second}
	base := "http://" + opts.Listen
	get := func(path string) string {
		res, err := browser.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return string(raw)
	}
	login := get("/login")
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(login)
	if len(match) != 2 {
		t.Fatal("missing CSRF token")
	}
	res, err := browser.PostForm(base+"/login", url.Values{"csrf": {match[1]}, "passphrase": {string(pass)}})
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	pages := login + get("/") + get("/unlock") + get("/audit")
	stop()
	for _, secret := range []string{"fake-env-token", "9000000010"} {
		if strings.Contains(auditLog(t, opts), secret) || strings.Contains(pages, secret) {
			t.Fatal("credential disclosed")
		}
	}
}

func TestNotifierMissingEnvFileIsOffWithoutAuditEvent(t *testing.T) {
	dir := envVault(t, []byte("fake-env-missing-pass"))
	telegram, notices := envTelegram(t)
	opts := runtimeOptions(t, dir, telegram.URL)
	stop, client := startRuntime(t, opts)
	if _, err := client.Request("alpha", "fake missing file request", time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-notices:
		t.Fatal("notifier delivered without credentials")
	case <-time.After(200 * time.Millisecond):
	}
	stop()
	if strings.Contains(auditLog(t, opts), "notifier.") {
		t.Fatal("missing file wrote a notifier audit event")
	}
}

func TestNotifierUnusableEnvFileIsOffWithOneGenericAuditEvent(t *testing.T) {
	good := "TELEGRAM_BOT_TOKEN=fake-bad-token\nTELEGRAM_CHAT_ID=9000000016\n"
	cases := map[string]struct {
		content string
		mode    os.FileMode
		link    bool
	}{
		"token only":   {"TELEGRAM_BOT_TOKEN=fake-bad-token\n", 0o600, false},
		"chat only":    {"TELEGRAM_CHAT_ID=9000000016\n", 0o600, false},
		"invalid chat": {"TELEGRAM_BOT_TOKEN=fake-bad-token\nTELEGRAM_CHAT_ID=@fake-bad-chat\n", 0o600, false},
		"mode 0640":    {good, 0o640, false},
		"mode 0644":    {good, 0o644, false},
		"symlink":      {good, 0o600, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := envVault(t, []byte("fake-env-bad-pass"))
			telegram, notices := envTelegram(t)
			opts := runtimeOptions(t, dir, telegram.URL)
			if c.link {
				target := filepath.Join(t.TempDir(), "target.env")
				writeEnvFile(t, target, c.content, c.mode)
				if err := os.Symlink(target, opts.EnvFile); err != nil {
					t.Fatal(err)
				}
			} else {
				writeEnvFile(t, opts.EnvFile, c.content, c.mode)
			}
			stop, client := startRuntime(t, opts)
			if _, err := client.Request("alpha", "fake unusable file request", time.Minute, 0); err != nil {
				t.Fatal(err)
			}
			select {
			case <-notices:
				t.Fatal("unusable credentials delivered a notice")
			case <-time.After(200 * time.Millisecond):
			}
			stop()
			raw := auditLog(t, opts)
			if n := strings.Count(raw, "notifier.failed"); n != 1 {
				t.Fatalf("notifier.failed events = %d, want 1", n)
			}
			for _, secret := range []string{"fake-bad-token", "9000000016", "fake-bad-chat", "TELEGRAM_", "telegram.env", opts.EnvFile} {
				if strings.Contains(raw, secret) {
					t.Fatal("audit event disclosed", secret)
				}
			}
		})
	}
}

func TestNotifierIgnoresProcessEnvironment(t *testing.T) {
	dir := envVault(t, []byte("fake-env-process-pass"))
	telegram, notices := envTelegram(t)
	t.Setenv("TELEGRAM_BOT_TOKEN", "fake-process-token")
	t.Setenv("TELEGRAM_CHAT_ID", "9000000012")
	opts := runtimeOptions(t, dir, telegram.URL)
	stop, client := startRuntime(t, opts)
	if _, err := client.Request("alpha", "fake process env request", time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-notices:
		t.Fatal("process environment configured the notifier")
	case <-time.After(200 * time.Millisecond):
	}
	stop()
	if strings.Contains(auditLog(t, opts), "notifier.") {
		t.Fatal("process environment wrote a notifier audit event")
	}
}

func TestStrayNotifierFilesInVaultAreIgnored(t *testing.T) {
	dir := envVault(t, []byte("fake-env-stray-pass"))
	if err := os.WriteFile(filepath.Join(dir, "notifier.json"), []byte("fake-stray-sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "service"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "service", "notifier.json"), []byte(`{"version":1,"chat_id":"1","token":"ZmFrZQ=="}`), 0o600); err != nil {
		t.Fatal(err)
	}
	telegram, notices := envTelegram(t)
	opts := runtimeOptions(t, dir, telegram.URL)
	stop, client := startRuntime(t, opts)
	if _, err := client.Request("alpha", "fake stray file request", time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-notices:
		t.Fatal("stray file configured the notifier")
	case <-time.After(200 * time.Millisecond):
	}
	stop()
	if strings.Contains(auditLog(t, opts), "notifier.") {
		t.Fatal("stray files wrote a notifier audit event")
	}
}
