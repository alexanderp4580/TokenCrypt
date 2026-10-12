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

func TestNotifierEnvironmentWorksLockedWithoutServiceFile(t *testing.T) {
	pass := []byte("fake-env-pass")
	dir := envVault(t, pass)
	telegram, notices := envTelegram(t)
	t.Setenv("TELEGRAM_BOT_TOKEN", "  fake-env-token\n")
	t.Setenv("TELEGRAM_CHAT_ID", " 9000000010 ")
	opts := runtimeOptions(t, dir, telegram.URL)
	stop, client := startRuntime(t, opts)
	if _, err := client.Request("alpha", "fake env request", time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-notices:
		if got.path != "/botfake-env-token/sendMessage" || got.chat != "9000000010" || strings.Contains(got.text, "fake-env-protected-value") {
			t.Fatal("environment credentials not used", got.path, got.chat)
		}
	case <-time.After(time.Second):
		t.Fatal("environment notifier did not deliver on a locked daemon")
	}
	status, err := client.Status()
	if err != nil || !status.Locked || len(status.Grants) != 0 {
		t.Fatal("environment notifier changed authorization")
	}
	if _, err := os.Stat(filepath.Join(dir, "service", "notifier.json")); !os.IsNotExist(err) {
		t.Fatal("environment credentials were written to disk")
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
	notifierPage := get("/notifier")
	if !strings.Contains(notifierPage, "Environment credentials override saved settings") {
		t.Fatal("notifier page omits the environment override note")
	}
	pages := login + get("/") + notifierPage + get("/login")
	stop()
	audit, err := os.ReadFile(filepath.Join(opts.StateDir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fake-env-token", "9000000010"} {
		if strings.Contains(string(audit), secret) || strings.Contains(pages, secret) {
			t.Fatal("environment credential disclosed")
		}
	}
}

func TestNotifierEnvironmentOverridesServiceFile(t *testing.T) {
	pass := []byte("fake-env-override-pass")
	dir := envVault(t, pass)
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SetServiceNotifier([]byte("fake-file-token"), "-1009000000011"); err != nil {
		t.Fatal(err)
	}
	telegram, notices := envTelegram(t)
	t.Setenv("TELEGRAM_BOT_TOKEN", "fake-env-token")
	t.Setenv("TELEGRAM_CHAT_ID", "9000000010")
	_, client := startRuntime(t, runtimeOptions(t, dir, telegram.URL))
	if _, err := client.Request("alpha", "fake env override request", time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-notices:
		if got.path != "/botfake-env-token/sendMessage" || got.chat != "9000000010" {
			t.Fatal("service file took precedence over environment")
		}
	case <-time.After(time.Second):
		t.Fatal("no notice")
	}
}

func TestNotifierPartialEnvironmentFallsBackWithGenericDiagnostic(t *testing.T) {
	pass := []byte("fake-env-partial-pass")
	for _, env := range []map[string]string{{"TELEGRAM_BOT_TOKEN": "fake-partial-token"}, {"TELEGRAM_CHAT_ID": "9000000016"}} {
		dir := envVault(t, pass)
		v, err := vault.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.SetServiceNotifier([]byte("fake-file-token"), "-1009000000011"); err != nil {
			t.Fatal(err)
		}
		telegram, notices := envTelegram(t)
		t.Setenv("TELEGRAM_BOT_TOKEN", "")
		t.Setenv("TELEGRAM_CHAT_ID", "")
		for k, val := range env {
			t.Setenv(k, val)
		}
		opts := runtimeOptions(t, dir, telegram.URL)
		stop, client := startRuntime(t, opts)
		if _, err := client.Request("alpha", "fake partial env request", time.Minute, 0); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-notices:
			if got.path != "/botfake-file-token/sendMessage" || got.chat != "-1009000000011" {
				t.Fatal("partial environment did not fall back")
			}
		case <-time.After(time.Second):
			t.Fatal("no fallback notice")
		}
		stop()
		raw, err := os.ReadFile(filepath.Join(opts.StateDir, "audit.log"))
		if err != nil || !strings.Contains(string(raw), "notifier.failed") {
			t.Fatal("missing generic diagnostic", err)
		}
		for _, secret := range []string{"fake-partial-token", "9000000016", "TELEGRAM_"} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("diagnostic disclosed environment data")
			}
		}
	}
}
