package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	"tokencrypt/internal/vault"
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
	writeEnvFile(t, opts.EnvFile, "TELEGRAM_BOT_TOKEN=fake-startup-bot\nTELEGRAM_CHAT_ID=9000000018\n", 0o600)
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

func runtimeOptions(t *testing.T, dir, telegram string) serveOptions {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return serveOptions{Config: daemon.Config{VaultDir: dir, StateDir: filepath.Join(dir, "state"), SocketPath: filepath.Join(dir, "runtime", "sock"), Listen: addr}, AllowedHosts: addr, ApprovalURL: "http://example.test", TelegramAPIBase: telegram, EnvFile: filepath.Join(t.TempDir(), "telegram.env")}
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
