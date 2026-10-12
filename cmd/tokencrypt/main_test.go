package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tokencrypt/internal/vault"
)

func TestSocketOverrideAndRuntimeDefault(t *testing.T) {
	for _, override := range []bool{true, false} {
		t.Run(map[bool]string{true: "override", false: "xdg_runtime"}[override], func(t *testing.T) {
			runtime := t.TempDir()
			socket := filepath.Join(runtime, "sock")
			if !override {
				socket = filepath.Join(runtime, "tokencrypt", "sock")
				if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("XDG_RUNTIME_DIR", runtime)
			t.Setenv("TOKENCRYPT_SOCKET", "")
			if override {
				t.Setenv("TOKENCRYPT_SOCKET", socket)
			}
			l, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/read" {
					t.Errorf("unexpected route %q", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []byte("fake-main-value")})
			})}
			go func() { _ = srv.Serve(l) }()
			defer srv.Close()
			var out, stderr bytes.Buffer
			if code := run([]string{"get", "api_token"}, &out, &stderr); code != 0 || out.String() != "fake-main-value" || stderr.Len() != 0 {
				t.Fatalf("dispatcher: %d %q %q", code, out.String(), stderr.String())
			}
		})
	}
}

func TestInitReadsPipedPassphraseTwice(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	var out, stderr bytes.Buffer
	code := runWithInput(context.Background(), []string{"init", "--vault-dir", dir}, strings.NewReader("fake-init-pass\nfake-init-pass\n"), &out, &stderr)
	if code != 0 {
		t.Fatalf("init: code=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(out.String()+stderr.String(), "fake-init-pass") {
		t.Fatal("passphrase appeared in output")
	}
	if _, err := vault.Open(dir); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		args  []string
		input string
		want  int
	}{
		{[]string{"init", "--vault-dir", filepath.Join(t.TempDir(), "mismatch")}, "fake-one\nfake-two\n", 1},
		{[]string{"init", "--vault-dir", dir, "fake-argument-pass"}, "", 2},
		{[]string{"init", "--vault-dir", dir}, "fake-init-pass\nfake-init-pass\n", 1},
	} {
		out.Reset()
		stderr.Reset()
		if got := runWithInput(context.Background(), row.args, strings.NewReader(row.input), &out, &stderr); got != row.want {
			t.Fatalf("init refusal: code=%d want=%d", got, row.want)
		}
	}
}
