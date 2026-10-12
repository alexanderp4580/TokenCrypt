package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"tokencrypt/internal/api"
	"tokencrypt/internal/core"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

type fakeAPI struct {
	mu      sync.Mutex
	values  map[string][]byte
	status  core.Status
	timeout bool
	socket  string
}

func fakeServer(t *testing.T, values map[string][]byte) *fakeAPI {
	t.Helper()
	f := &fakeAPI{values: values, socket: filepath.Join(t.TempDir(), "sock")}
	l, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(f.handle)}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	var in struct {
		Name, Reason, Kind string
		Duration, Wait     time.Duration
	}
	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			w.WriteHeader(400)
			return
		}
	}
	switch r.URL.Path {
	case "/read":
		value, ok := f.values[in.Name]
		if !ok {
			w.WriteHeader(403)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "no_grant"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": value})
	case "/status":
		_ = json.NewEncoder(w).Encode(map[string]any{"status": f.status})
	case "/request":
		state := core.StatePending
		if in.Wait > 0 && !f.timeout {
			state = core.StateApproved
		}
		req := core.Request{ID: "fake-request", Secret: in.Name, Reason: in.Reason, Duration: in.Duration, State: state}
		out := map[string]any{"request": req}
		if f.timeout {
			w.WriteHeader(408)
			out["error"] = map[string]string{"code": "timeout"}
		}
		_ = json.NewEncoder(w).Encode(out)
	case "/flag":
		f.status.Secrets = []vault.Meta{{Name: in.Name, Flag: &vault.Flag{Kind: in.Kind, Reason: in.Reason, Actor: "agent"}}}
		_ = json.NewEncoder(w).Encode(map[string]any{})
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeAPI) dial() (*api.Client, error) { return api.Dial(f.socket) }
func invoke(t *testing.T, f *fakeAPI, args ...string) (int, []byte, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := Run(args, &out, &err, f.dial)
	return code, out.Bytes(), err.String()
}

func TestGetBytesAndDeniedRead(t *testing.T) {
	for _, v := range [][]byte{[]byte("fake-value"), {}, {'a', '\n', 0, 0xff}, bytes.Repeat([]byte{0xab}, 1<<20)} {
		t.Run(strconv.Itoa(len(v)), func(t *testing.T) {
			f := fakeServer(t, map[string][]byte{"github_token": v})
			code, out, err := invoke(t, f, "get", "github_token")
			if code != 0 || !bytes.Equal(out, v) || err != "" {
				t.Fatalf("get: code=%d bytes=%d stderr=%q", code, len(out), err)
			}
		})
	}
	f := fakeServer(t, nil)
	code, out, err := invoke(t, f, "get", "github_token")
	if code != 1 || len(out) != 0 || !strings.Contains(err, "grant") {
		t.Fatalf("denied: %d %q %q", code, out, err)
	}
}

func TestRunEnvironmentAndChildExit(t *testing.T) {
	t.Setenv("TOKENCRYPT_CLI_HELPER", "1")
	t.Setenv("GITHUB_TOKEN", "fake-inherited-value")
	f := fakeServer(t, map[string][]byte{"github_token": []byte("fake-new-token"), "second_token": []byte("fake-second-value")})
	args := append([]string{"run", "--with", "github_token,second_token", "--"}, helperCommand("environment", "23", "GITHUB_TOKEN", "SECOND_TOKEN")...)
	code, out, err := invoke(t, f, args...)
	var env map[string]string
	if e := json.Unmarshal(out, &env); e != nil {
		t.Fatal(e)
	}
	if code != 23 || env["GITHUB_TOKEN"] != "fake-new-token" || env["SECOND_TOKEN"] != "fake-second-value" || err != "" {
		t.Fatalf("child result: code=%d keys=%d stderr=%q", code, len(env), err)
	}
}

func TestRunReadsAllGrantsBeforeChild(t *testing.T) {
	t.Setenv("TOKENCRYPT_CLI_HELPER", "1")
	marker := filepath.Join(t.TempDir(), "started")
	f := fakeServer(t, map[string][]byte{"github_token": []byte("fake-new-token")})
	args := append([]string{"run", "--with", "github_token,missing", "--"}, helperCommand("marker", marker)...)
	code, out, err := invoke(t, f, args...)
	if code != 1 || len(out) != 0 || !strings.Contains(err, "grant") || strings.Contains(err, "fake-new-token") {
		t.Fatalf("failed run: %d %q %q", code, out, err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("child started before all reads succeeded")
	}
}

func TestRunPreservesSignaledChildStatus(t *testing.T) {
	t.Setenv("TOKENCRYPT_CLI_HELPER", "1")
	f := fakeServer(t, map[string][]byte{"github_token": []byte("fake-token")})
	args := append([]string{"run", "--with", "github_token", "--"}, helperCommand("signal")...)
	code, out, err := invoke(t, f, args...)
	if code != 143 || len(out) != 0 || err != "" {
		t.Fatalf("signal exit: code=%d stdout=%d stderr=%q", code, len(out), err)
	}
}

func TestRunRejectsNULAndEnvironmentLimitBeforeChild(t *testing.T) {
	t.Setenv("TOKENCRYPT_CLI_HELPER", "1")
	// Linux permits 128 KiB including NAME, '=' and the terminating NUL.
	allowed := 128*1024 - len("GITHUB_TOKEN") - 2
	for _, row := range []struct {
		name  string
		value []byte
		want  int
	}{
		{"exact_boundary", bytes.Repeat([]byte{'x'}, allowed), 0},
		{"over_boundary", bytes.Repeat([]byte{'x'}, allowed+1), 1},
		{"maximum_secret", bytes.Repeat([]byte{'x'}, 1<<20), 1},
		{"NUL", []byte("fake\x00value"), 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "started")
			f := fakeServer(t, map[string][]byte{"github_token": row.value})
			args := append([]string{"run", "--with", "github_token", "--"}, helperCommand("marker", marker)...)
			code, out, err := invoke(t, f, args...)
			if code != row.want || len(out) != 0 {
				t.Fatalf("boundary: code=%d want=%d stdout=%d stderr=%q", code, row.want, len(out), err)
			}
			_, markerErr := os.Stat(marker)
			if row.want == 0 {
				if markerErr != nil || err != "" {
					t.Fatalf("allowed child: %v %q", markerErr, err)
				}
			} else {
				if !errors.Is(markerErr, os.ErrNotExist) || !strings.Contains(err, "get") || strings.Contains(err, string(row.value)) {
					t.Fatalf("invalid environment: marker=%v stderr=%q", markerErr, err)
				}
			}
		})
	}
}

func TestStatusEscapesAllUntrustedTextAndHasNoValue(t *testing.T) {
	f := fakeServer(t, map[string][]byte{"api_token": []byte("fake-stored-canary")})
	dirty := "fake\x1b[31m\nFORGED\x00\r"
	f.mu.Lock()
	f.status = core.Status{
		Secrets: []vault.Meta{{Name: "api_token", Description: dirty, Flag: &vault.Flag{Kind: "invalid", Actor: dirty, Reason: dirty}}},
		Grants:  []grants.Grant{{ID: dirty, Secret: "api_token", GrantedBy: dirty, Expires: time.Now().Add(time.Hour)}},
		Pending: []core.Request{{ID: dirty, Secret: "api_token", Reason: dirty, State: core.StatePending}},
	}
	f.mu.Unlock()
	code, out, err := invoke(t, f, "status")
	if code != 0 || err != "" || bytes.ContainsAny(out, "\x1b\x00\r") || bytes.Contains(out, []byte("fake-stored-canary")) {
		t.Fatalf("unsafe status: code=%d stderr=%q", code, err)
	}
	if !bytes.Contains(out, []byte(`fake\x1b[31m\nFORGED\x00\r`)) || !bytes.Contains(out, []byte("api_token")) || !bytes.Contains(out, []byte("invalid")) || !bytes.Contains(out, []byte("pending")) || !bytes.Contains(out, []byte("left=")) {
		t.Fatalf("incomplete status: %q", out)
	}
}

func TestRequestOptionsAfterNameAndWait(t *testing.T) {
	f := fakeServer(t, nil)
	code, out, err := invoke(t, f, "request", "api_token", "--for", "1h", "--reason", "fake reason", "--wait", "1s")
	if code != 0 || err != "" || !bytes.Contains(out, []byte("approved")) || !bytes.Contains(out, []byte("1h0m0s")) || !bytes.Contains(out, []byte("fake reason")) {
		t.Fatalf("request: %d %q %q", code, out, err)
	}
	f.mu.Lock()
	f.timeout = true
	f.mu.Unlock()
	code, out, err = invoke(t, f, "request", "api_token", "--wait", "1ms")
	if code != 1 || !bytes.Contains(out, []byte("fake-request")) || !bytes.Contains(out, []byte("pending")) || !strings.Contains(err, "timed out") {
		t.Fatalf("wait timeout: %d %q %q", code, out, err)
	}
}

func TestFlagOptionsAfterName(t *testing.T) {
	f := fakeServer(t, nil)
	code, _, err := invoke(t, f, "flag", "api_token", "--kind", "invalid", "--reason", "fake rejected token")
	if code != 0 || err != "" {
		t.Fatalf("flag: %d %q", code, err)
	}
	code, out, err := invoke(t, f, "status")
	if code != 0 || err != "" || !bytes.Contains(out, []byte("fake rejected token")) || !bytes.Contains(out, []byte("invalid")) {
		t.Fatalf("flag arguments lost: %d %q %q", code, out, err)
	}
}

func TestUsageErrorsNeverDial(t *testing.T) {
	cases := [][]string{
		{}, {"get"}, {"get", "../bad"}, {"get", "valid", "extra"}, {"status", "extra"},
		{"run", "--with", "valid", "child"}, {"run", "--with", "valid", "--"},
		{"run", "--with", "valid,", "--", "child"}, {"run", "--with", "valid,valid", "--", "child"},
		{"request", "valid", "--for", "invalid"}, {"request", "valid", "--for", "-1s"},
		{"request", "valid", "--wait", "-1s"}, {"request", "bad-name"},
		{"flag", "valid", "--kind", "clear"}, {"flag", "valid"}, {"flag", "bad-name", "--kind", "leaked"},
		{"create"}, {"update"}, {"delete"}, {"grant"}, {"unlock"}, {"clear"}, {"clear_flag"}, {"revoke"}, {"serve"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var out, err bytes.Buffer
			code := Run(args, &out, &err, func() (*api.Client, error) { t.Fatal("usage error dialed API"); return nil, nil })
			if code != 2 || out.Len() != 0 || err.Len() == 0 {
				t.Fatalf("usage: %d %q %q", code, out.String(), err.String())
			}
		})
	}
}

func TestDialFailureRedacted(t *testing.T) {
	var out, err bytes.Buffer
	code := Run([]string{"get", "valid"}, &out, &err, func() (*api.Client, error) { return nil, errors.New("fake-secret-canary") })
	if code != 1 || out.Len() != 0 || err.Len() == 0 || strings.Contains(err.String(), "fake-secret-canary") {
		t.Fatalf("dial failure leaked: %d %q", code, err.String())
	}
}

func TestCommandHelper(t *testing.T) {
	if os.Getenv("TOKENCRYPT_CLI_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(99)
	}
	args = args[1:]
	switch args[0] {
	case "signal":
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		os.Exit(94)
	case "environment":
		code, e := strconv.Atoi(args[1])
		if e != nil {
			os.Exit(98)
		}
		env := map[string]string{}
		for _, name := range args[2:] {
			env[name] = os.Getenv(name)
		}
		if e := json.NewEncoder(os.Stdout).Encode(env); e != nil {
			os.Exit(97)
		}
		os.Exit(code)
	case "marker":
		if e := os.WriteFile(args[1], []byte("started"), 0600); e != nil {
			os.Exit(96)
		}
		os.Exit(0)
	default:
		os.Exit(95)
	}
}

func helperCommand(args ...string) []string {
	return append([]string{os.Args[0], "-test.run=^TestCommandHelper$", "--"}, args...)
}
