package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"tokencrypt/internal/audit"
	"tokencrypt/internal/clock"
	"tokencrypt/internal/core"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

const fakePass = "fake-api-passphrase"
const fakeValue = "fake-secret-value-canary"

func service(t *testing.T) (*core.Service, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	if err := vault.Init(dir, []byte(fakePass), crypto.Params{Time: 1, MemoryKiB: 64, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	clk := clock.Real{}
	v, err := vault.OpenWithClock(dir, clk)
	if err != nil {
		t.Fatal(err)
	}
	a, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), clk)
	if err != nil {
		t.Fatal(err)
	}
	s := core.New(v, grants.New(clk, dir, core.NewChecker(v)), a, clk, core.DefaultConfig())
	t.Cleanup(s.Close)
	if err := s.Create("api_token", "test token", []byte(fakeValue), []byte(fakePass), "user"); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func start(t *testing.T, s *core.Service, path string, peer func(*net.UnixConn) (uint32, error)) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, s, path, peer) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("socket server did not stop")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		fi, err := os.Lstat(path)
		if err == nil && fi.Mode()&os.ModeSocket != 0 && fi.Mode().Perm() == 0600 {
			probe, probeErr := net.DialTimeout("unix", path, 20*time.Millisecond)
			if probeErr == nil {
				_ = probe.Close()
				break
			}
		}
		select {
		case err := <-done:
			t.Fatalf("serve before ready: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("socket not ready")
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cancel, done
}

func client(t *testing.T, path string) *Client {
	t.Helper()
	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func rawClient(t *testing.T, path string) *http.Client {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 3 * time.Second}
}

func exchange(t *testing.T, c *http.Client, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://unix"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("response content type = %q", r.Header.Get("Content-Type"))
	}
	return r.StatusCode, string(b)
}

func TestSocketPermissionsReadAndCancellation(t *testing.T) {
	s, _ := service(t)
	path := filepath.Join(t.TempDir(), "runtime", "sock")
	if err := os.Mkdir(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	cancel, _ := start(t, s, path, peerUID)
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0700 {
		t.Fatalf("directory mode: %v", fi.Mode())
	}
	c := client(t, path)
	if _, err := c.Read("api_token"); !errors.Is(err, core.ErrLocked) {
		t.Fatalf("locked read: %v", err)
	}
	if _, err := s.Unlock([]byte(fakePass)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read("api_token"); !errors.Is(err, core.ErrNoGrant) {
		t.Fatalf("ungranted read: %v", err)
	}
	if _, err := s.Grant("api_token", time.Minute, []byte(fakePass), "user", ""); err != nil {
		t.Fatal(err)
	}
	got, err := c.Read("api_token")
	if err != nil || string(got) != fakeValue {
		t.Fatalf("granted read failed: %v", err)
	}
	st, err := c.Status()
	if err != nil || len(st.Secrets) != 1 || len(st.Grants) != 1 {
		t.Fatalf("status: %+v, %v", st, err)
	}
	b, _ := json.Marshal(st)
	if bytes.Contains(b, []byte(fakeValue)) {
		t.Fatal("status leaked value")
	}
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancellation left socket")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestBinaryReads(t *testing.T) {
	for _, value := range [][]byte{{}, {'a', '\n', 0, 0xff}, bytes.Repeat([]byte{0xab}, vault.MaxValueBytes)} {
		t.Run(strconv.Itoa(len(value)), func(t *testing.T) {
			s, _ := service(t)
			if err := s.UpdateValue("api_token", value, []byte(fakePass), "user"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Grant("api_token", time.Minute, []byte(fakePass), "user", ""); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "sock")
			start(t, s, path, peerUID)
			got, err := client(t, path).Read("api_token")
			if err != nil || !bytes.Equal(got, value) {
				t.Fatalf("binary read len=%d: got len=%d, err=%v", len(value), len(got), err)
			}
		})
	}
}

func TestOnlyFourRoutesAndStrictBoundedJSON(t *testing.T) {
	s, _ := service(t)
	path := filepath.Join(t.TempDir(), "sock")
	start(t, s, path, peerUID)
	c := rawClient(t, path)
	for _, route := range []string{"/unknown", "/create", "/update", "/delete", "/grant", "/clear_flag", "/unlock", "/revoke", "/expiry", "/set_expiry", "/read/extra", "/status/"} {
		code, _ := exchange(t, c, "POST", route, `{}`)
		if code != 404 {
			t.Errorf("%s: %d", route, code)
		}
	}
	for _, row := range []struct {
		method, path, body string
		code               int
	}{
		{"GET", "/read", "", 405}, {"POST", "/status", `{}`, 405},
		{"POST", "/request", `{"name":"api_token","actor":"user"}`, 400},
		{"POST", "/request", `{"name":"api_token"} {}`, 400},
		{"POST", "/flag", `{`, 400}, {"POST", "/read", `null`, 400},
		{"POST", "/request", `{"name":"api_token","wait":-1}`, 400},
		{"POST", "/request", `{"name":"api_token","reason":"` + strings.Repeat("x", 9000) + `"}`, 413},
	} {
		code, body := exchange(t, c, row.method, row.path, row.body)
		if code != row.code {
			t.Errorf("%s %s: %d want %d (%s)", row.method, row.path, code, row.code, body)
		}
	}
	if len(s.Status().Pending) != 0 {
		t.Fatal("invalid request created pending item")
	}
}

func TestRequestWaitFlagAndRedactedErrors(t *testing.T) {
	s, dir := service(t)
	path := filepath.Join(t.TempDir(), "sock")
	start(t, s, path, peerUID)
	c := client(t, path)
	r, err := c.Request("api_token", "approve test", time.Minute, 0)
	if err != nil || r.State != core.StatePending || r.Duration != time.Minute {
		t.Fatalf("request: %+v %v", r, err)
	}
	waiting := make(chan core.Request, 1)
	errs := make(chan error, 1)
	go func() {
		r, err := c.Request("api_token", "wait test", time.Minute, time.Second)
		waiting <- r
		errs <- err
	}()
	select {
	case ev := <-s.Events():
		if ev.Kind != core.EventRequestCreated {
			t.Fatal(ev)
		}
	case <-time.After(time.Second):
		t.Fatal("first event missing")
	}
	select {
	case ev := <-s.Events():
		if err := s.Deny(ev.RequestID, "user"); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait request missing")
	}
	if r := <-waiting; r.State != core.StateDenied {
		t.Fatalf("wait result: %+v", r)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	r, err = c.Request("api_token", "short wait", time.Minute, 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || r.ID == "" || r.State != core.StatePending {
		t.Fatalf("timeout lost request: %+v %v", r, err)
	}
	if _, err := s.Grant("api_token", time.Minute, []byte(fakePass), "user", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.Flag("api_token", "invalid", fakeValue); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if len(st.Grants) != 0 || len(st.Pending) != 0 {
		t.Fatal("flag did not revoke/deny")
	}
	if st.Secrets[0].Flag.Actor != "agent" {
		t.Fatal("flag actor was not agent")
	}
	for _, op := range []func() error{func() error { _, e := c.Read("api_token"); return e }, func() error { _, e := c.Request("api_token", "test", time.Minute, 0); return e }} {
		err := op()
		var flagged *core.FlaggedError
		if !errors.As(err, &flagged) || flagged.Secret != "api_token" || flagged.Kind != "invalid" || strings.Contains(err.Error(), fakeValue) {
			t.Fatalf("flagged error: %v", err)
		}
	}
	if err := c.Flag("api_token", "clear", "test"); !errors.Is(err, core.ErrBadFlag) {
		t.Fatalf("bad flag: %v", err)
	}
	if _, err := c.Read("../invalid"); !errors.Is(err, vault.ErrBadName) {
		t.Fatalf("bad name: %v", err)
	}
	// Filesystem error details must not cross the socket.
	if err := os.Remove(filepath.Join(dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "meta.json"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err = c.Read("api_token")
	if err == nil || strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "meta.json") {
		t.Fatalf("filesystem error disclosure: %v", err)
	}
}

func TestPeerUIDCheckedForEachConnection(t *testing.T) {
	s, _ := service(t)
	path := filepath.Join(t.TempDir(), "sock")
	var reject atomic.Bool
	reject.Store(true)
	var calls atomic.Int32
	start(t, s, path, func(c *net.UnixConn) (uint32, error) {
		calls.Add(1)
		uid, err := peerUID(c)
		if reject.Load() {
			uid++
		}
		return uid, err
	})
	for i := 0; i < 2; i++ {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(c, "GET /status HTTP/1.1\r\nHost: unix\r\n\r\n")
		b, err := io.ReadAll(c)
		_ = c.Close()
		if len(b) != 0 {
			t.Fatalf("foreign uid received response: %q", b)
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatal("foreign uid not disconnected")
			}
		}
	}
	reject.Store(false)
	if _, err := client(t, path).Status(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 3 {
		t.Fatalf("peer checks=%d", calls.Load())
	}
}

func TestSafeSocketStartupAndCleanup(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "active", "stale", "directory_symlink"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := service(t)
			dir := filepath.Join(t.TempDir(), "run")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "sock")
			switch kind {
			case "regular":
				if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "directory_symlink":
				real := filepath.Join(t.TempDir(), "real")
				if err := os.Mkdir(real, 0755); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(dir, "link", "sock")
				if err := os.Symlink(real, filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
			case "active", "stale":
				l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				l.SetUnlinkOnClose(false)
				t.Cleanup(func() { _ = l.Close() })
				if kind == "stale" {
					_ = l.Close()
				}
			}
			if kind == "stale" {
				start(t, s, path, peerUID)
				if _, err := client(t, path).Status(); err != nil {
					t.Fatal(err)
				}
				return
			}
			before, err := os.Lstat(path)
			if kind != "directory_symlink" && err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := Serve(ctx, s, path); err == nil {
				t.Fatal("unsafe path accepted")
			}
			if kind != "directory_symlink" {
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(before, after) {
					t.Fatal("startup changed existing path")
				}
			}
		})
	}
}

func TestShutdownPreservesReplacementPath(t *testing.T) {
	s, _ := service(t)
	path := filepath.Join(t.TempDir(), "sock")
	cancel, _ := start(t, s, path, peerUID)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	cancel()
	// Wait for socket cleanup to release the directory lock.
	deadline := time.Now().Add(3 * time.Second)
	for {
		fd, err := os.Open(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		err = unix.Flock(int(fd.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		_ = fd.Close()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket directory lock not released")
		}
		time.Sleep(2 * time.Millisecond)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "preserve" {
		t.Fatal("shutdown removed replacement")
	}
}

func TestSocketDirectoryLockPreventsCompetingStarts(t *testing.T) {
	s, _ := service(t)
	dir := t.TempDir()
	fd, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if err := unix.Flock(int(fd.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sock")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := Serve(ctx, s, path); !errors.Is(err, ErrSocket) {
		t.Fatalf("locked socket directory accepted: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("contending start created socket")
	}
	if err := unix.Flock(int(fd.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	start(t, s, path, peerUID)
	if _, err := client(t, path).Status(); err != nil {
		t.Fatal(err)
	}
}

func TestPeerCredentialFailureFailsClosed(t *testing.T) {
	s, _ := service(t)
	path := filepath.Join(t.TempDir(), "sock")
	start(t, s, path, func(*net.UnixConn) (uint32, error) {
		return uint32(os.Geteuid()), errors.New("fake kernel credential failure")
	})
	if _, err := client(t, path).Status(); err == nil {
		t.Fatal("credential lookup failure allowed access")
	}
}
