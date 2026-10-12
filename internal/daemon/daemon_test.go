package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"tokencrypt/internal/api"
	"tokencrypt/internal/audit"
	"tokencrypt/internal/clock"
	"tokencrypt/internal/core"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

func config(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{VaultDir: filepath.Join(dir, "vault"), StateDir: filepath.Join(dir, "state"), SocketPath: filepath.Join(dir, "runtime", "sock"), Listen: "127.0.0.1:0"}
	if err := vault.Init(cfg.VaultDir, []byte("fake-pass"), crypto.Params{Time: 1, MemoryKiB: 64, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func start(t *testing.T, cfg Config) (context.CancelFunc, <-chan error, *api.Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()
	t.Cleanup(cancel)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if client, err := api.Dial(cfg.SocketPath); err == nil {
			if _, err := client.Status(); err == nil {
				t.Cleanup(client.Close)
				return cancel, done, client
			}
			client.Close()
		}
		select {
		case err := <-done:
			t.Fatalf("startup: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	t.Fatal("daemon did not start")
	return nil, nil, nil
}

func stopped(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hung")
	}
}

func TestSingleDaemonLockAndCancellation(t *testing.T) {
	cfg := config(t)
	cancel, done, _ := start(t, cfg)
	if err := Run(context.Background(), cfg); !errors.Is(err, ErrLocked) {
		t.Fatalf("second daemon: %v", err)
	}
	fi, err := os.Stat(filepath.Join(cfg.VaultDir, "lock"))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("lock mode: %v %v", fi, err)
	}
	cancel()
	stopped(t, done)
	if _, err := os.Stat(cfg.SocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remained: %v", err)
	}
	cancel, done, _ = start(t, cfg)
	cancel()
	stopped(t, done)
}

func TestWebFactorySharesCoreAndShutsDown(t *testing.T) {
	cfg := config(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = l.Addr().String()
	_ = l.Close()
	cfg.Web = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("Web used despite factory"); w.WriteHeader(500) })
	var svc *core.Service
	cfg.WebFactory = func(s *core.Service) http.Handler {
		svc = s
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := s.Flag("api_token", "invalid", "fake web reason", "user"); err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			_, _ = w.Write([]byte("fake-web"))
		})
	}
	v, err := vault.Open(cfg.VaultDir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.Unlock([]byte("fake-pass"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("api_token", "", []byte("fake-value")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	cancel, done, client := start(t, cfg)
	hc := &http.Client{Timeout: time.Second}
	r, err := hc.Get("http://" + cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("web status: %d", r.StatusCode)
	}
	st, err := client.Status()
	if err != nil || len(st.Secrets) != 1 || st.Secrets[0].Flag == nil || st.Secrets[0].Flag.Reason != "fake web reason" {
		t.Fatalf("shared core: %v %+v", err, st)
	}
	cancel()
	stopped(t, done)
	if _, err := hc.Get("http://" + cfg.Listen); err == nil {
		t.Fatal("HTTP listener survived shutdown")
	}
	if _, err := svc.Read("api_token"); !errors.Is(err, core.ErrClosed) {
		t.Fatalf("service remained open: %v", err)
	}
}

func TestRestartKeepsSavedGrantLocked(t *testing.T) {
	cfg := config(t)
	v, err := vault.Open(cfg.VaultDir)
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.Real{}
	a, err := audit.Open(filepath.Join(cfg.StateDir, "audit.log"), clk)
	if err != nil {
		t.Fatal(err)
	}
	g := grants.New(clk, cfg.VaultDir, core.NewChecker(v))
	s := core.New(v, g, a, clk, core.Config{})
	if err := s.Create("api_token", "", []byte("fake-value"), []byte("fake-pass"), "user"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Grant("api_token", 2*time.Hour, []byte("fake-pass"), "user", ""); err != nil {
		t.Fatal(err)
	}
	s.Close()
	cancel, done, client := start(t, cfg)
	if _, err := client.Read("api_token"); !errors.Is(err, core.ErrLocked) {
		t.Fatalf("saved grant accessible: %v", err)
	}
	cancel()
	stopped(t, done)
}

func TestBindFailureReleasesLockAndLeavesNoSocket(t *testing.T) {
	cfg := config(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = l.Addr().String()
	cfg.Web = http.NotFoundHandler()
	if err := Run(context.Background(), cfg); err == nil {
		t.Fatal("occupied listener accepted")
	}
	if _, err := os.Stat(cfg.SocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket after failed startup: %v", err)
	}
	_ = l.Close()
	cancel, done, _ := start(t, cfg)
	cancel()
	stopped(t, done)
}

func TestRejectsPublicListenAndUninitializedVault(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8765", "[::]:8765", "192.0.2.1:8765", "invalid"} {
		cfg := config(t)
		cfg.Listen = listen
		cfg.Web = http.NotFoundHandler()
		if err := Run(context.Background(), cfg); err == nil {
			t.Fatalf("unsafe listen accepted: %s", listen)
		}
	}
	cfg := config(t)
	if err := os.Remove(filepath.Join(cfg.VaultDir, "header.json")); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), cfg); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("uninitialized: %v", err)
	}
}

func TestAPIStartupFailureClosesHTTPAndCore(t *testing.T) {
	cfg := config(t)
	if err := os.MkdirAll(filepath.Dir(cfg.SocketPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SocketPath, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = l.Addr().String()
	_ = l.Close()
	var svc *core.Service
	cfg.WebFactory = func(s *core.Service) http.Handler { svc = s; return http.NotFoundHandler() }
	if err := Run(context.Background(), cfg); err == nil {
		t.Fatal("unsafe socket accepted")
	}
	l, err = net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatalf("HTTP leaked: %v", err)
	}
	_ = l.Close()
	if _, err := svc.Read("api_token"); !errors.Is(err, core.ErrClosed) {
		t.Fatalf("core leaked: %v", err)
	}
	if b, err := os.ReadFile(cfg.SocketPath); err != nil || string(b) != "occupied" {
		t.Fatal("existing socket-path file changed")
	}
}

func TestHardenSubprocess(t *testing.T) {
	if os.Getenv("TOKENCRYPT_HARDEN_HELPER") == "1" {
		report, err := Harden()
		if err != nil {
			t.Fatal(err)
		}
		dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || dumpable != 0 || report.Dumpable != 0 {
			t.Fatalf("dumpable: %d %+v %v", dumpable, report, err)
		}
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			t.Fatal(err)
		}
		if report.MemlockSoft != limit.Cur || report.MemlockHard != limit.Max {
			t.Fatal("wrong memlock limits")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHardenSubprocess$", "-test.v")
	cmd.Env = append(os.Environ(), "TOKENCRYPT_HARDEN_HELPER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("harden subprocess: %v %s", err, out)
	}
}
