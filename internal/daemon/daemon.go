// Package daemon owns the service, private socket and optional loopback website.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"tokencrypt/internal/api"
	"tokencrypt/internal/audit"
	"tokencrypt/internal/clock"
	"tokencrypt/internal/core"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

var (
	ErrLocked        = errors.New("daemon: another daemon holds the vault lock")
	ErrUninitialized = errors.New("daemon: vault is uninitialized")
)

// Config selects storage and listeners. WebFactory takes precedence over Web
// and receives the same service used by the agent API. Run does not harden the
// process; production entry points must call Harden before handling credentials.
type Config struct {
	VaultDir, StateDir, SocketPath, Listen string
	Web                                    http.Handler
	WebFactory                             func(*core.Service) http.Handler
	// SetupFactory supplies first-run setup while Run holds the vault lock.
	SetupFactory func(onReady func()) http.Handler
	// OnService starts owned background work and returns cleanup. Run cancels
	// its context and awaits cleanup before closing the service.
	OnService func(context.Context, *core.Service) func()
	Clock     clock.Clock
}

// Run owns all service resources until cancellation or a listener failure.
// The vault lock remains held until both servers and the service have closed.
func Run(ctx context.Context, cfg Config) error {
	if ctx.Err() != nil {
		return nil
	}
	if cfg.VaultDir == "" || cfg.StateDir == "" || cfg.SocketPath == "" {
		return errors.New("daemon: vault, state and socket paths are required")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.Real{}
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8765"
	}
	lock, err := acquireLock(cfg.VaultDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	v, err := vault.OpenWithClock(cfg.VaultDir, cfg.Clock)
	if errors.Is(err, os.ErrNotExist) {
		if cfg.SetupFactory == nil {
			return ErrUninitialized
		}
		if err := setup(ctx, cfg); err != nil || ctx.Err() != nil {
			return err
		}
		v, err = vault.OpenWithClock(cfg.VaultDir, cfg.Clock)
	}
	if err != nil {
		return fmt.Errorf("daemon: open vault: %w", err)
	}
	a, err := audit.Open(filepath.Join(cfg.StateDir, "audit.log"), cfg.Clock)
	if err != nil {
		return fmt.Errorf("daemon: open audit log: %w", err)
	}
	g := grants.New(cfg.Clock, cfg.VaultDir, core.NewChecker(v))
	svc := core.New(v, g, a, cfg.Clock, core.Config{})
	defer svc.Close()
	childCtx, cancel := context.WithCancel(ctx)
	if cfg.OnService != nil {
		if cleanup := cfg.OnService(childCtx, svc); cleanup != nil {
			defer cleanup()
		}
	}
	defer cancel()
	web := cfg.Web
	if cfg.WebFactory != nil {
		web = cfg.WebFactory(svc)
	}
	var server *http.Server
	var listener net.Listener
	if web != nil {
		host, _, err := net.SplitHostPort(cfg.Listen)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("daemon: website listener must use a loopback IP address")
		}
		listener, err = net.Listen("tcp", cfg.Listen)
		if err != nil {
			return fmt.Errorf("daemon: bind website: %w", err)
		}
		defer listener.Close()
		server = &http.Server{Handler: web, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return childCtx }, ErrorLog: log.New(io.Discard, "", 0)}
		defer server.Close()
	}
	results := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() { defer workers.Done(); results <- api.Serve(childCtx, svc, cfg.SocketPath) }()
	if server != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			err := server.Serve(listener)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			results <- err
		}()
	}
	var result error
	select {
	case <-ctx.Done():
	case result = <-results:
	}
	cancel()
	if server != nil {
		_ = server.Close()
	}
	workers.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return result
}

// setup retains the same vault lock through the transition to normal service.
// Shutdown lets the successful POST finish before Run rebinds the listener.
func setup(ctx context.Context, cfg Config) error {
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("daemon: website listener must use a loopback IP address")
	}
	l, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("daemon: bind setup: %w", err)
	}
	defer l.Close()
	ready := make(chan struct{})
	var once sync.Once
	server := &http.Server{Handler: cfg.SetupFactory(func() { once.Do(func() { close(ready) }) }), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }, ErrorLog: log.New(io.Discard, "", 0)}
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- server.Serve(l) }()
	select {
	case <-ctx.Done():
		_ = server.Close()
	case <-ready:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = server.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			_ = server.Close()
		}
	case err = <-done:
		return err
	}
	serveErr := <-done
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	if err != nil {
		return err
	}
	return serveErr
}

func acquireLock(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("daemon: unsafe vault directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(dir, "lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("daemon: open vault lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), filepath.Join(dir, "lock"))
	fi, err = f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("daemon: unsafe vault lock")
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("daemon: acquire vault lock: %w", err)
	}
	return f, nil
}
