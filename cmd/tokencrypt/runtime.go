package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"tokencrypt/internal/clock"
	"tokencrypt/internal/core"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/daemon"
	"tokencrypt/internal/notify"
	"tokencrypt/internal/web"
)

// startNotifier reads the env file once and starts Telegram delivery when it
// holds valid credentials. A missing file leaves the notifier off silently; an
// unsafe, partial or invalid file leaves it off with one generic audit event.
// The returned cleanup stops delivery and zeroes the token.
func startNotifier(ctx context.Context, svc *core.Service, opts serveOptions, clk clock.Clock) func() {
	token, chat, err := notify.LoadCredentials(opts.EnvFile)
	if errors.Is(err, notify.ErrNotConfigured) {
		return nil
	}
	if err != nil {
		_ = svc.LogNotifierEvent("notifier.failed", "notifier credentials unusable")
		return nil
	}
	transport := notify.NewTelegram(string(token), nil, opts.TelegramAPIBase)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		notify.Start(runCtx, svc, transport, chat, opts.ApprovalURL, clk)
	}()
	return func() {
		cancel()
		<-done
		crypto.Zero(token)
	}
}

func serve(ctx context.Context, opts serveOptions) error {
	clk := opts.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	opts.Clock = clk
	config := web.Config{AllowedHosts: strings.Split(opts.AllowedHosts, ","), SecureCookies: opts.SecureCookies, Clock: clk}
	opts.OnService = func(ctx context.Context, svc *core.Service) func() {
		return startNotifier(ctx, svc, opts, clk)
	}
	opts.WebFactory = func(svc *core.Service) http.Handler { return web.Handler(svc, config) }
	opts.SetupFactory = func(onReady func()) http.Handler { return web.SetupHandler(opts.VaultDir, config, onReady) }
	return daemon.Run(ctx, opts.Config)
}
