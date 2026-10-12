package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"sync"

	"tokencrypt/internal/clock"
	"tokencrypt/internal/core"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/daemon"
	"tokencrypt/internal/notify"
	"tokencrypt/internal/vault"
	"tokencrypt/internal/web"
)

// notifierLifecycle serializes credential replacement with event consumption.
// Its Runner retains the hourly budget for the whole daemon lifetime.
type notifierLifecycle struct {
	mu             sync.Mutex
	ctx            context.Context
	svc            *core.Service
	runner         *notify.Runner
	base, telegram string
	cancel         context.CancelFunc
	done           chan struct{}
	token          []byte
	chat           string
	closed         bool
	// envMode means TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID configure the
	// notifier; envToken holds the not yet started token and envChat its chat.
	envMode  bool
	envToken []byte
	envChat  string
}

// notifierEnv reads and unsets the notifier environment. ok is true when both
// variables are present and valid; partial or invalid configuration returns
// failed. Values are trimmed and never logged.
func notifierEnv() (token []byte, chat string, ok, failed bool) {
	rawToken, rawChat := os.Getenv("TELEGRAM_BOT_TOKEN"), os.Getenv("TELEGRAM_CHAT_ID")
	_ = os.Unsetenv("TELEGRAM_BOT_TOKEN")
	_ = os.Unsetenv("TELEGRAM_CHAT_ID")
	token = bytes.TrimSpace([]byte(rawToken))
	chat = strings.TrimSpace(rawChat)
	if len(token) == 0 && chat == "" {
		return nil, "", false, false
	}
	if !vault.ValidNotifierCredentials(token, chat) {
		crypto.Zero(token)
		return nil, "", false, true
	}
	return token, chat, true, false
}

func (n *notifierLifecycle) stop() {
	if n.cancel != nil {
		n.cancel()
		<-n.done
		n.cancel = nil
		n.done = nil
	}
	crypto.Zero(n.token)
	n.token = nil
	n.chat = ""
}

// refresh reads settings under the replacement lock, so concurrent saves cannot
// activate an older snapshot after a newer credential.
func (n *notifierLifecycle) refresh() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.envMode {
		if n.cancel == nil && n.envToken != nil {
			token := n.envToken
			n.envToken = nil
			n.replaceLocked(core.UnlockResult{NotifierToken: token, ChatID: n.envChat})
		}
		return
	}
	result := n.svc.Notifier()
	if n.cancel != nil && result.NotifierErr != nil {
		// Unreadable settings do not revoke a running notifier.
		crypto.Zero(result.NotifierToken)
		return
	}
	if n.cancel != nil && result.NotifierErr == nil && result.ChatID == n.chat && bytes.Equal(result.NotifierToken, n.token) {
		crypto.Zero(result.NotifierToken)
		return
	}
	n.replaceLocked(result)
}

func (n *notifierLifecycle) replaceLocked(result core.UnlockResult) {
	wasRunning := n.cancel != nil
	n.stop()
	if n.closed || n.ctx.Err() != nil || result.NotifierErr != nil || len(result.NotifierToken) == 0 || result.ChatID == "" {
		crypto.Zero(result.NotifierToken)
		if wasRunning && !n.closed && n.ctx.Err() == nil {
			_ = n.svc.LogNotifierEvent("notifier.failed", "notifier stopped: credentials unavailable")
		}
		return
	}
	n.token = result.NotifierToken
	n.chat = result.ChatID
	transport := notify.NewTelegram(string(n.token), nil, n.telegram)
	ctx, cancel := context.WithCancel(n.ctx)
	n.cancel = cancel
	n.done = make(chan struct{})
	done := n.done
	go func() {
		defer close(done)
		n.runner.Start(ctx, n.svc, transport, result.ChatID, n.base)
	}()
}

func (n *notifierLifecycle) close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	n.stop()
	crypto.Zero(n.envToken)
	n.envToken = nil
}

func serve(ctx context.Context, opts serveOptions) error {
	clk := opts.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	opts.Clock = clk
	config := web.Config{AllowedHosts: strings.Split(opts.AllowedHosts, ","), SecureCookies: opts.SecureCookies, Clock: clk}
	var lifecycle *notifierLifecycle
	envToken, envChat, envOK, envFailed := notifierEnv()
	config.EnvNotifier = envOK
	opts.OnService = func(ctx context.Context, svc *core.Service) func() {
		lifecycle = &notifierLifecycle{ctx: ctx, svc: svc, runner: notify.NewRunner(clk), base: opts.ApprovalURL, telegram: opts.TelegramAPIBase}
		if envOK {
			lifecycle.envMode, lifecycle.envToken, lifecycle.envChat = true, envToken, envChat
			lifecycle.refresh()
			return lifecycle.close
		}
		if envFailed {
			_ = svc.LogNotifierEvent("notifier.failed", "notifier environment unusable")
		}
		result := svc.Notifier()
		if result.NotifierErr != nil {
			_ = svc.LogNotifierEvent("notifier.failed", "notifier credentials unavailable")
		}
		crypto.Zero(result.NotifierToken)
		lifecycle.refresh()
		return lifecycle.close
	}
	opts.WebFactory = func(svc *core.Service) http.Handler {
		config.OnUnlock = func(result core.UnlockResult) {
			crypto.Zero(result.NotifierToken)
			lifecycle.refresh()
		}
		config.OnNotifier = lifecycle.refresh
		return web.Handler(svc, config)
	}
	opts.SetupFactory = func(onReady func()) http.Handler { return web.SetupHandler(opts.VaultDir, config, onReady) }
	return daemon.Run(ctx, opts.Config)
}
