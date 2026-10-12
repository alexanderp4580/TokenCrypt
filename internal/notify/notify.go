// Package notify delivers request and flag metadata without secret values.
package notify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"tokencrypt/internal/clock"
	"tokencrypt/internal/core"
)

// Transport sends plain text to a chat. Implementations must bound each call.
type Transport interface {
	Send(chatID, text string) error
}

// Runner keeps the notification budget and request deduplication state for one
// daemon lifetime. It holds no credentials; each Start receives the transport
// and chat.
type Runner struct {
	mu           sync.Mutex
	clk          clock.Clock
	attempts     []time.Duration
	seenRequests map[string]time.Duration
	pending      []core.Event
}

// NewRunner uses one monotonic clock for all notification runs.
func NewRunner(clk clock.Clock) *Runner {
	return &Runner{clk: clk, attempts: make([]time.Duration, 0, 30), seenRequests: make(map[string]time.Duration)}
}

// Start consumes service events until cancellation or service closure using a
// fresh Runner.
func Start(ctx context.Context, svc *core.Service, t Transport, chatID, approvalBaseURL string, clk clock.Clock) {
	NewRunner(clk).Start(ctx, svc, t, chatID, approvalBaseURL)
}

// Start blocks while consuming events. The daemon cancels and awaits it before
// closing the service. Telegram honors ctx; other transports must bound Send
// themselves. Callers keep event consumption sequential.
func (r *Runner) Start(ctx context.Context, svc *core.Service, t Transport, chatID, approvalBaseURL string) {
	r.run(ctx, svc.Events(), svc.LogNotifierEvent, t, chatID, approvalBaseURL)
}

const (
	// seenRetention exceeds any request lifetime, so a request ID is only
	// forgotten after its request can no longer produce another event.
	seenRetention   = 24 * time.Hour
	maxSeenRequests = 1024
)

// take reserves an attempt before delivery and returns its reservation time.
// Duplicate requests do not reserve or audit another attempt; rate-limited
// requests stay seen and are not retried.
func (r *Runner) take(requestID string) (send, dropped bool, at time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clk.Mono()
	if requestID != "" {
		r.pruneSeen(now)
		if _, seen := r.seenRequests[requestID]; seen {
			return false, false, 0
		}
		r.seenRequests[requestID] = now
	}
	active := r.attempts[:0]
	for _, t := range r.attempts {
		if now-t < time.Hour {
			active = append(active, t)
		}
	}
	r.attempts = active
	if len(r.attempts) >= 30 {
		return false, true, 0
	}
	r.attempts = append(r.attempts, now)
	return true, false, now
}

// pruneSeen drops entries past seenRetention, then the oldest entries until
// room remains for one more. The caller holds r.mu.
func (r *Runner) pruneSeen(now time.Duration) {
	for id, at := range r.seenRequests {
		if now-at >= seenRetention {
			delete(r.seenRequests, id)
		}
	}
	for len(r.seenRequests) >= maxSeenRequests {
		oldest, first := "", true
		var oldestAt time.Duration
		for id, at := range r.seenRequests {
			if first || at < oldestAt {
				oldest, oldestAt, first = id, at, false
			}
		}
		delete(r.seenRequests, oldest)
	}
}

// release returns a reservation whose delivery was cancelled before it
// completed, so the budget and the request's seen mark are not spent.
func (r *Runner) release(requestID string, at time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if requestID != "" {
		delete(r.seenRequests, requestID)
	}
	for i, t := range r.attempts {
		if t == at {
			r.attempts = append(r.attempts[:i], r.attempts[i+1:]...)
			break
		}
	}
}

// deferEvent keeps an undelivered event for the next run.
func (r *Runner) deferEvent(ev core.Event) {
	r.mu.Lock()
	r.pending = append(r.pending, ev)
	r.mu.Unlock()
}

func (r *Runner) takePending() []core.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.pending
	r.pending = nil
	return p
}

func (r *Runner) run(ctx context.Context, events <-chan core.Event, log func(string, string) error, t Transport, chatID, baseURL string) {
	for _, ev := range r.takePending() {
		r.handle(ctx, ev, log, t, chatID, baseURL)
	}
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			r.handle(ctx, ev, log, t, chatID, baseURL)
		}
	}
}

// handle delivers one event. An event that cancellation prevents from being
// delivered is kept for the next run of this Runner.
func (r *Runner) handle(ctx context.Context, ev core.Event, log func(string, string) error, t Transport, chatID, baseURL string) {
	text := ""
	switch ev.Kind {
	case "request.created":
		text = fmt.Sprintf("Access request: %s\nDuration: %s\nReason: %s\nApprove: %s/requests", ev.Secret, ev.Duration, ev.Reason, strings.TrimRight(baseURL, "/"))
	case "flag.set":
		text = fmt.Sprintf("Secret flagged: %s\nKind: %s\nActor: %s\nReason: %s", ev.Secret, ev.FlagKind, ev.Actor, ev.Reason)
	default:
		return
	}
	if ctx.Err() != nil {
		r.deferEvent(ev)
		return
	}
	id := ""
	if ev.Kind == "request.created" {
		id = ev.RequestID
	}
	send, dropped, at := r.take(id)
	if dropped {
		_ = log("notifier.dropped", "hourly notification limit reached")
	}
	if !send {
		return
	}
	var err error
	if sender, ok := t.(interface {
		send(context.Context, string, string) error
	}); ok {
		err = sender.send(ctx, chatID, text)
	} else {
		err = t.Send(chatID, text)
	}
	if err != nil && ctx.Err() != nil {
		r.release(id, at)
		r.deferEvent(ev)
		return
	}
	if err != nil {
		_ = log("notifier.failed", "notification delivery failed")
	}
}
