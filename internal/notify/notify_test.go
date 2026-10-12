package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tokencrypt/internal/audit"
	"tokencrypt/internal/clock"
	"tokencrypt/internal/core"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

const fakePass = "fake-passphrase"
const fakeValue = "FAKE-SECRET-VALUE-CANARY"
const fakeToken = "fake-bot-token"
const fakeChat = "987654321"

type sent struct{ chat, text string }
type fakeTransport struct {
	messages chan sent
	err      error
}

func (f *fakeTransport) Send(chat, text string) error { f.messages <- sent{chat, text}; return f.err }

type fixture struct {
	svc *core.Service
	clk *clock.Fake
}

func setup(t *testing.T) fixture {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC))
	dir := filepath.Join(t.TempDir(), "vault")
	if err := vault.Init(dir, []byte(fakePass), crypto.Params{Time: 1, MemoryKiB: 64, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	v, err := vault.OpenWithClock(dir, clk)
	if err != nil {
		t.Fatal(err)
	}
	a, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), clk)
	if err != nil {
		t.Fatal(err)
	}
	svc := core.New(v, grants.New(clk, dir, core.NewChecker(v)), a, clk, core.DefaultConfig())
	t.Cleanup(func() { svc.Close() })
	if err := svc.Create("api_token", "test", []byte(fakeValue), []byte(fakePass), "user"); err != nil {
		t.Fatal(err)
	}
	return fixture{svc, clk}
}
func launch(t *testing.T, f fixture, tr Transport) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); Start(ctx, f.svc, tr, fakeChat, "https://crypt.local/", f.clk) }()
	t.Cleanup(func() { cancel(); waitDone(t, done) })
	return cancel, done
}
func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("notifier did not stop")
	}
}
func receive(t *testing.T, tr *fakeTransport) sent {
	t.Helper()
	select {
	case m := <-tr.messages:
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("message not sent")
		return sent{}
	}
}
func auditType(t *testing.T, svc *core.Service, typ string) audit.Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		evs, err := svc.AuditTail(100)
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range evs {
			if ev.Type == typ {
				return ev
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("audit %s missing", typ)
	return audit.Event{}
}

func TestRequestAndFlagMessagesContainOnlyMetadata(t *testing.T) {
	f := setup(t)
	if _, err := f.svc.Unlock([]byte(fakePass)); err != nil {
		t.Fatal(err)
	}
	tr := &fakeTransport{messages: make(chan sent, 4)}
	launch(t, f, tr)
	req, err := f.svc.Request("api_token", "need <tag> *raw*\nline", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	m := receive(t, tr)
	for _, part := range []string{"api_token", "15m0s", "need <tag> *raw* line", "https://crypt.local/requests"} {
		if !strings.Contains(m.text, part) {
			t.Errorf("message %q missing %q", m.text, part)
		}
	}
	if m.chat != fakeChat || strings.Contains(m.text, fakeValue) || strings.Contains(m.text, fakePass) || strings.Contains(m.text, fakeToken) {
		t.Errorf("unsafe message %+v", m)
	}
	if err := f.svc.Flag("api_token", "leaked", "found <raw>", "agent"); err != nil {
		t.Fatal(err)
	}
	m = receive(t, tr)
	for _, part := range []string{"api_token", "leaked", "found <raw>", "agent"} {
		if !strings.Contains(m.text, part) {
			t.Errorf("flag missing %q: %q", part, m.text)
		}
	}
	if req.ID == "" {
		t.Fatal("request missing id")
	}
}
func TestThirtyFirstAttemptDroppedAndAuditSafe(t *testing.T) {
	f := setup(t)
	tr := &fakeTransport{messages: make(chan sent, 40), err: errors.New("unsafe " + fakeToken + " " + fakeChat + " " + fakeValue)}
	launch(t, f, tr)
	for i := 0; i < 31; i++ {
		if err := f.svc.Flag("api_token", "invalid", "test", "agent"); err != nil {
			t.Fatal(err)
		}
	}
	ev := auditType(t, f.svc, "notifier.dropped")
	auditType(t, f.svc, "notifier.failed")
	if len(tr.messages) != 30 {
		t.Fatalf("sent %d, want 30", len(tr.messages))
	}
	evs, err := f.svc.AuditTail(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range evs {
		if strings.HasPrefix(ev.Type, "notifier.") {
			for _, secret := range []string{fakeToken, fakeChat, fakeValue} {
				if strings.Contains(ev.Detail, secret) {
					t.Fatalf("unsafe audit %+v", ev)
				}
			}
		}
	}
	if ev.Detail == "" {
		t.Fatal("drop audit has no reason")
	}
	f.clk.AdvanceWall(24 * time.Hour)
	if err := f.svc.Flag("api_token", "invalid", "wall jump", "agent"); err != nil {
		t.Fatal(err)
	}
	deadlineDrop := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadlineDrop) {
		evs, _ := f.svc.AuditTail(100)
		n := 0
		for _, ev := range evs {
			if ev.Type == "notifier.dropped" {
				n++
			}
		}
		if n == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	// Mono time, rather than a wall-clock jump, frees the hourly budget.
	f.clk.AdvanceMono(time.Hour)
	if err := f.svc.Flag("api_token", "invalid", "new hour", "agent"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(tr.messages) != 31 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(tr.messages) != 31 {
		t.Fatalf("new hour sent %d, want 31", len(tr.messages))
	}
}
func TestCancellationAndServiceCloseStopLoop(t *testing.T) {
	for _, closeService := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "close"}[closeService], func(t *testing.T) {
			f := setup(t)
			tr := &fakeTransport{messages: make(chan sent, 2)}
			cancel, done := launch(t, f, tr)
			if closeService {
				f.svc.Close()
			} else {
				cancel()
			}
			waitDone(t, done)
			if !closeService {
				if err := f.svc.Flag("api_token", "invalid", "after cancel", "agent"); err != nil {
					t.Fatal(err)
				}
			}
			if len(tr.messages) != 0 {
				t.Fatal("sent after stop")
			}
		})
	}
}
func TestCanceledStartDoesNotSendBufferedEvents(t *testing.T) {
	f := setup(t)
	if _, err := f.svc.Request("api_token", "test", time.Minute); err != nil {
		t.Fatal(err)
	}
	tr := &fakeTransport{messages: make(chan sent, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Start(ctx, f.svc, tr, fakeChat, "https://crypt.local", f.clk)
	if len(tr.messages) != 0 {
		t.Fatal("sent buffered event with canceled context")
	}
}

func TestTelegramPlainJSONAndSafeErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{"success", 200, `{"ok":true,"result":{"message_id":1}}`, false},
		{"api failure", 200, `{"ok":false,"description":"` + fakeToken + " " + fakeChat + `"}`, true},
		{"http failure", 401, `{"ok":true}`, true},
		{"bad json", 200, "broken " + fakeToken, true},
		{"missing ok", 200, `{}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/bot"+fakeToken+"/sendMessage" {
					t.Errorf("request %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Error("wrong content type")
				}
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				if len(payload) != 2 || payload["chat_id"] != fakeChat || payload["text"] != "<raw> *text*\nnext" {
					t.Errorf("payload %+v", payload)
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			err := NewTelegram(fakeToken, server.Client(), server.URL).Send(fakeChat, "<raw> *text*\nnext")
			if (err != nil) != tc.wantErr {
				t.Fatalf("Send err=%v", err)
			}
			if err != nil {
				for _, secret := range []string{fakeToken, fakeChat, server.URL} {
					if strings.Contains(err.Error(), secret) {
						t.Errorf("unsafe error %v", err)
					}
				}
			}
		})
	}
}
func TestTelegramNetworkErrorRedacted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	err := NewTelegram(fakeToken, server.Client(), server.URL).Send(fakeChat, "test")
	if err == nil {
		t.Fatal("expected network error")
	}
	for _, secret := range []string{fakeToken, fakeChat, server.URL} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("unsafe error %v", err)
		}
	}
}

// A replay must not spend a fresh hourly budget or retry a failed request.
func TestRequestSentOnceAcrossHourlyWindows(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC))
	events := make(chan core.Event, 3)
	for i := 0; i < 3; i++ {
		events <- core.Event{Kind: "request.created", Secret: "api_token", RequestID: "fake-request", Reason: "test", Duration: time.Minute}
	}
	close(events)
	calls := 0
	tr := transportFunc(func(chat, text string) error {
		calls++
		clk.AdvanceMono(time.Hour)
		return errors.New("fake failure")
	})
	NewRunner(clk).run(context.Background(), events, func(string, string) error { return nil }, tr, fakeChat, "https://crypt.local")
	if calls != 1 {
		t.Fatalf("request sent %d times, want once", calls)
	}
}

type transportFunc func(string, string) error

func (f transportFunc) Send(chat, text string) error { return f(chat, text) }

func TestTelegramCancellationStopsInFlightDelivery(t *testing.T) {
	f := setup(t)
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() { close(release); server.Close() }()
	cancel, done := launch(t, f, NewTelegram(fakeToken, server.Client(), server.URL))
	if _, err := f.svc.Request("api_token", "test", time.Minute); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery did not start")
	}
	cancel()
	waitDone(t, done)
}

func TestTelegramRedirectDoesNotForwardCredentials(t *testing.T) {
	forwarded := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded <- struct{}{}
		io.WriteString(w, `{"ok":true}`)
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	if err := NewTelegram(fakeToken, server.Client(), server.URL).Send(fakeChat, "test"); !errors.Is(err, ErrSend) {
		t.Fatalf("redirect error %v, want ErrSend", err)
	}
	if len(forwarded) != 0 {
		t.Fatal("redirect forwarded notification")
	}
}

func TestTelegramOversizedResponseFailsSafely(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ok":true,"description":"`+strings.Repeat("x", 65536)+`"}`)
	}))
	defer server.Close()
	if err := NewTelegram(fakeToken, server.Client(), server.URL).Send(fakeChat, "test"); !errors.Is(err, ErrSend) {
		t.Fatalf("oversized response error %v, want ErrSend", err)
	}
}

func TestNotifierReplacementPreservesHourlyBudget(t *testing.T) {
	f := setup(t)
	runner := NewRunner(f.clk)
	start := func(ctx context.Context, tr Transport, chat string) {
		runner.Start(ctx, f.svc, tr, chat, "https://crypt.local")
	}
	launchRun := func(tr Transport, chat string) (context.CancelFunc, <-chan struct{}) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); start(ctx, tr, chat) }()
		t.Cleanup(func() { cancel(); waitDone(t, done) })
		return cancel, done
	}
	old := &fakeTransport{messages: make(chan sent, 30), err: errors.New("fake delivery failure")}
	cancel, done := launchRun(old, "-1009000000015")
	for i := 0; i < 30; i++ {
		if err := f.svc.Flag("api_token", "invalid", "test", "agent"); err != nil {
			t.Fatal(err)
		}
		receive(t, old)
	}
	cancel()
	waitDone(t, done)
	fresh := &fakeTransport{messages: make(chan sent, 2)}
	launchRun(fresh, "9000000014")
	if err := f.svc.Flag("api_token", "invalid", "over budget", "agent"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(fresh.messages) != 0 {
			t.Fatal("replacement sent the 31st attempt within one hour")
		}
		evs, err := f.svc.AuditTail(100)
		if err != nil {
			t.Fatal(err)
		}
		dropped := false
		for _, ev := range evs {
			if ev.Type == "notifier.dropped" {
				dropped = true
			}
		}
		if dropped {
			f.clk.AdvanceMono(time.Hour)
			if err := f.svc.Flag("api_token", "invalid", "new hour", "agent"); err != nil {
				t.Fatal(err)
			}
			if m := receive(t, fresh); m.chat != "9000000014" {
				t.Fatalf("sent to %q, want replacement chat", m.chat)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("replacement did not audit rate-limit drop")
}

type ctxTransport struct {
	cancel context.CancelFunc
	calls  int
}

func (c *ctxTransport) Send(string, string) error { return errors.New("unexpected plain send") }
func (c *ctxTransport) send(ctx context.Context, _, _ string) error {
	c.calls++
	c.cancel()
	return ctx.Err()
}

func requestEvent(id string) core.Event {
	return core.Event{Kind: "request.created", Secret: "api_token", RequestID: id, Reason: "test", Duration: time.Minute}
}

func noLog(string, string) error { return nil }

// An event dequeued while the run is being cancelled is delivered by the next run.
func TestEventDequeuedDuringCancellationIsDeliveredByNextRun(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC))
	r := NewRunner(clk)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	tr := transportFunc(func(string, string) error { calls++; return nil })
	r.handle(ctx, requestEvent("fake-request"), noLog, tr, fakeChat, "https://crypt.local")
	if calls != 0 {
		t.Fatal("canceled run sent a message")
	}
	events := make(chan core.Event)
	close(events)
	r.run(context.Background(), events, noLog, tr, fakeChat, "https://crypt.local")
	if calls != 1 {
		t.Fatalf("next run sent %d messages, want 1", calls)
	}
	r.run(context.Background(), events, noLog, tr, fakeChat, "https://crypt.local")
	if calls != 1 {
		t.Fatalf("delivered event repeated: %d", calls)
	}
}

// A send interrupted by cancellation spends no budget and leaves the request unseen.
func TestCanceledSendReleasesBudgetAndSeenMark(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC))
	r := NewRunner(clk)
	ctx, cancel := context.WithCancel(context.Background())
	tr := &ctxTransport{cancel: cancel}
	r.handle(ctx, requestEvent("fake-request"), noLog, tr, fakeChat, "https://crypt.local")
	if tr.calls != 1 {
		t.Fatalf("send called %d times", tr.calls)
	}
	if len(r.attempts) != 0 || len(r.seenRequests) != 0 {
		t.Fatalf("reservation kept: %d attempts, %d seen", len(r.attempts), len(r.seenRequests))
	}
	calls := 0
	events := make(chan core.Event)
	close(events)
	r.run(context.Background(), events, noLog, transportFunc(func(string, string) error { calls++; return nil }), fakeChat, "https://crypt.local")
	if calls != 1 {
		t.Fatalf("interrupted request delivered %d times, want 1", calls)
	}
}

func TestSeenRequestsAreBounded(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC))
	r := NewRunner(clk)
	r.take("old")
	clk.AdvanceMono(48 * time.Hour)
	r.take("fresh")
	if _, ok := r.seenRequests["old"]; ok {
		t.Fatal("entry older than the retention window kept")
	}
	if send, _, _ := r.take("fresh"); send {
		t.Fatal("recent request not deduplicated")
	}
	for i := 0; i < 3*maxSeenRequests; i++ {
		r.take(fmt.Sprintf("id-%d", i))
	}
	if len(r.seenRequests) > maxSeenRequests {
		t.Fatalf("seen map has %d entries, cap %d", len(r.seenRequests), maxSeenRequests)
	}
	if send, _, _ := r.take(fmt.Sprintf("id-%d", 3*maxSeenRequests-1)); send {
		t.Fatal("newest request not deduplicated")
	}
}
