package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tokencrypt/internal/audit"
	"tokencrypt/internal/clock"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

var t0 = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

const (
	pass        = "fake-vault-passphrase-0001"
	wrongPass   = "fake-wrong-passphrase-0002"
	canary      = "CANARY-VALUE-7f3a91"
	secretName  = "api_token"
	secondName  = "other_token"
	smallKDFMem = 64
)

func init() { waitRecheck = 2 * time.Millisecond }

type env struct {
	t         *testing.T
	clk       *clock.Fake
	dir       string
	auditPath string
	v         *vault.Vault
	g         *grants.Manager
	a         *audit.Log
	svc       *Service
}

// open builds a Service over dir with a fresh grants manager and audit log.
func (e *env) open() {
	e.t.Helper()
	v, err := vault.OpenWithClock(e.dir, e.clk)
	if err != nil {
		e.t.Fatal(err)
	}
	a, err := audit.Open(e.auditPath, e.clk)
	if err != nil {
		e.t.Fatal(err)
	}
	g := grants.New(e.clk, e.dir, NewChecker(v))
	e.v, e.g, e.a = v, g, a
	e.svc = New(v, g, a, e.clk, DefaultConfig())
	e.t.Cleanup(func() { e.svc.Close() })
}

// newEnv returns an unlocked service over a new vault holding no secrets.
func newEnv(t *testing.T) *env {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	err := vault.Init(dir, []byte(pass), crypto.Params{Time: 1, MemoryKiB: smallKDFMem, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, clk: clock.NewFake(t0), dir: dir, auditPath: filepath.Join(t.TempDir(), "audit.log")}
	e.open()
	if _, err := e.svc.Unlock([]byte(pass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return e
}

// restart closes the service and builds a new one over the same files; the
// new service is locked.
func (e *env) restart() {
	e.t.Helper()
	e.svc.Close()
	e.open()
}

func (e *env) create(name, value string) {
	e.t.Helper()
	if err := e.svc.Create(name, "desc of "+name, []byte(value), []byte(pass), "user"); err != nil {
		e.t.Fatalf("Create %s: %v", name, err)
	}
}

func (e *env) grant(name string, d time.Duration) grants.Grant {
	e.t.Helper()
	g, err := e.svc.Grant(name, d, []byte(pass), "user", "")
	if err != nil {
		e.t.Fatalf("Grant %s: %v", name, err)
	}
	return g
}

func (e *env) mustRead(name, want string) {
	e.t.Helper()
	got, err := e.svc.Read(name)
	if err != nil {
		e.t.Fatalf("Read %s: %v", name, err)
	}
	if string(got) != want {
		e.t.Fatalf("Read %s = %q, want %q", name, got, want)
	}
}

func (e *env) mustNotRead(name string) error {
	e.t.Helper()
	got, err := e.svc.Read(name)
	if err == nil {
		e.t.Fatalf("Read %s returned %q, want an error", name, got)
	}
	if len(got) != 0 {
		e.t.Fatalf("Read %s returned %d bytes together with an error", name, len(got))
	}
	return err
}

func (e *env) auditEvents() []audit.Event {
	e.t.Helper()
	evs, err := e.a.Tail(1000)
	if err != nil {
		e.t.Fatal(err)
	}
	return evs
}

func (e *env) auditOf(typ string) []audit.Event {
	var out []audit.Event
	for _, ev := range e.auditEvents() {
		if ev.Type == typ {
			out = append(out, ev)
		}
	}
	return out
}

func (e *env) meta(name string) vault.Meta {
	e.t.Helper()
	m, err := e.v.Get(name)
	if err != nil {
		e.t.Fatal(err)
	}
	return m
}

func (e *env) pending() []Request {
	e.t.Helper()
	return e.svc.Status().Pending
}

func failN(t *testing.T, svc *Service, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := svc.Verify([]byte(wrongPass)); !errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("failure %d: Verify = %v, want ErrWrongPassphrase", i+1, err)
		}
	}
}

func TestDefaultConfigHoldsGlobalConstraints(t *testing.T) {
	c := DefaultConfig()
	if c.MaxPending != 10 || c.RequestTTL != 10*time.Minute || c.MaxGrant != 90*24*time.Hour ||
		c.DefaultGrant != 10*time.Minute || c.MaxFailures != 5 || c.Lockout != 5*time.Minute {
		t.Errorf("DefaultConfig = %+v", c)
	}
}

// Passphrase operations ------------------------------------------------------

func TestWrongPassphraseFailsChangesNothingAndIsAudited(t *testing.T) {
	ops := map[string]func(e *env, p []byte) error{
		"verify": func(e *env, p []byte) error { return e.svc.Verify(p) },
		"create": func(e *env, p []byte) error { return e.svc.Create("new_one", "d", []byte("x"), p, "user") },
		"update": func(e *env, p []byte) error { return e.svc.UpdateValue(secretName, []byte("replaced"), p, "user") },
		"rename": func(e *env, p []byte) error { return e.svc.Rename(secretName, "renamed", p, "user") },
		"delete": func(e *env, p []byte) error { return e.svc.Delete(secretName, p, "user") },
		"grant": func(e *env, p []byte) error {
			_, err := e.svc.Grant(secretName, time.Hour, p, "user", "")
			return err
		},
		"clear_flag": func(e *env, p []byte) error { return e.svc.ClearFlag(secretName, p, "user") },
		"unlock": func(e *env, p []byte) error {
			_, err := e.svc.Unlock(p)
			return err
		},
		"restore": func(e *env, p []byte) error {
			_, err := e.svc.RestoreGrants(p, []string{"x"})
			return err
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.create(secretName, canary)
			before := e.svc.Status()
			err := op(e, []byte(wrongPass))
			if !errors.Is(err, ErrWrongPassphrase) {
				t.Fatalf("err = %v, want ErrWrongPassphrase", err)
			}
			after := e.svc.Status()
			if len(after.Secrets) != 1 || after.Secrets[0].Name != secretName ||
				!after.Secrets[0].Updated.Equal(before.Secrets[0].Updated) ||
				!bytes.Equal(after.Secrets[0].KeyID, before.Secrets[0].KeyID) || len(after.Grants) != 0 {
				t.Errorf("state changed: before %+v after %+v", before, after)
			}
			failed := e.auditOf(audit.LoginFailed)
			if len(failed) != 1 {
				t.Fatalf("login.failed events = %d, want 1", len(failed))
			}
			if err := e.svc.Verify([]byte(pass)); err != nil {
				t.Errorf("a right passphrase after one failure: %v", err)
			}
		})
	}
}

func TestThrottleLocksAfterFiveFailuresUntilLockoutPasses(t *testing.T) {
	e := newEnv(t)
	failN(t, e.svc, 5)
	// The right passphrase is refused while locked, on every operation.
	if err := e.svc.Verify([]byte(pass)); !errors.Is(err, ErrThrottled) {
		t.Fatalf("Verify = %v, want ErrThrottled", err)
	}
	if err := e.svc.Create("n", "", []byte("x"), []byte(pass), "user"); !errors.Is(err, ErrThrottled) {
		t.Fatalf("Create = %v, want ErrThrottled", err)
	}
	if _, err := e.svc.Grant("n", time.Minute, []byte(pass), "user", ""); !errors.Is(err, ErrThrottled) {
		t.Fatalf("Grant = %v, want ErrThrottled", err)
	}
	e.clk.AdvanceWall(5*time.Minute - time.Second)
	if err := e.svc.Verify([]byte(pass)); !errors.Is(err, ErrThrottled) {
		t.Fatalf("1s before the end of the lockout: Verify = %v, want ErrThrottled", err)
	}
	e.clk.AdvanceWall(time.Second)
	if err := e.svc.Verify([]byte(pass)); err != nil {
		t.Fatalf("after the lockout: Verify = %v", err)
	}
	// Success resets the count: four more failures do not lock.
	failN(t, e.svc, 4)
	if err := e.svc.Verify([]byte(pass)); err != nil {
		t.Fatalf("after four failures: Verify = %v", err)
	}
}

func TestThrottledAttemptsAreNotAuditedOrCounted(t *testing.T) {
	e := newEnv(t)
	failN(t, e.svc, 5)
	n := len(e.auditOf(audit.LoginFailed))
	for i := 0; i < 20; i++ {
		_ = e.svc.Verify([]byte(wrongPass))
	}
	if got := len(e.auditOf(audit.LoginFailed)); got != n {
		t.Errorf("login.failed events grew from %d to %d while throttled", n, got)
	}
	// The lockout still ends 5 minutes after the 5th failure.
	e.clk.AdvanceWall(5 * time.Minute)
	if err := e.svc.Verify([]byte(pass)); err != nil {
		t.Errorf("Verify after lockout = %v", err)
	}
}

func TestOneFailureAfterLockoutLocksAgain(t *testing.T) {
	e := newEnv(t)
	failN(t, e.svc, 5)
	e.clk.AdvanceWall(5 * time.Minute)
	failN(t, e.svc, 1)
	if err := e.svc.Verify([]byte(pass)); !errors.Is(err, ErrThrottled) {
		t.Fatalf("Verify = %v, want ErrThrottled after one more failure", err)
	}
}

func TestThrottleEndsOnMonotonicTimeToo(t *testing.T) {
	e := newEnv(t)
	failN(t, e.svc, 5)
	e.clk.AdvanceMono(5 * time.Minute)
	if err := e.svc.Verify([]byte(pass)); err != nil {
		t.Errorf("Verify after a monotonic lockout end = %v", err)
	}
}

func TestFailuresAcrossOperationsShareOneThrottle(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	bad := []byte(wrongPass)
	_ = e.svc.Verify(bad)
	_ = e.svc.Create("n", "", []byte("x"), bad, "user")
	_ = e.svc.UpdateValue(secretName, []byte("y"), bad, "user")
	_, _ = e.svc.Grant(secretName, time.Minute, bad, "user", "")
	_ = e.svc.Rename(secretName, "renamed_one", bad, "user")
	if err := e.svc.Verify([]byte(pass)); !errors.Is(err, ErrThrottled) {
		t.Fatalf("Verify = %v, want ErrThrottled after five mixed failures", err)
	}
}

func TestParallelWrongAttemptsRunAtMostFiveKeyDerivations(t *testing.T) {
	e := newEnv(t)
	var calls atomic.Int32
	real := e.svc.unlock
	e.svc.unlock = func(p []byte) (*vault.Session, error) {
		calls.Add(1)
		return real(p)
	}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.svc.Verify([]byte(wrongPass))
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 5 {
		t.Errorf("key derivations = %d, want 5", got)
	}
}

func TestKeyDerivationsNeverRunConcurrently(t *testing.T) {
	e := newEnv(t)
	var cur, max atomic.Int32
	real := e.svc.unlock
	e.svc.unlock = func(p []byte) (*vault.Session, error) {
		n := cur.Add(1)
		for {
			m := max.Load()
			if n <= m || max.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		defer cur.Add(-1)
		return real(p)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.svc.Verify([]byte(pass)); err != nil {
				t.Errorf("Verify: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := max.Load(); got != 1 {
		t.Errorf("concurrent derivations = %d, want 1", got)
	}
}

// Grants and reads -----------------------------------------------------------

func TestGrantThenReadReturnsValue(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	if err := e.mustNotRead(secretName); !errors.Is(err, ErrNoGrant) {
		t.Errorf("Read without grant = %v, want ErrNoGrant", err)
	}
	g := e.grant(secretName, 10*time.Minute)
	if g.Secret != secretName || !g.Expires.Equal(t0.Add(10*time.Minute)) || g.GrantedBy != "user" {
		t.Errorf("grant = %+v", g)
	}
	e.mustRead(secretName, canary)
	if got := e.meta(secretName).LastGranted; !got.Equal(t0) {
		t.Errorf("LastGranted = %v, want %v", got, t0)
	}
	e.clk.AdvanceWall(10 * time.Minute)
	e.mustNotRead(secretName)
}

func TestGrantOfOneSecretLeavesAnotherUnreadable(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.create(secondName, "OTHER-"+canary)
	e.grant(secretName, time.Hour)
	e.mustRead(secretName, canary)
	if err := e.mustNotRead(secondName); !errors.Is(err, ErrNoGrant) {
		t.Errorf("Read of other secret = %v, want ErrNoGrant", err)
	}
}

func TestGrantDurationBounds(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	_, err := e.svc.Grant(secretName, 90*24*time.Hour+time.Second, []byte(pass), "user", "")
	if !errors.Is(err, ErrDurationTooLong) {
		t.Errorf("91 days: err = %v, want ErrDurationTooLong", err)
	}
	if len(e.svc.Status().Grants) != 0 {
		t.Error("a grant exists after a rejected duration")
	}
	g := e.grant(secretName, 90*24*time.Hour)
	if !g.Expires.Equal(t0.Add(90 * 24 * time.Hour)) {
		t.Errorf("Expires = %v", g.Expires)
	}
}

func TestOverlongGrantDoesNotCountTowardThrottle(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	for i := 0; i < 8; i++ {
		_, err := e.svc.Grant(secretName, 100*24*time.Hour, []byte(wrongPass), "user", "")
		if !errors.Is(err, ErrDurationTooLong) {
			t.Fatalf("err = %v, want ErrDurationTooLong", err)
		}
	}
	if err := e.svc.Verify([]byte(pass)); err != nil {
		t.Errorf("Verify = %v", err)
	}
}

func TestGrantAndReadUnknownOrInvalidName(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Grant("missing", time.Minute, []byte(pass), "user", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("Grant missing = %v, want ErrNotFound", err)
	}
	if _, err := e.svc.Read("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Read missing = %v, want ErrNotFound", err)
	}
	if _, err := e.svc.Read("../etc"); !errors.Is(err, vault.ErrBadName) {
		t.Errorf("Read bad name = %v, want ErrBadName", err)
	}
}

func TestUpdateRenameDeleteRevokeLiveGrants(t *testing.T) {
	cases := map[string]func(e *env) error{
		"update": func(e *env) error { return e.svc.UpdateValue(secretName, []byte("new-"+canary), []byte(pass), "user") },
		"rename": func(e *env) error { return e.svc.Rename(secretName, "renamed", []byte(pass), "user") },
		"delete": func(e *env) error { return e.svc.Delete(secretName, []byte(pass), "user") },
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.create(secretName, canary)
			e.grant(secretName, time.Hour)
			e.grant(secretName, 48*time.Hour) // persisted
			e.mustRead(secretName, canary)
			if err := op(e); err != nil {
				t.Fatal(err)
			}
			e.mustNotRead(secretName)
			if n := len(e.svc.Status().Grants); n != 0 {
				t.Errorf("%d grants remain", n)
			}
			if raw, err := os.ReadFile(filepath.Join(e.dir, "grants.json")); err == nil && strings.Contains(string(raw), `"`+secretName+`"`) {
				t.Errorf("grants.json still names the secret: %s", raw)
			}
		})
	}
}

func TestUpdateMakesNextGrantReturnNewValue(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.grant(secretName, time.Hour)
	if err := e.svc.UpdateValue(secretName, []byte("v2-"+canary), []byte(pass), "user"); err != nil {
		t.Fatal(err)
	}
	e.grant(secretName, time.Hour)
	e.mustRead(secretName, "v2-"+canary)
	if got := e.auditOf(audit.SecretUpdated); len(got) != 1 || got[0].Secret != secretName || got[0].Actor != "user" {
		t.Errorf("secret.updated events = %+v", got)
	}
}

func TestRenameMovesSecretAndFlag(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	if err := e.svc.Rename(secretName, "renamed", []byte(pass), "user"); err != nil {
		t.Fatal(err)
	}
	e.grant("renamed", time.Hour)
	e.mustRead("renamed", canary)
	if err := e.mustNotRead(secretName); !errors.Is(err, ErrNotFound) {
		t.Errorf("Read old name = %v, want ErrNotFound", err)
	}
	got := e.auditOf(audit.SecretRenamed)
	if len(got) != 1 || got[0].Secret != secretName || !strings.Contains(got[0].Detail, "renamed") {
		t.Errorf("secret.renamed events = %+v", got)
	}
}

func TestSetDescriptionNeedsNoPassphrase(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	if err := e.svc.SetDescription(secretName, "new text"); err != nil {
		t.Fatal(err)
	}
	if got := e.meta(secretName).Description; got != "new text" {
		t.Errorf("Description = %q", got)
	}
	if err := e.svc.SetDescription("missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetDescription missing = %v", err)
	}
}

func TestCreateRejectsDuplicateAndBadName(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	if err := e.svc.Create(secretName, "", []byte("x"), []byte(pass), "user"); !errors.Is(err, vault.ErrExists) {
		t.Errorf("duplicate Create = %v", err)
	}
	if err := e.svc.Create("Bad-Name", "", []byte("x"), []byte(wrongPass), "user"); !errors.Is(err, vault.ErrBadName) {
		t.Errorf("bad name = %v, want ErrBadName before any passphrase check", err)
	}
}

// Flags ----------------------------------------------------------------------

func TestFlagRevokesDeniesBlocksAndReports(t *testing.T) {
	for _, kind := range []string{"leaked", "invalid"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			e.create(secretName, canary)
			e.create(secondName, "OTHER-"+canary)
			e.grant(secretName, time.Hour)
			e.grant(secretName, 48*time.Hour)
			e.grant(secondName, time.Hour)
			r1, err := e.svc.Request(secretName, "deploy", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			r2, err := e.svc.Request(secondName, "other", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			evs := e.svc.Events()
			drain(evs)

			if err := e.svc.Flag(secretName, kind, "service rejected token", "agent"); err != nil {
				t.Fatal(err)
			}

			var fe *FlaggedError
			err = e.mustNotRead(secretName)
			if !errors.Is(err, ErrFlagged) || !errors.As(err, &fe) || fe.Kind != kind || fe.Reason != "service rejected token" {
				t.Errorf("Read = %v, want ErrFlagged with kind and reason", err)
			}
			if _, err := e.svc.Request(secretName, "again", time.Hour); !errors.Is(err, ErrFlagged) {
				t.Errorf("Request = %v, want ErrFlagged", err)
			}
			if _, err := e.svc.Grant(secretName, time.Hour, []byte(pass), "user", ""); !errors.Is(err, ErrFlagged) {
				t.Errorf("Grant = %v, want ErrFlagged", err)
			}
			e.mustRead(secondName, "OTHER-"+canary)
			for _, g := range e.svc.Status().Grants {
				if g.Secret == secretName {
					t.Errorf("grant %s survived the flag", g.ID)
				}
			}
			if st := requestState(t, e, r1.ID); st != StateDenied {
				t.Errorf("flagged secret's request state = %q, want denied", st)
			}
			if st := requestState(t, e, r2.ID); st != StatePending {
				t.Errorf("other request state = %q, want pending", st)
			}
			f := e.meta(secretName).Flag
			if f == nil || f.Kind != kind || f.Actor != "agent" || f.Reason != "service rejected token" {
				t.Errorf("stored flag = %+v", f)
			}

			set := e.auditOf(audit.FlagSet)
			if len(set) != 1 || set[0].Actor != "agent" || set[0].Secret != secretName {
				t.Fatalf("flag.set events = %+v", set)
			}
			var d struct{ Kind, Actor, Reason string }
			if err := json.Unmarshal([]byte(set[0].Detail), &d); err != nil {
				t.Fatalf("Detail is not JSON: %q", set[0].Detail)
			}
			if d.Kind != kind || d.Actor != "agent" || d.Reason != "service rejected token" {
				t.Errorf("flag detail = %+v", d)
			}
			if den := e.auditOf(audit.RequestDenied); len(den) != 1 || den[0].Secret != secretName {
				t.Errorf("request.denied events = %+v", den)
			}

			ev := <-evs
			if ev.Kind != EventFlagSet || ev.Secret != secretName || ev.Actor != "agent" ||
				ev.FlagKind != kind || ev.Reason != "service rejected token" {
				t.Errorf("event = %+v", ev)
			}
		})
	}
}

func requestState(t *testing.T, e *env, id string) string {
	t.Helper()
	r, err := e.svc.Wait(canceled(), id)
	if err != nil && r.ID == "" {
		t.Fatalf("Wait %s: %v", id, err)
	}
	return r.State
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func drain(c <-chan Event) {
	for {
		select {
		case _, ok := <-c:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

func TestFlagRejectsUnknownKindAndChangesNothing(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.grant(secretName, time.Hour)
	if err := e.svc.Flag(secretName, "stale", "r", "agent"); !errors.Is(err, ErrBadFlag) {
		t.Fatalf("Flag = %v, want ErrBadFlag", err)
	}
	e.mustRead(secretName, canary)
	if e.meta(secretName).Flag != nil {
		t.Error("flag was set")
	}
	if err := e.svc.Flag("missing", "leaked", "r", "agent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Flag missing = %v, want ErrNotFound", err)
	}
	if len(e.auditOf(audit.FlagSet)) != 0 {
		t.Error("flag.set written for a rejected flag")
	}
}

func TestClearFlagNeedsPassphraseAndIsAudited(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	if err := e.svc.Flag(secretName, "leaked", "seen in a log", "agent"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ClearFlag(secretName, []byte(wrongPass), "user"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("ClearFlag with wrong passphrase = %v", err)
	}
	if e.meta(secretName).Flag == nil {
		t.Fatal("flag cleared by a wrong passphrase")
	}
	if err := e.svc.ClearFlag(secretName, []byte(pass), "user"); err != nil {
		t.Fatal(err)
	}
	if e.meta(secretName).Flag != nil {
		t.Error("flag still set")
	}
	e.grant(secretName, time.Hour)
	cleared := e.auditOf(audit.FlagCleared)
	if len(cleared) != 1 || cleared[0].Actor != "user" || cleared[0].Secret != secretName ||
		!strings.Contains(cleared[0].Detail, `"kind":"leaked"`) {
		t.Errorf("flag.cleared events = %+v", cleared)
	}
}

func TestUpdateValueClearsFlag(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	if err := e.svc.Flag(secretName, "invalid", "expired", "agent"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpdateValue(secretName, []byte("fresh-"+canary), []byte(pass), "user"); err != nil {
		t.Fatal(err)
	}
	if e.meta(secretName).Flag != nil {
		t.Error("flag survived an update")
	}
	e.grant(secretName, time.Hour)
	e.mustRead(secretName, "fresh-"+canary)
	cleared := e.auditOf(audit.FlagCleared)
	if len(cleared) != 1 || cleared[0].Actor != "user" || !strings.Contains(cleared[0].Detail, `"kind":"invalid"`) {
		t.Errorf("flag.cleared events = %+v", cleared)
	}
}

func TestFlaggedSecretCanStillBeDeleted(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	if err := e.svc.Flag(secretName, "leaked", "r", "agent"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Delete(secretName, []byte(pass), "user"); err != nil {
		t.Errorf("Delete = %v", err)
	}
}

// Requests -------------------------------------------------------------------

func TestRequestCreatesPendingAndEmitsEvent(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	evs := e.svc.Events()
	r, err := e.svc.Request(secretName, "deploy the site", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == "" || r.Secret != secretName || r.Reason != "deploy the site" || r.State != StatePending ||
		r.Duration != 24*time.Hour || !r.Created.Equal(t0) {
		t.Errorf("request = %+v", r)
	}
	select {
	case ev := <-evs:
		if ev.Kind != EventRequestCreated || ev.Secret != secretName || ev.RequestID != r.ID ||
			ev.Reason != "deploy the site" || ev.Duration != 24*time.Hour {
			t.Errorf("event = %+v", ev)
		}
	default:
		t.Error("no event")
	}
	if p := e.pending(); len(p) != 1 || p[0].ID != r.ID {
		t.Errorf("pending = %+v", p)
	}
	got := e.auditOf(audit.RequestCreated)
	if len(got) != 1 || got[0].Actor != "agent" || got[0].Secret != secretName {
		t.Errorf("request.created events = %+v", got)
	}
}

func TestRequestDurationDefaultsAndBound(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	r, err := e.svc.Request(secretName, "x", 0)
	if err != nil || r.Duration != 10*time.Minute {
		t.Errorf("Request(0) = %+v, %v; want the 10 minute default", r, err)
	}
	if _, err := e.svc.Request(secretName, "x", 91*24*time.Hour); !errors.Is(err, ErrDurationTooLong) {
		t.Errorf("Request(91d) = %v, want ErrDurationTooLong", err)
	}
	if _, err := e.svc.Request("missing", "x", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Errorf("Request missing = %v, want ErrNotFound", err)
	}
}

func TestEleventhPendingRequestIsRefusedUntilOneEnds(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	var first Request
	for i := 0; i < 10; i++ {
		r, err := e.svc.Request(secretName, "r", time.Minute)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		if i == 0 {
			first = r
		}
	}
	if _, err := e.svc.Request(secretName, "r", time.Minute); !errors.Is(err, ErrTooManyPending) {
		t.Fatalf("11th request = %v, want ErrTooManyPending", err)
	}
	if err := e.svc.Deny(first.ID, "user"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Request(secretName, "r", time.Minute); err != nil {
		t.Errorf("request after a deny = %v", err)
	}
}

func TestRequestExpiresAfterTenMinutesOfWallTime(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	r, _ := e.svc.Request(secretName, "r", time.Minute)
	e.clk.AdvanceWall(10*time.Minute - time.Second)
	if p := e.pending(); len(p) != 1 {
		t.Fatalf("pending after 9m59s = %d", len(p))
	}
	e.clk.AdvanceWall(time.Second)
	if p := e.pending(); len(p) != 0 {
		t.Fatalf("pending after 10m = %+v", p)
	}
	if st := requestState(t, e, r.ID); st != StateExpired {
		t.Errorf("state = %q, want expired", st)
	}
	_ = e.pending()
	if got := e.auditOf(audit.RequestExpired); len(got) != 1 || got[0].Secret != secretName {
		t.Errorf("request.expired events = %+v, want exactly one", got)
	}
	if err := e.svc.Deny(r.ID, "user"); !errors.Is(err, ErrNotPending) {
		t.Errorf("Deny expired = %v, want ErrNotPending", err)
	}
	if _, err := e.svc.Grant(secretName, time.Minute, []byte(pass), "user", r.ID); !errors.Is(err, ErrNotPending) {
		t.Errorf("Grant on expired request = %v, want ErrNotPending", err)
	}
}

func TestRequestExpiresOnMonotonicTimeToo(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	r, _ := e.svc.Request(secretName, "r", time.Minute)
	e.clk.AdvanceMono(10 * time.Minute)
	if st := requestState(t, e, r.ID); st != StateExpired {
		t.Errorf("state = %q, want expired", st)
	}
}

func TestWallClockJumpBackDoesNotReviveExpiredRequest(t *testing.T) {
	// Once seen as expired, a request stays expired.
	e := newEnv(t)
	e.create(secretName, canary)
	r, _ := e.svc.Request(secretName, "r", time.Minute)
	e.clk.AdvanceWall(10 * time.Minute)
	_ = e.pending()
	e.clk.SetWall(t0)
	if st := requestState(t, e, r.ID); st != StateExpired {
		t.Errorf("state = %q after clock moved back, want expired", st)
	}
}

func TestWaitReturnsOnApproval(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	r, _ := e.svc.Request(secretName, "r", time.Hour)
	res := waitAsync(e.svc, r.ID)
	time.Sleep(10 * time.Millisecond)
	if _, err := e.svc.Grant(secretName, time.Hour, []byte(pass), "user", r.ID); err != nil {
		t.Fatal(err)
	}
	got := <-res
	if got.err != nil || got.req.State != StateApproved {
		t.Errorf("Wait = %+v", got)
	}
	e.mustRead(secretName, canary)
	if ap := e.auditOf(audit.RequestApproved); len(ap) != 1 || ap[0].Actor != "user" {
		t.Errorf("request.approved events = %+v", ap)
	}
}

func TestWaitReturnsOnDeny(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	r, _ := e.svc.Request(secretName, "r", time.Hour)
	res := waitAsync(e.svc, r.ID)
	if err := e.svc.Deny(r.ID, "user"); err != nil {
		t.Fatal(err)
	}
	got := <-res
	if got.err != nil || got.req.State != StateDenied {
		t.Errorf("Wait = %+v", got)
	}
	if err := e.mustNotRead(secretName); !errors.Is(err, ErrNoGrant) {
		t.Errorf("Read after deny = %v", err)
	}
	if d := e.auditOf(audit.RequestDenied); len(d) != 1 || d[0].Actor != "user" {
		t.Errorf("request.denied events = %+v", d)
	}
}

func TestWaitReturnsOnExpiryWhenFakeTimeAdvances(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	r, _ := e.svc.Request(secretName, "r", time.Hour)
	res := waitAsync(e.svc, r.ID)
	time.Sleep(10 * time.Millisecond)
	e.clk.AdvanceWall(10 * time.Minute)
	select {
	case got := <-res:
		if got.err != nil || got.req.State != StateExpired {
			t.Errorf("Wait = %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not return after the request expired")
	}
}

func TestWaitHonorsContextCancellation(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	r, _ := e.svc.Request(secretName, "r", time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan waitResult, 1)
	go func() {
		req, err := e.svc.Wait(ctx, r.ID)
		done <- waitResult{req, err}
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) || got.req.State != StatePending {
			t.Errorf("Wait = %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait ignored cancellation")
	}
	if _, err := e.svc.Wait(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Wait unknown = %v, want ErrNotFound", err)
	}
}

type waitResult struct {
	req Request
	err error
}

func waitAsync(svc *Service, id string) <-chan waitResult {
	c := make(chan waitResult, 1)
	go func() {
		req, err := svc.Wait(context.Background(), id)
		c <- waitResult{req, err}
	}()
	return c
}

func TestApprovedGrantDurationIsTheUsersNotTheRequests(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	r, _ := e.svc.Request(secretName, "r", 24*time.Hour)
	g, err := e.svc.Grant(secretName, 10*time.Minute, []byte(pass), "user", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Expires.Equal(t0.Add(10*time.Minute)) || g.RequestID != r.ID {
		t.Errorf("grant = %+v", g)
	}
}

func TestGrantWithRequestOfAnotherSecretIsRefused(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.create(secondName, canary)
	r, _ := e.svc.Request(secretName, "r", time.Hour)
	if _, err := e.svc.Grant(secondName, time.Hour, []byte(pass), "user", r.ID); !errors.Is(err, ErrRequestMismatch) {
		t.Errorf("Grant = %v, want ErrRequestMismatch", err)
	}
	if _, err := e.svc.Grant(secondName, time.Hour, []byte(pass), "user", "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Grant with unknown request = %v, want ErrNotFound", err)
	}
	if st := requestState(t, e, r.ID); st != StatePending {
		t.Errorf("state = %q", st)
	}
}

func TestDenyUnknownRequest(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.Deny("nope", "user"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Deny = %v, want ErrNotFound", err)
	}
}

func TestReasonIsCappedAndControlCharactersBecomeSpaces(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	long := strings.Repeat("é", 300)
	r, err := e.svc.Request(secretName, long, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := []rune(r.Reason); len(got) != 200 || string(got) != strings.Repeat("é", 200) {
		t.Errorf("reason has %d runes", len(got))
	}
	r2, _ := e.svc.Request(secretName, "a\nb\x00c\td‮e f", time.Minute)
	if r2.Reason != "a b c d e f" {
		t.Errorf("reason = %q", r2.Reason)
	}
	if err := e.svc.Flag(secretName, "leaked", "x\r\ny", "agent\n"); err != nil {
		t.Fatal(err)
	}
	f := e.meta(secretName).Flag
	if f.Reason != "x  y" || f.Actor != "agent" {
		t.Errorf("flag = %+v", f)
	}
}

// Restart and unlock ---------------------------------------------------------

func TestUnlockRestoresOnlyConfirmedLongGrants(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.create(secondName, "OTHER-"+canary)
	e.create("short_one", "SHORT-"+canary)
	keep := e.grant(secretName, 24*time.Hour)
	e.grant(secondName, 48*time.Hour)
	e.grant("short_one", 30*time.Minute)

	e.restart()
	if err := e.mustNotRead(secretName); !errors.Is(err, ErrLocked) {
		t.Fatalf("Read before Unlock = %v, want ErrLocked", err)
	}
	if !e.svc.Status().Locked {
		t.Error("Status.Locked = false before Unlock")
	}
	if _, err := e.svc.Unlock([]byte(wrongPass)); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Unlock wrong = %v", err)
	}
	res, err := e.svc.Unlock([]byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("candidates = %+v, want the two long grants", res.Candidates)
	}
	if err := e.mustNotRead(secretName); !errors.Is(err, ErrLocked) {
		t.Errorf("Read after Unlock but before restore = %v, want ErrLocked", err)
	}
	if len(e.auditOf(audit.DaemonUnlocked)) == 0 {
		t.Error("no daemon.unlocked event")
	}

	if _, err := e.svc.RestoreGrants([]byte(wrongPass), []string{keep.ID}); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("RestoreGrants wrong = %v", err)
	}
	n, err := e.svc.RestoreGrants([]byte(pass), []string{keep.ID})
	if err != nil || n != 1 {
		t.Fatalf("RestoreGrants = %d, %v", n, err)
	}
	e.mustRead(secretName, canary)
	if err := e.mustNotRead(secondName); !errors.Is(err, ErrNoGrant) {
		t.Errorf("unconfirmed secret Read = %v, want ErrNoGrant", err)
	}
	if err := e.mustNotRead("short_one"); !errors.Is(err, ErrNoGrant) {
		t.Errorf("short grant Read = %v, want ErrNoGrant", err)
	}
	if e.svc.Status().Locked {
		t.Error("Status.Locked after restore")
	}
	if got := e.auditOf(audit.GrantRestored); len(got) != 1 || got[0].Secret != secretName {
		t.Errorf("grant.restored events = %+v", got)
	}
}

func TestRestoreGrantsRefusesIDsThatAreNotCandidates(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.grant(secretName, 24*time.Hour)
	e.restart()
	if _, err := e.svc.Unlock([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	n, err := e.svc.RestoreGrants([]byte(pass), []string{"forged"})
	if n != 0 || !errors.Is(err, grants.ErrNotCandidate) {
		t.Errorf("RestoreGrants = %d, %v", n, err)
	}
	e.mustNotRead(secretName)
}

func TestRestoreSkipsGrantOfSecretFlaggedWhileDown(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	g := e.grant(secretName, 24*time.Hour)
	e.restart()
	if err := e.v.SetFlag(secretName, vault.Flag{Kind: "leaked", Actor: "other", Reason: "r"}); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.Unlock([]byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 0 {
		t.Errorf("candidates = %+v", res.Candidates)
	}
	if n, err := e.svc.RestoreGrants([]byte(pass), []string{g.ID}); n != 0 || err == nil {
		t.Errorf("RestoreGrants = %d, %v", n, err)
	}
}

func TestUnlockIgnoresStrayNotifierFiles(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	if err := os.WriteFile(filepath.Join(e.dir, "notifier.json"), []byte("fake-stray-notifier"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(e.dir, "service"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "service", "notifier.json"), []byte("fake-stray-service"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.restart()
	if _, err := e.svc.Unlock([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	e.grant(secretName, time.Hour)
	e.mustRead(secretName, canary)
}

func TestUnlockWithoutCandidatesFinishesUnlock(t *testing.T) {
	e := newEnv(t)
	e.restart()
	res, err := e.svc.Unlock([]byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 0 {
		t.Errorf("result = %+v", res)
	}
	if e.svc.Status().Locked {
		t.Error("still locked with nothing to restore")
	}
}

// Audit hygiene --------------------------------------------------------------

func TestAuditHoldsNoValueOrPassphrase(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.create(secondName, canary)
	_ = e.svc.Verify([]byte(wrongPass))
	_ = e.svc.UpdateValue(secretName, []byte("new-"+canary), []byte(wrongPass), "user")
	e.grant(secretName, 24*time.Hour)
	r, _ := e.svc.Request(secondName, "needs it", time.Hour)
	_, _ = e.svc.Grant(secondName, time.Hour, []byte(pass), "user", r.ID)
	_ = e.svc.UpdateValue(secretName, []byte("new-"+canary), []byte(pass), "user")
	_ = e.svc.Flag(secondName, "leaked", "seen", "agent")
	_ = e.svc.ClearFlag(secondName, []byte(pass), "user")
	_ = e.svc.Rename(secondName, "third_one", []byte(pass), "user")
	_ = e.svc.Delete("third_one", []byte(pass), "user")
	g := e.svc.Status().Grants
	for _, x := range g {
		_ = e.svc.Revoke(x.ID, "user")
	}
	raw, err := os.ReadFile(e.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{canary, pass, wrongPass} {
		if bytes.Contains(raw, []byte(bad)) {
			t.Errorf("audit log contains %q", bad)
		}
	}
	for _, typ := range []string{
		audit.SecretCreated, audit.SecretUpdated, audit.SecretRenamed, audit.SecretDeleted,
		audit.FlagSet, audit.FlagCleared, audit.RequestCreated, audit.RequestApproved,
		audit.GrantStarted, audit.GrantRevoked, audit.LoginFailed,
	} {
		if len(e.auditOf(typ)) == 0 {
			t.Errorf("no %s event written", typ)
		}
	}
	// The vault files hold no plaintext either.
	_ = filepath.Walk(e.dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte(canary)) {
				t.Errorf("%s holds plaintext", p)
			}
		}
		return nil
	})
}

func TestLogNotifierEventAllowsOnlyNotifierTypesAndCleansDetail(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.LogNotifierEvent(audit.NotifierSet, "sent to chat\nline"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.LogNotifierEvent("notifier.failed", "HTTP 401"); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{audit.FlagCleared, audit.GrantStarted, "", "daemon.unlocked"} {
		if err := e.svc.LogNotifierEvent(typ, "x"); !errors.Is(err, ErrBadEventType) {
			t.Errorf("LogNotifierEvent(%q) = %v, want ErrBadEventType", typ, err)
		}
	}
	var evs []audit.Event
	for _, ev := range e.auditEvents() {
		if strings.HasPrefix(ev.Type, "notifier.") {
			evs = append(evs, ev)
		}
	}
	if len(evs) != 2 || evs[0].Type != audit.NotifierSet || evs[0].Actor != "notifier" || evs[0].Detail != "sent to chat line" {
		t.Errorf("events = %+v", evs)
	}
	if n := len(e.auditEvents()); n != 3 { // daemon.unlocked and the two above
		t.Errorf("%d events written, want 3: a rejected type must not be written", n)
	}
}

func TestAuditTailReturnsLastEvents(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.create(secondName, canary)
	got, err := e.svc.AuditTail(1)
	if err != nil || len(got) != 1 || got[0].Type != audit.SecretCreated || got[0].Secret != secondName {
		t.Errorf("AuditTail = %+v, %v", got, err)
	}
}

func TestAuditWriteFailureIsReportedAfterTheActionStands(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.a.Close()
	err := e.svc.Flag(secretName, "leaked", "r", "agent")
	if !errors.Is(err, ErrAudit) {
		t.Fatalf("Flag = %v, want ErrAudit", err)
	}
	if e.meta(secretName).Flag == nil {
		t.Error("flag not applied")
	}
	// A grant is not left readable when its audit event cannot be written.
	e2 := newEnv(t)
	e2.create(secretName, canary)
	e2.a.Close()
	if _, err := e2.svc.Grant(secretName, time.Hour, []byte(pass), "user", ""); !errors.Is(err, ErrAudit) {
		t.Fatalf("Grant = %v, want ErrAudit", err)
	}
	e2.mustNotRead(secretName)
}

// Revoke ---------------------------------------------------------------------

func TestRevokeEndsGrantAndIsAudited(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	g := e.grant(secretName, time.Hour)
	if err := e.svc.Revoke(g.ID, "user"); err != nil {
		t.Fatal(err)
	}
	e.mustNotRead(secretName)
	if got := e.auditOf(audit.GrantRevoked); len(got) != 1 || got[0].Secret != secretName || got[0].Actor != "user" {
		t.Errorf("grant.revoked events = %+v", got)
	}
	if err := e.svc.Revoke(g.ID, "user"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Revoke = %v, want ErrNotFound", err)
	}
}

func TestGrantEndedByTimeIsAuditedOnce(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.grant(secretName, 10*time.Minute)
	e.clk.AdvanceWall(10 * time.Minute)
	_ = e.svc.Status()
	_ = e.svc.Status()
	if got := e.auditOf(audit.GrantEnded); len(got) != 1 || got[0].Secret != secretName {
		t.Errorf("grant.ended events = %+v, want exactly one", got)
	}
}

// Fail-closed metadata handling ----------------------------------------------

func TestCheckerReportsFlaggedWhenMetadataIsUnreadable(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	chk := NewChecker(e.v)
	if chk.Flagged(secretName) {
		t.Fatal("Flagged = true for a healthy unflagged secret")
	}
	corruptMeta(t, e)
	if !chk.Flagged(secretName) {
		t.Error("Flagged = false with unreadable metadata")
	}
	if !chk.Flagged("missing") {
		t.Error("Flagged = false for an unknown secret")
	}
}

func corruptMeta(t *testing.T, e *env) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.dir, "meta.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUnreadableMetadataBlocksReadAndGrantAndShowsInStatus(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.grant(secretName, time.Hour)
	corruptMeta(t, e)

	if err := e.mustNotRead(secretName); !errors.Is(err, vault.ErrCorrupt) {
		t.Errorf("Read = %v, want ErrCorrupt", err)
	}
	if _, err := e.svc.Request(secretName, "r", time.Minute); !errors.Is(err, vault.ErrCorrupt) {
		t.Errorf("Request = %v, want ErrCorrupt", err)
	}
	if _, err := e.svc.Grant(secretName, time.Hour, []byte(pass), "user", ""); err == nil {
		t.Error("Grant succeeded with unreadable metadata")
	}
	st := e.svc.Status()
	if st.Error == "" || len(st.Secrets) != 0 {
		t.Errorf("Status = %+v, want an error and no secrets", st)
	}
	if strings.Contains(st.Error, e.dir) {
		t.Errorf("Status.Error leaks a path: %q", st.Error)
	}
}

func TestMetadataFailureDuringMutationStillRevokesLiveGrant(t *testing.T) {
	cases := map[string]func(e *env) error{
		"update": func(e *env) error { return e.svc.UpdateValue(secretName, []byte("new"), []byte(pass), "user") },
		"rename": func(e *env) error { return e.svc.Rename(secretName, "renamed", []byte(pass), "user") },
		"delete": func(e *env) error { return e.svc.Delete(secretName, []byte(pass), "user") },
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.create(secretName, canary)
			e.grant(secretName, time.Hour)
			e.grant(secretName, 48*time.Hour)
			corruptMeta(t, e)
			if err := op(e); err == nil {
				t.Fatal("mutation succeeded with unreadable metadata")
			}
			// Repair the metadata so only the grant table decides.
			if err := os.WriteFile(filepath.Join(e.dir, "meta.json"), []byte(`{"version":1,"secrets":{}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			e.mustNotRead(secretName)
			if n := len(e.svc.Status().Grants); n != 0 {
				t.Errorf("%d grants survived a failed mutation", n)
			}
		})
	}
}

func TestPartiallyAppliedUpdateLeavesNoReadableOldGrant(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	e := newEnv(t)
	e.create(secretName, canary)
	e.grant(secretName, time.Hour)
	// The secrets directory stays writable; meta.json cannot be replaced.
	if err := os.Chmod(e.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(e.dir, 0o700)
	err := e.svc.UpdateValue(secretName, []byte("new-"+canary), []byte(pass), "user")
	if !errors.Is(err, vault.ErrMetadata) {
		t.Fatalf("UpdateValue = %v, want an error wrapping ErrMetadata", err)
	}
	e.mustNotRead(secretName)
	if err := os.Chmod(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := e.auditOf(audit.SecretUpdated); len(got) != 1 {
		t.Errorf("secret.updated events = %d, want 1 for the applied change", len(got))
	}
	e.grant(secretName, time.Hour)
	e.mustRead(secretName, "new-"+canary)
}

func TestRevokePersistenceFailureIsReportedAndGrantStaysRevoked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	e := newEnv(t)
	e.create(secretName, canary)
	g := e.grant(secretName, 48*time.Hour)
	if err := os.Chmod(e.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(e.dir, 0o700)
	err := e.svc.Revoke(g.ID, "user")
	if !errors.Is(err, ErrRecordNotRemoved) {
		t.Fatalf("Revoke = %v, want ErrRecordNotRemoved", err)
	}
	e.mustNotRead(secretName)
	if got := e.auditOf(audit.GrantRevoked); len(got) != 1 {
		t.Errorf("grant.revoked events = %d, want 1", len(got))
	}
}

// Concurrency ----------------------------------------------------------------

func TestNoValueReadableAfterFlagReturnsUnderConcurrency(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	for round := 0; round < 5; round++ {
		stop := make(chan struct{})
		var wg sync.WaitGroup
		spin := func(f func()) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						f()
					}
				}
			}()
		}
		for i := 0; i < 3; i++ {
			spin(func() { _, _ = e.svc.Grant(secretName, time.Hour, []byte(pass), "user", "") })
		}
		for i := 0; i < 3; i++ {
			spin(func() { _, _ = e.svc.Read(secretName) })
		}
		spin(func() {
			for _, g := range e.svc.Status().Grants {
				_ = e.svc.Revoke(g.ID, "user")
			}
		})
		time.Sleep(15 * time.Millisecond)

		if err := e.svc.Flag(secretName, "leaked", "r", "agent"); err != nil {
			t.Fatal(err)
		}
		// Flag has returned; the spinners are still running.
		for i := 0; i < 50; i++ {
			if v, err := e.svc.Read(secretName); err == nil {
				t.Fatalf("round %d: Read returned %q after Flag returned", round, v)
			}
			if n := len(e.g.List()); n != 0 {
				t.Fatalf("round %d: %d live grants after Flag returned", round, n)
			}
		}
		close(stop)
		wg.Wait()
		if err := e.svc.ClearFlag(secretName, []byte(pass), "user"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUpdateConcurrentWithGrantNeverLeavesOldValueReadable(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, "old-"+canary)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = e.svc.Grant(secretName, time.Hour, []byte(pass), "user", "")
			}
		}
	}()
	time.Sleep(10 * time.Millisecond)
	if err := e.svc.UpdateValue(secretName, []byte("new-"+canary), []byte(pass), "user"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if v, err := e.svc.Read(secretName); err == nil && string(v) != "new-"+canary {
			t.Fatalf("Read returned the old value %q after UpdateValue returned", v)
		}
	}
	close(stop)
	wg.Wait()
}

// Lifecycle ------------------------------------------------------------------

func TestEventsDoNotBlockWhenNobodyReads(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			if err := e.svc.Flag(secretName, "leaked", "r", "agent"); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Flag blocked on an unread event channel")
	}
}

func TestCloseEndsEventsWaitsAndOperations(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.grant(secretName, time.Hour)
	r, _ := e.svc.Request(secretName, "r", time.Hour)
	evs := e.svc.Events()
	res := waitAsync(e.svc, r.ID)
	time.Sleep(10 * time.Millisecond)
	e.svc.Close()
	select {
	case got := <-res:
		if !errors.Is(got.err, ErrClosed) {
			t.Errorf("Wait = %+v, want ErrClosed", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not end on Close")
	}
	drain(evs)
	if _, ok := <-evs; ok {
		t.Error("event channel still open")
	}
	if _, err := e.svc.Read(secretName); !errors.Is(err, ErrClosed) {
		t.Errorf("Read after Close = %v", err)
	}
	if err := e.svc.Verify([]byte(pass)); !errors.Is(err, ErrClosed) {
		t.Errorf("Verify after Close = %v", err)
	}
	e.svc.Close() // idempotent
}
