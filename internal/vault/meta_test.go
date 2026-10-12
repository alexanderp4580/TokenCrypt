package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tokencrypt/internal/clock"
)

var (
	epoch         = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	notifierToken = []byte("123456:FAKE-bot-token-for-tests")
)

// newClockSession is newSession with a fake wall clock the test can move.
func newClockSession(t *testing.T) (*Vault, *Session, string, *clock.Fake) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	if err := Init(dir, pass, testParams); err != nil {
		t.Fatal(err)
	}
	fk := clock.NewFake(epoch)
	v, err := OpenWithClock(dir, fk)
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.Unlock(pass)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return v, s, dir, fk
}

func metaPath(dir string) string { return filepath.Join(dir, "meta.json") }

// failRenameNumber makes the n-th (1-based) atomic write fail before its
// rename and lets every other write through.
func failRenameNumber(t *testing.T, n int) {
	t.Helper()
	calls := 0
	beforeRename = func() error {
		calls++
		if calls == n {
			return errors.New("injected")
		}
		return nil
	}
	t.Cleanup(func() { beforeRename = nil })
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
}

func mustGet(t *testing.T, v *Vault, name string) Meta {
	t.Helper()
	m, err := v.Get(name)
	if err != nil {
		t.Fatalf("Get(%s): %v", name, err)
	}
	return m
}

func sameMeta(a, b Meta) bool {
	if a.Name != b.Name || a.Description != b.Description || !bytes.Equal(a.KeyID, b.KeyID) ||
		!a.Created.Equal(b.Created) || !a.Updated.Equal(b.Updated) || !a.LastGranted.Equal(b.LastGranted) {
		return false
	}
	if a.Flag == nil || b.Flag == nil {
		return a.Flag == b.Flag
	}
	return a.Flag.Kind == b.Flag.Kind && a.Flag.Actor == b.Flag.Actor &&
		a.Flag.Reason == b.Flag.Reason && a.Flag.At.Equal(b.Flag.At)
}

func TestCreateStoresDescriptionAndTimestamps(t *testing.T) {
	v, s, _, _ := newClockSession(t)
	if err := s.Create("tok", "deploy token", canary); err != nil {
		t.Fatal(err)
	}
	m := mustGet(t, v, "tok")
	id, _ := v.KeyID("tok")
	if m.Name != "tok" || m.Description != "deploy token" || !bytes.Equal(m.KeyID, id) {
		t.Fatalf("%+v", m)
	}
	if !m.Created.Equal(epoch) || !m.Updated.Equal(epoch) {
		t.Fatalf("created=%v updated=%v", m.Created, m.Updated)
	}
	if !m.LastGranted.IsZero() || m.Flag != nil {
		t.Fatalf("granted=%v flag=%v", m.LastGranted, m.Flag)
	}
}

func TestListIsSortedAndHoldsNoValue(t *testing.T) {
	v, s, _, _ := newClockSession(t)
	for _, n := range []string{"b", "a_x", "a", "c"} {
		if err := s.Create(n, "d-"+n, canary); err != nil {
			t.Fatal(err)
		}
	}
	list, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range list {
		names = append(names, m.Name)
		if strings.Contains(fmt.Sprintf("%+v %#v", m, m), string(canary)) {
			t.Errorf("%s: metadata holds the value", m.Name)
		}
		if m.Description != "d-"+m.Name {
			t.Errorf("%s: description %q", m.Name, m.Description)
		}
	}
	if got := strings.Join(names, ","); got != "a,a_x,b,c" {
		t.Fatalf("order %s", got)
	}
}

func TestListEmptyVault(t *testing.T) {
	v, _, _, _ := newClockSession(t)
	list, err := v.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("%v %v", list, err)
	}
}

func TestSetFlagKinds(t *testing.T) {
	v, s, _, fk := newClockSession(t)
	must(t, s.Create("tok", "", []byte("x")))
	for _, kind := range []string{"leaked", "invalid"} {
		fk.AdvanceWall(time.Minute)
		f := Flag{Kind: kind, Actor: "agent", Reason: "service said no"}
		if err := v.SetFlag("tok", f); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		got := mustGet(t, v, "tok").Flag
		if got == nil || got.Kind != kind || got.Actor != "agent" || got.Reason != "service said no" {
			t.Fatalf("%s: %+v", kind, got)
		}
		if !got.At.Equal(fk.Wall()) {
			t.Fatalf("%s: At %v, want the clock reading %v", kind, got.At, fk.Wall())
		}
	}
	at := epoch.Add(-time.Hour)
	if err := v.SetFlag("tok", Flag{Kind: "leaked", Actor: "user", At: at}); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, v, "tok").Flag; !got.At.Equal(at) {
		t.Fatalf("explicit At lost: %v", got.At)
	}
}

func TestSetFlagRejectsBadInput(t *testing.T) {
	v, s, _, _ := newClockSession(t)
	must(t, s.Create("tok", "", []byte("x")))
	if err := v.SetFlag("tok", Flag{Kind: "bogus", Actor: "agent"}); !errors.Is(err, ErrBadFlag) {
		t.Fatalf("kind: %v", err)
	}
	if err := v.SetFlag("tok", Flag{Kind: ""}); !errors.Is(err, ErrBadFlag) {
		t.Fatalf("empty kind: %v", err)
	}
	if mustGet(t, v, "tok").Flag != nil {
		t.Fatal("rejected flag was stored")
	}
	if err := v.SetFlag("missing", Flag{Kind: "leaked"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := v.SetFlag("../x", Flag{Kind: "leaked"}); !errors.Is(err, ErrBadName) {
		t.Fatalf("name: %v", err)
	}
	b, _ := os.ReadFile(metaPath(v.dir))
	if strings.Contains(string(b), "missing") || strings.Contains(string(b), "bogus") {
		t.Fatalf("rejected call wrote to meta.json: %s", b)
	}
}

func TestUpdateValueClearsFlag(t *testing.T) {
	v, s, _, fk := newClockSession(t)
	must(t, s.Create("tok", "d", []byte("one")))
	must(t, v.SetFlag("tok", Flag{Kind: "invalid", Actor: "agent", Reason: "expired"}))
	fk.AdvanceWall(time.Hour)
	if err := s.UpdateValue("tok", []byte("two")); err != nil {
		t.Fatal(err)
	}
	m := mustGet(t, v, "tok")
	if m.Flag != nil {
		t.Fatalf("flag survived: %+v", m.Flag)
	}
	if !m.Created.Equal(epoch) || !m.Updated.Equal(epoch.Add(time.Hour)) || m.Description != "d" {
		t.Fatalf("%+v", m)
	}
	id, _ := v.KeyID("tok")
	if !bytes.Equal(m.KeyID, id) {
		t.Fatal("meta key ID is not the current key ID")
	}
}

func TestClearFlag(t *testing.T) {
	v, s, _, _ := newClockSession(t)
	must(t, s.Create("tok", "", []byte("x")))
	must(t, v.SetFlag("tok", Flag{Kind: "leaked", Actor: "user"}))
	if err := v.ClearFlag("tok"); err != nil {
		t.Fatal(err)
	}
	if mustGet(t, v, "tok").Flag != nil {
		t.Fatal("flag remains")
	}
	if err := v.ClearFlag("tok"); err != nil {
		t.Fatalf("clearing an unflagged secret: %v", err)
	}
	if err := v.ClearFlag("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestSetDescriptionAndTouchGrantedChangeOnlyTheirField(t *testing.T) {
	v, s, _, fk := newClockSession(t)
	must(t, s.Create("tok", "old", []byte("x")))
	must(t, v.SetFlag("tok", Flag{Kind: "leaked", Actor: "user", Reason: "r"}))
	before := mustGet(t, v, "tok")
	fk.AdvanceWall(time.Hour)
	if err := v.SetDescription("tok", "new"); err != nil {
		t.Fatal(err)
	}
	m := mustGet(t, v, "tok")
	want := before
	want.Description = "new"
	if !sameMeta(m, want) {
		t.Fatalf("got %+v\nwant %+v", m, want)
	}
	at := epoch.Add(5 * time.Minute)
	if err := v.TouchGranted("tok", at); err != nil {
		t.Fatal(err)
	}
	m = mustGet(t, v, "tok")
	want.LastGranted = at
	if !sameMeta(m, want) {
		t.Fatalf("got %+v\nwant %+v", m, want)
	}
	for _, err := range []error{
		v.SetDescription("missing", "x"),
		v.TouchGranted("missing", at),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
	}
}

func TestRenameCarriesMetadata(t *testing.T) {
	v, s, dir, fk := newClockSession(t)
	must(t, s.Create("old", "desc", []byte("x")))
	must(t, v.SetFlag("old", Flag{Kind: "leaked", Actor: "user", Reason: "pasted in chat"}))
	granted := epoch.Add(time.Minute)
	must(t, v.TouchGranted("old", granted))
	before := mustGet(t, v, "old")
	fk.AdvanceWall(time.Hour)
	if err := s.Rename("old", "new"); err != nil {
		t.Fatal(err)
	}
	m := mustGet(t, v, "new")
	id, _ := v.KeyID("new")
	if m.Description != "desc" || !m.Created.Equal(before.Created) || !m.LastGranted.Equal(granted) ||
		!m.Updated.Equal(before.Updated) {
		t.Fatalf("%+v", m)
	}
	if m.Flag == nil || m.Flag.Kind != "leaked" || m.Flag.Reason != "pasted in chat" {
		t.Fatalf("flag %+v", m.Flag)
	}
	if !bytes.Equal(m.KeyID, id) || bytes.Equal(m.KeyID, before.KeyID) {
		t.Fatal("key ID does not follow the re-encrypted file")
	}
	if _, err := v.Get("old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old: %v", err)
	}
	b, _ := os.ReadFile(metaPath(dir))
	if strings.Contains(string(b), `"old"`) {
		t.Fatalf("meta.json still names the old secret: %s", b)
	}
}

func TestDeleteRemovesMetadata(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	must(t, s.Create("tok", "desc", []byte("x")))
	must(t, v.SetFlag("tok", Flag{Kind: "invalid", Actor: "agent"}))
	must(t, v.TouchGranted("tok", epoch))
	if err := s.Delete("tok"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("tok"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if list, _ := v.List(); len(list) != 0 {
		t.Fatalf("%+v", list)
	}
	b, _ := os.ReadFile(metaPath(dir))
	if strings.Contains(string(b), "tok") {
		t.Fatalf("meta.json keeps the entry: %s", b)
	}
	must(t, s.Create("tok", "", []byte("again")))
	m := mustGet(t, v, "tok")
	if m.Flag != nil || !m.LastGranted.IsZero() || m.Description != "" {
		t.Fatalf("metadata outlived delete: %+v", m)
	}
}

func TestMetaFileIsPrivateAndHoldsNoValue(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	must(t, s.Create("tok", "d", canary))
	must(t, v.SetFlag("tok", Flag{Kind: "leaked", Actor: "user", Reason: "r"}))
	fi, err := os.Stat(metaPath(dir))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	b, _ := os.ReadFile(metaPath(dir))
	if bytes.Contains(b, canary) || bytes.Contains(b, pass) {
		t.Fatal("meta.json holds a secret")
	}
}

func TestMetaWriteIsAtomic(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	must(t, s.Create("tok", "old", []byte("x")))
	before, _ := os.ReadFile(metaPath(dir))

	inHook := false
	beforeRename = func() error {
		inHook = true
		now, _ := os.ReadFile(metaPath(dir))
		if !bytes.Equal(now, before) {
			t.Error("meta.json changed before the rename")
		}
		return errors.New("injected")
	}
	t.Cleanup(func() { beforeRename = nil })

	if err := v.SetDescription("tok", "new"); err == nil {
		t.Fatal("write succeeded")
	}
	if !inHook {
		t.Fatal("metadata write bypassed the atomic helper")
	}
	beforeRename = nil
	after, _ := os.ReadFile(metaPath(dir))
	if !bytes.Equal(after, before) {
		t.Fatal("failed write changed meta.json")
	}
	if got := mustGet(t, v, "tok").Description; got != "old" {
		t.Fatalf("description %q", got)
	}
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		if strings.HasPrefix(e.Name(), ".tmp") {
			t.Errorf("leftover %s", e.Name())
		}
	}
}

func TestCreateFailsWhenMetadataCannotBeWritten(t *testing.T) {
	v, s, _, _ := newClockSession(t)
	failRenameNumber(t, 1)
	if err := s.Create("tok", "d", []byte("x")); err == nil {
		t.Fatal("create succeeded")
	}
	if v.Exists("tok") {
		t.Fatal("secret was written without metadata")
	}
}

func TestCreateFailsWhenSecretCannotBeWritten(t *testing.T) {
	v, s, _, _ := newClockSession(t)
	failRenameNumber(t, 2)
	if err := s.Create("tok", "d", []byte("x")); err == nil {
		t.Fatal("create succeeded")
	}
	if _, err := v.Get("tok"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get: %v", err)
	}
	if list, _ := v.List(); len(list) != 0 {
		t.Fatalf("leftover metadata is listed: %+v", list)
	}
	beforeRename = nil
	if err := s.Create("tok", "fresh", []byte("x")); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := mustGet(t, v, "tok").Description; got != "fresh" {
		t.Fatalf("description %q", got)
	}
}

func TestUpdateValueReportsMetadataFailure(t *testing.T) {
	v, s, _, _ := newClockSession(t)
	must(t, s.Create("tok", "", []byte("one")))
	must(t, v.SetFlag("tok", Flag{Kind: "leaked", Actor: "user"}))
	failRenameNumber(t, 2) // 1: secret file, 2: metadata
	err := s.UpdateValue("tok", []byte("two"))
	if !errors.Is(err, ErrMetadata) {
		t.Fatalf("got %v", err)
	}
	beforeRename = nil
	val, _, rerr := s.Reveal("tok")
	if rerr != nil || string(val) != "two" {
		t.Fatalf("the value write must be visible: %q %v", val, rerr)
	}
	if mustGet(t, v, "tok").Flag == nil {
		t.Fatal("a failed metadata write must leave the flag in place")
	}
	if err := s.UpdateValue("tok", []byte("three")); err != nil {
		t.Fatal(err)
	}
	if mustGet(t, v, "tok").Flag != nil {
		t.Fatal("retry did not clear the flag")
	}
}

func TestRenameFailureBeforeSecretWriteChangesNothing(t *testing.T) {
	v, s, _, _ := newClockSession(t)
	must(t, s.Create("old", "d", []byte("x")))
	failRenameNumber(t, 1) // metadata for the new name
	if err := s.Rename("old", "new"); err == nil {
		t.Fatal("rename succeeded")
	}
	beforeRename = nil
	if !v.Exists("old") || v.Exists("new") {
		t.Fatal("files changed")
	}
	if got := mustGet(t, v, "old").Description; got != "d" {
		t.Fatalf("description %q", got)
	}
}

func TestRenameReportsMetadataFailureAfterMove(t *testing.T) {
	v, s, _, _ := newClockSession(t)
	must(t, s.Create("old", "d", []byte("x")))
	must(t, v.SetFlag("old", Flag{Kind: "leaked", Actor: "user"}))
	failRenameNumber(t, 3) // 1: new metadata, 2: new secret, 3: drop old metadata
	err := s.Rename("old", "new")
	if !errors.Is(err, ErrMetadata) {
		t.Fatalf("got %v", err)
	}
	beforeRename = nil
	if v.Exists("old") || !v.Exists("new") {
		t.Fatal("the move itself must be complete")
	}
	m := mustGet(t, v, "new")
	if m.Description != "d" || m.Flag == nil {
		t.Fatalf("%+v", m)
	}
	if _, err := v.Get("old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old: %v", err)
	}
	list, _ := v.List()
	if len(list) != 1 || list[0].Name != "new" {
		t.Fatalf("%+v", list)
	}
}

func TestDeleteReportsMetadataFailure(t *testing.T) {
	v, s, _, _ := newClockSession(t)
	must(t, s.Create("tok", "d", []byte("x")))
	must(t, v.SetFlag("tok", Flag{Kind: "invalid", Actor: "agent"}))
	failRenameNumber(t, 1)
	err := s.Delete("tok")
	if !errors.Is(err, ErrMetadata) {
		t.Fatalf("got %v", err)
	}
	beforeRename = nil
	if v.Exists("tok") {
		t.Fatal("secret file remains")
	}
	if _, err := v.Get("tok"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get: %v", err)
	}
	must(t, s.Create("tok", "", []byte("again")))
	if mustGet(t, v, "tok").Flag != nil {
		t.Fatal("stale flag attached to a new secret")
	}
}

func TestDeleteRetryPrunesStaleRecord(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	must(t, s.Create("tok", "private note", []byte("x")))
	must(t, v.SetFlag("tok", Flag{Kind: "invalid", Actor: "agent", Reason: "stale reason text"}))
	failRenameNumber(t, 1)
	if err := s.Delete("tok"); !errors.Is(err, ErrMetadata) {
		t.Fatalf("first delete: %v", err)
	}
	beforeRename = nil
	b, _ := os.ReadFile(metaPath(dir))
	if !strings.Contains(string(b), "stale reason text") {
		t.Fatal("test setup: the record should still be in meta.json")
	}
	if err := s.Delete("tok"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retry: %v", err)
	}
	b, _ = os.ReadFile(metaPath(dir))
	if strings.Contains(string(b), "tok") || strings.Contains(string(b), "stale reason text") {
		t.Fatalf("retry left the record: %s", b)
	}
}

func TestDeleteOfOldNameRepairsFailedRename(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	must(t, s.Create("old", "private note", []byte("x")))
	failRenameNumber(t, 3)
	if err := s.Rename("old", "new"); !errors.Is(err, ErrMetadata) {
		t.Fatalf("rename: %v", err)
	}
	beforeRename = nil
	if err := s.Delete("old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete old: %v", err)
	}
	b, _ := os.ReadFile(metaPath(dir))
	if strings.Contains(string(b), `"old"`) {
		t.Fatalf("stale record remains: %s", b)
	}
	if m := mustGet(t, v, "new"); m.Description != "private note" {
		t.Fatalf("%+v", m)
	}
}

func TestDeletePruneFailureIsReported(t *testing.T) {
	_, s, _, _ := newClockSession(t)
	must(t, s.Create("tok", "", []byte("x")))
	failRenameNumber(t, 1)
	s.Delete("tok") // file removed, record write fails
	failRenameNumber(t, 1)
	err := s.Delete("tok")
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("a failed prune must not read as a plain not-found: %v", err)
	}
}

func TestDeleteOfMissingSecretLeavesMetadataAlone(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	must(t, s.Create("tok", "d", []byte("x")))
	before, _ := os.ReadFile(metaPath(dir))
	if err := s.Delete("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	after, _ := os.ReadFile(metaPath(dir))
	if !bytes.Equal(before, after) {
		t.Fatal("meta.json rewritten")
	}
	mustGet(t, v, "tok")
}

func TestSecretWithoutMetadataEntryIsListed(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	must(t, s.Create("tok", "d", []byte("x")))
	if err := os.Remove(metaPath(dir)); err != nil {
		t.Fatal(err)
	}
	m := mustGet(t, v, "tok")
	id, _ := v.KeyID("tok")
	if m.Name != "tok" || !bytes.Equal(m.KeyID, id) || m.Flag != nil || !m.Created.IsZero() {
		t.Fatalf("%+v", m)
	}
	list, err := v.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("%+v %v", list, err)
	}
	if err := v.SetDescription("tok", "again"); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, v, "tok").Description; got != "again" {
		t.Fatalf("description %q", got)
	}
}

func TestCorruptMetaFile(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	must(t, s.Create("tok", "d", []byte("x")))
	for _, body := range []string{"{not json", `{"version":9,"secrets":{}}`} {
		if err := os.WriteFile(metaPath(dir), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := v.List(); !errors.Is(err, ErrCorrupt) {
			t.Errorf("List %q: %v", body, err)
		}
		if _, err := v.Get("tok"); !errors.Is(err, ErrCorrupt) {
			t.Errorf("Get %q: %v", body, err)
		}
		if err := v.SetFlag("tok", Flag{Kind: "leaked"}); !errors.Is(err, ErrCorrupt) {
			t.Errorf("SetFlag %q: %v", body, err)
		}
		if err := s.UpdateValue("tok", []byte("y")); !errors.Is(err, ErrCorrupt) {
			t.Errorf("UpdateValue %q: %v", body, err)
		}
	}
	if val, _, err := s.Reveal("tok"); err != nil || string(val) != "x" {
		t.Fatalf("a corrupt meta.json must not change the secret: %q %v", val, err)
	}
}

func TestMetadataWritesHoldVaultLock(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	must(t, s.Create("tok", "", []byte("x")))
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ops := map[string]func() error{
		"description": func() error { return v.SetDescription("tok", "d") },
		"flag":        func() error { return v.SetFlag("tok", Flag{Kind: "leaked", Actor: "u"}) },
		"clear":       func() error { return v.ClearFlag("tok") },
		"granted":     func() error { return v.TouchGranted("tok", epoch) },
	}
	for name, op := range ops {
		op := op
		t.Run(name, func(t *testing.T) {
			inHook, release := make(chan struct{}), make(chan struct{})
			beforeRename = func() error {
				close(inHook)
				<-release
				return nil
			}
			t.Cleanup(func() { beforeRename = nil })
			done := make(chan error, 1)
			go func() { done <- op() }()
			<-inHook
			if other.mu.TryLock() {
				other.mu.Unlock()
				t.Error("directory lock not held during the metadata write")
			}
			beforeRename = nil
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !other.mu.TryLock() {
				t.Fatal("directory lock still held")
			}
			other.mu.Unlock()
		})
	}
}

func TestConcurrentMetadataUpdatesAreNotLost(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	const n = 16
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("s%02d", i)
		if err := s.Create(names[i], "", []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vv := v
			if i%2 == 1 {
				vv = other
			}
			if i%4 == 0 {
				errs[i] = vv.SetFlag(name, Flag{Kind: "invalid", Actor: "agent"})
			} else {
				errs[i] = vv.SetDescription(name, "d-"+name)
			}
		}()
	}
	wg.Wait()
	for i, name := range names {
		if errs[i] != nil {
			t.Fatalf("%s: %v", name, errs[i])
		}
		m := mustGet(t, v, name)
		if i%4 == 0 && m.Flag == nil || i%4 != 0 && m.Description != "d-"+name {
			t.Errorf("%s: lost update: %+v", name, m)
		}
	}
}

func TestNotifierRoundTrip(t *testing.T) {
	_, s, dir, _ := newClockSession(t)
	if err := s.SetNotifier(notifierToken, "4242"); err != nil {
		t.Fatal(err)
	}
	tok, chat, err := s.LoadNotifier()
	if err != nil || !bytes.Equal(tok, notifierToken) || chat != "4242" {
		t.Fatalf("%q %q %v", tok, chat, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "notifier.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, notifierToken) || bytes.Contains(raw, []byte("FAKE-bot-token")) {
		t.Fatal("notifier.json holds the token in plaintext")
	}
	if !bytes.Contains(raw, []byte("4242")) {
		t.Fatal("chat ID should be stored in plain")
	}
	fi, _ := os.Stat(filepath.Join(dir, "notifier.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestNotifierSurvivesNewSessionAndPassphraseChange(t *testing.T) {
	v, s, _, _ := newClockSession(t)
	must(t, s.SetNotifier(notifierToken, "4242"))
	if err := s.ChangePassphrase([]byte("fake-new-pass")); err != nil {
		t.Fatal(err)
	}
	s2, err := v.Unlock([]byte("fake-new-pass"))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	tok, chat, err := s2.LoadNotifier()
	if err != nil || !bytes.Equal(tok, notifierToken) || chat != "4242" {
		t.Fatalf("%q %q %v", tok, chat, err)
	}
}

func TestNotifierReplaceAndCallerOwnership(t *testing.T) {
	_, s, _, _ := newClockSession(t)
	must(t, s.SetNotifier(notifierToken, "1"))
	must(t, s.SetNotifier([]byte("999:FAKE-other"), "2"))
	tok, chat, err := s.LoadNotifier()
	if err != nil || string(tok) != "999:FAKE-other" || chat != "2" {
		t.Fatalf("%q %q %v", tok, chat, err)
	}
	for i := range tok {
		tok[i] = 0
	}
	again, _, _ := s.LoadNotifier()
	if string(again) != "999:FAKE-other" {
		t.Fatal("returned slice aliases stored state")
	}
	in := []byte("777:FAKE-in")
	must(t, s.SetNotifier(in, "3"))
	for i := range in {
		in[i] = 0
	}
	got, _, _ := s.LoadNotifier()
	if string(got) != "777:FAKE-in" {
		t.Fatalf("%q", got)
	}
}

func TestNotifierErrors(t *testing.T) {
	_, s, dir, _ := newClockSession(t)
	if _, _, err := s.LoadNotifier(); !errors.Is(err, ErrNoNotifier) {
		t.Fatalf("unset: %v", err)
	}
	if err := s.SetNotifier(nil, "1"); !errors.Is(err, ErrBadNotifier) {
		t.Fatalf("empty token: %v", err)
	}
	if err := s.SetNotifier(notifierToken, ""); !errors.Is(err, ErrBadNotifier) {
		t.Fatalf("empty chat: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notifier.json")); err == nil {
		t.Fatal("rejected input created the file")
	}
	must(t, s.SetNotifier(notifierToken, "1"))
	s.Close()
	if err := s.SetNotifier(notifierToken, "1"); !errors.Is(err, ErrClosed) {
		t.Fatalf("set after close: %v", err)
	}
	if _, _, err := s.LoadNotifier(); !errors.Is(err, ErrClosed) {
		t.Fatalf("load after close: %v", err)
	}
}

func TestNotifierIsBoundToVaultAndChatID(t *testing.T) {
	_, s, dir, _ := newClockSession(t)
	must(t, s.SetNotifier(notifierToken, "4242"))
	path := filepath.Join(dir, "notifier.json")
	raw, _ := os.ReadFile(path)

	// Another chat ID in the same file must not decrypt: the chat ID is
	// authenticated, so editing it cannot redirect notices.
	tampered := bytes.Replace(raw, []byte("4242"), []byte("9999"), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("test setup: chat ID not found in file")
	}
	os.WriteFile(path, tampered, 0o600)
	if tok, _, err := s.LoadNotifier(); err == nil || len(tok) != 0 {
		t.Fatalf("tampered chat ID accepted: %q %v", tok, err)
	}

	// A notifier file from a different vault does not open.
	_, other, otherDir, _ := newClockSession(t)
	other.SetNotifier(notifierToken, "4242")
	foreign, _ := os.ReadFile(filepath.Join(otherDir, "notifier.json"))
	os.WriteFile(path, foreign, 0o600)
	if _, _, err := s.LoadNotifier(); err == nil {
		t.Fatal("foreign notifier file accepted")
	}

	// A corrupt file is reported as corrupt, not as unset.
	os.WriteFile(path, []byte("{nope"), 0o600)
	if _, _, err := s.LoadNotifier(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v", err)
	}
}

func TestNotifierWriteIsAtomic(t *testing.T) {
	_, s, dir, _ := newClockSession(t)
	must(t, s.SetNotifier(notifierToken, "1"))
	path := filepath.Join(dir, "notifier.json")
	before, _ := os.ReadFile(path)
	beforeRename = func() error { return errors.New("injected") }
	t.Cleanup(func() { beforeRename = nil })
	if err := s.SetNotifier([]byte("999:FAKE-other"), "2"); err == nil {
		t.Fatal("write succeeded")
	}
	beforeRename = nil
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed write changed notifier.json")
	}
	tok, chat, err := s.LoadNotifier()
	if err != nil || !bytes.Equal(tok, notifierToken) || chat != "1" {
		t.Fatalf("%q %q %v", tok, chat, err)
	}
}

func TestNotifierWriteHoldsVaultLock(t *testing.T) {
	_, s, dir, _ := newClockSession(t)
	other, _ := Open(dir)
	inHook, release := make(chan struct{}), make(chan struct{})
	beforeRename = func() error {
		close(inHook)
		<-release
		return nil
	}
	t.Cleanup(func() { beforeRename = nil })
	done := make(chan error, 1)
	go func() { done <- s.SetNotifier(notifierToken, "1") }()
	<-inHook
	if other.mu.TryLock() {
		other.mu.Unlock()
		t.Error("directory lock not held during the notifier write")
	}
	beforeRename = nil
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
