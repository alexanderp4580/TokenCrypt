package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"tokencrypt/internal/crypto"
	"tokencrypt/internal/securemem"
)

var (
	testParams = crypto.Params{Time: 1, MemoryKiB: 64, Threads: 1}
	pass       = []byte("fake-pass-phrase-1")
	canary     = []byte("CANARY-fake-secret-value-7f3a")
)

func newSession(t *testing.T) (*Vault, *Session, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	if err := Init(dir, pass, testParams); err != nil {
		t.Fatal(err)
	}
	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.Unlock(pass)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return v, s, dir
}

func TestUnlockWrongPassphrase(t *testing.T) {
	v, _, _ := newSession(t)
	s, err := v.Unlock([]byte("wrong"))
	if !errors.Is(err, ErrWrongPassphrase) || s != nil {
		t.Fatalf("got %v, %v", s, err)
	}
}

func TestInitTwiceFails(t *testing.T) {
	_, _, dir := newSession(t)
	if err := Init(dir, pass, testParams); !errors.Is(err, ErrInitialized) {
		t.Fatalf("got %v", err)
	}
}

func TestRoundTripValues(t *testing.T) {
	_, s, _ := newSession(t)
	cases := map[string][]byte{
		"empty":     {},
		"multiline": []byte("a\nb\r\nc\n"),
		"binary":    {0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28},
		"max":       bytes.Repeat([]byte{'x'}, MaxValueBytes),
	}
	for name, val := range cases {
		if err := s.Create(name, "", val); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, id, err := s.Reveal(name)
		if err != nil || !bytes.Equal(got, val) || len(id) != 16 {
			t.Fatalf("%s: err=%v equal=%v id=%d", name, err, bytes.Equal(got, val), len(id))
		}
	}
	over := bytes.Repeat([]byte{'x'}, MaxValueBytes+1)
	if err := s.Create("over", "", over); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("create: %v", err)
	}
	if err := s.UpdateValue("max", over); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("update: %v", err)
	}
}

func TestNames(t *testing.T) {
	_, s, _ := newSession(t)
	for _, n := range []string{"../x", "a/b", "A", "a-b", "", strings.Repeat("a", 65), "1a", "_a"} {
		if err := s.Create(n, "", []byte("v")); !errors.Is(err, ErrBadName) {
			t.Errorf("%q: %v", n, err)
		}
		if ValidName(n) {
			t.Errorf("ValidName(%q)", n)
		}
	}
	if !ValidName(strings.Repeat("a", 64)) || !ValidName("a_1") {
		t.Error("valid names rejected")
	}
	if err := s.Create("dup", "", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("dup", "", []byte("2")); !errors.Is(err, ErrExists) {
		t.Fatalf("got %v", err)
	}
}

func TestNoPlaintextOnDisk(t *testing.T) {
	_, s, dir := newSession(t)
	if err := s.Create("tok", "d", canary); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateValue("tok", canary); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("tok", "tok2"); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassphrase([]byte("new-fake-pass")); err != nil {
		t.Fatal(err)
	}
	n := 0
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n++
		b, _ := os.ReadFile(p)
		for _, bad := range [][]byte{canary, pass, []byte("new-fake-pass")} {
			if bytes.Contains(b, bad) {
				t.Errorf("%s contains plaintext", p)
			}
		}
		return nil
	})
	if n < 2 {
		t.Fatalf("scanned %d files", n)
	}
}

func TestUpdateValue(t *testing.T) {
	v, s, dir := newSession(t)
	if err := s.Create("tok", "", []byte("one")); err != nil {
		t.Fatal(err)
	}
	oldID, _ := v.KeyID("tok")
	path := filepath.Join(dir, "secrets", "tok.json")
	oldRaw, _ := os.ReadFile(path)
	if err := s.UpdateValue("tok", []byte("two")); err != nil {
		t.Fatal(err)
	}
	val, newID, err := s.Reveal("tok")
	if err != nil || string(val) != "two" || bytes.Equal(oldID, newID) {
		t.Fatalf("val=%q err=%v sameID=%v", val, err, bytes.Equal(oldID, newID))
	}
	// Old ciphertext and wrapped DK moved into the new file's frame no longer open.
	var oldF, newF secretFile
	json.Unmarshal(oldRaw, &oldF)
	newRaw, _ := os.ReadFile(path)
	json.Unmarshal(newRaw, &newF)
	newF.Cipher = oldF.Cipher
	b, _ := json.Marshal(newF)
	os.WriteFile(path, b, 0o600)
	if _, _, err := s.Reveal("tok"); err == nil {
		t.Fatal("old ciphertext opened under new key")
	}
	if err := s.UpdateValue("missing", []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestRename(t *testing.T) {
	v, s, _ := newSession(t)
	s.Create("old", "", canary)
	if err := s.Rename("old", "new"); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.Reveal("new")
	if err != nil || !bytes.Equal(got, canary) {
		t.Fatalf("%q %v", got, err)
	}
	if _, _, err := s.Reveal("old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if v.Exists("old") || !v.Exists("new") {
		t.Fatal("Exists wrong")
	}
	s.Create("other", "", []byte("x"))
	if err := s.Rename("new", "other"); !errors.Is(err, ErrExists) {
		t.Fatalf("got %v", err)
	}
	if err := s.Rename("nope", "z"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := s.Rename("new", "Bad"); !errors.Is(err, ErrBadName) {
		t.Fatalf("got %v", err)
	}
}

func TestDelete(t *testing.T) {
	v, s, dir := newSession(t)
	s.Create("tok", "", []byte("x"))
	if err := s.Delete("tok"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", "tok.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file remains")
	}
	if _, _, err := s.Reveal("tok"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := s.Delete("tok"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if _, err := v.KeyID("tok"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestSwappedFilesFail(t *testing.T) {
	_, s, dir := newSession(t)
	s.Create("aa", "", []byte("one"))
	s.Create("bb", "", []byte("two"))
	pa, pb := filepath.Join(dir, "secrets", "aa.json"), filepath.Join(dir, "secrets", "bb.json")
	a, _ := os.ReadFile(pa)
	b, _ := os.ReadFile(pb)

	// Whole files swapped.
	os.WriteFile(pa, b, 0o600)
	os.WriteFile(pb, a, 0o600)
	for _, n := range []string{"aa", "bb"} {
		if _, _, err := s.Reveal(n); err == nil {
			t.Errorf("whole-file swap: %s revealed", n)
		}
	}

	// Name and key ID kept, wrapped DK and ciphertext swapped.
	var fa, fb secretFile
	json.Unmarshal(a, &fa)
	json.Unmarshal(b, &fb)
	fa.WrappedDK, fb.WrappedDK = fb.WrappedDK, fa.WrappedDK
	fa.Cipher, fb.Cipher = fb.Cipher, fa.Cipher
	ja, _ := json.Marshal(fa)
	jb, _ := json.Marshal(fb)
	os.WriteFile(pa, ja, 0o600)
	os.WriteFile(pb, jb, 0o600)
	for _, n := range []string{"aa", "bb"} {
		if _, _, err := s.Reveal(n); !errors.Is(err, crypto.ErrAuth) {
			t.Errorf("field swap: %s: %v", n, err)
		}
	}
}

func TestChangePassphrase(t *testing.T) {
	v, s, _ := newSession(t)
	s.Create("tok", "", canary)
	np := []byte("new-fake-pass")
	if err := s.ChangePassphrase(np); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Unlock(pass); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("old: %v", err)
	}
	s2, err := v.Unlock(np)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, _, err := s2.Reveal("tok")
	if err != nil || !bytes.Equal(got, canary) {
		t.Fatalf("%q %v", got, err)
	}
}

func TestPermissions(t *testing.T) {
	_, s, dir := newSession(t)
	s.Create("tok", "", []byte("x"))
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, _ := d.Info()
		want := fs.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s: %v want %v", p, info.Mode().Perm(), want)
		}
		return nil
	})
}

func TestCrashBeforeRename(t *testing.T) {
	v, s, dir := newSession(t)
	s.Create("tok", "", []byte("old"))
	beforeRename = func() error { return errors.New("injected") }
	t.Cleanup(func() { beforeRename = nil })

	if err := s.UpdateValue("tok", []byte("new")); err == nil {
		t.Fatal("update succeeded")
	}
	if err := s.Create("fresh", "", []byte("x")); err == nil {
		t.Fatal("create succeeded")
	}
	if err := s.ChangePassphrase([]byte("zzz")); err == nil {
		t.Fatal("change succeeded")
	}
	beforeRename = nil
	got, _, err := s.Reveal("tok")
	if err != nil || string(got) != "old" {
		t.Fatalf("%q %v", got, err)
	}
	if v.Exists("fresh") {
		t.Fatal("partial target exists")
	}
	if _, err := v.Unlock(pass); err != nil {
		t.Fatalf("old passphrase: %v", err)
	}
	for _, d := range []string{dir, filepath.Join(dir, "secrets")} {
		es, _ := os.ReadDir(d)
		for _, e := range es {
			if strings.HasPrefix(e.Name(), ".tmp") {
				t.Errorf("leftover %s", e.Name())
			}
		}
	}
}

func TestSessionClose(t *testing.T) {
	_, s, _ := newSession(t)
	s.Create("tok", "", []byte("x"))
	mk := s.mk
	s.Close()
	if !bytes.Equal(mk, make([]byte, len(mk))) {
		t.Fatal("MK not zeroed")
	}
	if _, _, err := s.Reveal("tok"); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
	if _, err := s.DeriveKey("x"); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
}

func TestSessionAttemptsMasterKeyLockAndReleasesIt(t *testing.T) {
	before := securemem.Snapshot()
	_, s, _ := newSession(t)
	during := securemem.Snapshot()
	if during.Attempts <= before.Attempts {
		t.Fatal("master key never attempted mlock")
	}
	s.Close()
	if after := securemem.Snapshot(); after.LockedBytes != before.LockedBytes {
		t.Fatal("session close retained locked pages")
	}
}

func TestRevealIsCallerOwned(t *testing.T) {
	_, s, _ := newSession(t)
	s.Create("tok", "", []byte("secret"))
	a, _, _ := s.Reveal("tok")
	crypto.Zero(a)
	b, _, _ := s.Reveal("tok")
	if string(b) != "secret" {
		t.Fatal("shared buffer")
	}
}

func TestDeriveKey(t *testing.T) {
	_, s, _ := newSession(t)
	a, err := s.DeriveKey("l1")
	b, _ := s.DeriveKey("l1")
	c, _ := s.DeriveKey("l2")
	if err != nil || len(a) != 32 || !bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Fatal("DeriveKey wrong")
	}
}

func TestParamBounds(t *testing.T) {
	bad := []crypto.Params{
		{Time: 0, MemoryKiB: 64, Threads: 1},
		{Time: 1, MemoryKiB: 64, Threads: 0},
		{Time: 1, MemoryKiB: 63, Threads: 1},
		{Time: 1, MemoryKiB: 1<<20 + 1, Threads: 1},
		{Time: 101, MemoryKiB: 64, Threads: 1},
		{Time: 1, MemoryKiB: 1024, Threads: 17},
	}
	for _, p := range bad {
		if err := Init(filepath.Join(t.TempDir(), "v"), pass, p); !errors.Is(err, ErrBadParams) {
			t.Errorf("Init %+v: %v", p, err)
		}
	}
	// Tampered header on disk: Open and Unlock refuse before running Argon2.
	for _, p := range bad {
		v, _, dir := newSession(t)
		path := filepath.Join(dir, "header.json")
		raw, _ := os.ReadFile(path)
		var h header
		json.Unmarshal(raw, &h)
		h.Params = p
		b, _ := json.Marshal(h)
		os.WriteFile(path, b, 0o600)
		if _, err := Open(dir); !errors.Is(err, ErrBadParams) {
			t.Errorf("Open %+v: %v", p, err)
		}
		if _, err := v.Unlock(pass); !errors.Is(err, ErrBadParams) {
			t.Errorf("Unlock %+v: %v", p, err)
		}
	}
	// Edges of the accepted range pass the check.
	for _, p := range []crypto.Params{
		{Time: 1, MemoryKiB: 64, Threads: 1},
		{Time: 100, MemoryKiB: 1 << 20, Threads: 16},
		crypto.DefaultParams(),
	} {
		if err := checkParams(p); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
}

// sessionsOn unlocks n sessions on dir. Sessions 0..n-2 each use their own
// Open; the last one shares the Vault of session 0 and has its own Unlock.
func sessionsOn(t *testing.T, dir string, n int) []*Session {
	t.Helper()
	var vs []*Vault
	var out []*Session
	for i := 0; i < n; i++ {
		var v *Vault
		if i == n-1 && len(vs) > 0 {
			v = vs[0]
		} else {
			var err error
			if v, err = Open(dir); err != nil {
				t.Fatal(err)
			}
			vs = append(vs, v)
		}
		s, err := v.Unlock(pass)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		out = append(out, s)
	}
	return out
}

// runTogether starts every fn after a shared barrier and returns their errors.
func runTogether(fns []func() error) []error {
	errs := make([]error, len(fns))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fn()
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

// winner returns the index of the only nil error and fails unless every other
// error satisfies one of the allowed errors.
func winner(t *testing.T, errs []error, allowed ...error) int {
	t.Helper()
	w := -1
	for i, err := range errs {
		if err == nil {
			if w >= 0 {
				t.Fatalf("workers %d and %d both succeeded", w, i)
			}
			w = i
			continue
		}
		ok := false
		for _, a := range allowed {
			ok = ok || errors.Is(err, a)
		}
		if !ok {
			t.Fatalf("worker %d: unexpected error %v", i, err)
		}
	}
	if w < 0 {
		t.Fatal("no worker succeeded")
	}
	return w
}

func TestConcurrentCreateSameNameAcrossSessions(t *testing.T) {
	_, _, dir := newSession(t)
	ss := sessionsOn(t, dir, 6)
	for round := 0; round < 5; round++ {
		name := "same" + string(rune('a'+round))
		vals := make([][]byte, len(ss))
		fns := make([]func() error, len(ss))
		for i, s := range ss {
			vals[i] = []byte("fake-value-" + string(rune('0'+i)))
			fns[i] = func() error { return s.Create(name, "", vals[i]) }
		}
		w := winner(t, runTogether(fns), ErrExists)
		got, _, err := ss[0].Reveal(name)
		if err != nil || !bytes.Equal(got, vals[w]) {
			t.Fatalf("%s: stored %q (%v), winner wrote %q", name, got, err, vals[w])
		}
	}
}

func TestConcurrentCreateAndRenameToSameName(t *testing.T) {
	_, _, dir := newSession(t)
	ss := sessionsOn(t, dir, 4)
	for _, n := range []string{"srca", "srcb"} {
		if err := ss[0].Create(n, "", []byte("fake-"+n)); err != nil {
			t.Fatal(err)
		}
	}
	vals := []string{"fake-created", "fake-srca", "fake-srcb", "fake-srca"}
	fns := []func() error{
		func() error { return ss[0].Create("dst", "", []byte(vals[0])) },
		func() error { return ss[1].Rename("srca", "dst") },
		func() error { return ss[2].Rename("srcb", "dst") },
		func() error { return ss[3].Rename("srca", "dst") },
	}
	w := winner(t, runTogether(fns), ErrExists, ErrNotFound)
	got, _, err := ss[0].Reveal("dst")
	if err != nil || string(got) != vals[w] {
		t.Fatalf("stored %q (%v), winner %d wrote %q", got, err, w, vals[w])
	}
}

func TestConcurrentInitOneWins(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	passes := make([][]byte, 6)
	fns := make([]func() error, len(passes))
	for i := range passes {
		passes[i] = []byte("fake-init-pass-" + string(rune('0'+i)))
		fns[i] = func() error { return Init(dir, passes[i], testParams) }
	}
	w := winner(t, runTogether(fns), ErrInitialized)
	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.Unlock(passes[w])
	if err != nil {
		t.Fatalf("winner passphrase: %v", err)
	}
	s.Close()
}

func TestVaultLockSharedByDirectory(t *testing.T) {
	_, _, dir := newSession(t)
	a, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	c, err := Open(link)
	if err != nil {
		t.Fatal(err)
	}
	if a.mu != b.mu || a.mu != c.mu {
		t.Fatal("Open objects for one directory use different locks")
	}
	_, _, other := newSession(t)
	o, err := Open(other)
	if err != nil {
		t.Fatal(err)
	}
	if o.mu == a.mu {
		t.Fatal("unrelated vaults share a lock")
	}
}

// TestWritesHoldVaultLock blocks each mutating operation after its check and
// temporary-file write and expects the directory lock, as seen through a
// second Open, to be held for exactly that time.
func TestWritesHoldVaultLock(t *testing.T) {
	_, _, dir := newSession(t)
	ss := sessionsOn(t, dir, 2)
	if err := ss[0].Create("tok", "", []byte("fake")); err != nil {
		t.Fatal(err)
	}
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, unrelated, _ := newSession(t)
	ops := []struct {
		name string
		op   func() error
	}{
		{"create", func() error { return ss[0].Create("fresh", "", []byte("x")) }},
		{"update", func() error { return ss[0].UpdateValue("tok", []byte("y")) }},
		{"passphrase", func() error { return ss[0].ChangePassphrase([]byte("fake-new-pass")) }},
		{"rename", func() error { return ss[0].Rename("tok", "moved") }},
	}
	for _, c := range ops {
		op := c.op
		t.Run(c.name, func(t *testing.T) {
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
				t.Error("directory lock not held during write")
			}
			if !unrelated.v.mu.TryLock() {
				t.Error("unrelated vault lock is held")
			} else {
				unrelated.v.mu.Unlock()
			}
			beforeRename = nil
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !other.mu.TryLock() {
				t.Fatal("directory lock still held after the operation")
			}
			other.mu.Unlock()
		})
	}
}

func TestFailedAndClosedOperationsReleaseVaultLock(t *testing.T) {
	v, s, _ := newSession(t)
	s.Create("tok", "", []byte("x"))
	for _, err := range []error{
		s.Create("tok", "", []byte("x")),
		s.Create("Bad", "", nil),
		s.UpdateValue("missing", nil),
		s.Rename("missing", "z"),
		s.Rename("tok", "tok"),
		s.Delete("missing"),
	} {
		if err == nil {
			t.Fatal("expected an error")
		}
	}
	s.Close()
	for _, err := range []error{
		s.Create("n", "", nil),
		s.UpdateValue("tok", nil),
		s.Rename("tok", "z"),
		s.Delete("tok"),
		s.ChangePassphrase([]byte("p")),
	} {
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("got %v", err)
		}
	}
	if !v.mu.TryLock() {
		t.Fatal("vault lock leaked")
	}
	v.mu.Unlock()
}

func TestClosingOneSessionLeavesOthersUsable(t *testing.T) {
	_, _, dir := newSession(t)
	ss := sessionsOn(t, dir, 2)
	mk0 := ss[0].mk
	ss[0].Close()
	if !bytes.Equal(mk0, make([]byte, len(mk0))) {
		t.Fatal("MK not zeroed")
	}
	if err := ss[1].Create("tok", "", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := ss[0].Create("tok2", "", []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
}

// recordSyncDir replaces syncDir for one test. check runs inside each call and
// may return an error to inject.
func recordSyncDir(t *testing.T, check func(dir string) error) *[]string {
	t.Helper()
	var calls []string
	orig := syncDir
	syncDir = func(dir string) error {
		calls = append(calls, dir)
		return check(dir)
	}
	t.Cleanup(func() { syncDir = orig })
	return &calls
}

func TestDeleteSyncsSecretsDirAfterUnlink(t *testing.T) {
	_, s, dir := newSession(t)
	s.Create("tok", "", []byte("x"))
	secrets := filepath.Join(dir, "secrets")
	target := filepath.Join(secrets, "tok.json")
	calls := recordSyncDir(t, func(d string) error {
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("syncDir(%s) ran before unlink", d)
		}
		return nil
	})
	if err := s.Delete("tok"); err != nil {
		t.Fatal(err)
	}
	// The secrets directory is synced right after the unlink; the metadata
	// write then syncs the vault directory.
	if len(*calls) != 2 || (*calls)[0] != secrets || (*calls)[1] != dir {
		t.Fatalf("syncDir calls: %v", *calls)
	}
}

func TestDeleteReportsSyncFailure(t *testing.T) {
	_, s, _ := newSession(t)
	s.Create("tok", "", []byte("x"))
	injected := errors.New("injected sync failure")
	recordSyncDir(t, func(string) error { return injected })
	if err := s.Delete("tok"); !errors.Is(err, injected) {
		t.Fatalf("got %v", err)
	}
}

func TestRenameSyncsSecretsDirAfterUnlink(t *testing.T) {
	_, s, dir := newSession(t)
	s.Create("old", "", []byte("x"))
	secrets := filepath.Join(dir, "secrets")
	oldFile := filepath.Join(secrets, "old.json")
	var afterUnlink []string
	recordSyncDir(t, func(d string) error {
		if _, err := os.Stat(oldFile); errors.Is(err, os.ErrNotExist) {
			afterUnlink = append(afterUnlink, d)
		}
		return nil
	})
	if err := s.Rename("old", "new"); err != nil {
		t.Fatal(err)
	}
	if len(afterUnlink) != 2 || afterUnlink[0] != secrets || afterUnlink[1] != dir {
		t.Fatalf("syncs after unlink: %v", afterUnlink)
	}
}

func TestRenameReportsSyncFailureAfterUnlink(t *testing.T) {
	_, s, dir := newSession(t)
	s.Create("old", "", []byte("x"))
	oldFile := filepath.Join(dir, "secrets", "old.json")
	injected := errors.New("injected sync failure")
	recordSyncDir(t, func(string) error {
		if _, err := os.Stat(oldFile); errors.Is(err, os.ErrNotExist) {
			return injected
		}
		return nil
	})
	if err := s.Rename("old", "new"); !errors.Is(err, injected) {
		t.Fatalf("got %v", err)
	}
}
