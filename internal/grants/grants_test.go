package grants

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tokencrypt/internal/clock"
	"tokencrypt/internal/securemem"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func TestLiveValueAttemptsLockAndRevokeReleasesIt(t *testing.T) {
	before := securemem.Snapshot()
	chk := newChecker()
	chk.setKey("api_token", 1)
	clk := clock.NewFake(t0)
	m := New(clk, t.TempDir(), chk)
	defer m.Close()
	g := Grant{ID: "fake-lock", Secret: "api_token", KeyID: chk.keyID("api_token"), Expires: t0.Add(time.Minute)}
	if err := m.Add(g, []byte("fake-value"), nil); err != nil {
		t.Fatal(err)
	}
	if during := securemem.Snapshot(); during.Attempts <= before.Attempts {
		t.Fatal("live value never attempted mlock")
	}
	if err := m.Revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	if after := securemem.Snapshot(); after.LockedBytes != before.LockedBytes {
		t.Fatal("revocation retained locked pages")
	}
}

// fakeChecker is a Checker over an in-memory table of secrets.
type fakeChecker struct {
	mu      sync.Mutex
	flagged map[string]bool
	keys    map[string][]byte
}

func newChecker() *fakeChecker {
	return &fakeChecker{flagged: map[string]bool{}, keys: map[string][]byte{}}
}

func (c *fakeChecker) Flagged(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.flagged[name]
}

func (c *fakeChecker) KeyID(name string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k, ok := c.keys[name]
	if !ok {
		return nil, errors.New("fake: no such secret")
	}
	return bytes.Clone(k), nil
}

func (c *fakeChecker) setKey(name string, b byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys[name] = bytes.Repeat([]byte{b}, 16)
}

func (c *fakeChecker) setFlagged(name string, on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flagged[name] = on
}

func (c *fakeChecker) keyID(name string) []byte {
	k, _ := c.KeyID(name)
	return k
}

type env struct {
	t   *testing.T
	clk *clock.Fake
	chk *fakeChecker
	dir string
	mac []byte
}

func newEnv(t *testing.T, secrets ...string) *env {
	t.Helper()
	chk := newChecker()
	for i, s := range secrets {
		chk.setKey(s, byte(i+1))
	}
	return &env{t: t, clk: clock.NewFake(t0), chk: chk, dir: t.TempDir(), mac: bytes.Repeat([]byte{7}, 32)}
}

// manager returns a new, locked Manager on the env's directory.
func (e *env) manager() *Manager {
	m := New(e.clk, e.dir, e.chk)
	e.t.Cleanup(m.Close)
	return m
}

// open returns a Manager that is already unlocked.
func (e *env) open() *Manager {
	m := e.manager()
	m.SetLocked(false)
	return m
}

func (e *env) grant(id, secret string, d time.Duration) Grant {
	return Grant{
		ID: id, Secret: secret, KeyID: e.chk.keyID(secret),
		Expires: e.clk.Wall().Add(d), GrantedBy: "user", RequestID: "req-" + id,
	}
}

func (e *env) add(m *Manager, id, secret string, d time.Duration, value string) {
	e.t.Helper()
	if err := m.Add(e.grant(id, secret, d), []byte(value), e.mac); err != nil {
		e.t.Fatalf("Add %s: %v", id, err)
	}
}

func (e *env) path() string { return filepath.Join(e.dir, "grants.json") }

// records returns the records stored in grants.json; none if the file is absent.
func (e *env) records() []map[string]any {
	e.t.Helper()
	b, err := os.ReadFile(e.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		e.t.Fatal(err)
	}
	var f struct {
		Grants []map[string]any `json:"grants"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		e.t.Fatal(err)
	}
	return f.Grants
}

func (e *env) recordIDs() []string {
	var ids []string
	for _, r := range e.records() {
		ids = append(ids, r["id"].(string))
	}
	sort.Strings(ids)
	return ids
}

// edit applies fn to every record of grants.json and writes the file back.
func (e *env) edit(fn func(r map[string]any)) {
	e.t.Helper()
	b, err := os.ReadFile(e.path())
	if err != nil {
		e.t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		e.t.Fatal(err)
	}
	for _, g := range doc["grants"].([]any) {
		fn(g.(map[string]any))
	}
	out, err := json.Marshal(doc)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(e.path(), out, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// storedValue returns the buffer the Manager holds for grant id, aliased.
func (m *Manager) storedValue(id string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.live[id].value
}

func allZero(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func mustRead(t *testing.T, m *Manager, name string) (string, Grant) {
	t.Helper()
	v, g, err := m.Read(name)
	if err != nil {
		t.Fatalf("Read %s: %v", name, err)
	}
	return string(v), g
}

func ids(gs []Grant) []string {
	var out []string
	for _, g := range gs {
		out = append(out, g.ID)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReadReturnsValueUntilExpires(t *testing.T) {
	e := newEnv(t, "api")
	m := e.open()
	e.add(m, "g1", "api", 10*time.Minute, "fake-api-value")
	buf := m.storedValue("g1")

	e.clk.AdvanceWall(10*time.Minute - time.Nanosecond)
	e.clk.AdvanceMono(10*time.Minute - time.Nanosecond)
	v, g := mustRead(t, m, "api")
	if v != "fake-api-value" || g.ID != "g1" || g.Secret != "api" || g.GrantedBy != "user" || g.RequestID != "req-g1" {
		t.Fatalf("Read = %q %+v", v, g)
	}
	if allZero(buf) {
		t.Fatal("buffer zeroed before expiry")
	}

	e.clk.AdvanceWall(time.Nanosecond)
	_, _, err := m.Read("api")
	wantErr(t, err, ErrNoGrant)
	if !allZero(buf) {
		t.Fatalf("stored buffer not zeroed at expiry: %q", buf)
	}
	if len(m.List()) != 0 {
		t.Fatal("expired grant still listed")
	}
}

func TestWallClockJumpExpiresWithoutMonotonicAdvance(t *testing.T) {
	e := newEnv(t, "api")
	m := e.open()
	e.add(m, "g1", "api", 10*time.Minute, "fake-api-value")
	buf := m.storedValue("g1")

	e.clk.SetWall(t0.Add(2 * time.Hour))
	_, _, err := m.Read("api")
	wantErr(t, err, ErrNoGrant)
	if !allZero(buf) {
		t.Fatal("buffer not zeroed after wall jump")
	}
}

func TestMonotonicAdvanceExpiresWithoutWallAdvance(t *testing.T) {
	e := newEnv(t, "api")
	m := e.open()
	e.add(m, "g1", "api", 10*time.Minute, "fake-api-value")
	buf := m.storedValue("g1")

	e.clk.AdvanceMono(9 * time.Minute)
	mustRead(t, m, "api")
	e.clk.AdvanceMono(time.Minute)
	_, _, err := m.Read("api")
	wantErr(t, err, ErrNoGrant)
	if !allZero(buf) {
		t.Fatal("buffer not zeroed after monotonic expiry")
	}
}

func TestMonotonicTrackedUpTo24HoursOnly(t *testing.T) {
	e := newEnv(t, "api", "db")
	m := e.open()
	e.add(m, "day", "api", 24*time.Hour, "fake-day-value")
	e.add(m, "week", "db", 7*24*time.Hour, "fake-week-value")

	e.clk.AdvanceMono(25 * time.Hour)
	_, _, err := m.Read("api")
	wantErr(t, err, ErrNoGrant)
	if v, _ := mustRead(t, m, "db"); v != "fake-week-value" {
		t.Fatalf("long grant value = %q", v)
	}
	e.clk.SetWall(t0.Add(8 * 24 * time.Hour))
	_, _, err = m.Read("db")
	wantErr(t, err, ErrNoGrant)
}

func TestRevokeRemovesGrantAndZeroesValue(t *testing.T) {
	e := newEnv(t, "api", "db")
	m := e.open()
	e.add(m, "g1", "api", 10*time.Minute, "fake-api-value")
	e.add(m, "g2", "db", 10*time.Minute, "fake-db-value")
	buf := m.storedValue("g1")

	if err := m.Revoke("g1"); err != nil {
		t.Fatal(err)
	}
	_, _, err := m.Read("api")
	wantErr(t, err, ErrNoGrant)
	if !allZero(buf) {
		t.Fatal("revoked buffer not zeroed")
	}
	wantErr(t, m.Revoke("g1"), ErrNoGrant)
	if v, _ := mustRead(t, m, "db"); v != "fake-db-value" {
		t.Fatalf("other grant = %q", v)
	}
}

func TestRevokeSecretRemovesAllGrantsOfSecretAndCounts(t *testing.T) {
	e := newEnv(t, "api", "db")
	m := e.open()
	e.add(m, "g1", "api", 10*time.Minute, "fake-api-value")
	e.add(m, "g2", "api", 20*time.Minute, "fake-api-value")
	e.add(m, "g3", "db", 10*time.Minute, "fake-db-value")
	b1, b2 := m.storedValue("g1"), m.storedValue("g2")

	if n := m.RevokeSecret("api"); n != 2 {
		t.Fatalf("RevokeSecret = %d, want 2", n)
	}
	if !allZero(b1) || !allZero(b2) {
		t.Fatal("revoked buffers not zeroed")
	}
	_, _, err := m.Read("api")
	wantErr(t, err, ErrNoGrant)
	if n := m.RevokeSecret("api"); n != 0 {
		t.Fatalf("second RevokeSecret = %d, want 0", n)
	}
	if got := ids(m.List()); !equalStrings(got, []string{"g3"}) {
		t.Fatalf("List = %v", got)
	}
}

func TestGrantNeverReturnsAnotherSecretsValue(t *testing.T) {
	e := newEnv(t, "api", "db")
	m := e.open()
	e.add(m, "g1", "api", 10*time.Minute, "fake-api-value")

	_, _, err := m.Read("db")
	wantErr(t, err, ErrNoGrant)
	e.add(m, "g2", "db", 10*time.Minute, "fake-db-value")
	if v, _ := mustRead(t, m, "db"); v != "fake-db-value" {
		t.Fatalf("db = %q", v)
	}
	if v, _ := mustRead(t, m, "api"); v != "fake-api-value" {
		t.Fatalf("api = %q", v)
	}
}

func TestReadPrefersLatestExpiryForSecret(t *testing.T) {
	e := newEnv(t, "api")
	m := e.open()
	e.add(m, "short", "api", 10*time.Minute, "fake-api-value")
	e.add(m, "long", "api", 30*time.Minute, "fake-api-value")
	if _, g := mustRead(t, m, "api"); g.ID != "long" {
		t.Fatalf("Read used grant %s", g.ID)
	}
	if err := m.Revoke("long"); err != nil {
		t.Fatal(err)
	}
	if _, g := mustRead(t, m, "api"); g.ID != "short" {
		t.Fatalf("Read used grant %s", g.ID)
	}
}

func TestListIsSortedByExpiry(t *testing.T) {
	e := newEnv(t, "api", "db", "s3")
	m := e.open()
	e.add(m, "b", "api", 30*time.Minute, "v1")
	e.add(m, "a", "db", 20*time.Minute, "v2")
	e.add(m, "c", "s3", 10*time.Minute, "v3")
	var got []string
	for _, g := range m.List() {
		got = append(got, g.ID)
	}
	if !equalStrings(got, []string{"c", "a", "b"}) {
		t.Fatalf("List order = %v", got)
	}
}

func TestBoundaryBuffersAreCopies(t *testing.T) {
	e := newEnv(t, "api")
	m := e.open()
	value := []byte("fake-owned-value")
	g := e.grant("g1", "api", 10*time.Minute)
	wantKey := bytes.Clone(g.KeyID)
	if err := m.Add(g, value, e.mac); err != nil {
		t.Fatal(err)
	}
	clear(value)
	clear(g.KeyID)

	v, got, err := m.Read("api")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "fake-owned-value" || !bytes.Equal(got.KeyID, wantKey) {
		t.Fatalf("Add kept the caller's buffers: %q %x", v, got.KeyID)
	}
	clear(v)
	clear(got.KeyID)
	l := m.List()
	clear(l[0].KeyID)
	v2, got2, _ := m.Read("api")
	if string(v2) != "fake-owned-value" || !bytes.Equal(got2.KeyID, wantKey) {
		t.Fatalf("Read/List returned internal buffers: %q %x", v2, got2.KeyID)
	}
}

func TestShortGrantsAreNotPersisted(t *testing.T) {
	e := newEnv(t, "api")
	m := e.open()
	e.add(m, "g1", "api", time.Hour, "fake-api-value")
	if _, err := os.Stat(e.path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("grants.json exists for a 1 hour grant: %v", err)
	}
}

func TestLongGrantsArePersistedWithoutValue(t *testing.T) {
	e := newEnv(t, "api")
	m := e.open()
	value := "fake-persisted-value"
	e.add(m, "g1", "api", time.Hour+time.Second, value)

	recs := e.records()
	if len(recs) != 1 || recs[0]["id"] != "g1" || recs[0]["secret"] != "api" {
		t.Fatalf("records = %v", recs)
	}
	raw, err := os.ReadFile(e.path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(value)) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(value)))) {
		t.Fatalf("grants.json holds the value: %s", raw)
	}
	st, err := os.Stat(e.path())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("grants.json mode = %v", st.Mode().Perm())
	}
}

func TestNewManagerStartsEmptyAndLocked(t *testing.T) {
	e := newEnv(t, "api")
	a := e.open()
	e.add(a, "g1", "api", 48*time.Hour, "fake-api-value")

	b := e.manager()
	if len(b.List()) != 0 {
		t.Fatal("new manager lists grants")
	}
	_, _, err := b.Read("api")
	wantErr(t, err, ErrLocked)
	if _, err := b.Candidates(e.mac); err != nil {
		t.Fatal(err)
	}
	_, _, err = b.Read("api")
	wantErr(t, err, ErrLocked)
}

func TestShortGrantsDoNotSurviveRestart(t *testing.T) {
	e := newEnv(t, "api")
	a := e.open()
	e.add(a, "g1", "api", 30*time.Minute, "fake-api-value")
	b := e.manager()
	c, err := b.Candidates(e.mac)
	if err != nil || len(c) != 0 {
		t.Fatalf("Candidates = %v, %v", c, err)
	}
}

func candidateEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, "api", "db", "s3", "s4", "s5", "s6")
	a := e.open()
	e.add(a, "g-good", "api", 48*time.Hour, "fake-v1")
	e.add(a, "g-short", "db", 2*time.Hour, "fake-v2")
	e.add(a, "g-flag", "s3", 48*time.Hour, "fake-v3")
	e.add(a, "g-key", "s4", 48*time.Hour, "fake-v4")
	e.add(a, "g-mac", "s5", 48*time.Hour, "fake-v5")
	e.add(a, "g-exp", "s6", 48*time.Hour, "fake-v6")
	return e
}

func TestCandidatesKeepOnlyVerifiedCurrentRecords(t *testing.T) {
	e := candidateEnv(t)
	e.edit(func(r map[string]any) {
		switch r["id"] {
		case "g-mac":
			mac, _ := base64.StdEncoding.DecodeString(r["mac"].(string))
			mac[0] ^= 0xff
			r["mac"] = base64.StdEncoding.EncodeToString(mac)
		case "g-exp":
			exp, err := time.Parse(time.RFC3339Nano, r["expires"].(string))
			if err != nil {
				t.Fatal(err)
			}
			r["expires"] = exp.Add(time.Hour).Format(time.RFC3339Nano)
		}
	})
	e.clk.AdvanceWall(3 * time.Hour)
	e.chk.setFlagged("s3", true)
	e.chk.setKey("s4", 99)

	b := e.manager()
	before, _ := os.ReadFile(e.path())
	got, err := b.Candidates(e.mac)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"g-good"}; !equalStrings(ids(got), want) {
		t.Fatalf("Candidates = %v, want %v", ids(got), want)
	}
	if got[0].Secret != "api" || !bytes.Equal(got[0].KeyID, e.chk.keyID("api")) || !got[0].Expires.Equal(t0.Add(48*time.Hour)) {
		t.Fatalf("candidate = %+v", got[0])
	}
	after, _ := os.ReadFile(e.path())
	if !bytes.Equal(before, after) {
		t.Fatal("Candidates modified grants.json")
	}
}

func TestCandidatesNeedFreshMacKey(t *testing.T) {
	e := newEnv(t, "api")
	a := e.open()
	e.add(a, "g1", "api", 48*time.Hour, "fake-api-value")
	b := e.manager()

	_, err := b.Candidates(nil)
	wantErr(t, err, ErrNoKey)
	_, err = b.Candidates([]byte("short"))
	wantErr(t, err, ErrNoKey)
	got, err := b.Candidates(bytes.Repeat([]byte{8}, 32))
	if err != nil || len(got) != 0 {
		t.Fatalf("wrong key: %v, %v", got, err)
	}
	if got, err = b.Candidates(e.mac); err != nil || len(got) != 1 {
		t.Fatalf("right key: %v, %v", got, err)
	}
}

func TestRestoreLoadsOnlyConfirmedIDs(t *testing.T) {
	e := newEnv(t, "api", "db")
	a := e.open()
	e.add(a, "g1", "api", 48*time.Hour, "fake-api-value")
	e.add(a, "g2", "db", 48*time.Hour, "fake-db-value")

	b := e.manager()
	if _, err := b.Candidates(e.mac); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"api": "fake-api-value", "db": "fake-db-value"}
	var revealed []string
	reveal := func(name string) ([]byte, error) {
		revealed = append(revealed, name)
		return []byte(values[name]), nil
	}
	if err := b.Restore([]string{"g1"}, reveal); err != nil {
		t.Fatal(err)
	}
	if !equalStrings(revealed, []string{"api"}) {
		t.Fatalf("reveal called for %v", revealed)
	}
	v, g := mustRead(t, b, "api")
	if v != "fake-api-value" || g.ID != "g1" || !g.Expires.Equal(t0.Add(48*time.Hour)) {
		t.Fatalf("restored = %q %+v", v, g)
	}
	_, _, err := b.Read("db")
	wantErr(t, err, ErrNoGrant)
	if got := e.recordIDs(); !equalStrings(got, []string{"g1"}) {
		t.Fatalf("records after restore = %v", got)
	}
}

func TestRestoredGrantExpiresAndLeavesFile(t *testing.T) {
	e := newEnv(t, "api")
	a := e.open()
	e.add(a, "g1", "api", 48*time.Hour, "fake-api-value")
	b := e.manager()
	if _, err := b.Candidates(e.mac); err != nil {
		t.Fatal(err)
	}
	if err := b.Restore([]string{"g1"}, func(string) ([]byte, error) { return []byte("fake-api-value"), nil }); err != nil {
		t.Fatal(err)
	}
	buf := b.storedValue("g1")
	e.clk.AdvanceWall(48 * time.Hour)
	_, _, err := b.Read("api")
	wantErr(t, err, ErrNoGrant)
	if !allZero(buf) {
		t.Fatal("restored buffer not zeroed")
	}
	if got := e.recordIDs(); len(got) != 0 {
		t.Fatalf("records after expiry = %v", got)
	}
}

func TestRestoredGrantWithinADayAlsoExpiresOnMonotonic(t *testing.T) {
	e := newEnv(t, "api")
	a := e.open()
	e.add(a, "g1", "api", 30*time.Hour, "fake-api-value")
	e.clk.AdvanceWall(10 * time.Hour) // 20 hours left at restore time
	b := e.manager()
	if _, err := b.Candidates(e.mac); err != nil {
		t.Fatal(err)
	}
	if err := b.Restore([]string{"g1"}, func(string) ([]byte, error) { return []byte("fake-api-value"), nil }); err != nil {
		t.Fatal(err)
	}
	e.clk.AdvanceMono(19 * time.Hour)
	mustRead(t, b, "api")
	e.clk.AdvanceMono(time.Hour)
	_, _, err := b.Read("api")
	wantErr(t, err, ErrNoGrant)
}

func TestRestoreRechecksFlagKeyAndReveal(t *testing.T) {
	e := newEnv(t, "api", "db", "s3")
	a := e.open()
	e.add(a, "g1", "api", 48*time.Hour, "fake-v1")
	e.add(a, "g2", "db", 48*time.Hour, "fake-v2")
	e.add(a, "g3", "s3", 48*time.Hour, "fake-v3")

	b := e.manager()
	got, err := b.Candidates(e.mac)
	if err != nil || len(got) != 3 {
		t.Fatalf("Candidates = %v, %v", got, err)
	}
	e.chk.setFlagged("api", true)
	e.chk.setKey("db", 55)
	errReveal := errors.New("fake reveal failure")
	var bufs [][]byte
	reveal := func(name string) ([]byte, error) {
		if name == "s3" {
			return nil, errReveal
		}
		buf := []byte("fake-revealed-" + name)
		bufs = append(bufs, buf)
		return buf, nil
	}
	err = b.Restore([]string{"g1", "g2", "g3"}, reveal)
	wantErr(t, err, ErrFlagged)
	wantErr(t, err, ErrKeyMismatch)
	wantErr(t, err, errReveal)
	for _, name := range []string{"api", "db", "s3"} {
		if _, _, err := b.Read(name); !errors.Is(err, ErrNoGrant) {
			t.Fatalf("Read %s = %v, want ErrNoGrant", name, err)
		}
	}
	for _, buf := range bufs {
		if !allZero(buf) {
			t.Fatalf("rejected reveal buffer not zeroed: %q", buf)
		}
	}
	if got := e.recordIDs(); len(got) != 0 {
		t.Fatalf("records after failed restore = %v", got)
	}
}

func TestRestoreZeroesRevealBufferAfterCopy(t *testing.T) {
	e := newEnv(t, "api")
	a := e.open()
	e.add(a, "g1", "api", 48*time.Hour, "fake-api-value")
	b := e.manager()
	if _, err := b.Candidates(e.mac); err != nil {
		t.Fatal(err)
	}
	revealed := []byte("fake-api-value")
	if err := b.Restore([]string{"g1"}, func(string) ([]byte, error) { return revealed, nil }); err != nil {
		t.Fatal(err)
	}
	if !allZero(revealed) {
		t.Fatal("reveal buffer not zeroed")
	}
	if v, _ := mustRead(t, b, "api"); v != "fake-api-value" {
		t.Fatalf("restored value = %q", v)
	}
}

func TestRestoreOnlyAcceptsVerifiedCandidates(t *testing.T) {
	e := newEnv(t, "api")
	a := e.open()
	e.add(a, "g1", "api", 48*time.Hour, "fake-api-value")
	b := e.manager()
	called := false
	reveal := func(string) ([]byte, error) { called = true; return []byte("x"), nil }

	err := b.Restore([]string{"g1"}, reveal) // no Candidates call
	wantErr(t, err, ErrNotCandidate)
	if called {
		t.Fatal("reveal called for a record that was never verified")
	}
	_, _, err = b.Read("api")
	wantErr(t, err, ErrNoGrant)
	if got := e.recordIDs(); !equalStrings(got, []string{"g1"}) {
		t.Fatalf("unverified record changed: %v", got)
	}
}

func TestRevokeAndExpiryRemoveRecords(t *testing.T) {
	e := newEnv(t, "api", "db")
	m := e.open()
	e.add(m, "g1", "api", 48*time.Hour, "fake-v1")
	e.add(m, "g2", "db", 72*time.Hour, "fake-v2")
	if got := e.recordIDs(); !equalStrings(got, []string{"g1", "g2"}) {
		t.Fatalf("records = %v", got)
	}
	if err := m.Revoke("g1"); err != nil {
		t.Fatal(err)
	}
	if got := e.recordIDs(); !equalStrings(got, []string{"g2"}) {
		t.Fatalf("records after revoke = %v", got)
	}
	e.clk.AdvanceWall(72 * time.Hour)
	_, _, err := m.Read("db")
	wantErr(t, err, ErrNoGrant)
	if got := e.recordIDs(); len(got) != 0 {
		t.Fatalf("records after expiry = %v", got)
	}

	// A revoked grant is not offered again after a restart.
	e.add(m, "g3", "api", 48*time.Hour, "fake-v3")
	if n := m.RevokeSecret("api"); n != 1 {
		t.Fatalf("RevokeSecret = %d", n)
	}
	got, err := e.manager().Candidates(e.mac)
	if err != nil || len(got) != 0 {
		t.Fatalf("Candidates after revoke = %v, %v", got, err)
	}
}

func TestPersistenceKeepsUnrelatedPendingRecords(t *testing.T) {
	e := newEnv(t, "api", "db", "s3")
	a := e.open()
	e.add(a, "p1", "api", 48*time.Hour, "fake-v1")
	e.add(a, "p2", "db", 48*time.Hour, "fake-v2")

	b := e.manager() // locked, nothing restored
	e.add(b, "n1", "s3", 48*time.Hour, "fake-v3")
	if got := e.recordIDs(); !equalStrings(got, []string{"n1", "p1", "p2"}) {
		t.Fatalf("records after Add on locked manager = %v", got)
	}
	// The new grant is usable while the restored ones are still locked.
	if v, _ := mustRead(t, b, "s3"); v != "fake-v3" {
		t.Fatalf("new grant = %q", v)
	}
	_, _, err := b.Read("api")
	wantErr(t, err, ErrLocked)

	if err := b.Revoke("n1"); err != nil {
		t.Fatal(err)
	}
	if got := e.recordIDs(); !equalStrings(got, []string{"p1", "p2"}) {
		t.Fatalf("records after Revoke = %v", got)
	}
	got, err := e.manager().Candidates(e.mac)
	if err != nil || !equalStrings(ids(got), []string{"p1", "p2"}) {
		t.Fatalf("Candidates = %v, %v", ids(got), err)
	}
}

func TestRevokeAndRevokeSecretReachPendingRecords(t *testing.T) {
	e := newEnv(t, "api", "db")
	a := e.open()
	e.add(a, "p1", "api", 48*time.Hour, "fake-v1")
	e.add(a, "p2", "db", 48*time.Hour, "fake-v2")

	b := e.manager()
	if err := b.Revoke("p1"); err != nil {
		t.Fatal(err)
	}
	wantErr(t, b.Revoke("p1"), ErrNoGrant)
	if n := b.RevokeSecret("db"); n != 0 {
		t.Fatalf("RevokeSecret counted %d live grants, want 0", n)
	}
	if got := e.recordIDs(); len(got) != 0 {
		t.Fatalf("records = %v", got)
	}
}

func TestRevokeDropsVerifiedCandidate(t *testing.T) {
	e := newEnv(t, "api")
	a := e.open()
	e.add(a, "g1", "api", 48*time.Hour, "fake-v1")
	b := e.manager()
	if _, err := b.Candidates(e.mac); err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke("g1"); err != nil {
		t.Fatal(err)
	}
	err := b.Restore([]string{"g1"}, func(string) ([]byte, error) { return []byte("x"), nil })
	wantErr(t, err, ErrNotCandidate)
	_, _, err = b.Read("api")
	wantErr(t, err, ErrNoGrant)
}

func TestAddRefusals(t *testing.T) {
	e := newEnv(t, "api")
	m := e.open()
	e.add(m, "dup", "api", 10*time.Minute, "fake-v1")

	flagged := newEnv(t, "api")
	flagged.chk.setFlagged("api", true)
	fm := flagged.open()

	stale := e.grant("stale", "api", 10*time.Minute)
	stale.KeyID = bytes.Repeat([]byte{42}, 16)
	missing := e.grant("missing", "ghost", 10*time.Minute)
	missing.KeyID = bytes.Repeat([]byte{1}, 16)

	cases := []struct {
		name string
		m    *Manager
		g    Grant
		mac  []byte
		want error
	}{
		{"duplicate id", m, e.grant("dup", "api", 10*time.Minute), e.mac, ErrDuplicate},
		{"expired", m, e.grant("x1", "api", 0), e.mac, ErrExpired},
		{"past", m, e.grant("x2", "api", -time.Minute), e.mac, ErrExpired},
		{"over 90 days", m, e.grant("x3", "api", 90*24*time.Hour+time.Second), e.mac, ErrTooLong},
		{"flagged", fm, flagged.grant("x4", "api", 10*time.Minute), flagged.mac, ErrFlagged},
		{"outdated key id", m, stale, e.mac, ErrKeyMismatch},
		{"unknown secret", m, missing, e.mac, ErrKeyMismatch},
		{"long without mac key", m, e.grant("x5", "api", 2*time.Hour), nil, ErrNoKey},
		{"missing id", m, Grant{Secret: "api", KeyID: e.chk.keyID("api"), Expires: t0.Add(time.Minute)}, e.mac, ErrBadGrant},
		{"missing secret", m, Grant{ID: "x6", KeyID: e.chk.keyID("api"), Expires: t0.Add(time.Minute)}, e.mac, ErrBadGrant},
		{"missing key id", m, Grant{ID: "x7", Secret: "api", Expires: t0.Add(time.Minute)}, e.mac, ErrBadGrant},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantErr(t, c.m.Add(c.g, []byte("fake-value"), c.mac), c.want)
		})
	}
	if got := ids(m.List()); !equalStrings(got, []string{"dup"}) {
		t.Fatalf("List after refusals = %v", got)
	}
	if got := e.recordIDs(); len(got) != 0 {
		t.Fatalf("refused grants were persisted: %v", got)
	}
	if err := m.Add(e.grant("max", "api", 90*24*time.Hour), []byte("fake-value"), e.mac); err != nil {
		t.Fatalf("90 day grant refused: %v", err)
	}
}

func TestAddSupportsEmptyValue(t *testing.T) {
	e := newEnv(t, "api")
	m := e.open()
	if err := m.Add(e.grant("g1", "api", time.Minute), nil, e.mac); err != nil {
		t.Fatal(err)
	}
	v, _, err := m.Read("api")
	if err != nil || len(v) != 0 {
		t.Fatalf("Read = %q, %v", v, err)
	}
}

func TestLongGrantFailsWhenRecordCannotBeWritten(t *testing.T) {
	e := newEnv(t, "api")
	e.dir = filepath.Join(e.dir, "missing")
	m := e.open()

	if err := m.Add(e.grant("g1", "api", 2*time.Hour), []byte("fake-v1"), e.mac); err == nil {
		t.Fatal("Add succeeded without a writable grants.json")
	}
	_, _, err := m.Read("api")
	wantErr(t, err, ErrNoGrant)
	e.add(m, "g2", "api", 10*time.Minute, "fake-v1") // short grants need no file
	mustRead(t, m, "api")
}

func TestCorruptRecordFileFailsClosed(t *testing.T) {
	e := newEnv(t, "api")
	if err := os.WriteFile(e.path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := e.open()

	err := m.Add(e.grant("g1", "api", 2*time.Hour), []byte("fake-v1"), e.mac)
	wantErr(t, err, ErrCorrupt)
	_, err = m.Candidates(e.mac)
	wantErr(t, err, ErrCorrupt)
	raw, _ := os.ReadFile(e.path())
	if string(raw) != "{not json" {
		t.Fatalf("corrupt file overwritten: %s", raw)
	}
	e.add(m, "g2", "api", 10*time.Minute, "fake-v1")
}

func TestCloseZeroesBuffersAndKeepsLongRecords(t *testing.T) {
	e := newEnv(t, "api", "db")
	m := e.open()
	e.add(m, "short", "api", 10*time.Minute, "fake-v1")
	e.add(m, "long", "db", 48*time.Hour, "fake-v2")
	b1, b2 := m.storedValue("short"), m.storedValue("long")

	m.Close()
	m.Close()
	if !allZero(b1) || !allZero(b2) {
		t.Fatal("Close left plaintext in memory")
	}
	_, _, err := m.Read("api")
	wantErr(t, err, ErrClosed)
	wantErr(t, m.Add(e.grant("g", "api", time.Minute), []byte("v"), e.mac), ErrClosed)
	if got := e.recordIDs(); !equalStrings(got, []string{"long"}) {
		t.Fatalf("records after Close = %v", got)
	}
}

func TestTimerZeroesExpiredBufferWithoutRead(t *testing.T) {
	chk := newChecker()
	chk.setKey("api", 1)
	m := New(clock.Real{}, t.TempDir(), chk)
	t.Cleanup(m.Close)
	g := Grant{ID: "g1", Secret: "api", KeyID: chk.keyID("api"), Expires: time.Now().Add(100 * time.Millisecond)}
	if err := m.Add(g, []byte("fake-v1"), nil); err != nil {
		t.Fatal(err)
	}
	buf := m.storedValue("g1")
	waitFor(t, "timer to zero the expired grant", func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return len(m.live) == 0 && allZero(buf)
	})
}

func TestTimerNoticesWallClockJump(t *testing.T) {
	old := recheck
	recheck = 10 * time.Millisecond
	t.Cleanup(func() { recheck = old })

	e := newEnv(t, "api")
	m := e.open()
	e.add(m, "g1", "api", 48*time.Hour, "fake-v1")
	buf := m.storedValue("g1")
	e.clk.SetWall(t0.Add(72 * time.Hour))
	waitFor(t, "timer to notice the wall-clock jump", func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return len(m.live) == 0 && allZero(buf)
	})
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestNoReadReturnsValueAfterRevoke(t *testing.T) {
	e := newEnv(t, "api")
	m := e.open()
	e.add(m, "g1", "api", 10*time.Minute, "fake-api-value")

	var revoked atomic.Bool
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 200; j++ {
				afterRevoke := revoked.Load()
				v, _, err := m.Read("api")
				if err == nil && afterRevoke {
					t.Error("Read returned a value after Revoke returned")
					return
				}
				if err == nil && string(v) != "fake-api-value" {
					t.Errorf("Read returned %q", v)
					return
				}
				if err != nil && !errors.Is(err, ErrNoGrant) {
					t.Errorf("Read error = %v", err)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		e.clk.AdvanceMono(time.Second)
		if err := m.Revoke("g1"); err != nil {
			t.Errorf("Revoke: %v", err)
		}
		revoked.Store(true)
		e.clk.AdvanceWall(time.Minute)
	}()
	close(start)
	wg.Wait()
	_, _, err := m.Read("api")
	wantErr(t, err, ErrNoGrant)
}

func TestRestoredGrantKeepsGrantedByAndRequestID(t *testing.T) {
	e := newEnv(t, "api")
	a := e.open()
	e.add(a, "g1", "api", 48*time.Hour, "fake-api-value")

	b := e.manager()
	got, err := b.Candidates(e.mac)
	if err != nil || len(got) != 1 {
		t.Fatalf("Candidates = %v, %v", got, err)
	}
	if got[0].GrantedBy != "user" || got[0].RequestID != "req-g1" {
		t.Fatalf("candidate = %+v", got[0])
	}
	if err := b.Restore([]string{"g1"}, func(string) ([]byte, error) { return []byte("fake-api-value"), nil }); err != nil {
		t.Fatal(err)
	}
	if _, g := mustRead(t, b, "api"); g.GrantedBy != "user" || g.RequestID != "req-g1" {
		t.Fatalf("restored grant = %+v", g)
	}
}

func TestCandidatesDropRecordWithChangedProvenance(t *testing.T) {
	for _, field := range []string{"granted_by", "request_id"} {
		t.Run(field, func(t *testing.T) {
			e := newEnv(t, "api")
			a := e.open()
			e.add(a, "g1", "api", 48*time.Hour, "fake-api-value")
			e.edit(func(r map[string]any) { r[field] = "changed" })
			got, err := e.manager().Candidates(e.mac)
			if err != nil || len(got) != 0 {
				t.Fatalf("Candidates = %v, %v", got, err)
			}
		})
	}
}

func TestCandidatesDropExpiryShiftedByTwoToThe64Nanoseconds(t *testing.T) {
	e := newEnv(t, "api")
	a := e.open()
	e.add(a, "g1", "api", 48*time.Hour, "fake-api-value")
	// 2^64 ns = 18446744073 s + 709551616 ns: the same UnixNano modulo 2^64.
	e.edit(func(r map[string]any) {
		exp, err := time.Parse(time.RFC3339Nano, r["expires"].(string))
		if err != nil {
			t.Fatal(err)
		}
		shifted := time.Unix(exp.Unix()+18446744073, int64(exp.Nanosecond())+709551616).UTC()
		r["expires"] = shifted.Format(time.RFC3339Nano)
	})
	got, err := e.manager().Candidates(e.mac)
	if err != nil || len(got) != 0 {
		t.Fatalf("Candidates = %v, %v", got, err)
	}
}

func TestCandidatesDropSignedRecordBeyondNinetyDays(t *testing.T) {
	e := newEnv(t, "api")
	r := record{
		ID: "far", Secret: "api", KeyID: e.chk.keyID("api"),
		Expires: t0.Add(MaxDuration + time.Hour), GrantedBy: "user",
	}
	r.sign(e.mac)
	b, err := json.Marshal(recordsDoc{Version: recordsVersion, Grants: []record{r}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.path(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := e.manager().Candidates(e.mac)
	if err != nil || len(got) != 0 {
		t.Fatalf("Candidates = %v, %v", got, err)
	}
}

func TestRestoreRefusesGrantBeyondNinetyDaysAfterClockStepBack(t *testing.T) {
	e := newEnv(t, "api")
	a := e.open()
	e.add(a, "g1", "api", 48*time.Hour, "fake-api-value")
	b := e.manager()
	if got, err := b.Candidates(e.mac); err != nil || len(got) != 1 {
		t.Fatalf("Candidates = %v, %v", got, err)
	}
	e.clk.SetWall(t0.Add(-MaxDuration))
	called := false
	err := b.Restore([]string{"g1"}, func(string) ([]byte, error) { called = true; return []byte("x"), nil })
	wantErr(t, err, ErrTooLong)
	if called {
		t.Fatal("reveal called for a grant beyond the 90-day bound")
	}
	_, _, rerr := b.Read("api")
	wantErr(t, rerr, ErrNoGrant)
}

func TestMacMessageDistinguishesInstantsTwoToThe64NsApart(t *testing.T) {
	a := record{ID: "g", Secret: "api", KeyID: []byte{1}, Expires: t0.Add(48 * time.Hour)}
	b := a
	b.Expires = time.Unix(a.Expires.Unix()+18446744073, int64(a.Expires.Nanosecond())+709551616).UTC()
	if bytes.Equal(a.macMessage(), b.macMessage()) {
		t.Fatal("records 2^64 ns apart share a MAC message")
	}
	key := bytes.Repeat([]byte{7}, 32)
	a.sign(key)
	b.MAC = a.MAC
	if b.verify(key) {
		t.Fatal("MAC of one expiry verifies another 2^64 ns later")
	}
}
