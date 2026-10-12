// Package grants holds the live grants of the daemon: decrypted secret values
// in memory until a grant expires or is revoked, and signed records of long
// grants in grants.json so the user can restore them after a restart.
package grants

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"tokencrypt/internal/clock"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/securemem"
)

const (
	// PersistAfter is the longest grant that exists in memory only.
	PersistAfter = time.Hour
	// MonoWithin is the longest grant, or the longest time left on a restored
	// grant, that also expires on monotonic time.
	MonoWithin = 24 * time.Hour
	// MaxDuration is the longest grant.
	MaxDuration = 90 * 24 * time.Hour
)

// recheck bounds the timer wait so a wall-clock jump is noticed within a
// minute. It is a variable for tests.
var recheck = time.Minute

var (
	// ErrNoGrant means no live grant covers the secret.
	ErrNoGrant = errors.New("grants: no live grant")
	// ErrLocked means no live grant covers the secret and long grants of an
	// earlier run have not been restored yet.
	ErrLocked = errors.New("grants: daemon is locked")
	// ErrClosed is returned by every method after Close.
	ErrClosed = errors.New("grants: manager closed")
	// ErrBadGrant means the grant lacks an ID, a secret or a key ID.
	ErrBadGrant = errors.New("grants: grant needs an ID, a secret and a key ID")
	// ErrDuplicate means a live grant already has the ID.
	ErrDuplicate = errors.New("grants: grant ID already in use")
	// ErrExpired means the grant has already ended.
	ErrExpired = errors.New("grants: grant already expired")
	// ErrTooLong means the grant lasts longer than MaxDuration.
	ErrTooLong = errors.New("grants: grant longer than 90 days")
	// ErrFlagged means the secret carries a flag.
	ErrFlagged = errors.New("grants: secret is flagged")
	// ErrKeyMismatch means the grant's key ID is not the secret's current one.
	ErrKeyMismatch = errors.New("grants: key ID is not the current key ID")
	// ErrNoKey means a record key of 32 bytes is required.
	ErrNoKey = errors.New("grants: a 32-byte record key is required")
	// ErrNotCandidate means the ID is not among the verified candidates.
	ErrNotCandidate = errors.New("grants: not a verified candidate")
	// ErrCorrupt means grants.json cannot be parsed.
	ErrCorrupt = errors.New("grants: corrupt grants.json")
)

// Grant is the right to read one secret until Expires. Every Grant the
// manager returns owns its KeyID.
type Grant struct {
	ID        string
	Secret    string
	KeyID     []byte
	Expires   time.Time
	GrantedBy string
	RequestID string
}

func (g Grant) clone() Grant {
	g.KeyID = bytes.Clone(g.KeyID)
	return g
}

// Checker reads the vault state a grant depends on. Its methods run under the
// manager's lock and must not call the Manager.
type Checker interface {
	// Flagged reports whether the secret carries a flag.
	Flagged(name string) bool
	// KeyID returns the key ID of the secret's current value.
	KeyID(name string) ([]byte, error)
}

// live is a grant whose value is in memory.
type live struct {
	grant     Grant
	value     []byte
	memory    *securemem.Buffer
	trackMono bool
	mono      time.Duration // deadline on clock Mono, valid when trackMono
	persisted bool          // has a record in grants.json
}

// Manager keeps the live grants of one vault. A new Manager is locked: a
// secret without a live grant reports ErrLocked until Restore or SetLocked
// marks the restore step done. It never keeps a record key.
type Manager struct {
	clk clock.Clock
	dir string
	chk Checker

	mu         sync.Mutex
	live       map[string]*live
	candidates map[string]record
	unremoved  map[string]bool // record IDs whose removal from grants.json failed
	locked     bool
	closed     bool
	timer      *time.Timer
}

// New returns a locked Manager that stores grants.json in dir. chk must not
// be nil.
func New(clk clock.Clock, dir string, chk Checker) *Manager {
	return &Manager{
		clk: clk, dir: dir, chk: chk,
		live:       map[string]*live{},
		candidates: map[string]record{},
		unremoved:  map[string]bool{},
		locked:     true,
	}
}

func (m *Manager) expired(l *live, wall time.Time, mono time.Duration) bool {
	return !wall.Before(l.grant.Expires) || (l.trackMono && mono >= l.mono)
}

// dropLocked zeroes and removes a live grant.
func (m *Manager) dropLocked(id string) {
	if l, ok := m.live[id]; ok {
		l.memory.Close()
		delete(m.live, id)
	}
}

// expireLocked removes every grant that has ended on either clock. A record
// that cannot be removed from grants.json is remembered and retried on the
// next write.
func (m *Manager) expireLocked() {
	wall, mono := m.clk.Wall(), m.clk.Mono()
	var gone []string
	for id, l := range m.live {
		if !m.expired(l, wall, mono) {
			continue
		}
		if l.persisted {
			gone = append(gone, id)
		}
		m.dropLocked(id)
	}
	if len(gone) > 0 {
		_, _ = m.updateRecords(nil, "", gone...)
	}
}

// scheduleLocked points the timer at the earliest deadline, never more than
// recheck away.
func (m *Manager) scheduleLocked() {
	if m.closed || len(m.live) == 0 {
		if m.timer != nil {
			m.timer.Stop()
		}
		return
	}
	wall, mono := m.clk.Wall(), m.clk.Mono()
	wait := recheck
	for _, l := range m.live {
		if d := l.grant.Expires.Sub(wall); d < wait {
			wait = d
		}
		if l.trackMono {
			if d := l.mono - mono; d < wait {
				wait = d
			}
		}
	}
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	if m.timer == nil {
		m.timer = time.AfterFunc(wait, m.onTimer)
		return
	}
	m.timer.Reset(wait)
}

func (m *Manager) onTimer() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.expireLocked()
	m.scheduleLocked()
}

// Add makes the grant readable. value and g.KeyID are copied; the caller
// keeps and must zero its own buffers. A grant longer than PersistAfter is
// also recorded in grants.json, signed with macKey, which must be 32 bytes
// and is not kept. Add works while the manager is locked. The secret must be
// unflagged and g.KeyID must be its current key ID, so a value read before an
// update cannot be granted after the update revoked the old grants.
func (m *Manager) Add(g Grant, value, macKey []byte) error {
	if g.ID == "" || g.Secret == "" || len(g.KeyID) == 0 {
		return ErrBadGrant
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.expireLocked()
	wall, mono := m.clk.Wall(), m.clk.Mono()
	d := g.Expires.Sub(wall)
	switch {
	case d <= 0:
		return ErrExpired
	case d > MaxDuration:
		return ErrTooLong
	}
	if _, ok := m.live[g.ID]; ok {
		return ErrDuplicate
	}
	if m.chk.Flagged(g.Secret) {
		return ErrFlagged
	}
	if id, err := m.chk.KeyID(g.Secret); err != nil || !bytes.Equal(id, g.KeyID) {
		return ErrKeyMismatch
	}
	l := &live{
		grant: Grant{
			ID: g.ID, Secret: g.Secret, KeyID: bytes.Clone(g.KeyID),
			Expires: g.Expires.UTC().Round(0), GrantedBy: g.GrantedBy, RequestID: g.RequestID,
		},
	}
	if d > PersistAfter {
		if len(macKey) != macKeySize {
			return ErrNoKey
		}
		rec := record{
			ID: l.grant.ID, Secret: l.grant.Secret, KeyID: bytes.Clone(l.grant.KeyID),
			Expires: l.grant.Expires, GrantedBy: l.grant.GrantedBy, RequestID: l.grant.RequestID,
		}
		rec.sign(macKey)
		if _, err := m.updateRecords(&rec, ""); err != nil {
			return err
		}
		l.persisted = true
	}
	if d <= MonoWithin {
		l.trackMono, l.mono = true, mono+d
	}
	l.memory = securemem.Copy(value)
	l.value = l.memory.Bytes
	m.live[g.ID] = l
	m.scheduleLocked()
	return nil
}

// Read returns a copy of the value of the live grant for name that ends
// last, and a copy of the grant. Without one it returns ErrLocked while the
// restore step is pending and ErrNoGrant otherwise.
func (m *Manager) Read(name string) ([]byte, Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, Grant{}, ErrClosed
	}
	m.expireLocked()
	var best *live
	for _, l := range m.live {
		if l.grant.Secret == name && (best == nil || l.grant.Expires.After(best.grant.Expires)) {
			best = l
		}
	}
	if best == nil {
		if m.locked {
			return nil, Grant{}, ErrLocked
		}
		return nil, Grant{}, ErrNoGrant
	}
	return bytes.Clone(best.value), best.grant.clone(), nil
}

// Revoke ends a live grant, or removes a record that was not restored yet.
// The value is zeroed and the record leaves grants.json. A grant revoked from
// memory stays revoked when the record write fails; the error says so.
func (m *Manager) Revoke(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	l, isLive := m.live[id]
	if isLive {
		m.dropLocked(id)
		m.scheduleLocked()
	}
	delete(m.candidates, id)
	if isLive && !l.persisted {
		return nil
	}
	removed, err := m.updateRecords(nil, "", id)
	if err != nil {
		return err
	}
	if !isLive && removed == 0 {
		return ErrNoGrant
	}
	return nil
}

// RevokeSecret ends every live grant for name and removes its records,
// including records that were not restored yet. It returns the number of live
// grants ended.
func (m *Manager) RevokeSecret(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0
	}
	var ids []string
	n := 0
	for id, l := range m.live {
		if l.grant.Secret != name {
			continue
		}
		n++
		if l.persisted {
			ids = append(ids, id)
		}
		m.dropLocked(id)
	}
	for id, r := range m.candidates {
		if r.Secret == name {
			delete(m.candidates, id)
		}
	}
	m.scheduleLocked()
	// A failed write leaves ids in the retry set. Records that were not
	// restored yet are also dropped by Candidates once the secret is flagged
	// or its value changed.
	_, _ = m.updateRecords(nil, name, ids...)
	return n
}

// List returns copies of the live grants, earliest expiry first.
func (m *Manager) List() []Grant {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.expireLocked()
	return m.grantsLocked()
}

func (m *Manager) grantsLocked() []Grant {
	out := make([]Grant, 0, len(m.live))
	for _, l := range m.live {
		out = append(out, l.grant.clone())
	}
	sortGrants(out)
	return out
}

func sortGrants(gs []Grant) {
	sort.Slice(gs, func(i, j int) bool {
		if !gs[i].Expires.Equal(gs[j].Expires) {
			return gs[i].Expires.Before(gs[j].Expires)
		}
		return gs[i].ID < gs[j].ID
	})
}

// SetLocked sets whether a secret without a live grant reports ErrLocked.
// Restore clears it.
func (m *Manager) SetLocked(locked bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locked = locked
}

// Candidates verifies the records in grants.json with macKey, which must be
// the 32-byte key derived from the master key for this unlock, and returns the
// grants that may be restored: signed, unexpired, not already live, on an
// unflagged secret and carrying its current key ID. The verified set is kept
// for Restore; grants.json is not changed.
func (m *Manager) Candidates(macKey []byte) ([]Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	m.candidates = nil
	if len(macKey) != macKeySize {
		return nil, ErrNoKey
	}
	recs, err := m.readRecords()
	if err != nil {
		return nil, err
	}
	wall := m.clk.Wall()
	cand := map[string]record{}
	var out []Grant
	for _, r := range recs {
		if _, duplicate := cand[r.ID]; duplicate {
			continue
		}
		if r.ID == "" || r.Secret == "" || !wall.Before(r.Expires) || m.unremoved[r.ID] {
			continue
		}
		if r.Expires.Sub(wall) > MaxDuration {
			continue
		}
		if _, ok := m.live[r.ID]; ok {
			continue
		}
		if !r.verify(macKey) || m.chk.Flagged(r.Secret) {
			continue
		}
		if id, err := m.chk.KeyID(r.Secret); err != nil || !bytes.Equal(id, r.KeyID) {
			continue
		}
		r.KeyID = bytes.Clone(r.KeyID)
		r.Expires = r.Expires.UTC().Round(0)
		cand[r.ID] = r
		out = append(out, r.grant())
	}
	m.candidates = cand
	sortGrants(out)
	return out, nil
}

func (r record) grant() Grant {
	return Grant{
		ID: r.ID, Secret: r.Secret, KeyID: bytes.Clone(r.KeyID),
		Expires: r.Expires, GrantedBy: r.GrantedBy, RequestID: r.RequestID,
	}
}

// Restore makes the confirmed candidates live and ends the locked state. reveal
// returns the current value of a secret; it must return a fresh slice, which
// Restore zeroes after copying, and must not call the Manager. Each confirmed
// grant is checked again for expiry, flag and key ID after its value was
// revealed. Candidates that were not confirmed, or failed a check, are removed
// from grants.json. Every failure is reported in the returned error; grants
// that passed are live regardless.
func (m *Manager) Restore(ids []string, reveal func(name string) ([]byte, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	wall, mono := m.clk.Wall(), m.clk.Mono()
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	var errs []error
	var prev string
	for i, id := range sorted {
		if i > 0 && id == prev {
			continue
		}
		prev = id
		if err := m.restoreOne(id, wall, mono, reveal); err != nil {
			errs = append(errs, fmt.Errorf("grant %s: %w", id, err))
		}
	}
	var declined []string
	for id := range m.candidates {
		if _, ok := m.live[id]; !ok {
			declined = append(declined, id)
		}
	}
	m.candidates = map[string]record{}
	if len(declined) > 0 {
		if _, err := m.updateRecords(nil, "", declined...); err != nil {
			errs = append(errs, err)
		}
	}
	m.locked = false
	m.scheduleLocked()
	return errors.Join(errs...)
}

func (m *Manager) restoreOne(id string, wall time.Time, mono time.Duration, reveal func(string) ([]byte, error)) error {
	r, ok := m.candidates[id]
	if !ok {
		return ErrNotCandidate
	}
	left := r.Expires.Sub(wall)
	if left <= 0 {
		return ErrExpired
	}
	if left > MaxDuration {
		return ErrTooLong
	}
	v, err := reveal(r.Secret)
	if err != nil {
		return err
	}
	value := bytes.Clone(v)
	crypto.Zero(v)
	if m.chk.Flagged(r.Secret) {
		crypto.Zero(value)
		return ErrFlagged
	}
	if kid, err := m.chk.KeyID(r.Secret); err != nil || !bytes.Equal(kid, r.KeyID) {
		crypto.Zero(value)
		return ErrKeyMismatch
	}
	memory := securemem.Copy(value)
	crypto.Zero(value)
	l := &live{grant: r.grant(), value: memory.Bytes, memory: memory, persisted: true}
	if left <= MonoWithin {
		l.trackMono, l.mono = true, mono+left
	}
	m.live[id] = l
	return nil
}

// Close stops the timer and zeroes every value. Long grants stay in
// grants.json so a restart can restore them. Later calls return ErrClosed.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	if m.timer != nil {
		m.timer.Stop()
	}
	for id := range m.live {
		m.dropLocked(id)
	}
	m.candidates = map[string]record{}
}
