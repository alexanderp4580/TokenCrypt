// Package core is the service behind the web UI and the agent socket. It owns
// the rules: which operations need the passphrase, how failures are
// throttled, how requests and flags work, and the order in which grants are
// revoked around a change to a secret. Operations on one Service are
// serialized, so once Flag, Revoke, UpdateValue, Rename or Delete returns, no
// later Read can return the old value.
package core

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"tokencrypt/internal/audit"
	"tokencrypt/internal/clock"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

const (
	// maxReason is the longest reason, in characters.
	maxReason = 200
	// maxActor is the longest actor name, in characters.
	maxActor = 64
	// eventBuffer is how many events wait for a reader before new ones are
	// dropped.
	eventBuffer = 64

	grantsLabel = "tokencrypt grants v1"

	actorDaemon = "daemon"
	actorAgent  = "agent"
	actorUser   = "user"
)

// Event kinds.
const (
	EventRequestCreated = "request.created"
	EventFlagSet        = "flag.set"
)

// Errors. Several are the errors of the packages below, so errors.Is matches
// either name.
var (
	ErrWrongPassphrase = vault.ErrWrongPassphrase
	ErrNotFound        = vault.ErrNotFound
	ErrBadFlag         = vault.ErrBadFlag
	ErrLocked          = grants.ErrLocked
	ErrNoGrant         = grants.ErrNoGrant

	// ErrThrottled means too many consecutive wrong passphrases; every
	// passphrase attempt is refused until the lockout has passed.
	ErrThrottled = errors.New("core: too many wrong passphrases; try again later")
	// ErrFlagged means the secret carries a flag. The concrete error is a
	// *FlaggedError holding the kind and reason.
	ErrFlagged = errors.New("core: secret is flagged")
	// ErrTooManyPending means the pending request limit is reached.
	ErrTooManyPending = errors.New("core: too many pending requests")
	// ErrDurationTooLong means the duration is over the longest grant.
	ErrDurationTooLong = errors.New("core: duration is longer than the longest grant")
	// ErrNotPending means the request has already been approved, denied or
	// has expired.
	ErrNotPending = errors.New("core: request is not pending")
	// ErrRequestMismatch means the request is for another secret.
	ErrRequestMismatch = errors.New("core: request is for another secret")
	// ErrBadEventType means a notifier event type outside "notifier.".
	ErrBadEventType = errors.New("core: not a notifier event type")
	// ErrAudit means the audit record could not be written. The action itself
	// was applied, except for a grant, which is revoked again.
	ErrAudit = errors.New("core: audit record not written")
	// ErrRecordNotRemoved means a grant was revoked in memory, so it cannot
	// be read, but its record in grants.json could not be removed. The
	// removal is retried on the next grants write and the record is never
	// restored once the secret has changed.
	ErrRecordNotRemoved = errors.New("core: grant revoked but its record was not removed")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("core: service closed")
)

// FlaggedError is the error for an operation on a flagged secret.
type FlaggedError struct {
	Secret, Kind, Reason string
}

func (e *FlaggedError) Error() string {
	return fmt.Sprintf("secret %q is flagged %s: %s", e.Secret, e.Kind, clean(e.Reason, maxReason))
}

// Is makes errors.Is(err, ErrFlagged) true.
func (e *FlaggedError) Is(target error) bool { return target == ErrFlagged }

// Config holds the limits. A zero field takes its DefaultConfig value.
type Config struct {
	MaxPending   int           // pending requests allowed at once
	RequestTTL   time.Duration // a request expires this long after it was made
	MaxGrant     time.Duration // longest grant and longest requested duration
	DefaultGrant time.Duration // duration when none is given
	MaxFailures  int           // consecutive wrong passphrases before a lockout
	Lockout      time.Duration // how long attempts are refused
}

// DefaultConfig returns the values of the design.
func DefaultConfig() Config {
	return Config{
		MaxPending:   10,
		RequestTTL:   10 * time.Minute,
		MaxGrant:     grants.MaxDuration,
		DefaultGrant: 10 * time.Minute,
		MaxFailures:  5,
		Lockout:      5 * time.Minute,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.MaxPending <= 0 {
		c.MaxPending = d.MaxPending
	}
	if c.RequestTTL <= 0 {
		c.RequestTTL = d.RequestTTL
	}
	if c.MaxGrant <= 0 {
		c.MaxGrant = d.MaxGrant
	}
	if c.DefaultGrant <= 0 {
		c.DefaultGrant = d.DefaultGrant
	}
	if c.MaxFailures <= 0 {
		c.MaxFailures = d.MaxFailures
	}
	if c.Lockout <= 0 {
		c.Lockout = d.Lockout
	}
	return c
}

// Event tells the notifier something happened. Reason is the request reason
// for request.created and the flag reason for flag.set.
type Event struct {
	Kind      string
	Secret    string
	RequestID string
	Actor     string
	FlagKind  string
	Reason    string
	Duration  time.Duration
}

// Status is a snapshot for the UI and the CLI. It holds no values. Error is
// not empty when the secret list could not be read; Secrets is then empty.
type Status struct {
	Secrets []vault.Meta
	Grants  []grants.Grant
	Pending []Request
	Locked  bool
	Error   string
}

// UnlockResult is what an unlock hands the daemon: the notifier credentials
// (empty when none are stored; NotifierErr says why they could not be read)
// and the long grants of an earlier run that the user may confirm. GrantsErr
// reports corrupt grant storage without preventing authenticated unlock.
type UnlockResult struct {
	NotifierToken []byte
	ChatID        string
	NotifierErr   error
	GrantsErr     error
	Candidates    []grants.Grant
}

type checker struct{ v *vault.Vault }

// NewChecker returns the grants.Checker over a vault. It fails closed: a
// secret whose metadata cannot be read, or that does not exist, counts as
// flagged.
func NewChecker(v *vault.Vault) grants.Checker { return checker{v} }

func (c checker) Flagged(name string) bool {
	m, err := c.v.Get(name)
	return err != nil || m.Flag != nil
}

func (c checker) KeyID(name string) ([]byte, error) { return c.v.KeyID(name) }

// Service is the core of one vault. Create it with New.
type Service struct {
	v   *vault.Vault
	g   *grants.Manager
	a   *audit.Log
	clk clock.Clock
	cfg Config
	thr *throttle

	// unlock derives the key; it is a field so tests can observe it.
	unlock func(pass []byte) (*vault.Session, error)
	// kdf allows one key derivation at a time.
	kdf sync.Mutex

	// mu serializes operations and guards everything below.
	mu       sync.Mutex
	reqs     map[string]*entry
	finished []string
	known    map[string]grants.Grant // grants whose end has not been audited
	locked   bool
	events   chan Event

	closed    atomic.Bool
	quit      chan struct{}
	closeOnce sync.Once
}

// New returns a Service over v, g and a. The Service takes ownership of g and
// a and closes them in Close. The Manager must use NewChecker(v) as its
// Checker. The Service starts locked until Unlock or RestoreGrants.
func New(v *vault.Vault, g *grants.Manager, a *audit.Log, clk clock.Clock, cfg Config) *Service {
	cfg = cfg.withDefaults()
	return &Service{
		v: v, g: g, a: a, clk: clk, cfg: cfg,
		thr:    newThrottle(clk, cfg.MaxFailures, cfg.Lockout),
		unlock: v.Unlock,
		reqs:   map[string]*entry{},
		known:  map[string]grants.Grant{},
		locked: true,
		events: make(chan Event, eventBuffer),
		quit:   make(chan struct{}),
	}
}

// Events returns the channel of request and flag events. Events are dropped
// when nobody reads and 64 are waiting. The channel closes on Close.
func (s *Service) Events() <-chan Event { return s.events }

// Close ends waits, closes the event channel, zeroes live grants (long grants
// stay recorded for a restart) and closes the audit log.
func (s *Service) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.quit)
		s.mu.Lock()
		close(s.events)
		s.mu.Unlock()
		s.g.Close()
		_ = s.a.Close()
	})
}

// lock takes the operation lock, or returns ErrClosed.
func (s *Service) lock() error {
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return ErrClosed
	}
	return nil
}

func (s *Service) emitLocked(e Event) {
	select {
	case s.events <- e:
	default:
	}
}

// clean makes agent-supplied text safe to log and show: invalid UTF-8 becomes
// U+FFFD, control, format and line-separator characters become spaces, the
// result is trimmed and cut to max characters.
func clean(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			break
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

const maxDescriptionBytes = 1024

func cleanDescription(s string) string {
	s = clean(s, maxDescriptionBytes)
	if len(s) > maxDescriptionBytes {
		end := maxDescriptionBytes
		for end > 0 && !utf8.RuneStart(s[end]) {
			end--
		}
		s = s[:end]
	}
	return strings.TrimSpace(s)
}

// write appends events to the audit log. It keeps going after a failure and
// returns ErrAudit if any write failed; a failed write is never repeated,
// because the line may already be in the file.
func (s *Service) write(evs ...audit.Event) error {
	var failed error
	for _, e := range evs {
		if e.Actor == "" {
			e.Actor = actorDaemon
		}
		if err := s.a.Write(e); err != nil && failed == nil {
			failed = err
		}
	}
	if failed != nil {
		return fmt.Errorf("%w: %v", ErrAudit, failed)
	}
	return nil
}

// sweepLocked ends expired requests and audits grants that ended by time.
func (s *Service) sweepLocked() {
	s.expireRequestsLocked()
	live := map[string]bool{}
	for _, g := range s.g.List() {
		live[g.ID] = true
	}
	for id, g := range s.known {
		if !live[id] {
			delete(s.known, id)
			_ = s.write(audit.Event{Type: audit.GrantEnded, Actor: actorDaemon, Secret: g.Secret,
				Detail: jsonDetail(map[string]string{"grant": id, "expires": g.Expires.Format(time.RFC3339)})})
		}
	}
}

// usable returns the metadata of name if the secret exists, is readable and
// is not flagged. Unreadable metadata refuses access instead of passing it.
func (s *Service) usable(name string) (vault.Meta, error) {
	m, err := s.v.Get(name)
	switch {
	case err == nil:
	case errors.Is(err, vault.ErrNotFound), errors.Is(err, vault.ErrBadName):
		return vault.Meta{}, err
	default:
		return vault.Meta{}, fmt.Errorf("core: secret state unreadable, access refused: %w", err)
	}
	if m.Flag != nil {
		return m, &FlaggedError{Secret: name, Kind: m.Flag.Kind, Reason: m.Flag.Reason}
	}
	return m, nil
}

// withKey runs fn with an unlocked vault session, under the operation lock,
// after the passphrase checked out. Key derivations run one at a time and
// count toward the throttle; a wrong passphrase is audited. The session is
// closed before withKey returns. The caller keeps pass.
func (s *Service) withKey(op, name, actor string, pass []byte, fn func(sess *vault.Session) error) error {
	if s.closed.Load() {
		return ErrClosed
	}
	if s.thr.blocked() {
		return ErrThrottled
	}
	s.kdf.Lock()
	// Attempts that queued behind a failing one are refused here, so a burst
	// of wrong guesses costs at most MaxFailures derivations.
	if s.thr.blocked() {
		s.kdf.Unlock()
		return ErrThrottled
	}
	sess, err := s.unlock(pass)
	if err != nil {
		if !errors.Is(err, vault.ErrWrongPassphrase) {
			s.kdf.Unlock()
			return err
		}
		fails, until := s.thr.failure()
		s.kdf.Unlock()
		d := map[string]any{"operation": op, "failures": fails}
		if !until.IsZero() {
			d["locked_until"] = until.UTC().Format(time.RFC3339)
		}
		ev := audit.Event{Type: audit.LoginFailed, Actor: actor, Detail: jsonDetail(d)}
		if vault.ValidName(name) {
			ev.Secret = name
		}
		if werr := s.write(ev); werr != nil {
			return errors.Join(ErrWrongPassphrase, werr)
		}
		return ErrWrongPassphrase
	}
	s.thr.success()
	s.kdf.Unlock()
	defer sess.Close()
	if err := s.lock(); err != nil {
		return err
	}
	defer s.mu.Unlock()
	s.sweepLocked()
	return fn(sess)
}

// Verify checks the passphrase. It counts toward the throttle like every
// other passphrase operation.
func (s *Service) Verify(pass []byte) error {
	return s.withKey("verify", "", actorUser, pass, func(*vault.Session) error { return nil })
}

// LogNotifierEvent writes a notifier event to the audit log. typ must start
// with "notifier."; detail must hold no credentials.
func (s *Service) LogNotifierEvent(typ, detail string) error {
	if !strings.HasPrefix(typ, "notifier.") {
		return ErrBadEventType
	}
	if err := s.lock(); err != nil {
		return err
	}
	defer s.mu.Unlock()
	return s.write(audit.Event{Type: typ, Actor: "notifier", Detail: clean(detail, maxReason)})
}

// AuditTail returns the last n audit events, oldest first.
func (s *Service) AuditTail(n int) ([]audit.Event, error) {
	if s.closed.Load() {
		return nil, ErrClosed
	}
	return s.a.Tail(n)
}

// Status returns the secrets, live grants and pending requests.
func (s *Service) Status() Status {
	if err := s.lock(); err != nil {
		return Status{Locked: true}
	}
	defer s.mu.Unlock()
	s.sweepLocked()
	st := Status{Grants: s.g.List(), Pending: s.pendingLocked(), Locked: s.locked}
	secrets, err := s.v.List()
	if err != nil {
		st.Error = listError(err)
		return st
	}
	st.Secrets = secrets
	return st
}

func listError(err error) string {
	if errors.Is(err, vault.ErrCorrupt) {
		return "secret list unavailable: a vault file is corrupt"
	}
	return "secret list unavailable: a vault file could not be read"
}

// Secret operations ----------------------------------------------------------

// Create stores a new secret.
func (s *Service) Create(name, desc string, value, pass []byte, actor string) error {
	return s.CreateWithExpiry(name, desc, value, pass, actor, "")
}

// CreateWithExpiry stores a secret with optional informational expiry metadata.
func (s *Service) CreateWithExpiry(name, desc string, value, pass []byte, actor, date string) error {
	if !vault.ValidExpiry(date) {
		return vault.ErrBadExpiry
	}
	if !vault.ValidName(name) {
		return vault.ErrBadName
	}
	if len(value) > vault.MaxValueBytes {
		return vault.ErrTooLarge
	}
	actor = clean(actor, maxActor)
	return s.withKey("create", name, actor, pass, func(sess *vault.Session) error {
		existed := s.v.Exists(name)
		err := sess.CreateWithExpiry(name, cleanDescription(desc), value, date)
		if existed || !s.v.Exists(name) {
			return err
		}
		return errors.Join(err, s.write(audit.Event{Type: audit.SecretCreated, Actor: actor, Secret: name}))
	})
}

// revokeSecretLocked ends every live grant for name, before the caller
// changes the secret, and returns the audit events.
func (s *Service) revokeSecretLocked(name, actor, why string) []audit.Event {
	var evs []audit.Event
	for _, g := range s.g.List() {
		if g.Secret != name {
			continue
		}
		delete(s.known, g.ID)
		evs = append(evs, audit.Event{Type: audit.GrantRevoked, Actor: actor, Secret: name,
			Detail: jsonDetail(map[string]string{"grant": g.ID, "reason": why})})
	}
	s.g.RevokeSecret(name)
	return evs
}

type flagDetail struct {
	Kind   string `json:"kind"`
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
}

// UpdateValue replaces the value, which revokes live grants and clears the
// flag. Live grants are revoked before the write, so a partial failure never
// leaves the old value readable.
func (s *Service) UpdateValue(name string, value, pass []byte, actor string) error {
	if !vault.ValidName(name) {
		return vault.ErrBadName
	}
	if len(value) > vault.MaxValueBytes {
		return vault.ErrTooLarge
	}
	actor = clean(actor, maxActor)
	return s.withKey("update", name, actor, pass, func(sess *vault.Session) error {
		before, _ := s.v.Get(name)
		evs := s.revokeSecretLocked(name, actor, "value updated")
		err := sess.UpdateValue(name, value)
		after, aerr := s.v.KeyID(name)
		if err == nil || (aerr == nil && before.KeyID != nil && string(after) != string(before.KeyID)) {
			evs = append(evs, audit.Event{Type: audit.SecretUpdated, Actor: actor, Secret: name})
		}
		if err == nil && before.Flag != nil {
			evs = append(evs, audit.Event{Type: audit.FlagCleared, Actor: actor, Secret: name,
				Detail: jsonDetail(flagDetail{Kind: before.Flag.Kind, Actor: actor, Reason: "value updated"})})
		}
		return errors.Join(err, s.write(evs...))
	})
}

// Rename moves a secret to a new name, revoking live grants and denying
// pending requests for the old name first.
func (s *Service) Rename(oldName, newName string, pass []byte, actor string) error {
	if !vault.ValidName(oldName) || !vault.ValidName(newName) {
		return vault.ErrBadName
	}
	actor = clean(actor, maxActor)
	return s.withKey("rename", oldName, actor, pass, func(sess *vault.Session) error {
		newExisted := s.v.Exists(newName)
		evs := s.revokeSecretLocked(oldName, actor, "secret renamed")
		evs = append(evs, s.denyPendingLocked(oldName, actor, "secret renamed")...)
		err := sess.Rename(oldName, newName)
		if !newExisted && s.v.Exists(newName) {
			evs = append(evs, audit.Event{Type: audit.SecretRenamed, Actor: actor, Secret: oldName,
				Detail: jsonDetail(map[string]string{"new_name": newName})})
		}
		return errors.Join(err, s.write(evs...))
	})
}

// Delete removes a secret, revoking live grants and denying pending requests
// first.
func (s *Service) Delete(name string, pass []byte, actor string) error {
	if !vault.ValidName(name) {
		return vault.ErrBadName
	}
	actor = clean(actor, maxActor)
	return s.withKey("delete", name, actor, pass, func(sess *vault.Session) error {
		existed := s.v.Exists(name)
		evs := s.revokeSecretLocked(name, actor, "secret deleted")
		evs = append(evs, s.denyPendingLocked(name, actor, "secret deleted")...)
		err := sess.Delete(name)
		if existed && !s.v.Exists(name) {
			evs = append(evs, audit.Event{Type: audit.SecretDeleted, Actor: actor, Secret: name})
		}
		return errors.Join(err, s.write(evs...))
	})
}

// SetDescription changes the description. It needs no passphrase.
func (s *Service) SetDescription(name, description string) error {
	if err := s.lock(); err != nil {
		return err
	}
	defer s.mu.Unlock()
	return s.v.SetDescription(name, cleanDescription(description))
}

// SetNotifier stores the Telegram bot token and chat ID.
func (s *Service) SetNotifier(token []byte, chatID string, pass []byte) error {
	return s.withKey("set_notifier", "", actorUser, pass, func(*vault.Session) error {
		if err := s.v.SetServiceNotifier(token, chatID); err != nil {
			return err
		}
		return s.write(audit.Event{Type: audit.NotifierSet, Actor: actorUser,
			Detail: "{}"})
	})
}

// ClearFlag removes the flag of a secret. It does nothing if there is none.
func (s *Service) ClearFlag(name string, pass []byte, actor string) error {
	if !vault.ValidName(name) {
		return vault.ErrBadName
	}
	actor = clean(actor, maxActor)
	return s.withKey("clear_flag", name, actor, pass, func(*vault.Session) error {
		m, err := s.v.Get(name)
		if err != nil {
			return err
		}
		if m.Flag == nil {
			return nil
		}
		if err := s.v.ClearFlag(name); err != nil {
			return err
		}
		return s.write(audit.Event{Type: audit.FlagCleared, Actor: actor, Secret: name,
			Detail: jsonDetail(flagDetail{Kind: m.Flag.Kind, Actor: actor, Reason: "flag cleared"})})
	})
}

// Flag marks a secret leaked or invalid. It needs no passphrase. Live grants
// end and pending requests are denied before it returns.
func (s *Service) Flag(name, kind, reason, actor string) error {
	if !vault.ValidName(name) {
		return vault.ErrBadName
	}
	if kind != vault.FlagLeaked && kind != vault.FlagInvalid {
		return vault.ErrBadFlag
	}
	actor = clean(actor, maxActor)
	reason = clean(reason, maxReason)
	if err := s.lock(); err != nil {
		return err
	}
	defer s.mu.Unlock()
	s.sweepLocked()
	if !s.v.Exists(name) {
		return vault.ErrNotFound
	}
	// Revoke first: even if the flag cannot be stored, no grant survives.
	evs := s.revokeSecretLocked(name, actor, "secret flagged")
	err := s.v.SetFlag(name, vault.Flag{Kind: kind, Actor: actor, Reason: reason, At: s.clk.Wall().UTC()})
	if err != nil {
		return errors.Join(fmt.Errorf("core: grants revoked but the flag was not stored: %w", err), s.write(evs...))
	}
	evs = append(evs, s.denyPendingLocked(name, actor, "secret flagged")...)
	evs = append(evs, audit.Event{Type: audit.FlagSet, Actor: actor, Secret: name,
		Detail: jsonDetail(flagDetail{Kind: kind, Actor: actor, Reason: reason})})
	werr := s.write(evs...)
	s.emitLocked(Event{Kind: EventFlagSet, Secret: name, Actor: actor, FlagKind: kind, Reason: reason})
	return werr
}

// Grants and reads -----------------------------------------------------------

// Grant decrypts the secret and makes it readable for d. A request ID marks
// that request approved. d is the user's choice; it is not the request's.
func (s *Service) Grant(name string, d time.Duration, pass []byte, actor, requestID string) (grants.Grant, error) {
	if !vault.ValidName(name) {
		return grants.Grant{}, vault.ErrBadName
	}
	if d <= 0 {
		d = s.cfg.DefaultGrant
	}
	if d > s.cfg.MaxGrant {
		return grants.Grant{}, ErrDurationTooLong
	}
	actor = clean(actor, maxActor)
	if requestID != "" {
		// Refuse before a key derivation is spent on it.
		if err := s.lock(); err != nil {
			return grants.Grant{}, err
		}
		s.expireRequestsLocked()
		err := s.checkRequestLocked(requestID, name)
		s.mu.Unlock()
		if err != nil {
			return grants.Grant{}, err
		}
	}
	var out grants.Grant
	err := s.withKey("grant", name, actor, pass, func(sess *vault.Session) error {
		var err error
		out, err = s.grantLocked(sess, name, d, actor, requestID)
		return err
	})
	if err != nil {
		return grants.Grant{}, err
	}
	return out, nil
}

func (s *Service) grantLocked(sess *vault.Session, name string, d time.Duration, actor, requestID string) (grants.Grant, error) {
	if requestID != "" {
		if err := s.checkRequestLocked(requestID, name); err != nil {
			return grants.Grant{}, err
		}
	}
	if _, err := s.usable(name); err != nil {
		return grants.Grant{}, err
	}
	value, keyID, err := sess.Reveal(name)
	if err != nil {
		return grants.Grant{}, err
	}
	defer crypto.Zero(value)
	var macKey []byte
	if d > grants.PersistAfter {
		if macKey, err = sess.DeriveKey(grantsLabel); err != nil {
			return grants.Grant{}, err
		}
		defer crypto.Zero(macKey)
	}
	id, err := newHexID()
	if err != nil {
		return grants.Grant{}, err
	}
	g := grants.Grant{
		ID: id, Secret: name, KeyID: keyID, Expires: s.clk.Wall().Add(d).UTC(),
		GrantedBy: actor, RequestID: requestID,
	}
	if err := s.g.Add(g, value, macKey); err != nil {
		if errors.Is(err, grants.ErrFlagged) {
			return grants.Grant{}, &FlaggedError{Secret: name}
		}
		return grants.Grant{}, err
	}
	evs := []audit.Event{{Type: audit.GrantStarted, Actor: actor, Secret: name,
		Detail: jsonDetail(map[string]string{"grant": id, "request": requestID,
			"expires": g.Expires.Format(time.RFC3339), "duration": d.String()})}}
	if requestID != "" {
		evs = append(evs, audit.Event{Type: audit.RequestApproved, Actor: actor, Secret: name,
			Detail: jsonDetail(map[string]string{"request": requestID, "grant": id})})
	}
	if err := s.write(evs...); err != nil {
		// No grant without its audit record.
		_ = s.g.Revoke(id)
		return grants.Grant{}, err
	}
	s.known[id] = g
	if requestID != "" {
		s.settleLocked(s.reqs[requestID], StateApproved)
	}
	// Last-granted time is informational; the grant stands without it.
	_ = s.v.TouchGranted(name, s.clk.Wall().UTC())
	return g, nil
}

// Read returns the value of a secret while a grant is live.
func (s *Service) Read(name string) ([]byte, error) {
	if !vault.ValidName(name) {
		return nil, vault.ErrBadName
	}
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	s.sweepLocked()
	if _, err := s.usable(name); err != nil {
		return nil, err
	}
	value, _, err := s.g.Read(name)
	if err != nil {
		return nil, err
	}
	_ = s.v.TouchGranted(name, s.clk.Wall().UTC())
	return value, nil
}

// Revoke ends one live grant.
func (s *Service) Revoke(id, actor string) error {
	actor = clean(actor, maxActor)
	if err := s.lock(); err != nil {
		return err
	}
	defer s.mu.Unlock()
	s.sweepLocked()
	secret := ""
	for _, g := range s.g.List() {
		if g.ID == id {
			secret = g.Secret
		}
	}
	rerr := s.g.Revoke(id)
	if errors.Is(rerr, grants.ErrNoGrant) {
		return ErrNotFound
	}
	delete(s.known, id)
	if rerr != nil {
		rerr = fmt.Errorf("%w: %w", ErrRecordNotRemoved, rerr)
	}
	return errors.Join(rerr, s.write(audit.Event{Type: audit.GrantRevoked, Actor: actor, Secret: secret,
		Detail: jsonDetail(map[string]string{"grant": id, "reason": "revoked"})}))
}

// Restart --------------------------------------------------------------------

func corruptGrantsWarning() error {
	return fmt.Errorf("%w: saved grants are unavailable; no grants were restored", grants.ErrCorrupt)
}

// Unlock verifies the passphrase after a start and returns the notifier
// credentials and the long grants waiting for confirmation. With nothing to
// confirm the locked state ends here; otherwise RestoreGrants ends it.
func (s *Service) Unlock(pass []byte) (UnlockResult, error) {
	var res UnlockResult
	err := s.withKey("unlock", "", actorUser, pass, func(sess *vault.Session) error {
		macKey, err := sess.DeriveKey(grantsLabel)
		if err != nil {
			return err
		}
		defer crypto.Zero(macKey)
		res.Candidates, err = s.g.Candidates(macKey)
		if errors.Is(err, grants.ErrCorrupt) {
			res.GrantsErr = corruptGrantsWarning()
		} else if err != nil {
			return err
		}
		token, chat, nerr := s.v.LoadServiceNotifier()
		if errors.Is(nerr, vault.ErrNoNotifier) {
			legacy, legacyChat, legacyErr := sess.LoadNotifier()
			if legacyErr == nil {
				token, chat, nerr = s.v.MigrateServiceNotifier(legacy, legacyChat)
				crypto.Zero(legacy)
			} else {
				nerr = legacyErr
			}
		}
		switch {
		case nerr == nil:
			res.NotifierToken, res.ChatID = token, chat
		case !errors.Is(nerr, vault.ErrNoNotifier):
			res.NotifierErr = vault.ErrNotifierUnavailable
		}
		if len(res.Candidates) == 0 {
			if err := s.g.Restore(nil, nil); err != nil {
				return err
			}
			s.locked = false
		}
		return s.write(audit.Event{Type: audit.DaemonUnlocked, Actor: actorUser})
	})
	if err != nil {
		crypto.Zero(res.NotifierToken)
		return UnlockResult{}, err
	}
	return res, nil
}

// RestoreGrants makes the confirmed long grants live again after a fresh
// passphrase check and a fresh verification of each record. It returns how
// many are live; unconfirmed ones are dropped. Corrupt grant storage ends the
// locked state without restoring values and returns a warning error.
func (s *Service) RestoreGrants(pass []byte, ids []string) (int, error) {
	n := 0
	err := s.withKey("restore", "", actorUser, pass, func(sess *vault.Session) error {
		macKey, err := sess.DeriveKey(grantsLabel)
		if err != nil {
			return err
		}
		defer crypto.Zero(macKey)
		if _, err := s.g.Candidates(macKey); err != nil {
			if errors.Is(err, grants.ErrCorrupt) {
				rerr := s.g.Restore(nil, nil)
				s.locked = false
				return errors.Join(corruptGrantsWarning(), rerr)
			}
			return err
		}
		rerr := s.g.Restore(ids, func(name string) ([]byte, error) {
			v, _, err := sess.Reveal(name)
			return v, err
		})
		s.locked = false
		want := map[string]bool{}
		for _, id := range ids {
			want[id] = true
		}
		var evs []audit.Event
		for _, g := range s.g.List() {
			if _, seen := s.known[g.ID]; want[g.ID] && !seen {
				s.known[g.ID] = g
				n++
				evs = append(evs, audit.Event{Type: audit.GrantRestored, Actor: actorUser, Secret: g.Secret,
					Detail: jsonDetail(map[string]string{"grant": g.ID, "expires": g.Expires.Format(time.RFC3339)})})
			}
		}
		return errors.Join(rerr, s.write(evs...))
	})
	return n, err
}

// SetExpiry changes informational token metadata and leaves grants unchanged.
// The authenticated website uses the same policy as SetDescription.
func (s *Service) SetExpiry(name, date string) error {
	if !vault.ValidExpiry(date) {
		return vault.ErrBadExpiry
	}
	if err := s.lock(); err != nil {
		return err
	}
	defer s.mu.Unlock()
	return s.v.SetExpiry(name, date)
}
