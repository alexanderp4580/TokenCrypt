package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"tokencrypt/internal/audit"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/vault"
)

// Request states.
const (
	StatePending  = "pending"
	StateApproved = "approved"
	StateDenied   = "denied"
	StateExpired  = "expired"
)

// maxFinished is how many ended requests are kept so Wait can still report
// their outcome.
const maxFinished = 100

// waitRecheck bounds how long Wait sleeps before it looks at the clocks
// again, so a clock step is noticed. It is a variable for tests.
var waitRecheck = time.Second

// Request is an agent's ask for access to one secret.
type Request struct {
	ID       string
	Secret   string
	Reason   string
	Duration time.Duration
	Created  time.Time
	State    string
}

// entry is a Request with its expiry on both clocks and a channel closed when
// it leaves the pending state.
type entry struct {
	Request
	deadlineWall time.Time
	deadlineMono time.Duration
	done         chan struct{}
}

func (e *entry) expired(wall time.Time, mono time.Duration) bool {
	return !wall.Before(e.deadlineWall) || mono >= e.deadlineMono
}

func newHexID() (string, error) {
	b, err := crypto.NewID()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func jsonDetail(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// settleLocked moves a pending request to state and wakes its waiters.
func (s *Service) settleLocked(e *entry, state string) {
	e.State = state
	close(e.done)
	s.finished = append(s.finished, e.ID)
	for len(s.finished) > maxFinished {
		delete(s.reqs, s.finished[0])
		s.finished = s.finished[1:]
	}
}

// expireRequestsLocked ends every pending request whose deadline has passed
// on either clock. The audit write is best effort: nothing the caller asked
// for depends on it.
func (s *Service) expireRequestsLocked() {
	wall, mono := s.clk.Wall(), s.clk.Mono()
	for _, e := range s.sortedLocked(StatePending) {
		if e.expired(wall, mono) {
			s.settleLocked(e, StateExpired)
			_ = s.write(audit.Event{Type: audit.RequestExpired, Actor: actorDaemon, Secret: e.Secret,
				Detail: jsonDetail(map[string]string{"request": e.ID})})
		}
	}
}

// sortedLocked returns the entries in state, oldest first.
func (s *Service) sortedLocked(state string) []*entry {
	var out []*entry
	for _, e := range s.reqs {
		if e.State == state {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *Service) pendingLocked() []Request {
	es := s.sortedLocked(StatePending)
	out := make([]Request, len(es))
	for i, e := range es {
		out[i] = e.Request
	}
	return out
}

// denyPendingLocked denies every pending request for name and returns the
// audit events.
func (s *Service) denyPendingLocked(name, actor, why string) []audit.Event {
	var evs []audit.Event
	for _, e := range s.sortedLocked(StatePending) {
		if e.Secret != name {
			continue
		}
		s.settleLocked(e, StateDenied)
		evs = append(evs, audit.Event{Type: audit.RequestDenied, Actor: actor, Secret: name,
			Detail: jsonDetail(map[string]string{"request": e.ID, "reason": why})})
	}
	return evs
}

// checkRequestLocked verifies that id is a pending request for name.
func (s *Service) checkRequestLocked(id, name string) error {
	e, ok := s.reqs[id]
	switch {
	case !ok:
		return ErrNotFound
	case e.State != StatePending:
		return ErrNotPending
	case e.Secret != name:
		return ErrRequestMismatch
	}
	return nil
}

// Request creates a pending request from the agent. A duration of zero or
// less means the default; it is only a suggestion for the grant form.
func (s *Service) Request(name, reason string, d time.Duration) (Request, error) {
	if !vault.ValidName(name) {
		return Request{}, vault.ErrBadName
	}
	if d <= 0 {
		d = s.cfg.DefaultGrant
	}
	if d > s.cfg.MaxGrant {
		return Request{}, ErrDurationTooLong
	}
	reason = clean(reason, maxReason)
	if err := s.lock(); err != nil {
		return Request{}, err
	}
	defer s.mu.Unlock()
	s.sweepLocked()
	if _, err := s.usable(name); err != nil {
		return Request{}, err
	}
	if len(s.sortedLocked(StatePending)) >= s.cfg.MaxPending {
		return Request{}, ErrTooManyPending
	}
	id, err := newHexID()
	if err != nil {
		return Request{}, err
	}
	now := s.clk.Wall().UTC()
	e := &entry{
		Request:      Request{ID: id, Secret: name, Reason: reason, Duration: d, Created: now, State: StatePending},
		deadlineWall: now.Add(s.cfg.RequestTTL),
		deadlineMono: s.clk.Mono() + s.cfg.RequestTTL,
		done:         make(chan struct{}),
	}
	s.reqs[id] = e
	auditErr := s.write(audit.Event{Type: audit.RequestCreated, Actor: actorAgent, Secret: name,
		Detail: jsonDetail(map[string]string{"request": id, "reason": reason, "duration": d.String()})})
	s.emitLocked(Event{Kind: EventRequestCreated, Secret: name, RequestID: id, Reason: reason, Duration: d})
	return e.Request, auditErr
}

// Wait blocks until the request is approved, denied or expired, the context
// ends or the service closes, and returns the request as last seen.
func (s *Service) Wait(ctx context.Context, id string) (Request, error) {
	for {
		if err := s.lock(); err != nil {
			return Request{}, err
		}
		s.expireRequestsLocked()
		e, ok := s.reqs[id]
		if !ok {
			s.mu.Unlock()
			return Request{}, ErrNotFound
		}
		r := e.Request
		if r.State != StatePending {
			s.mu.Unlock()
			return r, nil
		}
		done := e.done
		sleep := min(waitRecheck, e.deadlineWall.Sub(s.clk.Wall()), e.deadlineMono-s.clk.Mono())
		s.mu.Unlock()
		if sleep < time.Millisecond {
			sleep = time.Millisecond
		}
		timer := time.NewTimer(sleep)
		select {
		case <-done:
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return r, ctx.Err()
		case <-s.quit:
			timer.Stop()
			return r, ErrClosed
		}
		timer.Stop()
	}
}

// Deny ends a pending request without a grant.
func (s *Service) Deny(id, actor string) error {
	actor = clean(actor, maxActor)
	if err := s.lock(); err != nil {
		return err
	}
	defer s.mu.Unlock()
	s.expireRequestsLocked()
	e, ok := s.reqs[id]
	if !ok {
		return ErrNotFound
	}
	if e.State != StatePending {
		return ErrNotPending
	}
	s.settleLocked(e, StateDenied)
	return s.write(audit.Event{Type: audit.RequestDenied, Actor: actor, Secret: e.Secret,
		Detail: jsonDetail(map[string]string{"request": id})})
}
