package web

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"tokencrypt/internal/clock"
	"tokencrypt/internal/grants"
)

const sessionCookie = "tokencrypt_session"
const preauthCookie = "tokencrypt_preauth"
const maxSessions = 4096

type session struct {
	id, csrf   string
	auth       bool
	wall       time.Time
	mono       time.Duration
	candidates []grants.Grant
}

type sessionStore struct {
	mu      sync.Mutex
	items   map[string]session
	clk     clock.Clock
	timeout time.Duration
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (s *sessionStore) expired(x session) bool {
	return s.clk.Wall().Sub(x.wall) >= s.timeout || s.clk.Mono()-x.mono >= s.timeout
}

func (s *sessionStore) create(auth bool) (session, error) {
	id, err := randomToken()
	if err != nil {
		return session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, x := range s.items {
		if s.expired(x) {
			delete(s.items, id)
		}
	}
	if len(s.items) >= maxSessions {
		return session{}, http.ErrServerClosed
	}
	// Strip time.Time's monotonic reading so wall expiry also covers suspend.
	x := session{id: id, csrf: csrf, auth: auth, wall: s.clk.Wall().Round(0), mono: s.clk.Mono()}
	s.items[id] = x
	return x, nil
}

func (s *sessionStore) get(r *http.Request, auth bool) (session, bool) {
	name := preauthCookie
	if auth {
		name = sessionCookie
	}
	c, err := r.Cookie(name)
	if err != nil {
		return session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.items[c.Value]
	if !ok || x.auth != auth {
		return session{}, false
	}
	if s.expired(x) {
		delete(s.items, c.Value)
		return session{}, false
	}
	x.wall, x.mono = s.clk.Wall().Round(0), s.clk.Mono()
	s.items[x.id] = x
	x.candidates = append([]grants.Grant(nil), x.candidates...)
	return x, true
}

func (s *sessionStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
}

func (s *sessionStore) setCandidates(id string, candidates []grants.Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x, ok := s.items[id]; ok {
		x.candidates = append([]grants.Grant(nil), candidates...)
		s.items[id] = x
	}
}

func (s *server) cookie(w http.ResponseWriter, name, value string, remove bool) {
	c := &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode}
	if remove {
		c.MaxAge = -1
		c.Expires = time.Unix(1, 0)
	}
	http.SetCookie(w, c)
}
