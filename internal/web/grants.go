package web

import (
	"net/http"
	"time"

	"tokencrypt/internal/crypto"
	"tokencrypt/internal/vault"
)

type durationChoice struct {
	Value, Label string
	Duration     time.Duration
}

var durationChoices = []durationChoice{
	{"10m", "10 minutes", 10 * time.Minute}, {"1h", "1 hour", time.Hour},
	{"24h", "24 hours", 24 * time.Hour}, {"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour}, {"90d", "90 days", 90 * 24 * time.Hour},
}

func formDuration(r *http.Request) (time.Duration, bool) {
	for _, c := range durationChoices {
		if r.PostForm.Get("duration") == c.Value {
			return c.Duration, true
		}
	}
	return 0, false
}

func (s *server) grantsPage(w http.ResponseWriter, r *http.Request, x session) {
	if !method(w, r, "GET", "POST") {
		return
	}
	if r.Method == "GET" {
		name := r.URL.Query().Get("name")
		if name != "" && !vault.ValidName(name) {
			s.result(w, r, x, "grants", vault.ErrBadName)
			return
		}
		d := pageData{Title: "Grants", Section: "grants", CSRF: x.csrf, Authenticated: true, State: s.svc.Status(), Choices: durationChoices}
		for _, m := range d.State.Secrets {
			if !m.Corrupt && m.Flag == nil {
				d.GrantSecrets = append(d.GrantSecrets, m)
				if m.Name == name {
					copy := m
					d.Secret = &copy
				}
			}
		}
		if d.State.Error != "" {
			d.Error = "Secret list unavailable. Check the vault storage."
		}
		s.render(w, "grants", 200, d)
		return
	}
	s.approveGrant(w, r, x, "grants", "")
}

func (s *server) approveGrant(w http.ResponseWriter, r *http.Request, x session, page, requestID string) {
	name := r.PostForm.Get("name")
	if !vault.ValidName(name) {
		s.result(w, r, x, page, vault.ErrBadName)
		return
	}
	duration, ok := formDuration(r)
	if !ok {
		s.page(w, page, 400, x, "", "Choose one of the six durations, up to 90 days.")
		return
	}
	pass, ok := passphrase(r)
	if !ok {
		s.page(w, page, 400, x, "", "Enter a passphrase of at most 4096 bytes.")
		return
	}
	defer crypto.Zero(pass)
	_, err := s.svc.Grant(name, duration, pass, "user", requestID)
	s.result(w, r, x, page, err)
}

func (s *server) revoke(w http.ResponseWriter, r *http.Request, x session) {
	if !method(w, r, "POST") {
		return
	}
	id := r.PostForm.Get("id")
	if id == "" || len(id) > 128 {
		s.page(w, "grants", 400, x, "", "Choose a live grant.")
		return
	}
	s.result(w, r, x, "grants", s.svc.Revoke(id, "user"))
}
