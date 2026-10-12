package web

import (
	"errors"
	"net/http"

	"tokencrypt/internal/core"
)

func (s *server) requestAction(w http.ResponseWriter, r *http.Request, x session) {
	if !method(w, r, "POST") {
		return
	}
	if r.URL.Path == "/requests/deny-all" {
		s.denyAll(w, r, x)
		return
	}
	id := r.PostForm.Get("id")
	if id == "" || len(id) > 128 {
		s.page(w, "requests", 400, x, "", "Choose a pending request.")
		return
	}
	if r.URL.Path == "/requests/approve" {
		s.approveGrant(w, r, x, "requests", id)
	} else {
		s.result(w, r, x, "requests", s.svc.Deny(id, "user"))
	}
}

// denyAll rejects every request pending when the form is handled. A request
// that settled in the meantime is skipped.
func (s *server) denyAll(w http.ResponseWriter, r *http.Request, x session) {
	for _, p := range s.svc.Status().Pending {
		if err := s.svc.Deny(p.ID, "user"); err != nil && !errors.Is(err, core.ErrNotPending) && !errors.Is(err, core.ErrNotFound) {
			s.result(w, r, x, "requests", err)
			return
		}
	}
	http.Redirect(w, r, "/requests", http.StatusSeeOther)
}
