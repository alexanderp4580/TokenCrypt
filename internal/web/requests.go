package web

import "net/http"

func (s *server) requestAction(w http.ResponseWriter, r *http.Request, x session) {
	if !method(w, r, "POST") {
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
