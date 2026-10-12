package web

import (
	"crypto/subtle"
	"errors"
	"mime"
	"net/http"
)

// The bound allows a URL-encoded 1 MiB secret, including percent expansion.
const maxFormBytes = 4 << 20
const maxPassphraseBytes = 4096

func parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		http.Error(w, "Unsupported form", http.StatusUnsupportedMediaType)
		return false
	}
	if err := r.ParseForm(); err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Invalid form", http.StatusBadRequest)
		}
		return false
	}
	return true
}

func checkCSRF(w http.ResponseWriter, r *http.Request, x session) bool {
	if !parseForm(w, r) {
		return false
	}
	tokens := r.PostForm["csrf"]
	if len(tokens) != 1 || subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(x.csrf)) != 1 {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return false
	}
	return true
}
