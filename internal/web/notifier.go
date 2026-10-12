package web

import (
	"net/http"
	"strings"

	"tokencrypt/internal/crypto"
	"tokencrypt/internal/vault"
)

func (s *server) notifier(w http.ResponseWriter, r *http.Request, x session) {
	if !method(w, r, "GET", "POST") {
		return
	}
	if r.Method == "GET" {
		s.page(w, "notifier", 200, x, "", "")
		return
	}
	token, chat := r.PostForm.Get("token"), strings.TrimSpace(r.PostForm.Get("chat_id"))
	if !vault.ValidNotifierCredentials([]byte(token), chat) {
		s.page(w, "notifier", 400, x, "", "Enter a bot token (up to 4096 bytes) and a numeric chat ID such as 123456 or -100123.")
		return
	}
	pass, ok := passphrase(r)
	if !ok {
		s.page(w, "notifier", 400, x, "", "Enter a passphrase of at most 4096 bytes.")
		return
	}
	defer crypto.Zero(pass)
	value := []byte(token)
	defer crypto.Zero(value)
	err := s.svc.SetNotifier(value, chat, pass)
	// A rename may stand despite an audit or final fsync failure. Read-back
	// reconciliation also preserves the current credential on failed auth.
	if s.cfg.OnNotifier != nil {
		s.cfg.OnNotifier()
	}
	s.result(w, r, x, "notifier", err)
}
