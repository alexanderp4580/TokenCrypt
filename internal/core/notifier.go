package core

import (
	"errors"
	"tokencrypt/internal/vault"
)

// Notifier supplies the daemon's independent credential. The caller owns the
// token and must zero it. This operation is never exposed on the agent socket.
func (s *Service) Notifier() UnlockResult {
	token, chat, err := s.v.LoadServiceNotifier()
	if errors.Is(err, vault.ErrNoNotifier) {
		err = nil
	}
	return UnlockResult{NotifierToken: token, ChatID: chat, NotifierErr: err}
}
