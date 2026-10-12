package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"tokencrypt/internal/crypto"
)

const (
	notifierFile  = "notifier.json"
	kindNotifier  = "notifier"
	notifierLabel = "tokencrypt notifier v1"
)

var (
	ErrNoNotifier  = errors.New("vault: notifier not set")
	ErrBadNotifier = errors.New("vault: notifier token and chat ID must not be empty")
)

type notifierData struct {
	Version int    `json:"version"`
	ChatID  string `json:"chat_id"`
	Token   []byte `json:"token"`
}

// notifierAAD binds the sealed token to the notifier kind, the chat ID (so an
// edited chat ID cannot redirect notices) and the key ID of this vault's
// master key.
func (s *Session) notifierAAD(chatID string) []byte {
	return crypto.AAD(formatVersion, kindNotifier, chatID, s.mkID)
}

// SetNotifier stores the chat ID in plain and the bot token sealed under
// HKDF(MK, "tokencrypt notifier v1"). It replaces any earlier notifier.
func (s *Session) SetNotifier(token []byte, chatID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mk == nil {
		return ErrClosed
	}
	if len(token) == 0 || chatID == "" {
		return ErrBadNotifier
	}
	nk, err := crypto.HKDF(s.mk, notifierLabel)
	if err != nil {
		return err
	}
	defer crypto.Zero(nk)
	sealed, err := crypto.Seal(nk, token, s.notifierAAD(chatID))
	if err != nil {
		return err
	}
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	return writeJSON(filepath.Join(s.v.dir, notifierFile), maxNotifierFileBytes,
		&notifierData{Version: formatVersion, ChatID: chatID, Token: sealed})
}

// LoadNotifier returns the bot token and chat ID. It returns ErrNoNotifier if
// none was set and ErrCorrupt if the file is unreadable or does not
// authenticate under this vault. The token belongs to the caller.
func (s *Session) LoadNotifier() (token []byte, chatID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mk == nil {
		return nil, "", ErrClosed
	}
	b, err := readBounded(filepath.Join(s.v.dir, notifierFile), maxNotifierFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", ErrNoNotifier
	}
	if err != nil {
		return nil, "", err
	}
	var n notifierData
	if err := json.Unmarshal(b, &n); err != nil {
		return nil, "", fmt.Errorf("%w: %s: %v", ErrCorrupt, notifierFile, err)
	}
	if n.Version != formatVersion || n.ChatID == "" {
		return nil, "", fmt.Errorf("%w: %s fields", ErrCorrupt, notifierFile)
	}
	nk, err := crypto.HKDF(s.mk, notifierLabel)
	if err != nil {
		return nil, "", err
	}
	defer crypto.Zero(nk)
	token, err = crypto.Open(nk, n.Token, s.notifierAAD(n.ChatID))
	if err != nil {
		if errors.Is(err, crypto.ErrAuth) {
			return nil, "", fmt.Errorf("%w: %s does not authenticate", ErrCorrupt, notifierFile)
		}
		return nil, "", err
	}
	return token, n.ChatID, nil
}
