package vault

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"tokencrypt/internal/crypto"
)

// Service notifier credentials are independent of vault keys and secret grants.
// Only the daemon uses this file; the agent API has no credential operation.
const serviceNotifierDir = "service"

var ErrNotifierUnavailable = errors.New("vault: notifier credentials unavailable")

func (v *Vault) serviceNotifierPath() string {
	return filepath.Join(v.dir, serviceNotifierDir, notifierFile)
}

// validChatID accepts an optional minus sign followed by ASCII digits, as in
// 123456 or -100123, and no whitespace.
func validChatID(chat string) bool {
	digits := strings.TrimPrefix(chat, "-")
	if digits == "" || len(chat) > 64 {
		return false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	return true
}

func validServiceNotifier(token []byte, chat string) bool {
	return len(token) > 0 && len(token) <= 4096 && validChatID(chat)
}

// ValidNotifierCredentials reports whether a token and chat ID satisfy the
// service notifier limits, wherever the credentials come from.
func ValidNotifierCredentials(token []byte, chat string) bool {
	return validServiceNotifier(token, chat)
}

// LoadServiceNotifier returns caller-owned credentials without opening the vault.
// Missing configuration is distinct from unsafe or unreadable configuration.
func (v *Vault) LoadServiceNotifier() ([]byte, string, error) {
	dir := filepath.Dir(v.serviceNotifierPath())
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", ErrNoNotifier
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, "", ErrNotifierUnavailable
	}
	fd, err := unix.Open(v.serviceNotifierPath(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", ErrNoNotifier
	}
	if err != nil {
		return nil, "", ErrNotifierUnavailable
	}
	f := os.NewFile(uintptr(fd), v.serviceNotifierPath())
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxNotifierFileBytes {
		return nil, "", ErrNotifierUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, maxNotifierFileBytes+1))
	defer crypto.Zero(b)
	if err != nil || len(b) > maxNotifierFileBytes {
		return nil, "", ErrNotifierUnavailable
	}
	var n notifierData
	if json.Unmarshal(b, &n) != nil || n.Version != formatVersion || !validServiceNotifier(n.Token, n.ChatID) {
		crypto.Zero(n.Token)
		return nil, "", ErrNotifierUnavailable
	}
	return n.Token, n.ChatID, nil
}

func (v *Vault) writeServiceNotifier(token []byte, chat string) error {
	chat = strings.TrimSpace(chat)
	if !validServiceNotifier(token, chat) {
		return ErrBadNotifier
	}
	dir := filepath.Dir(v.serviceNotifierPath())
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return ErrNotifierUnavailable
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return ErrNotifierUnavailable
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return ErrNotifierUnavailable
	}
	// Persist the private directory entry as well as the credential file.
	if err := syncDir(v.dir); err != nil {
		return ErrNotifierUnavailable
	}
	b, err := json.Marshal(notifierData{Version: formatVersion, ChatID: chat, Token: token})
	if err != nil {
		return ErrNotifierUnavailable
	}
	defer crypto.Zero(b)
	if len(b) > maxNotifierFileBytes {
		return ErrFileTooLarge
	}
	if err := writeFileAtomic(v.serviceNotifierPath(), b); err != nil {
		return ErrNotifierUnavailable
	}
	return nil
}

// SetServiceNotifier is called only after core authenticates a settings write.
func (v *Vault) SetServiceNotifier(token []byte, chat string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.writeServiceNotifier(token, chat)
}

// MigrateServiceNotifier installs decrypted settings only when the independent
// credential is absent. An existing corrupt configuration also takes precedence.
func (v *Vault) MigrateServiceNotifier(token []byte, chat string) ([]byte, string, error) {
	chat = strings.TrimSpace(chat)
	v.mu.Lock()
	defer v.mu.Unlock()
	current, currentChat, err := v.LoadServiceNotifier()
	if !errors.Is(err, ErrNoNotifier) {
		return current, currentChat, err
	}
	if err := v.writeServiceNotifier(token, chat); err != nil {
		return nil, "", err
	}
	return append([]byte(nil), token...), chat, nil
}
