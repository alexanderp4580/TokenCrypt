package notify

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"tokencrypt/internal/crypto"
)

var (
	// ErrNotConfigured means the credentials file does not exist.
	ErrNotConfigured = errors.New("notify: credentials file not found")
	// ErrUnusable means the file exists but is unsafe, unreadable or holds
	// missing or invalid credentials. It carries no file content.
	ErrUnusable = errors.New("notify: credentials unusable")
)

const maxCredentialsFileBytes = 64 << 10

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

// ValidNotifierCredentials reports whether a token and chat ID satisfy the
// notifier limits.
func ValidNotifierCredentials(token []byte, chat string) bool {
	return len(token) > 0 && len(token) <= 4096 && validChatID(chat)
}

// LoadCredentials reads TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from a KEY=VALUE
// file. The file must be a regular file (not a symlink) owned by the current
// user with no group or other permission bits. The token belongs to the caller,
// who must zero it.
func LoadCredentials(path string) (token []byte, chat string, err error) {
	return loadCredentials(path, os.Getuid())
}

func loadCredentials(path string, uid int) ([]byte, string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, "", ErrNotConfigured
	}
	if err != nil {
		return nil, "", ErrUnusable
	}
	f := os.NewFile(uintptr(fd), "credentials")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Mode&0o077 != 0 || int(st.Uid) != uid || st.Size > maxCredentialsFileBytes {
		return nil, "", ErrUnusable
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxCredentialsFileBytes+1))
	defer crypto.Zero(raw)
	if err != nil || len(raw) > maxCredentialsFileBytes {
		return nil, "", ErrUnusable
	}
	var token []byte
	var chat string
	var haveToken, haveChat bool
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, value, ok := bytes.Cut(line, []byte("="))
		if !ok {
			continue
		}
		value = unquote(bytes.TrimSpace(value))
		switch string(bytes.TrimSpace(key)) {
		case "TELEGRAM_BOT_TOKEN":
			crypto.Zero(token)
			token, haveToken = bytes.Clone(value), true
		case "TELEGRAM_CHAT_ID":
			chat, haveChat = string(value), true
		}
	}
	if !haveToken || !haveChat || !ValidNotifierCredentials(token, chat) {
		crypto.Zero(token)
		return nil, "", ErrUnusable
	}
	return token, chat, nil
}

func unquote(v []byte) []byte {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}
