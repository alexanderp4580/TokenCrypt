package notify

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeEnv(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "telegram.env")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCredentialsParsesEnvFile(t *testing.T) {
	cases := map[string]string{
		"plain":      "TELEGRAM_BOT_TOKEN=fake-token\nTELEGRAM_CHAT_ID=-100123\n",
		"quotes":     "TELEGRAM_BOT_TOKEN=\"fake-token\"\nTELEGRAM_CHAT_ID='-100123'\n",
		"whitespace": "  TELEGRAM_BOT_TOKEN =  fake-token  \n\tTELEGRAM_CHAT_ID=\t-100123 \n",
		"comments":   "# note\n\nTELEGRAM_BOT_TOKEN=fake-token\n   # another\nTELEGRAM_CHAT_ID=-100123\n",
		"unknown":    "OTHER=1\nTELEGRAM_BOT_TOKEN=fake-token\nEXTRA=\"x\"\nTELEGRAM_CHAT_ID=-100123\n",
		"crlf":       "TELEGRAM_BOT_TOKEN=fake-token\r\nTELEGRAM_CHAT_ID=-100123\r\n",
		"no newline": "TELEGRAM_BOT_TOKEN=fake-token\nTELEGRAM_CHAT_ID=-100123",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			token, chat, err := LoadCredentials(writeEnv(t, content, 0o600))
			if err != nil || !bytes.Equal(token, []byte("fake-token")) || chat != "-100123" {
				t.Fatalf("token %q chat %q err %v", token, chat, err)
			}
		})
	}
}

func TestLoadCredentialsKeepsInnerQuotes(t *testing.T) {
	token, _, err := LoadCredentials(writeEnv(t, "TELEGRAM_BOT_TOKEN=\"fake'token\nTELEGRAM_CHAT_ID=1\n", 0o600))
	if err != nil || string(token) != "\"fake'token" {
		t.Fatalf("token %q err %v", token, err)
	}
}

func TestLoadCredentialsMissingFileIsNotConfigured(t *testing.T) {
	_, _, err := LoadCredentials(filepath.Join(t.TempDir(), "absent.env"))
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadCredentialsRejectsUnsafeFiles(t *testing.T) {
	content := "TELEGRAM_BOT_TOKEN=fake-token\nTELEGRAM_CHAT_ID=1\n"
	for _, mode := range []os.FileMode{0o640, 0o644, 0o604, 0o660, 0o666} {
		if _, _, err := LoadCredentials(writeEnv(t, content, mode)); !errors.Is(err, ErrUnusable) {
			t.Fatalf("mode %o: err = %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if _, _, err := LoadCredentials(writeEnv(t, content, mode)); err != nil {
			t.Fatalf("mode %o: err = %v", mode, err)
		}
	}
	real := writeEnv(t, content, 0o600)
	link := filepath.Join(t.TempDir(), "link.env")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCredentials(link); !errors.Is(err, ErrUnusable) {
		t.Fatalf("symlink: err = %v", err)
	}
	if _, _, err := LoadCredentials(t.TempDir()); !errors.Is(err, ErrUnusable) {
		t.Fatalf("directory: err = %v", err)
	}
	if _, _, err := loadCredentials(real, os.Getuid()+1); !errors.Is(err, ErrUnusable) {
		t.Fatalf("wrong owner: err = %v", err)
	}
	big := "TELEGRAM_BOT_TOKEN=fake\nTELEGRAM_CHAT_ID=1\n# " + string(bytes.Repeat([]byte{'x'}, 70<<10)) + "\n"
	if _, _, err := LoadCredentials(writeEnv(t, big, 0o600)); !errors.Is(err, ErrUnusable) {
		t.Fatalf("oversized: err = %v", err)
	}
}

func TestLoadCredentialsRejectsPartialAndInvalidValues(t *testing.T) {
	for name, content := range map[string]string{
		"empty file":    "",
		"token only":    "TELEGRAM_BOT_TOKEN=fake-token\n",
		"chat only":     "TELEGRAM_CHAT_ID=1\n",
		"empty token":   "TELEGRAM_BOT_TOKEN=\nTELEGRAM_CHAT_ID=1\n",
		"bad chat":      "TELEGRAM_BOT_TOKEN=fake-token\nTELEGRAM_CHAT_ID=@channel\n",
		"long token":    "TELEGRAM_BOT_TOKEN=" + string(bytes.Repeat([]byte{'t'}, 4097)) + "\nTELEGRAM_CHAT_ID=1\n",
		"commented out": "#TELEGRAM_BOT_TOKEN=fake-token\nTELEGRAM_CHAT_ID=1\n",
	} {
		t.Run(name, func(t *testing.T) {
			token, chat, err := LoadCredentials(writeEnv(t, content, 0o600))
			if !errors.Is(err, ErrUnusable) || len(token) != 0 || chat != "" {
				t.Fatalf("token %q chat %q err %v", token, chat, err)
			}
		})
	}
}

func TestValidNotifierCredentialsChatIDFormat(t *testing.T) {
	for _, chat := range []string{"123456", "-100123", "0"} {
		if !ValidNotifierCredentials([]byte("fake-token"), chat) {
			t.Fatalf("chat %q rejected", chat)
		}
	}
	for _, chat := range []string{"", " 123", "123 ", "12 3", "12\n3", "-", "--1", "1-", "abc", "@channel", "+1", "１２３", string(bytes.Repeat([]byte{'1'}, 65))} {
		if ValidNotifierCredentials([]byte("fake-token"), chat) {
			t.Fatalf("chat %q accepted", chat)
		}
	}
	if ValidNotifierCredentials(nil, "1") || ValidNotifierCredentials(bytes.Repeat([]byte{'t'}, 4097), "1") {
		t.Fatal("token limits not enforced")
	}
}
