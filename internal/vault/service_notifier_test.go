package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"tokencrypt/internal/crypto"
)

func TestServiceNotifierPrivateDurableAtomicStorage(t *testing.T) {
	v, _, _ := newSession(t)
	if _, _, err := v.LoadServiceNotifier(); !errors.Is(err, ErrNoNotifier) {
		t.Fatal(err)
	}
	if err := v.SetServiceNotifier([]byte("fake-private-token"), "-1009000000017"); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{filepath.Dir(v.serviceNotifierPath()): 0700, v.serviceNotifierPath(): 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("credential permission mismatch", err)
		}
	}
	before, err := os.ReadFile(v.serviceNotifierPath())
	if err != nil {
		t.Fatal(err)
	}
	beforeRename = func() error { return errors.New("fake atomic write failure") }
	t.Cleanup(func() { beforeRename = nil })
	if err := v.SetServiceNotifier([]byte("fake-replacement"), "-1009000000007"); !errors.Is(err, ErrNotifierUnavailable) {
		t.Fatal("failed write not reported")
	}
	beforeRename = nil
	after, _ := os.ReadFile(v.serviceNotifierPath())
	if !bytes.Equal(before, after) {
		t.Fatal("failed write changed credentials")
	}
	originalSync := syncDir
	synced := map[string]bool{}
	syncDir = func(dir string) error { synced[dir] = true; return originalSync(dir) }
	t.Cleanup(func() { syncDir = originalSync })
	if err := v.SetServiceNotifier([]byte("fake-durable-token"), "-1009000000007"); err != nil {
		t.Fatal(err)
	}
	if !synced[v.dir] || !synced[filepath.Dir(v.serviceNotifierPath())] {
		t.Fatal("credential directory entries were not synced")
	}
	token, chat, err := v.LoadServiceNotifier()
	defer crypto.Zero(token)
	if err != nil || string(token) != "fake-durable-token" || chat != "-1009000000007" {
		t.Fatal("independent credential roundtrip failed")
	}
}

func TestServiceNotifierRejectsUnsafeAndCorruptFiles(t *testing.T) {
	for _, kind := range []string{"malformed", "oversized", "version", "empty", "wide-file", "wide-dir", "symlink", "directory", "directory-symlink"} {
		t.Run(kind, func(t *testing.T) {
			v, _, _ := newSession(t)
			if err := v.SetServiceNotifier([]byte("fake-private-token"), "-1009000000007"); err != nil {
				t.Fatal(err)
			}
			path := v.serviceNotifierPath()
			var err error
			switch kind {
			case "malformed":
				err = os.WriteFile(path, []byte("fake-invalid-json"), 0600)
			case "oversized":
				err = os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxNotifierFileBytes+1), 0600)
			case "version":
				err = os.WriteFile(path, []byte(`{"version":99,"token":"ZmFrZQ==","chat_id":"-1009000000007"}`), 0600)
			case "empty":
				err = os.WriteFile(path, []byte(`{"version":1,"token":"","chat_id":"-1009000000007"}`), 0600)
			case "wide-file":
				err = os.Chmod(path, 0644)
			case "wide-dir":
				err = os.Chmod(filepath.Dir(path), 0755)
			case "symlink":
				if err = os.Remove(path); err == nil {
					err = os.Symlink(filepath.Join(v.dir, "header.json"), path)
				}
			case "directory":
				if err = os.Remove(path); err == nil {
					err = os.Mkdir(path, 0600)
				}
			case "directory-symlink":
				if err = os.RemoveAll(filepath.Dir(path)); err == nil {
					err = os.Symlink(t.TempDir(), filepath.Dir(path))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			token, chat, err := v.LoadServiceNotifier()
			if !errors.Is(err, ErrNotifierUnavailable) || len(token) != 0 || chat != "" || err.Error() != "vault: notifier credentials unavailable" {
				t.Fatal("unsafe credential did not fail generically")
			}
		})
	}
}

func TestServiceNotifierValidatesBeforeChangingFile(t *testing.T) {
	v, _, _ := newSession(t)
	if err := v.SetServiceNotifier([]byte("fake-good-token"), "-1009000000007"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(v.serviceNotifierPath())
	for _, row := range []struct {
		token []byte
		chat  string
	}{{nil, "-1009000000007"}, {[]byte("fake-token"), ""}, {bytes.Repeat([]byte{'x'}, 4097), "-1009000000007"}, {[]byte("fake-token"), string(bytes.Repeat([]byte{'x'}, 65))}} {
		if err := v.SetServiceNotifier(row.token, row.chat); !errors.Is(err, ErrBadNotifier) {
			t.Fatal("bad settings accepted")
		}
	}
	after, _ := os.ReadFile(v.serviceNotifierPath())
	if !bytes.Equal(before, after) {
		t.Fatal("invalid settings changed the file")
	}
}

func TestServiceNotifierFinalSyncFailureLeavesReadableAppliedSettings(t *testing.T) {
	v, _, _ := newSession(t)
	if err := v.SetServiceNotifier([]byte("fake-before-sync-failure"), "-1009000000003"); err != nil {
		t.Fatal(err)
	}
	originalSync := syncDir
	syncDir = func(dir string) error {
		if dir == filepath.Dir(v.serviceNotifierPath()) {
			return errors.New("fake final credential fsync failure")
		}
		return originalSync(dir)
	}
	t.Cleanup(func() { syncDir = originalSync })
	if err := v.SetServiceNotifier([]byte("fake-after-sync-failure"), "9000000000"); !errors.Is(err, ErrNotifierUnavailable) {
		t.Fatal("final sync failure not reported")
	}
	token, chat, err := v.LoadServiceNotifier()
	defer crypto.Zero(token)
	if err != nil || string(token) != "fake-after-sync-failure" || chat != "9000000000" {
		t.Fatal("applied settings unreadable after final sync failure")
	}
}

func TestServiceNotifierChatIDFormat(t *testing.T) {
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
	v, _, _ := newSession(t)
	if err := v.SetServiceNotifier([]byte("fake-token"), " 123456\n"); err != nil {
		t.Fatalf("surrounding whitespace not trimmed: %v", err)
	}
	_, chat, err := v.LoadServiceNotifier()
	if err != nil || chat != "123456" {
		t.Fatalf("stored chat %q err %v", chat, err)
	}
	if err := v.SetServiceNotifier([]byte("fake-token"), "12 34"); !errors.Is(err, ErrBadNotifier) {
		t.Fatal("inner whitespace accepted")
	}
}
