package core

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tokencrypt/internal/crypto"
	"tokencrypt/internal/vault"
)

func legacyNotifier(t *testing.T, e *env) {
	t.Helper()
	sess, err := e.v.Unlock([]byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.SetNotifier([]byte("fake-legacy-bot"), "-1009000000013"); err != nil {
		t.Fatal(err)
	}
}

func TestNotifierMigrationRequiresSuccessfulUnlockAndPreservesVault(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.grant(secretName, 24*time.Hour)
	legacyNotifier(t, e)
	paths := []string{"header.json", "secrets/" + secretName + ".json", "grants.json", "notifier.json"}
	before := make(map[string][]byte)
	for _, path := range paths {
		raw, err := os.ReadFile(filepath.Join(e.dir, path))
		if err != nil {
			t.Fatal(err)
		}
		before[path] = raw
	}
	e.restart()
	n := e.svc.Notifier()
	if n.NotifierErr != nil || len(n.NotifierToken) != 0 || !e.svc.Status().Locked {
		t.Fatal("legacy settings loaded before unlock")
	}
	if _, err := e.svc.Unlock([]byte(wrongPass)); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "service", "notifier.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong passphrase migrated settings")
	}
	res, err := e.svc.Unlock([]byte(pass))
	if err != nil || res.NotifierErr != nil || string(res.NotifierToken) != "fake-legacy-bot" || res.ChatID != "-1009000000013" || len(res.Candidates) != 1 {
		t.Fatal("authenticated migration failed", err)
	}
	crypto.Zero(res.NotifierToken)
	if !errors.Is(e.mustNotRead(secretName), ErrLocked) {
		t.Fatal("migration restored an unconfirmed grant")
	}
	for path, raw := range before {
		after, err := os.ReadFile(filepath.Join(e.dir, path))
		if err != nil || !bytes.Equal(raw, after) {
			t.Fatalf("migration changed %s", path)
		}
	}
	e.restart()
	n = e.svc.Notifier()
	if n.NotifierErr != nil || string(n.NotifierToken) != "fake-legacy-bot" {
		t.Fatal("migrated settings unavailable at restart")
	}
	crypto.Zero(n.NotifierToken)
}

func TestStandaloneNotifierTakesPrecedenceOverEncryptedSettings(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "configured", true: "corrupt"}[corrupt], func(t *testing.T) {
			e := newEnv(t)
			legacyNotifier(t, e)
			if err := e.svc.SetNotifier([]byte("fake-current-bot"), "-1009000000009", []byte(pass)); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(e.dir, "service", "notifier.json")
			if corrupt {
				if err := os.WriteFile(path, []byte("fake malformed credential"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			e.restart()
			res, err := e.svc.Unlock([]byte(pass))
			if err != nil {
				t.Fatal(err)
			}
			defer crypto.Zero(res.NotifierToken)
			if corrupt {
				if !errors.Is(res.NotifierErr, vault.ErrNotifierUnavailable) || len(res.NotifierToken) != 0 {
					t.Fatal("corrupt settings did not fail closed")
				}
			} else if string(res.NotifierToken) != "fake-current-bot" || res.ChatID != "-1009000000009" {
				t.Fatal("encrypted settings overwrote current settings")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("unlock overwrote standalone settings")
			}
		})
	}
}

func TestNotifierCredentialsAreIsolatedFromAuditAndStatus(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.SetNotifier([]byte("fake-isolated-bot"), "9000000012", []byte(pass)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(e.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"fake-isolated-bot", "9000000012", pass} {
		if strings.Contains(string(raw), credential) {
			t.Fatal("audit contains a credential")
		}
	}
	status := e.svc.Status()
	if len(status.Secrets) != 0 || len(status.Grants) != 0 {
		t.Fatal("notifier became a protected secret or grant")
	}
}
