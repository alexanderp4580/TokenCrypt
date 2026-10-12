package core

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

func TestUnlockCorruptGrantsEndsLock(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.restart()
	p := filepath.Join(e.dir, "grants.json")
	bad := []byte("broken grants")
	if err := os.WriteFile(p, bad, 0600); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.Unlock([]byte(pass))
	if err != nil {
		t.Fatalf("authenticated unlock: %v", err)
	}
	if !errors.Is(res.GrantsErr, grants.ErrCorrupt) || strings.Contains(res.GrantsErr.Error(), "broken grants") {
		t.Fatalf("unsafe or missing warning: %v", res.GrantsErr)
	}
	if len(res.Candidates) != 0 {
		t.Fatalf("result: %+v", res)
	}
	if e.svc.Status().Locked {
		t.Fatal("service remains locked")
	}
	if err := e.mustNotRead(secretName); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("read: %v", err)
	}
	if _, err := e.svc.Grant(secretName, 2*time.Hour, []byte(pass), "user", ""); !errors.Is(err, grants.ErrCorrupt) {
		t.Fatalf("long grant: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, bad) {
		t.Fatalf("corrupt file changed: %v", err)
	}
}

func TestRestoreGrantsCorruptFileEndsLockWithoutRestoring(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	g := e.grant(secretName, 2*time.Hour)
	e.restart()
	if _, err := e.svc.Unlock([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "grants.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	n, err := e.svc.RestoreGrants([]byte(pass), []string{g.ID})
	if n != 0 || !errors.Is(err, grants.ErrCorrupt) {
		t.Fatalf("restore: %d, %v", n, err)
	}
	if e.svc.Status().Locked {
		t.Fatal("service remains locked")
	}
	if err := e.mustNotRead(secretName); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("read: %v", err)
	}
}

func TestStatusListsHealthyAndCorruptSecrets(t *testing.T) {
	e := newEnv(t)
	e.create(secretName, canary)
	e.create(secondName, canary)
	if err := os.WriteFile(filepath.Join(e.dir, "secrets", secondName+".json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	st := e.svc.Status()
	if len(st.Secrets) != 2 || st.Error != "" {
		t.Fatalf("status: %+v", st)
	}
	for _, m := range st.Secrets {
		if m.Name == secondName && (!m.Corrupt || len(m.KeyID) != 0) {
			t.Fatalf("damaged entry: %+v", m)
		}
		if m.Name == secretName && m.Corrupt {
			t.Fatal("healthy entry marked corrupt")
		}
	}
	e.grant(secretName, time.Minute)
	e.mustRead(secretName, canary)
	if _, err := e.v.Get(secondName); !errors.Is(err, vault.ErrCorrupt) {
		t.Fatalf("get: %v", err)
	}
	if _, err := e.svc.Read(secondName); !errors.Is(err, vault.ErrCorrupt) {
		t.Fatalf("read: %v", err)
	}
	if _, err := e.svc.Grant(secondName, time.Minute, []byte(pass), "user", ""); !errors.Is(err, vault.ErrCorrupt) {
		t.Fatalf("grant: %v", err)
	}
	if err := e.svc.Delete(secondName, []byte(pass), "user"); err != nil {
		t.Fatal(err)
	}
	if st := e.svc.Status(); len(st.Secrets) != 1 {
		t.Fatalf("after delete: %+v", st)
	}
}

func TestDescriptionsAreCleanAndBoundedInBytes(t *testing.T) {
	e := newEnv(t)
	for _, create := range []bool{true, false} {
		desc := "first\n\x00\u2028" + strings.Repeat("界", 1000)
		var err error
		if create {
			err = e.svc.Create(secretName, desc, []byte(canary), []byte(pass), "user")
		} else {
			err = e.svc.SetDescription(secretName, desc)
		}
		if err != nil {
			t.Fatal(err)
		}
		got := e.meta(secretName).Description
		if len(got) > 1024 || !utf8.ValidString(got) || !strings.HasPrefix(got, "first   ") || strings.ContainsAny(got, "\n\x00\u2028") {
			t.Fatalf("description bytes=%d prefix=%q", len(got), got[:12])
		}
	}
}
