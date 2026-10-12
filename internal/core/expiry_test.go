package core

import (
	"errors"
	"testing"
	"time"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/vault"
)

func TestTokenExpiryIsInformationalAndPreservesGrant(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.CreateWithExpiry(secretName, "fake description", []byte(canary), []byte(pass), "user", "2026-01-01"); err != nil {
		t.Fatal(err)
	}
	g := e.grant(secretName, time.Hour)
	if err := e.svc.SetExpiry(secretName, "2026-02-30"); !errors.Is(err, vault.ErrBadExpiry) {
		t.Fatal(err)
	}
	if got := e.svc.Status().Secrets[0].ExpiresOn; got != "2026-01-01" {
		t.Fatal("invalid edit changed expiry")
	}
	if err := e.svc.SetExpiry(secretName, "2028-02-29"); err != nil {
		t.Fatal(err)
	}
	st := e.svc.Status()
	if len(st.Grants) != 1 || st.Grants[0].ID != g.ID || !st.Grants[0].Expires.Equal(g.Expires) {
		t.Fatal("expiry edit altered grant")
	}
	if err := e.svc.SetExpiry(secretName, "2026-01-01"); err != nil {
		t.Fatal(err)
	}
	value, err := e.svc.Read(secretName)
	defer crypto.Zero(value)
	if err != nil || string(value) != canary {
		t.Fatal("expired metadata denied granted read", err)
	}
}
