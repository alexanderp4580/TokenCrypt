package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExpiryMetadataValidationIsolationAndPersistence(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	must(t, s.Create("tok", "fake description", canary))
	if got := mustGet(t, v, "tok").ExpiresOn; got != "" {
		t.Fatal("legacy create must default Never")
	}
	must(t, v.SetFlag("tok", Flag{Kind: FlagInvalid, Actor: "fake"}))
	before := mustGet(t, v, "tok")
	cipher, err := os.ReadFile(filepath.Join(dir, "secrets", "tok.json"))
	must(t, err)
	must(t, v.SetExpiry("tok", "2028-02-29"))
	after := mustGet(t, v, "tok")
	if after.ExpiresOn != "2028-02-29" || !sameMeta(before, after) {
		t.Fatal("expiry edit changed other metadata")
	}
	for _, bad := range []string{"2027-02-29", "2026-04-31", "2026-1-01", "0000-01-01", "2026-10-12T00:00:00Z", "bad"} {
		if err := v.SetExpiry("tok", bad); !errors.Is(err, ErrBadExpiry) {
			t.Errorf("accepted invalid date %q", bad)
		}
		if mustGet(t, v, "tok").ExpiresOn != "2028-02-29" {
			t.Fatal("invalid edit changed expiry")
		}
	}
	current, err := os.ReadFile(filepath.Join(dir, "secrets", "tok.json"))
	must(t, err)
	if !bytes.Equal(cipher, current) {
		t.Fatal("expiry edit rewrote ciphertext")
	}
	reopened, err := Open(dir)
	must(t, err)
	if mustGet(t, reopened, "tok").ExpiresOn != "2028-02-29" {
		t.Fatal("expiry lost on reopen")
	}
	must(t, s.UpdateValue("tok", []byte("fake replacement")))
	must(t, s.Rename("tok", "renamed"))
	if mustGet(t, v, "renamed").ExpiresOn != "2028-02-29" {
		t.Fatal("expiry lost on value update or rename")
	}
	must(t, v.SetExpiry("renamed", ""))
	if mustGet(t, v, "renamed").ExpiresOn != "" {
		t.Fatal("Never did not clear date")
	}
	must(t, os.Remove(metaPath(dir)))
	if mustGet(t, v, "renamed").ExpiresOn != "" {
		t.Fatal("missing legacy metadata must mean Never")
	}
}

func TestCreateWithExpiryRejectsInvalidBeforeWrites(t *testing.T) {
	v, s, dir, _ := newClockSession(t)
	if err := s.CreateWithExpiry("tok", "fake", canary, "2026-02-30"); !errors.Is(err, ErrBadExpiry) {
		t.Fatal(err)
	}
	if v.Exists("tok") {
		t.Fatal("invalid expiry created secret")
	}
	if _, err := os.Stat(metaPath(dir)); !os.IsNotExist(err) {
		t.Fatal("invalid expiry wrote metadata")
	}
	must(t, s.CreateWithExpiry("tok", "fake", canary, "2026-01-01"))
	if mustGet(t, v, "tok").ExpiresOn != "2026-01-01" {
		t.Fatal("expired civil date must be allowed")
	}
}
