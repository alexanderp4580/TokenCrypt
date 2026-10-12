package cli

import (
	"strings"
	"testing"
	"time"
	"tokencrypt/internal/core"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

func TestStatusSeparatesTokenExpiryFromGrantExpiry(t *testing.T) {
	f := fakeServer(t, nil)
	f.status = core.Status{Secrets: []vault.Meta{{Name: "never"}, {Name: "dated", ExpiresOn: "2028-02-29"}}, Grants: []grants.Grant{{ID: "fake", Secret: "dated", Expires: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)}}}
	code, out, err := invoke(t, f, "status")
	if code != 0 || err != "" || !strings.Contains(string(out), `token_expires_on="Never"`) || !strings.Contains(string(out), `token_expires_on="2028-02-29"`) || !strings.Contains(string(out), `expires="2026-10-12T12:00:00Z"`) {
		t.Fatalf("status expiry fields missing: %d %s", code, out)
	}
}
