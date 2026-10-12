package api

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusExposesExpiryWithoutValuesOrWriteRoute(t *testing.T) {
	s, _ := service(t)
	path := filepath.Join(t.TempDir(), "sock")
	start(t, s, path, peerUID)
	c := client(t, path)
	st, err := c.Status()
	if err != nil || len(st.Secrets) != 1 || st.Secrets[0].ExpiresOn != "" {
		t.Fatal("legacy expiry status", err)
	}
	if err := s.SetExpiry("api_token", "2028-02-29"); err != nil {
		t.Fatal(err)
	}
	st, err = c.Status()
	if err != nil || st.Secrets[0].ExpiresOn != "2028-02-29" {
		t.Fatal("dated expiry status", err)
	}
	raw := rawClient(t, path)
	code, body := exchange(t, raw, "GET", "/status", "")
	if code != 200 || !strings.Contains(body, `"expires_on":"2028-02-29"`) || strings.Contains(body, fakeValue) || strings.Contains(body, fakePass) {
		t.Fatal("expiry wire metadata incorrect or unredacted")
	}
	for _, route := range []string{"/expiry", "/set_expiry"} {
		if code, _ := exchange(t, raw, "POST", route, `{"name":"api_token","expires_on":""}`); code != 404 {
			t.Fatal("expiry mutation exposed to agent")
		}
	}
}
