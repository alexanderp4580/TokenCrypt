package web

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestExpiryPresetCalendarBoundaries(t *testing.T) {
	for _, tc := range []struct{ today, choice, date, want string }{
		{"2027-01-31", "1m", "", "2027-02-28"},
		{"2028-01-31", "1m", "", "2028-02-29"},
		{"2028-02-29", "1y", "", "2029-02-28"},
		{"2028-02-29", "2y", "", "2030-02-28"},
		{"2026-12-31", "1d", "", "2027-01-01"},
		{"2026-10-12", "3d", "", "2026-10-15"},
		{"2026-10-12", "1w", "", "2026-10-19"},
		{"2026-10-12", "2w", "", "2026-10-26"},
		{"2026-11-30", "3m", "", "2027-02-28"},
		{"2026-08-31", "6m", "", "2027-02-28"},
		{"2026-10-12", "never", "2026-01-01", ""},
		{"2026-10-12", "custom", "2026-01-01", "2026-01-01"},
	} {
		today, _ := time.Parse("2006-01-02", tc.today)
		got, err := resolveExpiry(tc.choice, tc.date, today)
		if err != nil || got != tc.want {
			t.Errorf("%s + %s: got %q err=%v want %q", tc.today, tc.choice, got, err, tc.want)
		}
	}
	for _, tc := range []struct{ choice, date string }{{"custom", ""}, {"custom", "2027-02-29"}, {"custom", "bad"}, {"unexpected", ""}} {
		if _, err := resolveExpiry(tc.choice, tc.date, time.Now()); err == nil {
			t.Errorf("accepted invalid expiry %q/%q", tc.choice, tc.date)
		}
	}
}

func TestTokenExpiryDisplayUsesCalendarDays(t *testing.T) {
	now := time.Date(2026, 10, 12, 23, 59, 0, 0, time.FixedZone("viewer", -7*3600))
	for _, tc := range []struct{ date, want string }{{"", "Never"}, {"2026-10-11", "Expired"}, {"2026-10-12", "Expires today"}, {"2026-10-13", "1 day left"}, {"2026-10-15", "3 days left"}} {
		if got := expiryRemaining(tc.date, now); got != tc.want {
			t.Errorf("%q got %q want %q", tc.date, got, tc.want)
		}
	}
}

func TestExpiryCreateEditValidationAndRetention(t *testing.T) {
	svc, clk, _ := testService(t)
	clk.SetWall(time.Date(2027, 1, 31, 12, 0, 0, 0, time.UTC))
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	w := request(h, "GET", "/secrets", nil, a)
	for _, option := range []string{"Never", "1 day", "3 days", "1 week", "2 weeks", "1 month", "3 months", "6 months", "1 year", "2 years", "Custom date", `type="date"`} {
		if !strings.Contains(w.Body.String(), option) {
			t.Errorf("missing expiry choice/input %q", option)
		}
	}
	f := url.Values{"csrf": {csrf}, "name": {"fake_expiry"}, "description": {"fake"}, "value": {pageCanary}, "passphrase": {fakePass}, "expiry_choice": {"1m"}}
	w = request(h, "POST", "/secrets/create", f, a)
	if w.Code != 303 || svc.Status().Secrets[0].ExpiresOn != "2027-02-28" {
		t.Fatalf("preset without JS: %d", w.Code)
	}
	assertRedacted(t, w)

	f.Set("expires_on", "2027-02-30")
	w = request(h, "POST", "/secrets/expiry", f, a)
	if w.Code != 400 || svc.Status().Secrets[0].ExpiresOn != "2027-02-28" || !strings.Contains(w.Body.String(), `value="1m" selected`) {
		t.Fatal("malformed preset date was accepted")
	}
	f.Del("expires_on")
	f.Del("passphrase")
	f.Set("expiry_choice", "custom")
	f.Set("expires_on", "2027-02-30")
	w = request(h, "POST", "/secrets/expiry", f, a)
	if w.Code != 400 || svc.Status().Secrets[0].ExpiresOn != "2027-02-28" || !strings.Contains(w.Body.String(), `value="custom" selected`) || !strings.Contains(w.Body.String(), `value="2027-02-30"`) {
		t.Fatalf("invalid edit retention: %d %s", w.Code, w.Body.String())
	}
	f.Set("expires_on", "2026-01-01")
	w = request(h, "POST", "/secrets/expiry", f, a)
	if w.Code != 303 || svc.Status().Secrets[0].ExpiresOn != "2026-01-01" {
		t.Fatalf("expired edit: %d", w.Code)
	}
	for _, path := range []string{"/secrets", "/secrets/edit?name=fake_expiry"} {
		w = request(h, "GET", path, nil, a)
		if !strings.Contains(w.Body.String(), "Expired") || !strings.Contains(w.Body.String(), "1 Jan 2026") {
			t.Fatalf("expiry missing from %s", path)
		}
		assertRedacted(t, w)
	}
	// Reject mutations without session or CSRF.
	if w = request(h, "POST", "/secrets/expiry", f); w.Code != 303 {
		t.Fatalf("unauthenticated expiry: %d", w.Code)
	}
	f.Del("csrf")
	if w = request(h, "POST", "/secrets/expiry", f, a); w.Code != 403 {
		t.Fatalf("expiry missing CSRF: %d", w.Code)
	}
	f.Set("csrf", csrf)
	f.Set("name", "fake_second")
	f.Set("passphrase", fakePass)
	f.Set("expires_on", "")
	w = request(h, "POST", "/secrets/create", f, a)
	if w.Code != 400 || len(svc.Status().Secrets) != 1 || !strings.Contains(w.Body.String(), `value="custom" selected`) {
		t.Fatal("missing custom date did not retain choice/refuse creation")
	}
	f.Set("expires_on", "2028-03-01")
	f.Set("passphrase", "fake wrong pass")
	w = request(h, "POST", "/secrets/create", f, a)
	if w.Code != 400 || !strings.Contains(w.Body.String(), `value="2028-03-01"`) {
		t.Fatal("auth error did not retain expiry")
	}
	assertRedacted(t, w)
}

func TestExpiryEditRequiresExplicitChoiceAndPreservesMetadataAndGrants(t *testing.T) {
	svc, clk, dir := testService(t)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	// Legacy creation keeps its default when no expiry fields are submitted.
	f := url.Values{"csrf": {csrf}, "name": {"fake_expiry"}, "description": {"fake description"}, "value": {pageCanary}, "passphrase": {fakePass}}
	if w := request(h, "POST", "/secrets/create", f, a); w.Code != 303 || svc.Status().Secrets[0].ExpiresOn != "" {
		t.Fatal("legacy creation must default to Never")
	}
	if err := svc.SetExpiry("fake_expiry", "2028-02-29"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Grant("fake_expiry", time.Hour, []byte(fakePass), "user", ""); err != nil {
		t.Fatal(err)
	}
	before := svc.Status()
	metadata, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, choice := range []url.Values{
		{},
		{"expiry_choice": {""}},
		{"expires_on": {"2028-03-01"}},
		{"expiry_choice": {"never", "custom"}, "expires_on": {"2028-03-01"}},
	} {
		choice.Set("csrf", csrf)
		choice.Set("name", "fake_expiry")
		w := request(h, "POST", "/secrets/expiry", choice, a)
		if w.Code != 400 {
			t.Errorf("missing or ambiguous edit choice returned %d, want 400", w.Code)
		}
		after := svc.Status()
		if !reflect.DeepEqual(before.Secrets, after.Secrets) || !reflect.DeepEqual(before.Grants, after.Grants) {
			t.Fatal("rejected expiry edit changed metadata or live grants")
		}
		current, err := os.ReadFile(filepath.Join(dir, "meta.json"))
		if err != nil || !bytes.Equal(metadata, current) {
			t.Fatal("rejected expiry edit wrote metadata", err)
		}
		assertRedacted(t, w)
	}
	f = url.Values{"csrf": {csrf}, "name": {"fake_expiry"}, "expiry_choice": {"never"}}
	if w := request(h, "POST", "/secrets/expiry", f, a); w.Code != 303 || svc.Status().Secrets[0].ExpiresOn != "" {
		t.Fatal("explicit Never must clear expiry")
	}
	if !reflect.DeepEqual(before.Grants, svc.Status().Grants) {
		t.Fatal("explicit Never altered live grants")
	}
}
