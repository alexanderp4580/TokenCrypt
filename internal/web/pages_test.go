package web

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"tokencrypt/internal/audit"
	"tokencrypt/internal/core"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/grants"
	"tokencrypt/internal/vault"
)

const pageCanary = "fake-secret-canary-never-render"

func assertRedacted(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, s := range []string{pageCanary, fakePass, "fake-bot-token"} {
		if strings.Contains(w.Body.String(), s) {
			t.Fatalf("response exposed submitted credential at status %d", w.Code)
		}
	}
}

func createPageSecret(t *testing.T, svc *core.Service, name string) {
	t.Helper()
	if err := svc.Create(name, "Fake description", []byte(pageCanary), []byte(fakePass), "user"); err != nil {
		t.Fatal(err)
	}
}

func TestSecretPagesCRUDNeverRenderValues(t *testing.T) {
	svc, clk, dir := testService(t)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	f := url.Values{"csrf": {csrf}, "name": {"fake_note"}, "description": {"Fake note"}, "value": {pageCanary}, "passphrase": {"fake wrong pass"}}
	w := request(h, "POST", "/secrets/create", f, a)
	if w.Code != 400 || len(svc.Status().Secrets) != 0 {
		t.Fatalf("wrong-pass create: %d", w.Code)
	}
	assertRedacted(t, w)
	f.Set("passphrase", fakePass)
	w = request(h, "POST", "/secrets/create", f, a)
	if w.Code != 303 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	assertRedacted(t, w)
	for _, path := range []string{"/", "/secrets", "/secrets/edit?name=fake_note"} {
		w = request(h, "GET", path, nil, a)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "fake_note") {
			t.Fatalf("secret page %s: %d", path, w.Code)
		}
		assertRedacted(t, w)
	}
	f.Set("value", pageCanary+" updated")
	w = request(h, "POST", "/secrets/update", f, a)
	if w.Code != 303 {
		t.Fatalf("update: %d", w.Code)
	}
	assertRedacted(t, w)
	for _, path := range []string{"/secrets", "/secrets/edit?name=fake_note"} {
		w = request(h, "GET", path, nil, a)
		if w.Code != 200 {
			t.Fatalf("updated secret page %s: %d", path, w.Code)
		}
		assertRedacted(t, w)
	}
	f.Set("new_name", "renamed_note")
	w = request(h, "POST", "/secrets/rename", f, a)
	if w.Code != 303 || svc.Status().Secrets[0].Name != "renamed_note" {
		t.Fatalf("rename: %d", w.Code)
	}
	f.Set("name", "renamed_note")
	f.Set("description", "Edited description")
	if w = request(h, "POST", "/secrets/description", f, a); w.Code != 303 || svc.Status().Secrets[0].Description != "Edited description" {
		t.Fatalf("description: %d", w.Code)
	}
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := v.Unlock([]byte(fakePass))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	value, _, err := sess.Reveal("renamed_note")
	if err != nil || string(value) != pageCanary+" updated" {
		t.Fatal("web update did not store exact value", err)
	}
	crypto.Zero(value)
	if w = request(h, "POST", "/secrets/delete", f, a); w.Code != 303 || len(svc.Status().Secrets) != 0 {
		t.Fatalf("delete: %d", w.Code)
	}
}

func TestCreateInvalidFieldsShowErrorsAndAllowCorrection(t *testing.T) {
	cases := []struct {
		label, name, pass, message string
	}{
		{"mixed_name", "Cloud Flare Access Tolen", fakePass, "lowercase letter"},
		{"missing_name", "", fakePass, "lowercase letter"},
		{"missing_passphrase", "cloud_flare_access_tolen", "", "Enter a passphrase"},
		{"missing_fields", "", "", "lowercase letter"},
		{"wrong_passphrase", "cloud_flare_access_tolen", "fake wrong passphrase", "Passphrase not accepted"},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			svc, clk, _ := testService(t)
			h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
			a, csrf := login(t, h)
			f := url.Values{"csrf": {csrf}, "name": {tc.name}, "passphrase": {tc.pass}, "value": {pageCanary}}
			w := request(h, "POST", "/secrets/create", f, a)
			if w.Code != 400 || len(svc.Status().Secrets) != 0 || !strings.Contains(w.Body.String(), `role="alert"`) || !strings.Contains(w.Body.String(), tc.message) {
				t.Fatalf("create validation: status=%d", w.Code)
			}
			assertRedacted(t, w)
			f.Set("name", "cloud_flare_access_tolen")
			f.Set("passphrase", fakePass)
			w = request(h, "POST", "/secrets/create", f, a)
			if w.Code != 303 || len(svc.Status().Secrets) != 1 || svc.Status().Secrets[0].Name != "cloud_flare_access_tolen" {
				t.Fatalf("corrected create: status=%d", w.Code)
			}
		})
	}
}

// Restoring every candidate rather than submitted IDs would expose the unchecked secret.
func TestUnlockRestoresOnlyCheckedGrants(t *testing.T) {
	svc, clk, dir := testService(t)
	var selected string
	for _, name := range []string{"checked", "unchecked"} {
		createPageSecret(t, svc, name)
		g, err := svc.Grant(name, 7*24*time.Hour, []byte(fakePass), "user", "")
		if err != nil {
			t.Fatal(err)
		}
		if name == "checked" {
			selected = g.ID
		}
	}
	svc.Close()
	v, err := vault.OpenWithClock(dir, clk)
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(filepath.Join(dir, "audit.jsonl"), clk)
	if err != nil {
		t.Fatal(err)
	}
	svc = core.New(v, grants.New(clk, dir, core.NewChecker(v)), log, clk, core.Config{})
	t.Cleanup(svc.Close)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	f := url.Values{"csrf": {csrf}, "passphrase": {fakePass}}
	w := request(h, "POST", "/unlock", f, a)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "checked") || !strings.Contains(w.Body.String(), "unchecked") {
		t.Fatalf("unlock candidates: %d", w.Code)
	}
	assertRedacted(t, w)
	forms := regexp.MustCompile(`(?s)<form[^>]*action="/restore"[^>]*>.*?</form>`).FindAllString(w.Body.String(), -1)
	if len(forms) != 1 || !strings.Contains(forms[0], `name="csrf"`) || regexp.MustCompile(`<input[^>]*\schecked(?:\s|=|>)`).MatchString(forms[0]) {
		t.Fatal("saved grants must require an explicit selection and CSRF token")
	}
	f.Set("grant", selected)
	if w = request(h, "POST", "/restore", f, a); w.Code != 303 {
		t.Fatalf("restore selection: %d", w.Code)
	}
	value, err := svc.Read("checked")
	crypto.Zero(value)
	if err != nil {
		t.Fatal("checked grant not restored", err)
	}
	if _, err := svc.Read("unchecked"); !errors.Is(err, core.ErrNoGrant) {
		t.Fatal("unchecked grant restored", err)
	}
}

func TestSecretFormAcceptsOneMiBDecodedNote(t *testing.T) {
	svc, clk, dir := testService(t)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	note := strings.Repeat("\n+%&", (1<<20)/4)
	f := url.Values{"csrf": {csrf}, "name": {"large_note"}, "value": {note}, "passphrase": {fakePass}}
	w := request(h, "POST", "/secrets/create", f, a)
	if w.Code != 303 {
		t.Fatalf("1MiB form: %d %s", w.Code, w.Body.String())
	}
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := v.Unlock([]byte(fakePass))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	value, _, err := sess.Reveal("large_note")
	if err != nil || string(value) != note {
		t.Fatal("note changed", err)
	}
	crypto.Zero(value)
	f.Set("name", "too_large")
	f.Set("value", note+"x")
	w = request(h, "POST", "/secrets/create", f, a)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "1 MiB") || len(svc.Status().Secrets) != 1 {
		t.Fatalf("oversized note: %d", w.Code)
	}
	f.Set("name", "large_note")
	w = request(h, "POST", "/secrets/update", f, a)
	if w.Code != 400 {
		t.Fatalf("oversized update: %d", w.Code)
	}
	value, _, _ = sess.Reveal("large_note")
	if string(value) != note {
		t.Fatal("rejected update changed value")
	}
	crypto.Zero(value)
}

func TestDescriptionsNamesFlagsAndCorruptEntries(t *testing.T) {
	svc, clk, dir := testService(t)
	createPageSecret(t, svc, "healthy")
	createPageSecret(t, svc, "damaged")
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	f := url.Values{"csrf": {csrf}, "name": {"healthy"}, "description": {"Line\nnext\u202eend\u2028tail"}, "passphrase": {fakePass}}
	if w := request(h, "POST", "/secrets/description", f, a); w.Code != 303 || svc.Status().Secrets[1].Description != "Line next end tail" {
		t.Fatalf("description cleanup: %d %+v", w.Code, svc.Status().Secrets)
	}
	f.Set("kind", "leaked")
	f.Set("reason", "Fake flag <script>unsafe</script>")
	if w := request(h, "POST", "/secrets/flag", f, a); w.Code != 303 {
		t.Fatalf("flag: %d", w.Code)
	}
	w := request(h, "GET", "/secrets", nil, a)
	if !strings.Contains(w.Body.String(), "leaked") || !strings.Contains(w.Body.String(), "&lt;script&gt;") || strings.Contains(w.Body.String(), "/grants?name=healthy") || !strings.Contains(w.Body.String(), "/secrets/clear") {
		t.Fatalf("flag state missing: %s", w.Body.String())
	}
	if w = request(h, "GET", "/audit", nil, a); w.Code != 200 || !strings.Contains(w.Body.String(), "leaked") || !strings.Contains(w.Body.String(), "user") {
		t.Fatalf("audit flag detail: %d", w.Code)
	}
	assertRedacted(t, w)
	if w = request(h, "POST", "/secrets/clear", f, a); w.Code != 303 || svc.Status().Secrets[1].Flag != nil {
		t.Fatalf("clear flag: %d", w.Code)
	}
	for _, name := range []string{"../x", "A"} {
		f.Set("name", name)
		f.Set("new_name", name)
		f.Set("duration", "10m")
		f.Set("value", pageCanary)
		for _, action := range []string{"create", "update", "rename", "delete", "description", "flag", "clear"} {
			if w = request(h, "POST", "/secrets/"+action, f, a); w.Code != 400 {
				t.Fatalf("bad name %q at %s: %d", name, action, w.Code)
			}
			assertRedacted(t, w)
		}
		if w = request(h, "POST", "/grants", f, a); w.Code != 400 {
			t.Fatalf("grant bad name: %d", w.Code)
		}
		f.Set("id", "fake-request-id")
		if w = request(h, "POST", "/requests/approve", f, a); w.Code != 400 {
			t.Fatalf("approval bad name: %d", w.Code)
		}
		if w = request(h, "GET", "/secrets/edit?name="+url.QueryEscape(name), nil, a); w.Code != 400 {
			t.Fatalf("edit bad name: %d", w.Code)
		}
	}
	f.Set("name", "healthy")
	f.Set("new_name", "../x")
	if w = request(h, "POST", "/secrets/rename", f, a); w.Code != 400 {
		t.Fatalf("bad rename destination: %d", w.Code)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets", "damaged.json"), []byte("fake corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	w = request(h, "GET", "/secrets", nil, a)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "damaged") || !strings.Contains(w.Body.String(), "Damaged file") || !strings.Contains(w.Body.String(), "healthy") || strings.Contains(w.Body.String(), "/grants?name=damaged") || strings.Contains(w.Body.String(), "/secrets/edit?name=damaged") {
		t.Fatalf("damaged list handling: %d %s", w.Code, w.Body.String())
	}
	f.Set("name", "damaged")
	if w = request(h, "POST", "/secrets/description", f, a); w.Code != 400 {
		t.Fatalf("damaged file editable: %d", w.Code)
	}
	if w = request(h, "POST", "/secrets/delete", f, a); w.Code != 303 || len(svc.Status().Secrets) != 1 {
		t.Fatalf("damaged delete: %d", w.Code)
	}
}

// Rejecting or byte-slicing descriptions breaks the core normalization contract.
func TestDescriptionFormsNormalizeToValidUTF8Prefix(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"multibyte", strings.Repeat("é", 513), strings.Repeat("é", 512)},
		{"split_rune", strings.Repeat("a", 1023) + "é", strings.Repeat("a", 1023)},
		{"ascii", strings.Repeat("x", 2048), strings.Repeat("x", 1024)},
		{"invalid_utf8", "head\xfftail", "head�tail"},
		{"controls", "Line\nnext\u202eend\u2028tail\u2029last", "Line next end tail last"},
	}
	for _, action := range []string{"create", "description"} {
		for _, tc := range cases {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				svc, clk, _ := testService(t)
				if action == "description" {
					createPageSecret(t, svc, "fake_note")
				}
				h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
				a, csrf := login(t, h)
				f := url.Values{"csrf": {csrf}, "name": {"fake_note"}, "description": {tc.raw}, "value": {pageCanary}, "passphrase": {fakePass}}
				w := request(h, "POST", "/secrets/"+action, f, a)
				if w.Code != 303 {
					t.Fatalf("description normalization status: %d", w.Code)
				}
				state := svc.Status()
				if len(state.Secrets) != 1 {
					t.Fatal("description operation did not preserve the secret")
				}
				got := state.Secrets[0].Description
				if got != tc.want || !utf8.ValidString(got) || len(got) > 1024 {
					t.Fatalf("normalized description bytes=%d want bytes=%d", len(got), len(tc.want))
				}
				assertRedacted(t, request(h, "GET", "/secrets", nil, a))
			})
		}
	}
}

func TestGrantChoicesCountdownAndRevoke(t *testing.T) {
	svc, clk, _ := testService(t)
	createPageSecret(t, svc, "fake_token")
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	w := request(h, "GET", "/grants?name=fake_token", nil, a)
	if w.Code != 200 {
		t.Fatalf("grants: %d", w.Code)
	}
	block := regexp.MustCompile(`(?s)<select[^>]*name="duration"[^>]*>(.*?)</select>`).FindStringSubmatch(w.Body.String())
	if len(block) != 2 {
		t.Fatal("no duration choices")
	}
	options := regexp.MustCompile(`<option value="([^"]+)"`).FindAllStringSubmatch(block[1], -1)
	want := []string{"10m", "1h", "24h", "7d", "30d", "90d"}
	if len(options) != len(want) {
		t.Fatalf("duration count %d", len(options))
	}
	for i := range want {
		if options[i][1] != want[i] {
			t.Fatalf("duration %d: %s", i, options[i][1])
		}
	}
	f := url.Values{"csrf": {csrf}, "name": {"fake_token"}, "duration": {"91d"}, "passphrase": {fakePass}}
	if w = request(h, "POST", "/grants", f, a); w.Code != 400 || len(svc.Status().Grants) != 0 {
		t.Fatalf("91 day grant: %d", w.Code)
	}
	f.Set("duration", "10m")
	if w = request(h, "POST", "/grants", f, a); w.Code != 303 || len(svc.Status().Grants) != 1 {
		t.Fatalf("grant: %d", w.Code)
	}
	w = request(h, "GET", "/grants", nil, a)
	assertRedacted(t, w)
	if !strings.Contains(w.Body.String(), "data-expires=") || !strings.Contains(w.Body.String(), "10m") {
		t.Fatalf("grant countdown missing: %s", w.Body.String())
	}
	f.Set("id", svc.Status().Grants[0].ID)
	if w = request(h, "POST", "/grants/revoke", f, a); w.Code != 303 || len(svc.Status().Grants) != 0 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if _, err := svc.Read("fake_token"); err == nil {
		t.Fatal("revoked grant readable")
	}
}

func TestRequestApprovalDenialAndEscaping(t *testing.T) {
	svc, clk, _ := testService(t)
	createPageSecret(t, svc, "fake_token")
	r, err := svc.Request("fake_token", "<script>alert('fake')</script>\x1b[31m", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	w := request(h, "GET", "/requests", nil, a)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "&lt;script&gt;") || strings.Contains(w.Body.String(), "<script>alert") || strings.Contains(w.Body.String(), "\x1b") {
		t.Fatalf("request escaping: %d %s", w.Code, w.Body.String())
	}
	f := url.Values{"csrf": {csrf}, "id": {r.ID}, "name": {"fake_token"}, "duration": {"10m"}, "passphrase": {fakePass}}
	if w = request(h, "POST", "/requests/approve", f, a); w.Code != 303 {
		t.Fatalf("approve: %d", w.Code)
	}
	assertRedacted(t, w)
	done, err := svc.Wait(context.Background(), r.ID)
	if err != nil || done.State != core.StateApproved || len(svc.Status().Grants) != 1 {
		t.Fatal("approval did not settle request", err)
	}
	r, err = svc.Request("fake_token", "fake deny reason", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.Set("id", r.ID)
	if w = request(h, "POST", "/requests/deny", f, a); w.Code != 303 {
		t.Fatalf("deny: %d", w.Code)
	}
	done, err = svc.Wait(context.Background(), r.ID)
	if err != nil || done.State != core.StateDenied {
		t.Fatal("denial did not settle request", err)
	}
}

func TestNotifierSettingsAreWriteOnly(t *testing.T) {
	svc, clk, _ := testService(t)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	f := url.Values{"csrf": {csrf}, "token": {"fake-bot-token"}, "chat_id": {"9000000004"}, "passphrase": {"fake wrong pass"}}
	w := request(h, "POST", "/notifier", f, a)
	if w.Code != 400 {
		t.Fatalf("wrong notifier pass: %d", w.Code)
	}
	assertRedacted(t, w)
	f.Set("passphrase", fakePass)
	w = request(h, "POST", "/notifier", f, a)
	if w.Code != 303 {
		t.Fatalf("notifier set: %d", w.Code)
	}
	assertRedacted(t, w)
	w = request(h, "GET", "/notifier", nil, a)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/unlock") {
		t.Fatalf("notifier page: %d", w.Code)
	}
	assertRedacted(t, w)
	res, err := svc.Unlock([]byte(fakePass))
	if err != nil || string(res.NotifierToken) != "fake-bot-token" || res.ChatID != "9000000004" {
		t.Fatal("settings not stored", err)
	}
	crypto.Zero(res.NotifierToken)
}

func TestManagementFormsShareAuthenticationBoundary(t *testing.T) {
	svc, clk, _ := testService(t)
	createPageSecret(t, svc, "fake_token")
	if _, err := svc.Request("fake_token", "fake reason", time.Hour); err != nil {
		t.Fatal(err)
	}
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, _ := login(t, h)
	for _, path := range []string{"/secrets", "/secrets/edit?name=fake_token", "/grants", "/requests", "/notifier", "/audit", "/unlock"} {
		w := request(h, "GET", path, nil, a)
		if w.Code != 200 {
			t.Fatalf("page %s: %d", path, w.Code)
		}
		forms := regexp.MustCompile(`(?s)<form[^>]*method="post"[^>]*>.*?</form>`).FindAllString(w.Body.String(), -1)
		if len(forms) == 0 {
			t.Fatalf("no state form at %s", path)
		}
		for _, form := range forms {
			if !strings.Contains(form, `name="csrf"`) {
				t.Fatalf("CSRF field missing at %s", path)
			}
		}
		if w = request(h, "GET", path, nil); w.Code != 303 {
			t.Fatalf("anonymous page %s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/secrets/create", "/secrets/update", "/secrets/rename", "/secrets/delete", "/secrets/description", "/secrets/flag", "/secrets/clear", "/grants", "/grants/revoke", "/requests/approve", "/requests/deny", "/notifier"} {
		if w := request(h, "POST", path, url.Values{"name": {"fake_token"}, "value": {pageCanary}, "passphrase": {fakePass}}, a); w.Code != 403 {
			t.Fatalf("CSRF bypass %s: %d", path, w.Code)
		}
	}
	if _, err := svc.Read("fake_token"); !errors.Is(err, core.ErrLocked) {
		t.Fatal("CSRF-denied action granted value", err)
	}
}

// Missing duration guidance would let users select long access without its warning.
func TestGrantAndApprovalFormsWarnAboutLongAccess(t *testing.T) {
	svc, clk, _ := testService(t)
	createPageSecret(t, svc, "fake_token")
	if _, err := svc.Request("fake_token", "Fake long access request", 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, _ := login(t, h)
	for _, path := range []string{"/grants", "/requests"} {
		w := request(h, "GET", path, nil, a)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "longer than 24 hours") || !strings.Contains(w.Body.String(), "whole period") {
			t.Fatalf("long access warning missing at %s", path)
		}
	}
}

// A required value control prevents an allowed empty secret from being submitted.
func TestValueFormsPermitEmptySecrets(t *testing.T) {
	svc, clk, dir := testService(t)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	f := url.Values{"csrf": {csrf}, "name": {"empty_note"}, "value": {""}, "passphrase": {fakePass}}
	if w := request(h, "POST", "/secrets/create", f, a); w.Code != 303 {
		t.Fatalf("empty create: %d", w.Code)
	}
	for _, path := range []string{"/secrets", "/secrets/edit?name=empty_note"} {
		w := request(h, "GET", path, nil, a)
		control := regexp.MustCompile(`<textarea[^>]*name="value"[^>]*>`).FindString(w.Body.String())
		if w.Code != 200 || control == "" || strings.Contains(control, "required") {
			t.Fatalf("empty value cannot be submitted at %s", path)
		}
	}
	if w := request(h, "POST", "/secrets/update", f, a); w.Code != 303 {
		t.Fatalf("empty update: %d", w.Code)
	}
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := v.Unlock([]byte(fakePass))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	value, _, err := sess.Reveal("empty_note")
	defer crypto.Zero(value)
	if err != nil || len(value) != 0 {
		t.Fatal("empty value did not round-trip", err)
	}
}

func TestNotifierPageNotesEnvironmentOverride(t *testing.T) {
	const note = "Environment credentials override saved settings"
	for _, env := range []bool{false, true} {
		svc, clk, _ := testService(t)
		h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk, EnvNotifier: env})
		a, _ := login(t, h)
		w := request(h, "GET", "/notifier", nil, a)
		if w.Code != 200 || strings.Contains(w.Body.String(), note) != env {
			t.Fatalf("env %v: status %d, note present %v", env, w.Code, strings.Contains(w.Body.String(), note))
		}
	}
}

func TestNotifierRejectsInvalidChatID(t *testing.T) {
	svc, clk, _ := testService(t)
	h := Handler(svc, Config{AllowedHosts: []string{"crypt.local"}, Clock: clk})
	a, csrf := login(t, h)
	for _, chat := range []string{"abc", "12 34", "@channel", "1-2"} {
		f := url.Values{"csrf": {csrf}, "token": {"fake-bot-token"}, "chat_id": {chat}, "passphrase": {fakePass}}
		if w := request(h, "POST", "/notifier", f, a); w.Code != 400 {
			t.Fatalf("chat %q: status %d", chat, w.Code)
		}
	}
	if n := svc.Notifier(); len(n.NotifierToken) != 0 {
		t.Fatal("invalid chat ID stored")
	}
}
