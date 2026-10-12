// The end-to-end harness uses only fake credentials and temporary storage.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const fakePass = "fake-e2e-passphrase-only"
const canary = "FAKE_TOKENCRYPT_CANARY_87342"
const updated = "FAKE_TOKENCRYPT_REPLACEMENT_87342"
const botToken = "fake-e2e-bot-token"

type harness struct {
	binary, dir, base, host, telegram string
	client                            *http.Client
	process                           *exec.Cmd
	done                              chan error
	log                               bytes.Buffer
}

func fail(label string) { panic(label) }
func check(ok bool, label string) {
	if !ok {
		fail(label)
	}
	fmt.Println("PASS", label)
}
func (h *harness) cli(args ...string) (string, bool) {
	c := exec.Command(h.binary, args...)
	c.Env = append(os.Environ(), "TOKENCRYPT_SOCKET="+filepath.Join(h.dir, "sock"))
	var output bytes.Buffer
	c.Stdout = &output
	c.Stderr = io.Discard
	err := c.Run()
	return output.String(), err == nil
}
func (h *harness) page(path string) string {
	res, err := h.client.Get(h.base + path)
	if err != nil {
		fail("HTTP GET " + path)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		fail("HTTP GET status " + path)
	}
	if strings.Contains(string(b), canary) || strings.Contains(string(b), updated) || strings.Contains(string(b), botToken) {
		fail("web page exposes stored credential")
	}
	return string(b)
}

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
var idPattern = regexp.MustCompile(`name="id" value="([^"]+)"`)
var grantPattern = regexp.MustCompile(`name="grant" value="([^"]+)"`)

func field(pattern *regexp.Regexp, body string) string {
	m := pattern.FindStringSubmatch(body)
	if len(m) != 2 {
		fail("required form field")
	}
	return m[1]
}
func (h *harness) post(path, token string, fields url.Values, status int) string {
	fields.Set("csrf", token)
	res, err := h.client.PostForm(h.base+path, fields)
	if err != nil {
		fail("HTTP POST " + path)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != status {
		fail(fmt.Sprintf("HTTP POST %s expected %d got %d", path, status, res.StatusCode))
	}
	return string(b)
}
func values(fields ...string) url.Values {
	v := url.Values{}
	for i := 0; i < len(fields); i += 2 {
		v.Add(fields[i], fields[i+1])
	}
	return v
}
func (h *harness) start() {
	h.log.Reset()
	h.process = exec.Command(h.binary, "serve", "--vault-dir", filepath.Join(h.dir, "vault"), "--state-dir", filepath.Join(h.dir, "state"), "--socket", filepath.Join(h.dir, "sock"), "--listen", h.host, "--allowed-hosts", h.host, "--approval-url", h.base, "--telegram-api-base", h.telegram)
	h.process.Stdout = &h.log
	h.process.Stderr = &h.log
	if err := h.process.Start(); err != nil {
		fail("start daemon")
	}
	h.done = make(chan error, 1)
	go func() { h.done <- h.process.Wait() }()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-h.done:
			h.process = nil
			fail("daemon exited before listening")
		default:
		}
		res, err := h.client.Get(h.base + "/")
		if err == nil {
			res.Body.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	fail("daemon readiness timeout")
}
func (h *harness) stop(kill bool) {
	if h.process == nil {
		return
	}
	if kill {
		_ = h.process.Process.Kill()
	} else {
		_ = h.process.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-h.done:
	case <-time.After(15 * time.Second):
		_ = h.process.Process.Kill()
		<-h.done
		fail("daemon shutdown timeout")
	}
	h.process = nil
}
func (h *harness) login() string {
	body := h.page("/login")
	h.post("/login", field(csrfPattern, body), values("passphrase", fakePass), 303)
	return field(csrfPattern, h.page("/secrets"))
}
func (h *harness) grant(token, duration string) {
	h.post("/grants", token, values("name", "alpha", "duration", duration, "passphrase", fakePass), 303)
}
func (h *harness) revoke(token string) {
	body := h.page("/grants")
	h.post("/grants/revoke", token, values("id", field(idPattern, body)), 303)
}
func (h *harness) unreadable(name, label string) {
	out, ok := h.cli("get", name)
	check(!ok && out == "", label)
}
func run(binary string) {
	dir, err := os.MkdirTemp("", "tokencrypt-e2e-")
	if err != nil {
		fail("temporary directory")
	}
	defer os.RemoveAll(dir)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("free web port")
	}
	host := listener.Addr().String()
	listener.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var noticesMu sync.Mutex
	var notices []struct{ Path, Chat, Text string }
	telegram := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ChatID string `json:"chat_id"`
			Text   string `json:"text"`
		}
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		noticesMu.Lock()
		notices = append(notices, struct{ Path, Chat, Text string }{r.URL.Path, body.ChatID, body.Text})
		noticesMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer telegram.Close()
	h := &harness{binary: binary, dir: dir, base: "http://" + host, host: host, telegram: telegram.URL, client: client}
	defer h.stop(false)
	h.start()
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 5*time.Second)
	second := exec.CommandContext(secondCtx, binary, "serve", "--vault-dir", filepath.Join(dir, "vault"), "--state-dir", filepath.Join(dir, "state"), "--socket", filepath.Join(dir, "second-sock"), "--listen", host)
	second.Stdout, second.Stderr = io.Discard, io.Discard
	err = second.Run()
	check(err != nil && secondCtx.Err() == nil, "setup holds exclusive daemon lock")
	cancelSecond()
	body := h.page("/")
	check(strings.Contains(body, "confirmation"), "first run displays setup")
	token := field(csrfPattern, body)
	h.post("/setup", token, values("passphrase", fakePass, "confirmation", "mismatch"), 400)
	_, err = os.Stat(filepath.Join(dir, "vault", "header.json"))
	check(os.IsNotExist(err), "mismatched setup creates no vault")
	h.post("/setup", token, values("passphrase", fakePass, "confirmation", fakePass), 303)
	// Bootstrap may hand off to the normal daemon after completing the response.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		res, err := client.Get(h.base + "/login")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	token = h.login()
	check(true, "setup transitions to authenticated shared service")
	h.post("/unlock", token, values("passphrase", fakePass), 200)
	h.post("/secrets/create", token, values("name", "alpha", "description", "fake test secret", "value", canary, "passphrase", fakePass), 303)
	h.post("/secrets/create", token, values("name", "beta", "value", "FAKE_SECOND_SECRET", "passphrase", fakePass), 303)
	h.unreadable("alpha", "get fails without grant")
	_, ok := h.cli("run", "--with", "alpha", "--", "sh", "-c", "exit 0")
	check(!ok, "run fails without grant")
	h.post("/grants", token, values("name", "alpha", "duration", "10m", "passphrase", "fake-wrong-passphrase"), 400)
	h.unreadable("alpha", "wrong passphrase grants nothing")
	check(strings.Contains(h.page("/audit"), "login.failed"), "wrong passphrase appears in audit")
	h.grant(token, "10m")
	out, ok := h.cli("get", "alpha")
	check(ok && out == canary, "get returns granted value")
	out, ok = h.cli("run", "--with", "alpha", "--", "sh", "-c", `printf %s "$ALPHA"`)
	check(ok && out == canary, "run injects granted value")
	h.unreadable("beta", "grant leaves other secrets locked")
	h.revoke(token)
	h.unreadable("alpha", "revoke blocks get")
	h.grant(token, "10m")
	_, ok = h.cli("request", "alpha", "--for", "10m", "--reason", "flag pending request")
	check(ok, "request starts before flag")
	_, ok = h.cli("flag", "alpha", "--kind", "invalid", "--reason", "fake rejected token")
	check(ok, "agent sets invalid flag")
	h.unreadable("alpha", "invalid flag revokes access")
	_, ok = h.cli("run", "--with", "alpha", "--", "sh", "-c", "exit 0")
	check(!ok, "invalid flag blocks run")
	_, ok = h.cli("request", "alpha", "--reason", "must fail")
	check(!ok, "invalid flag blocks request")
	h.post("/grants", token, values("name", "alpha", "duration", "10m", "passphrase", fakePass), 400)
	check(strings.Contains(h.page("/requests"), "No pending requests"), "invalid flag denies pending requests")
	_, ok = h.cli("clear", "alpha")
	check(!ok, "agent cannot clear flag")
	h.post("/secrets/update", token, values("name", "alpha", "value", updated, "passphrase", fakePass), 303)
	h.grant(token, "10m")
	out, ok = h.cli("get", "alpha")
	check(ok && out == updated, "new value clears flag and is granted")
	h.revoke(token)
	h.post("/notifier", token, values("token", botToken, "chat_id", "12345", "passphrase", fakePass), 303)
	_, ok = h.cli("request", "alpha", "--for", "10m", "--reason", "fake <approval> reason")
	check(ok, "CLI requests access")
	body = h.page("/requests")
	check(strings.Contains(body, "fake &lt;approval&gt; reason"), "request appears escaped in web UI")
	deadline = time.Now().Add(5 * time.Second)
	received := false
	for time.Now().Before(deadline) {
		noticesMu.Lock()
		for _, n := range notices {
			if strings.Contains(n.Text, "fake <approval> reason") && n.Path == "/bot"+botToken+"/sendMessage" && n.Chat == "12345" && !strings.Contains(n.Text, updated) {
				received = true
			}
		}
		noticesMu.Unlock()
		if received {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	check(received, "fake Telegram receives metadata and approval link")
	h.post("/requests/approve", token, values("id", field(idPattern, body), "name", "alpha", "duration", "10m", "passphrase", fakePass), 303)
	out, ok = h.cli("get", "alpha")
	check(ok && out == updated, "web request approval grants CLI access")
	h.revoke(token)
	_, ok = h.cli("request", "alpha", "--reason", "deny this fake request")
	check(ok, "CLI creates request for denial")
	body = h.page("/requests")
	h.post("/requests/deny", token, values("id", field(idPattern, body)), 303)
	h.unreadable("alpha", "web denial leaves get blocked")
	h.grant(token, "24h")
	h.stop(true)
	jar, _ = cookiejar.New(nil)
	h.client.Jar = jar
	h.start()
	h.unreadable("alpha", "restart keeps long grant locked")
	_, ok = h.cli("request", "alpha", "--for", "10m", "--reason", "fake cold restart notice")
	check(ok, "locked restart accepts CLI request")
	deadline = time.Now().Add(5 * time.Second)
	received = false
	for time.Now().Before(deadline) {
		noticesMu.Lock()
		for _, n := range notices {
			if strings.Contains(n.Text, "fake cold restart notice") && n.Path == "/bot"+botToken+"/sendMessage" && n.Chat == "12345" {
				received = true
			}
		}
		noticesMu.Unlock()
		if received {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	check(received, "locked restart delivers fake Telegram without login or unlock")
	h.unreadable("alpha", "cold startup notification preserves locked long grant")
	token = h.login()
	body = h.post("/unlock", token, values("passphrase", fakePass), 200)
	id := field(grantPattern, body)
	h.unreadable("alpha", "unlock alone does not restore unconfirmed grant")
	h.post("/restore", token, values("grant", id, "passphrase", fakePass), 303)
	out, ok = h.cli("get", "alpha")
	check(ok && out == updated, "confirmed long grant survives daemon restart")
	h.page("/secrets")
	h.page("/grants")
	h.page("/notifier")
	h.page("/audit")
	check(true, "web pages omit stored values and notifier token")
	_, ok = h.cli("status")
	check(ok, "CLI status uses shared service")
	_ = filepath.WalkDir(filepath.Join(dir, "vault"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			fail("vault file scan")
		}
		if d.IsDir() {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			fail("vault read")
		}
		if bytes.Contains(b, []byte(canary)) || bytes.Contains(b, []byte(updated)) {
			fail("plaintext secret in vault")
		}
		if path == filepath.Join(dir, "vault", "service", "notifier.json") {
			var config struct {
				Token []byte `json:"token"`
				Chat  string `json:"chat_id"`
			}
			check(json.Unmarshal(b, &config) == nil && string(config.Token) == botToken && config.Chat == "12345", "service notifier has independent recoverable credentials")
			info, e := os.Stat(path)
			check(e == nil && info.Mode().Perm() == 0600, "service notifier file permissions are 0600")
			info, e = os.Stat(filepath.Dir(path))
			check(e == nil && info.Mode().Perm() == 0700, "service notifier directory permissions are 0700")
		} else if bytes.Contains(b, []byte(botToken)) {
			fail("notifier credential outside service storage")
		}
		return nil
	})
	check(true, "vault files contain no plaintext protected values")
	info, err := os.Stat(filepath.Join(dir, "sock"))
	check(err == nil && info.Mode().Perm() == 0600, "socket permissions are 0600")
	h.stop(false)
	_, err = os.Stat(filepath.Join(dir, "sock"))
	check(os.IsNotExist(err), "graceful shutdown removes socket")
	init := exec.Command(binary, "init", "--vault-dir", filepath.Join(dir, "init-vault"))
	init.Stdin = strings.NewReader(fakePass + "\n" + fakePass + "\n")
	init.Stdout, init.Stderr = io.Discard, io.Discard
	check(init.Run() == nil, "init accepts matching fake passphrase from stdin")
}
func main() {
	defer func() {
		if p := recover(); p != nil {
			fmt.Fprintln(os.Stderr, "FAIL", p)
			os.Exit(1)
		}
	}()
	if len(os.Args) != 2 {
		fail("usage: e2e BINARY")
	}
	run(os.Args[1])
}
