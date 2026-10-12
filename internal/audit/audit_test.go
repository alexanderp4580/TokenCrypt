package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tokencrypt/internal/clock"
)

var t0 = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func openLog(t *testing.T) (*Log, *clock.Fake, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "audit.log")
	clk := clock.NewFake(t0)
	l, err := Open(path, clk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, clk, path
}

func mustWrite(t *testing.T, l *Log, e Event) {
	t.Helper()
	if err := l.Write(e); err != nil {
		t.Fatalf("Write: %v", err)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		return nil
	}
	if data[len(data)-1] != '\n' {
		t.Fatalf("file does not end with a newline: %q", data)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func TestWriteThenTailReturnsEventsInOrder(t *testing.T) {
	l, clk, _ := openLog(t)
	mustWrite(t, l, Event{Type: SecretCreated, Actor: "user", Secret: "github_token"})
	clk.AdvanceWall(time.Minute)
	mustWrite(t, l, Event{Type: RequestCreated, Actor: "agent", Secret: "github_token", Detail: "deploy"})
	clk.AdvanceWall(time.Minute)
	mustWrite(t, l, Event{Type: RequestApproved, Actor: "user", Secret: "github_token"})

	got, err := l.Tail(10)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	wantTypes := []string{SecretCreated, RequestCreated, RequestApproved}
	if len(got) != len(wantTypes) {
		t.Fatalf("got %d events, want %d", len(got), len(wantTypes))
	}
	for i, e := range got {
		if e.Type != wantTypes[i] {
			t.Errorf("event %d type = %q, want %q", i, e.Type, wantTypes[i])
		}
		if e.Secret != "github_token" {
			t.Errorf("event %d secret = %q", i, e.Secret)
		}
	}
	if got[1].Actor != "agent" || got[1].Detail != "deploy" {
		t.Errorf("event 1 = %+v", got[1])
	}
}

func TestWriteSetsZeroTimeFromClock(t *testing.T) {
	l, clk, _ := openLog(t)
	mustWrite(t, l, Event{Type: LoginFailed, Actor: "web"})
	explicit := t0.Add(-time.Hour)
	mustWrite(t, l, Event{Time: explicit, Type: LoginFailed, Actor: "web"})
	clk.AdvanceWall(time.Hour)
	mustWrite(t, l, Event{Type: DaemonUnlocked, Actor: "user"})

	got, err := l.Tail(10)
	if err != nil {
		t.Fatal(err)
	}
	wants := []time.Time{t0, explicit, t0.Add(time.Hour)}
	for i, w := range wants {
		if !got[i].Time.Equal(w) {
			t.Errorf("event %d time = %v, want %v", i, got[i].Time, w)
		}
	}
}

func TestEachLineIsValidJSON(t *testing.T) {
	l, _, path := openLog(t)
	mustWrite(t, l, Event{Type: SecretCreated, Actor: "user", Secret: "a"})
	mustWrite(t, l, Event{Type: FlagSet, Actor: "agent", Secret: "a", Detail: "leaked: rejected by service"})

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %d is not JSON: %v: %q", i, err, line)
		}
		for _, k := range []string{"time", "type", "actor"} {
			if _, ok := m[k]; !ok {
				t.Errorf("line %d lacks %q: %q", i, k, line)
			}
		}
	}
}

func TestTailReturnsLastN(t *testing.T) {
	l, _, _ := openLog(t)
	for i := 0; i < 5; i++ {
		mustWrite(t, l, Event{Type: SecretUpdated, Actor: "user", Secret: fmt.Sprintf("s%d", i)})
	}

	got, err := l.Tail(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Secret != "s3" || got[1].Secret != "s4" {
		t.Errorf("Tail(2) = %+v", got)
	}

	all, err := l.Tail(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 || all[0].Secret != "s0" {
		t.Errorf("Tail(100) = %+v", all)
	}

	none, err := l.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Errorf("Tail(0) = %+v", none)
	}
}

func TestTailOfEmptyLog(t *testing.T) {
	l, _, _ := openLog(t)
	got, err := l.Tail(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("Tail = %+v", got)
	}
}

func TestFileAndDirectoryModes(t *testing.T) {
	_, _, path := openLog(t)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if m := fi.Mode().Perm(); m != 0o600 {
		t.Errorf("file mode = %o, want 600", m)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if m := di.Mode().Perm(); m != 0o700 {
		t.Errorf("dir mode = %o, want 700", m)
	}
}

func TestConcurrentWritesProduceIntactLines(t *testing.T) {
	l, _, path := openLog(t)
	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := Event{Type: SecretUpdated, Actor: "user", Secret: fmt.Sprintf("s%02d", i), Detail: strings.Repeat("x", 2000)}
			if err := l.Write(e); err != nil {
				t.Errorf("Write %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	lines := readLines(t, path)
	if len(lines) != n {
		t.Fatalf("got %d lines, want %d", len(lines), n)
	}
	seen := map[string]bool{}
	for _, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("damaged line: %v", err)
		}
		seen[e.Secret] = true
	}
	if len(seen) != n {
		t.Errorf("got %d distinct events, want %d", len(seen), n)
	}
}

func TestReopenAppends(t *testing.T) {
	l, clk, path := openLog(t)
	mustWrite(t, l, Event{Type: SecretCreated, Actor: "user", Secret: "first"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	l2, err := Open(path, clk)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	mustWrite(t, l2, Event{Type: SecretCreated, Actor: "user", Secret: "second"})

	got, err := l2.Tail(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Secret != "first" || got[1].Secret != "second" {
		t.Errorf("events = %+v", got)
	}
}

func TestDetailWithNewlinesStaysOnOneLine(t *testing.T) {
	l, _, path := openLog(t)
	detail := "line one\nline two\r\n{\"type\":\"grant.started\"}\n"
	mustWrite(t, l, Event{Type: FlagSet, Actor: "agent", Secret: "a", Detail: detail})

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %q", len(lines), lines)
	}
	got, err := l.Tail(1)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Detail != detail {
		t.Errorf("Detail = %q, want %q", got[0].Detail, detail)
	}
}

func TestTailSkipsUndecodableLines(t *testing.T) {
	l, _, path := openLog(t)
	mustWrite(t, l, Event{Type: SecretCreated, Actor: "user", Secret: "a"})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	w.WriteString("not json\n")
	w.Flush()
	f.Close()
	mustWrite(t, l, Event{Type: SecretDeleted, Actor: "user", Secret: "a"})

	got, err := l.Tail(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Type != SecretCreated || got[1].Type != SecretDeleted {
		t.Errorf("events = %+v", got)
	}
}

func TestOpenKeepsNextEventOffTornLastLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	whole := `{"time":"2026-10-09T12:00:00Z","type":"secret.created","actor":"user","secret":"first"}`
	torn := `{"time":"2026-10-09T12:01:00Z","type":"secret.cre`
	if err := os.WriteFile(path, []byte(whole+"\n"+torn), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path, clock.NewFake(t0))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	mustWrite(t, l, Event{Type: SecretDeleted, Actor: "user", Secret: "second"})

	got, err := l.Tail(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Secret != "first" || got[1].Secret != "second" {
		t.Errorf("events = %+v, want first and second", got)
	}
	if lines := readLines(t, path); len(lines) != 3 {
		t.Errorf("got %d lines, want 3: %q", len(lines), lines)
	}
}

func TestOpenKeepsCompleteLastLineWithoutNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	whole := `{"time":"2026-10-09T12:00:00Z","type":"secret.created","actor":"user","secret":"first"}`
	if err := os.WriteFile(path, []byte(whole), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path, clock.NewFake(t0))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	mustWrite(t, l, Event{Type: SecretDeleted, Actor: "user", Secret: "second"})

	got, err := l.Tail(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Secret != "first" || got[1].Secret != "second" {
		t.Errorf("events = %+v, want first and second", got)
	}
}

func TestOpenTightensModesOfExistingLogAndDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path, clock.NewFake(t0))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for p, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", filepath.Base(p), got, want)
		}
	}
}
