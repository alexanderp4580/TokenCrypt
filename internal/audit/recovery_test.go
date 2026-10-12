package audit

import (
	"encoding/json"
	"os"
	"testing"
)

func TestTailReadsOnlyBoundedNewestWindow(t *testing.T) {
	l, _, path := openLog(t)
	old, _ := json.Marshal(Event{Type: "old"})
	latest, _ := json.Marshal(Event{Type: "newest"})
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(append(old, '\n'), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(16 << 20); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(append(append([]byte{'\n'}, latest...), '\n'), (16<<20)-int64(len(latest))-2); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got, err := l.Tail(10)
	if err != nil || len(got) != 1 || got[0].Type != "newest" {
		t.Fatalf("tail: %+v, %v", got, err)
	}
}

func TestTailDropsPartialStartingLine(t *testing.T) {
	l, _, path := openLog(t)
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	// The bounded window begins at byte 1 inside this invalid first line.
	if _, err := f.WriteAt([]byte("x{\"type\":\"partial\"}\n"), 0); err != nil {
		t.Fatal(err)
	}
	latest := []byte("\n{\"type\":\"newest\"}\n")
	size := int64((2 << 20) + 1)
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(latest, size-int64(len(latest))); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got, err := l.Tail(10)
	if err != nil || len(got) != 1 || got[0].Type != "newest" {
		t.Fatalf("tail: %+v, %v", got, err)
	}
}

func TestOversizedAuditEventLeavesLogUnchanged(t *testing.T) {
	l, _, _ := openLog(t)
	if err := l.Write(Event{Type: "oversized", Detail: string(make([]byte, 2<<20))}); err == nil {
		t.Fatal("oversized event accepted")
	}
	got, err := l.Tail(10)
	if err != nil || len(got) != 0 {
		t.Fatalf("log changed: %+v, %v", got, err)
	}
}
