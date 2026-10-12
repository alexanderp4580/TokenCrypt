package grants

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFailedCandidatesClearsVerifiedSet(t *testing.T) {
	e := newEnv(t, "tok")
	m := e.open()
	e.add(m, "long", "tok", 2*time.Hour, "fake")
	m.Close()
	m = e.manager()
	if _, err := m.Candidates(e.mac); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.path(), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Candidates(e.mac); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("candidates: %v", err)
	}
	err := m.Restore([]string{"long"}, func(string) ([]byte, error) { return []byte("fake"), nil })
	if !errors.Is(err, ErrNotCandidate) || len(m.List()) != 0 {
		t.Fatalf("restored stale candidate: %v", err)
	}
}

func TestDuplicateCandidateIDsReturnedOnce(t *testing.T) {
	e := newEnv(t, "tok")
	m := e.open()
	e.add(m, "long", "tok", 2*time.Hour, "fake")
	m.Close()
	raw, err := os.ReadFile(e.path())
	if err != nil {
		t.Fatal(err)
	}
	var doc recordsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Grants = append(doc.Grants, doc.Grants[0])
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.path(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := e.manager().Candidates(e.mac)
	if err != nil || len(out) != 1 {
		t.Fatalf("candidates: %d, %v", len(out), err)
	}
}

func TestOversizedRecordsRejectedBeforeDecode(t *testing.T) {
	e := newEnv(t, "tok")
	f, err := os.Create(e.path())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(16 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	_, err = e.manager().Candidates(e.mac)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized records: %v", err)
	}
}

func TestOversizedRecordWriteLeavesFileAndGrantUnchanged(t *testing.T) {
	e := newEnv(t, "tok")
	m := e.open()
	e.add(m, "keep", "tok", 2*time.Hour, "keep-value")
	before, err := os.ReadFile(e.path())
	if err != nil {
		t.Fatal(err)
	}
	g := e.grant("large", "tok", 2*time.Hour)
	g.GrantedBy = strings.Repeat("x", 8<<20)
	if err := m.Add(g, []byte("fake"), e.mac); err == nil {
		t.Fatal("oversized grant accepted")
	}
	after, err := os.ReadFile(e.path())
	if err != nil || string(after) != string(before) {
		t.Fatal("records changed")
	}
	if len(m.List()) != 1 {
		t.Fatal("failed grant became live")
	}
}
