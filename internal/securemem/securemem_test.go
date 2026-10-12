package securemem

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCopyLockAndZeroBeforeRelease(t *testing.T) {
	before := Snapshot()
	input := []byte("fake-memory-value")
	b := Copy(input)
	if !bytes.Equal(b.Bytes, input) {
		t.Fatal("copy changed value")
	}
	input[0] = 'X'
	if b.Bytes[0] != 'f' {
		t.Fatal("buffer shares caller memory")
	}
	during := Snapshot()
	if during.Attempts != before.Attempts+1 {
		t.Fatal("no mlock attempt")
	}
	if b.LockError == nil && during.LockedBytes <= before.LockedBytes {
		t.Fatal("successful mlock not reported")
	}
	if b.LockError != nil && during.LockFailures != before.LockFailures+1 {
		t.Fatal("failed mlock not reported")
	}
	saved := b.Bytes
	b.Close()
	b.Close()
	if !bytes.Equal(saved, make([]byte, len(saved))) || b.Bytes != nil {
		t.Fatal("value not zeroed on close")
	}
	after := Snapshot()
	if after.LockedBytes != before.LockedBytes {
		t.Fatal("locked memory not released")
	}
	t.Logf("Mlock error=%v Munlock error=%v", b.LockError, b.UnlockError)
}

func TestMemlockFailureKeepsValueUsable(t *testing.T) {
	if os.Getenv("TOKENCRYPT_MEMLOCK_HELPER") == "1" {
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			t.Fatal(err)
		}
		limit.Cur = 0
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			t.Fatal(err)
		}
		b := Copy([]byte("fake-low-limit-value"))
		defer b.Close()
		if string(b.Bytes) != "fake-low-limit-value" || b.LockError == nil {
			t.Fatalf("best effort: error=%v", b.LockError)
		}
		st := Snapshot()
		if st.LockFailures != 1 || st.LockedBytes != 0 {
			t.Fatalf("failure counters: %+v", st)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMemlockFailureKeepsValueUsable$")
	cmd.Env = append(os.Environ(), "TOKENCRYPT_MEMLOCK_HELPER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("limit subprocess: %v %s", err, out)
	}
}
