// Package securemem owns page-isolated secret buffers with best-effort mlock.
// Callers must Close buffers after use. Lock failure never changes the value.
package securemem

import (
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Stats records kernel outcomes, without any values or keys.
type Stats struct {
	Attempts, LockFailures, UnlockFailures uint64
	LockedBytes                            uint64
	LastLockError, LastUnlockError         string
}

var counters struct {
	sync.Mutex
	stats Stats
}

// Snapshot returns the current memory-lock counters.
func Snapshot() Stats {
	counters.Lock()
	defer counters.Unlock()
	return counters.stats
}

// Buffer owns Bytes and its dedicated backing pages. Its owner serializes use
// against Close. LockError and UnlockError describe the actual kernel calls.
type Buffer struct {
	Bytes                  []byte
	LockError, UnlockError error
	pages                  []byte
	locked                 bool
}

// Copy copies value into page-aligned storage so releasing this lock cannot
// unlock another secret buffer that shares an ordinary Go heap page.
func Copy(value []byte) *Buffer {
	b := &Buffer{Bytes: []byte{}}
	if len(value) == 0 {
		return b
	}
	page := os.Getpagesize()
	size := ((len(value) + page - 1) / page) * page
	storage := make([]byte, size+page)
	address := uintptr(unsafe.Pointer(&storage[0]))
	offset := int((uintptr(page) - address%uintptr(page)) % uintptr(page))
	b.pages = storage[offset : offset+size : offset+size]
	b.Bytes = b.pages[:len(value):len(value)]
	copy(b.Bytes, value)
	b.LockError = unix.Mlock(b.pages)
	runtime.KeepAlive(storage)
	b.locked = b.LockError == nil
	counters.Lock()
	counters.stats.Attempts++
	if b.locked {
		counters.stats.LockedBytes += uint64(size)
	} else {
		counters.stats.LockFailures++
		counters.stats.LastLockError = b.LockError.Error()
	}
	counters.Unlock()
	return b
}

// Close zeroes the secret before unlocking its pages. It is idempotent; saved
// views of Bytes observe zeroes. Go may keep other copies; zeroing is best effort.
func (b *Buffer) Close() {
	if b == nil || b.Bytes == nil {
		return
	}
	clear(b.pages)
	if b.locked {
		b.UnlockError = unix.Munlock(b.pages)
		runtime.KeepAlive(b.pages)
		counters.Lock()
		if b.UnlockError == nil {
			counters.stats.LockedBytes -= uint64(len(b.pages))
		} else {
			counters.stats.UnlockFailures++
			counters.stats.LastUnlockError = b.UnlockError.Error()
		}
		counters.Unlock()
	}
	b.Bytes, b.pages = nil, nil
	b.locked = false
}
