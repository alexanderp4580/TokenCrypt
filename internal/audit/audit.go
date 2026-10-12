// Package audit appends security events to a JSON-lines log. Records carry
// names, actors and free-form detail text; callers never pass values or
// passphrases.
package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tokencrypt/internal/clock"
)

// Event types.
const (
	SecretCreated   = "secret.created"
	SecretUpdated   = "secret.updated"
	SecretRenamed   = "secret.renamed"
	SecretDeleted   = "secret.deleted"
	FlagSet         = "flag.set"
	FlagCleared     = "flag.cleared"
	RequestCreated  = "request.created"
	RequestApproved = "request.approved"
	RequestDenied   = "request.denied"
	RequestExpired  = "request.expired"
	GrantStarted    = "grant.started"
	GrantEnded      = "grant.ended"
	GrantRevoked    = "grant.revoked"
	GrantRestored   = "grant.restored"
	LoginFailed     = "login.failed"
	NotifierSet     = "notifier.set"
	DaemonUnlocked  = "daemon.unlocked"
)

// Event is one audit record. Secret and Detail are omitted from the JSON when
// empty.
type Event struct {
	Time   time.Time `json:"time"`
	Type   string    `json:"type"`
	Actor  string    `json:"actor"`
	Secret string    `json:"secret,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

var ErrTooLarge = errors.New("audit: event exceeds 2 MiB size limit")

// Log is an append-only audit file. It is safe for concurrent use.
type Log struct {
	clk  clock.Clock
	path string

	mu sync.Mutex
	f  *os.File
	// needNL is set when the file may end inside a line, so the next event
	// starts on a line of its own instead of joining the damaged one.
	needNL bool
}

// Open creates the log's directory and file if missing, sets their modes to
// 0700 and 0600, and opens the file for appending; existing records are kept.
// If the last line has no newline (a torn write), the next event starts on a
// new line.
func Open(path string, clk clock.Clock) (*Log, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Log{clk: clk, path: path, f: f}
	if err := l.prepare(); err != nil {
		f.Close()
		return nil, err
	}
	return l, nil
}

// prepare sets the file mode and notes whether the file ends mid-line.
func (l *Log) prepare() error {
	if err := l.f.Chmod(0o600); err != nil {
		return err
	}
	fi, err := l.f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() == 0 {
		return nil
	}
	var last [1]byte
	if _, err := l.f.ReadAt(last[:], fi.Size()-1); err != nil {
		return err
	}
	l.needNL = last[0] != '\n'
	return nil
}

// Write appends e as one JSON line and syncs it to disk. A zero Time is set
// from the clock. An error from the sync means the line may already be in the
// file, so callers must not write the event again.
func (l *Log) Write(e Event) error {
	if e.Time.IsZero() {
		e.Time = l.clk.Wall()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(line)+1 > maxTailBytes {
		return ErrTooLarge
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.needNL {
		line = append([]byte{'\n'}, line...)
	}
	if _, err := l.f.Write(line); err != nil {
		// A partial line may have reached the file.
		l.needNL = true
		return err
	}
	l.needNL = false
	return l.f.Sync()
}

const maxTailBytes = 2 << 20

// Tail returns up to the last n events, oldest first. Lines that do not
// decode as an Event are skipped. Only the newest 2 MiB are read; a partial
// starting line is discarded.
func (l *Log) Tail(n int) ([]Event, error) {
	if n <= 0 {
		return []Event{}, nil
	}
	l.mu.Lock()
	f, err := os.Open(l.path)
	if err != nil {
		l.mu.Unlock()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		l.mu.Unlock()
		return nil, err
	}
	start := info.Size() - maxTailBytes
	if start < 0 {
		start = 0
	}
	// Read the previous byte to distinguish a whole line from a partial one.
	offset := start
	if offset > 0 {
		offset--
	}
	data, err := io.ReadAll(io.NewSectionReader(f, offset, info.Size()-offset))
	f.Close()
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if start > 0 && len(data) > 0 {
		previous := data[0]
		data = data[1:]
		if previous != '\n' {
			if end := bytes.IndexByte(data, '\n'); end >= 0 {
				data = data[end+1:]
			} else {
				data = nil
			}
		}
	}
	var events []Event
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var e Event
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		events = append(events, e)
	}
	if len(events) > n {
		events = events[len(events)-n:]
	}
	return events, nil
}

// Close closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
