package grants

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"tokencrypt/internal/crypto"
)

const (
	recordsFile         = "grants.json"
	recordsVersion      = 1
	maxRecordsFileBytes = 8 << 20
	// macKeySize is the length of the key that signs records:
	// HKDF(MK, "tokencrypt grants v1").
	macKeySize = 32
	macDomain  = "tokencrypt grant record v1"
)

// record is the stored part of a long grant. It holds no value.
type record struct {
	ID        string    `json:"id"`
	Secret    string    `json:"secret"`
	KeyID     []byte    `json:"key_id"`
	Expires   time.Time `json:"expires"`
	GrantedBy string    `json:"granted_by"`
	RequestID string    `json:"request_id"`
	MAC       []byte    `json:"mac"`
}

type recordsDoc struct {
	Version int      `json:"version"`
	Grants  []record `json:"grants"`
}

// macMessage encodes every signed field with a length prefix so no two
// records share an encoding.
func (r *record) macMessage() []byte {
	b := []byte(macDomain)
	for _, f := range [][]byte{[]byte(r.ID), []byte(r.Secret), r.KeyID, []byte(r.GrantedBy), []byte(r.RequestID)} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	// Seconds and nanoseconds are signed separately: UnixNano wraps, so two
	// instants 2^64 ns apart would share a MAC.
	b = binary.BigEndian.AppendUint64(b, uint64(r.Expires.Unix()))
	return binary.BigEndian.AppendUint32(b, uint32(r.Expires.Nanosecond()))
}

func (r *record) sign(key []byte) { r.MAC = crypto.MAC(key, r.macMessage()) }

func (r *record) verify(key []byte) bool { return crypto.VerifyMAC(key, r.macMessage(), r.MAC) }

func (m *Manager) path() string { return filepath.Join(m.dir, recordsFile) }

// readRecords loads grants.json. A missing file is an empty set; a file that
// does not parse fails with ErrCorrupt.
func (m *Manager) readRecords() ([]record, error) {
	b, err := readBounded(m.path(), maxRecordsFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc recordsDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, recordsFile, err)
	}
	if doc.Version != recordsVersion {
		return nil, fmt.Errorf("%w: %s version", ErrCorrupt, recordsFile)
	}
	return doc.Grants, nil
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%w: file exceeds size limit", ErrCorrupt)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: file exceeds size limit", ErrCorrupt)
	}
	return b, nil
}

// updateRecords rewrites grants.json under the manager lock: it drops the
// records named in ids, those in the retry set and, when secret is not empty,
// those for that secret; drops records whose expiry has passed; and appends
// add. Other records are written back unchanged, so grants that are still
// waiting for a restore survive. A failed write puts ids in the retry set so
// Candidates and Restore never offer them again and the next write removes
// them. It returns the number of ids and secret matches that were present.
func (m *Manager) updateRecords(add *record, secret string, ids ...string) (int, error) {
	drop := map[string]bool{}
	for id := range m.unremoved {
		drop[id] = true
	}
	for _, id := range ids {
		drop[id] = true
	}
	fail := func(err error) (int, error) {
		for _, id := range ids {
			m.unremoved[id] = true
		}
		return 0, err
	}
	recs, err := m.readRecords()
	if err != nil {
		return fail(err)
	}
	wall := m.clk.Wall()
	out := make([]record, 0, len(recs)+1)
	removed := 0
	for _, r := range recs {
		switch {
		case drop[r.ID] || (secret != "" && r.Secret == secret):
			removed++
		case add != nil && r.ID == add.ID:
		case !wall.Before(r.Expires):
		default:
			out = append(out, r)
		}
	}
	if add == nil && len(out) == len(recs) {
		return 0, nil
	}
	if add != nil {
		out = append(out, *add)
	}
	b, err := json.Marshal(recordsDoc{Version: recordsVersion, Grants: out})
	if err != nil {
		return fail(err)
	}
	if err := writeFileAtomic(m.path(), b); err != nil {
		return fail(err)
	}
	clear(m.unremoved)
	return removed, nil
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory: write, fsync, rename, then fsync of the directory. The file mode
// is 0600. An error before the rename leaves the target unchanged.
func writeFileAtomic(path string, data []byte) error {
	if len(data) > maxRecordsFileBytes {
		return fmt.Errorf("%w: file exceeds size limit", ErrCorrupt)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-grants-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
