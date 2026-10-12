package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	metaFile      = "meta.json"
	metaVersion   = 1
	secretsSuffix = ".json"

	// FlagLeaked marks a secret the user suspects is compromised.
	FlagLeaked = "leaked"
	// FlagInvalid marks a secret the service rejects or that has expired.
	FlagInvalid = "invalid"
)

var (
	ErrBadExpiry = errors.New("vault: expiry must be a valid YYYY-MM-DD date or blank")
	ErrBadFlag   = errors.New("vault: flag kind must be leaked or invalid")
	// ErrMetadata wraps a failed metadata write that came after the secret
	// file operation of the same call had already been applied. The secret
	// change stands; the caller must treat the call as done and metadata as
	// stale. Repair: UpdateValue again; Delete again (it prunes the record
	// and returns ErrNotFound); after a failed Rename, Delete the old name.
	ErrMetadata = errors.New("vault: secret changed but metadata write failed")
)

// Flag marks a secret as unusable until the user replaces or clears it.
type Flag struct {
	Kind   string    `json:"kind"`
	Actor  string    `json:"actor"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// Meta is the plaintext state of one secret. It holds no value. KeyID is the
// key ID of the secret's current value, read from its file. Corrupt marks a
// file that List could not read; such an entry carries only its name.
type Meta struct {
	Name        string
	Description string
	ExpiresOn   string `json:"expires_on"`
	Created     time.Time
	Updated     time.Time
	LastGranted time.Time
	Flag        *Flag
	KeyID       []byte
	Corrupt     bool
}

// metaRecord is the stored part of Meta.
type metaRecord struct {
	Description string    `json:"description"`
	ExpiresOn   string    `json:"expires_on,omitempty"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
	LastGranted time.Time `json:"last_granted"`
	Flag        *Flag     `json:"flag,omitempty"`
}

type metaData struct {
	Version int                    `json:"version"`
	Secrets map[string]*metaRecord `json:"secrets"`
}

func (v *Vault) metaPath() string { return filepath.Join(v.dir, metaFile) }

func (v *Vault) now() time.Time { return v.clk.Wall().UTC() }

// readMeta loads meta.json. A missing file is an empty set. The result is
// owned by the caller.
func (v *Vault) readMeta() (*metaData, error) {
	b, err := readBounded(v.metaPath(), maxMetaFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return &metaData{Version: metaVersion, Secrets: map[string]*metaRecord{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var m metaData
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, metaFile, err)
	}
	if m.Version != metaVersion {
		return nil, fmt.Errorf("%w: %s version", ErrCorrupt, metaFile)
	}
	if m.Secrets == nil {
		m.Secrets = map[string]*metaRecord{}
	}
	return &m, nil
}

func (v *Vault) writeMeta(m *metaData) error { return writeJSON(v.metaPath(), maxMetaFileBytes, m) }

// metaErr marks err as a metadata failure that follows an applied secret
// change.
func metaErr(err error) error { return fmt.Errorf("%w: %w", ErrMetadata, err) }

// record returns the stored record for name, or a new empty one that is not
// yet in md.
func (md *metaData) record(name string) *metaRecord {
	if r := md.Secrets[name]; r != nil {
		return r
	}
	return &metaRecord{}
}

func metaOf(name string, r *metaRecord, keyID []byte) Meta {
	return Meta{
		Name: name, Description: r.Description, ExpiresOn: r.ExpiresOn,
		Created: r.Created, Updated: r.Updated, LastGranted: r.LastGranted,
		Flag: r.Flag, KeyID: keyID,
	}
}

// List returns the metadata of every secret, sorted by name. A secret file
// without a metadata entry is listed with zero times and no flag; a metadata
// entry without a secret file is ignored. Unreadable files return named Corrupt
// entries; unreadable meta.json still fails the whole call.
func (v *Vault) List() ([]Meta, error) {
	md, err := v.readMeta()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(v.dir, secretsDir))
	if err != nil {
		return nil, err
	}
	var out []Meta
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), secretsSuffix)
		if !ok || e.IsDir() || !ValidName(name) {
			continue
		}
		f, err := v.readSecret(name)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			out = append(out, Meta{Name: name, Corrupt: true})
			continue
		}
		out = append(out, metaOf(name, md.record(name), f.KeyID))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get returns the metadata of name, or ErrNotFound if no secret file exists.
func (v *Vault) Get(name string) (Meta, error) {
	f, err := v.readSecret(name)
	if err != nil {
		return Meta{}, err
	}
	md, err := v.readMeta()
	if err != nil {
		return Meta{}, err
	}
	return metaOf(name, md.record(name), f.KeyID), nil
}

// updateMeta applies fn to the record of an existing secret and writes
// meta.json, serialized with every other vault write. It needs no key.
func (v *Vault) updateMeta(name string, fn func(r *metaRecord)) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !ValidName(name) {
		return ErrBadName
	}
	if !v.Exists(name) {
		return ErrNotFound
	}
	md, err := v.readMeta()
	if err != nil {
		return err
	}
	r := md.record(name)
	fn(r)
	md.Secrets[name] = r
	return v.writeMeta(md)
}

// SetDescription replaces the description of name. Nothing else changes.
func (v *Vault) SetDescription(name, description string) error {
	return v.updateMeta(name, func(r *metaRecord) { r.Description = description })
}

// SetFlag sets the flag of name, replacing any existing one. A zero f.At is
// replaced by the current time. The kind must be FlagLeaked or FlagInvalid.
func (v *Vault) SetFlag(name string, f Flag) error {
	if f.Kind != FlagLeaked && f.Kind != FlagInvalid {
		return ErrBadFlag
	}
	if f.At.IsZero() {
		f.At = v.now()
	}
	return v.updateMeta(name, func(r *metaRecord) { r.Flag = &f })
}

// ClearFlag removes the flag of name. It succeeds if there is none.
func (v *Vault) ClearFlag(name string) error {
	return v.updateMeta(name, func(r *metaRecord) { r.Flag = nil })
}

// TouchGranted records at as the last time name was granted.
func (v *Vault) TouchGranted(name string, at time.Time) error {
	return v.updateMeta(name, func(r *metaRecord) { r.LastGranted = at })
}

// ValidExpiry accepts an optional civil date, valid through that calendar day.
func ValidExpiry(date string) bool {
	if date == "" {
		return true
	}
	if len(date) != 10 {
		return false
	}
	t, err := time.Parse("2006-01-02", date)
	return err == nil && t.Year() >= 1 && t.Format("2006-01-02") == date
}

// SetExpiry changes informational metadata without affecting secret access.
func (v *Vault) SetExpiry(name, date string) error {
	if !ValidExpiry(date) {
		return ErrBadExpiry
	}
	return v.updateMeta(name, func(r *metaRecord) { r.ExpiresOn = date })
}
