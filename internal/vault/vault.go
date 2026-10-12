// Package vault stores the wrapped master key, the encrypted secrets, their
// plaintext metadata and flags in a directory of JSON files. Secret create,
// update, rename, delete and reveal go through an unlocked Session; metadata
// and flags need no key.
package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"tokencrypt/internal/clock"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/securemem"
)

const (
	// MaxValueBytes is the largest secret value.
	MaxValueBytes = 1 << 20

	formatVersion = 1
	kdfName       = "argon2id"
	headerFile    = "header.json"
	secretsDir    = "secrets"

	kindMK     = "mk"
	kindDK     = "dk"
	kindSecret = "secret"

	// Bounds applied to the KDF parameters stored in header.json before
	// Argon2 runs, so a tampered header cannot weaken the KDF or exhaust
	// memory. MinMemoryKiB admits the small parameters used in tests.
	MinMemoryKiB uint32 = 64
	MaxMemoryKiB uint32 = 1 << 20 // 1 GiB
	MinTime      uint32 = 1
	MaxTime      uint32 = 100
	MinThreads   uint8  = 1
	MaxThreads   uint8  = 16
)

var (
	ErrWrongPassphrase = errors.New("vault: wrong passphrase")
	ErrNotFound        = errors.New("vault: secret not found")
	ErrExists          = errors.New("vault: secret already exists")
	ErrBadName         = errors.New("vault: invalid secret name")
	ErrTooLarge        = errors.New("vault: value larger than 1 MiB")
	ErrBadParams       = errors.New("vault: KDF parameters out of bounds")
	ErrInitialized     = errors.New("vault: already initialized")
	ErrClosed          = errors.New("vault: session closed")
	ErrCorrupt         = errors.New("vault: corrupt file")
	ErrFileTooLarge    = errors.New("vault: file exceeds size limit")
)

// ValidName reports whether name matches [a-z][a-z0-9_]{0,63}.
func ValidName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '_'):
		default:
			return false
		}
	}
	return true
}

func checkParams(p crypto.Params) error {
	if p.Time < MinTime || p.Time > MaxTime ||
		p.Threads < MinThreads || p.Threads > MaxThreads ||
		p.MemoryKiB < MinMemoryKiB || p.MemoryKiB > MaxMemoryKiB ||
		p.MemoryKiB < 8*uint32(p.Threads) {
		return ErrBadParams
	}
	return nil
}

type header struct {
	Version   int           `json:"version"`
	KDF       string        `json:"kdf"`
	Params    crypto.Params `json:"params"`
	Salt      []byte        `json:"salt"`
	KeyID     []byte        `json:"key_id"`
	WrappedMK []byte        `json:"wrapped_mk"`
}

type secretFile struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	KeyID     []byte `json:"key_id"`
	WrappedDK []byte `json:"wrapped_dk"`
	Cipher    []byte `json:"ciphertext"`
}

// dirLocks maps a canonical vault directory to the mutex that serializes
// writes to it. Every Vault and Session for one directory shares that mutex.
// Entries are never removed; there is one per directory used by the process.
var dirLocks sync.Map

// dirLock returns the write lock for dir. The key is the absolute path with
// symlinks resolved when dir exists, so different spellings of one directory
// share a lock.
func dirLock(dir string) *sync.Mutex {
	key, err := filepath.Abs(dir)
	if err != nil {
		key = filepath.Clean(dir)
	}
	if r, err := filepath.EvalSymlinks(key); err == nil {
		key = r
	}
	m, _ := dirLocks.LoadOrStore(key, new(sync.Mutex))
	return m.(*sync.Mutex)
}

// Vault is a vault directory. It holds no key material.
type Vault struct {
	dir string
	// mu serializes every check-then-write sequence on the directory. It is
	// shared by all Vault values for the same directory. A Session takes its
	// own mutex first and mu second; nothing holding mu takes a Session mutex.
	// Reads take no lock because each file is replaced atomically.
	mu  *sync.Mutex
	clk clock.Clock
}

func (v *Vault) headerPath() string { return filepath.Join(v.dir, headerFile) }
func (v *Vault) secretPath(name string) string {
	return filepath.Join(v.dir, secretsDir, name+".json")
}

func writeJSON(path string, max int64, x any) error {
	b, err := json.Marshal(x)
	if err != nil {
		return err
	}
	if int64(len(b)) > max {
		return ErrFileTooLarge
	}
	return writeFileAtomic(path, b)
}

func (v *Vault) readHeader() (*header, error) {
	b, err := readBounded(v.headerPath(), maxVaultFileBytes)
	if err != nil {
		return nil, err
	}
	var h header
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrCorrupt, err)
	}
	if h.Version != formatVersion || h.KDF != kdfName || len(h.Salt) != 16 || len(h.KeyID) != 16 {
		return nil, fmt.Errorf("%w: header fields", ErrCorrupt)
	}
	if err := checkParams(h.Params); err != nil {
		return nil, err
	}
	return &h, nil
}

// wrapMK derives the KEK from passphrase and salt and seals mk under it.
func wrapMK(passphrase, mk, salt, keyID []byte, p crypto.Params) ([]byte, error) {
	kek, err := crypto.DeriveKEK(passphrase, salt, p)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(kek)
	return crypto.Seal(kek, mk, crypto.AAD(formatVersion, kindMK, "", keyID))
}

// Init creates a new vault in dir with a random master key wrapped under the
// passphrase. It fails with ErrInitialized if dir already holds a vault and
// with ErrBadParams if p is outside the bounds.
func Init(dir string, passphrase []byte, p crypto.Params) error {
	if err := checkParams(p); err != nil {
		return err
	}
	for _, d := range []string{dir, filepath.Join(dir, secretsDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return err
		}
	}
	v := &Vault{dir: dir, mu: dirLock(dir)}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := os.Stat(v.headerPath()); err == nil {
		return ErrInitialized
	}
	mk, err := crypto.NewKey()
	if err != nil {
		return err
	}
	defer crypto.Zero(mk)
	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	keyID, err := crypto.NewID()
	if err != nil {
		return err
	}
	wrapped, err := wrapMK(passphrase, mk, salt, keyID, p)
	if err != nil {
		return err
	}
	return writeJSON(v.headerPath(), maxVaultFileBytes, &header{
		Version: formatVersion, KDF: kdfName, Params: p,
		Salt: salt, KeyID: keyID, WrappedMK: wrapped,
	})
}

// Open opens the vault in dir. It reads and bound-checks header.json.
func Open(dir string) (*Vault, error) { return OpenWithClock(dir, clock.Real{}) }

// OpenWithClock is Open with the wall clock used for metadata timestamps.
func OpenWithClock(dir string, clk clock.Clock) (*Vault, error) {
	v := &Vault{dir: dir, mu: dirLock(dir), clk: clk}
	if _, err := v.readHeader(); err != nil {
		return nil, err
	}
	return v, nil
}

// Unlock derives the KEK and unwraps the master key. A wrong passphrase
// returns ErrWrongPassphrase and no session. The header is read and
// bound-checked before Argon2 runs.
func (v *Vault) Unlock(passphrase []byte) (*Session, error) {
	h, err := v.readHeader()
	if err != nil {
		return nil, err
	}
	kek, err := crypto.DeriveKEK(passphrase, h.Salt, h.Params)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(kek)
	mk, err := crypto.Open(kek, h.WrappedMK, crypto.AAD(formatVersion, kindMK, "", h.KeyID))
	if err != nil {
		if errors.Is(err, crypto.ErrAuth) {
			return nil, ErrWrongPassphrase
		}
		return nil, err
	}
	memory := securemem.Copy(mk)
	crypto.Zero(mk)
	return &Session{v: v, mk: memory.Bytes, memory: memory, mkID: h.KeyID}, nil
}

func (v *Vault) readSecret(name string) (*secretFile, error) {
	if !ValidName(name) {
		return nil, ErrBadName
	}
	b, err := readBounded(v.secretPath(name), maxVaultFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var f secretFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, name, err)
	}
	if f.Version != formatVersion || f.Name != name || len(f.KeyID) != 16 {
		return nil, fmt.Errorf("%w: %s", ErrCorrupt, name)
	}
	return &f, nil
}

// Exists reports whether a secret file for name exists.
func (v *Vault) Exists(name string) bool {
	if !ValidName(name) {
		return false
	}
	_, err := os.Stat(v.secretPath(name))
	return err == nil
}

// KeyID returns the key ID of the current value of name. It needs no key.
func (v *Vault) KeyID(name string) ([]byte, error) {
	f, err := v.readSecret(name)
	if err != nil {
		return nil, err
	}
	return f.KeyID, nil
}

// Session is an unlocked vault holding the master key.
type Session struct {
	mu     sync.Mutex
	v      *Vault
	mk     []byte
	memory *securemem.Buffer
	// mkID is the key ID of the master key, authenticated by the unwrap.
	mkID []byte
}

// Close zeroes the master key. Later calls return ErrClosed.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.memory.Close()
	s.mk = nil
}

// seal builds a secret file for name with a fresh DK and key ID.
func (s *Session) seal(name string, value []byte) (*secretFile, error) {
	dk, err := crypto.NewKey()
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(dk)
	id, err := crypto.NewID()
	if err != nil {
		return nil, err
	}
	wrapped, err := crypto.Seal(s.mk, dk, crypto.AAD(formatVersion, kindDK, name, id))
	if err != nil {
		return nil, err
	}
	ct, err := crypto.Seal(dk, value, crypto.AAD(formatVersion, kindSecret, name, id))
	if err != nil {
		return nil, err
	}
	return &secretFile{Version: formatVersion, Name: name, KeyID: id, WrappedDK: wrapped, Cipher: ct}, nil
}

func (s *Session) open(name string) ([]byte, []byte, error) {
	f, err := s.v.readSecret(name)
	if err != nil {
		return nil, nil, err
	}
	dk, err := crypto.Open(s.mk, f.WrappedDK, crypto.AAD(formatVersion, kindDK, name, f.KeyID))
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Zero(dk)
	val, err := crypto.Open(dk, f.Cipher, crypto.AAD(formatVersion, kindSecret, name, f.KeyID))
	if err != nil {
		return nil, nil, err
	}
	return val, f.KeyID, nil
}

func (s *Session) writeSecret(f *secretFile) error {
	return writeJSON(s.v.secretPath(f.Name), maxVaultFileBytes, f)
}

// Create stores a new secret and its metadata. The metadata entry is written
// first: a failure or crash before the secret file lands leaves an entry that
// no secret file backs, which List and Get ignore and a later Create replaces.
func (s *Session) Create(name, description string, value []byte) error {
	return s.CreateWithExpiry(name, description, value, "")
}

// CreateWithExpiry stores a secret with an optional informational civil date.
func (s *Session) CreateWithExpiry(name, description string, value []byte, date string) error {
	if !ValidExpiry(date) {
		return ErrBadExpiry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mk == nil {
		return ErrClosed
	}
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	if !ValidName(name) {
		return ErrBadName
	}
	if len(value) > MaxValueBytes {
		return ErrTooLarge
	}
	if _, err := os.Stat(s.v.secretPath(name)); err == nil {
		return ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	md, err := s.v.readMeta()
	if err != nil {
		return err
	}
	f, err := s.seal(name, value)
	if err != nil {
		return err
	}
	now := s.v.now()
	md.Secrets[name] = &metaRecord{Description: description, Created: now, Updated: now, ExpiresOn: date}
	if err := s.v.writeMeta(md); err != nil {
		return err
	}
	return s.writeSecret(f)
}

// UpdateValue replaces the value of name with a new DK and key ID, stamps the
// update time and clears the flag. The secret file is written first, so a
// crash between the two writes leaves the flag in place rather than a cleared
// flag on the old value. If the metadata write fails the error wraps
// ErrMetadata, the new value stands and the flag is still set.
func (s *Session) UpdateValue(name string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mk == nil {
		return ErrClosed
	}
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	if !ValidName(name) {
		return ErrBadName
	}
	if len(value) > MaxValueBytes {
		return ErrTooLarge
	}
	if !s.v.Exists(name) {
		return ErrNotFound
	}
	md, err := s.v.readMeta()
	if err != nil {
		return err
	}
	f, err := s.seal(name, value)
	if err != nil {
		return err
	}
	if err := s.writeSecret(f); err != nil {
		return err
	}
	r := md.record(name)
	r.Updated, r.Flag = s.v.now(), nil
	md.Secrets[name] = r
	if err := s.v.writeMeta(md); err != nil {
		return metaErr(err)
	}
	return nil
}

// Rename re-encrypts name under newName with a new DK and key ID and moves
// its metadata unchanged, including the flag. The new metadata entry is
// written first, then the new file, then the old file is removed and the
// secrets directory synced, then the old entry is dropped. A failure before
// the new file lands changes no secret; a failed final metadata write returns
// an error wrapping ErrMetadata after the move is complete and leaves an
// entry for the old name that no file backs.
func (s *Session) Rename(oldName, newName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mk == nil {
		return ErrClosed
	}
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	if !ValidName(oldName) || !ValidName(newName) {
		return ErrBadName
	}
	val, _, err := s.open(oldName)
	if err != nil {
		return err
	}
	defer crypto.Zero(val)
	if s.v.Exists(newName) {
		return ErrExists
	}
	md, err := s.v.readMeta()
	if err != nil {
		return err
	}
	f, err := s.seal(newName, val)
	if err != nil {
		return err
	}
	moved := *md.record(oldName)
	md.Secrets[newName] = &moved
	if err := s.v.writeMeta(md); err != nil {
		return err
	}
	if err := s.writeSecret(f); err != nil {
		return err
	}
	rmErr := s.removeSecret(oldName)
	if rmErr != nil && s.v.Exists(oldName) {
		return rmErr
	}
	delete(md.Secrets, oldName)
	if err := s.v.writeMeta(md); err != nil {
		if rmErr != nil {
			return rmErr
		}
		return metaErr(err)
	}
	return rmErr
}

// removeSecret unlinks the file for name and syncs the secrets directory so
// the removal is durable. A non-nil error from the sync means the file is
// gone but the removal may not survive a crash.
func (s *Session) removeSecret(name string) error {
	if err := os.Remove(s.v.secretPath(name)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(s.v.secretPath(name)))
}

// Delete removes the secret file for name, syncs the secrets directory and
// drops the metadata entry. A failed metadata write returns an error wrapping
// ErrMetadata after the file is gone; the stale entry is ignored by List and
// Get and replaced by a later Create. Deleting a name that has no file still
// drops a stale entry, then returns ErrNotFound, so a retry after ErrMetadata
// (or Delete of the old name after a Rename that returned ErrMetadata)
// removes the leftover record. If that cleanup itself fails the error is
// returned as is.
func (s *Session) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mk == nil {
		return ErrClosed
	}
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	if !ValidName(name) {
		return ErrBadName
	}
	rmErr := s.removeSecret(name)
	missing := errors.Is(rmErr, os.ErrNotExist)
	if rmErr != nil && !missing && s.v.Exists(name) {
		return rmErr
	}
	md, err := s.v.readMeta()
	if err == nil && md.Secrets[name] != nil {
		delete(md.Secrets, name)
		err = s.v.writeMeta(md)
	}
	switch {
	case missing && err != nil:
		return err
	case missing:
		return ErrNotFound
	case err != nil && rmErr != nil:
		return rmErr
	case err != nil:
		return metaErr(err)
	}
	return rmErr
}

// Reveal returns the value and key ID of name. Both slices belong to the
// caller.
func (s *Session) Reveal(name string) (value []byte, keyID []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mk == nil {
		return nil, nil, ErrClosed
	}
	return s.open(name)
}

// DeriveKey returns HKDF(MK, label).
func (s *Session) DeriveKey(label string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mk == nil {
		return nil, ErrClosed
	}
	return crypto.HKDF(s.mk, label)
}

// ChangePassphrase re-wraps the master key under a new salt and the new
// passphrase with the stored KDF parameters. No secret is re-encrypted.
func (s *Session) ChangePassphrase(newPassphrase []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mk == nil {
		return ErrClosed
	}
	s.v.mu.Lock()
	defer s.v.mu.Unlock()
	h, err := s.v.readHeader()
	if err != nil {
		return err
	}
	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	wrapped, err := wrapMK(newPassphrase, s.mk, salt, h.KeyID, h.Params)
	if err != nil {
		return err
	}
	h.Salt, h.WrappedMK = salt, wrapped
	return writeJSON(s.v.headerPath(), maxVaultFileBytes, h)
}
