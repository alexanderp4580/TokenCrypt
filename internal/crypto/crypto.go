// Package crypto provides the key derivation, authenticated encryption,
// associated-data encoding, key expansion and MAC primitives of the vault.
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	keySize  = chacha20poly1305.KeySize
	idSize   = 16
	saltSize = 16
)

// ErrAuth is returned when a ciphertext fails authentication: wrong key,
// wrong associated data, altered bytes or a truncated blob.
var ErrAuth = errors.New("crypto: authentication failed")

// Params are the Argon2id cost parameters.
type Params struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// DefaultParams returns the Argon2id parameters for new vaults: 14 passes over
// 256 MiB with 4 lanes. BenchmarkDeriveKEK (5 runs) measured 0.85 to 1.16 s per
// derivation, mean about 1.0 s, on an 8-thread x86 CPU inside the
// toolchain container; 3 passes over 256 MiB took about 0.3 s. Other devices have
// other timings.
func DefaultParams() Params {
	return Params{Time: 14, MemoryKiB: 256 * 1024, Threads: 4}
}

// DeriveKEK derives a 32-byte key-encryption key from the passphrase with
// Argon2id. The salt must be 16 bytes.
func DeriveKEK(passphrase, salt []byte, p Params) ([]byte, error) {
	if len(salt) != saltSize {
		return nil, errors.New("crypto: salt must be 16 bytes")
	}
	if p.Time == 0 || p.Threads == 0 || p.MemoryKiB < 8*uint32(p.Threads) {
		return nil, errors.New("crypto: invalid KDF parameters")
	}
	return argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Threads, keySize), nil
}

func random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// NewKey returns 32 random bytes.
func NewKey() ([]byte, error) { return random(keySize) }

// NewID returns a 16-byte random key ID.
func NewID() ([]byte, error) { return random(idSize) }

// NewSalt returns a 16-byte random salt.
func NewSalt() ([]byte, error) { return random(saltSize) }

// Seal encrypts plaintext with XChaCha20-Poly1305 under key and a fresh random
// nonce, binding aad. The result is nonce followed by ciphertext.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce, err := random(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal. Any authentication failure returns ErrAuth.
func Open(key, blob, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrAuth
	}
	nonce, ct := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// AAD encodes the associated data: a 4-byte big-endian version followed by
// kind, name and key ID, each with a 4-byte big-endian length prefix.
func AAD(version int, kind, name string, keyID []byte) []byte {
	out := make([]byte, 4, 16+len(kind)+len(name)+len(keyID))
	binary.BigEndian.PutUint32(out, uint32(version))
	for _, f := range [][]byte{[]byte(kind), []byte(name), keyID} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

// HKDF derives a 32-byte key from key using HKDF-SHA256 with label as info.
func HKDF(key []byte, label string) ([]byte, error) {
	out := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, nil, []byte(label)), out); err != nil {
		return nil, err
	}
	return out, nil
}

// MAC returns HMAC-SHA256 of msg under key.
func MAC(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// VerifyMAC reports whether mac is the valid MAC of msg, in constant time.
func VerifyMAC(key, msg, mac []byte) bool {
	return hmac.Equal(MAC(key, msg), mac)
}

// Zero overwrites b with zeros.
func Zero(b []byte) { clear(b) }
