package crypto

import (
	"bytes"
	"errors"
	"testing"
)

var testParams = Params{Time: 1, MemoryKiB: 64, Threads: 1}

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := mustKey(t)
	aad := AAD(1, "secret", "api_token", []byte("0123456789abcdef"))
	for _, size := range []int{0, 1, 1 << 20} {
		pt := bytes.Repeat([]byte{0x5a}, size)
		blob, err := Seal(key, pt, aad)
		if err != nil {
			t.Fatalf("size %d: seal: %v", size, err)
		}
		got, err := Open(key, blob, aad)
		if err != nil {
			t.Fatalf("size %d: open: %v", size, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	aad := AAD(1, "dk", "", nil)
	blob, _ := Seal(mustKey(t), []byte("fake"), aad)
	if _, err := Open(mustKey(t), blob, aad); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestOpenRejectsChangedAADFields(t *testing.T) {
	key := mustKey(t)
	id := []byte("0123456789abcdef")
	blob, _ := Seal(key, []byte("fake"), AAD(1, "secret", "name_a", id))
	cases := map[string][]byte{
		"version": AAD(2, "secret", "name_a", id),
		"kind":    AAD(1, "dk", "name_a", id),
		"name":    AAD(1, "secret", "name_b", id),
		"keyID":   AAD(1, "secret", "name_a", []byte("fedcba9876543210")),
	}
	for field, aad := range cases {
		if _, err := Open(key, blob, aad); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: got %v, want ErrAuth", field, err)
		}
	}
}

func TestAADFieldBoundaries(t *testing.T) {
	a := AAD(1, "secret", "ab", []byte("c"))
	b := AAD(1, "secret", "a", []byte("bc"))
	if bytes.Equal(a, b) {
		t.Fatal("AAD must not be ambiguous across name and key ID")
	}
}

func TestOpenRejectsFlippedBit(t *testing.T) {
	key := mustKey(t)
	aad := AAD(1, "mk", "", nil)
	blob, _ := Seal(key, []byte("fake value"), aad)
	for _, i := range []int{0, 24, len(blob) - 1} {
		c := bytes.Clone(blob)
		c[i] ^= 1
		if _, err := Open(key, c, aad); !errors.Is(err, ErrAuth) {
			t.Errorf("flip at %d: got %v, want ErrAuth", i, err)
		}
	}
}

func TestOpenShortBlob(t *testing.T) {
	if _, err := Open(mustKey(t), []byte("short"), nil); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestSealBadKeyLength(t *testing.T) {
	if _, err := Seal([]byte("short"), []byte("x"), nil); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestSealIsRandomised(t *testing.T) {
	key := mustKey(t)
	a, _ := Seal(key, []byte("same"), nil)
	b, _ := Seal(key, []byte("same"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same input are equal")
	}
}

func TestDeriveKEK(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, 16)
	a, err := DeriveKEK([]byte("fake pass"), salt, testParams)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 {
		t.Fatalf("len %d", len(a))
	}
	b, _ := DeriveKEK([]byte("fake pass"), salt, testParams)
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
	c, _ := DeriveKEK([]byte("other pass"), salt, testParams)
	if bytes.Equal(a, c) {
		t.Fatal("passphrase ignored")
	}
	d, _ := DeriveKEK([]byte("fake pass"), bytes.Repeat([]byte{2}, 16), testParams)
	if bytes.Equal(a, d) {
		t.Fatal("salt ignored")
	}
}

func TestDeriveKEKRejectsBadInput(t *testing.T) {
	if _, err := DeriveKEK([]byte("p"), []byte("short"), testParams); err == nil {
		t.Error("expected error for short salt")
	}
	if _, err := DeriveKEK([]byte("p"), make([]byte, 16), Params{}); err == nil {
		t.Error("expected error for zero params")
	}
}

func TestHKDF(t *testing.T) {
	key := mustKey(t)
	a, err := HKDF(key, "tokencrypt notifier v1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := HKDF(key, "tokencrypt grants v1")
	if len(a) != 32 || bytes.Equal(a, b) {
		t.Fatal("labels must yield distinct 32-byte keys")
	}
	a2, _ := HKDF(key, "tokencrypt notifier v1")
	if !bytes.Equal(a, a2) {
		t.Fatal("not deterministic")
	}
}

func TestMAC(t *testing.T) {
	key := mustKey(t)
	mac := MAC(key, []byte("message"))
	if !VerifyMAC(key, []byte("message"), mac) {
		t.Fatal("valid mac rejected")
	}
	if VerifyMAC(key, []byte("messagf"), mac) {
		t.Fatal("changed message accepted")
	}
	if VerifyMAC(mustKey(t), []byte("message"), mac) {
		t.Fatal("wrong key accepted")
	}
	if VerifyMAC(key, []byte("message"), mac[:5]) {
		t.Fatal("truncated mac accepted")
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	Zero(b)
	if !bytes.Equal(b, make([]byte, 4)) {
		t.Fatal("not zeroed")
	}
}

func TestRandomValues(t *testing.T) {
	k1, k2 := mustKey(t), mustKey(t)
	if len(k1) != 32 || bytes.Equal(k1, k2) {
		t.Fatal("NewKey")
	}
	i1, _ := NewID()
	i2, _ := NewID()
	if len(i1) != 16 || bytes.Equal(i1, i2) {
		t.Fatal("NewID")
	}
	s1, _ := NewSalt()
	s2, _ := NewSalt()
	if len(s1) != 16 || bytes.Equal(s1, s2) {
		t.Fatal("NewSalt")
	}
}

func BenchmarkDeriveKEK(b *testing.B) {
	salt := make([]byte, 16)
	p := DefaultParams()
	for i := 0; i < b.N; i++ {
		if _, err := DeriveKEK([]byte("fake pass"), salt, p); err != nil {
			b.Fatal(err)
		}
	}
}
