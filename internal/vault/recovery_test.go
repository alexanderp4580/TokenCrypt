package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOversizedVaultFilesRejectedBeforeDecode(t *testing.T) {
	for _, typ := range []string{"header", "secret", "meta", "notifier"} {
		t.Run(typ, func(t *testing.T) {
			v, s, dir := newSession(t)
			if err := s.Create("tok", "desc", canary); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, typ+".json")
			if typ == "secret" {
				p = filepath.Join(dir, "secrets", "tok.json")
			}
			f, err := os.Create(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(16 << 20); err != nil {
				t.Fatal(err)
			}
			f.Close()
			switch typ {
			case "header":
				_, err = Open(dir)
			case "secret":
				_, err = v.Get("tok")
			case "meta":
				_, err = v.List()
			case "notifier":
				_, _, err = s.LoadNotifier()
			}
			if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "size limit") {
				t.Fatalf("oversized %s: %v", typ, err)
			}
		})
	}
}

func TestOversizedVaultWritesPreserveReadableFiles(t *testing.T) {
	v, s, dir := newSession(t)
	if err := s.Create("tok", "desc", canary); err != nil {
		t.Fatal(err)
	}
	if err := v.SetDescription("tok", strings.Repeat("x", 8<<20)); err == nil {
		t.Fatal("oversized metadata accepted")
	}
	if got, err := v.Get("tok"); err != nil || got.Description != "desc" {
		t.Fatalf("metadata: %+v, %v", got, err)
	}
	if err := s.SetNotifier([]byte("fake"), "123"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNotifier(bytes.Repeat([]byte{'x'}, 64<<10), "123"); err == nil {
		t.Fatal("oversized notifier accepted")
	}
	if tok, _, err := s.LoadNotifier(); err != nil || string(tok) != "fake" {
		t.Fatalf("notifier: %q, %v", tok, err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "header.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "header.json"), maxVaultFileBytes, strings.Repeat("x", 2<<20)); err == nil {
		t.Fatal("oversized header accepted")
	}
	after, err := os.ReadFile(filepath.Join(dir, "header.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("header changed")
	}
}

func TestCreatePropagatesStatFailureWithoutMetadataChange(t *testing.T) {
	_, s, dir := newSession(t)
	p := filepath.Join(dir, "secrets", "tok.json")
	// A symlink loop makes Stat fail with ELOOP rather than absence.
	if err := os.Symlink("tok.json", p); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("tok", "desc", canary); err == nil || errors.Is(err, ErrExists) {
		t.Fatalf("stat error: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "meta.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("metadata written after stat error: %v", err)
	}
	if _, err := os.Readlink(p); err != nil {
		t.Fatalf("symlink changed: %v", err)
	}
}

func TestMaximumValuesForStorageFileNames(t *testing.T) {
	_, s, _ := newSession(t)
	value := bytes.Repeat([]byte{'x'}, 1<<20)
	for _, name := range []string{"notifier", "meta", "header"} {
		if err := s.Create(name, "desc", value); err != nil {
			t.Fatalf("create %s at value limit: %v", name, err)
		}
		got, _, err := s.Reveal(name)
		if err != nil || !bytes.Equal(got, value) {
			t.Fatalf("reveal %s: %v", name, err)
		}
	}
}

func TestVaultRootNameDoesNotChangeFileLimits(t *testing.T) {
	for _, root := range []string{"secrets", "vault"} {
		t.Run(root, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), root)
			if err := Init(dir, pass, testParams); err != nil {
				t.Fatal(err)
			}
			v, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			s, err := v.Unlock(pass)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			t.Run("notifier", func(t *testing.T) {
				if err := s.SetNotifier([]byte("fake-valid-token"), "123"); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(filepath.Join(dir, "notifier.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err := s.SetNotifier(bytes.Repeat([]byte{'x'}, 64<<10), "123"); !errors.Is(err, ErrFileTooLarge) {
					t.Errorf("oversized notifier: %v", err)
				}
				after, err := os.ReadFile(filepath.Join(dir, "notifier.json"))
				if err != nil || !bytes.Equal(before, after) {
					t.Error("oversized update changed notifier file")
				}
				token, chat, err := s.LoadNotifier()
				if err != nil || string(token) != "fake-valid-token" || chat != "123" {
					t.Fatalf("readable notifier: %q, %q, %v", token, chat, err)
				}
			})
			t.Run("metadata", func(t *testing.T) {
				if err := s.Create("tok", "desc", canary); err != nil {
					t.Fatal(err)
				}
				description := strings.Repeat("x", 3<<20)
				if err := v.SetDescription("tok", description); err != nil {
					t.Fatalf("metadata within 8 MiB limit: %v", err)
				}
				got, err := v.Get("tok")
				if err != nil || got.Description != description {
					t.Fatalf("readable metadata: %v", err)
				}
			})
		})
	}
}
