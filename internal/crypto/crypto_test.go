package crypto_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/michael-dez/mdcrypt/internal/crypto"
)

const (
	pass    = "correct-horse-battery-staple"
	testAAD = "/home/user/notes/note.md"
)

func TestRoundTrip(t *testing.T) {
	token, err := crypto.Encrypt("hello world", pass, testAAD)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := crypto.Decrypt(token, pass)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
}

func TestTokenMatchesPattern(t *testing.T) {
	token, err := crypto.Encrypt("secret", pass, testAAD)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !crypto.TokenPattern.MatchString(token) {
		t.Errorf("token does not match pattern: %s", token)
	}
}

func TestWrongPassphrase(t *testing.T) {
	token, err := crypto.Encrypt("secret", pass, testAAD)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = crypto.Decrypt(token, "wrong-passphrase")
	if err == nil {
		t.Fatal("expected error on wrong passphrase, got nil")
	}
}

func TestNonDeterministic(t *testing.T) {
	a, err := crypto.Encrypt("same", pass, testAAD)
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.Encrypt("same", pass, testAAD)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two encryptions of the same value produced identical tokens")
	}
}

func TestAADFileBinding(t *testing.T) {
	token, err := crypto.Encrypt("secret", pass, "/notes/file1.md")
	if err != nil {
		t.Fatal(err)
	}

	// Tamper: swap the aad field to a different file path
	m := crypto.TokenPattern.FindStringSubmatch(token)
	if m == nil {
		t.Fatal("could not parse token")
	}
	newAAD := base64.StdEncoding.EncodeToString([]byte("/notes/file2.md"))
	oldAAD := m[crypto.TokenPattern.SubexpIndex("aad")]
	tampered := strings.Replace(token, "aad:"+oldAAD, "aad:"+newAAD, 1)

	_, err = crypto.Decrypt(tampered, pass)
	if err == nil {
		t.Fatal("expected decryption to fail with tampered AAD, got nil")
	}
}

func TestMalformedToken(t *testing.T) {
	_, err := crypto.Decrypt("ENC[garbage]", pass)
	if err == nil {
		t.Fatal("expected error on malformed token")
	}
}

func TestMultilinePlaintext(t *testing.T) {
	plain := "line one\nline two\nline three"
	token, err := crypto.Encrypt(plain, pass, testAAD)
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.Decrypt(token, pass)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Errorf("got %q, want %q", got, plain)
	}
}

func TestUnicodePlaintext(t *testing.T) {
	plain := "пароль: 🔑 café"
	token, err := crypto.Encrypt(plain, pass, testAAD)
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.Decrypt(token, pass)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Errorf("got %q, want %q", got, plain)
	}
}
