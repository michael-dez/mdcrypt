package crypto_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/michael-dez/mdcrypt/internal/crypto"
)

const passphrase = "correct-horse-battery-staple"

// testIdentity returns a fresh X25519 identity and the matching recipient.
func testIdentity(t *testing.T) (*age.X25519Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	return id, id.Recipient()
}

func TestRoundTripX25519(t *testing.T) {
	id, recipient := testIdentity(t)

	token, err := crypto.Encrypt("hello world", []age.Recipient{recipient})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := crypto.Decrypt(token, []age.Identity{id})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
}

func TestRoundTripPassphrase(t *testing.T) {
	r, err := crypto.PassphraseRecipient(passphrase)
	if err != nil {
		t.Fatalf("PassphraseRecipient: %v", err)
	}
	i, err := crypto.PassphraseIdentity(passphrase)
	if err != nil {
		t.Fatalf("PassphraseIdentity: %v", err)
	}

	token, err := crypto.Encrypt("hello world", []age.Recipient{r})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := crypto.Decrypt(token, []age.Identity{i})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
}

func TestTokenMatchesPattern(t *testing.T) {
	_, recipient := testIdentity(t)
	token, err := crypto.Encrypt("secret", []age.Recipient{recipient})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !crypto.TokenPattern.MatchString(token) {
		t.Errorf("token does not match pattern: %s", token)
	}
}

func TestWrongIdentity(t *testing.T) {
	_, recipient := testIdentity(t)
	otherID, _ := testIdentity(t)

	token, err := crypto.Encrypt("secret", []age.Recipient{recipient})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := crypto.Decrypt(token, []age.Identity{otherID}); err == nil {
		t.Fatal("expected error decrypting with wrong identity, got nil")
	}
}

func TestNonDeterministic(t *testing.T) {
	_, recipient := testIdentity(t)
	a, err := crypto.Encrypt("same", []age.Recipient{recipient})
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.Encrypt("same", []age.Recipient{recipient})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two encryptions of the same value produced identical tokens")
	}
}

func TestMultipleRecipients(t *testing.T) {
	id1, r1 := testIdentity(t)
	id2, r2 := testIdentity(t)

	token, err := crypto.Encrypt("shared secret", []age.Recipient{r1, r2})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	for name, id := range map[string]age.Identity{"id1": id1, "id2": id2} {
		got, err := crypto.Decrypt(token, []age.Identity{id})
		if err != nil {
			t.Errorf("%s: Decrypt: %v", name, err)
			continue
		}
		if got != "shared secret" {
			t.Errorf("%s: got %q, want %q", name, got, "shared secret")
		}
	}
}

func TestMalformedToken(t *testing.T) {
	id, _ := testIdentity(t)
	if _, err := crypto.Decrypt("ENC[garbage]", []age.Identity{id}); err == nil {
		t.Fatal("expected error on malformed token")
	}
}

func TestEncryptNoRecipients(t *testing.T) {
	if _, err := crypto.Encrypt("hi", nil); err == nil {
		t.Fatal("expected error when no recipients provided")
	}
}

func TestDecryptNoIdentities(t *testing.T) {
	_, recipient := testIdentity(t)
	token, err := crypto.Encrypt("secret", []age.Recipient{recipient})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Decrypt(token, nil); err == nil {
		t.Fatal("expected error when no identities provided")
	}
}

func TestMultilinePlaintext(t *testing.T) {
	id, recipient := testIdentity(t)
	plain := "line one\nline two\nline three"
	token, err := crypto.Encrypt(plain, []age.Recipient{recipient})
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.Decrypt(token, []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Errorf("got %q, want %q", got, plain)
	}
}

func TestUnicodePlaintext(t *testing.T) {
	id, recipient := testIdentity(t)
	plain := "пароль: 🔑 café"
	token, err := crypto.Encrypt(plain, []age.Recipient{recipient})
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.Decrypt(token, []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Errorf("got %q, want %q", got, plain)
	}
}

func TestLoadIdentitiesAndRecipients(t *testing.T) {
	id, _ := testIdentity(t)
	dir := t.TempDir()

	idPath := filepath.Join(dir, "identity.txt")
	if err := os.WriteFile(idPath, []byte(id.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rPath := filepath.Join(dir, "recipients.txt")
	if err := os.WriteFile(rPath, []byte(id.Recipient().String()+"\n# a comment\n\n"), 0644); err != nil {
		t.Fatal(err)
	}

	rs, err := crypto.LoadRecipients(rPath)
	if err != nil {
		t.Fatalf("LoadRecipients: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("got %d recipients, want 1", len(rs))
	}

	ids, err := crypto.LoadIdentities(idPath)
	if err != nil {
		t.Fatalf("LoadIdentities: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}

	token, err := crypto.Encrypt("from-file", rs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.Decrypt(token, ids)
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-file" {
		t.Errorf("round trip via file-loaded keys: got %q", got)
	}
}

func TestParseRecipient(t *testing.T) {
	_, recipient := testIdentity(t)
	r, err := crypto.ParseRecipient(recipient.(*age.X25519Recipient).String())
	if err != nil {
		t.Fatalf("ParseRecipient: %v", err)
	}
	if r == nil {
		t.Fatal("got nil recipient")
	}
}

func TestParseRecipientRejectsGarbage(t *testing.T) {
	if _, err := crypto.ParseRecipient("not-a-real-recipient"); err == nil {
		t.Error("expected error parsing garbage recipient")
	}
	if _, err := crypto.ParseRecipient(strings.Repeat("x", 80)); err == nil {
		t.Error("expected error parsing garbage recipient")
	}
}
