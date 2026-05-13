// Package crypto provides the encryption primitives for mdcrypt.
//
// Each ENC token wraps an age (https://age-encryption.org) ciphertext as
// base64 inside a single self-contained string:
//
//	ENC[AGE,data:<b64>]
//
// The age payload is in age's binary format (header + payload), so it
// already carries everything needed to decrypt — recipient stanzas, nonces,
// authentication tags, etc. — given the matching identity.
package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"filippo.io/age"
)

// TokenPattern matches a complete ENC[...] token.
var TokenPattern = regexp.MustCompile(
	`ENC\[AGE,data:(?P<data>[A-Za-z0-9+/=]+)\]`,
)

// Encrypt encrypts plaintext to the given age recipients and returns a
// self-contained ENC token. At least one recipient is required.
func Encrypt(plaintext string, recipients []age.Recipient) (string, error) {
	if len(recipients) == 0 {
		return "", errors.New("no recipients provided")
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return "", fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		return "", fmt.Errorf("writing plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("finalizing ciphertext: %w", err)
	}

	return fmt.Sprintf("ENC[AGE,data:%s]", base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

// Decrypt decrypts a single ENC token using the supplied identities.
// Returns an error on malformed tokens, no matching identity, or tampering.
func Decrypt(token string, identities []age.Identity) (string, error) {
	m := TokenPattern.FindStringSubmatch(token)
	if m == nil {
		return "", fmt.Errorf("not a valid ENC token: %q", token)
	}
	if len(identities) == 0 {
		return "", errors.New("no identities provided")
	}

	raw, err := base64.StdEncoding.DecodeString(m[TokenPattern.SubexpIndex("data")])
	if err != nil {
		return "", errors.New("malformed token: bad data field")
	}

	r, err := age.Decrypt(bytes.NewReader(raw), identities...)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("reading plaintext: %w", err)
	}
	return string(plaintext), nil
}

// LoadRecipients parses an age recipients file (one recipient per line,
// `#` comments and blank lines ignored). Suitable for ~/.config/mdcrypt/recipients.txt.
func LoadRecipients(path string) ([]age.Recipient, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening recipients file: %w", err)
	}
	defer f.Close()

	rs, err := age.ParseRecipients(f)
	if err != nil {
		return nil, fmt.Errorf("parsing recipients in %s: %w", path, err)
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("no recipients found in %s", path)
	}
	return rs, nil
}

// ParseRecipient parses a single age recipient string (e.g. "age1...").
func ParseRecipient(s string) (age.Recipient, error) {
	rs, err := age.ParseRecipients(bytes.NewReader([]byte(s + "\n")))
	if err != nil {
		return nil, err
	}
	if len(rs) != 1 {
		return nil, fmt.Errorf("expected 1 recipient, got %d", len(rs))
	}
	return rs[0], nil
}

// LoadIdentities parses an age identity file. A single file may hold
// multiple identities; all are returned and any may be used at decrypt time.
func LoadIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening identity file: %w", err)
	}
	defer f.Close()

	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parsing identities in %s: %w", path, err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities found in %s", path)
	}
	return ids, nil
}

// PassphraseRecipient wraps a passphrase as an age scrypt recipient,
// for users who prefer a memorized secret over a key file.
func PassphraseRecipient(passphrase string) (age.Recipient, error) {
	return age.NewScryptRecipient(passphrase)
}

// PassphraseIdentity wraps a passphrase as an age scrypt identity.
func PassphraseIdentity(passphrase string) (age.Identity, error) {
	return age.NewScryptIdentity(passphrase)
}
