// Package crypto provides the low-level encryption primitives for mdcrypt.
//
// Each ENC token is fully self-contained:
//
//	ENC[AES256_GCM,data:<b64>,iv:<b64>,tag:<b64>,aad:<b64>]
//
//	data = 16-byte Argon2id salt || AES-GCM ciphertext
//	iv   = 12-byte random nonce
//	tag  = 16-byte GCM authentication tag
//	aad  = base64(resolved file path) — binds the token to its source file
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"

	"golang.org/x/crypto/argon2"
)

const (
	saltLen = 16
	keyLen  = 32 // AES-256
	ivLen   = 12
	tagLen  = 16

	// Argon2id parameters
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 2
)

// TokenPattern matches a complete ENC[...] token.
var TokenPattern = regexp.MustCompile(
	`ENC\[AES256_GCM,` +
		`data:(?P<data>[A-Za-z0-9+/=]+),` +
		`iv:(?P<iv>[A-Za-z0-9+/=]+),` +
		`tag:(?P<tag>[A-Za-z0-9+/=]+),` +
		`aad:(?P<aad>[A-Za-z0-9+/=]+)\]`,
)

// FileAAD returns the AAD string used to bind a token to a file.
func FileAAD(resolvedPath string) string {
	return resolvedPath
}

// Encrypt encrypts plaintext with AES-256-GCM and returns a self-contained
// ENC[...] token. aad should be the resolved absolute path of the target file.
func Encrypt(plaintext, passphrase, aad string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	iv := make([]byte, ivLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("generating iv: %w", err)
	}

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	// Seal appends the tag to the ciphertext: result = ct || tag
	sealed := gcm.Seal(nil, iv, []byte(plaintext), []byte(aad))
	ct := sealed[:len(sealed)-tagLen]
	tag := sealed[len(sealed)-tagLen:]

	data := base64.StdEncoding.EncodeToString(append(salt, ct...))
	ivB64 := base64.StdEncoding.EncodeToString(iv)
	tagB64 := base64.StdEncoding.EncodeToString(tag)
	aadB64 := base64.StdEncoding.EncodeToString([]byte(aad))

	return fmt.Sprintf(
		"ENC[AES256_GCM,data:%s,iv:%s,tag:%s,aad:%s]",
		data, ivB64, tagB64, aadB64,
	), nil
}

// Decrypt decrypts a single ENC[...] token and returns the plaintext.
// Returns an error on wrong passphrase, tampering, or malformed token.
func Decrypt(token, passphrase string) (string, error) {
	m := TokenPattern.FindStringSubmatch(token)
	if m == nil {
		return "", fmt.Errorf("not a valid ENC token: %q", token)
	}

	idx := func(name string) string {
		return m[TokenPattern.SubexpIndex(name)]
	}

	rawData, err := base64.StdEncoding.DecodeString(idx("data"))
	if err != nil || len(rawData) < saltLen {
		return "", errors.New("malformed token: bad data field")
	}
	salt, ct := rawData[:saltLen], rawData[saltLen:]

	iv, err := base64.StdEncoding.DecodeString(idx("iv"))
	if err != nil {
		return "", errors.New("malformed token: bad iv field")
	}

	tag, err := base64.StdEncoding.DecodeString(idx("tag"))
	if err != nil {
		return "", errors.New("malformed token: bad tag field")
	}

	aad, err := base64.StdEncoding.DecodeString(idx("aad"))
	if err != nil {
		return "", errors.New("malformed token: bad aad field")
	}

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	// GCM.Open expects ct || tag
	plaintext, err := gcm.Open(nil, iv, append(ct, tag...), aad)
	if err != nil {
		return "", errors.New("decryption failed — wrong passphrase, corrupted token, or wrong file")
	}

	return string(plaintext), nil
}

func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(passphrase),
		salt,
		argonTime,
		argonMemory,
		argonThreads,
		keyLen,
	)
}
