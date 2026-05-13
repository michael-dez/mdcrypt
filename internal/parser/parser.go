// Package parser finds and transforms <!-- secret --> blocks in markdown text.
//
// Secret block syntax (HTML comments — invisible in rendered markdown):
//
//	<!-- secret -->
//	anything here — multiple lines, any content
//	<!-- /secret -->
//
// When encrypted the inner content is replaced with a single ENC token:
//
//	<!-- secret -->
//	ENC[AGE,data:...]
//	<!-- /secret -->
package parser

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/michael-dez/mdcrypt/internal/crypto"
)

var (
	// blockRe matches a complete <!-- secret -->...<!-- /secret --> block.
	blockRe = regexp.MustCompile(
		`(?s)<!--\s*secret\s*-->(?P<inner>.*?)<!--\s*/secret\s*-->`,
	)

	// fullTokenRe matches a string that is exactly one ENC token (after trimming).
	fullTokenRe = regexp.MustCompile(`^` + crypto.TokenPattern.String() + `$`)
)

// Block represents a parsed <!-- secret --> block.
type Block struct {
	FullMatch   string // the entire matched string including tags
	Inner       string // content between the tags (trimmed)
	IsEncrypted bool   // true if inner is already an ENC token
}

// FindBlocks returns all secret blocks found in text.
func FindBlocks(text string) []Block {
	matches := blockRe.FindAllStringSubmatchIndex(text, -1)
	blocks := make([]Block, 0, len(matches))
	for _, m := range blockRe.FindAllStringSubmatch(text, -1) {
		inner := strings.TrimSpace(m[blockRe.SubexpIndex("inner")])
		blocks = append(blocks, Block{
			FullMatch:   m[0],
			Inner:       inner,
			IsEncrypted: fullTokenRe.MatchString(inner),
		})
	}
	return blocks
}

// HasUnencryptedBlocks returns true if any secret block contains plaintext.
func HasUnencryptedBlocks(text string) bool {
	for _, b := range FindBlocks(text) {
		if !b.IsEncrypted {
			return true
		}
	}
	return false
}

// HasEncryptedBlocks returns true if any secret block holds an ENC token.
func HasEncryptedBlocks(text string) bool {
	for _, b := range FindBlocks(text) {
		if b.IsEncrypted {
			return true
		}
	}
	return false
}

// EncryptFn receives plaintext inner content and returns an ENC token.
type EncryptFn func(plaintext string) (string, error)

// DecryptFn receives an ENC token and returns plaintext.
type DecryptFn func(token string) (string, error)

// EncryptResult holds the outcome of EncryptBlocks.
type EncryptResult struct {
	Text  string
	Count int
}

// DecryptResult holds the outcome of DecryptBlocks.
type DecryptResult struct {
	Text   string
	Count  int
	Errors []error
}

// splitSurroundingSpace splits s into leading whitespace, trimmed content, and
// trailing whitespace. If s is all whitespace, the entire string is returned as
// the leading run. Used to preserve the original spacing between the secret
// tags and their inner content across an encrypt/decrypt round trip.
func splitSurroundingSpace(s string) (lead, mid, trail string) {
	leftTrimmed := strings.TrimLeftFunc(s, unicode.IsSpace)
	lead = s[:len(s)-len(leftTrimmed)]
	mid = strings.TrimRightFunc(leftTrimmed, unicode.IsSpace)
	trail = leftTrimmed[len(mid):]
	return lead, mid, trail
}

// EncryptBlocks replaces each unencrypted secret block's inner content with an
// ENC token produced by encryptFn. Already-encrypted blocks are left untouched.
func EncryptBlocks(text string, encryptFn EncryptFn) (EncryptResult, error) {
	var (
		result strings.Builder
		count  int
		pos    int
		encErr error
	)

	for _, loc := range blockRe.FindAllStringSubmatchIndex(text, -1) {
		// loc[0]:loc[1] = full match
		// loc[innerStart]:loc[innerEnd] = inner group
		innerStart := loc[blockRe.SubexpIndex("inner")*2]
		innerEnd := loc[blockRe.SubexpIndex("inner")*2+1]
		lead, mid, trail := splitSurroundingSpace(text[innerStart:innerEnd])

		// Append text before this block
		result.WriteString(text[pos:loc[0]])

		if fullTokenRe.MatchString(mid) {
			// Already encrypted — leave verbatim
			result.WriteString(text[loc[0]:loc[1]])
		} else {
			token, err := encryptFn(mid)
			if err != nil {
				encErr = fmt.Errorf("encrypting block: %w", err)
				result.WriteString(text[loc[0]:loc[1]])
			} else {
				result.WriteString("<!-- secret -->")
				result.WriteString(lead)
				result.WriteString(token)
				result.WriteString(trail)
				result.WriteString("<!-- /secret -->")
				count++
			}
		}
		pos = loc[1]
	}

	result.WriteString(text[pos:])
	return EncryptResult{Text: result.String(), Count: count}, encErr
}

// DecryptBlocks replaces each encrypted secret block with its decrypted inner
// content. Unencrypted blocks are left untouched.
func DecryptBlocks(text string, decryptFn DecryptFn) DecryptResult {
	var (
		result strings.Builder
		count  int
		errs   []error
		pos    int
	)

	for _, loc := range blockRe.FindAllStringSubmatchIndex(text, -1) {
		innerStart := loc[blockRe.SubexpIndex("inner")*2]
		innerEnd := loc[blockRe.SubexpIndex("inner")*2+1]
		lead, mid, trail := splitSurroundingSpace(text[innerStart:innerEnd])

		result.WriteString(text[pos:loc[0]])

		if !fullTokenRe.MatchString(mid) {
			// Not encrypted — leave verbatim
			result.WriteString(text[loc[0]:loc[1]])
		} else {
			plaintext, err := decryptFn(mid)
			if err != nil {
				errs = append(errs, err)
				result.WriteString(text[loc[0]:loc[1]])
			} else {
				result.WriteString("<!-- secret -->")
				result.WriteString(lead)
				result.WriteString(plaintext)
				result.WriteString(trail)
				result.WriteString("<!-- /secret -->")
				count++
			}
		}
		pos = loc[1]
	}

	result.WriteString(text[pos:])
	return DecryptResult{Text: result.String(), Count: count, Errors: errs}
}
