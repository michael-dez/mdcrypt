package parser_test

import (
	"strings"
	"testing"

	"github.com/michael-dez/mdcrypt/internal/crypto"
	"github.com/michael-dez/mdcrypt/internal/parser"
)

const (
	pass    = "correct-horse-battery-staple"
	testAAD = "/home/user/notes/note.md"
)

var plainDoc = strings.TrimSpace(`
# Note

Some prose.

<!-- secret -->
my-api-key-12345
<!-- /secret -->

More prose.
`)

func encFn(pt string) (string, error) {
	return crypto.Encrypt(pt, pass, testAAD)
}

func decFn(tok string) (string, error) {
	return crypto.Decrypt(tok, pass)
}

func TestFindBlocksPlaintext(t *testing.T) {
	blocks := parser.FindBlocks(plainDoc)
	if len(blocks) != 1 {
		t.Fatalf("got %d blocks, want 1", len(blocks))
	}
	if blocks[0].IsEncrypted {
		t.Error("block should not be encrypted")
	}
	if blocks[0].Inner != "my-api-key-12345" {
		t.Errorf("inner = %q, want %q", blocks[0].Inner, "my-api-key-12345")
	}
}

func TestHasUnencrypted(t *testing.T) {
	if !parser.HasUnencryptedBlocks(plainDoc) {
		t.Error("expected HasUnencryptedBlocks = true")
	}
	if parser.HasEncryptedBlocks(plainDoc) {
		t.Error("expected HasEncryptedBlocks = false")
	}
}

func TestEncryptBlocks(t *testing.T) {
	result, err := parser.EncryptBlocks(plainDoc, encFn)
	if err != nil {
		t.Fatalf("EncryptBlocks: %v", err)
	}
	if result.Count != 1 {
		t.Errorf("Count = %d, want 1", result.Count)
	}
	if !parser.HasEncryptedBlocks(result.Text) {
		t.Error("result should have encrypted blocks")
	}
	if parser.HasUnencryptedBlocks(result.Text) {
		t.Error("result should have no unencrypted blocks")
	}
	if strings.Contains(result.Text, "my-api-key-12345") {
		t.Error("plaintext should not appear in result")
	}
}

func TestDecryptBlocks(t *testing.T) {
	enc, err := parser.EncryptBlocks(plainDoc, encFn)
	if err != nil {
		t.Fatal(err)
	}
	dec := parser.DecryptBlocks(enc.Text, decFn)
	if dec.Count != 1 {
		t.Errorf("Count = %d, want 1", dec.Count)
	}
	if len(dec.Errors) != 0 {
		t.Errorf("unexpected errors: %v", dec.Errors)
	}
	if !strings.Contains(dec.Text, "my-api-key-12345") {
		t.Error("decrypted text should contain original secret")
	}
}

func TestIdempotentEncrypt(t *testing.T) {
	enc1, err := parser.EncryptBlocks(plainDoc, encFn)
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := parser.EncryptBlocks(enc1.Text, encFn)
	if err != nil {
		t.Fatal(err)
	}
	if enc2.Count != 0 {
		t.Errorf("second encrypt Count = %d, want 0", enc2.Count)
	}
	if enc1.Text != enc2.Text {
		t.Error("second encrypt changed the text")
	}
}

func TestMultipleBlocks(t *testing.T) {
	doc := "<!-- secret -->\nfirst-secret\n<!-- /secret -->\nmiddle\n<!-- secret -->\nsecond-secret\n<!-- /secret -->"

	enc, err := parser.EncryptBlocks(doc, encFn)
	if err != nil {
		t.Fatal(err)
	}
	if enc.Count != 2 {
		t.Errorf("encrypt Count = %d, want 2", enc.Count)
	}

	dec := parser.DecryptBlocks(enc.Text, decFn)
	if dec.Count != 2 {
		t.Errorf("decrypt Count = %d, want 2", dec.Count)
	}
	if len(dec.Errors) != 0 {
		t.Errorf("unexpected errors: %v", dec.Errors)
	}
	if !strings.Contains(dec.Text, "first-secret") {
		t.Error("first-secret missing from decrypted text")
	}
	if !strings.Contains(dec.Text, "second-secret") {
		t.Error("second-secret missing from decrypted text")
	}
}

func TestNoBlocks(t *testing.T) {
	doc := "# Just a normal note\n\nNo secrets here."
	if len(parser.FindBlocks(doc)) != 0 {
		t.Error("expected no blocks")
	}
	if parser.HasUnencryptedBlocks(doc) {
		t.Error("expected HasUnencryptedBlocks = false")
	}
}

func TestProsePreserved(t *testing.T) {
	doc := "Before\n<!-- secret -->\nsecret\n<!-- /secret -->\nAfter"

	enc, err := parser.EncryptBlocks(doc, encFn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc.Text, "Before\n") {
		t.Errorf("prefix lost: %q", enc.Text[:20])
	}
	if !strings.HasSuffix(enc.Text, "\nAfter") {
		t.Errorf("suffix lost: %q", enc.Text[len(enc.Text)-10:])
	}

	dec := parser.DecryptBlocks(enc.Text, decFn)
	if !strings.HasPrefix(dec.Text, "Before\n") {
		t.Error("prefix lost after decrypt")
	}
	if !strings.HasSuffix(dec.Text, "\nAfter") {
		t.Error("suffix lost after decrypt")
	}
}

func TestRoundTripPreservesFormatting(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{
			name: "inline block",
			doc:  "Prose. <!-- secret -->my-api-key-12345<!-- /secret --> more prose.",
		},
		{
			name: "inline with internal spaces",
			doc:  "key: <!-- secret --> my-api-key-12345 <!-- /secret -->\n",
		},
		{
			name: "multiline block",
			doc:  "Before\n<!-- secret -->\nmy-api-key-12345\n<!-- /secret -->\nAfter\n",
		},
		{
			name: "mixed inline and multiline",
			doc: "# Header\n\nFirst secret: <!-- secret -->inline-secret<!-- /secret -->.\n\n" +
				"Second:\n<!-- secret -->\nmultiline-secret\n<!-- /secret -->\n\nDone.\n",
		},
		{
			name: "no trailing newline",
			doc:  "<!-- secret -->only-content<!-- /secret -->",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := parser.EncryptBlocks(tc.doc, encFn)
			if err != nil {
				t.Fatalf("EncryptBlocks: %v", err)
			}
			dec := parser.DecryptBlocks(enc.Text, decFn)
			if len(dec.Errors) != 0 {
				t.Fatalf("DecryptBlocks errors: %v", dec.Errors)
			}
			if dec.Text != tc.doc {
				t.Errorf("round-trip mismatch\noriginal:  %q\ndecrypted: %q", tc.doc, dec.Text)
			}
		})
	}
}

func TestEncryptPreservesInlineFormatting(t *testing.T) {
	doc := "key: <!-- secret -->secret-value<!-- /secret --> done"
	enc, err := parser.EncryptBlocks(doc, encFn)
	if err != nil {
		t.Fatal(err)
	}
	// The encrypted form must stay inline — no newlines injected around the token.
	if strings.Contains(enc.Text, "<!-- secret -->\n") {
		t.Errorf("inline block was canonicalized to multiline: %q", enc.Text)
	}
	if !strings.HasPrefix(enc.Text, "key: <!-- secret -->") {
		t.Errorf("prefix lost: %q", enc.Text)
	}
	if !strings.HasSuffix(enc.Text, "<!-- /secret --> done") {
		t.Errorf("suffix lost: %q", enc.Text)
	}
}

func TestWrongPassLeavesBlockIntact(t *testing.T) {
	enc, err := parser.EncryptBlocks(plainDoc, encFn)
	if err != nil {
		t.Fatal(err)
	}

	badDecFn := func(tok string) (string, error) {
		return crypto.Decrypt(tok, "wrong-pass")
	}

	dec := parser.DecryptBlocks(enc.Text, badDecFn)
	if dec.Count != 0 {
		t.Errorf("Count = %d, want 0 (all should fail)", dec.Count)
	}
	if len(dec.Errors) == 0 {
		t.Error("expected errors from bad passphrase")
	}
	if !parser.HasEncryptedBlocks(dec.Text) {
		t.Error("block should remain encrypted on failure")
	}
}
