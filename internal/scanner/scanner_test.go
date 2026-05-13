package scanner_test

import (
	"fmt"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/michael-dez/mdcrypt/internal/crypto"
	"github.com/michael-dez/mdcrypt/internal/scanner"
)

var testRecipients = func() []age.Recipient {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		panic(err)
	}
	return []age.Recipient{id.Recipient()}
}()

func scan(text string) []scanner.Finding {
	return scanner.ScanText(text, "test.md")
}

func TestDetectsAWSKey(t *testing.T) {
	if len(scan("access: AKIAIOSFODNN7EXAMPLE")) == 0 {
		t.Error("should detect AWS access key")
	}
}

func TestDetectsGitHubPAT(t *testing.T) {
	if len(scan("token: ghp_"+strings.Repeat("A", 36))) == 0 {
		t.Error("should detect GitHub PAT")
	}
}

func TestDetectsOpenAIKey(t *testing.T) {
	if len(scan("key: sk-proj-ABCDEF1234567890abcdef")) == 0 {
		t.Error("should detect sk- style key")
	}
}

func TestDetectsPassword(t *testing.T) {
	if len(scan("password: hunter2")) == 0 {
		t.Error("should detect bare password")
	}
}

func TestDetectsBearer(t *testing.T) {
	if len(scan("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.abc")) == 0 {
		t.Error("should detect Bearer token")
	}
}

func TestCleanDocNoFindings(t *testing.T) {
	if len(scan("# Normal note\n\nNo secrets here.")) != 0 {
		t.Error("clean doc should have no findings")
	}
}

func TestSkipsEncTokenLines(t *testing.T) {
	token, err := crypto.Encrypt("sk-proj-SECRET", testRecipients)
	if err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf("key = %s", token)
	if len(scan(doc)) != 0 {
		t.Error("line with ENC token should not be flagged")
	}
}

func TestSkipsEncryptedBlockContents(t *testing.T) {
	token, err := crypto.Encrypt("AKIAIOSFODNN7EXAMPLE", testRecipients)
	if err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf("<!-- secret -->\n%s\n<!-- /secret -->", token)
	if len(scan(doc)) != 0 {
		t.Error("encrypted block contents should not be flagged")
	}
}

func TestPlainSecretBlockStillFlagged(t *testing.T) {
	doc := "<!-- secret -->\nAKIAIOSFODNN7EXAMPLE\n<!-- /secret -->"
	if len(scan(doc)) == 0 {
		t.Error("unencrypted secret inside block should still be flagged")
	}
}
