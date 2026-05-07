// Package scanner provides heuristic detection of unencrypted secrets in
// markdown files. Used by the scan command and the pre-commit hook.
package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/michael-dez/mdcrypt/internal/crypto"
	"github.com/michael-dez/mdcrypt/internal/parser"
)

// pattern pairs a human-readable label with a detection regex.
type pattern struct {
	label string
	re    *regexp.Regexp
}

// secretPatterns are ordered roughly by specificity.
var secretPatterns = []pattern{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"GitHub PAT", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{"GitHub fine-grained PAT", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{80,}`)},
	{"OpenAI/Anthropic key", regexp.MustCompile(`sk-[A-Za-z0-9-]{20,}`)},
	{"PEM private key", regexp.MustCompile(`-----BEGIN .{1,30}PRIVATE KEY-----`)},
	{"Generic API key", regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*['"]?\S{8,}`)},
	{"Generic token", regexp.MustCompile(`(?i)\btoken\s*[:=]\s*['"]?\S{8,}`)},
	{"Bare password", regexp.MustCompile(`(?i)\bpassword\s*[:=]\s*['"]?\S{6,}`)},
	{"Bearer token", regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+\S+`)},
	{"Long base64 blob", regexp.MustCompile(`(?:^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?:[^A-Za-z0-9+/=]|$)`)},
}

// Finding represents a single detection result.
type Finding struct {
	File    string
	Line    int
	Label   string
	Snippet string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: [%s] %s", f.File, f.Line, f.Label, f.Snippet)
}

// ScanText scans text for likely unencrypted secrets.
// Lines inside already-encrypted secret blocks are skipped.
func ScanText(text, filePath string) []Finding {
	// Find line ranges that are inside encrypted blocks so we can skip them.
	encryptedLines := encryptedBlockLines(text)

	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip lines inside an encrypted block.
		if encryptedLines[lineNum] {
			continue
		}

		// Skip lines that are purely an ENC token.
		if crypto.TokenPattern.MatchString(line) {
			continue
		}

		for _, p := range secretPatterns {
			if p.re.MatchString(line) {
				snippet := line
				if len(snippet) > 100 {
					snippet = snippet[:100]
				}
				findings = append(findings, Finding{
					File:    filePath,
					Line:    lineNum,
					Label:   p.label,
					Snippet: strings.TrimSpace(snippet),
				})
				break // one finding per line
			}
		}
	}

	return findings
}

// ScanFile scans a single markdown file.
func ScanFile(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return ScanText(string(data), path), nil
}

// ScanDir recursively scans all .md files under root.
func ScanDir(root string) ([]Finding, []error) {
	var (
		findings []Finding
		errs     []error
	)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			ff, err := ScanFile(path)
			if err != nil {
				errs = append(errs, err)
			} else {
				findings = append(findings, ff...)
			}
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}

	return findings, errs
}

// encryptedBlockLines returns a set of 1-indexed line numbers that fall inside
// an already-encrypted <!-- secret --> block.
func encryptedBlockLines(text string) map[int]bool {
	result := map[int]bool{}
	blocks := parser.FindBlocks(text)

	lines := strings.Split(text, "\n")
	for _, b := range blocks {
		if !b.IsEncrypted {
			continue
		}
		// Find the line range of this block's full match.
		start, end := blockLineRange(text, lines, b.FullMatch)
		for l := start; l <= end; l++ {
			result[l] = true
		}
	}
	return result
}

// blockLineRange finds the 1-indexed start and end lines of needle in text.
func blockLineRange(text string, lines []string, needle string) (int, int) {
	idx := strings.Index(text, needle)
	if idx < 0 {
		return 0, 0
	}
	before := text[:idx]
	start := strings.Count(before, "\n") + 1
	end := start + strings.Count(needle, "\n")
	return start, end
}
