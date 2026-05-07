// Command mdcrypt provides inline partial encryption for markdown files.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/michael-dez/mdcrypt/internal/crypto"
	"github.com/michael-dez/mdcrypt/internal/parser"
	"github.com/michael-dez/mdcrypt/internal/scanner"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ── Passphrase ────────────────────────────────────────────────────────────────

func getPassphrase(confirm bool) (string, error) {
	if pp := os.Getenv("MDCRYPT_KEY"); pp != "" {
		return pp, nil
	}

	fmt.Fprint(os.Stderr, "Passphrase: ")
	pp, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}

	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		pp2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("reading passphrase confirmation: %w", err)
		}
		if string(pp) != string(pp2) {
			return "", errors.New("passphrases do not match")
		}
	}

	return string(pp), nil
}

// ── encrypt command ───────────────────────────────────────────────────────────

func newEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt <file.md>",
		Short: "Encrypt all plaintext <!-- secret --> blocks in a file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}
			text := string(data)

			blocks := parser.FindBlocks(text)
			var plainBlocks []parser.Block
			for _, b := range blocks {
				if !b.IsEncrypted {
					plainBlocks = append(plainBlocks, b)
				}
			}

			if len(plainBlocks) == 0 {
				encCount := 0
				for _, b := range blocks {
					if b.IsEncrypted {
						encCount++
					}
				}
				if encCount > 0 {
					fmt.Fprintf(os.Stderr, "All %d secret block(s) are already encrypted.\n", encCount)
				} else {
					fmt.Fprintln(os.Stderr, "No <!-- secret --> blocks found.")
				}
				return nil
			}

			fmt.Fprintf(os.Stderr, "Found %d unencrypted block(s). Enter passphrase to encrypt.\n", len(plainBlocks))
			passphrase, err := getPassphrase(true)
			if err != nil {
				return err
			}

			aad := crypto.FileAAD(path)
			encryptFn := func(plaintext string) (string, error) {
				return crypto.Encrypt(plaintext, passphrase, aad)
			}

			result, err := parser.EncryptBlocks(text, encryptFn)
			if err != nil {
				return err
			}

			if err := os.WriteFile(path, []byte(result.Text), 0644); err != nil {
				return fmt.Errorf("writing file: %w", err)
			}

			fmt.Fprintf(os.Stderr, "✓ Encrypted %d block(s) in %s\n", result.Count, args[0])
			return nil
		},
	}
}

// ── decrypt command ───────────────────────────────────────────────────────────

func newDecryptCmd() *cobra.Command {
	var inplace bool

	cmd := &cobra.Command{
		Use:   "decrypt <file.md>",
		Short: "Decrypt ENC blocks (stdout by default)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDecrypt(args[0], inplace)
		},
	}

	cmd.Flags().BoolVar(&inplace, "inplace", false,
		"Write plaintext back to file (never commit the result!)")
	return cmd
}

// ── view command ──────────────────────────────────────────────────────────────

func newViewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "view <file.md>",
		Short: "Decrypt to stdout only (safe — never writes to disk)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDecrypt(args[0], false)
		},
	}
}

func runDecrypt(filePath string, inplace bool) error {
	path, err := filepath.Abs(filePath)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}
	text := string(data)

	blocks := parser.FindBlocks(text)
	var encBlocks []parser.Block
	for _, b := range blocks {
		if b.IsEncrypted {
			encBlocks = append(encBlocks, b)
		}
	}

	if len(encBlocks) == 0 {
		if len(blocks) > 0 {
			fmt.Fprintln(os.Stderr, "Secret block(s) found but none are encrypted yet.")
		} else {
			fmt.Fprintln(os.Stderr, "No <!-- secret --> blocks found.")
		}
		return nil
	}

	passphrase, err := getPassphrase(false)
	if err != nil {
		return err
	}

	decryptFn := func(token string) (string, error) {
		return crypto.Decrypt(token, passphrase)
	}

	result := parser.DecryptBlocks(text, decryptFn)

	if inplace {
		if err := os.WriteFile(path, []byte(result.Text), 0644); err != nil {
			return fmt.Errorf("writing file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "✓ Decrypted %d block(s) in-place: %s\n", result.Count, filePath)
	} else {
		fmt.Print(result.Text)
	}

	if len(result.Errors) > 0 {
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "error: %v\n", e)
		}
		return fmt.Errorf("%d block(s) failed to decrypt", len(result.Errors))
	}
	return nil
}

// ── scan command ──────────────────────────────────────────────────────────────

func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan [path]",
		Short: "Heuristic scan for unencrypted secrets",
		Long: `Scan markdown files for patterns that look like unencrypted secrets.
Lines inside already-encrypted <!-- secret --> blocks are skipped.
Exits with code 1 if any findings are reported.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) == 1 {
				target = args[0]
			}

			info, err := os.Stat(target)
			if err != nil {
				return fmt.Errorf("path not found: %s", target)
			}

			var (
				findings []scanner.Finding
				scanErrs []error
			)

			if info.IsDir() {
				findings, scanErrs = scanner.ScanDir(target)
			} else {
				findings, err = scanner.ScanFile(target)
				if err != nil {
					scanErrs = append(scanErrs, err)
				}
			}

			for _, e := range scanErrs {
				fmt.Fprintf(os.Stderr, "warning: %v\n", e)
			}

			if len(findings) == 0 {
				fmt.Println("✓ No obvious unencrypted secrets found.")
				return nil
			}

			for _, f := range findings {
				fmt.Println(f)
			}
			fmt.Fprintf(os.Stderr,
				"\n%d potential secret(s) found. Wrap them in <!-- secret -->...<!-- /secret --> and run `mdcrypt encrypt`.\n",
				len(findings),
			)
			os.Exit(1)
			return nil
		},
	}
}

// ── root ──────────────────────────────────────────────────────────────────────

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "mdcrypt",
		Short: "Inline partial encryption for markdown files",
		Long: `mdcrypt — SOPS for prose.

Wrap secrets in <!-- secret --> blocks, then run 'mdcrypt encrypt' to
replace the content with a self-contained AES-256-GCM token. The rest
of the document stays plain text.`,
	}

	root.AddCommand(
		newEncryptCmd(),
		newDecryptCmd(),
		newViewCmd(),
		newScanCmd(),
	)

	return root
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
