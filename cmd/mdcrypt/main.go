// Command mdcrypt provides inline partial encryption for markdown files.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/michael-dez/mdcrypt/internal/crypto"
	"github.com/michael-dez/mdcrypt/internal/parser"
	"github.com/michael-dez/mdcrypt/internal/scanner"
)

// ── Key resolution ────────────────────────────────────────────────────────────
//
// Recipients (encrypt-side):
//   1. -r/--recipient flags (repeatable, raw "age1..." strings)
//   2. $MDCRYPT_RECIPIENTS (path to a recipients file)
//   3. ~/.config/mdcrypt/recipients.txt
//
// Identities (decrypt-side):
//   1. -i/--identity flags (repeatable, paths to identity files)
//   2. $MDCRYPT_IDENTITY (path to an identity file)
//   3. ~/.config/mdcrypt/identity.txt
//
// --passphrase swaps both sides to age scrypt mode and ignores the above.

const (
	defaultRecipientsFile = "recipients.txt"
	defaultIdentityFile   = "identity.txt"
)

func defaultConfigPath(name string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "mdcrypt", name), nil
}

func resolveRecipients(flagRecipients []string) ([]age.Recipient, error) {
	if len(flagRecipients) > 0 {
		out := make([]age.Recipient, 0, len(flagRecipients))
		for _, s := range flagRecipients {
			r, err := crypto.ParseRecipient(s)
			if err != nil {
				return nil, fmt.Errorf("recipient %q: %w", s, err)
			}
			out = append(out, r)
		}
		return out, nil
	}

	if path := os.Getenv("MDCRYPT_RECIPIENTS"); path != "" {
		return crypto.LoadRecipients(path)
	}

	path, err := defaultConfigPath(defaultRecipientsFile)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no recipients given: pass --recipient, set $MDCRYPT_RECIPIENTS, or create %s", path)
	}
	return crypto.LoadRecipients(path)
}

func resolveIdentities(flagIdentities []string) ([]age.Identity, error) {
	paths := flagIdentities
	if len(paths) == 0 {
		if p := os.Getenv("MDCRYPT_IDENTITY"); p != "" {
			paths = []string{p}
		} else {
			p, err := defaultConfigPath(defaultIdentityFile)
			if err != nil {
				return nil, err
			}
			if _, err := os.Stat(p); err != nil {
				return nil, fmt.Errorf("no identity given: pass --identity, set $MDCRYPT_IDENTITY, or create %s", p)
			}
			paths = []string{p}
		}
	}

	var all []age.Identity
	for _, p := range paths {
		ids, err := crypto.LoadIdentities(p)
		if err != nil {
			return nil, err
		}
		all = append(all, ids...)
	}
	return all, nil
}

// promptPassphrase reads a passphrase from the TTY, optionally with confirmation.
func promptPassphrase(confirm bool) (string, error) {
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

	if len(pp) == 0 {
		return "", errors.New("empty passphrase")
	}
	return string(pp), nil
}

// ── encrypt command ───────────────────────────────────────────────────────────

func newEncryptCmd() *cobra.Command {
	var (
		recipients   []string
		usePassphrase bool
	)

	cmd := &cobra.Command{
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

			var recips []age.Recipient
			if usePassphrase {
				pp, err := promptPassphrase(true)
				if err != nil {
					return err
				}
				r, err := crypto.PassphraseRecipient(pp)
				if err != nil {
					return err
				}
				recips = []age.Recipient{r}
			} else {
				recips, err = resolveRecipients(recipients)
				if err != nil {
					return err
				}
			}

			encryptFn := func(plaintext string) (string, error) {
				return crypto.Encrypt(plaintext, recips)
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

	cmd.Flags().StringSliceVarP(&recipients, "recipient", "r", nil,
		"age recipient (e.g. age1...); repeatable for multiple recipients")
	cmd.Flags().BoolVar(&usePassphrase, "passphrase", false,
		"Encrypt with a passphrase (age scrypt) instead of recipient keys")
	return cmd
}

// ── decrypt command ───────────────────────────────────────────────────────────

func newDecryptCmd() *cobra.Command {
	var (
		identities    []string
		inplace       bool
		usePassphrase bool
	)

	cmd := &cobra.Command{
		Use:   "decrypt <file.md>",
		Short: "Decrypt ENC blocks (stdout by default)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDecrypt(args[0], inplace, identities, usePassphrase)
		},
	}

	cmd.Flags().StringSliceVarP(&identities, "identity", "i", nil,
		"Path to an age identity file; repeatable")
	cmd.Flags().BoolVar(&usePassphrase, "passphrase", false,
		"Decrypt with a passphrase (age scrypt) instead of an identity file")
	cmd.Flags().BoolVar(&inplace, "inplace", false,
		"Write plaintext back to file (never commit the result!)")
	return cmd
}

// ── view command ──────────────────────────────────────────────────────────────

func newViewCmd() *cobra.Command {
	var (
		identities    []string
		usePassphrase bool
	)

	cmd := &cobra.Command{
		Use:   "view <file.md>",
		Short: "Decrypt to stdout only (safe — never writes to disk)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDecrypt(args[0], false, identities, usePassphrase)
		},
	}

	cmd.Flags().StringSliceVarP(&identities, "identity", "i", nil,
		"Path to an age identity file; repeatable")
	cmd.Flags().BoolVar(&usePassphrase, "passphrase", false,
		"Decrypt with a passphrase (age scrypt) instead of an identity file")
	return cmd
}

func runDecrypt(filePath string, inplace bool, identityFlags []string, usePassphrase bool) error {
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

	var ids []age.Identity
	if usePassphrase {
		pp, err := promptPassphrase(false)
		if err != nil {
			return err
		}
		id, err := crypto.PassphraseIdentity(pp)
		if err != nil {
			return err
		}
		ids = []age.Identity{id}
	} else {
		ids, err = resolveIdentities(identityFlags)
		if err != nil {
			return err
		}
	}

	decryptFn := func(token string) (string, error) {
		return crypto.Decrypt(token, ids)
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
replace the content with a self-contained age token. The rest of the
document stays plain text.

Keys are managed using the age (https://age-encryption.org) format.
Generate one with: age-keygen -o ~/.config/mdcrypt/identity.txt
and place the matching recipient line in ~/.config/mdcrypt/recipients.txt.`,
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
