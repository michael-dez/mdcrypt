# mdcrypt

**Inline partial encryption for markdown files** — SOPS for prose.

Sensitive values are wrapped in `<!-- secret -->` blocks. Running `mdcrypt encrypt` replaces the inner content with a single self-contained `ENC[...]` token. The rest of the document stays plain text, human-readable, and diff-friendly in Git.

```markdown
# My note

Some ordinary prose.

<!-- secret -->
sk-ant-api03-MYSUPERSECRETKEY
<!-- /secret -->

More ordinary prose.
```

After encrypting:

```markdown
# My note

Some ordinary prose.

<!-- secret -->
ENC[AGE,data:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB...]
<!-- /secret -->

More ordinary prose.
```

The `<!-- secret -->` / `<!-- /secret -->` tags are **invisible in rendered markdown**, so the file looks completely clean on GitHub.

---

## Security model

mdcrypt uses [age](https://age-encryption.org) for all encryption. Each `ENC[AGE,data:...]` token is a base64-wrapped age ciphertext — already a complete, self-contained format with its own header, nonce, and authentication tag.

| Property | Implementation |
|---|---|
| Primitives | X25519 + ChaCha20-Poly1305 (via age) |
| Key format | Standard age `AGE-SECRET-KEY-...` identities and `age1...` recipients |
| Multi-recipient | Encrypt once to several recipients; any matching identity decrypts |
| Passphrase mode | Optional scrypt-based fallback for users without a key file |
| Integrity | Poly1305 authentication tag — any tampering is detected at decrypt time |

No secret material is stored inside the encrypted file — the age recipients/identities live entirely outside the markdown.

---

## Installation

**From source** (requires Go 1.22+):

```bash
git clone https://github.com/michael-dez/mdcrypt
cd mdcrypt
go build -o mdcrypt ./cmd/mdcrypt
mv mdcrypt ~/bin/   # or anywhere on $PATH
```

**Pre-built binaries** are available on the [Releases](https://github.com/michael-dez/mdcrypt/releases) page for Linux, macOS, and Windows (amd64 and arm64).

---

## Key setup

mdcrypt does not generate keys itself — use the standard [`age-keygen`](https://age-encryption.org) tool:

```bash
mkdir -p ~/.config/mdcrypt
age-keygen -o ~/.config/mdcrypt/identity.txt

# extract the matching public key (recipient) into recipients.txt
grep '^# public key:' ~/.config/mdcrypt/identity.txt \
  | sed 's/^# public key: //' \
  > ~/.config/mdcrypt/recipients.txt
```

After this, `mdcrypt encrypt` and `mdcrypt view` work with no flags.

To encrypt for multiple recipients (e.g. yourself + a teammate), append their public keys to `recipients.txt` — one per line.

---

## Usage

### 1. Mark secrets in your note

```markdown
<!-- secret -->
ghp_myGitHubPersonalAccessToken
<!-- /secret -->
```

The block can contain multiple lines — the entire inner content is encrypted as one blob.

### 2. Encrypt

```bash
mdcrypt encrypt note.md
```

Replaces every unencrypted `<!-- secret -->` block in-place. Already-encrypted blocks are left untouched.

You can override the recipient(s) inline:

```bash
mdcrypt encrypt -r age1abc... -r age1def... note.md
```

### 3. View decrypted (safe — stdout only, never writes to disk)

```bash
mdcrypt view note.md
```

### 4. Decrypt in-place

Writes plaintext back to the file. Useful for editing. **Do not commit the result.**

```bash
mdcrypt decrypt --inplace note.md
```

### 5. Scan for unencrypted secrets

```bash
mdcrypt scan              # scans current directory recursively
mdcrypt scan ./notes      # scans a specific directory
mdcrypt scan note.md      # scans a single file
```

---

## Key resolution

**Recipients** (used by `encrypt`), in order of precedence:

1. `-r/--recipient age1...` flags (repeatable)
2. `$MDCRYPT_RECIPIENTS` — path to a recipients file
3. `~/.config/mdcrypt/recipients.txt`

**Identities** (used by `decrypt` and `view`):

1. `-i/--identity <path>` flags (repeatable)
2. `$MDCRYPT_IDENTITY` — path to an identity file
3. `~/.config/mdcrypt/identity.txt`

---

## Passphrase mode

If you'd rather memorize a passphrase than manage a key file, pass `--passphrase` on either side:

```bash
mdcrypt encrypt --passphrase note.md   # prompts twice (with confirmation)
mdcrypt view --passphrase note.md      # prompts once
```

This uses age's standard scrypt recipient/identity, so the resulting tokens are still in the `ENC[AGE,...]` format and remain decryptable with the `age` CLI.

---

## Git pre-commit hook

Install the hook to catch unencrypted secrets before they reach GitHub:

```bash
bash scripts/install-hooks.sh
```

The hook runs `mdcrypt scan` on every staged `.md` file and aborts the commit if a likely secret is found unencrypted (including inside a plaintext `<!-- secret -->` block).

---

## ENC token format

```
ENC[AGE,data:<base64>]
```

`data` is the standard [age binary ciphertext](https://age-encryption.org), base64-encoded. Because it's a real age payload, you can also decrypt it with the upstream `age` CLI after base64-decoding the `data:` field.

---

## Suggested workflow for a public GitHub notes repo

1. Write notes normally.
2. When you need to embed a secret, wrap it in `<!-- secret -->...<!-- /secret -->`.
3. Before committing: `mdcrypt encrypt note.md`.
4. The pre-commit hook catches anything you missed.
5. Push — the repo is safe to be public.
6. To read secrets locally: `mdcrypt view note.md | less`.
7. To edit: `mdcrypt decrypt --inplace note.md`, edit, then `mdcrypt encrypt note.md` again.

---

## Limitations

- mdcrypt does not manage your keys — use `age-keygen` and keep your identity file safe.
- The `scan` patterns are heuristic and won't catch every type of secret.
- `--inplace` decrypt writes plaintext to disk temporarily. Prefer `view` when you only need to read.

---

## License

MIT
