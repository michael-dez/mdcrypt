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
ENC[AES256_GCM,data:a1b2c3...,iv:d4e5f6...,tag:g7h8i9...,aad:L2hvbWU...]
<!-- /secret -->

More ordinary prose.
```

The `<!-- secret -->` / `<!-- /secret -->` tags are **invisible in rendered markdown**, so the file looks completely clean on GitHub.

---

## Security model

| Property | Implementation |
|---|---|
| Encryption | AES-256-GCM (authenticated encryption) |
| Key derivation | Argon2id — memory-hard, GPU-resistant |
| Salt | 16 random bytes per token, embedded in the token itself |
| Nonce | 12 random bytes per encryption call |
| File binding | AAD = resolved absolute file path; a token cannot be copy-pasted into another file and decrypted |
| Integrity | GCM authentication tag — any tampering is detected at decrypt time |

The passphrase never touches disk. It is read from `$MDCRYPT_KEY` or via a secure terminal prompt.

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

## Usage

### 1. Mark secrets in your note

Wrap any sensitive value in a secret block:

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

Prompts for a passphrase (with confirmation), then replaces every unencrypted `<!-- secret -->` block in-place. Already-encrypted blocks are left untouched.

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

## Environment variable

Set `MDCRYPT_KEY` to skip interactive prompts (e.g. in scripts or CI):

```bash
export MDCRYPT_KEY="my-passphrase"
mdcrypt view note.md
```

To set it without leaving a trace in shell history:

```bash
read -rs MDCRYPT_KEY && export MDCRYPT_KEY
```

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
ENC[AES256_GCM,data:<base64>,iv:<base64>,tag:<base64>,aad:<base64>]
```

| Field  | Contents |
|--------|----------|
| `data` | 16-byte Argon2id salt ‖ AES-GCM ciphertext, base64-encoded |
| `iv`   | 12-byte random nonce |
| `tag`  | 16-byte GCM authentication tag |
| `aad`  | base64-encoded resolved file path (additional authenticated data) |

Each token is fully self-contained — no sidecar files, no key registry.

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

- mdcrypt does not manage your passphrase — use your OS keychain or a password manager.
- The `scan` patterns are heuristic and won't catch every type of secret.
- `--inplace` decrypt writes plaintext to disk temporarily. Prefer `view` when you only need to read.
- AAD binding means if you **rename or move** a file, existing tokens can no longer be decrypted. Decrypt before moving, then re-encrypt after.

---

## License

MIT
