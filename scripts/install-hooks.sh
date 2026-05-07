#!/usr/bin/env bash
# scripts/install-hooks.sh
# Run once from your notes repo root after installing mdcrypt.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/pre-commit"
DST="$REPO_ROOT/.git/hooks/pre-commit"

if [[ ! -f "$SRC" ]]; then
    echo "Error: hook source not found at $SRC" >&2
    exit 1
fi

if [[ -f "$DST" ]]; then
    echo "Existing hook found at $DST — backing up to $DST.bak"
    cp "$DST" "$DST.bak"
fi

cp "$SRC" "$DST"
chmod +x "$DST"
echo "✓ Installed pre-commit hook at $DST"
