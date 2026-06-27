#!/usr/bin/env bash
set -euo pipefail

REPO="https://raw.githubusercontent.com/TidyMaze/membridge/main/cli/memb.sh"
INSTALL_DIR="$HOME/.local/bin"
BIN="$INSTALL_DIR/memb"

echo "Installing memb..."

# Check age
if ! command -v age >/dev/null 2>&1; then
  echo ""
  echo "  age is required but not installed."
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "  Install with: brew install age"
  else
    echo "  Install with: apt install age  (or your distro's package manager)"
  fi
  echo ""
  exit 1
fi

mkdir -p "$INSTALL_DIR"
curl -fsSL "$REPO" -o "$BIN"
chmod +x "$BIN"

echo "Installed to $BIN"

# PATH check
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
  echo ""
  echo "  Add to your shell config (~/.zshrc or ~/.bashrc):"
  echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
  echo ""
fi

echo "Done. Run: memb login"
