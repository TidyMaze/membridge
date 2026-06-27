#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="$HOME/.memory"
CONFIG_FILE="$CONFIG_DIR/config"
LOCAL_FILE="$CONFIG_DIR/context.md"
AGE_KEY_FILE="$CONFIG_DIR/key.txt"
SILENT=0

# Parse --silent flag before the subcommand
for arg in "$@"; do
  [ "$arg" = "--silent" ] && SILENT=1
done

mkdir -p "$CONFIG_DIR"

load_config() {
  [ -f "$CONFIG_FILE" ] || { echo "Not configured. Run: memory configure <api_key>" >&2; exit 1; }
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
}

require_deps() {
  command -v curl >/dev/null || { echo "curl required" >&2; exit 1; }
  command -v age >/dev/null || { echo "age required (brew install age / apt install age)" >&2; exit 1; }
}

cmd_configure() {
  local key="$1"
  : "${MEMORY_ENDPOINT:=https://yourdomain.com}"
  cat > "$CONFIG_FILE" <<EOF
MEMORY_KEY=$key
MEMORY_ENDPOINT=${MEMORY_ENDPOINT}
MEMORY_AGE_KEY=$AGE_KEY_FILE
EOF
  if [ ! -f "$AGE_KEY_FILE" ]; then
    age-keygen -o "$AGE_KEY_FILE"
    chmod 600 "$AGE_KEY_FILE"
  fi
  echo "Configured. Identity: $AGE_KEY_FILE"
}

cmd_login() {
  load_config
  echo "Opening browser to ${MEMORY_ENDPOINT}/auth/github ..."
  if command -v open >/dev/null; then open "${MEMORY_ENDPOINT}/auth/github"
  elif command -v xdg-open >/dev/null; then xdg-open "${MEMORY_ENDPOINT}/auth/github"
  else echo "Visit: ${MEMORY_ENDPOINT}/auth/github"
  fi
}

cmd_push() {
  load_config
  require_deps
  [ -f "$LOCAL_FILE" ] || { echo "No local context at $LOCAL_FILE" >&2; exit 1; }
  local pubkey
  pubkey=$(age-keygen -y "$MEMORY_AGE_KEY")
  age -r "$pubkey" "$LOCAL_FILE" | curl -sf -X POST \
    -H "Authorization: Bearer $MEMORY_KEY" \
    --data-binary @- "$MEMORY_ENDPOINT/api/context" > /dev/null
  if [ "$SILENT" -eq 0 ]; then echo "Pushed."; fi
}

cmd_pull() {
  load_config
  require_deps
  local tmp
  tmp=$(mktemp /tmp/membridge.XXXXXX)
  curl -sf -H "Authorization: Bearer $MEMORY_KEY" "$MEMORY_ENDPOINT/api/context" -o "$tmp"
  age -d -i "$MEMORY_AGE_KEY" "$tmp" > "$LOCAL_FILE"
  rm -f "$tmp"
  echo "Pulled to $LOCAL_FILE"
}

cmd_edit() {
  load_config
  : "${EDITOR:=vi}"
  [ -f "$LOCAL_FILE" ] || printf '## Rules\n\n## Decisions\n\n## Notes\n' > "$LOCAL_FILE"
  "$EDITOR" "$LOCAL_FILE"
  cmd_push
}

cmd_status() {
  load_config
  if [ -f "$LOCAL_FILE" ]; then
    echo "Local last modified: $(date -r "$(stat -f %m "$LOCAL_FILE" 2>/dev/null || stat -c %Y "$LOCAL_FILE")")"
  else
    echo "No local file."
  fi
  curl -sf -H "Authorization: Bearer $MEMORY_KEY" "$MEMORY_ENDPOINT/api/context" -o /dev/null -D - 2>/dev/null \
    | grep -i '^date:' || echo "Remote: not reachable or not found"
}

case "${1:-}" in
  configure) cmd_configure "${2:?usage: memory configure <api_key>}" ;;
  login)     cmd_login ;;
  push)      cmd_push ;;
  pull)      cmd_pull ;;
  edit)      cmd_edit ;;
  status)    cmd_status ;;
  --silent)  ;; # consumed above
  *)
    echo "Usage: memory {configure <key>|login|push|pull|edit|status}" >&2
    exit 1
    ;;
esac
