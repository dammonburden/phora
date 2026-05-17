#!/usr/bin/env bash
set -euo pipefail

MAX_FILE_SIZE=$((2 * 1024 * 1024))
ROOT="${1:-.}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

file_size() {
  if stat -f '%z' "$1" >/dev/null 2>&1; then
    stat -f '%z' "$1"
  else
    stat -c '%s' "$1"
  fi
}

candidate_files() {
  if [ -d "$ROOT/.git" ]; then
    git -C "$ROOT" ls-files --cached --others --exclude-standard -z
  else
    (cd "$ROOT" && find . -type f -not -path './.git/*' -print0)
  fi
}

is_blocked_path() {
  local rel="$1"
  local base="${rel##*/}"

  case "$rel" in
    .git|.git/*|*/.git|*/.git/*) return 0 ;;
    .zig-cache|.zig-cache/*|*/.zig-cache|*/.zig-cache/*) return 0 ;;
    zig-out|zig-out/*|*/zig-out|*/zig-out/*) return 0 ;;
    .local-state|.local-state/*|*/.local-state|*/.local-state/*) return 0 ;;
    analysis-output|analysis-output/*|*/analysis-output|*/analysis-output/*) return 0 ;;
    local-notes|local-notes/*|*/local-notes|*/local-notes/*) return 0 ;;
    benchmarks/results|benchmarks/results/*|*/benchmarks/results|*/benchmarks/results/*) return 0 ;;
    benchmark-results|benchmark-results/*|*/benchmark-results|*/benchmark-results/*) return 0 ;;
    __pycache__|__pycache__/*|*/__pycache__|*/__pycache__/*) return 0 ;;
  esac

  case "$base" in
    .DS_Store|.mcp.json) return 0 ;;
    scratch-*|test-output-*) return 0 ;;
    *.macho|*.o|*.pyc|*.sqlite|*.sqlite-shm|*.sqlite-wal|*.swp|*.swo|*.tmp) return 0 ;;
  esac

  return 1
}

is_secret_filename() {
  local lower
  lower="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"

  case "$lower" in
    .env|.env.*|*/.env|*/.env.*) return 0 ;;
    *secret*|*token*|*password*|*credential*|*api_key*|*apikey*) return 0 ;;
    *private_key*|*private-key*|*.pem|*.key|*.p12|*.pfx) return 0 ;;
    id_rsa|*/id_rsa|id_ed25519|*/id_ed25519|*.mobileprovision) return 0 ;;
  esac

  return 1
}

has_nul_byte() {
  perl -e 'local $/; my $s = <>; exit(index($s, "\0") >= 0 ? 0 : 1)' "$1"
}

[ -d "$ROOT" ] || die "audit target does not exist or is not a directory: $ROOT"
ROOT="$(cd "$ROOT" && pwd -P)"

failed=0
count=0

while IFS= read -r -d '' rel; do
  rel="${rel#./}"
  [ -n "$rel" ] || continue

  path="$ROOT/$rel"
  [ -f "$path" ] || continue
  count=$((count + 1))

  if is_blocked_path "$rel"; then
    printf 'ERROR: blocked publish path: %s\n' "$rel" >&2
    failed=1
  fi

  if is_secret_filename "$rel"; then
    printf 'ERROR: secret-like filename is not publishable: %s\n' "$rel" >&2
    failed=1
  fi

  size="$(file_size "$path")"
  if [ "$size" -gt "$MAX_FILE_SIZE" ]; then
    printf 'ERROR: file exceeds 2 MiB limit: %s (%s bytes)\n' "$rel" "$size" >&2
    failed=1
  fi

  if has_nul_byte "$path"; then
    printf 'ERROR: binary content detected in publish candidate: %s\n' "$rel" >&2
    failed=1
  fi
done < <(candidate_files)

if [ "$count" -eq 0 ]; then
  die "audit target has no publish candidate files: $ROOT"
fi

if [ "$failed" -ne 0 ]; then
  die "safe publish audit failed for $ROOT"
fi

printf 'Audit passed: %s (%d candidate files)\n' "$ROOT" "$count"
