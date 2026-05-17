#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

EXPORT_DIR=""
REMOTE=""
BRANCH="main"
PUSH=0
CONFIRM_PRIVATE=0
CONFIRM_PUBLIC=0
BUILD_TMP=""
ZIG_TEST_FAILED=0

usage() {
  cat <<'EOF'
Usage: scripts/github-safe-publish.sh [options]

Options:
  --export-dir PATH          Create the sanitized Git repo at PATH.
  --remote URL               Use this Git remote as origin when pushing.
  --branch NAME              Initial branch name. Default: main.
  --push                     Push to origin after all checks pass.
  --confirm-private-repo     Required with --push to a private repo.
  --confirm-public-repo      Required with --push to a public repo.
  -h, --help                 Show this help.

Default mode creates a sanitized source-only export and does not push.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

note() {
  printf '%s\n' "$*"
}

is_inside_source_tree() {
  local path="$1"

  case "$path" in
    "$ROOT"|"$ROOT"/*) return 0 ;;
  esac

  return 1
}

resolve_existing_parent() {
  local target="$1"
  local dir
  local next

  dir="$(dirname "$target")"
  while [ ! -e "$dir" ]; do
    next="$(dirname "$dir")"
    [ "$next" != "$dir" ] || die "cannot resolve export parent: $target"
    dir="$next"
  done

  [ -d "$dir" ] || die "nearest existing export parent is not a directory: $dir"
  (cd "$dir" && pwd -P)
}

cleanup() {
  if [ -n "$BUILD_TMP" ] && [ -d "$BUILD_TMP" ]; then
    rm -rf "$BUILD_TMP"
  fi
}
trap cleanup EXIT

while [ "$#" -gt 0 ]; do
  case "$1" in
    --export-dir)
      [ "$#" -ge 2 ] || die "--export-dir requires a path"
      EXPORT_DIR="$2"
      shift 2
      ;;
    --remote)
      [ "$#" -ge 2 ] || die "--remote requires a URL"
      REMOTE="$2"
      shift 2
      ;;
    --branch)
      [ "$#" -ge 2 ] || die "--branch requires a branch name"
      BRANCH="$2"
      shift 2
      ;;
    --push)
      PUSH=1
      shift
      ;;
    --confirm-private-repo)
      CONFIRM_PRIVATE=1
      shift
      ;;
    --confirm-public-repo)
      CONFIRM_PUBLIC=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[ -n "$BRANCH" ] || die "--branch cannot be empty"

if [ "$PUSH" -eq 1 ]; then
  [ -n "$REMOTE" ] || die "--push requires --remote"
  if [ "$CONFIRM_PRIVATE" -eq 1 ] && [ "$CONFIRM_PUBLIC" -eq 1 ]; then
    die "--push requires exactly one visibility confirmation flag"
  fi
  if [ "$CONFIRM_PRIVATE" -ne 1 ] && [ "$CONFIRM_PUBLIC" -ne 1 ]; then
    die "--push requires --confirm-private-repo or --confirm-public-repo"
  fi
fi

[ -x "$SCRIPT_DIR/github-safe-audit.sh" ] || die "missing executable audit script: $SCRIPT_DIR/github-safe-audit.sh"
[ -f "$ROOT/build.zig" ] || die "must be run from the Phora source tree"

if [ -z "$EXPORT_DIR" ]; then
  EXPORT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/phora-github-export.XXXXXX")"
else
  resolved_export_parent="$(resolve_existing_parent "$EXPORT_DIR")"
  if is_inside_source_tree "$resolved_export_parent"; then
    die "--export-dir must be outside the Phora source tree: $EXPORT_DIR"
  fi

  if [ -e "$EXPORT_DIR" ]; then
    [ -d "$EXPORT_DIR" ] || die "export path exists and is not a directory: $EXPORT_DIR"
    resolved_export_dir="$(cd "$EXPORT_DIR" && pwd -P)"
    if is_inside_source_tree "$resolved_export_dir"; then
      die "--export-dir must be outside the Phora source tree: $EXPORT_DIR"
    fi
    if [ -n "$(find "$EXPORT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
      die "export directory must be empty: $EXPORT_DIR"
    fi
  else
    mkdir -p "$EXPORT_DIR"
  fi
fi
EXPORT_DIR="$(cd "$EXPORT_DIR" && pwd -P)"
if is_inside_source_tree "$EXPORT_DIR"; then
  die "--export-dir must be outside the Phora source tree: $EXPORT_DIR"
fi

copy_file() {
  local rel="$1"
  local src="$ROOT/$rel"
  local dst="$EXPORT_DIR/$rel"

  [ -f "$src" ] || die "allowlisted file is missing: $rel"
  mkdir -p "$(dirname "$dst")"
  cp "$src" "$dst"
}

note "Creating sanitized source export at: $EXPORT_DIR"

while IFS= read -r -d '' src_file; do
  rel="${src_file#"$ROOT"/}"
  copy_file "$rel"
done < <(find "$ROOT/src" -type f -name '*.zig' -print0)

for rel in \
  build.zig \
  .gitignore \
  .gitattributes \
  LICENSE \
  README.md \
  SECURITY.md \
  .mcp.example.json \
  benchmarks/cases.json \
  scripts/bench-phora.py \
  scripts/github-safe-audit.sh \
  scripts/github-safe-publish.sh
do
  copy_file "$rel"
done

chmod +x "$EXPORT_DIR/scripts/bench-phora.py" "$EXPORT_DIR/scripts/github-safe-audit.sh" "$EXPORT_DIR/scripts/github-safe-publish.sh"

"$SCRIPT_DIR/github-safe-audit.sh" "$EXPORT_DIR"

git -C "$EXPORT_DIR" init -b "$BRANCH" >/dev/null

if ! git -C "$EXPORT_DIR" config user.name >/dev/null; then
  git -C "$EXPORT_DIR" config user.name "Phora Safe Publish"
fi
if ! git -C "$EXPORT_DIR" config user.email >/dev/null; then
  git -C "$EXPORT_DIR" config user.email "phora-safe-publish@example.invalid"
fi

if command -v zig >/dev/null 2>&1; then
  note "Running zig build test in sanitized export..."
  BUILD_TMP="$(mktemp -d "${TMPDIR:-/tmp}/phora-zig-build.XXXXXX")"
  mkdir -p "$BUILD_TMP/cache" "$BUILD_TMP/global-cache" "$BUILD_TMP/prefix"
  set +e
  (
    cd "$EXPORT_DIR"
    zig build test \
      --cache-dir "$BUILD_TMP/cache" \
      --global-cache-dir "$BUILD_TMP/global-cache" \
      --prefix "$BUILD_TMP/prefix"
  )
  zig_status=$?
  set -e
  if [ "$zig_status" -ne 0 ]; then
    ZIG_TEST_FAILED=1
    note "zig build test failed in the sanitized export; dry-run export will still be created, but push is blocked."
  fi
else
  note "Skipping zig build test: zig is not available on PATH."
fi

"$EXPORT_DIR/scripts/github-safe-audit.sh" "$EXPORT_DIR"

git -C "$EXPORT_DIR" add -A
"$EXPORT_DIR/scripts/github-safe-audit.sh" "$EXPORT_DIR"
git -C "$EXPORT_DIR" commit -m "Initial Phora source export" >/dev/null

note ""
note "Publish candidate files:"
git -C "$EXPORT_DIR" ls-files

note ""
note "Export directory:"
note "$EXPORT_DIR"
du -sh "$EXPORT_DIR"

if [ "$PUSH" -eq 1 ]; then
  if [ "$ZIG_TEST_FAILED" -ne 0 ]; then
    die "not pushing because zig build test failed in the sanitized export"
  fi
  "$EXPORT_DIR/scripts/github-safe-audit.sh" "$EXPORT_DIR"
  git -C "$EXPORT_DIR" remote add origin "$REMOTE"
  if [ "$CONFIRM_PUBLIC" -eq 1 ]; then
    note "Pushing branch '$BRANCH' to public remote..."
  else
    note "Pushing branch '$BRANCH' to private remote..."
  fi
  git -C "$EXPORT_DIR" push -u origin "$BRANCH"
else
  if [ -n "$REMOTE" ]; then
    note ""
    note "Remote was provided but not added because --push was not provided."
  fi
  note ""
  note "No push performed. To push later, rerun with --remote URL --push and one visibility confirmation flag."
fi
