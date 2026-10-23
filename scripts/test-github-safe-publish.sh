#!/usr/bin/env bash
set -euo pipefail

# Exercise export/cache behavior without compiling code or contacting a remote.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/phora-export-cache-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT
TEST_ROOT="$(cd "$TEST_ROOT" && pwd -P)"
FAKE_ZIG="$TEST_ROOT/fake zig"
SHARED_CACHE="$TEST_ROOT/shared cache"
TEST_SOURCE="$TEST_ROOT/source tree"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

# Local export commits must not depend on the caller's signing configuration.
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL="$TEST_ROOT/gitconfig"
cat >"$GIT_CONFIG_GLOBAL" <<'EOF'
[user]
  name = Phora Export Test
  email = phora-export-test@example.invalid
[commit]
  gpgsign = false
[gc]
  auto = 0
EOF

# A small source fixture keeps these shell checks independent of Phora's size.
mkdir -p "$TEST_SOURCE/src"
printf '// Fake compiler fixture.\n' >"$TEST_SOURCE/src/main.zig"
for rel in \
  build.zig .gitignore .gitattributes LICENSE README.md SECURITY.md .mcp.example.json \
  benchmarks/cases.json scripts/bench-phora.py scripts/github-safe-audit.sh \
  scripts/github-safe-publish.sh scripts/test-github-safe-publish.sh
do
  mkdir -p "$TEST_SOURCE/$(dirname "$rel")"
  cp "$ROOT/$rel" "$TEST_SOURCE/$rel"
done
PUBLISH_SCRIPT="$TEST_SOURCE/scripts/github-safe-publish.sh"

cat >"$FAKE_ZIG" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = build ] && [ "$2" = test ]
shift 2
local_cache=""
prefix=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --cache-dir) local_cache="$2"; shift 2 ;;
    --prefix) prefix="$2"; shift 2 ;;
    *) printf 'unexpected argument: %s\n' "$1" >&2; exit 98 ;;
  esac
done
[ -d "$local_cache" ] && [ -d "$prefix" ]
[ -d "$ZIG_GLOBAL_CACHE_DIR" ]
warm=cold
[ ! -e "$ZIG_GLOBAL_CACHE_DIR/fake-zig-cache-marker" ] || warm=warm
touch "$ZIG_GLOBAL_CACHE_DIR/fake-zig-cache-marker"
printf '%s\n' "$ZIG_GLOBAL_CACHE_DIR" "$local_cache" "$prefix" "$warm" >"$PHORA_TEST_CALL_LOG"
exit "${PHORA_TEST_ZIG_EXIT:-0}"
EOF
chmod +x "$FAKE_ZIG"

assert_clean_run() {
  local name="$1"
  local expected_cache="$2"
  local expected_warm="$3"
  local call_log="$TEST_ROOT/$name.call"
  [ "$(sed -n '1p' "$call_log")" = "$expected_cache" ] || fail "$name: wrong global cache"
  [ "$(sed -n '4p' "$call_log")" = "$expected_warm" ] || fail "$name: cache reuse mismatch"
  [ ! -e "$(sed -n '2p' "$call_log")" ] || fail "$name: local cache survived"
  [ ! -e "$(sed -n '3p' "$call_log")" ] || fail "$name: install prefix survived"
  [ -f "$expected_cache/fake-zig-cache-marker" ] || fail "$name: global cache was removed"
  [ ! -e "$TEST_ROOT/$name export/.zig-cache" ] || fail "$name: local cache in export"
  [ ! -e "$TEST_ROOT/$name export/zig-out" ] || fail "$name: build output in export"
  [ -z "$(find "$TEST_ROOT/$name export" -name .git -prune -o -name fake-zig-cache-marker -print -quit)" ] || fail "$name: global cache in export"
}

run_success() {
  local name="$1"
  shift
  env ZIG="$FAKE_ZIG" PHORA_TEST_ZIG_EXIT=0 PHORA_TEST_CALL_LOG="$TEST_ROOT/$name.call" "$@" \
    "$PUBLISH_SCRIPT" --require-tests --export-dir "$TEST_ROOT/$name export" \
    >"$TEST_ROOT/$name.log" 2>&1 || { cat "$TEST_ROOT/$name.log" >&2; fail "$name: export failed"; }
  git -C "$TEST_ROOT/$name export" rev-parse --verify HEAD >/dev/null || fail "$name: no export commit"
  [ -z "$(git -C "$TEST_ROOT/$name export" remote)" ] || fail "$name: remote configured"
}

run_failure() {
  local name="$1"
  local expected_error="$2"
  shift 2
  if env PHORA_TEST_CALL_LOG="$TEST_ROOT/$name.call" "$@" \
    "$PUBLISH_SCRIPT" --require-tests --export-dir "$TEST_ROOT/$name export" \
    >"$TEST_ROOT/$name.log" 2>&1; then
    fail "$name: export unexpectedly succeeded"
  fi
  grep -F "$expected_error" "$TEST_ROOT/$name.log" >/dev/null || { cat "$TEST_ROOT/$name.log" >&2; fail "$name: wrong failure"; }
  if git -C "$TEST_ROOT/$name export" rev-parse --verify HEAD >/dev/null 2>&1; then
    fail "$name: failed tests produced an export commit"
  fi
}

run_success first PHORA_EXPORT_ZIG_CACHE_DIR="$SHARED_CACHE" ZIG_GLOBAL_CACHE_DIR="$TEST_ROOT/unused cache"
assert_clean_run first "$SHARED_CACHE" cold
run_success second PHORA_EXPORT_ZIG_CACHE_DIR="$SHARED_CACHE" ZIG_GLOBAL_CACHE_DIR="$TEST_ROOT/unused cache"
assert_clean_run second "$SHARED_CACHE" warm
[ "$(sed -n '2p' "$TEST_ROOT/first.call")" != "$(sed -n '2p' "$TEST_ROOT/second.call")" ] || fail 'local cache was reused'
[ ! -e "$TEST_ROOT/unused cache" ] || fail 'override precedence failed'

run_success inherited PHORA_EXPORT_ZIG_CACHE_DIR= ZIG_GLOBAL_CACHE_DIR="$SHARED_CACHE"
assert_clean_run inherited "$SHARED_CACHE" warm
run_success xdg PHORA_EXPORT_ZIG_CACHE_DIR= ZIG_GLOBAL_CACHE_DIR= XDG_CACHE_HOME="$TEST_ROOT/xdg cache"
assert_clean_run xdg "$TEST_ROOT/xdg cache/phora/zig-export" cold
(
  cd "$TEST_ROOT"
  run_success relative PHORA_EXPORT_ZIG_CACHE_DIR='relative cache' ZIG_GLOBAL_CACHE_DIR=
)
assert_clean_run relative "$TEST_ROOT/relative cache" cold

run_failure failed 'zig build test failed in the sanitized export' \
  ZIG="$FAKE_ZIG" PHORA_TEST_ZIG_EXIT=37 PHORA_EXPORT_ZIG_CACHE_DIR="$SHARED_CACHE"
assert_clean_run failed "$SHARED_CACHE" warm
run_failure missing 'Zig is unavailable:' ZIG="$TEST_ROOT/missing zig" PHORA_EXPORT_ZIG_CACHE_DIR="$TEST_ROOT/not created"
[ ! -e "$TEST_ROOT/missing.call" ] || fail 'missing compiler was invoked'
[ ! -e "$TEST_ROOT/not created" ] || fail 'missing compiler created a cache'
run_failure source-cache 'Zig global cache must be outside' ZIG="$FAKE_ZIG" PHORA_EXPORT_ZIG_CACHE_DIR="$TEST_SOURCE/.zig-cache/phora-export-regression"
[ ! -e "$TEST_ROOT/source-cache.call" ] || fail 'source-tree cache reached compiler'
run_failure export-cache 'Zig global cache must be outside' ZIG="$FAKE_ZIG" PHORA_EXPORT_ZIG_CACHE_DIR="$TEST_ROOT/export-cache export/global cache"
[ ! -e "$TEST_ROOT/export-cache.call" ] || fail 'export-tree cache reached compiler'

printf 'PASS: export cache reuse, overrides, spaces, strict failures, cleanup, and cache isolation (fake compiler only)\n'
