#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/check-bun-locks.sh"

assert_file_contains() {
  local file="$1"
  local expected="$2"

  if ! grep -Fq "$expected" "$file"; then
    echo "expected $file to contain: $expected" >&2
    echo "actual:" >&2
    cat "$file" >&2
    exit 1
  fi
}

new_repo() {
  local dir
  dir="$(mktemp -d)"

  git -C "$dir" init -q
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name "Test User"

  mkdir -p "$dir/cli" "$dir/control-plane/dashboard-ui"
  printf '{"dependencies":{"left-pad":"1.0.0"}}\n' > "$dir/cli/package.json"
  printf 'lock\n' > "$dir/cli/bun.lock"
  printf '{"dependencies":{"react":"19.0.0"}}\n' > "$dir/control-plane/dashboard-ui/package.json"
  printf 'lock\n' > "$dir/control-plane/dashboard-ui/bun.lock"
  git -C "$dir" add .
  git -C "$dir" commit -qm "initial"

  printf '%s\n' "$dir"
}

with_fake_bun() {
  local bin_dir="$1"
  local log_file="$2"
  local mode="${3:-clean}"

  mkdir -p "$bin_dir"
  cat > "$bin_dir/bun" <<'BUN'
#!/usr/bin/env bash
set -euo pipefail

printf '%s|%s\n' "$PWD" "$*" >> "$FAKE_BUN_LOG"

if [[ "${FAKE_BUN_MODE:-clean}" == "dirty-lock" ]]; then
  printf 'changed by fake bun\n' >> bun.lock
fi
BUN
  chmod +x "$bin_dir/bun"

  export PATH="$bin_dir:$PATH"
  export FAKE_BUN_LOG="$log_file"
  export FAKE_BUN_MODE="$mode"
}

test_skips_when_no_package_manifest_is_staged() {
  local repo bin_dir log_file
  repo="$(new_repo)"
  bin_dir="$(mktemp -d)"
  log_file="$repo/bun.log"
  with_fake_bun "$bin_dir" "$log_file"

  printf 'docs\n' > "$repo/README.md"
  git -C "$repo" add README.md

  (cd "$repo" && "$SCRIPT")
  if [[ -e "$log_file" ]]; then
    echo "expected bun not to run for unrelated staged files" >&2
    cat "$log_file" >&2
    exit 1
  fi
}

test_skips_unrelated_staged_files_without_bun() {
  local repo
  repo="$(new_repo)"

  printf 'docs\n' > "$repo/README.md"
  git -C "$repo" add README.md

  (cd "$repo" && PATH="/usr/bin:/bin" "$SCRIPT")
}

test_checks_each_staged_manifest_workspace() {
  local repo bin_dir log_file
  repo="$(new_repo)"
  bin_dir="$(mktemp -d)"
  log_file="$repo/bun.log"
  with_fake_bun "$bin_dir" "$log_file"

  printf '{"dependencies":{"left-pad":"1.0.1"}}\n' > "$repo/cli/package.json"
  git -C "$repo" add cli/package.json

  (cd "$repo" && "$SCRIPT")
  assert_file_contains "$log_file" "$repo/cli|install --frozen-lockfile"
}

test_fails_when_bun_changes_lockfile() {
  local repo bin_dir log_file output
  repo="$(new_repo)"
  bin_dir="$(mktemp -d)"
  log_file="$repo/bun.log"
  output="$repo/output.log"
  with_fake_bun "$bin_dir" "$log_file" "dirty-lock"

  printf '{"dependencies":{"left-pad":"1.0.2"}}\n' > "$repo/cli/package.json"
  git -C "$repo" add cli/package.json

  if (cd "$repo" && "$SCRIPT") > "$output" 2>&1; then
    echo "expected hook check to fail when bun.lock changes" >&2
    exit 1
  fi

  assert_file_contains "$output" "cli/bun.lock changed after bun install --frozen-lockfile"
}

test_skips_when_no_package_manifest_is_staged
test_skips_unrelated_staged_files_without_bun
test_checks_each_staged_manifest_workspace
test_fails_when_bun_changes_lockfile
