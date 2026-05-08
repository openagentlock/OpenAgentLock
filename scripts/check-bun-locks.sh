#!/usr/bin/env bash
set -euo pipefail

workspaces=(
  "cli"
  "control-plane/dashboard-ui"
)

repo_root="$(git rev-parse --show-toplevel)"
staged_files=()
while IFS= read -r staged_file; do
  staged_files+=("$staged_file")
done < <(git diff --cached --name-only --diff-filter=ACMR)

if [[ "${#staged_files[@]}" -eq 0 ]]; then
  exit 0
fi

needs_check() {
  local workspace="$1"
  local manifest="$workspace/package.json"
  local file

  for file in "${staged_files[@]}"; do
    if [[ "$file" == "$manifest" ]]; then
      return 0
    fi
  done

  return 1
}

check_workspaces=()
for workspace in "${workspaces[@]}"; do
  if needs_check "$workspace"; then
    check_workspaces+=("$workspace")
  fi
done

if [[ "${#check_workspaces[@]}" -eq 0 ]]; then
  exit 0
fi

if ! command -v bun >/dev/null 2>&1; then
  echo "bun is required to verify lockfile sync before committing." >&2
  exit 1
fi

for workspace in "${check_workspaces[@]}"; do
  lockfile="$workspace/bun.lock"
  before="$(git -C "$repo_root" hash-object "$lockfile")"

  echo "Checking $workspace bun.lock"
  (cd "$repo_root/$workspace" && bun install --frozen-lockfile)

  after="$(git -C "$repo_root" hash-object "$lockfile")"
  if [[ "$before" != "$after" ]]; then
    echo "$lockfile changed after bun install --frozen-lockfile." >&2
    echo "Stage the updated lockfile and commit again." >&2
    exit 1
  fi
done
