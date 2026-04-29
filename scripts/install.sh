#!/usr/bin/env bash
# OpenAgentLock — one-shot installer.
#
# Usage:
#   curl -fsSL https://openagentlock.github.io/OpenAgentLock/install.sh | bash
#
# What it does:
#   1. Pulls the ghcr.io/openagentlock/agentlockd image.
#   2. Drops a docker-compose.yml in your CWD if one isn't already there.
#   3. Starts the control plane.
#   4. Installs the CLI via Bun (or npm), if neither is found prints the manual command.
#   5. Prints next steps.

set -euo pipefail

CYAN='\033[0;36m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

step() { printf "${CYAN}==> %s${RESET}\n" "$*"; }
ok()   { printf "${GREEN}    %s${RESET}\n" "$*"; }
warn() { printf "${YELLOW}    %s${RESET}\n" "$*"; }
err()  { printf "${RED}!! %s${RESET}\n" "$*" >&2; }

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "$1 is required but not on PATH."
    exit 1
  fi
}

step "Checking prerequisites"
require docker
ok "docker found"

step "Pulling control-plane image"
docker pull ghcr.io/openagentlock/agentlockd:latest
ok "image pulled"

if [[ ! -f docker-compose.yml ]]; then
  step "Writing docker-compose.yml"
  curl -fsSL -o docker-compose.yml \
    https://raw.githubusercontent.com/openagentlock/openagentlock/main/docker-compose.yml
  ok "docker-compose.yml written"
else
  warn "docker-compose.yml already exists — leaving it alone"
fi

step "Starting control plane"
docker compose up -d
ok "control plane is running"

step "Installing CLI"
if command -v bun >/dev/null 2>&1; then
  bun add -g @openagentlock/cli
  ok "installed via bun"
elif command -v npm >/dev/null 2>&1; then
  npm i -g @openagentlock/cli
  ok "installed via npm"
else
  warn "neither bun nor npm found"
  warn "install Bun (https://bun.sh) or Node, then run:"
  warn "  bun add -g @openagentlock/cli"
  warn "  # or"
  warn "  npm i -g @openagentlock/cli"
fi

cat <<'EOF'

Done.

Next steps:

  agentlock detect            # list local agent harnesses
  agentlock install           # plan + apply hooks (interactive)
  open http://127.0.0.1:7879  # local web dashboard

Documentation: https://openagentlock.github.io/OpenAgentLock/
EOF
