# control-plane

OpenAgentLock daemon (agentlockd). Local HTTP service that evaluates policy, drives the install/uninstall plan-apply flow, and appends every decision to the Merkle ledger. Listens on `127.0.0.1:7878`. Go module path: `github.com/openagentlock/OpenAgentLock/control-plane`.

## Run with Docker

```bash
docker pull ghcr.io/openagentlock/agentlockd:latest
docker run -d --name agentlock \
  -v agentlock-state:/var/lib/agentlock \
  -p 127.0.0.1:7878:7878 \
  -p 127.0.0.1:7879:7879 \
  -e NVIDIA_API_KEY \
  -e OPENROUTER_API_KEY \
  ghcr.io/openagentlock/agentlockd:latest
```

State lives in the `agentlock-state` named volume. The CLI on your host owns harness-config writes; the daemon never reads or writes `~/.claude`, `~/.codex`, or `~/.cursor`, so no bind mount is needed.

Or via the published `docker-compose.yml`:

```bash
curl -O https://raw.githubusercontent.com/openagentlock/openagentlock/main/docker-compose.yml
docker compose up -d
```

External guardrail provider keys are optional. Set `NVIDIA_API_KEY` and/or `OPENROUTER_API_KEY` before starting Docker; the daemon reads them once into memory and does not persist them.

## Endpoints

The control plane exposes a versioned HTTP API. The contract lives in `api/openapi.yaml`; the live service mirrors it at `/v1/health`, `/v1/gates`, `/v1/install/plan`, `/v1/install/apply`, `/v1/uninstall`, `/v1/mode`, `/v1/mcp/pin`, `/v1/sessions`, `/v1/ledger/root`, `/v1/ledger/proof/:seq`, `/v1/ledger/verify`, plus harness hook endpoints under `/v1/hooks/...`.

The local web dashboard is served on `127.0.0.1:7879`.

## Build from source

```bash
cd control-plane
# build the rust ledger first (FFI dependency)
( cd ../ledger && cargo build --release )
go test -race ./...
go build -o control-plane ./cmd/control-plane
```

## Why Go

Concurrency is the dominant concern: many short-lived HTTP requests, an SSE stream, a single-writer ledger appender, harness hooks. Go's stdlib covers this without third-party routers, and the binary fits cleanly into a distroless image. The Rust crate next door owns Merkle correctness.
