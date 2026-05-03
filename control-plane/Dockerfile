# Multi-stage build of the OpenAgentLock control plane.
#
# Build context is the repo root (the published docker-publish.yml uses
# `context: .` and `file: control-plane/Dockerfile`).
#
# Layers:
#   1. rust-builder       — compiles ledger/ to libopenagentlock_ledger.a
#   2. dashboard-builder  — builds the Vite SPA. Vite's outDir resolves to
#                           /src/control-plane/internal/dashboard/dist
#                           (see control-plane/dashboard-ui/vite.config.ts).
#   3. go-builder         — compiles the Go binary, linking the Rust
#                           staticlib via CGO.
#   4. runtime            — distroless cc.

# ---------- 1. rust-builder ----------
FROM rust:1-slim AS rust-builder
WORKDIR /src
COPY ledger /src/ledger
WORKDIR /src/ledger
RUN cargo build --release --lib

# ---------- 2. dashboard-builder ----------
FROM oven/bun:1.3 AS dashboard-builder
# vite outDir is "../internal/dashboard/dist", so we need both dirs
# present at the right relative paths.
WORKDIR /src/control-plane
COPY control-plane/dashboard-ui ./dashboard-ui
WORKDIR /src/control-plane/dashboard-ui
RUN bun install --frozen-lockfile || bun install
RUN bun run build

# ---------- 3. go-builder ----------
FROM golang:1.26-bookworm AS go-builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY control-plane/go.mod control-plane/go.sum ./control-plane/
WORKDIR /src/control-plane
RUN go mod download

COPY control-plane/cmd ./cmd
COPY control-plane/internal ./internal
COPY control-plane/api ./api
COPY --from=rust-builder /src/ledger/include /src/ledger/include
COPY --from=rust-builder /src/ledger/target/release/libopenagentlock_ledger.a /src/ledger/target/release/libopenagentlock_ledger.a
COPY --from=dashboard-builder /src/control-plane/internal/dashboard/dist /src/control-plane/internal/dashboard/dist

ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-I/src/ledger/include"
ENV CGO_LDFLAGS="-L/src/ledger/target/release -lopenagentlock_ledger"

RUN go build -o /out/control-plane ./cmd/control-plane

# Stage an empty AGENTLOCK_HOME owned by the distroless nonroot uid (65532).
# Distroless has no shell/mkdir/chown, so we prepare the dir here and
# COPY --chown it into the runtime image.
RUN install -d -m 0700 -o 65532 -g 65532 /out/agentlock-home

# ---------- 4. runtime ----------
FROM gcr.io/distroless/cc-debian12 AS runtime
COPY --from=go-builder /out/control-plane /usr/local/bin/agentlockd
COPY --from=go-builder --chown=65532:65532 /out/agentlock-home /var/lib/agentlock
COPY policies/default.yaml /etc/agentlock/policies/default.yaml
ENV AGENTLOCK_LISTEN=0.0.0.0:7878
ENV AGENTLOCK_DASHBOARD_LISTEN=0.0.0.0:7879
ENV AGENTLOCK_HOME=/var/lib/agentlock
ENV AGENTLOCK_IN_CONTAINER=1
# Default to unattested so `docker run` works zero-conf. TUI + dashboard
# show the red "UNATTESTED — LEDGER NOT SIGNED" banner. Override with
# `-e AGENTLOCK_ALLOW_UNATTESTED=0` and supply a TOTP/software signer.
ENV AGENTLOCK_ALLOW_UNATTESTED=1
EXPOSE 7878 7879
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agentlockd"]
