# Multi-stage build of the OpenAgentLock control plane.
#
# Layers:
#   1. rust-builder — compiles ledger/ to a staticlib (libopenagentlock_ledger.a)
#   2. dashboard-builder — builds the Vite/Bun SPA into control-plane/internal/dashboard/dist
#   3. go-builder — compiles the Go binary, linking the Rust staticlib via CGO
#   4. runtime — distroless

# ---------- 1. rust-builder ----------
FROM rust:1.95-slim AS rust-builder
WORKDIR /src
COPY ledger /src/ledger
WORKDIR /src/ledger
RUN cargo build --release --lib

# ---------- 2. dashboard-builder ----------
FROM oven/bun:1.3 AS dashboard-builder
WORKDIR /src/control-plane/dashboard-ui
COPY control-plane/dashboard-ui/package.json control-plane/dashboard-ui/bun.lockb* ./
RUN bun install --frozen-lockfile || bun install
COPY control-plane/dashboard-ui/ ./
RUN bun run build

# ---------- 3. go-builder ----------
FROM golang:1.23-bookworm AS go-builder
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
COPY --from=dashboard-builder /src/control-plane/dashboard-ui/dist /src/control-plane/internal/dashboard/dist

ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-I/src/ledger/include"
ENV CGO_LDFLAGS="-L/src/ledger/target/release -lopenagentlock_ledger"

RUN go build -o /out/control-plane ./cmd/control-plane

# ---------- 4. runtime ----------
FROM gcr.io/distroless/cc-debian12 AS runtime
COPY --from=go-builder /out/control-plane /usr/local/bin/control-plane
ENV AGENTLOCK_LISTEN=0.0.0.0:7878
ENV AGENTLOCK_DASHBOARD_LISTEN=0.0.0.0:7879
EXPOSE 7878 7879
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/control-plane"]
