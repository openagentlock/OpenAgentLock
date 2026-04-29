# Contributing

Thanks for considering a contribution. OpenAgentLock is a security-focused project; please open an issue first for anything beyond a small fix so we can align on scope.

## Development setup

Three languages, one repo:

- **`cli/`** — TypeScript on Bun. `bun install`, `bun run typecheck`, `bun test`.
- **`control-plane/`** — Go. `go vet ./... && go test -race ./...`. Requires the Rust ledger built first; see `ledger/README.md`.
- **`ledger/`** — Rust (edition 2021). `cargo test`.

You'll need:

- [Bun](https://bun.sh) >= 1.1
- Go >= 1.23
- Rust >= 1.78
- Docker (for control-plane)

## Workflow

1. Fork + branch from `main`.
2. Add tests for any net-new behavior. Detection logic is the only area where stub-first is acceptable; it has regression tests now.
3. `bun test`, `cargo test`, and `go test -race` must pass before review.
4. Open a PR with a clear summary. CI runs ci.yml on each push.

## Reporting security issues

Do **not** open a public issue for a vulnerability. Email security@openagentlock.dev (see `SECURITY.md`).

## License of contributions

By contributing you agree that your contributions are licensed under the FSL-1.1-Apache-2.0 found in `LICENSE`.
