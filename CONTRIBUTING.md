# Contributing

Thanks for considering a contribution. OpenAgentLock is a security-focused project; please open a GitHub issue first for anything beyond a small fix so we can align on scope.

## Development setup

Three languages, one repo:

- **`cli/`** — TypeScript on Bun. `bun install`, `bun run typecheck`, `bun test`.
- **`control-plane/`** — Go. `go vet ./... && go test -race ./...`. Requires the Rust ledger built first; see `ledger/README.md`.
- **`ledger/`** — Rust (edition 2021). `cargo test`.

You'll need:

- [Bun](https://bun.sh) >= 1.1
- Go >= 1.21
- Rust >= 1.85
- Docker (for control-plane)

## Workflow

1. Fork + branch from `main`.
2. Add tests for any net-new behavior. Detection logic is the only area where stub-first is acceptable; it has regression tests now.
3. `bun test`, `cargo test`, and `go test -race` must pass before review.
4. Open a PR with a clear summary. CI runs `ci.yml` on each push.

## Reporting issues

- **Bugs / feature requests:** open a GitHub issue at <https://github.com/openagentlock/OpenAgentLock/issues>.
- **Security vulnerabilities:** see [`SECURITY.md`](SECURITY.md). Please do **not** open a public issue for security reports.

## License of contributions

By contributing you agree that your contributions are licensed under the FSL-1.1-Apache-2.0 found in `LICENSE`.
