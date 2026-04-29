# `openagentlock-ledger`

Append-only Merkle ledger for OpenAgentLock. Rust crate built as a lib, a C-ABI `staticlib`, and a `cdylib` so the Go control plane links the verification logic directly — no chance of two implementations drifting.

## What it does

- SHA-256 leaf hashing (RFC 6962 leaf prefix)
- Merkle tree construction with odd-tail duplication
- Inclusion proof generation
- Inclusion proof verification

## Build

```bash
cd ledger
cargo build --release
cargo test
```

`cargo build --release` also produces `libopenagentlock_ledger.a` and `libopenagentlock_ledger.{so,dylib}` for FFI consumers.

## License

FSL-1.1-Apache-2.0 (see repo `LICENSE`).
