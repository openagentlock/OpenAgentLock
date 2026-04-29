# The ledger

Every decision the control plane makes — every `allow`, every `deny`, every install plan applied — is appended to a local **Merkle ledger**. The ledger gives you two properties:

1. **Tamper-evidence** — any later edit to a leaf changes the root.
2. **Verifiability** — anyone with the public key + a leaf + an inclusion proof can prove (without a remote service) that the leaf was committed at a given sequence.

The ledger crate is Rust. The Go control plane links it via FFI so the verification logic exists in exactly one place.

## Shape

- **Leaves** are the canonicalized JSON of an event (RFC 8785 JCS), prefixed per RFC 6962 (`0x00` byte) and SHA-256 hashed.
- **Internal nodes** are SHA-256 of the concatenation of left and right child hashes (RFC 6962 prefix `0x01`).
- **Odd tails** are duplicated to round each level (also per RFC 6962).
- **Roots** are signed by the **session** key; sessions are signed by your **long-lived** key (TOTP / OS keychain / hardware key — see [Signers](signers.md)).

## Endpoints

| Method | Path | What |
|---|---|---|
| `GET` | `/v1/ledger/root` | Current root + sequence + signature metadata |
| `GET` | `/v1/ledger/proof/:seq` | Inclusion proof for the leaf at `seq` |
| `POST` | `/v1/ledger/verify` | Verify a `(leaf, seq, proof, root)` tuple offline |

A standalone `agentlock ledger verify` command runs the same check from the host, useful in CI or compliance pipelines where you don't want to talk to the daemon.

## Verification, end-to-end

```bash
# Get the current root
curl -s http://127.0.0.1:7878/v1/ledger/root | jq

# Get an inclusion proof for sequence 1234
curl -s http://127.0.0.1:7878/v1/ledger/proof/1234 | jq

# Verify offline
agentlock ledger verify \
  --leaf-file leaf.json \
  --proof-file proof.json \
  --root-file root.json
```

`agentlock ledger verify` exits non-zero on mismatch.

## What it is not

- **Not a blockchain.** No consensus, no peers, no token. The ledger is a single-writer append-only log.
- **Not retroactive.** Entries that pre-date a stronger-signer enrollment carry the weaker signer's stamp; you cannot upgrade them.
- **Not a transport-layer integrity check.** TLS protects the wire; the ledger protects the record.

## Storage

The ledger is a single SQLite database file at `${AGENTLOCK_HOME}/ledger.db`. Inside the Docker image, that path lives on a named volume (`agentlock-state` in the published `docker-compose.yml`) so it survives container restarts.

You can copy the file out and rebuild the Merkle tree from scratch with `cargo run --example rebuild` from the source tree — useful for forensics.
