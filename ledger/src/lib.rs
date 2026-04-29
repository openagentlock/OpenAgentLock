//! OpenAgentLock append-only Merkle ledger. Single-writer, JSONL on disk,
//! leaf hashes chained so tampering at any seq breaks verification from
//! that point on. Built as a Rust lib with a C ABI (`staticlib`+`cdylib`)
//! so the Go control-plane can call into it without paying the cost of
//! porting the verification logic to two languages.

pub mod ffi;
pub mod merkle;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("verification failed at seq {seq}: {reason}")]
    Verify { seq: u64, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub ts_unix_ns: u128,
    pub kind: EntryKind,
    pub source: String,
    pub session_id: String,
    pub payload: serde_json::Value,
    pub payload_hash: String,
    pub sig: String,
    pub signer: SignerTag,
    pub signer_pk: String,
    pub prev_leaf: String,
    pub leaf: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    SessionStart,
    SessionRotate,
    GateCheck,
    GateApproval,
    PostResult,
    McpPin,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SignerTag {
    Yubikey,
    Software,
}
