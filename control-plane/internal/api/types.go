// Wire types for the OpenAgentLock control-plane HTTP API. Mirror api/openapi.yaml.
// Add JSON tags here as handlers land.

package api

import "time"

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
	VerdictAsk   Verdict = "ask"
)

type SignerKind string

const (
	SignerYubiKey  SignerKind = "yubikey"
	SignerSoftware SignerKind = "software"
)

type Session struct {
	ID            string     `json:"id"`
	StartedAt     time.Time  `json:"started_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	PolicyHash    string     `json:"policy_hash"`
	SessionPubKey string     `json:"session_pubkey"`
	Signer        SignerKind `json:"signer"`
	SignerPubKey  string     `json:"signer_pubkey"`
}

type GateCheckRequest struct {
	SessionID string                 `json:"session_id"`
	Source    string                 `json:"source"` // "claude-code" | "mcp-proxy" | ...
	Tool      string                 `json:"tool"`
	Input     map[string]any         `json:"input"`
	Cwd       string                 `json:"cwd,omitempty"`
	Meta      map[string]any         `json:"meta,omitempty"`
}

type GateCheckResponse struct {
	Verdict       Verdict `json:"verdict"`
	RuleID        string  `json:"rule_id"`
	Reason        string  `json:"reason"`
	LedgerSeq     uint64  `json:"ledger_seq"`
	ApprovalID    string  `json:"approval_id,omitempty"` // present when verdict=ask
	RequireRotate bool    `json:"require_rotate,omitempty"`
}

type Approval struct {
	ID         string         `json:"id"`
	SessionID  string         `json:"session_id"`
	Tool       string         `json:"tool"`
	Input      map[string]any `json:"input"`
	RuleID     string         `json:"rule_id"`
	Reason     string         `json:"reason"`
	DeadlineAt time.Time      `json:"deadline_at"`
}

type ApprovalDecision struct {
	ApprovalID string     `json:"approval_id"`
	Decision   Verdict    `json:"decision"` // allow | deny only
	Signer     SignerKind `json:"signer"`
	Signature  string     `json:"signature"` // ed25519 over canonical(approval)
}

type LedgerRoot struct {
	Root         string    `json:"root"`
	Seq          uint64    `json:"seq"`
	GenesisPK    string    `json:"genesis_pubkey"`
	ComputedAt   time.Time `json:"computed_at"`
}
