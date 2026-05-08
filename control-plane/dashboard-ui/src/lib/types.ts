export interface LedgerEntry {
  seq: number;
  ts: string;
  source: string;
  tool?: string;
  tool_use_id: string;
  signer: string;
  input?: Record<string, unknown>;
  tool_input?: Record<string, unknown>;
  rule_id?: string;
  verdict?: string;
  // True when the original verdict was deny but the daemon's monitor
  // mode forced the runtime to allow. UI renders these as "alert"
  // (IDS-style) instead of "deny" (IPS-style) — the call did go through.
  monitor_match?: boolean;
  policy_trace?: PolicyTraceItem[];
  payload_hash: string;
  sig: string;
  leaf_hash: string;
  prev_leaf: string;
}

export interface PolicyTraceItem {
  layer?: string;
  source?: string;
  rule_id: string;
  verdict: string;
  precedence?: string;
  priority?: number;
}

export interface ModeInfo {
  mode: "firewall" | "monitor";
  env: string;
  runtime_override: string;
}

export interface GateView {
  id: string;
  mode: string;
  disabled: boolean;
  source: string;
  /** @deprecated Compatibility summary for simple matchers. Prefer `match.tool`. */
  tool?: string;
  /** @deprecated Compatibility summary for simple matchers. Prefer `match.tool_prefix`. */
  tool_prefix?: string;
  /** @deprecated Compatibility summary for simple matchers. Prefer `match.any_command_regex`. */
  any_command_regex?: string[];
  /** @deprecated Compatibility summary for simple matchers. Prefer `match.any_path_regex`. */
  any_path_regex?: string[];
  /** @deprecated Compatibility summary for simple matchers. Prefer `match.any_url_regex`. */
  any_url_regex?: string[];
  /** Canonical recursive matcher schema. Consumers should prefer this over top-level summaries. */
  match?: MatchView;
  evaluators: string[];
}

export interface MatchView {
  tool?: string;
  tool_prefix?: string;
  path_glob_regex?: string;
  any_command_regex?: string[];
  any_path_regex?: string[];
  any_url_regex?: string[];
  any_of?: MatchView[];
}

export interface PolicyView {
  hash: string;
  policy_mode: string;
  daemon_mode: string;
  gates: GateView[];
}

export interface SessionRow {
  id: string;
  harness: string;
  signer: string;
  policy_hash: string;
  started_at: string;
  expires_at: string;
  active: boolean;
  needs_reload: boolean;
}

export interface SessionsResponse {
  live_policy_hash: string;
  sessions: SessionRow[];
}

export interface MCPPinRow {
  server: string;
  fingerprint: string;
}

export interface PendingMCPPinRow {
  id: string;
  server: string;
  fingerprint: string;
  known_fingerprint?: string;
  status: "unknown" | "changed";
  server_info?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface MCPPinsResponse {
  pins: MCPPinRow[];
  pending: PendingMCPPinRow[];
}

export interface RootInfo {
  root: string;
  seq: number;
  count: number;
  computed_at: string;
}

export interface FalsePositiveCase {
  schema_version: number;
  created_at: string;
  policy_hash: string;
  event: {
    seq: number;
    source: string;
    tool?: string;
    tool_use_id: string;
    verdict: string;
    monitor_match?: boolean;
    rule_id: string;
  };
  input: Record<string, string>;
  raw_input?: Record<string, string>;
  redactions?: string[];
  matched_gate: GateView;
  policy_trace?: PolicyTraceItem[];
  audit: {
    payload_hash: string;
    leaf_hash: string;
    prev_leaf: string;
  };
}

export interface FalsePositiveValidation {
  ok: boolean;
  errors?: string[];
  replacement_id?: string;
  replacement_verdict?: string;
}

export interface FalsePositiveApplyResult {
  hash: string;
  gates: number;
  disabled_id: string;
  replacement_id: string;
  needs_reload: boolean;
}
