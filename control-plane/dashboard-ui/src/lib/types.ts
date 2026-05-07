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
  tool?: string;
  tool_prefix?: string;
  any_command_regex?: string[];
  evaluators: string[];
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
