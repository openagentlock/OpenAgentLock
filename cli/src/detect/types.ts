// Detection types. Every harness has a Detector that probes the local
// filesystem for evidence of an install and reports what it found.

export type HarnessId =
  | "claude-code"
  | "claude-desktop"
  | "codex"
  | "opencode"
  | "cursor"
  | "cline"
  | "continue"
  | "gemini"
  | "vscode-copilot";

export type HookSurface =
  | "lifecycle-hooks"     // PreToolUse / PostToolUse style
  | "mcp-stdio"           // MCP server config we can MITM
  | "mcp-http"            // HTTP/SSE MCP transport
  | "extension-only";     // editor-extension settings, no shell hooks

export interface DetectedScope {
  // A "scope" is one config surface we could install into. Most harnesses
  // expose two: a global/user config and per-project configs.
  kind: "global" | "project";
  path: string;
  /// True if the file currently exists; false if we'd create it.
  exists: boolean;
}

export interface Detection {
  id: HarnessId;
  displayName: string;
  installed: boolean;
  /// Human-readable evidence (e.g. "found ~/.claude/settings.json").
  evidence: string[];
  /// Optional version string parsed from a binary or a config field.
  version?: string;
  /// Where we could install hooks / proxy entries.
  scopes: DetectedScope[];
  /// What surfaces this harness exposes for hardening.
  surfaces: HookSurface[];
  /// Notes the user should see at selection time (e.g. "VSCode must be
  /// closed during install"). Plain strings, no markup.
  notes: string[];
  /// True when this harness already has agentlock wired (claude hook
  /// entries with _agentlock:true, or a dev-stub marker file). Drives
  /// the install picker pre-check + "wired → url" sub-line.
  agentlockInstalled?: boolean;
  /// Daemon URL the existing agentlock install points at, if we could
  /// extract it from the on-disk config / marker.
  agentlockDaemonURL?: string;
}

export interface Detector {
  id: HarnessId;
  displayName: string;
  detect(): Promise<Detection>;
}
