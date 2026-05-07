package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimalYAML = `
version: 1
mode: enforce
defaults:
  bash: allow
gates:
  - id: rogue.destructive-bash
    match:
      tool: Bash
      any_command_regex:
        - 'rm\s+(-[rRfF]+\s+)+\S+'
        - 'git\s+push\s+.*--force'
    evaluate:
      - kind: always
        action: deny
`

const monitorYAML = `
version: 1
mode: monitor
defaults:
  bash: allow
gates:
  - id: rogue.destructive-bash
    match:
      tool: Bash
      any_command_regex:
        - 'git\s+push\s+.*--force'
    evaluate:
      - kind: always
        action: deny
`

const multiRuleYAML = `
version: 1
mode: enforce
defaults:
  bash: allow
gates:
  - id: supply-chain.pkg-install
    match:
      tool: Bash
      command_regex: '^(pip|npm) install\b'
    evaluate:
      - kind: always
        action: deny
  - id: rogue.destructive-bash
    match:
      tool: Bash
      any_command_regex:
        - 'rm\s+-rf\b'
    evaluate:
      - kind: always
        action: deny
`

func TestLoad_ParsesMinimalYAML(t *testing.T) {
	p, err := Load(strings.NewReader(minimalYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Mode != "enforce" {
		t.Fatalf("mode = %q, want enforce", p.Mode)
	}
	if len(p.Gates) != 1 {
		t.Fatalf("len(gates) = %d, want 1", len(p.Gates))
	}
	if p.Gates[0].ID != "rogue.destructive-bash" {
		t.Fatalf("gate.id = %q", p.Gates[0].ID)
	}
}

func TestLoad_RejectsUnknownEvaluatorKind(t *testing.T) {
	src := `
version: 1
gates:
  - id: x
    match: { tool: Bash }
    evaluate:
      - kind: invented-kind
`
	if _, err := Load(strings.NewReader(src)); err == nil {
		t.Fatal("expected error on unknown kind")
	}
}

func TestLoad_RejectsBadRegex(t *testing.T) {
	src := `
version: 1
gates:
  - id: x
    match:
      tool: Bash
      command_regex: '([unclosed'
    evaluate:
      - kind: always
        action: deny
`
	if _, err := Load(strings.NewReader(src)); err == nil {
		t.Fatal("expected error on bad regex")
	}
}

func TestHash_DeterministicAcrossReads(t *testing.T) {
	a, err := Load(strings.NewReader(minimalYAML))
	if err != nil {
		t.Fatalf("load a: %v", err)
	}
	b, err := Load(strings.NewReader(minimalYAML))
	if err != nil {
		t.Fatalf("load b: %v", err)
	}
	if a.Hash != b.Hash {
		t.Fatalf("hash mismatch %q vs %q", a.Hash, b.Hash)
	}
	if !strings.HasPrefix(a.Hash, "sha256:") {
		t.Fatalf("hash prefix: %q", a.Hash)
	}
}

func TestEvaluate_DestructiveBashEnforceDenies(t *testing.T) {
	p, _ := Load(strings.NewReader(minimalYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "rm -rf /"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("verdict = %q, want deny", v.Verdict)
	}
	if v.RuleID != "rogue.destructive-bash" {
		t.Fatalf("rule_id = %q", v.RuleID)
	}
	if v.Reason == "" {
		t.Fatal("reason must be populated")
	}
}

func TestEvaluate_ForcePushDenies(t *testing.T) {
	p, _ := Load(strings.NewReader(minimalYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "git push --force origin main"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("verdict = %q, want deny", v.Verdict)
	}
}

func TestEvaluate_NonMatchingBashAllows(t *testing.T) {
	p, _ := Load(strings.NewReader(minimalYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "ls -la"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("verdict = %q, want allow", v.Verdict)
	}
	if v.RuleID != "default" {
		t.Fatalf("rule_id = %q, want default", v.RuleID)
	}
}

func TestEvaluate_MonitorForcesAllowButTagsRule(t *testing.T) {
	p, _ := Load(strings.NewReader(monitorYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "git push --force origin main"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("verdict = %q, want allow (monitor mode)", v.Verdict)
	}
	if v.RuleID != "rogue.destructive-bash" {
		t.Fatalf("rule_id = %q", v.RuleID)
	}
	if !v.MonitorMatch {
		t.Fatal("expected MonitorMatch = true")
	}
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	p, _ := Load(strings.NewReader(multiRuleYAML))
	// Crafted to match only the second rule.
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "rm -rf /tmp/x"},
	})
	if v.RuleID != "rogue.destructive-bash" {
		t.Fatalf("rule_id = %q", v.RuleID)
	}

	// First rule wins for a pip-install command.
	v2 := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "pip install foo"},
	})
	if v2.RuleID != "supply-chain.pkg-install" {
		t.Fatalf("rule_id = %q", v2.RuleID)
	}
}

func TestEvaluateLayered_DenyOverridesPersonalAllow(t *testing.T) {
	base, _ := Load(strings.NewReader(`version: 1
mode: enforce
gates:
  - id: base.safe
    match: { tool: Bash, command_regex: '^echo ' }
    evaluate:
      - kind: always
        action: allow
`))
	group, _ := LoadBytes([]byte(`version: 1
mode: enforce
gates:
  - id: group.secret-read
    source: group:compliance
    match:
      tool: Bash
      command_regex: '^cat secret'
    evaluate:
      - kind: always
        action: deny
`))
	user, _ := LoadBytes([]byte(`version: 1
mode: enforce
gates:
  - id: user.secret-read
    source: user:alice
    match:
      tool: Bash
      command_regex: '^cat secret'
    evaluate:
      - kind: always
        action: allow
`))
	got := EvaluateLayered(base, []Layer{{Name: "group:compliance", Policy: group}, {Name: "user:alice", Policy: user}}, EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "cat secret.txt"},
	})
	if got.Verdict != "deny" || got.RuleID != "group.secret-read" {
		t.Fatalf("got verdict=%q rule=%q, want group deny", got.Verdict, got.RuleID)
	}
	if len(got.Trace) != 2 {
		t.Fatalf("trace len = %d, want 2: %+v", len(got.Trace), got.Trace)
	}
}

func TestEvaluateLayered_PriorityPrecedenceCanChooseAllow(t *testing.T) {
	base, _ := Load(strings.NewReader(`version: 1
mode: enforce
gates:
  - id: base.never
    match: { tool: Bash, command_regex: '^never$' }
    evaluate:
      - kind: always
        action: deny
`))
	lowDeny, _ := LoadBytes([]byte(`version: 1
mode: enforce
gates:
  - id: shared.net
    source: group:default
    precedence: priority
    priority: 10
    match:
      tool: Bash
      command_regex: '^curl '
    evaluate:
      - kind: always
        action: deny
`))
	highAllow, _ := LoadBytes([]byte(`version: 1
mode: enforce
gates:
  - id: shared.net
    source: group:red-team
    precedence: priority
    priority: 20
    match:
      tool: Bash
      command_regex: '^curl '
    evaluate:
      - kind: always
        action: allow
`))
	got := EvaluateLayered(base, []Layer{{Name: "group:default", Policy: lowDeny}, {Name: "group:red-team", Policy: highAllow}}, EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "curl https://example.com"},
	})
	if got.Verdict != "allow" || got.RuleID != "shared.net" {
		t.Fatalf("got verdict=%q rule=%q, want higher-priority allow", got.Verdict, got.RuleID)
	}
}

const pkgInstallYAML = `
version: 1
mode: enforce
gates:
  - id: supply-chain.pkg-install
    match:
      tool: Bash
      command_regex: '^(pip|npm|brew|cargo) install\s'
    evaluate:
      - kind: allowlist
        list: __INLINE__:numpy,requests,react
        on_hit: allow
        on_miss: deny
`

const netEgressYAML = `
version: 1
mode: enforce
gates:
  - id: rogue.net-egress
    match:
      tool: Bash
      command_regex: '\b(curl|wget)\b'
    evaluate:
      - kind: host-allowlist
        list: __INLINE__:api.anthropic.com,api.openai.com
        on_hit: allow
        on_miss: deny
`

const netEgressURLYAML = `
version: 1
mode: enforce
gates:
  - id: rogue.net-egress
    match:
      any_of:
        - tool: Bash
          command_regex: '\b(curl|wget)\b'
        - tool: WebFetch
          any_url_regex:
            - '^https?://'
        - tool: WebSearch
          any_url_regex:
            - '^https?://'
    evaluate:
      - kind: host-allowlist
        list: __INLINE__:api.anthropic.com,api.openai.com
        on_hit: allow
        on_miss: deny
`

const typosquatYAML = `
version: 1
mode: enforce
gates:
  - id: supply-chain.pkg-install
    match:
      tool: Bash
      command_regex: '^(pip|npm|brew|cargo) install\s'
    evaluate:
      - kind: typosquat
        reference: __INLINE__:numpy,requests,react,tensorflow
        action_on_near_miss: deny
      - kind: allowlist
        list: __INLINE__:numpy,requests,react,tensorflow
        on_hit: allow
        on_miss: deny
`

func TestEvaluate_Typosquat_NearMissDenies(t *testing.T) {
	p, err := Load(strings.NewReader(typosquatYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// edit distance 1 from "requests"
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "pip install reqeusts"},
	})
	if v.Verdict != "deny" || v.RuleID != "supply-chain.pkg-install" {
		t.Fatalf("got %+v", v)
	}
	if !strings.Contains(v.Reason, "pkg-install") {
		t.Fatalf("reason: %q", v.Reason)
	}
}

func TestEvaluate_Typosquat_ExactMatchPassesThrough(t *testing.T) {
	p, _ := Load(strings.NewReader(typosquatYAML))
	// exact "numpy" → typosquat skips → allowlist allow
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "pip install numpy"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_Typosquat_UnrelatedPassesThrough(t *testing.T) {
	p, _ := Load(strings.NewReader(typosquatYAML))
	// "evilpkg" far from any allowlist entry → typosquat skips → allowlist miss → deny
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "pip install evilpkg"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("got %+v", v)
	}
}

func pinTofuYAML(storePath string) string {
	return `
version: 1
mode: enforce
gates:
  - id: supply-chain.untrusted-mcp
    match:
      tool_prefix: "mcp__"
    evaluate:
      - kind: pin-tofu
        store: ` + storePath + `
        on_unknown: allow
        on_known: allow
        on_changed: deny
`
}

func TestEvaluate_PinTofu_FirstSeenAllowsAndPersists(t *testing.T) {
	store := filepath.Join(t.TempDir(), "pinned-mcp.json")
	p, err := Load(strings.NewReader(pinTofuYAML(store)))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	v := p.Evaluate(EvalRequest{
		Tool: "mcp__filesystem__read",
		Input: map[string]any{
			"mcp_server":      "filesystem",
			"mcp_fingerprint": "sha256:aaaa",
		},
	})
	if v.Verdict != "allow" || v.RuleID != "supply-chain.untrusted-mcp" {
		t.Fatalf("got %+v", v)
	}
	// Re-load the pin store: should have recorded the fingerprint.
	raw, err := os.ReadFile(store)
	if err != nil {
		t.Fatalf("store file missing: %v", err)
	}
	if !strings.Contains(string(raw), "sha256:aaaa") {
		t.Fatalf("store contents: %q", string(raw))
	}
}

func TestEvaluate_PinTofu_KnownFingerprintAllowsAgain(t *testing.T) {
	store := filepath.Join(t.TempDir(), "pinned-mcp.json")
	p, _ := Load(strings.NewReader(pinTofuYAML(store)))
	req := EvalRequest{
		Tool: "mcp__github__list_repos",
		Input: map[string]any{
			"mcp_server":      "github",
			"mcp_fingerprint": "sha256:bbbb",
		},
	}
	p.Evaluate(req) // first, pins
	v := p.Evaluate(req)
	if v.Verdict != "allow" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_PinTofu_MismatchDenies(t *testing.T) {
	store := filepath.Join(t.TempDir(), "pinned-mcp.json")
	p, _ := Load(strings.NewReader(pinTofuYAML(store)))
	p.Evaluate(EvalRequest{
		Tool: "mcp__slack__post",
		Input: map[string]any{
			"mcp_server":      "slack",
			"mcp_fingerprint": "sha256:cccc",
		},
	})
	// same server, different fingerprint
	v := p.Evaluate(EvalRequest{
		Tool: "mcp__slack__post",
		Input: map[string]any{
			"mcp_server":      "slack",
			"mcp_fingerprint": "sha256:dddd",
		},
	})
	if v.Verdict != "deny" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_PinTofu_NoServerFieldSkips(t *testing.T) {
	store := filepath.Join(t.TempDir(), "pinned-mcp.json")
	p, _ := Load(strings.NewReader(pinTofuYAML(store)))
	// tool_prefix matches but no mcp_server in input → evaluator skips →
	// gate falls through to default.
	v := p.Evaluate(EvalRequest{
		Tool:  "mcp__noop__x",
		Input: map[string]any{},
	})
	if v.Verdict != "allow" || v.RuleID != "default" {
		t.Fatalf("got %+v", v)
	}
}

const multiEvalYAML = `
version: 1
mode: enforce
gates:
  - id: multi
    match:
      tool: Bash
      command_regex: '^pip install '
    evaluate:
      - kind: allowlist
        list: __INLINE__:a,b,c
        on_hit: allow
        on_miss: skip
      - kind: always
        action: deny
`

func TestEvaluate_Allowlist_HitAllows(t *testing.T) {
	p, err := Load(strings.NewReader(pkgInstallYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "pip install numpy"},
	})
	if v.Verdict != "allow" || v.RuleID != "supply-chain.pkg-install" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_Allowlist_MissDenies(t *testing.T) {
	p, _ := Load(strings.NewReader(pkgInstallYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "pip install evilpkg"},
	})
	if v.Verdict != "deny" || v.RuleID != "supply-chain.pkg-install" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_Allowlist_NpmInstallAllowed(t *testing.T) {
	p, _ := Load(strings.NewReader(pkgInstallYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "npm install react"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_HostAllowlist_HitAllows(t *testing.T) {
	p, _ := Load(strings.NewReader(netEgressYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "curl https://api.anthropic.com/v1/messages"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_HostAllowlist_UnknownHostDenies(t *testing.T) {
	p, _ := Load(strings.NewReader(netEgressYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "curl https://evil.biz/pwn"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_HostAllowlist_NoURLDoesNotMatch(t *testing.T) {
	p, _ := Load(strings.NewReader(netEgressYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "curl --help"},
	})
	// No URL in command — evaluator can't decide. Should skip (allow by default).
	if v.Verdict != "allow" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_HostAllowlist_WebFetchURLHitAllows(t *testing.T) {
	p, err := Load(strings.NewReader(netEgressURLYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	v := p.Evaluate(EvalRequest{
		Tool:  "WebFetch",
		Input: map[string]any{"url": "https://api.openai.com/v1/responses"},
	})
	if v.Verdict != "allow" || v.RuleID != "rogue.net-egress" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_HostAllowlist_WebSearchURLMissDenies(t *testing.T) {
	p, _ := Load(strings.NewReader(netEgressURLYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "WebSearch",
		Input: map[string]any{"url": "https://evil.biz/search?q=secrets"},
	})
	if v.Verdict != "deny" || v.RuleID != "rogue.net-egress" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_HostAllowlist_PrefersURLFieldOverCommand(t *testing.T) {
	p, _ := Load(strings.NewReader(netEgressURLYAML))
	v := p.Evaluate(EvalRequest{
		Tool: "WebFetch",
		Input: map[string]any{
			"url":     "https://api.openai.com/v1/responses",
			"command": "curl https://evil.biz/pwn",
		},
	})
	if v.Verdict != "allow" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_MultiEvaluator_SkipThenAlways(t *testing.T) {
	p, _ := Load(strings.NewReader(multiEvalYAML))
	// "zzz" not in allowlist → on_miss=skip → fallthrough to always:deny
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "pip install zzz"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("got %+v", v)
	}
	// "a" in allowlist → on_hit=allow, stops pipeline
	v2 := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "pip install a"},
	})
	if v2.Verdict != "allow" {
		t.Fatalf("got %+v", v2)
	}
}

const secretReadYAML = `
version: 1
mode: enforce
gates:
  - id: rogue.secret-read
    match:
      any_of:
        - { tool: Read, path_glob: "**/.env*" }
        - { tool: Read, path_glob: "**/.ssh/**" }
        - { tool: Bash, command_regex: 'cat\s+.*(\.env|credentials)' }
    evaluate:
      - kind: always
        action: deny
`

func TestEvaluate_SecretRead_EnvFileDenied(t *testing.T) {
	p, err := Load(strings.NewReader(secretReadYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	v := p.Evaluate(EvalRequest{
		Tool:  "Read",
		Input: map[string]any{"file_path": "/home/alice/project/.env"},
	})
	if v.Verdict != "deny" || v.RuleID != "rogue.secret-read" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_SecretRead_SshDirectoryDenied(t *testing.T) {
	p, _ := Load(strings.NewReader(secretReadYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Read",
		Input: map[string]any{"file_path": "/home/alice/.ssh/id_rsa"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_SecretRead_BashCatEnvDenied(t *testing.T) {
	p, _ := Load(strings.NewReader(secretReadYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "cat .env.local"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_SecretRead_BenignReadAllowed(t *testing.T) {
	p, _ := Load(strings.NewReader(secretReadYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Read",
		Input: map[string]any{"file_path": "/home/alice/project/README.md"},
	})
	if v.Verdict != "allow" || v.RuleID != "default" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_SecretRead_BenignBashAllowed(t *testing.T) {
	p, _ := Load(strings.NewReader(secretReadYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "cat README.md"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_SecretRead_WrongToolDoesNotMatch(t *testing.T) {
	p, _ := Load(strings.NewReader(secretReadYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Write",
		Input: map[string]any{"file_path": "/home/alice/.env"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("got %+v", v)
	}
}

func TestEvaluate_NonBashToolDoesNotTriggerBashRule(t *testing.T) {
	p, _ := Load(strings.NewReader(minimalYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Read",
		Input: map[string]any{"file_path": "/tmp/foo"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("verdict = %q, want allow", v.Verdict)
	}
	if v.RuleID != "default" {
		t.Fatalf("rule_id = %q", v.RuleID)
	}
}

const anyPathRegexYAML = `
version: 1
mode: enforce
defaults:
  read: allow
gates:
  - id: rogue.secret-read
    match:
      tool: Read
      any_path_regex:
        - '/\.ssh/id_[^/]+$'
        - '\.env(\.|$)'
        - '/secrets\.(json|yaml)$'
    evaluate:
      - kind: always
        action: deny
`

func TestEvaluate_AnyPathRegex_DeniesSshKey(t *testing.T) {
	p, err := Load(strings.NewReader(anyPathRegexYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	v := p.Evaluate(EvalRequest{
		Tool:  "Read",
		Input: map[string]any{"file_path": "/Users/alice/.ssh/id_ed25519"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("verdict = %q, want deny (on id_ed25519)", v.Verdict)
	}
	if v.RuleID != "rogue.secret-read" {
		t.Fatalf("rule_id = %q", v.RuleID)
	}
}

func TestEvaluate_AnyPathRegex_DeniesDotenv(t *testing.T) {
	p, _ := Load(strings.NewReader(anyPathRegexYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Read",
		Input: map[string]any{"file_path": "./apps/web/.env"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("verdict = %q, want deny", v.Verdict)
	}
}

func TestEvaluate_AnyPathRegex_AllowsUnmatched(t *testing.T) {
	p, _ := Load(strings.NewReader(anyPathRegexYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Read",
		Input: map[string]any{"file_path": "/Users/alice/work/README.md"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("verdict = %q, want allow", v.Verdict)
	}
}

// Some harnesses surface the read target under `path` instead of
// `file_path`. Evaluator must accept either key.
func TestEvaluate_AnyPathRegex_FallsBackToPathKey(t *testing.T) {
	p, _ := Load(strings.NewReader(anyPathRegexYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Read",
		Input: map[string]any{"path": "/home/bob/.ssh/id_rsa"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("verdict = %q, want deny via `path` key", v.Verdict)
	}
}

func TestEvaluate_AnyPathRegex_NoPathInInput(t *testing.T) {
	p, _ := Load(strings.NewReader(anyPathRegexYAML))
	// Tool is Read but the harness didn't include a path — can't match.
	v := p.Evaluate(EvalRequest{
		Tool:  "Read",
		Input: map[string]any{},
	})
	if v.Verdict != "allow" {
		t.Fatalf("verdict = %q, want allow (no path means no match)", v.Verdict)
	}
}

func TestLoad_AnyPathRegex_RejectsBadRegex(t *testing.T) {
	bad := `
version: 1
mode: enforce
defaults: { read: allow }
gates:
  - id: bad.regex
    match:
      tool: Read
      any_path_regex:
        - '[unclosed'
    evaluate:
      - kind: always
        action: deny
`
	_, err := Load(strings.NewReader(bad))
	if err == nil {
		t.Fatal("expected Load to reject unclosed regex")
	}
}

// Disabled gates must be skipped even when they'd otherwise match.
// The inverse — enabling a disabled gate flips the verdict to deny —
// is what `PATCH /v1/policy/gates/{id}` promises via its `disabled`
// field; this test locks in the engine's part of that contract.
func TestEvaluate_DisabledGateIsSkipped(t *testing.T) {
	disabledYAML := `
version: 1
mode: enforce
defaults: { bash: allow }
gates:
  - id: rogue.destructive-bash
    disabled: true
    match:
      tool: Bash
      any_command_regex:
        - 'rm\s+-rf\b'
    evaluate:
      - kind: always
        action: deny
`
	p, err := Load(strings.NewReader(disabledYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "rm -rf /tmp/x"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("disabled gate fired anyway: verdict = %q, rule = %q", v.Verdict, v.RuleID)
	}
	if v.RuleID != "default" {
		t.Fatalf("disabled gate should produce default verdict, got rule = %q", v.RuleID)
	}
}

// A gate-level `mode: monitor` must override the policy default
// without pulling the whole policy into monitor mode. This is how
// the baseline bundle keeps `recon.host-fingerprint` monitor-only
// even when the overall policy.mode is enforce.
func TestEvaluate_PerGateMonitorOverridesEnforcePolicy(t *testing.T) {
	yamlSrc := `
version: 1
mode: enforce
defaults: { bash: allow }
gates:
  - id: recon.host-fingerprint
    mode: monitor
    match:
      tool: Bash
      any_command_regex:
        - 'launchctl\s+list\b'
    evaluate:
      - kind: always
        action: deny
  - id: rogue.destructive-bash
    match:
      tool: Bash
      any_command_regex:
        - 'rm\s+-rf\b'
    evaluate:
      - kind: always
        action: deny
`
	p, _ := Load(strings.NewReader(yamlSrc))
	// Monitor-mode gate: verdict flips to allow, but MonitorMatch is true
	// and RuleID names the matched rule so the ledger still records it.
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "launchctl list"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("monitor gate should produce allow, got %q", v.Verdict)
	}
	if !v.MonitorMatch {
		t.Fatal("MonitorMatch must be true on a monitor-mode match")
	}
	if v.RuleID != "recon.host-fingerprint" {
		t.Fatalf("rule id lost: %q", v.RuleID)
	}
	// Enforce-mode gate in the same policy still denies.
	v2 := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "rm -rf /tmp/x"},
	})
	if v2.Verdict != "deny" {
		t.Fatalf("sibling enforce gate lost: %q", v2.Verdict)
	}
}

// Baseline policy bundle must parse cleanly; this catches schema drift
// before anyone copies policy/baseline.yaml into their dev/policy.yaml.
func TestLoad_BaselinePolicyParses(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "policy", "baseline.yaml"))
	if err != nil {
		t.Skipf("baseline policy not present: %v", err)
	}
	p, err := LoadBytes(b)
	if err != nil {
		t.Fatalf("LoadBytes(baseline.yaml): %v", err)
	}
	if len(p.Gates) == 0 {
		t.Fatal("baseline policy must define at least one gate")
	}
	// rogue.destructive-bash must exist + be enabled (safety net default).
	found := false
	for _, g := range p.Gates {
		if g.ID == "rogue.destructive-bash" {
			found = true
			if g.Disabled {
				t.Fatal("rogue.destructive-bash must not be disabled in the baseline")
			}
		}
	}
	if !found {
		t.Fatal("baseline policy missing rogue.destructive-bash")
	}
}

const anyURLRegexYAML = `
version: 1
mode: enforce
defaults:
  webfetch: allow
gates:
  - id: rogue.net-egress-url
    match:
      tool: WebFetch
      any_url_regex:
        - '^https?://(?:[a-z0-9-]+\.)*attacker\.example(?:/|$)'
        - '^https?://[^/]*requestbin\.com'
    evaluate:
      - kind: always
        action: deny
`

func TestEvaluate_AnyURLRegex_DeniesAttackerHost(t *testing.T) {
	p, err := Load(strings.NewReader(anyURLRegexYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	v := p.Evaluate(EvalRequest{
		Tool:  "WebFetch",
		Input: map[string]any{"url": "https://attacker.example/exfil"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("verdict = %q, want deny", v.Verdict)
	}
	if v.RuleID != "rogue.net-egress-url" {
		t.Fatalf("rule_id = %q", v.RuleID)
	}
}

func TestEvaluate_AnyURLRegex_AllowsTrustedHost(t *testing.T) {
	p, _ := Load(strings.NewReader(anyURLRegexYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "WebFetch",
		Input: map[string]any{"url": "https://api.github.com/repos/foo/bar"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("verdict = %q, want allow", v.Verdict)
	}
}

func TestEvaluate_AnyURLRegex_NoURLInInput(t *testing.T) {
	p, _ := Load(strings.NewReader(anyURLRegexYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "WebFetch",
		Input: map[string]any{},
	})
	if v.Verdict != "allow" {
		t.Fatalf("verdict = %q, want allow when no url", v.Verdict)
	}
}

func TestLoad_AnyURLRegex_RejectsBadRegex(t *testing.T) {
	bad := `
version: 1
mode: enforce
defaults: { webfetch: allow }
gates:
  - id: bad.regex
    match:
      tool: WebFetch
      any_url_regex:
        - '[unclosed'
    evaluate:
      - kind: always
        action: deny
`
	_, err := Load(strings.NewReader(bad))
	if err == nil {
		t.Fatal("expected Load to reject malformed any_url_regex")
	}
}

const nudgeYAML = `
version: 1
mode: enforce
defaults:
  bash: allow
gates:
  - id: safety.rm-suggest-trash
    match:
      tool: Bash
      any_command_regex:
        - '\brm\s+(-[rRfF]+\s+)+\S+'
    evaluate:
      - kind: always
        action: deny
        nudge: "use trash instead"
`

const nudgeMonitorYAML = `
version: 1
mode: monitor
defaults:
  bash: allow
gates:
  - id: safety.rm-suggest-trash
    match:
      tool: Bash
      any_command_regex:
        - '\brm\s+(-[rRfF]+\s+)+\S+'
    evaluate:
      - kind: always
        action: deny
        nudge: "use trash instead"
`

const nudgeMixedYAML = `
version: 1
mode: enforce
defaults:
  bash: allow
gates:
  - id: with.nudge
    match:
      tool: Bash
      command_regex: '^do-nudge\b'
    evaluate:
      - kind: always
        action: deny
        nudge: "try the safe alternative"
  - id: without.nudge
    match:
      tool: Bash
      command_regex: '^no-nudge\b'
    evaluate:
      - kind: always
        action: deny
`

// Loading a YAML rule with a `nudge:` produces a Gate whose evals slice
// carries the string at the matching index. The slice was previously
// two parallel slices (Evaluators + EvalNudges); welded into a single
// []evalEntry to prevent drift.
func TestLoad_NudgeStoredOnGate(t *testing.T) {
	p, err := Load(strings.NewReader(nudgeYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(p.Gates) != 1 {
		t.Fatalf("len(gates) = %d, want 1", len(p.Gates))
	}
	g := p.Gates[0]
	if len(g.Evals) != 1 {
		t.Fatalf("len(Evals) = %d, want 1", len(g.Evals))
	}
	if g.Evals[0].nudge != "use trash instead" {
		t.Fatalf("Evals[0].nudge = %q, want %q", g.Evals[0].nudge, "use trash instead")
	}
	if g.Evals[0].eval == nil {
		t.Fatal("Evals[0].eval must be non-nil")
	}
}

// A matching deny rule with a nudge surfaces the nudge in the result.
func TestEvaluate_DenyCarriesNudge(t *testing.T) {
	p, _ := Load(strings.NewReader(nudgeYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "rm -rf /tmp/x"},
	})
	if v.Verdict != "deny" {
		t.Fatalf("verdict = %q, want deny", v.Verdict)
	}
	if v.Nudge != "use trash instead" {
		t.Fatalf("nudge = %q, want %q", v.Nudge, "use trash instead")
	}
}

// A matching deny rule that omits the nudge field returns an empty string.
// (Backward compat — existing rules pre-nudge keep working unchanged.)
func TestEvaluate_DenyWithoutNudgeIsEmpty(t *testing.T) {
	p, _ := Load(strings.NewReader(nudgeMixedYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "no-nudge target"},
	})
	if v.Verdict != "deny" || v.RuleID != "without.nudge" {
		t.Fatalf("got %+v", v)
	}
	if v.Nudge != "" {
		t.Fatalf("nudge = %q, want empty (rule has no nudge)", v.Nudge)
	}
}

// Sister rule with a nudge still attaches it; confirms the parallel-slice
// lookup uses the correct gate (not just the first one).
func TestEvaluate_DenyWithNudgeWhenSiblingHasNone(t *testing.T) {
	p, _ := Load(strings.NewReader(nudgeMixedYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "do-nudge target"},
	})
	if v.Verdict != "deny" || v.RuleID != "with.nudge" {
		t.Fatalf("got %+v", v)
	}
	if v.Nudge != "try the safe alternative" {
		t.Fatalf("nudge = %q", v.Nudge)
	}
}

// A non-matching request returns the default allow verdict and never
// surfaces a nudge from somewhere else in the policy.
func TestEvaluate_NonMatchingRequestHasNoNudge(t *testing.T) {
	p, _ := Load(strings.NewReader(nudgeYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "ls -la"},
	})
	if v.Verdict != "allow" || v.RuleID != "default" {
		t.Fatalf("got %+v", v)
	}
	if v.Nudge != "" {
		t.Fatalf("nudge leaked: %q", v.Nudge)
	}
}

// Monitor-mode matches downgrade deny → allow but PRESERVE the nudge so
// a downstream daemon-level firewall escalation can re-attach the hint.
// The decision to suppress the nudge on a final-allow verdict lives in
// the API layer (applyDaemonModeOverride) — see
// TestApplyDaemonModeOverride_MonitorMatchStripsNudge.
func TestEvaluate_MonitorDowngradeKeepsNudge(t *testing.T) {
	p, _ := Load(strings.NewReader(nudgeMonitorYAML))
	v := p.Evaluate(EvalRequest{
		Tool:  "Bash",
		Input: map[string]any{"command": "rm -rf /tmp/x"},
	})
	if v.Verdict != "allow" {
		t.Fatalf("verdict = %q, want allow (monitor)", v.Verdict)
	}
	if !v.MonitorMatch {
		t.Fatal("MonitorMatch must be true on a monitor downgrade")
	}
	if v.OriginalVerdict != "deny" {
		t.Fatalf("OriginalVerdict = %q, want deny", v.OriginalVerdict)
	}
	if v.Nudge != "use trash instead" {
		t.Fatalf("nudge must survive monitor downgrade for firewall re-escalation, got %q", v.Nudge)
	}
}
