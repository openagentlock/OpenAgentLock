package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// install_claude_desktop wires Anthropic's standalone Claude Desktop app
// (distinct from Claude Code). Claude Desktop has no PreToolUse /
// PostToolUse hook surface upstream — see anthropics/claude-code#45514,
// closed-as-duplicate without a ship. The only documented extension
// surface is `mcpServers` entries in claude_desktop_config.json.
//
// What we install:
//
//  1. An "agentlock" MCP server entry — observability tools (status,
//     recent ledger entries) backed by the daemon. Read-only.
//  2. EVERY existing entry under mcpServers is rewritten to spawn
//     `agentlock mcp-proxy --name <id> -- <original-cmd> <args...>`.
//     The proxy sits between Claude Desktop and the real MCP server,
//     pumps bytes both ways verbatim, and on each JSON-RPC tools/call
//     requests a verdict from /v1/hooks/claude-desktop/pre-tool-use.
//     Allow → forward to child. Deny → synthesize MCP error reply.
//
// The original command/args/env for each wrapped entry are preserved
// under `_agentlock_original` on the same entry. stripClaudeDesktopConfig
// reverses the wrap by reading those originals back. Re-running install
// is idempotent: we always re-read originals first, then re-wrap, so
// drift from a user-edited args list is corrected on every run.
//
// What this does NOT cover: Anthropic's server-side features (web
// search, code interpreter) run in their cloud and aren't gateable by
// any local solution — Claude Code can't reach them either. Documented
// in docs/status.md.

// claudeDesktopServerName is the key under mcpServers we own (the
// observability-only MCP server entry). User-installed entries get
// wrapped in-place under their original names so server-name-based
// references in user prompts continue to work.
const claudeDesktopServerName = "agentlock"

// agentlockOriginalKey holds the verbatim command/args/env of a
// user-installed MCP server before we wrapped it. Strip on uninstall
// reads this back to restore the original entry.
const agentlockOriginalKey = "_agentlock_original"

// claudeDesktopConfigPath returns the platform-correct config path. The
// CLI normally pre-resolves this and passes it via
// harness_config_dirs["claude-desktop"]; the daemon-side fallback only
// kicks in for older CLIs that don't send the override.
//
// macOS:   $HOME/Library/Application Support/Claude/claude_desktop_config.json
// Windows: %APPDATA%/Claude/claude_desktop_config.json
// Linux:   no official Claude Desktop release; we still resolve a path
//
//	(under XDG_CONFIG_HOME/Claude) so dev sandboxes work, but
//	users won't have the app installed there.
func claudeDesktopConfigPath(configDirOverride string, overrides map[string]string) (string, error) {
	dir := configDirOverride
	if dir == "" {
		if d := overrides["claude-desktop"]; d != "" {
			dir = d
		} else if devHome := os.Getenv("AGENTLOCK_DEV_HOME"); devHome != "" {
			dir = claudeDesktopDevDir(devHome)
		} else if d, err := claudeDesktopHostDir(); err == nil {
			dir = d
		} else {
			return "", fmt.Errorf("cannot resolve Claude Desktop config dir; set config_dir_override, AGENTLOCK_DEV_HOME, or HOME/APPDATA")
		}
	}
	return filepath.Join(dir, "claude_desktop_config.json"), nil
}

// claudeDesktopDevDir mirrors the CLI's appSupport()-based resolution
// inside the AGENTLOCK_DEV_HOME sandbox. Tests that set DEV_HOME to a
// tmpdir get a path with the same shape the production install would
// hit, so the merge / strip codepaths exercise the same parent dirs.
func claudeDesktopDevDir(devHome string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(devHome, "Library", "Application Support", "Claude")
	case "windows":
		return filepath.Join(devHome, "AppData", "Roaming", "Claude")
	default:
		return filepath.Join(devHome, ".config", "Claude")
	}
}

// claudeDesktopHostDir is the real-host fallback when no override and no
// dev sandbox is set. Honors $APPDATA on Windows; falls back to the
// per-OS conventional dir relative to $HOME otherwise.
func claudeDesktopHostDir() (string, error) {
	if runtime.GOOS == "windows" {
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return filepath.Join(appdata, "Claude"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		if env := os.Getenv("HOME"); env != "" {
			home = env
		} else {
			return "", fmt.Errorf("no home directory")
		}
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude"), nil
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Claude"), nil
	default:
		return filepath.Join(home, ".config", "Claude"), nil
	}
}

// claudeDesktopServerEntry returns the mcpServers["agentlock"] entry we
// merge into the user's config. The `_agentlock: true` field is an
// unknown key to MCP / Claude Desktop and is ignored at launch; we keep
// it so uninstall identifies our entry without relying on the env var
// (which a user could legitimately set on their own server).
func claudeDesktopServerEntry(daemonURL, agentlockBinary string) map[string]any {
	bin := claudeCodeBinary(agentlockBinary)
	daemonURL = strings.TrimRight(daemonURL, "/")
	return map[string]any{
		"_agentlock": true,
		"command":    bin,
		"args":       []any{"mcp-server"},
		"env": map[string]any{
			"AGENTLOCK_DAEMON_URL": daemonURL,
		},
	}
}

// wrapMcpServerEntry rewrites a single mcpServers entry to spawn
// `agentlock mcp-proxy --name <id> -- <original-cmd> <args...>` while
// preserving the original under _agentlock_original for restore. If
// the entry is already wrapped (carries our marker), we re-read its
// preserved original and re-wrap it — handles drift where the user
// edited the wrapped command directly.
func wrapMcpServerEntry(name string, original map[string]any, daemonURL, agentlockBinary string) map[string]any {
	bin := claudeCodeBinary(agentlockBinary)
	daemonURL = strings.TrimRight(daemonURL, "/")

	// If this is already our wrapper, recover the real original from
	// the stashed copy so a re-install doesn't double-wrap.
	if isAgentlockEntry(original) {
		if stashed, ok := original[agentlockOriginalKey].(map[string]any); ok {
			original = stashed
		}
	}

	origCmd, _ := original["command"].(string)
	origArgsRaw, _ := original["args"].([]any)
	origEnv, _ := original["env"].(map[string]any)

	// Build the proxy's args: --name <id> -- <orig-cmd> <orig-args...>.
	// Use []any rather than []string so json.Marshal emits a JSON array.
	args := []any{"mcp-proxy", "--name", name, "--", origCmd}
	args = append(args, origArgsRaw...)

	// Inherit the original's env so credentials, API keys, etc. still
	// reach the child. Add our own AGENTLOCK_DAEMON_URL if absent so the
	// proxy can find the daemon without relying on PATH-time defaults.
	env := map[string]any{}
	for k, v := range origEnv {
		env[k] = v
	}
	if _, ok := env["AGENTLOCK_DAEMON_URL"]; !ok {
		env["AGENTLOCK_DAEMON_URL"] = daemonURL
	}

	// Preserve the original verbatim so strip can put it back exactly.
	originalCopy := map[string]any{
		"command": origCmd,
		"args":    origArgsRaw,
	}
	if len(origEnv) > 0 {
		originalCopy["env"] = origEnv
	}

	return map[string]any{
		"_agentlock":         true,
		agentlockOriginalKey: originalCopy,
		"command":            bin,
		"args":               args,
		"env":                env,
	}
}

// mergeClaudeDesktopConfig parses the existing claude_desktop_config.json
// bytes (may be empty), wraps every user-installed MCP server with our
// proxy, refreshes our standalone observability entry, and returns the
// new bytes. Idempotent on every run — the wrapper helper unwinds any
// existing wrap to find the original before re-wrapping, so drift from
// a user-edited args list is corrected each time.
func mergeClaudeDesktopConfig(existing []byte, daemonURL, agentlockBinary string) ([]byte, error) {
	cfg := map[string]any{}
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &cfg); err != nil {
			return nil, fmt.Errorf("parse existing config: %w", err)
		}
	}

	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}

	// Refresh our observability entry. Always replace; the user can't
	// have a legitimate non-agentlock server named "agentlock" because
	// MCP server names are user-chosen and we own this one by convention.
	servers[claudeDesktopServerName] = claudeDesktopServerEntry(daemonURL, agentlockBinary)

	// Wrap every other entry. Skip our own observability entry (already
	// handled above) — we don't proxy the proxy.
	for name, v := range servers {
		if name == claudeDesktopServerName {
			continue
		}
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		servers[name] = wrapMcpServerEntry(name, entry, daemonURL, agentlockBinary)
	}

	cfg["mcpServers"] = servers
	return json.MarshalIndent(cfg, "", "  ")
}

// claudeDesktopPlan returns the merged config the CLI should write. When
// existingFiles[configPath] is unset we emit a fresh config carrying
// only the agentlock entry; otherwise we merge against the supplied
// bytes so user-set mcpServers + any other top-level keys survive.
func claudeDesktopPlan(daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string, existingFiles map[string]string) (fileOp, []string) {
	warnings := []string{
		// Honest scope statement. We gate the MCP slice (every tools/call
		// to a user-installed MCP server or .mcpb Desktop Extension), but
		// Claude Desktop has additional local capabilities that don't go
		// through MCP and are NOT gated by this install:
		//   - Computer Use (direct mouse/keyboard control)
		//   - Cowork's non-MCP agentic paths (where applicable)
		//   - Integrated terminal command execution
		//   - Native connectors (Slack, Google Calendar, etc.)
		//   - Server-side features (web search, code interpreter)
		// Documented in docs/status.md so dashboard / report can't
		// overstate coverage.
		"claude-desktop: agentlock gates MCP tool calls only — every user-installed MCP server and .mcpb Desktop Extension is wrapped. NOT gated: Computer Use, integrated terminal, native connectors (Slack/GCal), Cowork's non-MCP paths, and Anthropic cloud features (web search, code interpreter). For full local enforcement, use Claude Code instead.",
	}

	configPath, err := claudeDesktopConfigPath(configDirOverride, overrides)
	if err != nil {
		configPath = "<unresolved: " + err.Error() + ">"
	}
	abs := configPath
	if a, err := filepath.Abs(configPath); err == nil {
		abs = a
	}

	var existing []byte
	backupPath := ""
	if c, ok := existingFiles[abs]; ok && c != "" {
		existing = []byte(c)
		backupPath = fmt.Sprintf("%s.agentlock-backup-%d", abs, time.Now().UnixNano())
	}

	merged, mergeErr := mergeClaudeDesktopConfig(existing, daemonURL, agentlockBinary)
	if mergeErr != nil {
		// Existing config was unparseable. Fall back to an agentlock-only
		// payload so the install still produces something usable; the
		// CLI will surface the parse error when it diffs against existing.
		fresh := map[string]any{
			"mcpServers": map[string]any{
				claudeDesktopServerName: claudeDesktopServerEntry(daemonURL, agentlockBinary),
			},
		}
		merged, _ = json.MarshalIndent(fresh, "", "  ")
	}
	return fileOp{
		Op:         "write",
		Path:       abs,
		Content:    string(merged),
		Reason:     fmt.Sprintf("register agentlock as MCP server in Claude Desktop → %s (no PreToolUse upstream)", strings.TrimRight(daemonURL, "/")),
		BackupPath: backupPath,
	}, warnings
}

// stripClaudeDesktopConfig reverses the wrap. For each entry tagged
// _agentlock:true:
//
//   - if it has a stashed _agentlock_original, restore that original
//     in place (the user's MCP server returns to its pre-install state)
//   - if it has no original (our standalone "agentlock" observability
//     entry), drop it entirely
//
// Pure: no disk I/O. Mirrors stripClaudeSettings's contract so the
// uninstall switch can dispatch uniformly.
func stripClaudeDesktopConfig(existing []byte) ([]byte, int, error) {
	if len(existing) == 0 {
		return nil, 0, nil
	}
	cfg := map[string]any{}
	if err := json.Unmarshal(existing, &cfg); err != nil {
		return nil, 0, fmt.Errorf("parse desktop config: %w", err)
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		return nil, 0, nil
	}

	removed := 0
	for name, v := range servers {
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if !isAgentlockEntry(entry) {
			continue
		}
		if original, ok := entry[agentlockOriginalKey].(map[string]any); ok {
			// Restore the user's original entry verbatim. Drop the
			// _agentlock_original wrapper so the restored entry doesn't
			// carry stray markers.
			restored := map[string]any{
				"command": original["command"],
				"args":    original["args"],
			}
			if e, ok := original["env"].(map[string]any); ok && len(e) > 0 {
				restored["env"] = e
			}
			servers[name] = restored
			removed++
			continue
		}
		// No stashed original = our standalone observability entry. Drop it.
		delete(servers, name)
		removed++
	}
	if len(servers) == 0 {
		delete(cfg, "mcpServers")
	} else {
		cfg["mcpServers"] = servers
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("marshal: %w", err)
	}
	return out, removed, nil
}
