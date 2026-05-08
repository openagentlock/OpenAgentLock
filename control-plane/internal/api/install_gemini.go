// Gemini CLI install helpers — plan, merge, strip. Settings live at
// ~/.gemini/settings.json with hooks under a top-level `hooks` map keyed
// by Gemini's PascalCase event names (BeforeTool, AfterTool,
// SessionStart, SessionEnd). Transport is command-only: each entry
// spawns the agentlock shim, which POSTs to /v1/hooks/gemini/<event>
// and translates the daemon response into Gemini's `{decision, reason}`
// shape.
//
// Differences from the Codex installer:
//   * No enabling flag (Codex needed `[features].hooks = true` in
//     config.toml). Gemini hooks activate as soon as the settings.json
//     entry exists.
//   * Settings file is shared with the rest of Gemini's config (model
//     defaults, theme, MCP servers). Merge is non-destructive: only
//     entries tagged `_agentlock: true` under the hooks map are
//     touched on uninstall.
//   * Timeout is in MILLISECONDS, not seconds. (Codex/Claude both use
//     seconds — easy footgun if copied wholesale.)
//   * Gemini supports MCP tools natively via `mcp_<server>_<tool>`
//     matchers, so there's no Codex-style "MCP gap" warning.

package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// geminiSettingsPath returns the absolute path to settings.json under the
// chosen Gemini config directory. Returning an error rather than a
// synthesized "/.gemini/settings.json" prevents apply from suggesting an
// attacker-friendly path when HOME is unset.
//
// Precedence: --config-dir flag > harness_config_dirs[gemini] (the
// CLI's host-resolved path) > AGENTLOCK_DEV_HOME > daemon's $HOME.
func geminiSettingsPath(configDirOverride string, overrides map[string]string) (string, error) {
	dir, err := geminiConfigDir(configDirOverride, overrides)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "settings.json"), nil
}

func geminiConfigDir(configDirOverride string, overrides map[string]string) (string, error) {
	if configDirOverride != "" {
		return configDirOverride, nil
	}
	if d := overrides["gemini"]; d != "" {
		return d, nil
	}
	if devHome := os.Getenv("AGENTLOCK_DEV_HOME"); devHome != "" {
		return filepath.Join(devHome, ".gemini"), nil
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".gemini"), nil
	}
	if envHome := os.Getenv("HOME"); envHome != "" {
		return filepath.Join(envHome, ".gemini"), nil
	}
	return "", fmt.Errorf("cannot resolve user home directory; set config_dir_override, AGENTLOCK_DEV_HOME, or HOME")
}

const geminiBinaryDefault = "agentlock"

func geminiBinary(override string) string {
	if override != "" {
		return override
	}
	return geminiBinaryDefault
}

// geminiHookConfig returns the hooks map merged into settings.json under
// the top-level `hooks` key. Each outer entry carries `_agentlock: true`
// so uninstall can identify our entries without depending on daemon URL
// or shim path. Event keys are Gemini's PascalCase native names.
//
// Per-event timeouts (milliseconds — Gemini's wire unit):
//   - SessionStart 10000  (cheap, mostly a session-create + ledger write)
//   - BeforeTool   60000  (gate path; matches Codex's 60s budget)
//   - AfterTool    10000  (observability; tool already ran)
//   - SessionEnd   10000  (observability; teardown)
//
// `matcher: "*"` regex matches every tool — the gate logic lives in the
// daemon, not the matcher. Per-tool short-circuits would just push policy
// into hook config and de-sync from /v1/policy.
func geminiHookConfig(daemonURL, agentlockBinary string) map[string]any {
	bin := geminiBinary(agentlockBinary)
	mk := func(event string, timeoutMs int) map[string]any {
		return map[string]any{
			"_agentlock": true,
			"matcher":    ".*",
			"hooks": []any{
				map[string]any{
					"type":    "command",
					"command": fmt.Sprintf("%s hook gemini %s", shellQuote(bin), event),
					"env": map[string]any{
						"AGENTLOCK_DAEMON_URL": strings.TrimRight(daemonURL, "/"),
					},
					"timeout": timeoutMs,
				},
			},
		}
	}
	return map[string]any{
		"SessionStart": []any{mk("session-start", 10000)},
		"BeforeTool":   []any{mk("pre-tool-use", 60000)},
		"AfterTool":    []any{mk("post-tool-use", 10000)},
		"SessionEnd":   []any{mk("stop", 10000)},
	}
}

// geminiPlan returns the file op for a Gemini install. Pure: no disk
// I/O. The CLI executes the returned op on the host. Warnings slice is
// returned for shape parity with codexPlan even though Gemini has no
// gating caveat — leaves room for future advisories without changing
// the dispatch site.
func geminiPlan(daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string, existingFiles map[string]string) (fileOp, []string) {
	settingsPath, err := geminiSettingsPath(configDirOverride, overrides)
	if err != nil {
		settingsPath = "<unresolved: " + err.Error() + ">"
	}
	abs := settingsPath
	if a, abserr := filepath.Abs(settingsPath); abserr == nil {
		abs = a
	}

	var existing []byte
	backupPath := ""
	if c, ok := existingFiles[abs]; ok && c != "" {
		existing = []byte(c)
		backupPath = fmt.Sprintf("%s.agentlock-backup-%d", abs, time.Now().UnixNano())
	}

	merged, mergeErr := mergeGeminiSettings(existing, daemonURL, agentlockBinary)
	if mergeErr != nil {
		body := map[string]any{"hooks": geminiHookConfig(daemonURL, agentlockBinary)}
		merged, _ = json.MarshalIndent(body, "", "  ")
	}
	return fileOp{
		Op:         "write",
		Path:       abs,
		Content:    string(merged),
		Reason:     fmt.Sprintf("wire Gemini CLI hooks → %s (via shim)", daemonURL),
		BackupPath: backupPath,
	}, nil
}

// mergeGeminiSettings merges our entries into existing settings.json
// bytes, preserving any non-_agentlock entries the user added by hand
// and any non-hooks top-level fields (model defaults, theme, MCP
// server pins, etc.). Idempotent: re-applying replaces our own entries
// rather than duplicating them. Mirrors mergeClaudeSettings.
func mergeGeminiSettings(existing []byte, daemonURL, agentlockBinary string) ([]byte, error) {
	root := map[string]any{}
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &root); err != nil {
			return nil, fmt.Errorf("parse existing settings.json: %w", err)
		}
	}

	hooks, _ := root["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}

	ours := geminiHookConfig(daemonURL, agentlockBinary)
	for cat, oursArrAny := range ours {
		oursArr, _ := oursArrAny.([]any)
		existingArr, _ := hooks[cat].([]any)
		kept := make([]any, 0, len(existingArr))
		for _, e := range existingArr {
			if !isAgentlockEntry(e) {
				kept = append(kept, e)
			}
		}
		kept = append(kept, oursArr...)
		hooks[cat] = kept
	}
	root["hooks"] = hooks

	return json.MarshalIndent(root, "", "  ")
}

// stripGeminiSettings parses the supplied settings.json bytes, removes
// every entry under hooks.<event> tagged _agentlock:true, trims empty
// containers, and returns the new bytes + count. Pure: no disk I/O.
// Mirrors stripClaudeSettings — Gemini's hooks layout is structurally
// identical (top-level `hooks` map keyed by event name).
func stripGeminiSettings(existing []byte) ([]byte, int, error) {
	if len(existing) == 0 {
		return nil, 0, nil
	}
	settings := map[string]any{}
	if err := json.Unmarshal(existing, &settings); err != nil {
		return nil, 0, fmt.Errorf("parse settings: %w", err)
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		return nil, 0, nil
	}

	removed := 0
	for cat, v := range hooks {
		arr, ok := v.([]any)
		if !ok {
			continue
		}
		kept := make([]any, 0, len(arr))
		for _, e := range arr {
			if isAgentlockEntry(e) {
				removed++
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) == 0 {
			delete(hooks, cat)
		} else {
			hooks[cat] = kept
		}
	}
	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"] = hooks
	}

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("marshal: %w", err)
	}
	return out, removed, nil
}
