// Codex CLI install helpers — plan, apply, uninstall. The wire shape is
// JSON (~/.codex/hooks.json) but the transport is command-only: each
// hook entry spawns the agentlock shim, which in turn POSTs to the
// daemon. See docs/reference/hook-daemon-path.md.
//
// Codex's lifecycle hooks are gated by `[features].hooks = true` in
// ~/.codex/config.toml. The plan auto-emits a write op for that file
// when the flag is missing or false, with the merged TOML bytes ready
// for the CLI to write atomically.

package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const codexMCPGapWarning = "Codex CLI: PreToolUse only fires for shell tool calls today. MCP tool calls are NOT gated by OpenAgentLock until upstream expands hook coverage."

var (
	codexFlagLineRegex        = regexp.MustCompile(`(?m)^\s*codex_hooks\s*=\s*(true|false)\b`)
	codexFeatureHookLineRegex = regexp.MustCompile(`(?m)^\s*hooks\s*=\s*(true|false)\b`)
)

// codexHooksPath returns the absolute path to the hooks.json file we'd
// write. Mirrors claudeCodeSettingsPath: returning an error rather than
// a synthesized "/.codex/hooks.json" prevents apply from suggesting an
// attacker-friendly absolute path when HOME is unset.
func codexHooksPath(configDirOverride string, overrides map[string]string) (string, error) {
	return codexHooksPathForHarness("codex", configDirOverride, overrides)
}

func codexHooksPathForHarness(harnessID, configDirOverride string, overrides map[string]string) (string, error) {
	dir, err := codexConfigDir(configDirOverride, overrides)
	if configDirOverride == "" {
		if d := overrides[harnessID]; d != "" {
			dir = d
			err = nil
		}
	}
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hooks.json"), nil
}

func codexConfigTomlPath(configDirOverride string, overrides map[string]string) (string, error) {
	return codexConfigTomlPathForHarness("codex", configDirOverride, overrides)
}

func codexConfigTomlPathForHarness(harnessID, configDirOverride string, overrides map[string]string) (string, error) {
	dir, err := codexConfigDir(configDirOverride, overrides)
	if configDirOverride == "" {
		if d := overrides[harnessID]; d != "" {
			dir = d
			err = nil
		}
	}
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.toml"), nil
}

// Precedence: --config-dir flag > harness_config_dirs[codex] > daemon's $HOME.
func codexConfigDir(configDirOverride string, overrides map[string]string) (string, error) {
	if configDirOverride != "" {
		return configDirOverride, nil
	}
	if d := overrides["codex"]; d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".codex"), nil
	}
	if envHome := os.Getenv("HOME"); envHome != "" {
		return filepath.Join(envHome, ".codex"), nil
	}
	return "", fmt.Errorf("cannot resolve user home directory; set config_dir_override or HOME")
}

// codexBinaryDefault is the command Codex spawns when no override is
// supplied. Relies on PATH; the CLI normally passes an absolute path.
const codexBinaryDefault = "agentlock"

func codexBinary(override string) string {
	if override != "" {
		return override
	}
	return codexBinaryDefault
}

// codexHookConfig returns the hook map we want merged into hooks.json.
// Each outer entry carries "_agentlock": true so uninstall can identify
// our entries without depending on the binary path or daemon URL.
//
// Transport is "command" (the shim binary), not "http" — Codex's hook
// runner doesn't speak HTTP natively. The shim POSTs to the daemon and
// translates the response into Codex's exit-code / JSON shape.
func codexHookConfig(daemonURL, agentlockBinary string) map[string]any {
	return codexHookConfigFor(daemonURL, agentlockBinary, "codex")
}

func codexHookConfigFor(daemonURL, agentlockBinary, hookHarness string) map[string]any {
	bin := codexBinary(agentlockBinary)
	mk := func(event string, timeout int) map[string]any {
		return map[string]any{
			"_agentlock": true,
			"matcher":    "*",
			"hooks": []any{
				map[string]any{
					"type":    "command",
					"command": fmt.Sprintf("%s hook %s %s", shellQuote(bin), hookHarness, event),
					"env": map[string]any{
						"AGENTLOCK_DAEMON_URL": strings.TrimRight(daemonURL, "/"),
					},
					"timeout": timeout,
				},
			},
		}
	}
	return map[string]any{
		"SessionStart": []any{mk("session-start", 10)},
		"PreToolUse":   []any{mk("pre-tool-use", 60)},
		"PostToolUse":  []any{mk("post-tool-use", 10)},
		"Stop":         []any{mk("stop", 10)},
	}
}

func codexDesktopPlan(daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string, existingFiles map[string]string) ([]fileOp, []string) {
	ops, warnings := codexPlanFor("Codex Desktop", "codex-desktop", daemonURL, configDirOverride, agentlockBinary, overrides, existingFiles)
	warnings = append(warnings, "Codex Desktop uses the shared Codex app-server hook config in ~/.codex for current desktop builds.")
	return ops, warnings
}

func codexSharedPlan(daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string, existingFiles map[string]string) ([]fileOp, []string) {
	ops, warnings := codexPlanFor("Codex CLI/Desktop", "codex-auto", daemonURL, configDirOverride, agentlockBinary, overrides, existingFiles)
	warnings = append(warnings, "Codex CLI and Codex Desktop share ~/.codex/hooks.json; one shared hook set auto-tags runtime source as codex or codex-desktop.")
	return ops, warnings
}

// codexPlan returns the file ops the CLI should execute for a Codex
// install. Always one hooks.json op; optionally a config.toml op when
// [features].hooks isn't already true on the host. The daemon never
// reads or writes host files in the new flow.
func codexPlan(daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string, existingFiles map[string]string) ([]fileOp, []string) {
	return codexPlanFor("Codex CLI", "codex", daemonURL, configDirOverride, agentlockBinary, overrides, existingFiles)
}

func codexPlanFor(displayName, hookHarness, daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string, existingFiles map[string]string) ([]fileOp, []string) {
	warnings := []string{codexMCPGapWarning}
	ops := make([]fileOp, 0, 2)

	hooksPath, err := codexHooksPathForHarness(hookHarness, configDirOverride, overrides)
	if err != nil {
		hooksPath = "<unresolved: " + err.Error() + ">"
	}
	hooksAbs := hooksPath
	if a, abserr := filepath.Abs(hooksPath); abserr == nil {
		hooksAbs = a
	}

	var existingHooks []byte
	hooksBackup := ""
	if c, ok := existingFiles[hooksAbs]; ok && c != "" {
		existingHooks = []byte(c)
		hooksBackup = fmt.Sprintf("%s.agentlock-backup-%d", hooksAbs, time.Now().UnixNano())
	}

	mergedHooks, mergeErr := mergeCodexHooksFor(existingHooks, daemonURL, agentlockBinary, hookHarness)
	if mergeErr != nil {
		body := map[string]any{"hooks": codexHookConfigFor(daemonURL, agentlockBinary, hookHarness)}
		mergedHooks, _ = json.MarshalIndent(body, "", "  ")
	}
	ops = append(ops, fileOp{
		Op:         "write",
		Path:       hooksAbs,
		Content:    string(mergedHooks),
		Reason:     fmt.Sprintf("wire %s hooks → %s (via shim)", displayName, daemonURL),
		BackupPath: hooksBackup,
	})

	tomlPath, tomlErr := codexConfigTomlPathForHarness(hookHarness, configDirOverride, overrides)
	if tomlErr == nil {
		tomlAbs := tomlPath
		if a, abserr := filepath.Abs(tomlPath); abserr == nil {
			tomlAbs = a
		}
		if op, note, ok := codexConfigTomlPlan(tomlAbs, existingFiles); ok {
			ops = append(ops, op)
			if note != "" {
				warnings = append(warnings, note)
			}
		}
	}

	return ops, warnings
}

// codexConfigTomlPlan returns the (optional) file op for enabling Codex
// lifecycle hooks in config.toml. Current app-server builds require
// `[features].hooks = true`; the legacy top-level `codex_hooks = true`
// still works in some CLI builds but Desktop logs it as deprecated.
// Pure: takes existing bytes via existingFiles and never touches disk.
func codexConfigTomlPlan(tomlAbs string, existingFiles map[string]string) (fileOp, string, bool) {
	c, present := existingFiles[tomlAbs]
	if !present {
		return fileOp{
			Op:      "write",
			Path:    tomlAbs,
			Content: "[features]\nhooks = true\n",
			Reason:  fmt.Sprintf("create %s with [features].hooks = true", tomlAbs),
		}, fmt.Sprintf("created %s with [features].hooks = true", tomlAbs), true
	}

	existing := []byte(c)
	state, idx, featuresInsertAt := featureHooksFlag(existing)
	switch state {
	case "true":
		return fileOp{}, "", false
	case "false":
		updated := append([]byte(nil), existing[:idx.start]...)
		updated = append(updated, []byte("hooks = true")...)
		updated = append(updated, existing[idx.end:]...)
		backup := fmt.Sprintf("%s.agentlock-backup-%d", tomlAbs, time.Now().UnixNano())
		return fileOp{
			Op:         "write",
			Path:       tomlAbs,
			Content:    string(updated),
			Reason:     fmt.Sprintf("flip [features].hooks false→true in %s", tomlAbs),
			BackupPath: backup,
		}, fmt.Sprintf("flipped [features].hooks false→true in %s (backup: %s)", tomlAbs, backup), true
	default:
		// Migration rule: when we touch Codex config, write only the
		// current [features].hooks key and remove legacy top-level
		// codex_hooks lines. Desktop logs the legacy key as deprecated.
		base := stripTopLevelCodexFlagLines(existing)
		if string(base) != string(existing) {
			_, _, featuresInsertAt = featureHooksFlag(base)
		}
		var buf []byte
		if featuresInsertAt >= 0 {
			buf = append(buf, base[:featuresInsertAt]...)
			buf = append(buf, []byte("hooks = true\n")...)
			buf = append(buf, base[featuresInsertAt:]...)
		} else {
			buf = append(buf, base...)
			if len(buf) > 0 && buf[len(buf)-1] != '\n' {
				buf = append(buf, '\n')
			}
			if len(buf) > 0 {
				buf = append(buf, '\n')
			}
			buf = append(buf, []byte("[features]\nhooks = true\n")...)
		}
		backup := fmt.Sprintf("%s.agentlock-backup-%d", tomlAbs, time.Now().UnixNano())
		return fileOp{
			Op:         "write",
			Path:       tomlAbs,
			Content:    string(buf),
			Reason:     fmt.Sprintf("insert [features].hooks = true in %s", tomlAbs),
			BackupPath: backup,
		}, fmt.Sprintf("added [features].hooks = true to %s (backup: %s)", tomlAbs, backup), true
	}
}

// featureHooksFlag scans config.toml for `[features].hooks`. It returns
// the flag state, the span of an existing hooks assignment, and the byte
// offset immediately after the [features] header for inserting a missing
// hooks line. The legacy top-level codex_hooks key is intentionally not
// treated as sufficient because Desktop app-server deprecates it.
func featureHooksFlag(b []byte) (string, codexFlagSpan, int) {
	cursor := 0
	inFeatures := false
	featuresInsertAt := -1
	for cursor < len(b) {
		nl := indexByteFrom(b, '\n', cursor)
		end := nl
		if end < 0 {
			end = len(b)
		}
		line := b[cursor:end]
		trimmed := strings.TrimSpace(string(line))
		if strings.HasPrefix(trimmed, "[") {
			inFeatures = trimmed == "[features]"
			if inFeatures {
				if nl >= 0 {
					featuresInsertAt = nl + 1
				} else {
					featuresInsertAt = len(b)
				}
			}
		} else if inFeatures && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if m := codexFeatureHookLineRegex.FindSubmatchIndex(line); m != nil {
				return string(line[m[2]:m[3]]), codexFlagSpan{cursor + m[0], cursor + m[1]}, featuresInsertAt
			}
		}
		if nl < 0 {
			break
		}
		cursor = nl + 1
	}
	return "", codexFlagSpan{}, featuresInsertAt
}

type codexFlagSpan struct{ start, end int }

// stripTopLevelCodexFlagLines removes deprecated pre-section
// `codex_hooks = (true|false)` assignments while preserving all section
// content. It is only used when emitting a replacement config.toml.
func stripTopLevelCodexFlagLines(b []byte) []byte {
	cursor := 0
	out := make([]byte, 0, len(b))
	for cursor < len(b) {
		nl := indexByteFrom(b, '\n', cursor)
		end := nl
		if end < 0 {
			end = len(b)
		}
		line := b[cursor:end]
		trimmed := strings.TrimSpace(string(line))
		if strings.HasPrefix(trimmed, "[") {
			out = append(out, b[cursor:]...)
			return out
		}
		includeLine := true
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if m := codexFlagLineRegex.FindSubmatchIndex(line); m != nil {
				includeLine = false
			}
		}
		if includeLine {
			out = append(out, b[cursor:end]...)
			if nl >= 0 {
				out = append(out, '\n')
			}
		}
		if nl < 0 {
			break
		}
		cursor = nl + 1
	}
	return out
}

func indexByteFrom(b []byte, c byte, from int) int {
	if from >= len(b) {
		return -1
	}
	idx := strings.IndexByte(string(b[from:]), c)
	if idx < 0 {
		return -1
	}
	return from + idx
}

// mergeCodexHooks merges our entries into existing hooks.json bytes,
// preserving any non-_agentlock entries the user added by hand.
// Idempotent: re-applying replaces our own entries rather than
// duplicating them. Mirrors mergeClaudeSettings.
func mergeCodexHooks(existing []byte, daemonURL, agentlockBinary string) ([]byte, error) {
	return mergeCodexHooksFor(existing, daemonURL, agentlockBinary, "codex")
}

func mergeCodexHooksFor(existing []byte, daemonURL, agentlockBinary, hookHarness string) ([]byte, error) {
	root := map[string]any{}
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &root); err != nil {
			return nil, fmt.Errorf("parse existing hooks.json: %w", err)
		}
	}

	// Codex's hooks.json may use either {"hooks": {...}} (matching
	// Claude's wrapper) or top-level event keys. Support both — read
	// from wherever the user already had entries, write into "hooks"
	// for consistency.
	var hooks map[string]any
	if h, ok := root["hooks"].(map[string]any); ok {
		hooks = h
	} else if hasTopLevelEvents(root) {
		hooks = root
	} else {
		hooks = map[string]any{}
	}

	ours := codexHookConfigFor(daemonURL, agentlockBinary, hookHarness)
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

	// Always re-emit under the "hooks" wrapper. If the original used
	// top-level event keys, normalize to the wrapped form on write.
	out := map[string]any{}
	for k, v := range root {
		if !isCodexEventKey(k) && k != "hooks" {
			out[k] = v
		}
	}
	out["hooks"] = hooks

	return json.MarshalIndent(out, "", "  ")
}

func hasTopLevelEvents(m map[string]any) bool {
	for k := range m {
		if isCodexEventKey(k) {
			return true
		}
	}
	return false
}

func isCodexEventKey(k string) bool {
	switch k {
	case "SessionStart", "PreToolUse", "PostToolUse", "Stop", "PermissionRequest", "UserPromptSubmit":
		return true
	}
	return false
}

// stripCodexHooks parses the supplied hooks.json bytes, removes every
// entry tagged _agentlock:true, trims empty containers, and returns the
// new bytes + count. Pure: no disk I/O. Mirrors stripClaudeSettings.
func stripCodexHooks(existing []byte) ([]byte, int, error) {
	if len(existing) == 0 {
		return nil, 0, nil
	}
	root := map[string]any{}
	if err := json.Unmarshal(existing, &root); err != nil {
		return nil, 0, fmt.Errorf("parse hooks.json: %w", err)
	}

	hooks, _ := root["hooks"].(map[string]any)
	usedWrapper := hooks != nil
	if hooks == nil && hasTopLevelEvents(root) {
		hooks = map[string]any{}
		for k, v := range root {
			if isCodexEventKey(k) {
				hooks[k] = v
				delete(root, k)
			}
		}
	}
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
		delete(root, "hooks")
	} else if usedWrapper || len(root) > 0 {
		root["hooks"] = hooks
	} else {
		// Original file used top-level event keys and we just emptied
		// it. Preserve the top-level shape rather than re-introducing
		// an empty "hooks" wrapper.
		for k, v := range hooks {
			root[k] = v
		}
	}

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("marshal: %w", err)
	}
	return out, removed, nil
}
