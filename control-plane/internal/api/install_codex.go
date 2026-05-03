// Codex CLI install helpers — plan, apply, uninstall. The wire shape is
// JSON (~/.codex/hooks.json) but the transport is command-only: each
// hook entry spawns the agentlock shim, which in turn POSTs to the
// daemon. See docs/reference/hook-daemon-path.md.
//
// Codex's lifecycle hooks are gated by `codex_hooks = true` in
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
	codexFlagLineRegex = regexp.MustCompile(`(?m)^\s*codex_hooks\s*=\s*(true|false)\b`)
)

// codexHooksPath returns the absolute path to the hooks.json file we'd
// write. Mirrors claudeCodeSettingsPath: returning an error rather than
// a synthesized "/.codex/hooks.json" prevents apply from suggesting an
// attacker-friendly absolute path when HOME is unset.
func codexHooksPath(configDirOverride string, overrides map[string]string) (string, error) {
	dir, err := codexConfigDir(configDirOverride, overrides)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hooks.json"), nil
}

func codexConfigTomlPath(configDirOverride string, overrides map[string]string) (string, error) {
	dir, err := codexConfigDir(configDirOverride, overrides)
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
	bin := codexBinary(agentlockBinary)
	mk := func(event string, timeout int) map[string]any {
		return map[string]any{
			"_agentlock": true,
			"matcher":    "*",
			"hooks": []any{
				map[string]any{
					"type":    "command",
					"command": fmt.Sprintf("%s hook codex %s", shellQuote(bin), event),
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

// codexPlan returns the file ops the CLI should execute for a Codex
// install. Always one hooks.json op; optionally a config.toml op when
// the codex_hooks flag isn't already true on the host. The daemon never
// reads or writes host files in the new flow.
func codexPlan(daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string, existingFiles map[string]string) ([]fileOp, []string) {
	warnings := []string{codexMCPGapWarning}
	ops := make([]fileOp, 0, 2)

	hooksPath, err := codexHooksPath(configDirOverride, overrides)
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

	mergedHooks, mergeErr := mergeCodexHooks(existingHooks, daemonURL, agentlockBinary)
	if mergeErr != nil {
		body := map[string]any{"hooks": codexHookConfig(daemonURL, agentlockBinary)}
		mergedHooks, _ = json.MarshalIndent(body, "", "  ")
	}
	ops = append(ops, fileOp{
		Op:         "write",
		Path:       hooksAbs,
		Content:    string(mergedHooks),
		Reason:     fmt.Sprintf("wire Codex CLI hooks → %s (via shim)", daemonURL),
		BackupPath: hooksBackup,
	})

	tomlPath, tomlErr := codexConfigTomlPath(configDirOverride, overrides)
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

// codexConfigTomlPlan returns the (optional) file op for the codex
// config.toml flag-flip. Returns ok=false to mean "no change needed"
// (flag already true). Pure: takes the existing bytes via existingFiles
// and never touches disk. Mirrors the cases the old apply-time helper
// covered:
//  1. file missing → write "codex_hooks = true\n"
//  2. flag missing → append "codex_hooks = true\n"
//  3. flag = false → rewrite the matching line to true
//  4. flag = true → skip
func codexConfigTomlPlan(tomlAbs string, existingFiles map[string]string) (fileOp, string, bool) {
	c, present := existingFiles[tomlAbs]
	if !present {
		return fileOp{
			Op:      "write",
			Path:    tomlAbs,
			Content: "codex_hooks = true\n",
			Reason:  fmt.Sprintf("create %s with codex_hooks = true", tomlAbs),
		}, fmt.Sprintf("created %s with codex_hooks = true", tomlAbs), true
	}

	existing := []byte(c)
	state, idx := topLevelCodexFlag(existing)
	switch state {
	case "true":
		return fileOp{}, "", false
	case "false":
		updated := append([]byte(nil), existing[:idx.start]...)
		updated = append(updated, []byte("codex_hooks = true")...)
		updated = append(updated, existing[idx.end:]...)
		backup := fmt.Sprintf("%s.agentlock-backup-%d", tomlAbs, time.Now().UnixNano())
		return fileOp{
			Op:         "write",
			Path:       tomlAbs,
			Content:    string(updated),
			Reason:     fmt.Sprintf("flip codex_hooks false→true in %s", tomlAbs),
			BackupPath: backup,
		}, fmt.Sprintf("flipped codex_hooks false→true in %s (backup: %s)", tomlAbs, backup), true
	default:
		// Insert before the first [section] header. Appending to the end
		// of a file that already has sections lands the line *inside*
		// the last section — which the codex parser then reads as
		// e.g. `tui.model_availability_nux.codex_hooks = true` and
		// rejects ("invalid type: boolean true, expected u32"). Only
		// fall back to end-of-file when the file has no sections at all.
		insertAt := firstSectionHeaderOffset(existing)
		var buf []byte
		if insertAt < 0 {
			// No sections — safe to append.
			buf = append(buf, existing...)
			if len(buf) > 0 && buf[len(buf)-1] != '\n' {
				buf = append(buf, '\n')
			}
			buf = append(buf, []byte("codex_hooks = true\n")...)
		} else {
			// Insert immediately before the first section. Make sure the
			// preceding bytes end with a newline so the new line stands
			// alone, and add a trailing blank line so it's visually
			// separated from the section header.
			buf = append(buf, existing[:insertAt]...)
			if len(buf) > 0 && buf[len(buf)-1] != '\n' {
				buf = append(buf, '\n')
			}
			buf = append(buf, []byte("codex_hooks = true\n\n")...)
			buf = append(buf, existing[insertAt:]...)
		}
		backup := fmt.Sprintf("%s.agentlock-backup-%d", tomlAbs, time.Now().UnixNano())
		return fileOp{
			Op:         "write",
			Path:       tomlAbs,
			Content:    string(buf),
			Reason:     fmt.Sprintf("insert codex_hooks = true at top of %s", tomlAbs),
			BackupPath: backup,
		}, fmt.Sprintf("added codex_hooks = true to %s (backup: %s)", tomlAbs, backup), true
	}
}

// firstSectionHeaderOffset returns the byte offset of the first line that
// starts (after whitespace) with `[`. Returns -1 when no section header
// exists in the file.
func firstSectionHeaderOffset(b []byte) int {
	cursor := 0
	for cursor < len(b) {
		nl := indexByteFrom(b, '\n', cursor)
		end := nl
		if end < 0 {
			end = len(b)
		}
		line := b[cursor:end]
		trimmed := strings.TrimSpace(string(line))
		if strings.HasPrefix(trimmed, "[") {
			return cursor
		}
		if nl < 0 {
			return -1
		}
		cursor = nl + 1
	}
	return -1
}

type codexFlagSpan struct{ start, end int }

// topLevelCodexFlag scans bytes for the first top-level (pre-section)
// `codex_hooks = (true|false)` line. Returns "" if none found.
func topLevelCodexFlag(b []byte) (string, codexFlagSpan) {
	cursor := 0
	for cursor < len(b) {
		nl := indexByteFrom(b, '\n', cursor)
		end := nl
		if end < 0 {
			end = len(b)
		}
		line := b[cursor:end]
		trimmed := strings.TrimSpace(string(line))
		if strings.HasPrefix(trimmed, "[") {
			return "", codexFlagSpan{}
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if m := codexFlagLineRegex.FindSubmatchIndex(line); m != nil {
				return string(line[m[2]:m[3]]), codexFlagSpan{cursor + m[0], cursor + m[1]}
			}
		}
		if nl < 0 {
			break
		}
		cursor = nl + 1
	}
	return "", codexFlagSpan{}
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

	ours := codexHookConfig(daemonURL, agentlockBinary)
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
