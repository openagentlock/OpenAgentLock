// Codex CLI install helpers — plan, apply, uninstall. The wire shape is
// JSON (~/.codex/hooks.json) but the transport is command-only: each
// hook entry spawns the agentlock shim, which in turn POSTs to the
// daemon. See docs/reference/hook-daemon-path.md.
//
// Codex's lifecycle hooks are gated by `codex_hooks = true` in
// ~/.codex/config.toml. Apply auto-enables the flag (creating the file
// if needed, backing it up if it existed) so users don't have to hand-
// edit their TOML before installing. The same checkSafeCodexTarget
// guard that protects hooks.json also protects config.toml — writes
// into a real ~/.codex still require AGENTLOCK_ALLOW_APPLY_REAL_HOME=1.

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
)

const codexMCPGapWarning = "Codex CLI: PreToolUse only fires for shell tool calls today. MCP tool calls are NOT gated by OpenAgentLock until upstream expands hook coverage."

var (
	codexFlagLineRegex = regexp.MustCompile(`(?m)^\s*codex_hooks\s*=\s*(true|false)\b`)
)

// codexHooksPath returns the absolute path to the hooks.json file we'd
// write. Mirrors claudeCodeSettingsPath: returning an error rather than
// a synthesized "/.codex/hooks.json" prevents apply from writing into
// an attacker-friendly absolute path when HOME is unset.
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

// codexFlagEnabled returns true when ~/.codex/config.toml has
// `codex_hooks = true` as a top-level key (i.e. before the first
// section header). A bare line scan beats pulling in a TOML parser
// for a single boolean probe. Same scan as cli/src/detect/codex.ts so
// the detector's preview matches the apply gate.
func codexFlagEnabled(configTomlPath string) (bool, error) {
	b, err := os.ReadFile(configTomlPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", configTomlPath, err)
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			break
		}
		m := codexFlagLineRegex.FindStringSubmatch(line)
		if m != nil {
			return m[1] == "true", nil
		}
	}
	return false, nil
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
					"command": fmt.Sprintf("%s hook codex %s", bin, event),
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

func codexPlan(daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string) (fileOp, []string) {
	hooksPath, err := codexHooksPath(configDirOverride, overrides)
	if err != nil {
		hooksPath = "<unresolved: " + err.Error() + ">"
	}
	body := map[string]any{"hooks": codexHookConfig(daemonURL, agentlockBinary)}
	b, _ := json.MarshalIndent(body, "", "  ")
	return fileOp{
		Op:      "write",
		Path:    hooksPath,
		Content: string(b),
		Reason:  fmt.Sprintf("wire Codex CLI hooks → %s (via shim)", daemonURL),
	}, []string{codexMCPGapWarning}
}

func applyCodex(daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string) (installManifestE, fileOp, []string, error) {
	tomlPath, err := codexConfigTomlPath(configDirOverride, overrides)
	if err != nil {
		return installManifestE{}, fileOp{}, nil, err
	}
	tomlNote, err := ensureCodexFlagEnabled(tomlPath)
	if err != nil {
		return installManifestE{}, fileOp{}, nil, err
	}
	warnings := []string{codexMCPGapWarning}
	if tomlNote != "" {
		warnings = append(warnings, tomlNote)
	}

	hooksPath, err := codexHooksPath(configDirOverride, overrides)
	if err != nil {
		return installManifestE{}, fileOp{}, nil, err
	}
	abs, err := filepath.Abs(hooksPath)
	if err != nil {
		return installManifestE{}, fileOp{}, nil, fmt.Errorf("resolve %s: %w", hooksPath, err)
	}
	if err := checkSafeCodexTarget(abs); err != nil {
		return installManifestE{}, fileOp{}, nil, err
	}

	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return installManifestE{}, fileOp{}, nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	existing, readErr := os.ReadFile(abs)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return installManifestE{}, fileOp{}, nil, fmt.Errorf("read %s: %w", abs, readErr)
	}

	backupPath := ""
	if len(existing) > 0 {
		backupPath = fmt.Sprintf("%s.agentlock-backup-%d", abs, time.Now().UnixNano())
		if err := policy.AtomicWriteFile(backupPath, existing, 0o600); err != nil {
			return installManifestE{}, fileOp{}, nil, fmt.Errorf("write backup: %w", err)
		}
	}

	merged, err := mergeCodexHooks(existing, daemonURL, agentlockBinary)
	if err != nil {
		return installManifestE{}, fileOp{}, nil, err
	}
	if err := policy.AtomicWriteFile(abs, merged, 0o644); err != nil {
		return installManifestE{}, fileOp{}, nil, fmt.Errorf("write hooks.json: %w", err)
	}

	return installManifestE{
			Harness:      "codex",
			SettingsPath: abs,
			BackupPath:   backupPath,
			DaemonURL:    daemonURL,
		}, fileOp{
			Op:         "write",
			Path:       abs,
			Reason:     fmt.Sprintf("wired Codex CLI hooks → %s (via shim)", daemonURL),
			BackupPath: backupPath,
		}, warnings, nil
}

// ensureCodexFlagEnabled idempotently makes sure
// `codex_hooks = true` is a top-level key in the user's config.toml.
// Cases:
//  1. file missing → create with `codex_hooks = true\n`
//  2. flag missing → append `codex_hooks = true\n`
//  3. flag = false → rewrite to true (with backup)
//  4. flag = true → no-op
//
// Returns a human-readable note when a write happened (empty string =
// no change), so the caller can surface it as an install warning. The
// real-home guard mirrors hooks.json: writes into a real ~/.codex
// require AGENTLOCK_ALLOW_APPLY_REAL_HOME=1.
func ensureCodexFlagEnabled(tomlPath string) (string, error) {
	abs, err := filepath.Abs(tomlPath)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", tomlPath, err)
	}
	if err := checkSafeCodexTarget(abs); err != nil {
		return "", err
	}

	existing, readErr := os.ReadFile(abs)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return "", fmt.Errorf("read %s: %w", abs, readErr)
	}

	// Case 1: file missing → create with the flag set.
	if errors.Is(readErr, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(abs), err)
		}
		if err := policy.AtomicWriteFile(abs, []byte("codex_hooks = true\n"), 0o644); err != nil {
			return "", fmt.Errorf("write %s: %w", abs, err)
		}
		return fmt.Sprintf("created %s with codex_hooks = true", abs), nil
	}

	// Look only at top-level (pre-first-section) lines, mirroring
	// codexFlagEnabled.
	state, idx := topLevelCodexFlag(existing)
	switch state {
	case "true":
		return "", nil // case 4: already set
	case "false":
		// case 3: rewrite the matching line.
		updated := append([]byte(nil), existing[:idx.start]...)
		updated = append(updated, []byte("codex_hooks = true")...)
		updated = append(updated, existing[idx.end:]...)
		backup := fmt.Sprintf("%s.agentlock-backup-%d", abs, time.Now().UnixNano())
		if err := policy.AtomicWriteFile(backup, existing, 0o600); err != nil {
			return "", fmt.Errorf("write backup: %w", err)
		}
		if err := policy.AtomicWriteFile(abs, updated, 0o644); err != nil {
			return "", fmt.Errorf("write %s: %w", abs, err)
		}
		return fmt.Sprintf("flipped codex_hooks false→true in %s (backup: %s)", abs, backup), nil
	default:
		// case 2: append. Make sure we don't glue onto a partial line.
		var buf []byte
		buf = append(buf, existing...)
		if len(buf) > 0 && buf[len(buf)-1] != '\n' {
			buf = append(buf, '\n')
		}
		buf = append(buf, []byte("codex_hooks = true\n")...)
		backup := fmt.Sprintf("%s.agentlock-backup-%d", abs, time.Now().UnixNano())
		if err := policy.AtomicWriteFile(backup, existing, 0o600); err != nil {
			return "", fmt.Errorf("write backup: %w", err)
		}
		if err := policy.AtomicWriteFile(abs, buf, 0o644); err != nil {
			return "", fmt.Errorf("write %s: %w", abs, err)
		}
		return fmt.Sprintf("added codex_hooks = true to %s (backup: %s)", abs, backup), nil
	}
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

// checkSafeCodexTarget refuses to let apply write into the developer's
// real ~/.codex directory, mirroring checkSafeClaudeTarget. Fail-SAFE:
// if HOME can't be resolved, treat the target as unsafe.
func checkSafeCodexTarget(absPath string) error {
	if os.Getenv("AGENTLOCK_ALLOW_APPLY_REAL_HOME") == "1" {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		if h := os.Getenv("HOME"); h != "" {
			home = h
		} else {
			return fmt.Errorf("%w: cannot determine $HOME; refusing to apply", errUnsafeTarget)
		}
	}
	absHome, err := filepath.Abs(home)
	if err != nil {
		return fmt.Errorf("%w: resolve home: %v", errUnsafeTarget, err)
	}
	resolvedHome, err := filepath.EvalSymlinks(absHome)
	if err != nil {
		resolvedHome = absHome
	}
	realCodex := filepath.Clean(filepath.Join(resolvedHome, ".codex"))

	resolvedTarget := absPath
	dirResolved, derr := filepath.EvalSymlinks(filepath.Dir(absPath))
	if derr == nil {
		resolvedTarget = filepath.Join(dirResolved, filepath.Base(absPath))
	}
	resolvedTarget = filepath.Clean(resolvedTarget)

	rel, err := filepath.Rel(realCodex, resolvedTarget)
	if err != nil {
		return nil
	}
	if rel == "." || (!strings.HasPrefix(rel, "..") && !strings.HasPrefix(rel, string(os.PathSeparator))) {
		return fmt.Errorf("%w: %s", errUnsafeTarget, absPath)
	}
	return nil
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

// stripCodexHooks loads the current hooks.json, removes every entry
// tagged _agentlock:true, trims empty containers, and writes it back.
// Mirrors stripClaudeSettings.
func stripCodexHooks(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	root := map[string]any{}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &root); err != nil {
			return 0, fmt.Errorf("parse %s: %w", path, err)
		}
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
		return 0, nil
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
		return 0, fmt.Errorf("marshal: %w", err)
	}
	if err := policy.AtomicWriteFile(path, out, 0o644); err != nil {
		return 0, fmt.Errorf("write %s: %w", path, err)
	}
	return removed, nil
}
