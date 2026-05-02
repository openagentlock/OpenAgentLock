// Cursor IDE install helpers — plan, apply, uninstall. Cursor's hook
// config lives at ~/.cursor/hooks.json with a top-level `version: 1` and
// camelCase event keys (`preToolUse`, `sessionStart`, ...). Transport
// is command-only: each entry spawns the agentlock shim, which POSTs
// to /v1/hooks/cursor/<event> and translates the daemon response into
// Cursor's `{permission, agent_message?}` shape.
//
// Unlike Codex, Cursor's hooks are on by default — no config flag
// gate. We still refuse to write into the developer's real ~/.cursor
// unless AGENTLOCK_ALLOW_APPLY_REAL_HOME=1 is set.

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
)

// cursorHooksPath returns the absolute path to hooks.json under the
// chosen Cursor config directory.
//
// Precedence: --config-dir flag > harness_config_dirs[cursor] (the
// CLI's host-resolved path) > AGENTLOCK_DEV_HOME > daemon's $HOME.
// Mirrors claudeCodeSettingsPath so the container/host bind-mount
// posture is consistent across harnesses.
func cursorHooksPath(configDirOverride string, overrides map[string]string) (string, error) {
	dir, err := cursorConfigDir(configDirOverride, overrides)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hooks.json"), nil
}

func cursorConfigDir(configDirOverride string, overrides map[string]string) (string, error) {
	if configDirOverride != "" {
		return configDirOverride, nil
	}
	if d := overrides["cursor"]; d != "" {
		return d, nil
	}
	if devHome := os.Getenv("AGENTLOCK_DEV_HOME"); devHome != "" {
		return filepath.Join(devHome, ".cursor"), nil
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".cursor"), nil
	}
	if envHome := os.Getenv("HOME"); envHome != "" {
		return filepath.Join(envHome, ".cursor"), nil
	}
	return "", fmt.Errorf("cannot resolve user home directory; set config_dir_override, AGENTLOCK_DEV_HOME, or HOME")
}

const cursorBinaryDefault = "agentlock"

func cursorBinary(override string) string {
	if override != "" {
		return override
	}
	return cursorBinaryDefault
}

// cursorHookConfig returns the hooks map merged into hooks.json under
// the top-level "hooks" key. Each outer entry carries "_agentlock":
// true so uninstall can identify our entries without depending on
// daemon URL or shim path. Event keys are Cursor's native camelCase.
//
// Wired events:
//   - sessionStart            (observability; harness boot)
//   - preToolUse              (gate; generic tool calls)
//   - beforeShellExecution    (gate; shell-specific intercepts)
//   - beforeMCPExecution      (gate; MCP tool calls — deduped vs preToolUse)
//   - afterMCPExecution       (observability; deduped vs postToolUse)
//   - postToolUse             (observability; tool completion)
//   - sessionEnd              (observability; harness shutdown)
//
// Cursor 2.x's validator expects a FLAT entry shape: `command` is a
// string directly on the entry, not nested inside an inner
// `hooks: [{type, command, ...}]` wrapper the way Claude / Codex
// structure theirs. Cursor logs `Hook script command must be a string`
// when it sees the nested form, then refuses to load any entry. The
// loader tolerates extra keys (`_agentlock`, `env`, `timeout`,
// `matcher`) so we keep them at the top level.
//
// Cursor's `failClosed` defaults to false; we leave it omitted to
// preserve the harness default and let operators opt in by hand if
// they want fail-closed semantics. Parity with Codex/Claude.
func cursorHookConfig(daemonURL, agentlockBinary string) map[string]any {
	bin := cursorBinary(agentlockBinary)
	mk := func(event string, timeout int) map[string]any {
		return map[string]any{
			"_agentlock": true,
			"matcher":    "*",
			"type":       "command",
			"command":    fmt.Sprintf("%s hook cursor %s", bin, event),
			"env": map[string]any{
				"AGENTLOCK_DAEMON_URL": strings.TrimRight(daemonURL, "/"),
			},
			"timeout": timeout,
		}
	}
	// Cursor uses `sessionEnd` for the close event, not `stop`.
	return map[string]any{
		"sessionStart":         []any{mk("session-start", 10)},
		"preToolUse":           []any{mk("pre-tool-use", 60)},
		"beforeShellExecution": []any{mk("before-shell-execution", 60)},
		"beforeMCPExecution":   []any{mk("before-mcp-execution", 60)},
		"afterMCPExecution":    []any{mk("after-mcp-execution", 10)},
		"postToolUse":          []any{mk("post-tool-use", 10)},
		"sessionEnd":           []any{mk("stop", 10)},
	}
}

// cursorPlan returns the file op for a Cursor install. The warnings
// slice is currently empty (Cursor has no flag-gate caveat analogous
// to Codex), but we keep the return shape to leave room for future
// MCP-specific advisories.
func cursorPlan(daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string) (fileOp, []string) {
	hooksPath, err := cursorHooksPath(configDirOverride, overrides)
	if err != nil {
		hooksPath = "<unresolved: " + err.Error() + ">"
	}
	body := map[string]any{
		"version": 1,
		"hooks":   cursorHookConfig(daemonURL, agentlockBinary),
	}
	b, _ := json.MarshalIndent(body, "", "  ")
	return fileOp{
		Op:      "write",
		Path:    hooksPath,
		Content: string(b),
		Reason:  fmt.Sprintf("wire Cursor hooks → %s (via shim)", daemonURL),
	}, nil
}

func applyCursor(daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string) (installManifestE, fileOp, error) {
	hooksPath, err := cursorHooksPath(configDirOverride, overrides)
	if err != nil {
		return installManifestE{}, fileOp{}, err
	}
	abs, err := filepath.Abs(hooksPath)
	if err != nil {
		return installManifestE{}, fileOp{}, fmt.Errorf("resolve %s: %w", hooksPath, err)
	}
	if err := checkSafeCursorTarget(abs); err != nil {
		return installManifestE{}, fileOp{}, err
	}

	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return installManifestE{}, fileOp{}, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	existing, readErr := os.ReadFile(abs)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return installManifestE{}, fileOp{}, fmt.Errorf("read %s: %w", abs, readErr)
	}

	backupPath := ""
	if len(existing) > 0 {
		backupPath = fmt.Sprintf("%s.agentlock-backup-%d", abs, time.Now().UnixNano())
		if err := policy.AtomicWriteFile(backupPath, existing, 0o600); err != nil {
			return installManifestE{}, fileOp{}, fmt.Errorf("write backup: %w", err)
		}
	}

	merged, err := mergeCursorHooks(existing, daemonURL, agentlockBinary)
	if err != nil {
		return installManifestE{}, fileOp{}, err
	}
	if err := policy.AtomicWriteFile(abs, merged, 0o644); err != nil {
		return installManifestE{}, fileOp{}, fmt.Errorf("write hooks.json: %w", err)
	}

	return installManifestE{
			Harness:      "cursor",
			SettingsPath: abs,
			BackupPath:   backupPath,
			DaemonURL:    daemonURL,
		}, fileOp{
			Op:         "write",
			Path:       abs,
			Reason:     fmt.Sprintf("wired Cursor hooks → %s (via shim)", daemonURL),
			BackupPath: backupPath,
		}, nil
}

// checkSafeCursorTarget refuses to let apply write into the developer's
// real ~/.cursor directory. Mirrors checkSafeCodexTarget / checkSafeClaudeTarget.
func checkSafeCursorTarget(absPath string) error {
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
	realCursor := filepath.Clean(filepath.Join(resolvedHome, ".cursor"))

	resolvedTarget := absPath
	dirResolved, derr := filepath.EvalSymlinks(filepath.Dir(absPath))
	if derr == nil {
		resolvedTarget = filepath.Join(dirResolved, filepath.Base(absPath))
	}
	resolvedTarget = filepath.Clean(resolvedTarget)

	rel, err := filepath.Rel(realCursor, resolvedTarget)
	if err != nil {
		return nil
	}
	if rel == "." || (!strings.HasPrefix(rel, "..") && !strings.HasPrefix(rel, string(os.PathSeparator))) {
		return fmt.Errorf("%w: %s", errUnsafeTarget, absPath)
	}
	return nil
}

// mergeCursorHooks merges our entries into existing hooks.json bytes,
// preserving any non-_agentlock entries the user added by hand and any
// pre-existing top-level fields (notably `version`). Idempotent:
// re-applying replaces our own entries rather than duplicating them.
func mergeCursorHooks(existing []byte, daemonURL, agentlockBinary string) ([]byte, error) {
	root := map[string]any{}
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &root); err != nil {
			return nil, fmt.Errorf("parse existing hooks.json: %w", err)
		}
	}

	hooks, _ := root["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}

	ours := cursorHookConfig(daemonURL, agentlockBinary)
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

	// Always carry a top-level version field. Preserve whatever the
	// user had if present; otherwise default to 1 (the only Cursor
	// hooks schema version we know of as of 1.7).
	if _, has := root["version"]; !has {
		root["version"] = 1
	}

	return json.MarshalIndent(root, "", "  ")
}

// stripCursorHooks loads the current hooks.json, removes every entry
// tagged _agentlock:true, trims empty containers, and writes it back.
// Mirrors stripCodexHooks. Preserves the top-level version field and
// any non-_agentlock user entries.
func stripCursorHooks(path string) (int, error) {
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
	} else {
		root["hooks"] = hooks
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
