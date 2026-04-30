// Codex CLI install helpers — plan, apply, uninstall. The wire shape is
// JSON (~/.codex/hooks.json) but the transport is command-only: each
// hook entry spawns the agentlock shim, which in turn POSTs to the
// daemon. See docs/reference/hook-daemon-path.md.
//
// Codex's lifecycle hooks are gated by `codex_hooks = true` in
// ~/.codex/config.toml. Apply refuses if the flag is unset; we never
// write into the user's TOML.

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
	errCodexFlagDisabled = errors.New("codex_hooks = true is missing from config.toml; enable it before installing")
	codexFlagLineRegex   = regexp.MustCompile(`(?m)^\s*codex_hooks\s*=\s*(true|false)\b`)
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
	enabled, err := codexFlagEnabled(tomlPath)
	if err != nil {
		return installManifestE{}, fileOp{}, nil, err
	}
	if !enabled {
		return installManifestE{}, fileOp{}, nil, fmt.Errorf("%w (path: %s)", errCodexFlagDisabled, tomlPath)
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
		}, []string{codexMCPGapWarning}, nil
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
