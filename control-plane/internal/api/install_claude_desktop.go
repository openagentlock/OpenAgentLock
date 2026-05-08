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

// claudeDesktopPlan returns the merged file ops the CLI should execute.
//
// Two surfaces:
//
//  1. claude_desktop_config.json — the manual mcpServers JSON path.
//     Each entry is rewritten through `agentlock mcp-proxy --name <id>
//     -- <orig-cmd> <args>`; original preserved under
//     `_agentlock_original` for clean restore.
//
//  2. Per-extension bundle manifests under
//     `<config-dir>/Claude Extensions/<ext-id>/manifest.json` — the
//     actual launch source for Desktop Extensions installed via
//     Settings → Extensions UI. Claude Desktop's manifest schema
//     validator is strict (`additionalProperties: false` everywhere),
//     so wrap markers can't live in the legacy `mcp_config._agentlock`
//     slot. Instead we use the schema-blessed root-level `_meta`
//     object (added in MCPB v0.3) — `_meta.agentlock.{wrapped,
//     original_command, original_args, original_env,
//     original_manifest_version}`. Manifest versions 0.1 / 0.2 (or
//     missing) are bumped to 0.3 on wrap; the original is stashed for
//     restore. Rewriting `mcp_config.command` to a non-`node`/non-
//     `python` binary defeats Claude Desktop's UtilityProcess
//     short-circuit and forces basic-execution spawn — that's how the
//     proxy ends up in the byte path.
//
// The Desktop Extensions registry (`extensions-installations.json`)
// is intentionally NOT wrapped — empirical probing (May 2026) showed
// it's an audit record only, not the launch source. Wrapping it
// would be dead text and risks fighting Anthropic's auto-update
// hash check. mergeExtensionRegistry / stripExtensionRegistry remain
// in this file as defensive helpers for cleanup of any stale wrap
// state, but the install path never emits a registry write op.
func claudeDesktopPlan(daemonURL, configDirOverride, agentlockBinary string, overrides map[string]string, existingFiles map[string]string) ([]fileOp, []string) {
	warnings := []string{
		"claude-desktop: agentlock gates MCP tool calls for both manual mcpServers entries (claude_desktop_config.json) and Desktop Extensions installed via Settings → Extensions UI. Each per-extension bundle manifest is rewritten in place; auto-updates from Anthropic may overwrite the wrap on extension version bumps — re-run `agentlock install` after extension updates. Other surfaces remain out of scope: Computer Use, integrated terminal, native connectors (Slack/GCal), Cowork's non-MCP paths, server-side cloud features. For full local enforcement of an agent harness, use Claude Code.",
	}

	ops := make([]fileOp, 0, 4)

	// claude_desktop_config.json — manual mcpServers path.
	configPath, err := claudeDesktopConfigPath(configDirOverride, overrides)
	if err != nil {
		configPath = "<unresolved: " + err.Error() + ">"
	}
	cfgAbs := configPath
	if a, err := filepath.Abs(configPath); err == nil {
		cfgAbs = a
	}
	var cfgExisting []byte
	cfgBackup := ""
	if c, ok := existingFiles[cfgAbs]; ok && c != "" {
		cfgExisting = []byte(c)
		cfgBackup = fmt.Sprintf("%s.agentlock-backup-%d", cfgAbs, time.Now().UnixNano())
	}
	merged, mergeErr := mergeClaudeDesktopConfig(cfgExisting, daemonURL, agentlockBinary)
	if mergeErr != nil {
		fresh := map[string]any{
			"mcpServers": map[string]any{
				claudeDesktopServerName: claudeDesktopServerEntry(daemonURL, agentlockBinary),
			},
		}
		merged, _ = json.MarshalIndent(fresh, "", "  ")
	}
	ops = append(ops, fileOp{
		Op:         "write",
		Path:       cfgAbs,
		Content:    string(merged),
		Reason:     fmt.Sprintf("register agentlock as MCP server in Claude Desktop → %s (no PreToolUse upstream)", strings.TrimRight(daemonURL, "/")),
		BackupPath: cfgBackup,
	})

	// Desktop Extension bundle manifests — _meta.agentlock wrap.
	bundlesDir, _ := claudeDesktopExtensionsDir(configDirOverride, overrides)
	if bundlesDir != "" {
		registryAbsPath, _ := extensionsRegistryPath(configDirOverride, overrides)
		settings := collectExtensionSettings(existingFiles, registryAbsPath)
		ops = append(ops, bundleManifestOps(bundlesDir, daemonURL, agentlockBinary, settings, existingFiles)...)
	}

	return ops, warnings
}

// claudeDesktopExtensionsDir returns the absolute path of
// "<config-dir>/Claude Extensions". Sibling of the registry — same
// override / dev-home / host-fallback resolution rules.
func claudeDesktopExtensionsDir(configDirOverride string, overrides map[string]string) (string, error) {
	cfg, err := claudeDesktopConfigPath(configDirOverride, overrides)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), "Claude Extensions"), nil
}

// bundleManifestOps walks existingFiles for any path of the form
// "<bundlesDir>/<ext-id>/manifest.json" and emits a wrap op for each
// matching extension that isn't disabled. Disabled extensions are
// either skipped (already-unwrapped) or unwrapped (if they were
// wrapped on a prior install). The CLI is responsible for sending
// each bundle manifest's contents in existing_files; manifests not
// supplied are silently skipped.
func bundleManifestOps(bundlesDir, daemonURL, agentlockBinary string, settings map[string]extensionSettings, existingFiles map[string]string) []fileOp {
	abs := bundlesDir
	if a, err := filepath.Abs(bundlesDir); err == nil {
		abs = a
	}
	var ops []fileOp
	for path, body := range existingFiles {
		// filepath.Base is platform-agnostic; strings.HasSuffix on a
		// hard-coded "/manifest.json" misses Windows paths that use
		// backslash separators when the CLI sends native-separator
		// paths (CodeRabbit finding).
		if filepath.Base(path) != "manifest.json" {
			continue
		}
		// path layout: <abs>/<extID>/manifest.json
		extDir := filepath.Dir(path)
		if filepath.Dir(extDir) != abs {
			continue
		}
		extID := filepath.Base(extDir)

		merged, ok := mergeBundleManifest([]byte(body), extID, daemonURL, agentlockBinary, settings)
		if !ok {
			continue
		}
		ops = append(ops, fileOp{
			Op:         "write",
			Path:       path,
			Content:    string(merged),
			Reason:     fmt.Sprintf("wrap Desktop Extension bundle %q → %s", extID, strings.TrimRight(daemonURL, "/")),
			BackupPath: fmt.Sprintf("%s.agentlock-backup-%d", path, time.Now().UnixNano()),
		})
	}
	return ops
}

// mergeBundleManifest parses one extension's on-disk manifest.json,
// applies wrapManifest (or restoreManifest when the extension is now
// disabled), and returns the new bytes. Returns ok=false when the
// manifest is unparseable or there's nothing to do (e.g. disabled
// extension that was never wrapped — no write op needed).
func mergeBundleManifest(existing []byte, extID, daemonURL, agentlockBinary string, settings map[string]extensionSettings) ([]byte, bool) {
	manifest := map[string]any{}
	if err := json.Unmarshal(existing, &manifest); err != nil {
		return nil, false
	}

	// Disabled extensions: unwind any prior wrap, no-op otherwise.
	// Leaving an unmodified disabled extension untouched avoids a
	// pointless write op every install run.
	if s, ok := settings[extID]; ok && !s.IsEnabled {
		if !restoreManifest(manifest) {
			return nil, false
		}
		out, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return nil, false
		}
		return out, true
	}

	if !wrapManifest(manifest, extID, daemonURL, agentlockBinary) {
		return nil, false
	}
	out, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, false
	}
	return out, true
}

// stripBundleManifest reverses the wrap on a single bundle manifest.
// Returns the new bytes plus 1 if a wrap was undone, 0 otherwise.
// Pure: no disk I/O.
func stripBundleManifest(existing []byte) ([]byte, int, error) {
	if len(existing) == 0 {
		return nil, 0, nil
	}
	manifest := map[string]any{}
	if err := json.Unmarshal(existing, &manifest); err != nil {
		return nil, 0, fmt.Errorf("parse bundle manifest: %w", err)
	}
	if !restoreManifest(manifest) {
		return nil, 0, nil
	}
	out, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("marshal: %w", err)
	}
	return out, 1, nil
}

// extensionsRegistryPath sits next to claude_desktop_config.json in the
// same Claude support dir. Anthropic stores the install record for every
// Desktop Extension here; the per-extension settings (isEnabled,
// userConfig) live one dir over in "Claude Extensions Settings/".
func extensionsRegistryPath(configDirOverride string, overrides map[string]string) (string, error) {
	cfg, err := claudeDesktopConfigPath(configDirOverride, overrides)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), "extensions-installations.json"), nil
}

// extensionSettings is the parsed shape of one
// "Claude Extensions Settings/<id>.json" file. We only need isEnabled
// today; userConfig is preserved on disk by Claude Desktop and not our
// concern.
type extensionSettings struct {
	IsEnabled bool `json:"isEnabled"`
}

// collectExtensionSettings walks existingFiles for any path that looks
// like a Claude Extensions Settings/<id>.json sibling of the registry
// path, parses each, and returns a map keyed by extension id. Missing
// or unparseable entries default to enabled — same behavior Claude
// Desktop seems to take when the settings file is absent on first run
// (we err on the side of wrapping; a disabled extension that we wrap
// is harmless because it's never spawned anyway).
func collectExtensionSettings(existingFiles map[string]string, registryAbsPath string) map[string]extensionSettings {
	out := map[string]extensionSettings{}
	settingsDir := filepath.Join(filepath.Dir(registryAbsPath), "Claude Extensions Settings")
	for path, body := range existingFiles {
		if filepath.Dir(path) != settingsDir {
			continue
		}
		base := filepath.Base(path)
		if !strings.HasSuffix(base, ".json") {
			continue
		}
		extID := strings.TrimSuffix(base, ".json")
		var parsed extensionSettings
		if err := json.Unmarshal([]byte(body), &parsed); err != nil {
			// Default to enabled on parse error — matches the "wrap
			// unless explicitly disabled" posture above.
			parsed.IsEnabled = true
		}
		out[extID] = parsed
	}
	return out
}

// wrapManifest rewrites one Desktop Extension manifest in place to
// route MCP traffic through `agentlock mcp-proxy --name <ext-id> --
// <orig-cmd> <args...>`. The schema-blessed `_meta.agentlock` slot
// (MCPB v0.3+) carries the originals so a strip can restore them.
//
// Two non-obvious moves:
//
//   - manifest_version is bumped from "0.1" / "0.2" / missing → "0.3"
//     when needed, so the validator accepts our `_meta` block. The
//     original is stashed under _meta.agentlock.original_manifest_version
//     (or _meta.agentlock.original_manifest_version_absent when the
//     field was missing) for byte-clean restore.
//
//   - mcp_config.command is rewritten to the agentlock binary path
//     (NOT "node" / "python"), which forces Claude Desktop's runtime
//     into the basic-execution branch. Otherwise, for type=node /
//     type=python extensions, Claude Desktop short-circuits via
//     UtilityProcess (Electron's built-in node) and would bypass our
//     wrap entirely. Empirically verified May 2026.
//
// Template variables in args (`${__dirname}`,
// `${user_config.<key>}`) pass through verbatim — Claude Desktop
// expands them at launch, the proxy spawns whatever it's handed.
//
// Returns true if the wrap was applied; false on shape mismatch
// (no `server.mcp_config`). Idempotent: re-wrapping reads the prior
// _meta.agentlock to recover real originals first.
func wrapManifest(manifest map[string]any, extID, daemonURL, agentlockBinary string) bool {
	server, ok := manifest["server"].(map[string]any)
	if !ok {
		return false
	}
	mcp, ok := server["mcp_config"].(map[string]any)
	if !ok {
		return false
	}

	bin := claudeCodeBinary(agentlockBinary)
	daemonURL = strings.TrimRight(daemonURL, "/")

	// Recover prior originals (if previously wrapped) so a re-wrap
	// reflects the user's true source state, not our wrapper.
	meta, _ := manifest["_meta"].(map[string]any)
	prior, _ := meta["agentlock"].(map[string]any)

	var (
		origCmd                 string
		origArgs                []any
		origEnv                 map[string]any
		origManifestVersion     string
		origManifestVersionMiss bool
	)
	if prior != nil {
		origCmd, _ = prior["original_command"].(string)
		origArgs, _ = prior["original_args"].([]any)
		origEnv, _ = prior["original_env"].(map[string]any)
		origManifestVersion, _ = prior["original_manifest_version"].(string)
		if a, ok := prior["original_manifest_version_absent"].(bool); ok && a {
			origManifestVersionMiss = true
		}
	} else {
		origCmd, _ = mcp["command"].(string)
		origArgs, _ = mcp["args"].([]any)
		origEnv, _ = mcp["env"].(map[string]any)
	}

	args := []any{"mcp-proxy", "--name", extID, "--", origCmd}
	args = append(args, origArgs...)

	env := map[string]any{}
	for k, v := range origEnv {
		env[k] = v
	}
	if _, ok := env["AGENTLOCK_DAEMON_URL"]; !ok {
		env["AGENTLOCK_DAEMON_URL"] = daemonURL
	}

	newMcp := map[string]any{
		"command": bin,
		"args":    args,
	}
	if len(env) > 0 {
		newMcp["env"] = env
	}
	server["mcp_config"] = newMcp

	// Bump manifest_version if the current value would reject _meta.
	// MCPB v0.3 added the field; v0.1 and v0.2 schemas are
	// additionalProperties:false at root and would reject it.
	mv, hasMV := manifest["manifest_version"].(string)
	shouldBump := !hasMV || mv == "0.1" || mv == "0.2"
	if shouldBump {
		// Stash the original on the FIRST wrap. Re-wrap re-uses what
		// we already recovered above from prior so we don't lose the
		// real source over multiple install runs.
		if prior == nil {
			if hasMV {
				origManifestVersion = mv
			} else {
				origManifestVersionMiss = true
			}
		}
		manifest["manifest_version"] = "0.3"
	}

	// dxt_version is the deprecated alias for manifest_version (kept for
	// older bundles that haven't migrated yet, e.g. Anthropic's own
	// Control Chrome ships dxt_version "0.1" with no manifest_version).
	// The v0.3 schema pins it to const "0.3" when present, so a stale
	// value must be bumped in lockstep or the validator rejects the
	// whole manifest with `dxt_version: Invalid literal value`.
	var (
		origDxtVersion       string
		origDxtVersionMiss   bool
	)
	if prior != nil {
		origDxtVersion, _ = prior["original_dxt_version"].(string)
		if a, ok := prior["original_dxt_version_absent"].(bool); ok && a {
			origDxtVersionMiss = true
		}
	}
	dxt, hasDxt := manifest["dxt_version"].(string)
	if hasDxt && dxt != "0.3" {
		if prior == nil {
			origDxtVersion = dxt
		}
		manifest["dxt_version"] = "0.3"
	} else if !hasDxt && prior == nil {
		origDxtVersionMiss = true
	}

	if meta == nil {
		meta = map[string]any{}
	}
	agentlockMeta := map[string]any{
		"wrapped":          true,
		"original_command": origCmd,
		"original_args":    origArgs,
	}
	if len(origEnv) > 0 {
		agentlockMeta["original_env"] = origEnv
	}
	if origManifestVersion != "" {
		agentlockMeta["original_manifest_version"] = origManifestVersion
	}
	if origManifestVersionMiss {
		agentlockMeta["original_manifest_version_absent"] = true
	}
	if origDxtVersion != "" {
		agentlockMeta["original_dxt_version"] = origDxtVersion
	}
	if origDxtVersionMiss {
		agentlockMeta["original_dxt_version_absent"] = true
	}
	meta["agentlock"] = agentlockMeta
	manifest["_meta"] = meta

	return true
}

// restoreManifest is wrapManifest's inverse: reads _meta.agentlock,
// restores server.mcp_config + manifest_version to their pre-wrap
// values, and deletes the agentlock namespace from _meta. If _meta
// has no other namespaces left it's removed entirely so the manifest
// returns to byte-equivalent shape on a v0.3 host. Returns true if
// a wrap was undone.
func restoreManifest(manifest map[string]any) bool {
	meta, _ := manifest["_meta"].(map[string]any)
	if meta == nil {
		return false
	}
	agentlockMeta, _ := meta["agentlock"].(map[string]any)
	if agentlockMeta == nil {
		return false
	}
	server, _ := manifest["server"].(map[string]any)
	if server == nil {
		return false
	}

	origCmd, _ := agentlockMeta["original_command"].(string)
	origArgs, _ := agentlockMeta["original_args"].([]any)
	origEnv, _ := agentlockMeta["original_env"].(map[string]any)

	restoredMcp := map[string]any{
		"command": origCmd,
		"args":    origArgs,
	}
	if len(origEnv) > 0 {
		restoredMcp["env"] = origEnv
	}
	server["mcp_config"] = restoredMcp

	if origMV, ok := agentlockMeta["original_manifest_version"].(string); ok && origMV != "" {
		manifest["manifest_version"] = origMV
	} else if a, ok := agentlockMeta["original_manifest_version_absent"].(bool); ok && a {
		delete(manifest, "manifest_version")
	}

	if origDxt, ok := agentlockMeta["original_dxt_version"].(string); ok && origDxt != "" {
		manifest["dxt_version"] = origDxt
	} else if a, ok := agentlockMeta["original_dxt_version_absent"].(bool); ok && a {
		delete(manifest, "dxt_version")
	}

	delete(meta, "agentlock")
	if len(meta) == 0 {
		delete(manifest, "_meta")
	}

	return true
}

// mergeExtensionRegistry walks each entry in extensions-installations.json
// and applies wrapManifest to its nested manifest. The registry is
// not the launch source (claudeDesktopPlan does not call this today)
// but the helper stays around so a future install pipeline that
// needs registry coherency can rely on it. Disabled extensions are
// unwrapped if previously wrapped, otherwise left alone.
//
// Idempotent: wrapManifest reads any prior _meta.agentlock first.
func mergeExtensionRegistry(existing []byte, daemonURL, agentlockBinary string, settings map[string]extensionSettings) ([]byte, error) {
	if len(existing) == 0 {
		return nil, fmt.Errorf("empty registry")
	}
	root := map[string]any{}
	if err := json.Unmarshal(existing, &root); err != nil {
		return nil, fmt.Errorf("parse extensions registry: %w", err)
	}
	extensions, _ := root["extensions"].(map[string]any)
	if extensions == nil {
		return json.MarshalIndent(root, "", "  ")
	}

	for extID, raw := range extensions {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		manifest, ok := entry["manifest"].(map[string]any)
		if !ok {
			continue
		}
		if s, ok := settings[extID]; ok && !s.IsEnabled {
			restoreManifest(manifest)
			continue
		}
		wrapManifest(manifest, extID, daemonURL, agentlockBinary)
	}
	return json.MarshalIndent(root, "", "  ")
}

// stripExtensionRegistry reverses the wrap for uninstall. Each
// extension whose nested manifest carries _meta.agentlock is
// restored. Non-wrapped entries pass through. Returns (newBytes,
// removalCount, error).
func stripExtensionRegistry(existing []byte) ([]byte, int, error) {
	if len(existing) == 0 {
		return nil, 0, nil
	}
	root := map[string]any{}
	if err := json.Unmarshal(existing, &root); err != nil {
		return nil, 0, fmt.Errorf("parse extensions registry: %w", err)
	}
	extensions, _ := root["extensions"].(map[string]any)
	if extensions == nil {
		return nil, 0, nil
	}

	removed := 0
	for _, raw := range extensions {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		manifest, ok := entry["manifest"].(map[string]any)
		if !ok {
			continue
		}
		if restoreManifest(manifest) {
			removed++
		}
	}

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("marshal: %w", err)
	}
	return out, removed, nil
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
