package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

type detectReportRequest struct {
	SessionID  string              `json:"session_id"`
	Detections []storage.Detection `json:"detections"`
}

func detectReportHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("detect.report")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req detectReportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if err := d.Store.SaveDetections(r.Context(), req.SessionID, req.Detections); err != nil {
			if errors.Is(err, storage.ErrSessionNotFound) {
				writeError(w, http.StatusNotFound, "session_not_found", req.SessionID)
				return
			}
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"stored": len(req.Detections)})
	}
}

type installPlanRequest struct {
	SessionID         string   `json:"session_id"`
	Harnesses         []string `json:"harnesses"`
	DaemonURL         string   `json:"daemon_url"`
	ConfigDirOverride string   `json:"config_dir_override,omitempty"`
	// AgentlockBinary is the path Codex's command-hooks should spawn.
	// Optional: defaults to "agentlock" (resolved via PATH at hook time).
	// CLI callers should pass an absolute path so the dev loop and CI
	// don't depend on PATH lookups inside Codex's spawn environment.
	AgentlockBinary string `json:"agentlock_binary,omitempty"`
	// StatusLineScript is the absolute path to the small bash script the
	// CLI wrote at install time that prints "OpenAgentLock ✓ / ⚠ daemon
	// offline". When set, Claude Code's settings.json gets a statusLine
	// entry pointing at it. Empty means "skip the statusLine wiring."
	StatusLineScript string `json:"status_line_script,omitempty"`
	// HarnessConfigDirs lets the CLI pre-resolve per-harness config dirs
	// on the host, so the daemon doesn't probe its own os.UserHomeDir()
	// (which is /home/nonroot inside a container). Keys are harness ids
	// ("claude-code", "codex"). ConfigDirOverride still wins when set.
	HarnessConfigDirs map[string]string `json:"harness_config_dirs,omitempty"`
	// ExistingFiles carries the current utf8 contents of host files the
	// daemon needs to merge against when planning ops. Keys are absolute
	// paths; missing keys mean "file does not exist on the host." Set by
	// the CLI which has access to the real $HOME; the daemon never reads
	// host files itself in the new flow.
	ExistingFiles map[string]string `json:"existing_files,omitempty"`
}

type fileOp struct {
	Op         string `json:"op"`
	Path       string `json:"path"`
	Content    string `json:"content,omitempty"`
	Reason     string `json:"reason,omitempty"`
	BackupPath string `json:"backup_path,omitempty"`
}

// installPlanHandler computes the file ops needed to wire the selected
// harnesses up to the control-plane over HTTP hooks. It does NOT write —
// the CLI executes the returned ops on the host.
func installPlanHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("install.plan")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req installPlanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if req.DaemonURL == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "daemon_url required")
			return
		}
		if k, err := validateHarnessConfigDirs(req.HarnessConfigDirs, d.AgentlockHome); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_config_dir",
				fmt.Sprintf("%s (key=%s)", err.Error(), k))
			return
		}
		if _, err := d.Store.GetSession(r.Context(), req.SessionID); err != nil {
			if errors.Is(err, storage.ErrSessionNotFound) {
				writeError(w, http.StatusNotFound, "session_not_found", req.SessionID)
				return
			}
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}

		ops, skipped, warnings := buildPlanOps(req)
		writeJSON(w, http.StatusOK, map[string]any{
			"session_id": req.SessionID,
			"operations": ops,
			"skipped":    skipped,
			"warnings":   warnings,
			"applied":    false,
		})
	}
}

// buildPlanOps walks the requested harnesses and asks each plan helper to
// emit the file ops the CLI should execute. Shared between plan and apply
// so both endpoints return identical operation shapes.
func buildPlanOps(req installPlanRequest) ([]fileOp, []string, []string) {
	devHome := os.Getenv("AGENTLOCK_DEV_HOME")
	ops := make([]fileOp, 0)
	skipped := make([]string, 0)
	warnings := make([]string, 0)
	for _, h := range req.Harnesses {
		switch h {
		case "claude-code":
			ops = append(ops, claudeCodePlan(req.DaemonURL, req.ConfigDirOverride, req.AgentlockBinary, req.StatusLineScript, req.HarnessConfigDirs, req.ExistingFiles))
		case "claude-desktop":
			desktopOps, ws := claudeDesktopPlan(req.DaemonURL, req.ConfigDirOverride, req.AgentlockBinary, req.HarnessConfigDirs, req.ExistingFiles)
			ops = append(ops, desktopOps...)
			warnings = append(warnings, ws...)
		case "codex":
			codexOps, ws := codexPlan(req.DaemonURL, req.ConfigDirOverride, req.AgentlockBinary, req.HarnessConfigDirs, req.ExistingFiles)
			ops = append(ops, codexOps...)
			warnings = append(warnings, ws...)
		case "cursor":
			op, ws := cursorPlan(req.DaemonURL, req.ConfigDirOverride, req.AgentlockBinary, req.HarnessConfigDirs, req.ExistingFiles)
			ops = append(ops, op)
			warnings = append(warnings, ws...)
		case "gemini":
			op, ws := geminiPlan(req.DaemonURL, req.ConfigDirOverride, req.AgentlockBinary, req.HarnessConfigDirs, req.ExistingFiles)
			ops = append(ops, op)
			warnings = append(warnings, ws...)
		default:
			if devHome == "" || !knownHarnessID(h) {
				skipped = append(skipped, h)
				continue
			}
			ops = append(ops, devStubPlan(devHome, h, req.DaemonURL))
		}
	}
	return ops, skipped, warnings
}

// knownHarnessID is the daemon-side whitelist of harness ids the install
// pipeline recognises. It mirrors the CLI's HarnessId union — anything
// outside this set is rejected up-front so a bad payload can't trick the
// dev-stub branch into writing a file at an arbitrary nested path.
func knownHarnessID(h string) bool {
	switch h {
	case "codex", "opencode", "cursor", "cline", "continue",
		"gemini", "vscode-copilot":
		return true
	}
	return false
}

// devStubDir returns the directory inside the dev sandbox where the
// per-harness marker lives. Each harness gets its own ".<id>" subtree so
// it mirrors how its real config dir would look — codex → .codex,
// vscode-copilot → .vscode-copilot, etc.
func devStubDir(devHome, harness string) string {
	return filepath.Join(devHome, "."+harness)
}

// devStubPath is where the dev-mode marker JSON lands for a given harness.
func devStubPath(devHome, harness string) string {
	return filepath.Join(devStubDir(devHome, harness), ".agentlock-dev.json")
}

// devStubContent is the JSON body of the per-harness marker file. It
// records that agentlock acknowledged the harness in dev mode so a
// later real-integration commit can pick up where this left off.
func devStubContent(harness, daemonURL string) ([]byte, error) {
	body := map[string]any{
		"agentlock_dev": true,
		"harness":       harness,
		"daemon_url":    strings.TrimRight(daemonURL, "/"),
		"wired_at":      time.Now().UTC().Format(time.RFC3339Nano),
	}
	return json.MarshalIndent(body, "", "  ")
}

// devStubPlan describes the no-real-hooks dev marker write for a harness
// the daemon doesn't yet have a real installer for. Lets the picker /
// apply / ledger pipeline run against every harness while the per-harness
// integrations are still in flight. The CLI executes the actual write.
func devStubPlan(devHome, harness, daemonURL string) fileOp {
	body, _ := devStubContent(harness, daemonURL)
	return fileOp{
		Op:      "write",
		Path:    devStubPath(devHome, harness),
		Content: string(body),
		Reason:  fmt.Sprintf("dev sandbox marker for %s → %s", harness, daemonURL),
	}
}

// claudeCodeBinaryDefault is the command Claude Code spawns when no
// override is supplied. Relies on PATH; the CLI normally passes an
// absolute path so hook fire doesn't depend on PATH lookups inside the
// harness's spawn environment.
const claudeCodeBinaryDefault = "agentlock"

func claudeCodeBinary(override string) string {
	if override != "" {
		return override
	}
	return claudeCodeBinaryDefault
}

// claudeCodeHookConfig returns the hook config map we want merged into a
// Claude Code settings.json. Every outer entry carries "_agentlock": true
// so uninstall can identify our entries without relying on daemon_url.
//
// Transport is "command" (the shim binary), not "http" — keeping it
// uniform with codex/cursor lets daemon outages fail-open silently
// instead of surfacing as a red "PreToolUse:Bash hook error" banner on
// every tool call. The shim translates the daemon's claudeHookOutput
// response into Claude Code's exit-code / JSON contract.
func claudeCodeHookConfig(daemonURL, agentlockBinary string) map[string]any {
	bin := claudeCodeBinary(agentlockBinary)
	daemonURL = strings.TrimRight(daemonURL, "/")
	mk := func(event string, timeout int, withMatcher bool) map[string]any {
		entry := map[string]any{
			"_agentlock": true,
			"hooks": []any{
				map[string]any{
					"type":    "command",
					"command": fmt.Sprintf("%s hook claude-code %s", shellQuote(bin), event),
					"env": map[string]any{
						"AGENTLOCK_DAEMON_URL": daemonURL,
					},
					"timeout": timeout,
				},
			},
		}
		// Claude Code rejects `matcher` on SessionStart/Stop schema
		// validation; only the tool-scoped events accept it.
		if withMatcher {
			entry["matcher"] = "*"
		}
		return entry
	}
	return map[string]any{
		// SessionStart fires before any tool call when Claude Code boots
		// (or resumes, or clears). Wiring it is how the dashboard sees a
		// session appear at launch instead of waiting for the first tool.
		"SessionStart": []any{mk("session-start", 10, false)},
		"PreToolUse":   []any{mk("pre-tool-use", 60, true)},
		// PostToolUse isn't a gate — it's ledger completeness. Each
		// tool call gets a matching "ran to completion" entry so the
		// dashboard can distinguish a successful allow from a tool
		// that silently failed.
		"PostToolUse": []any{mk("post-tool-use", 10, true)},
		"Stop":        []any{mk("stop", 10, false)},
	}
}

// claudeCodeSettingsPath returns the settings.json path for the given
// override, or an error if we can't resolve the user's home and no
// override was supplied. Returning an error — rather than silently
// producing "/.claude/settings.json" — prevents the apply handler from
// suggesting writes into an attacker-friendly absolute path when HOME is unset.
//
// Precedence: --config-dir flag > harness_config_dirs[claude-code] (the
// CLI's host-resolved path) > AGENTLOCK_DEV_HOME > daemon's $HOME.
func claudeCodeSettingsPath(configDirOverride string, overrides map[string]string) (string, error) {
	dir := configDirOverride
	if dir == "" {
		if d := overrides["claude-code"]; d != "" {
			dir = d
		} else if devHome := os.Getenv("AGENTLOCK_DEV_HOME"); devHome != "" {
			// AGENTLOCK_DEV_HOME wins for source-build callers
			// (just cp-serve) that don't send harness_config_dirs.
			dir = filepath.Join(devHome, ".claude")
		} else if home, err := os.UserHomeDir(); err == nil && home != "" {
			dir = filepath.Join(home, ".claude")
		} else if envHome := os.Getenv("HOME"); envHome != "" {
			dir = filepath.Join(envHome, ".claude")
		} else {
			return "", fmt.Errorf("cannot resolve user home directory; set config_dir_override, AGENTLOCK_DEV_HOME, or HOME")
		}
	}
	return filepath.Join(dir, "settings.json"), nil
}

// claudeCodePlan returns the merged settings.json the CLI should write.
// When existingFiles[settingsPath] is set, we merge our hook entries into
// the existing JSON so user-set keys (model, enabledPlugins, custom hooks)
// survive. Otherwise we emit a fresh settings.json with just our hooks.
//
// The op carries op.BackupPath when an existing file was supplied — the
// CLI uses that as the suggested backup name and creates it during apply.
// The daemon never reads or writes host files in the new flow.
func claudeCodePlan(daemonURL, configDirOverride, agentlockBinary, statusLineScript string, overrides map[string]string, existingFiles map[string]string) fileOp {
	settingsPath, err := claudeCodeSettingsPath(configDirOverride, overrides)
	if err != nil {
		// Plan is informational — keep going with a placeholder so the
		// caller can still read the hook shape. Apply on the CLI side
		// will refuse to execute an op with this synthesized path.
		settingsPath = "<unresolved: " + err.Error() + ">"
	}
	abs := settingsPath
	if a, err := filepath.Abs(settingsPath); err == nil {
		abs = a
	}

	var existing []byte
	backupPath := ""
	if c, ok := existingFiles[abs]; ok && c != "" {
		existing = []byte(c)
		backupPath = fmt.Sprintf("%s.agentlock-backup-%d", abs, time.Now().UnixNano())
	}

	merged, mergeErr := mergeClaudeSettings(existing, daemonURL, agentlockBinary, statusLineScript)
	if mergeErr != nil {
		// Fall back to the agentlock-only payload so we still produce a
		// usable op; the CLI will surface the parse error when it sees
		// the existing file contents differ.
		hook := map[string]any{"hooks": claudeCodeHookConfig(daemonURL, agentlockBinary)}
		if statusLineScript != "" {
			hook["statusLine"] = claudeStatusLineEntry(statusLineScript)
		}
		merged, _ = json.MarshalIndent(hook, "", "  ")
	}
	return fileOp{
		Op:         "write",
		Path:       abs,
		Content:    string(merged),
		Reason:     fmt.Sprintf("wire Claude Code hooks → %s (via shim)", daemonURL),
		BackupPath: backupPath,
	}
}

// --- apply --------------------------------------------------------------

type installApplyResponse struct {
	SessionID    string   `json:"session_id"`
	Applied      bool     `json:"applied"`
	Operations   []fileOp `json:"operations"`
	ManifestPath string   `json:"manifest_path"`
	Skipped      []string `json:"skipped"`
	// Warnings are non-fatal install advisories (e.g. "Codex MCP tool
	// calls are not gated"). The CLI prints them; the manifest persists
	// them so subsequent dashboard / docs surfaces can replay them.
	Warnings []string `json:"warnings,omitempty"`
}

// installApplyHandler returns the same ops the plan endpoint would, then
// records the install in the manifest + ledger. The CLI is responsible
// for actually executing the ops on the host filesystem.
func installApplyHandler(d Deps) http.HandlerFunc {
	if d.Store == nil || d.AgentlockHome == "" {
		return todo("install.apply")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req installPlanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if req.DaemonURL == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "daemon_url required")
			return
		}
		if k, err := validateHarnessConfigDirs(req.HarnessConfigDirs, d.AgentlockHome); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_config_dir",
				fmt.Sprintf("%s (key=%s)", err.Error(), k))
			return
		}
		// Validate session_id shape up-front — same rule manifestPath
		// enforces — so we fail fast before any record-keeping work.
		if !sessionIDPattern.MatchString(req.SessionID) {
			writeError(w, http.StatusBadRequest, "invalid_session_id",
				"session_id must match [A-Za-z0-9_-]{1,128}")
			return
		}
		sess, err := d.Store.GetSession(r.Context(), req.SessionID)
		if err != nil {
			if errors.Is(err, storage.ErrSessionNotFound) {
				writeError(w, http.StatusNotFound, "session_not_found", req.SessionID)
				return
			}
			log.Printf("install.apply: GetSession: %v", err)
			writeError(w, http.StatusInternalServerError, "storage_error", "session lookup failed")
			return
		}

		ops, skipped, warnings := buildPlanOps(req)
		entries := make([]installManifestE, 0, len(ops))
		for _, op := range ops {
			harness := harnessForPath(op.Path)
			entries = append(entries, installManifestE{
				Harness:      harness,
				SettingsPath: op.Path,
				BackupPath:   op.BackupPath,
				DaemonURL:    req.DaemonURL,
			})
		}

		m := installManifest{
			SessionID: req.SessionID,
			AppliedAt: time.Now().UTC(),
			Entries:   entries,
		}
		if err := writeManifest(d.AgentlockHome, m); err != nil {
			log.Printf("install.apply: writeManifest: %v", err)
			writeError(w, http.StatusInternalServerError, "manifest_error", "failed to write install manifest")
			return
		}

		manifestBytes, err := json.Marshal(m)
		if err != nil {
			_ = deleteManifest(d.AgentlockHome, req.SessionID)
			log.Printf("install.apply: marshal manifest: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "manifest hash failed")
			return
		}
		payloadHash := sha256.Sum256(manifestBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "system",
			ToolUseID:   "install.apply",
			Signer:      sess.Signer,
			Verdict:     "allow",
			PayloadHash: payloadHash[:],
		}); err != nil {
			// Ledger is the source of truth; an install without a ledger
			// entry is worse than no install. Roll back the manifest so
			// a retry can see a clean state.
			if rmErr := deleteManifest(d.AgentlockHome, req.SessionID); rmErr != nil {
				log.Printf("install.apply: manifest rollback after ledger error: %v", rmErr)
			}
			log.Printf("install.apply: AppendLedger: %v", err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed; install rolled back")
			return
		}

		mPath, err := manifestPath(d.AgentlockHome, req.SessionID)
		if err != nil {
			// Already validated above, but keep the nil-safe path for
			// belt-and-suspenders in case the pattern ever changes.
			log.Printf("install.apply: manifestPath resolve: %v", err)
			writeError(w, http.StatusInternalServerError, "manifest_error", "manifest path resolve failed")
			return
		}
		writeJSON(w, http.StatusOK, installApplyResponse{
			SessionID:    req.SessionID,
			Applied:      true,
			Operations:   ops,
			ManifestPath: mPath,
			Skipped:      skipped,
			Warnings:     warnings,
		})
	}
}

// harnessForPath maps an op.Path back to the harness id we'd record in
// the manifest. The plan helpers always emit paths under a known
// per-harness file name (settings.json for Claude, hooks.json /
// config.toml for Codex/Cursor, .agentlock-dev.json for dev stubs), so
// a base-name + dir scan is sufficient — no need to plumb the harness
// through every fileOp.
func harnessForPath(path string) string {
	dir := filepath.Base(filepath.Dir(path))
	switch {
	case strings.HasSuffix(path, "claude_desktop_config.json"),
		strings.HasSuffix(path, "extensions-installations.json"):
		return "claude-desktop"
	case strings.HasSuffix(path, "manifest.json") &&
		strings.Contains(path, "/Claude Extensions/"):
		// Bundle manifest of a Desktop Extension. Path shape:
		// <config-dir>/Claude Extensions/<ext-id>/manifest.json.
		return "claude-desktop"
	case strings.HasSuffix(path, "settings.json"):
		// Gemini also writes settings.json (in ~/.gemini); disambiguate
		// by parent directory. Anything else is Claude Code.
		if dir == ".gemini" {
			return "gemini"
		}
		return "claude-code"
	case strings.HasSuffix(path, ".agentlock-dev.json"):
		// devStubDir is "<devHome>/.<harness>", so base of dir = ".harness"
		if strings.HasPrefix(dir, ".") {
			return strings.TrimPrefix(dir, ".")
		}
		return ""
	case strings.HasSuffix(path, "config.toml"):
		return "codex"
	case strings.HasSuffix(path, "hooks.json"):
		// Tell codex apart from cursor by the parent directory name.
		switch dir {
		case ".cursor":
			return "cursor"
		default:
			return "codex"
		}
	}
	return ""
}

// mergeClaudeSettings merges our hook entries into the existing settings.json
// bytes. Existing non-agentlock entries under hooks.PreToolUse / hooks.Stop
// are preserved. Our own (tagged with _agentlock:true) are replaced, so the
// operation is idempotent.
//
// When statusLineScript is non-empty we additionally write a statusLine
// entry tagged _agentlock:true so users see live "OpenAgentLock ✓ /
// ⚠ daemon offline" under their Claude Code chat. We never clobber a
// user-defined statusLine (one without our tag).
func mergeClaudeSettings(existing []byte, daemonURL, agentlockBinary, statusLineScript string) ([]byte, error) {
	settings := map[string]any{}
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &settings); err != nil {
			return nil, fmt.Errorf("parse existing settings: %w", err)
		}
	}

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}

	ours := claudeCodeHookConfig(daemonURL, agentlockBinary)
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
	settings["hooks"] = hooks

	if statusLineScript != "" {
		if existingSL, ok := settings["statusLine"].(map[string]any); ok && !isAgentlockEntry(existingSL) {
			// User has their own statusLine — leave it alone.
		} else {
			settings["statusLine"] = claudeStatusLineEntry(statusLineScript)
		}
	}

	return json.MarshalIndent(settings, "", "  ")
}

// claudeStatusLineEntry renders the settings.json statusLine block that
// points Claude Code at our health-check script. Claude Code passes this
// string through a shell on every UI render, so spaces in the path (e.g.
// macOS "Library/Application Support") need quoting too — same fix as
// the hook command writers above.
func claudeStatusLineEntry(scriptPath string) map[string]any {
	return map[string]any{
		"_agentlock": true,
		"type":       "command",
		"command":    shellQuote(scriptPath),
		"padding":    0,
	}
}

func isAgentlockEntry(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	b, _ := m["_agentlock"].(bool)
	return b
}

// shellQuote wraps a path in single quotes so a shell-interpreted hook
// command survives spaces (e.g. macOS "Library/Application Support").
// Hook configs across Claude Code / Codex / Cursor pass the command
// string through /bin/sh, which splits on unquoted whitespace and
// executes "/Users/ronaldli/Library/Application" as a script — that's
// the "line 1: on: command not found" failure mode that produced red
// "PreToolUse:hook error" banners in earlier installs. Single quotes
// are the simplest robust escape: macOS state dirs can't contain '\”.
// For the (extremely unlikely) edge case where they do, we fall back
// to the close-quote / escaped-quote / open-quote idiom.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// --- uninstall ----------------------------------------------------------

type installUninstallRequest struct {
	SessionID string `json:"session_id"`
	// ExistingFiles carries the current contents of the manifest's
	// settings paths so the daemon can compute the post-strip bytes
	// without reading host files. Optional — entries with missing keys
	// are treated as already-empty (the strip becomes a no-op).
	ExistingFiles map[string]string `json:"existing_files,omitempty"`
}

type uninstallOp struct {
	Op             string `json:"op"`
	Path           string `json:"path"`
	EntriesRemoved int    `json:"entries_removed"`
	// Content is the bytes the CLI should write back to Path after the
	// strip. Empty when the file had no agentlock entries (the CLI then
	// leaves the file untouched).
	Content string `json:"content,omitempty"`
	Error   string `json:"error,omitempty"`
}

type installUninstallResponse struct {
	SessionID   string        `json:"session_id"`
	Uninstalled bool          `json:"uninstalled"`
	Operations  []uninstallOp `json:"operations"`
	// Failures is a non-empty count when one or more entries could not
	// be stripped cleanly. Clients should treat Uninstalled=true with
	// Failures>0 as a partial success and retry (or manually inspect).
	Failures int `json:"failures"`
}

func installUninstallHandler(d Deps) http.HandlerFunc {
	if d.Store == nil || d.AgentlockHome == "" {
		return todo("install.uninstall")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req installUninstallRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if !sessionIDPattern.MatchString(req.SessionID) {
			writeError(w, http.StatusBadRequest, "invalid_session_id",
				"session_id must match [A-Za-z0-9_-]{1,128}")
			return
		}
		sess, err := d.Store.GetSession(r.Context(), req.SessionID)
		if err != nil {
			if errors.Is(err, storage.ErrSessionNotFound) {
				writeError(w, http.StatusNotFound, "session_not_found", req.SessionID)
				return
			}
			log.Printf("install.uninstall: GetSession: %v", err)
			writeError(w, http.StatusInternalServerError, "storage_error", "session lookup failed")
			return
		}
		m, err := readManifest(d.AgentlockHome, req.SessionID)
		if err != nil {
			if errors.Is(err, ErrManifestNotFound) {
				writeError(w, http.StatusNotFound, "manifest_not_found", req.SessionID)
				return
			}
			log.Printf("install.uninstall: readManifest: %v", err)
			writeError(w, http.StatusInternalServerError, "manifest_error", "manifest read failed")
			return
		}

		// Compute strip ops without touching disk. The CLI executes them.
		ops := make([]uninstallOp, 0, len(m.Entries))
		failures := 0
		for _, e := range m.Entries {
			op := uninstallOp{Op: "strip", Path: e.SettingsPath}
			existing := []byte(req.ExistingFiles[e.SettingsPath])
			var (
				newBytes []byte
				removed  int
				stripErr error
			)
			switch e.Harness {
			case "codex":
				newBytes, removed, stripErr = stripCodexHooks(existing)
			case "cursor":
				newBytes, removed, stripErr = stripCursorHooks(existing)
			case "gemini":
				newBytes, removed, stripErr = stripGeminiSettings(existing)
			case "claude-desktop":
				// Three file shapes land here:
				//   - claude_desktop_config.json (manual mcpServers path)
				//   - extensions-installations.json (Desktop Extensions registry)
				//   - <Claude Extensions>/<id>/manifest.json (bundle manifests, the actual launch source)
				if strings.HasSuffix(e.SettingsPath, "extensions-installations.json") {
					newBytes, removed, stripErr = stripExtensionRegistry(existing)
				} else if strings.HasSuffix(e.SettingsPath, "manifest.json") &&
					strings.Contains(e.SettingsPath, "/Claude Extensions/") {
					newBytes, removed, stripErr = stripBundleManifest(existing)
				} else {
					newBytes, removed, stripErr = stripClaudeDesktopConfig(existing)
				}
			default:
				// Default to Claude's settings.json shape. Older manifests
				// without a Harness field land here, which is the right
				// behavior — claude-code was the only harness pre-Codex.
				newBytes, removed, stripErr = stripClaudeSettings(existing)
			}
			if stripErr != nil {
				failures++
				op.Error = stripErr.Error()
				log.Printf("install.uninstall: strip %s (%s): %v", e.SettingsPath, e.Harness, stripErr)
			} else {
				op.EntriesRemoved = removed
				if removed > 0 {
					op.Content = string(newBytes)
				}
			}
			ops = append(ops, op)
		}

		// Archive only when every entry stripped cleanly — otherwise a
		// retry with the same session_id needs the manifest intact.
		if failures == 0 {
			if err := archiveManifest(d.AgentlockHome, req.SessionID); err != nil {
				log.Printf("install.uninstall: archive: %v", err)
				writeError(w, http.StatusInternalServerError, "archive_error", "archive manifest failed")
				return
			}
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id": req.SessionID,
			"ops":        ops,
			"failures":   failures,
		})
		if err != nil {
			log.Printf("install.uninstall: marshal payload: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload hash failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "system",
			ToolUseID:   "install.uninstall",
			Signer:      sess.Signer,
			Verdict:     "allow",
			PayloadHash: payloadHash[:],
		}); err != nil {
			log.Printf("install.uninstall: AppendLedger: %v", err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed")
			return
		}

		status := http.StatusOK
		if failures > 0 {
			status = http.StatusMultiStatus
		}
		writeJSON(w, status, installUninstallResponse{
			SessionID:   req.SessionID,
			Uninstalled: failures == 0,
			Operations:  ops,
			Failures:    failures,
		})
	}
}

// --- per-harness uninstall ---------------------------------------------
//
// installUninstallHarnessesHandler is the inverse of the install picker:
// the CLI sends the harness ids the user just deselected, the daemon
// computes the strip ops (new file contents) for each one, and the diff
// is logged to the ledger as a single entry. The CLI executes the
// returned ops. Lets a re-run of `agentlock install` honor unchecks
// without forcing the user to call a separate uninstall command.

type installUninstallHarnessesRequest struct {
	SessionID         string            `json:"session_id"`
	Harnesses         []string          `json:"harnesses"`
	ConfigDirOverride string            `json:"config_dir_override,omitempty"`
	HarnessConfigDirs map[string]string `json:"harness_config_dirs,omitempty"`
	// ExistingFiles carries the current contents of the per-harness
	// config files the daemon needs to strip. Same shape and rules as
	// installPlanRequest.ExistingFiles.
	ExistingFiles map[string]string `json:"existing_files,omitempty"`
}

func installUninstallHarnessesHandler(d Deps) http.HandlerFunc {
	if d.Store == nil || d.AgentlockHome == "" {
		return todo("install.uninstall_harnesses")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req installUninstallHarnessesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if !sessionIDPattern.MatchString(req.SessionID) {
			writeError(w, http.StatusBadRequest, "invalid_session_id",
				"session_id must match [A-Za-z0-9_-]{1,128}")
			return
		}
		if k, err := validateHarnessConfigDirs(req.HarnessConfigDirs, d.AgentlockHome); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_config_dir",
				fmt.Sprintf("%s (key=%s)", err.Error(), k))
			return
		}
		sess, err := d.Store.GetSession(r.Context(), req.SessionID)
		if err != nil {
			if errors.Is(err, storage.ErrSessionNotFound) {
				writeError(w, http.StatusNotFound, "session_not_found", req.SessionID)
				return
			}
			log.Printf("install.uninstall_harnesses: GetSession: %v", err)
			writeError(w, http.StatusInternalServerError, "storage_error", "session lookup failed")
			return
		}
		devHome := os.Getenv("AGENTLOCK_DEV_HOME")

		ops := make([]uninstallOp, 0, len(req.Harnesses))
		failures := 0
		for _, h := range req.Harnesses {
			switch h {
			case "claude-code":
				p, err := claudeCodeSettingsPath(req.ConfigDirOverride, req.HarnessConfigDirs)
				if err != nil {
					failures++
					ops = append(ops, uninstallOp{Op: "strip", Path: "<unresolved>", Error: err.Error()})
					continue
				}
				existing := []byte(req.ExistingFiles[p])
				newBytes, removed, stripErr := stripClaudeSettings(existing)
				op := uninstallOp{Op: "strip", Path: p}
				if stripErr != nil {
					failures++
					op.Error = stripErr.Error()
					log.Printf("install.uninstall_harnesses: strip %s: %v", p, stripErr)
				} else {
					op.EntriesRemoved = removed
					if removed > 0 {
						op.Content = string(newBytes)
					}
				}
				ops = append(ops, op)
			case "codex":
				p, err := codexHooksPath(req.ConfigDirOverride, req.HarnessConfigDirs)
				if err != nil {
					failures++
					ops = append(ops, uninstallOp{Op: "strip", Path: "<unresolved>", Error: err.Error()})
					continue
				}
				existing := []byte(req.ExistingFiles[p])
				newBytes, removed, stripErr := stripCodexHooks(existing)
				op := uninstallOp{Op: "strip", Path: p}
				if stripErr != nil {
					failures++
					op.Error = stripErr.Error()
					log.Printf("install.uninstall_harnesses: strip codex %s: %v", p, stripErr)
				} else {
					op.EntriesRemoved = removed
					if removed > 0 {
						op.Content = string(newBytes)
					}
				}
				ops = append(ops, op)
			case "cursor":
				p, err := cursorHooksPath(req.ConfigDirOverride, req.HarnessConfigDirs)
				if err != nil {
					failures++
					ops = append(ops, uninstallOp{Op: "strip", Path: "<unresolved>", Error: err.Error()})
					continue
				}
				existing := []byte(req.ExistingFiles[p])
				newBytes, removed, stripErr := stripCursorHooks(existing)
				op := uninstallOp{Op: "strip", Path: p}
				if stripErr != nil {
					failures++
					op.Error = stripErr.Error()
					log.Printf("install.uninstall_harnesses: strip cursor %s: %v", p, stripErr)
				} else {
					op.EntriesRemoved = removed
					if removed > 0 {
						op.Content = string(newBytes)
					}
				}
				ops = append(ops, op)
			case "gemini":
				p, err := geminiSettingsPath(req.ConfigDirOverride, req.HarnessConfigDirs)
				if err != nil {
					failures++
					ops = append(ops, uninstallOp{Op: "strip", Path: "<unresolved>", Error: err.Error()})
					continue
				}
				existing := []byte(req.ExistingFiles[p])
				newBytes, removed, stripErr := stripGeminiSettings(existing)
				op := uninstallOp{Op: "strip", Path: p}
				if stripErr != nil {
					failures++
					op.Error = stripErr.Error()
					log.Printf("install.uninstall_harnesses: strip gemini %s: %v", p, stripErr)
				} else {
					op.EntriesRemoved = removed
					if removed > 0 {
						op.Content = string(newBytes)
					}
				}
				ops = append(ops, op)
			case "claude-desktop":
				// Strip both files Claude Desktop install touches: the
				// mcpServers config (claude_desktop_config.json) and
				// the Desktop Extensions registry
				// (extensions-installations.json). Each is independent
				// — one can be missing without affecting the other.
				cfgP, err := claudeDesktopConfigPath(req.ConfigDirOverride, req.HarnessConfigDirs)
				if err != nil {
					failures++
					ops = append(ops, uninstallOp{Op: "strip", Path: "<unresolved>", Error: err.Error()})
				} else {
					cfgExisting := []byte(req.ExistingFiles[cfgP])
					newBytes, removed, stripErr := stripClaudeDesktopConfig(cfgExisting)
					op := uninstallOp{Op: "strip", Path: cfgP}
					if stripErr != nil {
						failures++
						op.Error = stripErr.Error()
						log.Printf("install.uninstall_harnesses: strip claude-desktop %s: %v", cfgP, stripErr)
					} else {
						op.EntriesRemoved = removed
						if removed > 0 {
							op.Content = string(newBytes)
						}
					}
					ops = append(ops, op)
				}
				if regP, err := extensionsRegistryPath(req.ConfigDirOverride, req.HarnessConfigDirs); err == nil {
					regExisting := []byte(req.ExistingFiles[regP])
					if len(regExisting) > 0 {
						newBytes, removed, stripErr := stripExtensionRegistry(regExisting)
						op := uninstallOp{Op: "strip", Path: regP}
						if stripErr != nil {
							failures++
							op.Error = stripErr.Error()
							log.Printf("install.uninstall_harnesses: strip claude-desktop extensions %s: %v", regP, stripErr)
						} else {
							op.EntriesRemoved = removed
							if removed > 0 {
								op.Content = string(newBytes)
							}
						}
						ops = append(ops, op)
					}
				}
				// Strip every per-extension bundle manifest the CLI sent
				// us. The on-disk manifest is THE launch source for
				// Desktop Extensions (probed empirically) so this is
				// what actually un-gates the user.
				bundlesDir, _ := claudeDesktopExtensionsDir(req.ConfigDirOverride, req.HarnessConfigDirs)
				if bundlesDir != "" {
					absBundles := bundlesDir
					if a, err := filepath.Abs(bundlesDir); err == nil {
						absBundles = a
					}
					for path, body := range req.ExistingFiles {
						if !strings.HasSuffix(path, "/manifest.json") {
							continue
						}
						if filepath.Dir(filepath.Dir(path)) != absBundles {
							continue
						}
						newBytes, removed, stripErr := stripBundleManifest([]byte(body))
						op := uninstallOp{Op: "strip", Path: path}
						if stripErr != nil {
							failures++
							op.Error = stripErr.Error()
							log.Printf("install.uninstall_harnesses: strip claude-desktop bundle %s: %v", path, stripErr)
						} else {
							op.EntriesRemoved = removed
							if removed > 0 {
								op.Content = string(newBytes)
							}
						}
						ops = append(ops, op)
					}
				}
			default:
				if devHome == "" || !knownHarnessID(h) {
					// No real installer + not in dev mode → nothing to do.
					ops = append(ops, uninstallOp{Op: "skip", Path: h})
					continue
				}
				p := devStubPath(devHome, h)
				ops = append(ops, uninstallOp{Op: "remove", Path: p, EntriesRemoved: 1})
			}
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id": req.SessionID,
			"harnesses":  req.Harnesses,
			"ops":        ops,
			"failures":   failures,
		})
		if err != nil {
			log.Printf("install.uninstall_harnesses: marshal payload: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload hash failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "system",
			ToolUseID:   "install.uninstall_harnesses",
			Signer:      sess.Signer,
			Verdict:     "allow",
			PayloadHash: payloadHash[:],
		}); err != nil {
			log.Printf("install.uninstall_harnesses: AppendLedger: %v", err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed")
			return
		}

		status := http.StatusOK
		if failures > 0 {
			status = http.StatusMultiStatus
		}
		writeJSON(w, status, installUninstallResponse{
			SessionID:   req.SessionID,
			Uninstalled: failures == 0,
			Operations:  ops,
			Failures:    failures,
		})
	}
}

// stripClaudeSettings parses the supplied settings.json bytes, removes
// every entry under hooks.<event> tagged _agentlock:true, trims empty
// containers, and returns the new bytes + count. Pure: no disk I/O. The
// CLI is responsible for writing the result back.
func stripClaudeSettings(existing []byte) ([]byte, int, error) {
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

	// Strip our statusLine entry too, leaving any user-defined one alone.
	if sl, ok := settings["statusLine"].(map[string]any); ok && isAgentlockEntry(sl) {
		delete(settings, "statusLine")
		removed++
	}

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("marshal: %w", err)
	}
	return out, removed, nil
}
