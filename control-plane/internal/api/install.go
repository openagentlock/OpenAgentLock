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

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
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
	// HarnessConfigDirs lets the CLI pre-resolve per-harness config dirs
	// on the host, so the daemon doesn't probe its own os.UserHomeDir()
	// (which is /home/nonroot inside a container). Keys are harness ids
	// ("claude-code", "codex"). ConfigDirOverride still wins when set.
	HarnessConfigDirs map[string]string `json:"harness_config_dirs,omitempty"`
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
// apply is a separate, gated endpoint.
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

		devHome := os.Getenv("AGENTLOCK_DEV_HOME")
		ops := make([]fileOp, 0)
		skipped := make([]string, 0)
		warnings := make([]string, 0)
		for _, h := range req.Harnesses {
			switch h {
			case "claude-code":
				ops = append(ops, claudeCodePlan(req.DaemonURL, req.ConfigDirOverride, req.HarnessConfigDirs))
			case "codex":
				op, ws := codexPlan(req.DaemonURL, req.ConfigDirOverride, req.AgentlockBinary, req.HarnessConfigDirs)
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
		writeJSON(w, http.StatusOK, map[string]any{
			"session_id": req.SessionID,
			"operations": ops,
			"skipped":    skipped,
			"warnings":   warnings,
			"applied":    false,
			"apply_note": "Use POST /v1/install/apply with AGENTLOCK_ALLOW_APPLY=1 to actually write files.",
		})
	}
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

// devStubPath is where devStubPlan / applyDevStub would write the marker
// JSON for a given harness inside the dev sandbox.
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
// integrations are still in flight.
func devStubPlan(devHome, harness, daemonURL string) fileOp {
	return fileOp{
		Op:     "write",
		Path:   devStubPath(devHome, harness),
		Reason: fmt.Sprintf("dev sandbox marker for %s → %s", harness, daemonURL),
	}
}

// claudeCodeHookConfig returns the hook config map we want merged into a
// Claude Code settings.json. Every outer entry carries "_agentlock": true
// so uninstall can identify our entries without relying on daemon_url.
// URLs target the harness-shaped endpoints under /v1/hooks/claude-code/*
// which consume Claude's native hook body and emit Claude's expected
// hookSpecificOutput shape.
func claudeCodeHookConfig(daemonURL string) map[string]any {
	daemonURL = strings.TrimRight(daemonURL, "/")
	return map[string]any{
		// SessionStart fires before any tool call when Claude Code boots
		// (or resumes, or clears). Wiring it is how the dashboard sees a
		// session appear at launch instead of waiting for the first tool.
		"SessionStart": []any{
			map[string]any{
				"_agentlock": true,
				"hooks": []any{
					map[string]any{
						"type":    "http",
						"url":     daemonURL + "/v1/hooks/claude-code/session-start",
						"timeout": 10,
					},
				},
			},
		},
		"PreToolUse": []any{
			map[string]any{
				"_agentlock": true,
				"matcher":    "*",
				"hooks": []any{
					map[string]any{
						"type":    "http",
						"url":     daemonURL + "/v1/hooks/claude-code/pre-tool-use",
						"timeout": 60,
					},
				},
			},
		},
		// PostToolUse isn't a gate — it's ledger completeness. Each
		// tool call gets a matching "ran to completion" entry so the
		// dashboard can distinguish a successful allow from a tool
		// that silently failed.
		"PostToolUse": []any{
			map[string]any{
				"_agentlock": true,
				"matcher":    "*",
				"hooks": []any{
					map[string]any{
						"type":    "http",
						"url":     daemonURL + "/v1/hooks/claude-code/post-tool-use",
						"timeout": 10,
					},
				},
			},
		},
		"Stop": []any{
			map[string]any{
				"_agentlock": true,
				"hooks": []any{
					map[string]any{
						"type":    "http",
						"url":     daemonURL + "/v1/hooks/claude-code/stop",
						"timeout": 10,
					},
				},
			},
		},
	}
}

// claudeCodeSettingsPath returns the settings.json path for the given
// override, or an error if we can't resolve the user's home and no
// override was supplied. Returning an error — rather than silently
// producing "/.claude/settings.json" — prevents the apply handler from
// writing into an attacker-friendly absolute path when HOME is unset.
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

func claudeCodePlan(daemonURL, configDirOverride string, overrides map[string]string) fileOp {
	settingsPath, err := claudeCodeSettingsPath(configDirOverride, overrides)
	if err != nil {
		// Plan is informational — keep going with a placeholder so the
		// caller can still read the hook shape. Apply will refuse to
		// write this path.
		settingsPath = "<unresolved: " + err.Error() + ">"
	}
	hook := map[string]any{"hooks": claudeCodeHookConfig(daemonURL)}
	b, _ := json.MarshalIndent(hook, "", "  ")
	return fileOp{
		Op:      "write",
		Path:    settingsPath,
		Content: string(b),
		Reason:  fmt.Sprintf("wire Claude Code hooks → %s", daemonURL),
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

func installApplyHandler(d Deps) http.HandlerFunc {
	if d.Store == nil || d.AgentlockHome == "" {
		return todo("install.apply")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("AGENTLOCK_ALLOW_APPLY") != "1" {
			writeError(w, http.StatusForbidden, "apply_disabled",
				"set AGENTLOCK_ALLOW_APPLY=1 to enable install apply")
			return
		}
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
		// enforces — so we fail fast before any filesystem work.
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

		devHome := os.Getenv("AGENTLOCK_DEV_HOME")
		entries := make([]installManifestE, 0)
		ops := make([]fileOp, 0)
		skipped := make([]string, 0)
		warnings := make([]string, 0)
		for _, h := range req.Harnesses {
			switch h {
			case "claude-code":
				entry, op, err := applyClaudeCode(req.DaemonURL, req.ConfigDirOverride, req.HarnessConfigDirs)
				if err != nil {
					if errors.Is(err, errUnsafeTarget) {
						writeError(w, http.StatusForbidden, "unsafe_target", err.Error())
						return
					}
					log.Printf("install.apply: applyClaudeCode: %v", err)
					writeError(w, http.StatusInternalServerError, "apply_error", "claude-code install failed")
					return
				}
				entries = append(entries, entry)
				ops = append(ops, op)
			case "codex":
				entry, op, ws, err := applyCodex(req.DaemonURL, req.ConfigDirOverride, req.AgentlockBinary, req.HarnessConfigDirs)
				if err != nil {
					if errors.Is(err, errUnsafeTarget) {
						writeError(w, http.StatusForbidden, "unsafe_target", err.Error())
						return
					}
					log.Printf("install.apply: applyCodex: %v", err)
					writeError(w, http.StatusInternalServerError, "apply_error", "codex install failed")
					return
				}
				entries = append(entries, entry)
				ops = append(ops, op)
				warnings = append(warnings, ws...)
			default:
				if devHome == "" || !knownHarnessID(h) {
					skipped = append(skipped, h)
					continue
				}
				entry, op, err := applyDevStub(devHome, h, req.DaemonURL)
				if err != nil {
					log.Printf("install.apply: applyDevStub %s: %v", h, err)
					writeError(w, http.StatusInternalServerError, "apply_error",
						fmt.Sprintf("%s dev stub install failed", h))
					return
				}
				entries = append(entries, entry)
				ops = append(ops, op)
			}
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

var errUnsafeTarget = errors.New("target path resolves under real home .claude; set AGENTLOCK_ALLOW_APPLY_REAL_HOME=1 to override")

func applyClaudeCode(daemonURL, configDirOverride string, overrides map[string]string) (installManifestE, fileOp, error) {
	settingsPath, err := claudeCodeSettingsPath(configDirOverride, overrides)
	if err != nil {
		return installManifestE{}, fileOp{}, err
	}
	abs, err := filepath.Abs(settingsPath)
	if err != nil {
		return installManifestE{}, fileOp{}, fmt.Errorf("resolve %s: %w", settingsPath, err)
	}
	if err := checkSafeClaudeTarget(abs); err != nil {
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

	merged, err := mergeClaudeSettings(existing, daemonURL)
	if err != nil {
		return installManifestE{}, fileOp{}, err
	}
	if err := policy.AtomicWriteFile(abs, merged, 0o644); err != nil {
		return installManifestE{}, fileOp{}, fmt.Errorf("write settings: %w", err)
	}

	return installManifestE{
			Harness:      "claude-code",
			SettingsPath: abs,
			BackupPath:   backupPath,
			DaemonURL:    daemonURL,
		}, fileOp{
			Op:         "write",
			Path:       abs,
			Reason:     fmt.Sprintf("wired Claude Code hooks → %s", daemonURL),
			BackupPath: backupPath,
		}, nil
}

// applyDevStub writes the dev-sandbox marker JSON for a non-claude harness
// in AGENTLOCK_DEV_HOME mode. Mirrors applyClaudeCode's manifest+op return
// shape so the apply loop can record it the same way. Caller must have
// already verified the harness id and dev-mode env.
func applyDevStub(devHome, harness, daemonURL string) (installManifestE, fileOp, error) {
	stubAbs, err := filepath.Abs(devStubPath(devHome, harness))
	if err != nil {
		return installManifestE{}, fileOp{}, fmt.Errorf("resolve stub path: %w", err)
	}
	dir := filepath.Dir(stubAbs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return installManifestE{}, fileOp{}, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	body, err := devStubContent(harness, daemonURL)
	if err != nil {
		return installManifestE{}, fileOp{}, fmt.Errorf("marshal stub: %w", err)
	}
	if err := policy.AtomicWriteFile(stubAbs, body, 0o644); err != nil {
		return installManifestE{}, fileOp{}, fmt.Errorf("write stub %s: %w", stubAbs, err)
	}
	return installManifestE{
			Harness:      harness,
			SettingsPath: stubAbs,
			DaemonURL:    daemonURL,
		}, fileOp{
			Op:     "write",
			Path:   stubAbs,
			Reason: fmt.Sprintf("dev sandbox marker for %s → %s", harness, daemonURL),
		}, nil
}

// checkSafeClaudeTarget refuses to let apply write into the developer's
// real ~/.claude directory. It is fail-SAFE: if we cannot determine
// where $HOME is (permissions, weird containers) we treat the target as
// unsafe rather than waving it through. Both the home prefix and the
// target path are symlink-resolved before the containment comparison so
// a symlink inside ~/.claude pointing to /tmp (or vice versa) can't
// evade the check.
func checkSafeClaudeTarget(absPath string) error {
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
		// Non-fatal: the home dir may not have symlinks worth following.
		// Fall back to the abs form.
		resolvedHome = absHome
	}
	realClaude := filepath.Clean(filepath.Join(resolvedHome, ".claude"))

	resolvedTarget := absPath
	// EvalSymlinks requires the path to exist; for a not-yet-written
	// settings.json, resolve the parent instead.
	dirResolved, derr := filepath.EvalSymlinks(filepath.Dir(absPath))
	if derr == nil {
		resolvedTarget = filepath.Join(dirResolved, filepath.Base(absPath))
	}
	resolvedTarget = filepath.Clean(resolvedTarget)

	rel, err := filepath.Rel(realClaude, resolvedTarget)
	if err != nil {
		// Different volumes → can't possibly be under ~/.claude.
		return nil
	}
	if rel == "." || (!strings.HasPrefix(rel, "..") && !strings.HasPrefix(rel, string(os.PathSeparator))) {
		return fmt.Errorf("%w: %s", errUnsafeTarget, absPath)
	}
	return nil
}

// mergeClaudeSettings merges our hook entries into the existing settings.json
// bytes. Existing non-agentlock entries under hooks.PreToolUse / hooks.Stop
// are preserved. Our own (tagged with _agentlock:true) are replaced, so the
// operation is idempotent.
func mergeClaudeSettings(existing []byte, daemonURL string) ([]byte, error) {
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

	ours := claudeCodeHookConfig(daemonURL)
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

	return json.MarshalIndent(settings, "", "  ")
}

func isAgentlockEntry(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	b, _ := m["_agentlock"].(bool)
	return b
}

// --- uninstall ----------------------------------------------------------

type installUninstallRequest struct {
	SessionID string `json:"session_id"`
}

type uninstallOp struct {
	Op             string `json:"op"`
	Path           string `json:"path"`
	EntriesRemoved int    `json:"entries_removed"`
	Error          string `json:"error,omitempty"`
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
		if os.Getenv("AGENTLOCK_ALLOW_APPLY") != "1" {
			writeError(w, http.StatusForbidden, "apply_disabled",
				"set AGENTLOCK_ALLOW_APPLY=1 to enable install uninstall")
			return
		}
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

		// Attempt every entry; collect per-entry failures. Better to
		// strip 3 of 4 and tell the user which one needs hand-fixing
		// than to leave all 4 partially mutated.
		ops := make([]uninstallOp, 0, len(m.Entries))
		failures := 0
		for _, e := range m.Entries {
			op := uninstallOp{Op: "strip", Path: e.SettingsPath}
			var (
				removed int
				err     error
			)
			switch e.Harness {
			case "codex":
				removed, err = stripCodexHooks(e.SettingsPath)
			default:
				// Default to Claude's settings.json shape. Older manifests
				// without a Harness field land here, which is the right
				// behavior — claude-code was the only harness pre-Codex.
				removed, err = stripClaudeSettings(e.SettingsPath)
			}
			if err != nil {
				failures++
				op.Error = err.Error()
				log.Printf("install.uninstall: strip %s (%s): %v", e.SettingsPath, e.Harness, err)
			} else {
				op.EntriesRemoved = removed
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
// strips the agentlock wiring for each one (claude settings entries OR
// the dev-stub marker), and the diff is logged to the ledger as a
// single entry. Lets a re-run of `agentlock install` honor unchecks
// without forcing the user to call a separate uninstall command.

type installUninstallHarnessesRequest struct {
	SessionID         string            `json:"session_id"`
	Harnesses         []string          `json:"harnesses"`
	ConfigDirOverride string            `json:"config_dir_override,omitempty"`
	HarnessConfigDirs map[string]string `json:"harness_config_dirs,omitempty"`
}

func installUninstallHarnessesHandler(d Deps) http.HandlerFunc {
	if d.Store == nil || d.AgentlockHome == "" {
		return todo("install.uninstall_harnesses")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("AGENTLOCK_ALLOW_APPLY") != "1" {
			writeError(w, http.StatusForbidden, "apply_disabled",
				"set AGENTLOCK_ALLOW_APPLY=1 to enable per-harness uninstall")
			return
		}
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
				removed, err := stripClaudeSettings(p)
				op := uninstallOp{Op: "strip", Path: p}
				if err != nil {
					failures++
					op.Error = err.Error()
					log.Printf("install.uninstall_harnesses: strip %s: %v", p, err)
				} else {
					op.EntriesRemoved = removed
				}
				ops = append(ops, op)
			case "codex":
				p, err := codexHooksPath(req.ConfigDirOverride, req.HarnessConfigDirs)
				if err != nil {
					failures++
					ops = append(ops, uninstallOp{Op: "strip", Path: "<unresolved>", Error: err.Error()})
					continue
				}
				removed, err := stripCodexHooks(p)
				op := uninstallOp{Op: "strip", Path: p}
				if err != nil {
					failures++
					op.Error = err.Error()
					log.Printf("install.uninstall_harnesses: strip codex %s: %v", p, err)
				} else {
					op.EntriesRemoved = removed
				}
				ops = append(ops, op)
			default:
				if devHome == "" || !knownHarnessID(h) {
					// No real installer + not in dev mode → nothing to do.
					ops = append(ops, uninstallOp{Op: "skip", Path: h})
					continue
				}
				p := devStubPath(devHome, h)
				op := uninstallOp{Op: "remove", Path: p}
				if err := os.Remove(p); err != nil {
					if errors.Is(err, os.ErrNotExist) {
						// Already gone — treat as success with 0 removed.
						ops = append(ops, op)
						continue
					}
					failures++
					op.Error = err.Error()
					log.Printf("install.uninstall_harnesses: rm %s: %v", p, err)
				} else {
					op.EntriesRemoved = 1
				}
				ops = append(ops, op)
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

// stripClaudeSettings loads the current settings.json (not the backup), removes
// every entry under hooks.PreToolUse / hooks.Stop tagged _agentlock:true, and
// trims empty containers. Returns the number of entries removed.
func stripClaudeSettings(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	settings := map[string]any{}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &settings); err != nil {
			return 0, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	hooks, _ := settings["hooks"].(map[string]any)
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
		delete(settings, "hooks")
	} else {
		settings["hooks"] = hooks
	}

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("marshal: %w", err)
	}
	if err := policy.AtomicWriteFile(path, out, 0o644); err != nil {
		return 0, fmt.Errorf("write %s: %w", path, err)
	}
	return removed, nil
}
