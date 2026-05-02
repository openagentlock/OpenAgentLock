package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectReport_StoresDetections(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := fmt.Sprintf(`{
		"session_id": %q,
		"detections": [
			{"harness": "claude-code", "installed": true, "paths": ["~/.claude"], "surfaces": ["lifecycle-hooks"]},
			{"harness": "cursor", "installed": false, "paths": [], "surfaces": []}
		]
	}`, fx.sessionID)
	res, err := http.Post(fx.srv.URL+"/v1/detect/report", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if n, _ := out["stored"].(float64); int(n) != 2 {
		t.Fatalf("stored = %v", out["stored"])
	}
}

func TestDetectReport_UnknownSession404(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{"session_id":"nope","detections":[]}`
	res, err := http.Post(fx.srv.URL+"/v1/detect/report", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

func TestInstallPlan_ClaudeCodeProducesWriteOp(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	planBody := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["claude-code"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": "/tmp/fake-claude"
	}`, fx.sessionID)
	res, err := http.Post(fx.srv.URL+"/v1/install/plan", "application/json", strings.NewReader(planBody))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	var plan map[string]any
	_ = json.NewDecoder(res.Body).Decode(&plan)
	ops, _ := plan["operations"].([]any)
	if len(ops) == 0 {
		t.Fatalf("expected write operations: %+v", plan)
	}
	op, _ := ops[0].(map[string]any)
	if op["op"] != "write" {
		t.Fatalf("op = %v", op["op"])
	}
	path, _ := op["path"].(string)
	if !strings.Contains(path, "settings.json") {
		t.Fatalf("path: %q", path)
	}
	content, _ := op["content"].(string)
	if !strings.Contains(content, "http://127.0.0.1:7878") {
		t.Fatalf("expected daemon URL in hook config, got: %s", content)
	}
	if !strings.Contains(content, "PreToolUse") {
		t.Fatalf("expected PreToolUse hook in config: %s", content)
	}
}

func TestInstallPlan_HarnessConfigDirs_Honored(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	// Send harness_config_dirs WITHOUT a config_dir_override flag — the
	// CLI's normal Docker-mode behavior. Plan must echo back paths under
	// the host dir, not the daemon's $HOME.
	hostHome := t.TempDir()
	planBody := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["claude-code","codex"],
		"daemon_url": "http://127.0.0.1:7878",
		"harness_config_dirs": {
			"claude-code": %q,
			"codex": %q
		}
	}`, fx.sessionID,
		filepath.Join(hostHome, ".claude"),
		filepath.Join(hostHome, ".codex"))
	res, err := http.Post(fx.srv.URL+"/v1/install/plan", "application/json", strings.NewReader(planBody))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	var plan map[string]any
	_ = json.NewDecoder(res.Body).Decode(&plan)
	ops, _ := plan["operations"].([]any)
	if len(ops) != 2 {
		t.Fatalf("want 2 ops, got %d: %+v", len(ops), plan)
	}
	for _, anyOp := range ops {
		op, _ := anyOp.(map[string]any)
		path, _ := op["path"].(string)
		if !strings.HasPrefix(path, hostHome) {
			t.Fatalf("plan path %q must start with host dir %q (daemon is leaking its own $HOME)", path, hostHome)
		}
	}
}

func TestInstallPlan_HarnessConfigDirs_RejectsRelativePath(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["claude-code"],
		"daemon_url": "http://127.0.0.1:7878",
		"harness_config_dirs": {"claude-code": "relative/path"}
	}`, fx.sessionID)
	res, err := http.Post(fx.srv.URL+"/v1/install/plan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: want 400, got %d", res.StatusCode)
	}
	var out map[string]string
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out["error"] != "invalid_config_dir" {
		t.Fatalf("error: want invalid_config_dir, got %q", out["error"])
	}
}

func TestInstallPlan_HarnessConfigDirs_LegacyFlagWins(t *testing.T) {
	// When --config-dir is set the legacy flag wins so existing CLI
	// behavior is preserved (e.g. dev runs that point at ./dev/.claude).
	fx := newGateFixture(t, enforcePolicyYAML)
	hostHome := t.TempDir()
	overrideDir := "/tmp/legacy-override"
	planBody := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["claude-code"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q,
		"harness_config_dirs": {"claude-code": %q}
	}`, fx.sessionID, overrideDir, filepath.Join(hostHome, ".claude"))
	res, err := http.Post(fx.srv.URL+"/v1/install/plan", "application/json", strings.NewReader(planBody))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var plan map[string]any
	_ = json.NewDecoder(res.Body).Decode(&plan)
	ops, _ := plan["operations"].([]any)
	op, _ := ops[0].(map[string]any)
	path, _ := op["path"].(string)
	if !strings.HasPrefix(path, overrideDir) {
		t.Fatalf("legacy --config-dir must win; got %q (override=%q, host=%q)", path, overrideDir, hostHome)
	}
}

func TestInstallPlan_UnknownHarness_Skipped(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	body := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["cline","gemini"],
		"daemon_url": "http://127.0.0.1:7878"
	}`, fx.sessionID)
	res, err := http.Post(fx.srv.URL+"/v1/install/plan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	var plan map[string]any
	if err := json.NewDecoder(res.Body).Decode(&plan); err != nil {
		t.Fatalf("decode: %v", err)
	}
	skipped, _ := plan["skipped"].([]any)
	if len(skipped) != 2 {
		t.Fatalf("skipped = %+v", plan["skipped"])
	}
	ops, _ := plan["operations"].([]any)
	if len(ops) != 0 {
		t.Fatalf("expected no ops, got %+v", ops)
	}
}

// ---- apply ----

func applyBody(fx gateFixture, overrideDir string) string {
	return fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["claude-code"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q
	}`, fx.sessionID, overrideDir)
}

func postApply(t *testing.T, fx gateFixture, overrideDir string) *http.Response {
	t.Helper()
	res, err := http.Post(fx.srv.URL+"/v1/install/apply", "application/json", strings.NewReader(applyBody(fx, overrideDir)))
	if err != nil {
		t.Fatalf("POST apply: %v", err)
	}
	return res
}

func decodeJSON(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	defer res.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func TestInstallApply_RefusedWithoutAllowEnv(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	// No AGENTLOCK_ALLOW_APPLY.
	res := postApply(t, fx, t.TempDir())
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(res.Body).Decode(&body)
	if body["error"] != "apply_disabled" {
		t.Fatalf("error = %v", body["error"])
	}
}

func TestInstallApply_WritesSettingsJson(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	res := postApply(t, fx, dir)
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeJSON(t, res)
	if out["applied"] != true {
		t.Fatalf("applied = %v", out["applied"])
	}

	settingsPath := filepath.Join(dir, "settings.json")
	b, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !strings.Contains(string(b), "PreToolUse") {
		t.Fatalf("missing PreToolUse: %s", b)
	}
	if !strings.Contains(string(b), "_agentlock") {
		t.Fatalf("missing _agentlock marker: %s", b)
	}
	if !strings.Contains(string(b), "/v1/hooks/claude-code/pre-tool-use") {
		t.Fatalf("missing claude-code pre-tool-use URL: %s", b)
	}

	// Ledger grew with install.apply entry (in addition to session.create).
	entries, err := fx.store.ListLedger(context.Background())
	if err != nil {
		t.Fatalf("ListLedger: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.ToolUseID == "install.apply" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("install.apply ledger entry missing: %+v", entries)
	}
}

func TestInstallApply_PreservesExistingUserHooks(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	userSettings := `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "Write", "hooks": [{"type": "command", "command": "my-user-hook.sh"}]}
			]
		},
		"telemetry": false
	}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(userSettings), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	res := postApply(t, fx, dir)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	res.Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
	s := string(b)
	if !strings.Contains(s, "my-user-hook.sh") {
		t.Fatalf("user hook lost: %s", s)
	}
	if !strings.Contains(s, `"telemetry": false`) {
		t.Fatalf("user top-level setting lost: %s", s)
	}
	if !strings.Contains(s, "_agentlock") {
		t.Fatalf("our marker missing: %s", s)
	}
}

func TestInstallApply_WritesBackupFile(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	original := []byte(`{"user":"settings"}`)
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), original, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	res := postApply(t, fx, dir)
	res.Body.Close()

	matches, _ := filepath.Glob(filepath.Join(dir, "settings.json.agentlock-backup-*"))
	if len(matches) != 1 {
		t.Fatalf("want exactly 1 backup, got %d (%v)", len(matches), matches)
	}
	b, _ := os.ReadFile(matches[0])
	if !bytes.Equal(b, original) {
		t.Fatalf("backup content drift: got %s", b)
	}
}

func TestInstallApply_Idempotent(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	_ = postApply(t, fx, dir).Body.Close()
	_ = postApply(t, fx, dir).Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
	// Our marker should appear exactly twice (once each for PreToolUse + Stop),
	// not four (would indicate duplication on second apply).
	// SessionStart + PreToolUse + PostToolUse + Stop = 4 entries,
	// each tagged once. Idempotent apply must not duplicate any.
	got := strings.Count(string(b), `"_agentlock"`)
	if got != 4 {
		t.Fatalf("expected 4 _agentlock entries, got %d: %s", got, b)
	}
}

func TestInstallApply_RefusesRealHomeClaude(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)

	home, _ := os.UserHomeDir()
	if home == "" {
		t.Skip("no home")
	}
	res := postApply(t, fx, filepath.Join(home, ".claude"))
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(res.Body).Decode(&body)
	if body["error"] != "unsafe_target" {
		t.Fatalf("error = %v", body["error"])
	}
}

func TestInstallApply_UnknownSession404(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	_ = fx.sessionID // unused on purpose

	body := fmt.Sprintf(`{
		"session_id": "nope",
		"harnesses": ["claude-code"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q
	}`, t.TempDir())
	res, err := http.Post(fx.srv.URL+"/v1/install/apply", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

// ---- uninstall ----

func postUninstall(t *testing.T, fx gateFixture, sessionID string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"session_id":%q}`, sessionID)
	res, err := http.Post(fx.srv.URL+"/v1/install/uninstall", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST uninstall: %v", err)
	}
	return res
}

func TestInstallUninstall_RefusedWithoutAllowEnv(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	res := postUninstall(t, fx, fx.sessionID)
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

func TestInstallUninstall_StripsOurEntriesOnly(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	// Seed with a user hook first.
	userSettings := `{"hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"mine.sh"}]}]}}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(userSettings), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_ = postApply(t, fx, dir).Body.Close()
	res := postUninstall(t, fx, fx.sessionID)
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	res.Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
	s := string(b)
	if !strings.Contains(s, "mine.sh") {
		t.Fatalf("user hook lost: %s", s)
	}
	if strings.Contains(s, "_agentlock") {
		t.Fatalf("our marker should be gone: %s", s)
	}
	if strings.Contains(s, "/v1/hooks/claude-code/pre-tool-use") {
		t.Fatalf("our URL should be gone: %s", s)
	}
}

func TestInstallUninstall_PreservesUserEditsMadeAfterInstall(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	_ = postApply(t, fx, dir).Body.Close()

	// Simulate the user adding their own hook after install, plus a top-level
	// unrelated setting.
	settingsPath := filepath.Join(dir, "settings.json")
	b, _ := os.ReadFile(settingsPath)
	var s map[string]any
	_ = json.Unmarshal(b, &s)
	hooks, _ := s["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	hooks["PreToolUse"] = append(pre, map[string]any{
		"matcher": "Edit",
		"hooks":   []any{map[string]any{"type": "command", "command": "user-added.sh"}},
	})
	s["hooks"] = hooks
	s["telemetry"] = false
	nb, _ := json.MarshalIndent(s, "", "  ")
	if err := os.WriteFile(settingsPath, nb, 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	res := postUninstall(t, fx, fx.sessionID)
	res.Body.Close()

	final, _ := os.ReadFile(settingsPath)
	fs := string(final)
	if !strings.Contains(fs, "user-added.sh") {
		t.Fatalf("post-install user edit lost: %s", fs)
	}
	if !strings.Contains(fs, `"telemetry": false`) {
		t.Fatalf("post-install top-level user edit lost: %s", fs)
	}
	if strings.Contains(fs, "_agentlock") {
		t.Fatalf("our marker should be gone: %s", fs)
	}
}

func TestInstallUninstall_RemovesEmptyContainers(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	_ = postApply(t, fx, dir).Body.Close()
	_ = postUninstall(t, fx, fx.sessionID).Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, has := s["hooks"]; has {
		t.Fatalf("hooks container should be gone: %s", b)
	}
}

func TestInstallUninstall_IgnoresBackupFile(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"original":true}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = postApply(t, fx, dir).Body.Close()

	// Mutate settings AFTER apply; uninstall should read from this, not the backup.
	final := `{"user_changed":"after-install","hooks":{"PreToolUse":[{"_agentlock":true,"matcher":"*","hooks":[{"type":"http","url":"x"}]}]}}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(final), 0o644); err != nil {
		t.Fatalf("mutate: %v", err)
	}

	_ = postUninstall(t, fx, fx.sessionID).Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
	if !strings.Contains(string(b), "user_changed") {
		t.Fatalf("post-apply mutation lost: %s", b)
	}
	if strings.Contains(string(b), "_agentlock") {
		t.Fatalf("marker should be gone: %s", b)
	}

	// Backup still on disk.
	matches, _ := filepath.Glob(filepath.Join(dir, "settings.json.agentlock-backup-*"))
	if len(matches) != 1 {
		t.Fatalf("backup missing or multiplied: %v", matches)
	}
}

func TestInstallUninstall_UnknownSession404(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	res := postUninstall(t, fx, "nope")
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", res.StatusCode)
	}
}
