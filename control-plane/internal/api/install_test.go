package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	if len(ops) < 2 {
		t.Fatalf("want >=2 ops, got %d: %+v", len(ops), plan)
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
		"harnesses": ["cline","opencode"],
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

// TestClaudeCodePlan_PreservesExistingUserKeys exercises the merge path
// directly: a settings.json with model + hooks keys should round-trip
// through claudeCodePlan with the agentlock entries spliced in and the
// user's keys intact.
func TestClaudeCodePlan_PreservesExistingUserKeys(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	abs, err := filepath.Abs(settingsPath)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	existing := `{"model":"opus","hooks":{}}`
	op := claudeCodePlan(
		"http://127.0.0.1:7878",
		filepath.Dir(abs),
		"",
		"",
		nil,
		map[string]string{abs: existing},
	)
	if op.Op != "write" {
		t.Fatalf("op = %v", op.Op)
	}
	if op.Path != abs {
		t.Fatalf("path = %q, want %q", op.Path, abs)
	}
	if op.BackupPath == "" {
		t.Fatalf("backup_path must be set when an existing file was supplied")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(op.Content), &parsed); err != nil {
		t.Fatalf("parse merged content: %v\n%s", err, op.Content)
	}
	if parsed["model"] != "opus" {
		t.Fatalf("user-set model lost: %+v", parsed)
	}
	hooks, _ := parsed["hooks"].(map[string]any)
	if hooks == nil {
		t.Fatalf("hooks dropped: %+v", parsed)
	}
	pre, _ := hooks["PreToolUse"].([]any)
	if len(pre) == 0 {
		t.Fatalf("PreToolUse not wired: %+v", hooks)
	}
	first, _ := pre[0].(map[string]any)
	if b, _ := first["_agentlock"].(bool); !b {
		t.Fatalf("agentlock marker missing on PreToolUse entry: %+v", first)
	}
}

// Regression: paths with spaces (e.g. macOS "Library/Application Support")
// must be shell-quoted so /bin/sh doesn't split them when running the hook.
// Without quoting, Claude/Codex/Cursor render a red "hook error" banner with
// "line 1: on: command not found" or "exit code 127" on every event.
func TestClaudeCodePlan_QuotesBinaryPathWithSpaces(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	abs, _ := filepath.Abs(settingsPath)
	op := claudeCodePlan(
		"http://127.0.0.1:7878",
		filepath.Dir(abs),
		"/Users/x/Library/Application Support/OpenAgentLock/bin/agentlock",
		"",
		nil,
		nil,
	)
	// The wired command must wrap the binary path in single quotes so
	// /bin/sh treats it as one token.
	if !strings.Contains(op.Content, "'/Users/x/Library/Application Support/OpenAgentLock/bin/agentlock'") {
		t.Fatalf("binary path not shell-quoted in hook command:\n%s", op.Content)
	}
}

// statusLine wiring: when status_line_script is supplied, the merged
// settings.json must carry an _agentlock-tagged statusLine pointing at
// the script. Re-running keeps it idempotent. A user-defined statusLine
// (no _agentlock tag) must survive untouched.
func TestClaudeCodePlan_StatusLineWiring(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	abs, _ := filepath.Abs(settingsPath)
	op := claudeCodePlan(
		"http://127.0.0.1:7878",
		filepath.Dir(abs),
		"",
		"/usr/local/oal/bin/agentlock-status",
		nil,
		nil,
	)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(op.Content), &parsed); err != nil {
		t.Fatalf("parse: %v\n%s", err, op.Content)
	}
	sl, ok := parsed["statusLine"].(map[string]any)
	if !ok {
		t.Fatalf("statusLine not wired: %+v", parsed)
	}
	if got := sl["command"]; got != "'/usr/local/oal/bin/agentlock-status'" {
		t.Fatalf("statusLine command = %v (expected single-quoted to survive shell parsing of paths with spaces)", got)
	}
	if b, _ := sl["_agentlock"].(bool); !b {
		t.Fatalf("agentlock marker missing on statusLine: %+v", sl)
	}

	// User-defined statusLine should be preserved.
	existing := `{"statusLine":{"type":"command","command":"/my/own/status"}}`
	op2 := claudeCodePlan(
		"http://127.0.0.1:7878",
		filepath.Dir(abs),
		"",
		"/usr/local/oal/bin/agentlock-status",
		nil,
		map[string]string{abs: existing},
	)
	var parsed2 map[string]any
	if err := json.Unmarshal([]byte(op2.Content), &parsed2); err != nil {
		t.Fatalf("parse2: %v", err)
	}
	sl2, _ := parsed2["statusLine"].(map[string]any)
	if got := sl2["command"]; got != "/my/own/status" {
		t.Fatalf("user statusLine clobbered: %v", got)
	}
}

// stripClaudeSettings should remove an agentlock-tagged statusLine so
// uninstall reverts the file cleanly.
func TestStripClaudeSettings_RemovesStatusLine(t *testing.T) {
	in := []byte(`{
		"hooks": {"PreToolUse": [{"_agentlock": true}]},
		"statusLine": {"_agentlock": true, "type": "command", "command": "/x"}
	}`)
	out, removed, err := stripClaudeSettings(in)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if removed < 2 {
		t.Fatalf("expected at least 2 removed (hook + statusLine), got %d", removed)
	}
	var parsed map[string]any
	_ = json.Unmarshal(out, &parsed)
	if _, has := parsed["statusLine"]; has {
		t.Fatalf("statusLine not stripped: %s", out)
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

func applyBodyWithExisting(fx gateFixture, overrideDir string, existing map[string]string) string {
	ex, _ := json.Marshal(existing)
	return fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["claude-code"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q,
		"existing_files": %s
	}`, fx.sessionID, overrideDir, ex)
}

func postApply(t *testing.T, fx gateFixture, overrideDir string) *http.Response {
	t.Helper()
	res, err := http.Post(fx.srv.URL+"/v1/install/apply", "application/json", strings.NewReader(applyBody(fx, overrideDir)))
	if err != nil {
		t.Fatalf("POST apply: %v", err)
	}
	return res
}

func postApplyWithExisting(t *testing.T, fx gateFixture, overrideDir string, existing map[string]string) *http.Response {
	t.Helper()
	res, err := http.Post(fx.srv.URL+"/v1/install/apply", "application/json", strings.NewReader(applyBodyWithExisting(fx, overrideDir, existing)))
	if err != nil {
		t.Fatalf("POST apply: %v", err)
	}
	return res
}

func decodeApplyResponse(t *testing.T, res *http.Response) installApplyResponse {
	t.Helper()
	defer res.Body.Close()
	var out installApplyResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func findOpByPath(ops []fileOp, suffix string) (fileOp, bool) {
	for _, op := range ops {
		if strings.HasSuffix(op.Path, suffix) {
			return op, true
		}
	}
	return fileOp{}, false
}

func TestInstallApply_ReturnsSettingsContent(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	res := postApply(t, fx, dir)
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeApplyResponse(t, res)
	if !out.Applied {
		t.Fatalf("applied = %v", out.Applied)
	}
	op, ok := findOpByPath(out.Operations, "settings.json")
	if !ok {
		t.Fatalf("no settings.json op in response: %+v", out.Operations)
	}
	if op.Op != "write" {
		t.Fatalf("op = %v", op.Op)
	}
	if !strings.Contains(op.Content, "PreToolUse") {
		t.Fatalf("missing PreToolUse: %s", op.Content)
	}
	if !strings.Contains(op.Content, "_agentlock") {
		t.Fatalf("missing _agentlock marker: %s", op.Content)
	}
	if !strings.Contains(op.Content, "hook claude-code pre-tool-use") {
		t.Fatalf("missing claude-code pre-tool-use shim invocation: %s", op.Content)
	}
	if !strings.Contains(op.Content, `"type": "command"`) {
		t.Fatalf("expected command-typed hook entries: %s", op.Content)
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
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	settingsPath, _ := filepath.Abs(filepath.Join(dir, "settings.json"))
	userSettings := `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "Write", "hooks": [{"type": "command", "command": "my-user-hook.sh"}]}
			]
		},
		"telemetry": false
	}`
	res := postApplyWithExisting(t, fx, dir, map[string]string{settingsPath: userSettings})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	out := decodeApplyResponse(t, res)
	op, ok := findOpByPath(out.Operations, "settings.json")
	if !ok {
		t.Fatalf("no settings.json op: %+v", out.Operations)
	}
	s := op.Content
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

func TestInstallApply_BackupPathSetWhenExistingFileSupplied(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	settingsPath, _ := filepath.Abs(filepath.Join(dir, "settings.json"))
	original := `{"user":"settings"}`

	res := postApplyWithExisting(t, fx, dir, map[string]string{settingsPath: original})
	out := decodeApplyResponse(t, res)
	op, ok := findOpByPath(out.Operations, "settings.json")
	if !ok {
		t.Fatalf("no settings.json op: %+v", out.Operations)
	}
	if op.BackupPath == "" {
		t.Fatalf("backup_path must be set when existing_files carried bytes; got empty")
	}
	if !strings.HasPrefix(op.BackupPath, settingsPath+".agentlock-backup-") {
		t.Fatalf("backup_path shape unexpected: %q", op.BackupPath)
	}
}

func TestInstallApply_Idempotent(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	settingsPath, _ := filepath.Abs(filepath.Join(dir, "settings.json"))

	// First apply: no existing file. CLI would write the result to disk.
	first := decodeApplyResponse(t, postApply(t, fx, dir))
	firstOp, _ := findOpByPath(first.Operations, "settings.json")

	// Second apply: simulate the CLI having written the previous content
	// back to disk by sending it as existing_files.
	second := decodeApplyResponse(t, postApplyWithExisting(t, fx, dir, map[string]string{settingsPath: firstOp.Content}))
	secondOp, _ := findOpByPath(second.Operations, "settings.json")

	// Our marker should appear exactly 4 times in the second op's content
	// (SessionStart + PreToolUse + PostToolUse + Stop), not 8 — re-applying
	// must not duplicate.
	got := strings.Count(secondOp.Content, `"_agentlock"`)
	if got != 4 {
		t.Fatalf("expected 4 _agentlock entries, got %d: %s", got, secondOp.Content)
	}
}

func TestInstallApply_UnknownSession404(t *testing.T) {
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

func postUninstallWithExisting(t *testing.T, fx gateFixture, sessionID string, existing map[string]string) *http.Response {
	t.Helper()
	ex, _ := json.Marshal(existing)
	body := fmt.Sprintf(`{"session_id":%q,"existing_files":%s}`, sessionID, ex)
	res, err := http.Post(fx.srv.URL+"/v1/install/uninstall", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST uninstall: %v", err)
	}
	return res
}

func decodeUninstallResponse(t *testing.T, res *http.Response) installUninstallResponse {
	t.Helper()
	defer res.Body.Close()
	var out installUninstallResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func TestInstallUninstall_StripsOurEntriesOnly(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	settingsPath, _ := filepath.Abs(filepath.Join(dir, "settings.json"))
	// Apply with a user hook in existing_files so the manifest records
	// the right path. The merged content is what the CLI would write back.
	userSettings := `{"hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"mine.sh"}]}]}}`
	applyOut := decodeApplyResponse(t, postApplyWithExisting(t, fx, dir, map[string]string{settingsPath: userSettings}))
	mergedOp, _ := findOpByPath(applyOut.Operations, "settings.json")

	// Now uninstall, simulating the CLI sending back the merged file
	// contents as existing_files.
	res := postUninstallWithExisting(t, fx, fx.sessionID, map[string]string{settingsPath: mergedOp.Content})
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	out := decodeUninstallResponse(t, res)
	if !out.Uninstalled {
		t.Fatalf("uninstalled = false; %+v", out)
	}
	var stripOp uninstallOp
	for _, op := range out.Operations {
		if op.Path == settingsPath {
			stripOp = op
			break
		}
	}
	if stripOp.Op != "strip" {
		t.Fatalf("missing strip op for %s: %+v", settingsPath, out.Operations)
	}
	if stripOp.EntriesRemoved == 0 {
		t.Fatalf("expected entries removed > 0; got %+v", stripOp)
	}
	if stripOp.Content == "" {
		t.Fatalf("expected non-empty Content (the post-strip JSON), got empty: %+v", stripOp)
	}
	if !strings.Contains(stripOp.Content, "mine.sh") {
		t.Fatalf("user hook lost in strip output: %s", stripOp.Content)
	}
	if strings.Contains(stripOp.Content, "_agentlock") {
		t.Fatalf("agentlock marker should be gone from strip output: %s", stripOp.Content)
	}
}

func TestInstallUninstall_PreservesUserEditsMadeAfterInstall(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	settingsPath, _ := filepath.Abs(filepath.Join(dir, "settings.json"))
	applyOut := decodeApplyResponse(t, postApply(t, fx, dir))
	merged, _ := findOpByPath(applyOut.Operations, "settings.json")

	// Simulate the user adding their own hook after install, plus a
	// top-level unrelated setting.
	var s map[string]any
	_ = json.Unmarshal([]byte(merged.Content), &s)
	hooks, _ := s["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	hooks["PreToolUse"] = append(pre, map[string]any{
		"matcher": "Edit",
		"hooks":   []any{map[string]any{"type": "command", "command": "user-added.sh"}},
	})
	s["hooks"] = hooks
	s["telemetry"] = false
	mutated, _ := json.MarshalIndent(s, "", "  ")

	res := postUninstallWithExisting(t, fx, fx.sessionID, map[string]string{settingsPath: string(mutated)})
	out := decodeUninstallResponse(t, res)
	stripOp, _ := func() (uninstallOp, bool) {
		for _, op := range out.Operations {
			if op.Path == settingsPath {
				return op, true
			}
		}
		return uninstallOp{}, false
	}()
	if !strings.Contains(stripOp.Content, "user-added.sh") {
		t.Fatalf("post-install user edit lost: %s", stripOp.Content)
	}
	if !strings.Contains(stripOp.Content, `"telemetry": false`) {
		t.Fatalf("post-install top-level user edit lost: %s", stripOp.Content)
	}
	if strings.Contains(stripOp.Content, "_agentlock") {
		t.Fatalf("our marker should be gone: %s", stripOp.Content)
	}
}

func TestInstallUninstall_RemovesEmptyContainers(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	dir := t.TempDir()
	settingsPath, _ := filepath.Abs(filepath.Join(dir, "settings.json"))
	applyOut := decodeApplyResponse(t, postApply(t, fx, dir))
	merged, _ := findOpByPath(applyOut.Operations, "settings.json")

	res := postUninstallWithExisting(t, fx, fx.sessionID, map[string]string{settingsPath: merged.Content})
	out := decodeUninstallResponse(t, res)
	var stripOp uninstallOp
	for _, op := range out.Operations {
		if op.Path == settingsPath {
			stripOp = op
			break
		}
	}
	var s map[string]any
	if err := json.Unmarshal([]byte(stripOp.Content), &s); err != nil {
		t.Fatalf("parse: %v\n%s", err, stripOp.Content)
	}
	if _, has := s["hooks"]; has {
		t.Fatalf("hooks container should be gone: %s", stripOp.Content)
	}
}

func TestInstallUninstall_UnknownSession404(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	res := postUninstall(t, fx, "nope")
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", res.StatusCode)
	}
}
