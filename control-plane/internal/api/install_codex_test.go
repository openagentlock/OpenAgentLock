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

func writeCodexConfigToml(t *testing.T, dir string, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}
}

func codexApplyBody(fx gateFixture, dir, binary string) string {
	return fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["codex"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q,
		"agentlock_binary": %q
	}`, fx.sessionID, dir, binary)
}

func postCodexApply(t *testing.T, fx gateFixture, dir, binary string) *http.Response {
	t.Helper()
	res, err := http.Post(
		fx.srv.URL+"/v1/install/apply",
		"application/json",
		strings.NewReader(codexApplyBody(fx, dir, binary)),
	)
	if err != nil {
		t.Fatalf("POST apply: %v", err)
	}
	return res
}

func TestInstallPlan_CodexProducesWriteOpAndWarning(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	writeCodexConfigToml(t, dir, "codex_hooks = true\n")

	body := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["codex"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": %q,
		"agentlock_binary": "/usr/local/bin/agentlock"
	}`, fx.sessionID, dir)
	res, err := http.Post(fx.srv.URL+"/v1/install/plan", "application/json", strings.NewReader(body))
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
		t.Fatalf("expected ops: %+v", plan)
	}
	op, _ := ops[0].(map[string]any)
	path, _ := op["path"].(string)
	if !strings.HasSuffix(path, "hooks.json") {
		t.Fatalf("expected hooks.json path, got %q", path)
	}
	content, _ := op["content"].(string)
	if !strings.Contains(content, "/usr/local/bin/agentlock hook codex pre-tool-use") {
		t.Fatalf("expected shim command in content, got: %s", content)
	}
	if !strings.Contains(content, `"AGENTLOCK_DAEMON_URL": "http://127.0.0.1:7878"`) {
		t.Fatalf("expected daemon URL env, got: %s", content)
	}
	warns, _ := plan["warnings"].([]any)
	if len(warns) == 0 {
		t.Fatalf("expected MCP-gap warning, got: %+v", plan)
	}
	if !strings.Contains(warns[0].(string), "MCP tool calls are NOT gated") {
		t.Fatalf("warning text drift: %v", warns[0])
	}
}

func TestInstallApply_CodexRefusedWhenFlagDisabled(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	// config.toml exists but the flag isn't set to true.
	writeCodexConfigToml(t, dir, "# nothing relevant\n")

	res := postCodexApply(t, fx, dir, "/usr/local/bin/agentlock")
	defer res.Body.Close()
	if res.StatusCode != http.StatusFailedDependency {
		t.Fatalf("status = %d, want 424", res.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(res.Body).Decode(&body)
	if body["error"] != "codex_hooks_disabled" {
		t.Fatalf("error = %v", body["error"])
	}
}

func TestInstallApply_CodexRefusedWhenConfigMissing(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir() // no config.toml at all
	res := postCodexApply(t, fx, dir, "/usr/local/bin/agentlock")
	defer res.Body.Close()
	if res.StatusCode != http.StatusFailedDependency {
		t.Fatalf("status = %d, want 424", res.StatusCode)
	}
}

func TestInstallApply_CodexWritesHooksJson(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	writeCodexConfigToml(t, dir, "codex_hooks = true\n")

	res := postCodexApply(t, fx, dir, "/usr/local/bin/agentlock")
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	var out installApplyResponse
	_ = json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	if !out.Applied {
		t.Fatalf("not applied: %+v", out)
	}
	if len(out.Warnings) == 0 || !strings.Contains(out.Warnings[0], "MCP") {
		t.Fatalf("missing MCP warning: %+v", out.Warnings)
	}

	hooksPath := filepath.Join(dir, "hooks.json")
	b, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatalf("read hooks.json: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		`"_agentlock"`,
		`"PreToolUse"`,
		`"SessionStart"`,
		`"PostToolUse"`,
		`"Stop"`,
		`"type": "command"`,
		`/usr/local/bin/agentlock hook codex pre-tool-use`,
		`"AGENTLOCK_DAEMON_URL"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in hooks.json: %s", want, s)
		}
	}

	// Ledger must show install.apply.
	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "install.apply" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("missing install.apply ledger entry: %+v", entries)
	}
}

func TestInstallApply_CodexPreservesExistingUserHooks(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	writeCodexConfigToml(t, dir, "codex_hooks = true\n")

	user := `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "*", "hooks": [{"type": "command", "command": "user-hook.sh"}]}
			]
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(user), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	res := postCodexApply(t, fx, dir, "/usr/local/bin/agentlock")
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	res.Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "hooks.json"))
	s := string(b)
	if !strings.Contains(s, "user-hook.sh") {
		t.Fatalf("user hook lost: %s", s)
	}
	if !strings.Contains(s, "_agentlock") {
		t.Fatalf("our entry missing: %s", s)
	}
}

func TestInstallApply_CodexIdempotent(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	writeCodexConfigToml(t, dir, "codex_hooks = true\n")

	_ = postCodexApply(t, fx, dir, "/usr/local/bin/agentlock").Body.Close()
	_ = postCodexApply(t, fx, dir, "/usr/local/bin/agentlock").Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "hooks.json"))
	got := strings.Count(string(b), `"_agentlock"`)
	if got != 4 {
		t.Fatalf("expected 4 _agentlock entries, got %d: %s", got, b)
	}
}

func TestInstallUninstall_CodexStripsOurEntriesOnly(t *testing.T) {
	t.Setenv("AGENTLOCK_ALLOW_APPLY", "1")
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()
	writeCodexConfigToml(t, dir, "codex_hooks = true\n")

	user := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"mine.sh"}]}]}}`
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(user), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_ = postCodexApply(t, fx, dir, "/usr/local/bin/agentlock").Body.Close()
	res := postUninstall(t, fx, fx.sessionID)
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	res.Body.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "hooks.json"))
	s := string(b)
	if !strings.Contains(s, "mine.sh") {
		t.Fatalf("user hook lost: %s", s)
	}
	if strings.Contains(s, "_agentlock") {
		t.Fatalf("our marker should be gone: %s", s)
	}
	if strings.Contains(s, "agentlock hook codex") {
		t.Fatalf("our shim invocation should be gone: %s", s)
	}
}
