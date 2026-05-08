package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestInstallPlan_CodexDesktopUsesSharedCodexHooks(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()

	body := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["codex-desktop"],
		"daemon_url": "http://127.0.0.1:7878",
		"harness_config_dirs": {"codex-desktop": %q},
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
	if err := json.NewDecoder(res.Body).Decode(&plan); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	ops, ok := plan["operations"].([]any)
	if !ok {
		t.Fatalf("operations is not []any: %+v", plan)
	}
	if len(ops) == 0 {
		t.Fatalf("expected shared codex ops for desktop install, got: %+v", plan)
	}
	op, ok := ops[0].(map[string]any)
	if !ok {
		t.Fatalf("ops[0] is not map[string]any: %+v", ops[0])
	}
	content, ok := op["content"].(string)
	if !ok {
		t.Fatalf("content is not string: %+v", op["content"])
	}
	if strings.Count(content, "hook codex pre-tool-use") != 1 {
		t.Fatalf("expected shared codex pre-tool hook, got:\n%s", content)
	}
	if strings.Contains(content, "hook codex-desktop pre-tool-use") {
		t.Fatalf("did not expect separate desktop hook in shared install, got:\n%s", content)
	}
	if skipped, ok := plan["skipped"].([]any); !ok || len(skipped) != 0 {
		t.Fatalf("expected no skipped harnesses, got: %+v", plan)
	}
	warnings, ok := plan["warnings"].([]any)
	if !ok || len(warnings) == 0 {
		t.Fatalf("expected desktop trust warning, got: %+v", plan)
	}
	if !strings.Contains(fmt.Sprint(warnings), "supported through the shared ~/.codex hook config") {
		t.Fatalf("warning text drift: %v", warnings)
	}
}

func TestInstallPlan_CodexAndCodexDesktopInstallsOnlyCodex(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	dir := t.TempDir()

	body := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["codex", "codex-desktop"],
		"daemon_url": "http://127.0.0.1:7878",
		"harness_config_dirs": {"codex": %q, "codex-desktop": %q}
	}`, fx.sessionID, dir, dir)
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
	if err := json.NewDecoder(res.Body).Decode(&plan); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	ops, ok := plan["operations"].([]any)
	if !ok || len(ops) == 0 {
		t.Fatalf("expected operations: %+v", plan)
	}
	op, ok := ops[0].(map[string]any)
	if !ok {
		t.Fatalf("ops[0] is not map[string]any: %+v", ops[0])
	}
	content, ok := op["content"].(string)
	if !ok {
		t.Fatalf("content is not string: %+v", op["content"])
	}
	if strings.Count(content, "hook codex-auto pre-tool-use") != 0 {
		t.Fatalf("did not expect shared codex-auto hook, got:\n%s", content)
	}
	if strings.Count(content, "hook codex pre-tool-use") != 1 {
		t.Fatalf("expected codex CLI pre-tool hook, got:\n%s", content)
	}
	if skipped, ok := plan["skipped"].([]any); !ok || len(skipped) != 0 {
		t.Fatalf("expected no skipped harnesses, got: %+v", plan)
	}
}
