// AddRuleModal — guided rule creation for the dashboard.
//
// Five presets map 1:1 to the demo scenarios in docs/guide/scenarios.md:
//   - Package install (supply-chain.pkg-install) → Bash command regex
//   - Destructive bash (rogue.destructive-bash)  → Bash command regex
//   - Secret read    (rogue.secret-read)         → Read path regex
//   - Network egress (rogue.net-egress)          → WebFetch URL regex
//   - Custom                                     → all fields visible
//
// Picking a preset prefills the id, tool, regex placeholder, and action
// so the user can hit Create with one tweak. Only the regex field for
// the active rule type is shown, so the form stays focused. "Custom"
// reveals every field for advanced gates that mix matchers.

import type { FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";
import { apiSend } from "@/lib/api";

interface AddRuleModalProps {
  onClose: () => void;
  onCreated: (id: string) => void;
}

type RuleType = "bash" | "pkg-install" | "destructive" | "secret-read" | "net-egress-url" | "custom";

interface Preset {
  label: string;
  description: string;
  idSuggestion: string;
  tool: string;
  regexPlaceholder: string;
  regexExamples: string;
  action: "deny" | "allow";
  fields: ReadonlyArray<"command" | "path" | "url" | "all">;
}

const PRESETS: Record<RuleType, Preset> = {
  "pkg-install": {
    label: "Package install (pip / npm / brew / cargo)",
    description: "Match Bash commands that install packages.",
    idSuggestion: "supply-chain.pkg-install",
    tool: "Bash",
    regexPlaceholder: "^(pip|pip3|npm|brew|cargo|gem) (install|add) ",
    regexExamples: "^pip install\n^npm install\n^brew install\n^cargo add",
    action: "deny",
    fields: ["command"],
  },
  destructive: {
    label: "Destructive bash (rm -rf, force-push, drop table)",
    description: "Block irreversible shell commands.",
    idSuggestion: "rogue.destructive-bash",
    tool: "Bash",
    regexPlaceholder: "rm\\s+-rf\\b\n^git\\s+push\\s+.*--force",
    regexExamples: "rm\\s+(-[rRfF]+\\s+)+\\S+\ngit\\s+push\\s+.*--force\n^kubectl delete\nDROP\\s+TABLE",
    action: "deny",
    fields: ["command"],
  },
  "secret-read": {
    label: "Secret read (.env, ~/.ssh, credentials)",
    description: "Match Read on sensitive paths.",
    idSuggestion: "rogue.secret-read",
    tool: "Read",
    regexPlaceholder: "\\.env(\\.|$)\n/\\.ssh/id_[^/]+$",
    regexExamples: "\\.env(\\.|$)\n/\\.ssh/id_[^/]+$\n/secrets\\.(json|yaml)$",
    action: "deny",
    fields: ["path"],
  },
  "net-egress-url": {
    label: "Network egress (WebFetch / WebSearch URL)",
    description: "Block fetches to suspect hosts.",
    idSuggestion: "rogue.net-egress",
    tool: "WebFetch",
    regexPlaceholder: "^https?://(?:[a-z0-9-]+\\.)*attacker\\.example",
    regexExamples: "^https?://[^/]*requestbin\\.com\n^https?://[^/]*pastebin\\.com\n^https?://(?:[a-z0-9-]+\\.)*ngrok\\.io",
    action: "deny",
    fields: ["url"],
  },
  bash: {
    label: "Generic bash command",
    description: "Match any Bash invocation.",
    idSuggestion: "custom.bash",
    tool: "Bash",
    regexPlaceholder: "^my-command",
    regexExamples: "^my-command",
    action: "deny",
    fields: ["command"],
  },
  custom: {
    label: "Custom (advanced — all fields)",
    description: "Combine command / path / URL matchers freely.",
    idSuggestion: "custom.rule",
    tool: "",
    regexPlaceholder: "",
    regexExamples: "",
    action: "deny",
    fields: ["all"],
  },
};

const TOOL_OPTIONS = [
  "Bash",
  "Read",
  "Write",
  "Edit",
  "MultiEdit",
  "WebFetch",
  "WebSearch",
  "Glob",
  "Grep",
  "Task",
] as const;

export function AddRuleModal({ onClose, onCreated }: AddRuleModalProps) {
  const [ruleType, setRuleType] = useState<RuleType>("destructive");
  const preset = PRESETS[ruleType];

  const [id, setId] = useState(preset.idSuggestion);
  const [tool, setTool] = useState(preset.tool);
  const [commandRegexes, setCommandRegexes] = useState("");
  const [pathRegexes, setPathRegexes] = useState("");
  const [urlRegexes, setUrlRegexes] = useState("");
  const [action, setAction] = useState<"deny" | "allow">(preset.action);
  const [mode, setMode] = useState<"inherit" | "monitor" | "enforce">("inherit");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reset id / tool / action whenever the user picks a different preset
  // so they always see a sane starting point for the rule type.
  useEffect(() => {
    setId(preset.idSuggestion);
    setTool(preset.tool);
    setAction(preset.action);
    setError(null);
  }, [ruleType, preset]);

  const showCommand = useMemo(
    () => preset.fields.includes("command") || preset.fields.includes("all"),
    [preset.fields],
  );
  const showPath = useMemo(
    () => preset.fields.includes("path") || preset.fields.includes("all"),
    [preset.fields],
  );
  const showURL = useMemo(
    () => preset.fields.includes("url") || preset.fields.includes("all"),
    [preset.fields],
  );

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!id.trim()) {
      setError("id is required");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const splitLines = (s: string): string[] =>
        s.split("\n").map((x) => x.trim()).filter((x) => x.length > 0);

      const body: Record<string, unknown> = {
        id: id.trim(),
        tool: tool.trim() || undefined,
        action,
        mode,
      };
      if (showCommand) {
        const cmds = splitLines(commandRegexes);
        if (cmds.length > 0) body.any_command_regex = cmds;
      }
      if (showPath) {
        const paths = splitLines(pathRegexes);
        if (paths.length > 0) body.any_path_regex = paths;
      }
      if (showURL) {
        const urls = splitLines(urlRegexes);
        if (urls.length > 0) body.any_url_regex = urls;
      }
      await apiSend("/v1/policy/gates", "POST", body);
      onCreated(id.trim());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <form
        onSubmit={onSubmit}
        className="bg-panel border border-border rounded-md w-[560px] max-h-[90vh] overflow-y-auto p-5 shadow-lg"
      >
        <div className="flex items-start justify-between mb-4">
          <div className="text-sm font-semibold text-neutral-100">Add rule</div>
          <button type="button" className="oal-btn-link" onClick={onClose}>
            close
          </button>
        </div>

        <div className="space-y-3">
          <div>
            <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
              rule type
            </label>
            <select
              className="oal-input w-full"
              value={ruleType}
              onChange={(e) => setRuleType(e.target.value as RuleType)}
            >
              {(Object.keys(PRESETS) as RuleType[]).map((k) => (
                <option key={k} value={k}>
                  {PRESETS[k].label}
                </option>
              ))}
            </select>
            <p className="text-[11px] text-muted mt-1">{preset.description}</p>
          </div>

          <div>
            <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
              id <span className="text-deny">*</span>
            </label>
            <input
              className="oal-input w-full"
              value={id}
              onChange={(e) => setId(e.target.value)}
              placeholder="supply-chain.pkg-install"
              autoFocus
            />
          </div>

          <div>
            <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
              tool
            </label>
            {ruleType === "custom" ? (
              <input
                className="oal-input w-full"
                value={tool}
                onChange={(e) => setTool(e.target.value)}
                placeholder="Bash"
              />
            ) : (
              <select
                className="oal-input w-full"
                value={tool}
                onChange={(e) => setTool(e.target.value)}
              >
                {[tool, ...TOOL_OPTIONS.filter((t) => t !== tool)].map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            )}
          </div>

          {showCommand && (
            <div>
              <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
                command pattern{ruleType !== "custom" ? "" : " (any_command_regex)"}{" "}
                <span className="text-muted normal-case">— one per line</span>
              </label>
              <textarea
                className="oal-input w-full font-mono min-h-[96px]"
                value={commandRegexes}
                onChange={(e) => setCommandRegexes(e.target.value)}
                placeholder={preset.regexExamples || preset.regexPlaceholder}
              />
            </div>
          )}

          {showPath && (
            <div>
              <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
                path pattern{ruleType !== "custom" ? "" : " (any_path_regex)"}{" "}
                <span className="text-muted normal-case">— one per line</span>
              </label>
              <textarea
                className="oal-input w-full font-mono min-h-[96px]"
                value={pathRegexes}
                onChange={(e) => setPathRegexes(e.target.value)}
                placeholder={preset.regexExamples || "\\.env(\\.|$)"}
              />
            </div>
          )}

          {showURL && (
            <div>
              <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
                URL pattern{ruleType !== "custom" ? "" : " (any_url_regex)"}{" "}
                <span className="text-muted normal-case">— one per line, matched against input.url</span>
              </label>
              <textarea
                className="oal-input w-full font-mono min-h-[96px]"
                value={urlRegexes}
                onChange={(e) => setUrlRegexes(e.target.value)}
                placeholder={preset.regexExamples || "^https?://attacker\\.example"}
              />
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
                action
              </label>
              <select
                className="oal-input w-full"
                value={action}
                onChange={(e) => setAction(e.target.value as "deny" | "allow")}
              >
                <option value="deny">deny</option>
                <option value="allow">allow</option>
              </select>
            </div>
            <div>
              <label className="text-[11px] uppercase tracking-wider text-muted mb-1 block">
                mode
              </label>
              <select
                className="oal-input w-full"
                value={mode}
                onChange={(e) => setMode(e.target.value as "inherit" | "monitor" | "enforce")}
              >
                <option value="inherit">inherit</option>
                <option value="monitor">monitor</option>
                <option value="enforce">enforce</option>
              </select>
            </div>
          </div>

          {error && <div className="text-xs text-deny">{error}</div>}

          <div className="flex gap-2 pt-2">
            <button type="submit" className="oal-btn" disabled={submitting}>
              {submitting ? "Creating…" : "Create"}
            </button>
            <button type="button" className="oal-btn" onClick={onClose}>
              Cancel
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
