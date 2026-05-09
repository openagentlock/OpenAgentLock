# LLM-based guardrails (roadmap)

> **Status: <span class="md-status-pill shipped">Initial external-provider slice shipped</span>** — OpenAgentLock now has startup-env provider configuration, catalog discovery, runtime classifier evaluation for NVIDIA-style guardrails, and web/TUI visibility. Broader policy-schema integration and community-rule contribution flows remain roadmap.

OpenAgentLock's evaluator is intentionally **deterministic YAML**: a path-shape match plus a verdict. That is the right default — fast, auditable, no LLM-shaped failure modes in the hot path. But there are policy questions that genuinely cannot be decided by regex, and forcing them through `command_regex` produces either dangerous false negatives or unworkable false positives. Examples we've hit in the wild:

- "Block prompt-injected requests to leak credentials" — the malicious instruction may be in any tool input, in any wording.
- "Refuse to assist with self-harm or weapons synthesis" when the agent is wrapping a chat assistant.
- "Block exfiltration of company-confidential content" when the content is extracted from real source files (not a regex away).

For these we want a second tier of evaluator that calls into a **safety classifier** model and returns a structured result that OpenAgentLock can audit. The first shipped slice supports external hosted providers as an explicit opt-in. Local-only operation remains the default when no provider is configured.

## Severity model

Each category in a guardrail verdict carries a severity from a fixed ordered scale:

```
none < low < medium < high < critical
```

Comparison operators (`>=`, `>`, `=`) in the policy's `on_threshold` block are evaluated against this ordering. The literal `category: any` matches if **any** category meets the threshold.

The classifier we wrap may emit raw boolean per-category flags rather than severities directly. The OpenAgentLock-side adapter normalizes those into the scale above using a per-model mapping table — for the NemoGuard models, a `true` flag maps to `high` by default, with overrides shipped in the model registry entry.

## Reference: Llama 3.1 NemoGuard

The shape we're targeting is close to NVIDIA's [`llama-3.1-nemotron-safety-guard-8b-v3`](https://build.nvidia.com/nvidia/llama-3_1-nemotron-safety-guard-8b-v3). Input: a tool-call or message payload + the agent's recent context. Output: structured JSON over a fixed taxonomy. The classifier emits booleans; the daemon-side adapter rewrites them into severity scores before the gate's `on_threshold` block evaluates:

```jsonc
// Classifier output, before adapter rewrite:
{
  "safe": false,
  "categories": {
    "indiscriminate_weapons": true,
    "privacy": false,
    "self_harm": false
    // ... etc
  },
  "rationale": "request mentions enrichment of fissile material..."
}

// After OpenAgentLock adapter rewrite — what the policy sees:
{
  "safe": false,
  "categories": {
    "indiscriminate_weapons": { "severity": "high",   "raw": true  },
    "privacy":                { "severity": "none",   "raw": false },
    "self_harm":              { "severity": "none",   "raw": false }
  },
  "rationale": "request mentions enrichment of fissile material..."
}
```

A guardrail-typed gate then matches `severity: ">= high"` against `indiscriminate_weapons` and the `category: any` rule fires.

## Proposed gate shape

```yaml
gates:
  - id: guardrail.injection-resistance
    match:
      tool: "*"            # apply to every tool call
    evaluate:
      - kind: llm_guardrail
        model: nemoguard-8b   # local registry of models
        on_threshold:
          # any high-severity category trips deny
          - category: any
            severity: ">= high"
            action: deny
          # specific categories mapped explicitly
          - category: privacy
            severity: ">= medium"
            action: deny
        cache_ttl: 60s        # avoid re-classifying identical payloads
        max_latency: 400ms    # cap; on timeout the rule abstains
```

Key invariants:

1. **Local policy first.** Deterministic YAML policy runs before external guardrails. Local deny stops immediately; external guardrails only run after a local allow.
2. **Abstain, not deny, on failure.** If the model is slow/unavailable, the rule abstains (returns `skip`) rather than denying — guardrails must not become a DoS surface. The `monitor` policy mode logs the abstention.
3. **Deterministic core stays primary.** Guardrail evaluators run *after* deterministic regex/glob matchers. The simple matchers absorb the easy cases; the LLM only sees what the policy explicitly routes to it.
4. **Same audit trail.** Verdicts keep local policy, guardrail, and final verdicts distinct. A guardrail deny is not presented as a deterministic YAML rule hit.

## Shipped external-provider slice

The daemon exposes:

- `GET /v1/guardrails/providers`
- `POST /v1/guardrails/providers/{id}/test`
- `GET /v1/guardrails/catalog`
- `PUT /v1/guardrails/enabled`
- `GET /v1/guardrails/traces/{seq}`

Provider credentials are read from environment variables when the control plane starts, not from the web dashboard or CLI:

```bash
NVIDIA_API_KEY=... OPENROUTER_API_KEY=... docker compose up -d
```

The daemon stores these keys in RAM only. They are never written by the dashboard and are cleared on daemon restart.

Provider behavior:

- NVIDIA catalog entries are normalized as `classifier_model` entries and can run in the post-local-policy runtime stage.
- OpenRouter guardrails are normalized as `account_policy` entries. They are visible in catalog surfaces but do not run as OpenAgentLock runtime classifiers in this slice, so they should be treated as catalog visibility rather than enforcement.
- Provider errors, unsupported runtime entries, and malformed classifier responses produce `abstain`, not implicit allow or deny.

## Wire shape

A new evaluator kind in the policy schema:

```yaml
- kind: llm_guardrail
  model: <model-id>            # required; resolved via /v1/llm/models
  prompt_field: input.command  # which path on the tool call to send
  context_fields:              # optional extra context
    - input.file_path
    - session.policy_hash
  on_threshold: [...]
  cache_ttl: 60s
  max_latency: 400ms
```

Policies can mix-and-match — most rules will stay regex; a small number will route through the classifier when the regex tier reports an ambiguous match.

## Rollout plan

| Step | Status |
|---|---|
| Roadmap doc (this file) | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/guardrails/providers` provider registry endpoint | <span class="md-status-pill shipped">Shipped</span> |
| `/v1/guardrails/catalog` normalized provider catalog | <span class="md-status-pill shipped">Shipped</span> |
| NVIDIA runtime classifier integration | <span class="md-status-pill shipped">Shipped</span> |
| OpenRouter account-policy catalog visibility | <span class="md-status-pill shipped">Shipped</span> |
| Startup-env RAM provider key configuration | <span class="md-status-pill shipped">Shipped</span> |
| Catalog cache / abstain semantics + tests | <span class="md-status-pill shipped">Shipped</span> |
| Provider-measured runtime latency in traces | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Dashboard and TUI multi-stage trace visibility | <span class="md-status-pill shipped">Shipped</span> |
| Add `kind: llm_guardrail` to the policy schema, parser only | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Local `ollama` / `vllm` / `llama.cpp` backends | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Community-rule shape (`schema_version: 2` adds the kind) | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Opt-in community contribution pipeline | <span class="md-status-pill not-yet">Not yet implemented</span> |

## Why a roadmap doc instead of just an issue

Guardrail rules will look very different from regex rules — they ship the model id, threshold table, and a context-extraction recipe. We want contributors to the [openagentlock/rules](https://github.com/openagentlock/rules) registry to be able to author these without running into "is the schema settled yet?" — and to be able to author against a stable wire shape *before* the evaluator lands so the rules are ready when the daemon ships support.

If you're interested in helping land any of the not-yet-implemented rows, file an issue on the main repo. The two highest-leverage starting points are the `/v1/llm/models` registry and an ollama-backed first evaluator.
