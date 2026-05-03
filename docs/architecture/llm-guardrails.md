# LLM-based guardrails (roadmap)

> **Status: <span class="md-status-pill not-yet">Not yet implemented</span>** — design is in flight; this doc captures the shape we're aiming at so policy authors and contributors can reason about it before code lands.

OpenAgentLock's evaluator is intentionally **deterministic YAML**: a path-shape match plus a verdict. That is the right default — fast, auditable, no LLM-shaped failure modes in the hot path. But there are policy questions that genuinely cannot be decided by regex, and forcing them through `command_regex` produces either dangerous false negatives or unworkable false positives. Examples we've hit in the wild:

- "Block prompt-injected requests to leak credentials" — the malicious instruction may be in any tool input, in any wording.
- "Refuse to assist with self-harm or weapons synthesis" when the agent is wrapping a chat assistant.
- "Block exfiltration of company-confidential content" when the content is extracted from real source files (not a regex away).

For these we want a second tier of evaluator that calls into a small **safety classifier** model — running locally — and returns a numeric score that policy can act on.

## Reference: Llama 3.1 NemoGuard

The shape we're targeting is close to NVIDIA's [`llama-3.1-nemotron-safety-guard-8b-v3`](https://build.nvidia.com/nvidia/llama-3_1-nemotron-safety-guard-8b-v3). Input: a tool-call or message payload + the agent's recent context. Output: structured JSON over a fixed taxonomy:

```json
{
  "safe": false,
  "categories": {
    "violent_crimes": false,
    "non_violent_crimes": false,
    "sex_crimes": false,
    "child_exploitation": false,
    "indiscriminate_weapons": true,
    "hate": false,
    "self_harm": false,
    "intellectual_property": false,
    "privacy": false,
    "specialized_advice": false,
    "elections": false,
    "code_interpreter_abuse": false,
    "profanity": false
  },
  "rationale": "request mentions enrichment of fissile material..."
}
```

A guardrail-typed gate consumes this verdict.

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

1. **Local-first.** Model serving runs on the same host as the daemon. No prompts leave the box. Default backend is `ollama` (which already supports the NeMo Guard models); we'll wire `vllm` and `llama.cpp` as alternates.
2. **Abstain, not deny, on failure.** If the model is slow/unavailable, the rule abstains (returns `skip`) rather than denying — guardrails must not become a DoS surface. The `monitor` policy mode logs the abstention.
3. **Deterministic core stays primary.** Guardrail evaluators run *after* deterministic regex/glob matchers. The simple matchers absorb the easy cases; the LLM only sees what the policy explicitly routes to it.
4. **Same audit trail.** Verdicts include the classifier output; ledger entries record `signer`, `model`, and the structured taxonomy verdict so a verifier can reproduce the call.

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
| Add `kind: llm_guardrail` to the policy schema, parser only | <span class="md-status-pill not-yet">Not yet implemented</span> |
| `/v1/llm/models` registry endpoint | <span class="md-status-pill not-yet">Not yet implemented</span> |
| First evaluator implementation against `ollama` running NeMo Guard locally | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Latency / cache / abstain semantics + tests | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Community-rule shape (`schema_version: 2` adds the kind) | <span class="md-status-pill not-yet">Not yet implemented</span> |
| Dashboard UI shows model verdicts in the event row | <span class="md-status-pill not-yet">Not yet implemented</span> |

## Why a roadmap doc instead of just an issue

Guardrail rules will look very different from regex rules — they ship the model id, threshold table, and a context-extraction recipe. We want contributors to the [openagentlock/rules](https://github.com/openagentlock/rules) registry to be able to author these without running into "is the schema settled yet?" — and to be able to author against a stable wire shape *before* the evaluator lands so the rules are ready when the daemon ships support.

If you're interested in helping land any of the not-yet-implemented rows, file an issue on the main repo. The two highest-leverage starting points are the `/v1/llm/models` registry and an ollama-backed first evaluator.
