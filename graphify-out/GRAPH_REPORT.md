# Graph Report - OpenAgentLock  (2026-04-28)

## Corpus Check
- 157 files · ~180,039 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1281 nodes · 3397 edges · 30 communities detected
- Extraction: 74% EXTRACTED · 26% INFERRED · 0% AMBIGUOUS · INFERRED: 871 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]

## God Nodes (most connected - your core abstractions)
1. `newGateFixture()` - 74 edges
2. `M()` - 57 edges
3. `NewRouter()` - 56 edges
4. `Load()` - 51 edges
5. `H()` - 45 edges
6. `e()` - 44 edges
7. `make()` - 39 edges
8. `writeJSON()` - 39 edges
9. `t()` - 36 edges
10. `next()` - 36 edges

## Surprising Connections (you probably didn't know these)
- `EventsPane()` --calls--> `slice()`  [INFERRED]
  cli/src/tui/dashboard.tsx → site/assets/javascripts/lunr/wordcut.js
- `rustTargetForGo()` --calls--> `trim()`  [INFERRED]
  cli/tests/e2e.test.ts → site/assets/javascripts/lunr/wordcut.js
- `createSession()` --calls--> `parse()`  [INFERRED]
  cli/tests/e2e.test.ts → site/assets/javascripts/lunr/wordcut.js
- `run()` --calls--> `TestMCPPin_BadBody400()`  [INFERRED]
  cli/tests/e2e.test.ts → control-plane/internal/api/mcp_test.go
- `run()` --calls--> `TestEveryNonHealthRouteIs501UntilSignoff()`  [INFERRED]
  cli/tests/e2e.test.ts → control-plane/internal/api/router_test.go

## Communities

### Community 0 - "Community 0"
Cohesion: 0.05
Nodes (202): _(), a(), Aa(), Ae(), ai(), an(), Ao(), ar() (+194 more)

### Community 1 - "Community 1"
Cohesion: 0.03
Nodes (163): addGateRequest, authBootstrapRequest, authLoginRequest, claudeHookOutput, claudeHookSpecifics, claudePostToolInput, claudePreToolInput, claudeSessionStartInput (+155 more)

### Community 2 - "Community 2"
Cohesion: 0.02
Nodes (122): onSubmit(), apiBase(), apiJSON(), apiSend(), mergeHeaders(), codexHooksFlagEnabled(), json(), createSession() (+114 more)

### Community 3 - "Community 3"
Cohesion: 0.04
Nodes (125): authFixture, gateFixture, signedFixture, Build(), newAuthFixture(), postJSON(), TestAuthBootstrap_HappyPath(), TestAuthBootstrap_SecondCallReturns409() (+117 more)

### Community 4 - "Community 4"
Cohesion: 0.04
Nodes (58): claudeAgentlockState(), devStubAgentlockState(), devStubStateForHarness(), originOf(), apiClient(), LedgerRoot, editorUserDir(), Dashboard() (+50 more)

### Community 5 - "Community 5"
Cohesion: 0.05
Nodes (74): allowlistEvaluator, alwaysEvaluator, compileEvaluator(), compileMatch(), compilePathGlob(), editDistanceAtMost1(), EvalRequest, EvalResult (+66 more)

### Community 6 - "Community 6"
Cohesion: 0.1
Nodes (35): call_leaf_hash(), call_merkle_root(), call_verify(), leaf_hash_accepts_empty_sig(), leaf_hash_matches_pure_rust(), LeafHashFFI(), merkle_root_empty_input_is_sha256_of_empty(), MerkleRoot() (+27 more)

### Community 7 - "Community 7"
Cohesion: 0.28
Nodes (30): _(), a(), b(), c(), d(), E(), er(), f() (+22 more)

### Community 8 - "Community 8"
Cohesion: 0.23
Nodes (14): _(), a(), c(), d(), f(), i(), l(), m() (+6 more)

### Community 9 - "Community 9"
Cohesion: 0.21
Nodes (13): _(), a(), c(), e(), f(), i(), k(), l() (+5 more)

### Community 10 - "Community 10"
Cohesion: 0.21
Nodes (13): a(), b(), c(), d(), e(), h(), i(), l() (+5 more)

### Community 11 - "Community 11"
Cohesion: 0.19
Nodes (14): a(), c(), d(), e(), f(), l(), m(), n() (+6 more)

### Community 12 - "Community 12"
Cohesion: 0.23
Nodes (14): _(), a(), d(), e(), f(), i(), l(), m() (+6 more)

### Community 13 - "Community 13"
Cohesion: 0.28
Nodes (13): a(), b(), c(), f(), i(), k(), l(), m() (+5 more)

### Community 14 - "Community 14"
Cohesion: 0.23
Nodes (13): AttestationPayload, assertPrintable(), CanonicalAttestation(), fixturePayload(), TestCanonicalAttestation_ByteExactFixture(), TestCanonicalAttestation_RejectsControlChar(), TestVerify_AcceptsValidSignature(), TestVerify_RejectsInvalidPubKeyLength() (+5 more)

### Community 15 - "Community 15"
Cohesion: 0.22
Nodes (11): Header(), jsonString(), ledgerTailHandler(), writeSSEEvent(), corsForLocalAPI(), Handler(), serveIndex(), TestDashboard_CspAndFrameHeaders() (+3 more)

### Community 16 - "Community 16"
Cohesion: 0.21
Nodes (7): _(), i(), l(), n(), s(), t(), u()

### Community 17 - "Community 17"
Cohesion: 0.15
Nodes (5): Authenticator, Config, LoginResult, Mode, noneAuth

### Community 18 - "Community 18"
Cohesion: 0.33
Nodes (10): a(), c(), f(), l(), m(), n(), o(), r() (+2 more)

### Community 19 - "Community 19"
Cohesion: 0.33
Nodes (10): a(), c(), d(), e(), l(), m(), n(), o() (+2 more)

### Community 20 - "Community 20"
Cohesion: 0.2
Nodes (3): fullLocal(), fullLocal(), shortTime()

### Community 21 - "Community 21"
Cohesion: 0.33
Nodes (7): a(), c(), e(), i(), s(), t(), u()

### Community 22 - "Community 22"
Cohesion: 0.25
Nodes (7): Approval, ApprovalDecision, gateCheckRequest, gateCheckResponse, Session, SignerKind, Verdict

### Community 23 - "Community 23"
Cohesion: 0.39
Nodes (6): RootLayout(), useModeInfo(), usePolicyView(), usePoll(), useRootInfo(), useSessions()

### Community 24 - "Community 24"
Cohesion: 0.4
Nodes (2): s(), t()

### Community 25 - "Community 25"
Cohesion: 0.4
Nodes (4): Entry, EntryKind, LedgerError, SignerTag

### Community 26 - "Community 26"
Cohesion: 0.5
Nodes (2): canonicalAttestation(), signAttestation()

### Community 27 - "Community 27"
Cohesion: 0.7
Nodes (4): e(), n(), r(), t()

### Community 31 - "Community 31"
Cohesion: 0.5
Nodes (1): Agentlock

### Community 32 - "Community 32"
Cohesion: 0.5
Nodes (3): Detection, SessionView, Storage

## Knowledge Gaps
- **69 isolated node(s):** `LedgerError`, `Entry`, `EntryKind`, `SignerTag`, `AttestationPayload` (+64 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 24`** (6 nodes): `e()`, `n()`, `o()`, `s()`, `t()`, `lunr.da.min.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 26`** (5 nodes): `assertPrintable()`, `canonicalAttestation()`, `escapeString()`, `signAttestation()`, `canonical.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 31`** (4 nodes): `Agentlock`, `.caveats()`, `.install()`, `agentlock.rb`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `make()` connect `Community 1` to `Community 0`, `Community 2`, `Community 3`, `Community 5`, `Community 6`?**
  _High betweenness centrality (0.218) - this node is a cross-community bridge._
- **Why does `NewRouter()` connect `Community 1` to `Community 3`, `Community 15`?**
  _High betweenness centrality (0.062) - this node is a cross-community bridge._
- **Why does `filter()` connect `Community 2` to `Community 0`, `Community 1`, `Community 4`?**
  _High betweenness centrality (0.059) - this node is a cross-community bridge._
- **Are the 67 inferred relationships involving `newGateFixture()` (e.g. with `TestSessionEnd_Returns204AndWritesLedgerEntry()` and `TestSessionEnd_UnknownSessionReturns404()`) actually correct?**
  _`newGateFixture()` has 67 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `M()` (e.g. with `.Subscribe()` and `next()`) actually correct?**
  _`M()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 51 inferred relationships involving `NewRouter()` (e.g. with `main()` and `newMCPFixture()`) actually correct?**
  _`NewRouter()` has 51 INFERRED edges - model-reasoned connections that need verification._
- **Are the 46 inferred relationships involving `Load()` (e.g. with `loadPolicy()` and `daemonMode()`) actually correct?**
  _`Load()` has 46 INFERRED edges - model-reasoned connections that need verification._