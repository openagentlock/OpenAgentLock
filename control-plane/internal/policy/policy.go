// Package policy is the deterministic YAML policy parser + evaluator.
//
// Slice-2 subset: only the `always` evaluator with action allow/deny is
// wired. typosquat / allowlist / host-allowlist / pin-tofu land in their
// own slices. The wire schema in docs/guide/policies.md is the full target; we
// parse a subset and reject the rest with a clear error.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type rawPolicy struct {
	Version  int       `yaml:"version"`
	Mode     string    `yaml:"mode"`
	Defaults rawDef    `yaml:"defaults"`
	Gates    []rawGate `yaml:"gates"`
}

type rawDef struct {
	Bash  string `yaml:"bash"`
	Read  string `yaml:"read"`
	Write string `yaml:"write"`
}

type rawGate struct {
	ID         string    `yaml:"id"`
	Source     string    `yaml:"source,omitempty"`
	Mode       string    `yaml:"mode,omitempty"`
	Severity   string    `yaml:"severity,omitempty"`
	Disabled   bool      `yaml:"disabled,omitempty"`
	Precedence string    `yaml:"precedence,omitempty"`
	Priority   int       `yaml:"priority,omitempty"`
	Match      rawMatch  `yaml:"match"`
	Evaluate   []rawEval `yaml:"evaluate"`
}

type rawMatch struct {
	Tool            string     `yaml:"tool,omitempty"`
	ToolPrefix      string     `yaml:"tool_prefix,omitempty"`
	PathGlob        string     `yaml:"path_glob,omitempty"`
	CommandRegex    string     `yaml:"command_regex,omitempty"`
	AnyCommandRegex []string   `yaml:"any_command_regex,omitempty"`
	AnyPathRegex    []string   `yaml:"any_path_regex,omitempty"`
	AnyURLRegex     []string   `yaml:"any_url_regex,omitempty"`
	AnyOf           []rawMatch `yaml:"any_of,omitempty"`
}

type rawEval struct {
	Kind   string `yaml:"kind"`
	Action string `yaml:"action,omitempty"`
	// Other fields belong to future evaluator kinds; yaml lets them through.
	Reference        string `yaml:"reference,omitempty"`
	List             string `yaml:"list,omitempty"`
	ActionOnNearMiss string `yaml:"action_on_near_miss,omitempty"`
	OnHit            string `yaml:"on_hit,omitempty"`
	OnMiss           string `yaml:"on_miss,omitempty"`
	OnKnown          string `yaml:"on_known,omitempty"`
	OnUnknown        string `yaml:"on_unknown,omitempty"`
	OnChanged        string `yaml:"on_changed,omitempty"`
	Store            string `yaml:"store,omitempty"`
	// Nudge is an optional human-readable hint surfaced alongside a deny
	// verdict so the agent gets concrete remediation guidance ("use trash
	// instead") rather than a bare block. Ignored on allow / skip.
	Nudge string `yaml:"nudge,omitempty"`
}

// Policy is the compiled form of a YAML policy.
type Policy struct {
	Hash  string
	Mode  string
	Gates []Gate
	// RawYAML is the exact bytes Load / LoadBytes parsed to produce
	// this Policy. CRUD mutation endpoints round-trip through the raw
	// form so evaluator kinds we don't model explicitly (allowlist,
	// typosquat, pin-tracker, ...) survive the rebuild.
	RawYAML []byte
}

// evalEntry pairs a compiled evaluator with the optional human-readable
// nudge string from the same evaluate[] YAML entry. Welding the two
// together via a single slice prevents the parallel-slice footgun the
// previous shape had (Evaluators + EvalNudges drifting out of sync).
type evalEntry struct {
	eval  Evaluator
	nudge string
}

type Gate struct {
	ID         string
	Mode       string // monitor | enforce — inherits Policy.Mode if empty
	Disabled   bool   // true = skip this gate during evaluation
	Source     string // daemon | registry | group | user | per-repo:<path>
	Precedence string // empty = deny-overrides; priority = compare same rule id by Priority
	Priority   int
	Match      Matcher
	// Evals is the compiled evaluate[] pipeline. Each entry carries the
	// evaluator plus its optional `nudge:` hint; the firing entry's nudge
	// gets propagated into EvalResult on a deny verdict.
	Evals []evalEntry
}

// Evaluators returns the compiled evaluators from this gate, in order.
// External callers (the read-only policy view in the API package) need
// to introspect the evaluator types without poking at the unexported
// nudge field on each entry.
func (g Gate) Evaluators() []Evaluator {
	out := make([]Evaluator, len(g.Evals))
	for i, e := range g.Evals {
		out[i] = e.eval
	}
	return out
}

// Evaluator is a step in a gate's `evaluate` pipeline. Each returns
// "allow", "deny", or "skip" (continue to the next). The first non-skip
// verdict wins.
type Evaluator interface {
	Evaluate(req EvalRequest) (verdict string)
}

// alwaysEvaluator returns a fixed verdict.
type alwaysEvaluator struct{ Action string }

func (e alwaysEvaluator) Evaluate(_ EvalRequest) string { return e.Action }

// allowlistEvaluator extracts a pkg token from the command
// (word after install/add) and checks against a set. on_hit / on_miss
// can each be allow | deny | skip.
type allowlistEvaluator struct {
	set    map[string]struct{}
	OnHit  string
	OnMiss string
}

func (e allowlistEvaluator) Evaluate(req EvalRequest) string {
	cmd, _ := req.Input["command"].(string)
	tok := extractPackageToken(cmd)
	if tok == "" {
		return "skip"
	}
	if _, ok := e.set[tok]; ok {
		return e.OnHit
	}
	return e.OnMiss
}

// hostAllowlistEvaluator extracts the first URL host out of the command
// and checks against a set.
type hostAllowlistEvaluator struct {
	set    map[string]struct{}
	OnHit  string
	OnMiss string
}

func (e hostAllowlistEvaluator) Evaluate(req EvalRequest) string {
	host := extractHostFromInput(req.Input)
	if host == "" {
		return "skip"
	}
	if _, ok := e.set[host]; ok {
		return e.OnHit
	}
	return e.OnMiss
}

// pinTofuEvaluator tracks the first-seen fingerprint for each MCP
// server and then enforces it on subsequent calls (Trust On First Use).
// State lives in a JSON file so pins survive daemon restart.
type pinTofuEvaluator struct {
	storePath string
	mu        sync.Mutex
	OnUnknown string
	OnKnown   string
	OnChanged string
}

func (e *pinTofuEvaluator) Evaluate(req EvalRequest) string {
	server, _ := req.Input["mcp_server"].(string)
	fp, _ := req.Input["mcp_fingerprint"].(string)
	if server == "" || fp == "" {
		return "skip"
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	pins, err := readPinStore(e.storePath)
	if err != nil {
		// Failing open here would let a disk fault silently wipe every
		// pin; instead surface the error by skipping the rule so the
		// pipeline's next evaluator (or the default) decides, and log
		// so an operator sees it in the daemon's stderr.
		log.Printf("pin-tofu: read %s: %v", e.storePath, err)
		return "skip"
	}
	prior, ok := pins[server]
	if !ok {
		pins[server] = fp
		if err := writePinStore(e.storePath, pins); err != nil {
			log.Printf("pin-tofu: write %s: %v", e.storePath, err)
			return "skip"
		}
		return e.OnUnknown
	}
	if prior == fp {
		return e.OnKnown
	}
	return e.OnChanged
}

func readPinStore(path string) (map[string]string, error) {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	if len(data) == 0 {
		return out, nil
	}
	if err := yaml.Unmarshal(data, &out); err != nil {
		// Fall back to JSON via yaml is fine, yaml handles both.
		return out, err
	}
	return out, nil
}

func writePinStore(path string, pins map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Emit JSON (deterministic, jq-friendly, also valid yaml).
	var b strings.Builder
	b.WriteString("{")
	keys := make([]string, 0, len(pins))
	for k := range pins {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q:%q", k, pins[k])
	}
	b.WriteString("}")
	return AtomicWriteFile(path, []byte(b.String()), 0o600)
}

// AtomicWriteFile writes bytes to a temp file in the same directory,
// fsyncs, then renames into place. A crash mid-write leaves the prior
// file intact rather than a half-written blob.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if anything below fails.
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// typosquatEvaluator flags a token that is edit-distance ≤ 1 away from
// any entry in the reference set but not an exact match. That catches
// the classic pip install reqeusts / numpty / python-requsts style
// supply-chain bait without depending on an external feed.
type typosquatEvaluator struct {
	reference []string
	Action    string
}

func (e typosquatEvaluator) Evaluate(req EvalRequest) string {
	cmd, _ := req.Input["command"].(string)
	tok := extractPackageToken(cmd)
	if tok == "" {
		return "skip"
	}
	for _, r := range e.reference {
		if tok == r {
			return "skip" // exact match, let the next evaluator decide
		}
	}
	for _, r := range e.reference {
		if editDistanceAtMost1(tok, r) {
			return e.Action
		}
	}
	return "skip"
}

// editDistanceAtMost1 returns true iff a and b are within Levenshtein
// distance 1 (single insert, delete, or substitution). Short-circuits
// when the length difference exceeds 1.
func editDistanceAtMost1(a, b string) bool {
	if a == b {
		return true
	}
	la, lb := len(a), len(b)
	if la-lb > 1 || lb-la > 1 {
		return false
	}
	// Ensure la <= lb for the two-pointer walk.
	if la > lb {
		a, b = b, a
		la, lb = lb, la
	}
	i, j := 0, 0
	diff := 0
	for i < la && j < lb {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		diff++
		if diff > 1 {
			return false
		}
		if la == lb {
			i++
			j++
		} else {
			j++
		}
	}
	if j < lb {
		diff++
	}
	return diff <= 1
}

var pkgTokenRE = regexp.MustCompile(`\b(?:install|add|-i)\s+(?:--?\S+\s+)*([A-Za-z0-9_][A-Za-z0-9_.\-]*)`)

func extractPackageToken(cmd string) string {
	m := pkgTokenRE.FindStringSubmatch(cmd)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

var urlHostRE = regexp.MustCompile(`https?://([A-Za-z0-9.\-]+)`)

func extractHostFromInput(input map[string]any) string {
	u, _ := input["url"].(string)
	if u != "" {
		if host := extractHost(u); host != "" {
			return host
		}
	}
	cmd, _ := input["command"].(string)
	return extractHost(cmd)
}

func extractHost(cmd string) string {
	m := urlHostRE.FindStringSubmatch(cmd)
	if len(m) < 2 {
		return ""
	}
	return strings.ToLower(m[1])
}

// Matcher is a compiled match expression. Either `AnyOf` is populated
// (in which case any sub-matcher that fires fires the whole) OR a set
// of the leaf criteria (Tool / ToolPrefix / PathGlob / CommandRegex).
// A Matcher with no criteria set matches nothing — a policy with that
// shape was broken at parse.
type Matcher struct {
	Tool        string
	ToolPrefix  string
	PathGlobRE  *regexp.Regexp
	Regexes     []*regexp.Regexp // compiled from command_regex + any_command_regex
	PathRegexes []*regexp.Regexp // compiled from any_path_regex — matched against input.file_path / input.path
	URLRegexes  []*regexp.Regexp // compiled from any_url_regex — matched against input.url
	AnyOf       []Matcher
}

type EvalRequest struct {
	Tool  string
	Input map[string]any
}

type EvalResult struct {
	Verdict      string // allow | deny
	RuleID       string // "default" if no gate matched
	Reason       string
	MonitorMatch bool // true when a rule matched but mode=monitor forced allow
	// OriginalVerdict is the verdict the matched evaluator returned
	// before any monitor downgrade. Carries the truth across the
	// monitor-suppressed boundary so a daemon-level firewall override
	// can re-apply the original deny without re-running the gate.
	// Equal to Verdict when MonitorMatch is false.
	OriginalVerdict string
	// Nudge is the optional human-readable hint propagated from the
	// firing evaluate clause. Populated whenever a rule with a nudge
	// matched and produced a deny — including monitor-downgraded
	// matches, so a daemon-level firewall escalation can re-surface the
	// hint. The API layer (applyDaemonModeOverride) is responsible for
	// clearing this when the agent is being allowed to proceed.
	Nudge string
	Trace []TraceItem
	// Source/Precedence/Priority describe the firing gate. They are
	// duplicated into TraceItem for layered evaluation and kept here so
	// callers that evaluate one policy can still ledger the source.
	Source     string
	Precedence string
	Priority   int
}

type TraceItem struct {
	Layer      string `json:"layer,omitempty"`
	Source     string `json:"source,omitempty"`
	RuleID     string `json:"rule_id"`
	Verdict    string `json:"verdict"`
	Precedence string `json:"precedence,omitempty"`
	Priority   int    `json:"priority,omitempty"`
}

type Layer struct {
	Name   string
	Policy *Policy
}

// Load parses YAML into a compiled Policy. Returns an error for unknown
// evaluator kinds or bad regex — callers should refuse to start the daemon
// on parse errors; silent degradation would be worse than a crashloop.
func Load(r io.Reader) (*Policy, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return loadBytesWithSource(buf, "daemon", "")
}

func loadBytesWithSource(buf []byte, source, defaultMode string) (*Policy, error) {
	var raw rawPolicy
	if err := yaml.Unmarshal(buf, &raw); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if raw.Mode == "" {
		raw.Mode = defaultMode
	}
	if raw.Mode == "" {
		raw.Mode = "monitor"
	}
	if raw.Mode != "monitor" && raw.Mode != "enforce" {
		return nil, fmt.Errorf("unknown mode %q", raw.Mode)
	}

	gates := make([]Gate, 0, len(raw.Gates))
	for _, rg := range raw.Gates {
		if len(rg.Evaluate) == 0 {
			return nil, fmt.Errorf("gate %q: missing evaluate", rg.ID)
		}
		evals := make([]evalEntry, 0, len(rg.Evaluate))
		for i, e := range rg.Evaluate {
			ev, err := compileEvaluator(e)
			if err != nil {
				return nil, fmt.Errorf("gate %q: evaluate[%d]: %w", rg.ID, i, err)
			}
			evals = append(evals, evalEntry{eval: ev, nudge: e.Nudge})
		}
		m, err := compileMatch(rg.Match)
		if err != nil {
			return nil, fmt.Errorf("gate %q: %w", rg.ID, err)
		}
		if !matcherIsUseful(m) {
			return nil, fmt.Errorf("gate %q: match has no criteria", rg.ID)
		}
		gateSource := rg.Source
		if gateSource == "" {
			gateSource = source
		}
		gates = append(gates, Gate{
			ID:         rg.ID,
			Mode:       rg.Mode,
			Disabled:   rg.Disabled,
			Source:     gateSource,
			Precedence: rg.Precedence,
			Priority:   rg.Priority,
			Match:      m,
			Evals:      evals,
		})
	}

	sum := sha256.Sum256(buf)
	return &Policy{
		Hash:    "sha256:" + hex.EncodeToString(sum[:]),
		Mode:    raw.Mode,
		Gates:   gates,
		RawYAML: append([]byte(nil), buf...),
	}, nil
}

func LoadBytes(b []byte) (*Policy, error) {
	return Load(bytes.NewReader(b))
}

// MergeRestrictiveExtension overlays a repo-local policy file onto the live
// daemon policy. Repo files are intentionally additive until their content hash
// is approved: only gates that can produce a deny are appended, while disabled
// gates, always-allow gates, and same-id overrides are ignored so an untrusted
// checkout cannot weaken daemon policy.
func MergeRestrictiveExtension(base *Policy, extension []byte, source string) (*Policy, error) {
	if base == nil || len(bytes.TrimSpace(extension)) == 0 {
		return base, nil
	}
	repo, err := loadBytesWithSource(extension, source, base.Mode)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for _, g := range base.Gates {
		seen[g.ID] = struct{}{}
	}
	merged := *base
	merged.Gates = append([]Gate(nil), base.Gates...)
	for _, g := range repo.Gates {
		if _, exists := seen[g.ID]; exists {
			continue
		}
		if !gateIsRestrictive(g) {
			continue
		}
		merged.Gates = append(merged.Gates, g)
	}
	sum := sha256.Sum256([]byte(base.Hash + "\n" + source + "\n" + string(extension)))
	merged.Hash = "sha256:" + hex.EncodeToString(sum[:])
	merged.RawYAML = append(append([]byte(nil), base.RawYAML...), extension...)
	return &merged, nil
}

func gateIsRestrictive(g Gate) bool {
	if g.Disabled {
		return false
	}
	for _, e := range g.Evals {
		if e.eval.Evaluate(EvalRequest{Tool: "__agentlock_probe__", Input: map[string]any{}}) == "deny" {
			return true
		}
	}
	allAlwaysAllow := len(g.Evals) > 0
	for _, e := range g.Evals {
		ae, ok := e.eval.(alwaysEvaluator)
		if !ok || ae.Action != "allow" {
			allAlwaysAllow = false
			break
		}
	}
	if allAlwaysAllow {
		return false
	}
	// Non-constant evaluators such as allowlist / typosquat can deny for
	// matching inputs, so keep them additive unless the gate is disabled or
	// a known always-allow override.
	return len(g.Evals) > 0
}

func (p *Policy) Evaluate(req EvalRequest) EvalResult {
	for _, g := range p.Gates {
		if g.Disabled {
			continue
		}
		if !gateMatches(g, req) {
			continue
		}
		verdict := "skip"
		firingIdx := -1
		for i, e := range g.Evals {
			v := e.eval.Evaluate(req)
			if v == "skip" {
				continue
			}
			verdict = v
			firingIdx = i
			break
		}
		if verdict == "skip" {
			// Every evaluator skipped — treat as not-matched so later
			// gates (or the default) get a chance.
			continue
		}
		effectiveMode := g.Mode
		if effectiveMode == "" {
			effectiveMode = p.Mode
		}
		reason := fmt.Sprintf("matched rule %s (%s)", g.ID, verdict)
		// Pull the nudge from the firing evaluator's entry. The slice is
		// always built alongside the evaluators (see Load), so the index
		// is guaranteed in range — no bounds check needed.
		var nudge string
		if firingIdx >= 0 {
			nudge = g.Evals[firingIdx].nudge
		}
		if effectiveMode == "monitor" {
			// Nudge is preserved through monitor downgrade so daemon-level
			// firewall escalation can re-attach it; the API layer decides
			// whether to surface it.
			return EvalResult{
				Verdict:         "allow",
				RuleID:          g.ID,
				Reason:          "monitor: " + reason,
				MonitorMatch:    true,
				OriginalVerdict: verdict,
				Nudge:           nudge,
				Trace: []TraceItem{{
					Source:     g.Source,
					RuleID:     g.ID,
					Verdict:    verdict,
					Precedence: g.Precedence,
					Priority:   g.Priority,
				}},
				Source:     g.Source,
				Precedence: g.Precedence,
				Priority:   g.Priority,
			}
		}
		// Only carry the nudge through on a deny verdict; an allow
		// outcome means the agent is proceeding and doesn't need a hint.
		var resultNudge string
		if verdict == "deny" {
			resultNudge = nudge
		}
		return EvalResult{
			Verdict:         verdict,
			RuleID:          g.ID,
			Reason:          reason,
			OriginalVerdict: verdict,
			Nudge:           resultNudge,
			Trace: []TraceItem{{
				Source:     g.Source,
				RuleID:     g.ID,
				Verdict:    verdict,
				Precedence: g.Precedence,
				Priority:   g.Priority,
			}},
			Source:     g.Source,
			Precedence: g.Precedence,
			Priority:   g.Priority,
		}
	}
	return EvalResult{
		Verdict:         "allow",
		RuleID:          "default",
		Reason:          "no rule matched",
		OriginalVerdict: "allow",
	}
}

func EvaluateLayered(base *Policy, layers []Layer, req EvalRequest) EvalResult {
	if base == nil {
		return EvalResult{Verdict: "allow", RuleID: "default", Reason: "no policy loaded", OriginalVerdict: "allow"}
	}
	results := make([]EvalResult, 0, len(layers)+1)
	baseResult := base.Evaluate(req)
	if baseResult.RuleID != "default" {
		baseResult.Trace = stampTraceLayer(baseResult.Trace, "daemon")
		results = append(results, baseResult)
	}
	for _, layer := range layers {
		if layer.Policy == nil {
			continue
		}
		r := layer.Policy.Evaluate(req)
		if r.RuleID == "default" {
			continue
		}
		r.Trace = stampTraceLayer(r.Trace, layer.Name)
		results = append(results, r)
	}
	if len(results) == 0 {
		return baseResult
	}
	effective := collapsePriorityConflicts(results)
	chosen := effective[0]
	for _, r := range effective {
		if r.OriginalVerdict == "deny" {
			chosen = r
			break
		}
	}
	chosen.Trace = flattenTrace(results)
	if chosen.Reason == "" {
		chosen.Reason = "matched layered policy"
	}
	return chosen
}

func stampTraceLayer(items []TraceItem, layer string) []TraceItem {
	out := append([]TraceItem(nil), items...)
	for i := range out {
		if out[i].Layer == "" {
			out[i].Layer = traceLayer(out[i], layer)
		}
	}
	return out
}

func traceLayer(item TraceItem, fallback string) string {
	if strings.HasPrefix(item.Source, "per-repo:") {
		return item.Source
	}
	return fallback
}

func flattenTrace(results []EvalResult) []TraceItem {
	var out []TraceItem
	for _, r := range results {
		out = append(out, r.Trace...)
	}
	return out
}

func collapsePriorityConflicts(results []EvalResult) []EvalResult {
	bestByRule := map[string]int{}
	drop := map[int]struct{}{}
	for i, r := range results {
		if r.Precedence != "priority" {
			continue
		}
		if prior, ok := bestByRule[r.RuleID]; ok {
			if r.Priority >= results[prior].Priority {
				drop[prior] = struct{}{}
				bestByRule[r.RuleID] = i
			} else {
				drop[i] = struct{}{}
			}
			continue
		}
		bestByRule[r.RuleID] = i
	}
	out := make([]EvalResult, 0, len(results))
	for i, r := range results {
		if _, ok := drop[i]; !ok {
			out = append(out, r)
		}
	}
	return out
}

func gateMatches(g Gate, req EvalRequest) bool {
	return matcherMatches(g.Match, req)
}

func matcherMatches(m Matcher, req EvalRequest) bool {
	if len(m.AnyOf) > 0 {
		for _, sub := range m.AnyOf {
			if matcherMatches(sub, req) {
				return true
			}
		}
		return false
	}
	if m.Tool != "" && m.Tool != req.Tool {
		return false
	}
	if m.ToolPrefix != "" && !strings.HasPrefix(req.Tool, m.ToolPrefix) {
		return false
	}
	if m.PathGlobRE != nil {
		fp, _ := req.Input["file_path"].(string)
		if !m.PathGlobRE.MatchString(fp) {
			return false
		}
	}
	if len(m.Regexes) > 0 {
		cmd, _ := req.Input["command"].(string)
		if cmd == "" {
			return false
		}
		hit := false
		for _, re := range m.Regexes {
			if re.MatchString(cmd) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(m.PathRegexes) > 0 {
		// Read / Write / Edit tools surface the target path under
		// file_path; some harnesses use plain path. Accept either.
		p, _ := req.Input["file_path"].(string)
		if p == "" {
			p, _ = req.Input["path"].(string)
		}
		if p == "" {
			return false
		}
		hit := false
		for _, re := range m.PathRegexes {
			if re.MatchString(p) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(m.URLRegexes) > 0 {
		// WebFetch / WebSearch surface the target under `url`. Lets a
		// net-egress gate match by destination host without needing a
		// bash-command regex on `curl`/`wget`.
		u, _ := req.Input["url"].(string)
		if u == "" {
			return false
		}
		hit := false
		for _, re := range m.URLRegexes {
			if re.MatchString(u) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func compileEvaluator(re rawEval) (Evaluator, error) {
	switch re.Kind {
	case "always":
		if re.Action != "allow" && re.Action != "deny" {
			return nil, fmt.Errorf("always.action must be allow|deny, got %q", re.Action)
		}
		return alwaysEvaluator{Action: re.Action}, nil
	case "allowlist":
		set, err := loadAllowlist(re.List)
		if err != nil {
			return nil, fmt.Errorf("allowlist.list %q: %w", re.List, err)
		}
		if err := validateOnVerdict(re.OnHit); err != nil {
			return nil, fmt.Errorf("on_hit: %w", err)
		}
		if err := validateOnVerdict(re.OnMiss); err != nil {
			return nil, fmt.Errorf("on_miss: %w", err)
		}
		return allowlistEvaluator{set: set, OnHit: re.OnHit, OnMiss: re.OnMiss}, nil
	case "host-allowlist":
		set, err := loadAllowlist(re.List)
		if err != nil {
			return nil, fmt.Errorf("host-allowlist.list %q: %w", re.List, err)
		}
		if err := validateOnVerdict(re.OnHit); err != nil {
			return nil, fmt.Errorf("on_hit: %w", err)
		}
		if err := validateOnVerdict(re.OnMiss); err != nil {
			return nil, fmt.Errorf("on_miss: %w", err)
		}
		// lowercase for case-insensitive host comparison
		lc := make(map[string]struct{}, len(set))
		for k := range set {
			lc[strings.ToLower(k)] = struct{}{}
		}
		return hostAllowlistEvaluator{set: lc, OnHit: re.OnHit, OnMiss: re.OnMiss}, nil
	case "pin-tofu":
		if re.Store == "" {
			return nil, fmt.Errorf("pin-tofu.store required")
		}
		store := expandEnv(re.Store)
		if err := validateOnVerdict(re.OnUnknown); err != nil {
			return nil, fmt.Errorf("on_unknown: %w", err)
		}
		if err := validateOnVerdict(re.OnKnown); err != nil {
			return nil, fmt.Errorf("on_known: %w", err)
		}
		if err := validateOnVerdict(re.OnChanged); err != nil {
			return nil, fmt.Errorf("on_changed: %w", err)
		}
		return &pinTofuEvaluator{
			storePath: store,
			OnUnknown: re.OnUnknown,
			OnKnown:   re.OnKnown,
			OnChanged: re.OnChanged,
		}, nil
	case "typosquat":
		set, err := loadAllowlist(re.Reference)
		if err != nil {
			return nil, fmt.Errorf("typosquat.reference %q: %w", re.Reference, err)
		}
		action := re.ActionOnNearMiss
		if action == "" {
			action = "deny"
		}
		if action != "deny" && action != "skip" {
			return nil, fmt.Errorf("typosquat.action_on_near_miss must be deny|skip, got %q", action)
		}
		ref := make([]string, 0, len(set))
		for k := range set {
			ref = append(ref, k)
		}
		return typosquatEvaluator{reference: ref, Action: action}, nil
	default:
		return nil, fmt.Errorf("evaluator kind %q not supported", re.Kind)
	}
}

// expandEnv substitutes $AGENTLOCK_HOME (or any $VAR) at policy-load time
// so pin-tofu stores can live under the daemon's state dir without
// hardcoding an absolute path in the policy file.
func expandEnv(s string) string {
	return os.ExpandEnv(s)
}

func validateOnVerdict(v string) error {
	switch v {
	case "allow", "deny", "skip":
		return nil
	}
	return fmt.Errorf("must be allow|deny|skip, got %q", v)
}

// loadAllowlist reads a list into a set. Supports two syntaxes so tests
// stay self-contained:
//   - "__INLINE__:a,b,c"           → literal items inline
//   - "path/to/file.txt"           → newline-separated, # comments
func loadAllowlist(spec string) (map[string]struct{}, error) {
	set := map[string]struct{}{}
	if strings.HasPrefix(spec, "__INLINE__:") {
		for _, tok := range strings.Split(strings.TrimPrefix(spec, "__INLINE__:"), ",") {
			t := strings.TrimSpace(tok)
			if t != "" {
				set[t] = struct{}{}
			}
		}
		return set, nil
	}
	data, err := os.ReadFile(spec)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = struct{}{}
	}
	return set, nil
}

func compileMatch(rm rawMatch) (Matcher, error) {
	var m Matcher
	if len(rm.AnyOf) > 0 {
		m.AnyOf = make([]Matcher, 0, len(rm.AnyOf))
		for i, sub := range rm.AnyOf {
			c, err := compileMatch(sub)
			if err != nil {
				return Matcher{}, fmt.Errorf("any_of[%d]: %w", i, err)
			}
			if !matcherIsUseful(c) {
				return Matcher{}, fmt.Errorf("any_of[%d]: empty sub-matcher", i)
			}
			m.AnyOf = append(m.AnyOf, c)
		}
		return m, nil
	}
	m.Tool = rm.Tool
	m.ToolPrefix = rm.ToolPrefix
	if rm.PathGlob != "" {
		re, err := compilePathGlob(rm.PathGlob)
		if err != nil {
			return Matcher{}, fmt.Errorf("path_glob %q: %w", rm.PathGlob, err)
		}
		m.PathGlobRE = re
	}
	if rm.CommandRegex != "" {
		re, err := regexp.Compile(rm.CommandRegex)
		if err != nil {
			return Matcher{}, fmt.Errorf("command_regex: %w", err)
		}
		m.Regexes = append(m.Regexes, re)
	}
	for _, s := range rm.AnyCommandRegex {
		re, err := regexp.Compile(s)
		if err != nil {
			return Matcher{}, fmt.Errorf("any_command_regex %q: %w", s, err)
		}
		m.Regexes = append(m.Regexes, re)
	}
	for _, s := range rm.AnyPathRegex {
		re, err := regexp.Compile(s)
		if err != nil {
			return Matcher{}, fmt.Errorf("any_path_regex %q: %w", s, err)
		}
		m.PathRegexes = append(m.PathRegexes, re)
	}
	for _, s := range rm.AnyURLRegex {
		re, err := regexp.Compile(s)
		if err != nil {
			return Matcher{}, fmt.Errorf("any_url_regex %q: %w", s, err)
		}
		m.URLRegexes = append(m.URLRegexes, re)
	}
	return m, nil
}

// matcherIsUseful requires at least one concrete criterion. AnyPathRegex
// counts as a criterion so a secret-read gate with tool=Read + path
// regexes (no command regex) still compiles.
func matcherIsUseful(m Matcher) bool {
	if len(m.AnyOf) > 0 {
		return true
	}
	return m.Tool != "" ||
		m.ToolPrefix != "" ||
		m.PathGlobRE != nil ||
		len(m.Regexes) > 0 ||
		len(m.PathRegexes) > 0 ||
		len(m.URLRegexes) > 0
}

// compilePathGlob compiles a minimal glob syntax (`**`, `*`, `?`, literals)
// into an anchored regex. Enough to express the paths the baseline policy
// uses — secret-read `**/.env*` / `**/.ssh/**` etc — without pulling a
// full glob dependency.
func compilePathGlob(g string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	i := 0
	for i < len(g) {
		// Handle `**/` and `**` before any single `*`.
		if i+2 <= len(g) && g[i] == '*' && g[i+1] == '*' {
			if i+3 <= len(g) && g[i+2] == '/' {
				b.WriteString("(?:.*/)?")
				i += 3
				continue
			}
			b.WriteString(".*")
			i += 2
			continue
		}
		switch c := g[i]; c {
		case '*':
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
		i++
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
