# SAST Triage Agent — Honest Assessment & Redesign Analysis

> Scope: an honest evaluation of `sast-triage-agent` as it stands today, a comparison
> against `RHEcosystemAppEng/sast-ai-workflow` and the published state of the art,
> and a concrete recommendation for how to evolve the tool given the constraint of
> only having Gemini 2.5 Pro on Vertex AI and an organizational ambition to run
> across 2000+ applications.
>
> Bottom line up front: the current tool is not fundamentally broken, but several
> of its core mechanisms (`verify_analysis` self-check, self-reported confidence,
> single-pass ReAct, generic prompt) are exactly the patterns the 2024-2026
> literature has identified as failure modes. The path forward is targeted
> structural change, not a rewrite. LangGraph is a good destination, but should
> be approached as the implementation vehicle for a redesigned flow, not as the
> redesign itself.

---

## 1. Direct answers to your questions

### 1.1 Is sast-ai-workflow really built for one repo? Why not just use Claude Code?

Yes — it was bootstrapped against Red Hat's `systemd` SAST findings and the
public artifacts (CWE checklists, the C-only `repo_handler`, the FAISS
known-FP corpus) reflect that. The current `nvidia-nat`-registered workflow
is general enough to point at any C codebase, but the tuning is C/RHEL.

That doesn't make the effort wasted, and it isn't really comparable to
running Claude Code on the codebase. There are three reasons a structured
agent beats a generalist coding agent at this specific task:

- **Determinism of the artifact.** The output of `claude` or `codex`
  on a SAST report is a chat session; the output of a triage system has
  to be a structured verdict per finding, with traceable evidence,
  feeding back into the SAST tool's own state machine
  (`TO_VERIFY` → `CONFIRMED` / `NOT_EXPLOITABLE`). You can build that on
  top of a generalist agent, but you end up reinventing exactly what
  sast-ai-workflow built.
- **Audit and reproducibility.** Each verdict needs to be defensible
  against a security auditor. A purpose-built pipeline can pin model
  versions, log structured prompt+sample sets, and evaluate against a
  ground-truth dataset. A generalist Claude Code session can't, easily.
- **Scale economics.** Running a generalist agent (Claude Code with
  Opus, no caching, no clustering) on 2 million findings is not
  cost-feasible. A purpose-built system can pre-cluster, share evidence
  across findings, and short-circuit obvious cases. (More on cost in §6.)

The single-codebase framing of sast-ai-workflow is a tactical reality
(they have one customer = Red Hat), not a sign that the architectural
shape is wrong.

### 1.2 LangChain vs LangGraph — what's the difference?

LangChain is the underlying primitives (LLM clients, tools, message types,
output parsers, the `bind_tools` mechanism). LangGraph is built on top of
LangChain and adds a stateful directed-graph execution model:

| | LangChain | LangGraph |
|---|---|---|
| Linear chain (A → B → C) | Native | Native |
| Cycles / loops back to a previous step | Awkward (manual `while True`) | First-class (conditional edges) |
| Branching based on state | Awkward | First-class (`add_conditional_edges`) |
| Inspectable, persistable graph state | No (you maintain it yourself) | First-class (`StateGraph`, checkpointing) |
| Multi-agent orchestration | DIY | Idiomatic (subgraphs, supervisor, swarm) |
| Human-in-the-loop interrupts | DIY | First-class (interrupt nodes) |

Your current code (`sast_triage/agent.py:195-321`) is a Python `for iteration in
range(max_iterations)` loop that manually appends messages and dispatches
tools — this is a hand-rolled ReAct loop sitting on top of LangChain
primitives. It works, but as soon as you want:

- a real second-LLM critic that can route back to "research more",
- circuit breakers (max critic rejections, no-progress detection),
- deterministic state replay for debugging a specific finding,
- HITL escalation as a graph state,

the manual loop becomes the wrong tool. LangGraph is the right tool for
that. It is not a magic bullet — it doesn't make weak models smarter —
but the orchestration code stops fighting you.

**My recommendation: yes, migrate, but as a means to an end.** Don't
migrate first and then figure out the architecture; design the redesigned
flow first (next sections), and let the graph fall out of that.

### 1.3 What models does sast-ai-workflow use? What's their accuracy?

- They support OpenAI-compatible endpoints and NVIDIA NIMs via
  `ChatNVIDIA`. The default config does not name a specific model; it
  reads `LLM_MODEL_NAME` from environment. There is no public statement
  from the project that they run, e.g., GPT-4 vs Llama-3.1 70B vs Gemini.
- They have **no published precision/recall**. The repo includes a
  Ragas-based evaluation framework (`evaluation/`), but no benchmark
  results in the README, no paper, no conference talk. Last release
  (v0.0.2, April 2026) is pre-1.0.
- The README's only quantitative-sounding claim is "primarily focused on
  identifying false alarms" — i.e., they're tuned for FP filtering, not
  TP recall.

**This matters more than it sounds.** Sast-ai-workflow is a credible
*reference architecture*, not a *validated system*. It is fine as
inspiration for engineering decisions; it is not evidence that a particular
design works at production quality. Your benchmark numbers will be the
first proof point either of you has.

### 1.4 Will the changes I recommended actually move the needle?

Probably yes, but with calibrated expectations. Three pieces of published
evidence:

- **ZeroFalse (arXiv 2510.02534, October 2025):** with CWE-specialized
  prompts and structured "evidence contracts," the authors hit
  F1 = 0.912 on OWASP Java Benchmark using GPT-4o-class models. The key
  finding is that *CWE-specific prompts substantially outperform generic
  ones*, which is exactly the cheapest change available to you.
- **Sifting the Noise (arXiv 2601.22952):** agentic frameworks reduce
  SAST FP rates from >92% (raw) to ~6.3% (best). But the same paper warns
  that *agentic gains shrink with weaker backbones*; the strong-model
  results don't transfer one-for-one. Gemini wasn't tested.
- **AutoReview (FSE 2025):** multi-agent for security code review beats
  single-agent baselines by +18.72% F1.

**Honest expectation for a Gemini 2.5 Pro stack with the changes I'd
recommend:** plausibly a 5-10 point F1 improvement over your current
single-pass setup, primarily through reducing high-confidence
false-negatives. *That is the failure mode you described, and it's the
one the literature most consistently fixes.* The improvement will not
be uniform — easy CWEs (path traversal, command injection) will benefit
more than hard ones (logic flaws, race conditions).

It will not get you to "Claude Opus on Claude Code" quality. The model
ceiling on Gemini 2.5 Pro for code reasoning is real — it scores ~63%
on SWE-Bench Verified vs ~73% for Sonnet 4. Structure can compensate
for some of that gap, but not all.

### 1.5 Do the changes require LangGraph?

No, technically. Per-CWE checklists, an explicit critic LLM call, and
multi-sample self-consistency can all be implemented in your existing
LangChain loop. You'd write:

```python
analysis = await analyst_llm.ainvoke(messages)
critique = await critic_llm.ainvoke(critic_messages_built_from(analysis))
if critique.verdict == "needs_more_research":
    # loop
```

**But you should still migrate, because the moment you have a real
critic with a "go back and research more" path, your single-loop control
flow turns into a state machine, and you'll start bug-fixing the
control flow more than the prompts.** I'd time the migration with the
introduction of the second LLM role: do them in the same change.

---

## 2. Honest assessment of `sast-triage-agent` today

I've read `sast_triage/agent.py`, `sast_triage/agent_tools.py`, and
`sast_triage/prompts.py`. Things that are well-engineered, things that
are theatrical, things that are fundamentally wrong.

### 2.1 What's good

- **The triage *flow* is sound.** Fetch finding → trace dataflow →
  check sanitization → decide → record. That's the right shape; you
  don't need to throw it out.
- **Production hygiene is good.** Path-traversal validation in
  `validate_safe_path`, structured Pydantic verdicts, incremental result
  saving, secret masking in preprocessing, gitleaks integration, the
  per-finding logging system — these are things many open-source SAST
  agents skip and they matter for an enterprise rollout.
- **The "uncertainty → CONFIRMED" rule (`prompts.py:26`) is the right
  *direction*.** You've identified the asymmetric cost (FN > FP) and
  encoded it. The implementation has problems (§2.3) but the principle
  is correct.
- **Preprocessing of placeholders is well-designed.** The `__IPV4__` /
  `__MASKED_SECRET__` strategy keeps secrets out of the LLM context
  without breaking analysis.

### 2.2 What's theatrical (looks like it does something, doesn't really)

- **`verify_analysis` is performative self-checking.** The same model,
  with the same conversation context, decides whether its own analysis
  is complete. There's no information asymmetry; the model has every
  reason to set `is_analysis_complete=True` to terminate the loop.
  `agent_tools.py:303-307` is essentially a rubber stamp. The published
  literature on calibration (CISC, Mind the Confidence Gap) is
  consistent that same-model self-attestation is unreliable.
- **`is_analysis_complete: bool` parameter.** A boolean that the model
  picks while looking at its own justifications. There is no
  adversarial pressure on this decision.
- **"Target 3-5 tool calls" instruction (`prompts.py:43`) fights with
  "Use a tool in every response" (line 42).** Gemini will interpret
  this as "do as few tool calls as I can get away with," which biases
  toward shallow investigation. Combined with the high-confidence-FN
  problem, this is not a coincidence.
- **Self-reported confidence as a primary signal.** Your observation
  that "confidence is quite high in most cases and even when the
  decision is wrong" *is the published failure mode*. It's not a bug
  in your prompt; it's a property of LLM verbal-confidence reports.
  - GPT-4 verbalized confidence achieves only ~62.7% AUROC at
    discriminating correct from incorrect (NAACL 2024 survey).
  - Models cluster verbalized confidence at round numbers — 90, 95,
    100 — not on a smooth 0-1 scale (arXiv 2502.11028, "Mind the
    Confidence Gap").
  - You will not fix this with prompt engineering. You fix it with
    *external* signals — sample voting, critic agreement, evidence
    counts.

### 2.3 What's fundamentally flawed

- **Single-model, single-pass triage is structurally weak for an
  adversarial review task.** You're asking the model to be both the
  defendant ("here's why this is exploitable") and the judge ("am I
  right?"). The right shape is researcher → analyst → critic, with the
  critic having a different prompt and ideally different sampling
  parameters, so disagreement is structurally possible.
- **No CWE / queryName specialization.** The system prompt
  (`prompts.py`) is one generic 50-line block applied to SQLi, XSS,
  path traversal, SSRF, command injection alike. ZeroFalse showed
  CWE-specialized prompts are the single highest-leverage change for
  this task. Each Checkmarx query family has different evidence
  requirements (SQLi: parameterization vs string concat; XSS: encoding
  context; path traversal: canonicalization vs prefix check); a
  generic prompt cannot encode all of them.
- **Message history grows unboundedly.** Your loop appends every tool
  result to `messages` (`agent.py:201`, `agent.py:309`). On a finding
  that requires 15 file reads, the model sees ~30K tokens of historical
  tool noise, and Gemini 2.5 Pro is documented (Google's own forum,
  Cursor / Copilot bug reports) to degrade in long-horizon agent mode.
  Sast-ai-workflow's "stateless prompt rebuild" pattern (CODE BANK
  injected fresh each turn, no history) is specifically a workaround
  for this — and it would help you too.
- **The "uncertainty → CONFIRMED" rule is flat.** It tells the model
  *what to do* without giving it a way to *signal* uncertainty.
  Gemini's known sycophancy means it will reinterpret its own
  uncertainty as certainty to avoid triggering the rule, then commit
  with high confidence. The fix is a graded escalation: uncertainty
  becomes `PROPOSED_NOT_EXPLOITABLE` (HITL), not silent `CONFIRMED`.
  *Your own message already proposed this — it's the right move.*
- **Findings are analyzed in isolation.** A codebase with 200 SQL
  injection findings often has 3-5 query-construction patterns; the
  current tool will trace each one individually. This is wasteful at
  scale and, more importantly, throws away the strongest signal
  available: pattern-level reasoning. (See §5 for the clustering
  redesign.)
- **Temperature 0.1 is treated as if it gives reproducibility. It
  doesn't.** Cloud LLMs lack batch invariance — your verdict can
  change because the request landed in a different inference batch
  (Thinking Machines Lab, Sept 2025). T=0 doesn't fix it. The right
  framing is *stable verdicts via aggregation*, not *deterministic
  outputs*.

### 2.4 Calibrated severity

| Issue | Severity | Effort to fix |
|---|---|---|
| `verify_analysis` is self-rubber-stamping | High | Medium (replace with separate critic LLM) |
| Self-reported confidence is the primary signal | High | Medium (add N-sample self-consistency) |
| Generic prompt; no CWE specialization | High | Low (per-queryName checklist files) |
| Message history grows unboundedly | Medium | Medium (stateless prompt rebuild) |
| Uncertainty rule has no escalation valve | Medium | Low (add `PROPOSED_NOT_EXPLOITABLE`) |
| No clustering of similar findings | Medium-High at scale | High (new pipeline node) |
| Temperature 0.1 misunderstood as deterministic | Documentation issue | Low (write it down) |
| LangChain manual loop vs LangGraph | Low *now*; medium *if you add a critic* | Medium |

---

## 3. The fundamental constraint you're working around: Gemini 2.5 Pro

The single most important fact about your redesign is the model
constraint, and it should drive the architecture.

Gemini 2.5 Pro is genuinely capable of careful reasoning, but it has
three documented failure modes that bear directly on this use case:

- **Sycophancy.** Google's own AI Developers Forum has an extended
  community thread titled "Uncontrollable and Formulaic Sycophancy
  from Gemini 2.5 Pro is Severely Impacting User Experience" — this
  is acknowledged at Google. *Implication for you:* a critic LLM
  built from the same Gemini 2.5 Pro will tend to agree with the
  analyst's verdict by default. You have to structurally force
  disagreement: different system prompt (adversarial role), different
  temperature (e.g. 0.6 instead of 0.1 for the critic), and a structured
  output that *requires citing specific code lines for every
  agreement*. "Looks fine to me" should not be a valid critic output.
- **Long-horizon agent degradation.** Multiple GitHub Copilot and
  Cursor user reports describe Gemini 2.5 Pro in agent mode "spinning
  away, adding thousands of lines without stopping" or "becoming
  terrible at following direct instructions" past ~20 turns.
  *Implication:* don't trust 30-turn ReAct loops. Cap research at, say,
  10 tool calls per phase, then force a hand-off to the analyst LLM
  with a clean "here's everything we found" prompt.
- **Tool-calling reliability.** The most-reported pain point. Robust
  schemas (Pydantic structured output everywhere), tolerant parsers,
  and a "if the model returns malformed args, give it one retry, then
  fall back" pattern.

The right framing is: **Gemini 2.5 Pro is a capable analyst that
needs an externally-imposed process.** Stronger models can self-impose
that process; Gemini cannot. Your job in the redesign is to be that
external process.

---

## 4. Recommended architecture

### 4.1 Per-finding pipeline (the core)

```
   ┌────────────────────────────────────────────────────────────┐
   │                  per-finding subgraph                      │
   │                                                            │
   │      ┌──────────┐    ┌──────────┐    ┌──────────┐          │
   │      │ Research │───▶│ Analyst  │───▶│  Critic  │          │
   │      │   LLM    │    │   LLM    │    │   LLM    │          │
   │      └──────────┘    └──────────┘    └──────────┘          │
   │           ▲              ▲                │                │
   │           │              │                │                │
   │           └─── more ─────┴─── reanalyze ──┘                │
   │              research                                      │
   │                  feedback                                  │
   │                                                            │
   │                  ┌─────────────────┐                       │
   │                  │ Self-consistency│                       │
   │                  │ aggregator      │ ◀── N samples         │
   │                  └─────────────────┘                       │
   │                          │                                 │
   │                          ▼                                 │
   │              ┌────────────────────────┐                    │
   │              │ Verdict + Calibrated   │                    │
   │              │ Confidence + Status    │                    │
   │              └────────────────────────┘                    │
   └────────────────────────────────────────────────────────────┘
```

**Three LLM roles, three different prompts, all on Gemini 2.5 Pro:**

1. **Researcher.** Tools only (no verdict). System prompt: "Gather
   evidence, do not analyze." Hard cap of N tool calls. Outputs a
   structured `EvidenceBundle` (files read, lines quoted, sanitizers
   identified). *No exit until N tool calls or `RESEARCH_COMPLETE`.*
2. **Analyst.** No tools. Sees the `EvidenceBundle` and the per-CWE
   checklist. Mandatory step structure: identify source, identify
   sink, list every line between, list every guard, classify each
   guard as effective/ineffective. Outputs structured
   `AnalystVerdict { verdict, confidence, reasoning, evidence_refs }`.
3. **Critic.** No tools. Sees the analyst's verdict, the evidence,
   and the checklist. System prompt: adversarial — *"Find the weakest
   point in this verdict. If you cannot find one, prove it by citing
   the specific code that rules out each named alternative
   exploitation path."* Outputs `CritiqueResult { decision: APPROVED |
   NEEDS_MORE_RESEARCH | DISAGREES, gaps: list[str] }`. Run at higher
   temperature (0.5-0.7) to break sycophancy.

**Self-consistency layer (the calibration win):** for each finding,
run the analyst+critic pair N=3 times (with different temperatures or
seeds), then aggregate:

- 3/3 agree, all approved → high-confidence verdict
- 2/3 agree → medium-confidence verdict
- 1/3 split or any disagreement → `PROPOSED_NOT_EXPLOITABLE` →
  human review

**The calibrated confidence is then *agreement rate × evidence
strength*, not the model's self-report.** This is the single highest-
leverage change available given the literature. CISC (Confidence-
Informed Self-Consistency, arXiv 2502.06233) is the current SOTA
implementation pattern.

This is more expensive (3× analyst+critic per finding) but you can
scope it: cheap CWE / cheap match → 1 sample; ambiguous → 3 samples;
disputed → 5. Section 6 has cost numbers.

### 4.2 Pipeline-level orchestration

Outside the per-finding subgraph, run a small linear pipeline:

```
   Fetch findings (Checkmarx)
        │
        ▼
   Cluster / dedupe by (queryName, sink_signature, source_signature)
        │
        ▼
   For each cluster: pick representative
        │
        ▼
   Run per-finding subgraph on representative
        │
        ▼
   For non-representatives in same cluster:
       fast pattern-match validation against representative's verdict
       (LLM call: "is this the same vulnerability shape?")
        │
        ▼
   Confidence-based escalation:
       - high  → CONFIRMED / NOT_EXPLOITABLE
       - medium → PROPOSED_NOT_EXPLOITABLE (HITL)
       - low or disputed → PROPOSED_NOT_EXPLOITABLE (HITL)
        │
        ▼
   Write back to Checkmarx
```

Clustering before analysis is what lets you tackle 2000 apps × 1000
findings without running the full pipeline 2 million times. It's also
where you get *better* answers, not just cheaper ones — pattern-level
reasoning lets the analyst see "this codebase uses parameterized
queries everywhere, so all 200 SQLi findings inherit that decision."

### 4.3 Concrete implementation choices

- **LangGraph for the per-finding subgraph.** This is where the loops
  and conditional routing live; LangGraph earns its keep here.
- **Plain Python orchestration for the outer pipeline.** Don't put
  cluster-and-write-back in a graph; it's linear and benefits from
  being readable.
- **Per-CWE / per-queryName checklist files** in
  `sast_triage/checklists/<query>.yaml` (steal the pattern from
  sast-ai-workflow but tailor to Checkmarx queries: SQLi, XSS_Reflected,
  Path_Traversal, SSRF, Hardcoded_*, etc.). Mapping from Checkmarx
  `queryName` → checklist file is a one-line lookup.
- **Stateless prompt rebuild for the researcher.** Each turn the
  researcher sees: (a) the finding, (b) an "evidence so far"
  block summarizing what's been fetched, (c) a "tools tried" block
  listing failed/succeeded calls. No raw message history. This is
  what sast-ai-workflow's `stateless_model_middleware` does and it's
  worth copying.
- **Temperature strategy:**
  - Researcher T=0.1 (deterministic enough; tool-call accuracy matters)
  - Analyst T=0.1 baseline; T=0.4 for self-consistency samples
  - Critic T=0.5-0.7 to break sycophancy
- **Don't copy sast-ai-workflow's confidence formula.** Their
  37.5%-weighted "agent confidence" component is the same self-report
  mistake; their formula gives the appearance of rigor without the
  calibration. Use *agreement rate from self-consistency* as the
  primary signal instead.
- **Status escalation:** add `PROPOSED_NOT_EXPLOITABLE` as a verdict
  state. Any finding that doesn't pass both confidence and agreement
  thresholds goes there, not to `NOT_EXPLOITABLE`. *This is your
  insight from the conversation; it's also the only safe way to
  deploy at scale given Gemini's miscalibration.*

---

## 5. Phased roadmap (concrete, ordered, with effort estimates)

The order matters. Each phase is independently shippable and gives a
measurable benchmark improvement.

### Phase 1 — Cheap structural wins (1-2 weeks)

Goal: ~5 F1 points improvement, no architectural change.

1. **Per-CWE / per-Checkmarx-queryName checklist files.** Map
   `queryName` from the finding to a YAML checklist; inject into the
   system prompt. Start with the top 10 query families by volume.
2. **Mandatory analysis steps in the prompt.** Replace the current
   freeform "trace the data flow" with explicit numbered steps:
   `(1) name source line, (2) name sink line, (3) enumerate every
   line between, (4) enumerate every control-flow guard, (5)
   classify each guard as effective/ineffective with code citation`.
3. **Add `PROPOSED_NOT_EXPLOITABLE` verdict.** Plumb through the
   `TriageDecision` model, the assessment output, and Checkmarx
   write-back.
4. **Document the temperature reality.** A `docs/determinism.md`
   noting that T=0 ≠ deterministic, why, and what you do about it.
   This is for your auditors and for management.

### Phase 2 — Real critic, real calibration (2-4 weeks)

Goal: kill the high-confidence-FN failure mode.

1. **Replace `verify_analysis` with a separate critic LLM call.**
   Different system prompt (adversarial), different temperature
   (0.5-0.7), structured `CritiqueResult` output. Loop back to
   research at most twice.
2. **Migrate the per-finding flow to LangGraph.** This is the
   right time. The graph is small (research / analyst / critic +
   conditional edges) and the migration is bounded.
3. **Self-consistency aggregator.** N=3 analyst+critic samples per
   finding, weighted majority verdict, agreement-rate as the
   confidence signal. Adaptive N: 1 sample for high-agreement,
   3-5 for ambiguous. Agreement rate replaces the
   `assessment_confidence` self-report as the primary signal;
   keep the self-report as a secondary diagnostic.

### Phase 3 — Scale architecture (1-2 months)

Goal: make 2000 apps × 1000 findings tractable.

1. **Finding clustering** by `(queryName, sink_function, source_kind)`.
2. **Cluster-representative analysis** with pattern-match validation
   for non-representatives. Validation is a single cheap LLM call
   per non-representative.
3. **HITL queue for `PROPOSED_NOT_EXPLOITABLE`.** Some kind of
   review UI or at minimum a structured CSV/spreadsheet export so
   analysts can sweep through the medium-confidence verdicts in bulk.
4. **Stateless prompt rebuild for the researcher node.** The longest
   investigations are where Gemini degrades most; this is where it
   pays off.

### Phase 4 — Continuous improvement (ongoing)

1. **Internal gold-set benchmark.** Take ~200 findings across CWE
   types with analyst-confirmed verdicts; this is your source of truth.
   Re-run it on every change. *No SAST AI vendor publishes a gold-set
   you can use; you'll have to build yours, and it's worth doing
   formally.*
2. **Per-CWE precision/recall dashboards.** Track regressions per
   CWE family — "we got better on SQLi but worse on path traversal"
   is information you currently can't see.
3. **A/B testing harness** for prompt changes. Run new prompt against
   gold-set; compare to baseline; ship if precision and recall both
   improve.

---

## 6. Scale and cost reality check

Rough math for a single full sweep at the scale management is asking
about. Assume Gemini 2.5 Pro on Vertex AI: ~$1.25 / 1M input tokens,
~$5 / 1M output tokens, including thinking tokens (which can dominate).

### Per-finding cost, current architecture

- ~30K input tokens × 1.25 / 1M = ~$0.04 input
- ~5K output tokens × 5 / 1M = ~$0.025 output
- Thinking can 2× this in practice
- **~$0.10-0.20 per finding**

### Per-finding cost, proposed architecture (no clustering)

- Researcher: similar to current, ~$0.10
- Analyst (×3 for self-consistency): ~$0.05-0.10 each = ~$0.20
- Critic (×3): ~$0.05-0.10 each = ~$0.20
- **~$0.50 per finding** — 3-5× current cost

### Why clustering is non-optional

- 2000 apps × 500 avg findings = 1M findings
- At $0.50 / finding without clustering = **$500K per full sweep**
- With aggressive clustering (assume 10× dedup factor on average,
  realistic for codebases with repetitive patterns): ~$50-100K
- With cheap pattern-match validation per non-representative:
  add ~$0.01 each, so 900K × $0.01 = $9K
- **Realistic full-sweep cost with clustering: $60-120K, vs $500K naive**

These numbers are rough — real cost depends heavily on codebase size,
average finding complexity, and how aggressive clustering is — but the
order of magnitude shows why §4.2 (clustering) isn't optional. It's
the difference between feasible and not.

### Throughput

Vertex AI Gemini 2.5 Pro: rate-limited but parallel-friendly. Two
findings in flight is trivial; 50 in flight needs quota uplift. At
~30s per finding (3 LLM calls × ~10s each), 50-way concurrency =
~6000 findings/hour = ~1M findings in ~7 days of wall-clock.
Reasonable for a quarterly sweep; tight for a continuous-incremental
workflow.

---

## 7. The two referenced repositories

### 7.1 `ultraworkers/claw-code`

What it is: a Rust/Python rewrite of Claude Code's tool-loop and prompt
shape, derived from the late-March 2026 Anthropic source-map leak. 191k
stars (the fastest GitHub repo to 100k stars). 96.5% Rust.

Useful for our purposes? **As reference, not as dependency.**

- Transferable patterns: tool schema design (`Read`, `Edit`, `Grep`),
  the `TodoWrite` decomposition pattern, structured stop-reasons,
  per-tool concurrency rules.
- *Not* transferable: it's a generalist coding agent. None of its
  prompts or tools are tuned for SAST triage. Copying its system
  prompt verbatim would actively hurt — Claude Code's prompt is tuned
  for "make code changes safely," not "skeptically review a security
  finding."
- Risk: legal status is murky (derivative work from a leaked source
  map), changing rapidly, no stable release, no LTS guarantee.
- The two patterns that *are* worth borrowing for SAST triage:
  - **Strict tool-result schemas** with explicit error shapes — your
    `read_file` returns either a result or `{"error": ...}`; that's
    the right pattern but you should make it Pydantic-validated.
  - **Plan / Todo decomposition** — for findings that are clearly
    multi-step (cross-file dataflow), having the agent emit a 3-bullet
    plan before tool-calling is a known win. You don't have this.

### 7.2 `JackChen-me/open-multi-agent`

What it is: a small TypeScript multi-agent orchestrator that converts
a goal into a task DAG, with MCP tool support and live tracing. MIT-
licensed. Launched April 2026.

Useful? **No.** It's small, young, no published benchmarks, no
production users beyond a niche WordPress security tool. The DAG-from-
goal idea is interesting but LangGraph already does this and is the
more battle-tested choice. Don't take a dependency on this repo.

### 7.3 What you should take from "the Claude Code leak" generally

Honestly, the actually useful insight is much simpler than the hype
suggests: **Claude Code's quality is a property of the model, not the
architecture.** The agent loop is fairly conventional ReAct with a
sensible toolbox. The reason Claude Code feels capable is that Opus
and Sonnet 4.5+ are very capable at agentic reasoning. With Gemini 2.5
Pro you can't reproduce that quality by copying the loop; you have to
compensate with structure (multi-LLM roles, self-consistency,
checklists, escalation) — exactly the redesign in §4.

---

## 8. Things I'm specifically pushing back on

You explicitly invited disagreement. Three places I think your framing
is slightly off:

### 8.1 "Maybe lowest temperature isn't always the only truth"

Right instinct, with a refinement. T=0.1 (or T=0) gives you *mode
collapse* — the model always returns its single most-confident answer,
so you can't tell whether it's confident-because-correct or
confident-because-trained-to-be. You actually *want* sampling variance
to extract a calibration signal. The right framing is:

- T=0.1 for the *single* researcher pass (you want stable tool calls).
- T=0.4-0.7 for the *N* analyst+critic samples (you want diverse
  reasoning to vote across).
- Aggregate the votes deterministically.

So "lowest temperature" is the right answer for the production-stable
parts and the wrong answer for the calibration parts. Use both.

### 8.2 "If I gave Claude Code with Opus a finding, it would do well"

Yes — but for a reason that's worth being precise about. Opus would
do well because it can self-impose the process the redesign is asking
*you* to externally impose for Gemini. The reframing: "the architecture
in §4 is what Opus does internally for free, externalized so that
Gemini 2.5 Pro can do it." This isn't a workaround for an inferior
tool; it's the right architecture *regardless of model*, because:

- It makes the verdict auditable (each role's output is logged).
- It makes calibration possible (sample voting gives an external
  signal).
- It makes the system robust to model swaps (swap in a stronger model
  later, the architecture still works; the structure isn't load-bearing
  *only* because of model weakness).

So even if you got Opus tomorrow, you'd want most of the redesign.
You'd just need fewer self-consistency samples.

### 8.3 "Maybe one big agent should analyze the codebase first, then dive into findings"

This is partly right and partly a red herring.

- **Right:** clustering and pattern-recognition (§4.2) is a real win.
  Don't analyze 200 SQLi findings independently; identify the 3-5
  query-construction patterns and reason about each pattern once.
- **Red herring:** a single "big picture" pre-analysis pass over the
  whole codebase before triage begins. This sounds appealing but in
  practice (a) the model can't hold a 100k-LOC codebase in working
  memory usefully, (b) the "summary" is more lossy than helpful for
  per-finding reasoning, and (c) you'd be paying for that pass on every
  rerun. Cluster-on-the-fly is the better instantiation of the same
  intuition.

---

## 9. Is this realistic? Can it beat what Checkmarx ships?

**Yes, on both.** Two reasons.

First, the bar Checkmarx clears is unknown. Their AI Triage product
publishes no precision/recall numbers; the only public claim is a
customer testimonial of "80% noise reduction." There is no competitive
target you have to beat — you can compete by simply being measurable.

Second, you have an advantage they don't: you control the prompt, the
schema, the escalation policy, the gold-set, and the feedback loop.
A vendor's product is tuned for the median customer; your tool can be
tuned for *your* code, *your* CWE distribution, *your* risk tolerance.
On a closed corpus that you can label, a focused pipeline reliably
beats a generic vendor product.

The realistic ceiling for a Gemini-2.5-Pro stack with the redesign in
§4 is approximately:

- **CONFIRMED recall: 0.85-0.92.** Your stated minimum is 0.90 —
  achievable but not guaranteed; the self-consistency layer is what
  makes 0.90 likely vs 0.85.
- **NOT_EXPLOITABLE precision: 0.92-0.97.** The escalation valve to
  `PROPOSED_NOT_EXPLOITABLE` is what makes the high end possible —
  you're trading recall for precision on the FP-filter side.
- **Average score (justification quality, 0-4): 2.5-3.0.** The
  CWE-specific prompts plus mandatory analysis steps are what move
  this; the critic loop is what keeps it consistent.

These are estimates, not guarantees. You'll only know once the
internal gold-set exists and the redesign is shipped. **Build the
gold-set first** — even before Phase 1, ideally — so you can measure.

---

## 10. Decisions I'd want from you before we start

You said no questions for routine things, but a few are not routine:

1. **The gold-set.** Do you have ~200 findings (across CWE types, both
   exploitable and not) with analyst-confirmed verdicts, ideally
   already in your benchmark format? If yes, we use that. If not,
   building it is Phase 0 and is worth a week's delay before any
   redesign.
2. **`PROPOSED_NOT_EXPLOITABLE` write-back.** Does Checkmarx's API
   actually accept this state for write-back from your tool?
   (`utils/checkmarx_helpers.py` would need to handle it.)
   The escalation strategy depends on this.
3. **Concurrency budget.** What's your Vertex AI Gemini 2.5 Pro QPM
   quota today? The cost numbers in §6 assume you can run ~50 findings
   in parallel; if the quota is much lower, the wall-clock for a
   2000-app sweep moves from "a week" to "a quarter."
4. **Sast-ai-workflow's stateless prompt pattern.** I'd want to lift
   the technique. Is there any organizational concern about copying
   the design (it's Apache-2.0, but you know your context)?

If we proceed, my first concrete action would be Phase 1 step 1 — the
per-CWE checklist files, mapped to your Checkmarx queryName
distribution. That's a one-day change with a measurable benchmark
delta and zero architectural risk.

---

## Sources cited

- ZeroFalse — `https://arxiv.org/abs/2510.02534`
- Sifting the Noise — `https://arxiv.org/abs/2601.22952`
- IRIS (neurosymbolic) — `https://arxiv.org/abs/2405.17238`
- AutoReview (multi-agent code review, FSE 2025) —
  `https://dl.acm.org/doi/pdf/10.1145/3696630.3728618`
- CISC (self-consistency confidence) — `https://arxiv.org/abs/2502.06233`
- Mind the Confidence Gap — `https://arxiv.org/abs/2502.11028`
- LLM Calibration Survey (NAACL 2024) —
  `https://aclanthology.org/2024.naacl-long.366/`
- Defeating Nondeterminism in LLM Inference (Thinking Machines Lab) —
  `https://thinkingmachines.ai/blog/defeating-nondeterminism-in-llm-inference/`
- Non-Determinism of "Deterministic" LLM Settings —
  `https://arxiv.org/abs/2408.04667`
- Semgrep Assistant 96% benchmark —
  `https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/`
- Vertex AI Gemini Thinking docs —
  `https://docs.cloud.google.com/vertex-ai/generative-ai/docs/thinking`
- Gemini 2.5 Pro sycophancy thread —
  `https://discuss.ai.google.dev/t/feedback-issue-uncontrollable-and-formulaic-sycophancy-from-gemini-2-5-pro-is-severely-impacting-user-experience/109255`
- RHEcosystemAppEng/sast-ai-workflow —
  `https://github.com/RHEcosystemAppEng/sast-ai-workflow`
- ultraworkers/claw-code — `https://github.com/ultraworkers/claw-code`
- JackChen-me/open-multi-agent —
  `https://github.com/JackChen-me/open-multi-agent`
- Checkmarx One Triage Assist —
  `https://checkmarx.com/product/triage-and-remediation/`
