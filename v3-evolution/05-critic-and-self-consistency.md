# 05 — Critic LLM + self-consistency

> Scope: replace the theatrical `verify_analysis` self-check with
> (a) a separate critic LLM call with adversarial system prompt,
> and (b) N-sample self-consistency that produces a calibrated
> confidence as the agreement rate, not the model's self-report.
>
> Depends on: `07-langgraph-and-stateless.md` (graph structure),
> `04-prompt-redesign.md` (analyst prompt + checklist context).

## Goal

Two changes, applied together:

1. **Separate critic LLM call** that *only* critiques the
   analyst's verdict. Different system prompt (adversarial),
   different temperature (0.5-0.7 to defeat sycophancy),
   structured output schema.
2. **Self-consistency:** N independent analyst+critic samples per
   finding; final verdict is the plurality vote; final confidence
   is the agreement rate.

This is the single largest leverage change for the high-confidence-
false-negative failure mode the user has observed.

## Background

The current `verify_analysis` tool (`agent_tools.py:284-318`) is
called by the same agent, in the same context, on the same model.
It rubber-stamps itself ~always.

Published evidence:
- **AutoReview (FSE 2025):** +18.72% F1 from multi-agent
  research+analyst+critic vs single-agent baseline.
- **Mind the Confidence Gap (arXiv 2502.11028):** LLMs cluster
  verbalized confidence around 90/95/100. Self-reported confidence
  alone is uncalibrated.
- **CISC (arXiv 2502.06233):** confidence-weighted self-consistency
  needs ~40% fewer samples than vanilla to match accuracy. We
  start with vanilla and upgrade to CISC if cost matters.

## Critic LLM

### Role

The critic receives the analyst's verdict + the original
EvidenceBundle + the checklist, and decides one of:

- **`APPROVED`** — the analysis is sufficient; commit.
- **`NEEDS_MORE_RESEARCH`** — the verdict can't be defended with
  the evidence on hand; specific gaps listed in
  `required_information`; loop back to research.
- **`REANALYZE`** — the evidence is sufficient but the analyst's
  reasoning is flawed; specific critique provided; loop back to
  analyst with that feedback prepended.

### Critic system prompt skeleton

```text
You are a Senior Security Reviewer. You receive an analyst's
verdict on a SAST finding. Your only job is to find the weakest
point.

Standards:
- For CONFIRMED verdicts: is the path *reachable* in this specific
  code? Is there an unhandled guard the analyst missed? Cite the
  specific line.
- For NOT_EXPLOITABLE verdicts: is the cited sanitizer/guard
  *actually* effective for this vulnerability type? Does the
  analyst's reasoning rule out *every* path, or just the obvious
  one? Cite specific code.

Rules:
- "Looks fine to me" is NOT a valid output. If you approve, you
  must cite specific code in the EvidenceBundle that rules out
  each named alternative exploitation path.
- If you cannot cite specific code to defend the verdict, decision
  must be NEEDS_MORE_RESEARCH or REANALYZE.
- Do not commit to a verdict yourself; only critique.

Output: CritiqueResult JSON.
```

### Pydantic schema

```python
class CritiqueResult(BaseModel):
    decision: Literal["APPROVED", "NEEDS_MORE_RESEARCH", "REANALYZE"]
    rationale: str
    gaps: list[str] = []                  # for NEEDS_MORE_RESEARCH
    required_information: list[str] = []  # specific things to find
    reanalysis_feedback: str = ""         # for REANALYZE
    weakest_point: str                    # mandatory; even on APPROVE
    citation_lines: list[str] = []        # file:line for every claim
```

### Configuration

```python
class CriticConfig(BaseModel):
    temperature: float = 0.6
    max_research_loops: int = 2  # how many times to loop back to research
    max_reanalysis_loops: int = 2
```

Critic temperature is higher than analyst (0.6 vs 0.1) deliberately:
- Sycophancy is partly a low-entropy phenomenon — high-confidence
  tokens dominate.
- Higher T introduces enough variance for the critic to explore
  alternatives.
- The output is structured (Pydantic-validated) so prose variance
  doesn't translate into verdict variance.

## Self-consistency

### N-sample voting

For each finding, the analyst+critic loop runs N times
independently. Default N=3. Each run produces an
`AnalystVerdict` (after critic-approved) or terminates as
`REFUSED` (research loop bound hit).

Final aggregation:

```python
verdicts = [sample.verdict for sample in samples]
majority = Counter(verdicts).most_common(1)[0][0]
agreement_rate = verdicts.count(majority) / len(verdicts)

# Final confidence is agreement-driven, not self-reported.
evidence_strength = compute_evidence_strength(
    files_explored=len(set(s.evidence_refs for s in samples)),
    citations_per_step=sum(len(s.citation_lines) for s in samples) / len(samples),
)
final_confidence = 0.7 * agreement_rate + 0.3 * evidence_strength
```

### Adaptive N

Running N samples multiplies the analyst+critic cost by roughly N.
Adaptive sampling avoids paying for samples that won't change the
outcome:

- Start with N=2 samples.
- If verdicts agree and both critics APPROVED → commit with
  agreement_rate=1.0.
- If verdicts disagree → run sample 3 as tiebreaker.
- If still split → mark `PROPOSED_NOT_EXPLOITABLE` (escalate).

This typically yields ~2.2 samples per finding on average,
saving ~25% vs fixed N=3.

### Sample diversity

To get meaningful agreement signal, samples must be diverse:

- Vary analyst temperature: sample 1 = 0.1, sample 2 = 0.3,
  sample 3 = 0.5.
- Critic temperature stays at 0.6 for all.
- Optionally: vary sample seed (Vertex AI doesn't expose seeds
  reliably; temperature variation is the practical lever).

Low diversity → all samples agree by default → agreement rate is
meaningless. Build a unit test that asserts non-zero verdict
disagreement on at least 10% of gold-set findings.

## Configuration

```python
# config.py additions

ANALYST_TEMPERATURES = [0.1, 0.3, 0.5]  # used in order
CRITIC_TEMPERATURE = 0.6
DEFAULT_SAMPLES = 3
ADAPTIVE_SAMPLING = True
TIEBREAKER_THRESHOLD = 0.5  # disagreement triggers extra sample

FINAL_CONFIDENCE_WEIGHTS = {
    "agreement_rate": 0.7,
    "evidence_strength": 0.3,
}
```

## Implementation steps

1. Define `CritiqueResult` Pydantic model in
   `sast_triage/agent_models.py`.
2. Write critic system prompt in `sast_triage/prompts.py` (named
   `CRITIC_SYSTEM_PROMPT`).
3. Add critic node to the LangGraph per-finding subgraph (see
   `07-langgraph-and-stateless.md`).
4. Implement self-consistency aggregator as a separate function in
   `sast_triage/aggregator.py`. Pure function — takes N samples,
   returns final verdict + confidence + breakdown.
5. Remove `verify_analysis` tool from `agent_tools.py`. The
   critic LLM call replaces it. Tests that referenced
   `verify_analysis` need updates.
6. Run gold-set. The targets to validate: confidence calibration
   improves (ECE drops), high-confidence false negatives drop, and
   verdict stability rises — at the expense of more LLM calls per
   finding (roughly proportional to the sample count).

## Acceptance criteria

- `verify_analysis` tool removed; tests updated.
- Critic LLM runs as a distinct LLM call with different prompt and
  temperature.
- Self-consistency aggregator is unit-tested with synthetic
  sample sets (all-agree, 2/3-agree, split, all-disagree).
- Gold-set benchmark targets to validate:
  - High-confidence false-negative count drops substantially vs
    the baseline (the primary objective).
  - ECE on the confidence-vs-correctness calibration table improves.
  - Verdict stability re-run rate reaches ≥ 95%.
- Per-finding cost rises (multiple analyst+critic passes); clustering
  (`09-finding-clustering.md`) amortizes this on real workloads.
  Track the cost so the trade-off is visible, but it is a tunable
  knob (sample count), not a fixed target.

## Risks / rollback

- **Risk:** Gemini sycophancy persists despite the adversarial
  prompt; critic approves analyst nearly always. **Mitigation:**
  the gold-set will catch this — if `NEEDS_MORE_RESEARCH` /
  `REANALYZE` rates are < 5%, the critic isn't doing its job;
  tune the prompt or raise temperature. Add a deliberately-wrong
  fake `AnalystVerdict` to the test suite — the critic must reject
  it.
- **Risk:** self-consistency adds too much latency for interactive
  use. **Mitigation:** samples run in parallel via asyncio; with
  Vertex's QPM headroom, N=3 should add < 30s of wall-clock.
- **Rollback:** the aggregator is a single function; reverting to
  single-sample mode is a one-line config flip
  (`DEFAULT_SAMPLES = 1`).

## Out of scope

- Confidence-weighted self-consistency (CISC). Defer to Phase 3+
  if cost matters.
- A second critic on TOP-of the first critic. Diminishing returns;
  not worth the complexity.
- Cross-finding pattern memory (the critic remembering what it
  approved on similar findings). Phase 4+ if at all.
