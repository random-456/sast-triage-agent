# Design decisions

A log of design decisions about agent reasoning, prompts, routing, topology and classification quality. Each entry records the date, the decision, the context that prompted it, why it was chosen and the alternatives that were rejected. Newest first.

---

## 2026-06-02: Clamp confidence on non-convergent termination

**Context.** The per-finding graph can terminate on a circuit breaker (`max_research` or `max_reanalysis`) without the critic ever approving the verdict. The aggregator computed the final confidence from `agreement_rate` and `evidence_strength` and ignored the stop reason. On a finding that loops through `NEEDS_MORE_RESEARCH`, each refinement replaces the single in-progress sample (`graph/analyst.py`), so the aggregator votes over one sample: `agreement_rate` is then trivially 1.0 and confidence is `0.7 * 1.0 + 0.3 * evidence_strength`, floored at 0.70 and clearing `CONFIDENCE_THRESHOLD` (0.85) once evidence strength reaches 0.5. A not-exploitable verdict at or above the threshold becomes `NOT_EXPLOITABLE` and leaves the review queue with no human seeing it. That is a silently lost true positive, the failure mode the tool is built to avoid, and it was reachable from the confidence math alone without any reasoning error. (issue #77, Step 1)

**Decision.** In the aggregator, when the loop stopped without genuine critic approval (`stop_reason != "approved"`) and the verdict is not-exploitable (`is_vulnerable is False`), cap the confidence at `NON_CONVERGENT_CONFIDENCE_CAP` (0.8, below `CONFIDENCE_THRESHOLD`). This routes the finding to `PROPOSED_NOT_EXPLOITABLE` for human review. Positive verdicts are not touched. The justification states that the analysis stopped without approval and the verdict is unconfirmed. The cap value is a conservative placeholder to be calibrated against the gold-set, like `CONFIDENCE_THRESHOLD` itself.

**Why.**

- A confident dismissal must be earned by genuine convergence (critic approval), not produced by a breaker firing.
- The cap is recall-safe by construction. `derive_state` maps a positive classification to `CONFIRMED` regardless of confidence, so capping only ever moves a non-convergent dismissal from `NOT_EXPLOITABLE` to `PROPOSED_NOT_EXPLOITABLE`. It cannot lower CONFIRMED recall, the primary gated metric.
- A hard cap guarantees the result lands below the threshold for every non-convergent dismissal, independent of the input confidence.
- The classification (`is_vulnerable=False`) is preserved, so a wrong dismissal still counts against recall in the benchmark rather than being hidden.
- The condition `stop_reason != "approved"` covers every non-convergent stop at once: the two breakers, the defensive no-critique path and any future stop reason such as the reserved `no_progress`.

**Alternatives rejected.**

- Multiplier on confidence (for example `confidence * 0.9`). The issue suggested this. Rejected because the outcome depends on the constant and the input: a high enough starting confidence can still clear the threshold. A hard cap guarantees the property and is simpler to reason about.
- Reclassify non-convergent dismissals as `REFUSED` (set `is_vulnerable` to None). Rejected because it removes the finding from the recall denominator, flatters the classification metrics and hides misses. `PROPOSED_NOT_EXPLOITABLE` keeps the miss visible while still routing to a human.
- Route non-convergent findings to `CONFIRMED`. Rejected because it floods the confirmed queue with unvalidated findings, hurts CONFIRMED precision and misrepresents what the agent concluded.
- Fix only the single-sample agreement inflation (ignore agreement below two samples). Rejected as too narrow: it misses non-convergent stops that did accumulate samples, such as `max_reanalysis` with two agreeing samples. The deeper cause of the single-sample case (refinement replacing the sample) is tracked separately as issue #77 Step 2.

**Scope.** This is issue #77 Step 1, the confidence clamp only. The companion Step 1 item (the refinement message in `graph/analyst.py` that asserts requested evidence was gathered) and all of Step 2 (honest termination when evidence is unobtainable, self-consistency under refinement) are separate changes.
