# Design decisions

A log of design decisions about agent reasoning, prompts, routing, topology and classification quality. Each entry records the date, the decision, the context that prompted it, why it was chosen and the alternatives that were rejected. Newest first.

---

## 2026-06-04: Honest confidence on uncorroborated samples

**Context.** Self-consistency votes over the analyst samples and the aggregator turns the agreement rate into the final confidence. On a finding that loops through refinement (`NEEDS_MORE_RESEARCH` or `REANALYZE`) the analyst replaces the in-progress sample instead of appending (`graph/analyst.py`), so a looping finding can reach the aggregator with a single sample. `tally` over one vote returns `agreement_rate = 1.0` by definition (`top_count == len == 1`), which is not agreement at all: it is one opinion. The aggregator blended that 1.0 into the confidence (`0.7 * 1.0 + 0.3 * evidence_strength`) and reported `agreement_rate = 1.0` as a diagnostic, overstating corroboration on exactly the hardest findings. (issue #77, F3)

**Decision.** In the aggregator, credit the agreement term only when at least `_MIN_CORROBORATING_SAMPLES` (2) samples back the verdict. Below that the confidence rests on evidence strength alone (`(1 - CONFIDENCE_AGREEMENT_WEIGHT) * evidence_strength`) and `agreement_rate` is reported as `None` (undefined with one sample, matching the empty-sample path). The single-sample justification states "a single analyst sample (no self-consistency corroboration)" rather than claiming a percentage agreed. The multi-sample path and the split path are unchanged.

**Why.**

- A single sample carries no agreement signal, so crediting `agreement_rate = 1.0` was a calibration error that inflated both the confidence and the `agreement_rate` diagnostic precisely where the reasoning was least corroborated.
- The change is recall-safe by construction. It never touches `is_vulnerable`, and `derive_state` maps a positive classification to `CONFIRMED` at any confidence, so a single-sample exploitable verdict stays `CONFIRMED` with an honest, lower confidence.
- It changes no disposition in production. A single-sample aggregation can only occur on a non-`approved` stop, because an `APPROVED` verdict always collects a second sample (`target_samples_for` is floored at `INITIAL_SAMPLES`), and the existing non-convergent clamp already routed those not-exploitable dismissals to `PROPOSED_NOT_EXPLOITABLE`. The fix corrects the reported confidence and the agreement diagnostic, which feed calibration and the benchmark, and removes the reliance on the clamp as the sole guard for the single-sample case.
- `_MIN_CORROBORATING_SAMPLES` is the structural "needs a second opinion" minimum, kept separate from `INITIAL_SAMPLES` (the sampling policy) so a later change to the sample count cannot silently re-enable single-sample agreement credit.

**Alternatives rejected.**

- Decouple refinement from sampling so looping findings accumulate independent samples (the structural F3 fix). Rejected for now: it ripples through the analyst, routing, state and the circuit breakers and multiplies LLM cost on the hardest findings, for a marginal false-negative payoff once the clamp already closes the silent-miss path. Revisit if gold-set calibration shows hard findings being mis-dismissed on an approved stop.
- Leave the single-sample confidence as is. Rejected: it keeps a misleading 1.0 agreement diagnostic and an inflated confidence, which corrupts calibration and the benchmark confidence reporting, and leaves the clamp as the only guard.

**Scope.** issue #77 F3, the aggregator confidence only. It affects the confidence number and the `agreement_rate` diagnostic, not the classification, so it cannot regress CONFIRMED recall; validate against the benchmark for calibration. Honest termination on an evidence stall (the other Step 2 item) is a separate change.

## 2026-06-02: False-negative-averse checklist subsystem

**Context.** The per-CWE checklists guide the analyst and critic on what evidence to gather and which controls neutralize each vulnerability class. A review (issue #77) found they were inconsistent on the project's false-negative-averse stance and in places nudged dismissal: the two XSS checklists framed auto-escaping as making "most findings false positives"; the generic fallback let a finding be dismissed on an assumed single-tenant deployment; several checklists let a control be credited without reading it (a query builder that "binds by default", a "plain data argument"); and a source whose origin could not be verified (another system, a database of unknown provenance) could be treated as not attacker-controlled. Separately, DOM/client XSS (Checkmarx `Client_Potential_XSS`) had no checklist and fell through to the reflected-XSS one, whose "returned as JSON, so not XSS" reasoning is wrong for a client-side sink. The schema also allowed a checklist with no evidence items or no bypass list to load silently.

**Decision.**

- Render one shared DEFAULT STANCE into every checklist from `render_checklist_section`, so the research, analyst and critic nodes all see it: the sink is decisive; a source of unverifiable origin is attacker-controlled and a dismissal on source grounds requires the evidence to prove the value cannot be attacker-influenced; a control counts only when read in the evidence, not assumed; and where no effective control is established the verdict leans CONFIRMED (the undecidable/null path is preserved). One source of truth that a per-CWE file cannot omit.
- Remove the dismissal-leaning priors: the XSS "most findings are false positives" framing becomes "auto-escaping is per-sink and per-context, confirm it at the sink"; the generic single-tenant/privileged-local dismissal becomes "provably not attacker-influenced (constant, enum, code-fixed)" plus an explicit "do not dismiss on an assumed deployment model".
- Fix the highest false-negative content gaps the review found: the SQLi "auto-parameterizes by default" false positive (now requires reading the call), the JS `parseInt('1; DROP')` bypass, the command-injection "usually NOT_EXPLOITABLE" framing (now gated on a fixed program, no option injection, no re-enabled shell and not an interpreter), and path-traversal zip-slip and basename platform caveats.
- Add an `xss_dom` checklist for DOM/client XSS and route `Client_Potential_XSS` (a confirmed queryName) to it; route `CWE-116` (improper output encoding) to `xss_reflected`.
- Harden the schema: `evidence_required` and `sanitizer_patterns.ineffective` must be non-empty and free-text fields must not be blank, so a guard-removing checklist cannot load silently.

**Why.**

- The stance lives once and is seen by every node, so the analyst's lean-exploitable rule is reinforced exactly where the per-CWE control lists could otherwise override it.
- Requiring source non-influence to be proven, rather than assuming trust, closes the same unearned-confidence failure as the F1 and F2 changes, on the source side.
- The DOM checklist closes a real lost-true-positive path: a client-side XSS routed to the reflected checklist could be dismissed on the server Content-Type.
- Keeping the stance in one place leaves the per-CWE files focused on CWE-specific evidence, which is easier to keep accurate.

**Alternatives rejected.**

- Restate the lean-CONFIRMED rule in each of the six YAMLs. Rejected as duplication a seventh checklist could forget; the renderer is a single source of truth covering current and future checklists.
- Fold DOM guidance into `xss_reflected`. Rejected because DOM XSS has different sources and sinks and the server-Content-Type reasoning does not apply; a dedicated checklist routed on the confirmed queryName is clearer.
- Leave the source criterion as "attacker-controlled" without the provenance rule. Rejected: it lets the analyst dismiss a finding whose source it merely cannot prove is user-controlled, which is a false negative.

**Scope.** The issue #77 comprehensive-review item on prompts and checklists. It affects classification quality, so validate against the benchmark and do not regress CONFIRMED recall.

## 2026-06-02: Stop asserting that requested evidence was gathered

**Context.** When the critic returns `NEEDS_MORE_RESEARCH` or `REANALYZE` with a `required_information` list, the analyst's refinement message (`graph/analyst.py`) appended `"Missing information that has now been gathered: <list>"`. That claim was unconditional: it asserted the listed evidence was in hand whether or not research had found it, and research often cannot find it because the evidence is outside the cloned repository. On a real run (issue #77) the analyst then reasoned "the evidence has now been provided, confirming this" and committed a verdict on evidence that never arrived. The same mechanism confabulates in either direction: that run resolved to CONFIRMED (safe), but an invented "an effective guard was found" would resolve to NOT_EXPLOITABLE and lose a true positive. (issue #77, Step 1)

**Decision.** Rewrite the refinement message to state what the reviewer requested, not that it was obtained: `"The reviewer asked for this additional information: <list>"`. Nothing claims the information is present. The analyst system prompt already requires grounding every claim in a concrete `file:line` from the CODE BANK, so the analyst checks what is actually there.

**Why.**

- The model violated its own grounding rule because the refinement message overrode it with a direct false assertion. Removing the falsehood lets the existing rule work rather than layering on another rule.
- This is the confabulation half of the false-negative risk. The confidence clamp (the other Step 1 change) only catches verdicts that stop without critic approval; a confabulated verdict the critic then approves would not be clamped, so the message itself must not seed a false premise.
- Truthful framing is direction-agnostic: it removes the push toward both a fabricated CONFIRMED and a fabricated NOT_EXPLOITABLE.

**Alternatives rejected.**

- Add a rule telling the analyst to trust only evidence in the CODE BANK. Rejected as redundant: that rule already exists in the analyst system prompt. The problem was a message that contradicted it, so the fix is to remove the contradiction, not to add a second rule.
- Make the message conditional on whether research actually grew the CODE BANK. Rejected as more complex and unnecessary: the analyst can already see the CODE BANK and is instructed to ground claims in it, so stating the request truthfully is enough.

**Scope.** This is the second issue #77 Step 1 change, alongside the confidence clamp. Step 2 (honest termination when evidence is unobtainable, self-consistency under refinement) is separate.

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
