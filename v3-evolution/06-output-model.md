# 06 — Output model: classification + disposition

> Scope: separate the agent's output into a raw classification
> (`is_vulnerable`) and a derived disposition (`suggested_state`),
> with a calibrated confidence between them. Introduces
> `PROPOSED_NOT_EXPLOITABLE` as a disposition for low-confidence
> dismissals. The tool never writes back to Checkmarx; all output
> is advisory and lives in the local result files.
>
> Depends on: `02-gold-set-benchmark.md`.
> Pairs with: `05-critic-and-self-consistency.md` (produces the
> confidence the disposition is derived from).

## Goal

A per-finding output that cleanly separates two different things:

1. **Classification** — what the agent believes: is this finding
   exploitable or not?
2. **Disposition** — what to do about it, given how confident the
   agent is.

Conflating these is what makes a verdict scheme hard to measure.
Separating them keeps the benchmark stable and gives a human
reviewer a prioritized queue.

## Read-only constraint (global)

The tool **only reads from Checkmarx One**. It never writes any
triage state back — not `CONFIRMED`, not `NOT_EXPLOITABLE`, not
`PROPOSED_NOT_EXPLOITABLE`. Every verdict is advisory and is stored
only in the local analysis output file and the benchmark. (Checkmarx
One's predicates endpoint *does* accept these states; not writing
back is a deliberate scope choice, not a platform limitation.
Write-back may be added later but is out of scope here.)

This must be stated plainly in the shipped documentation so an
operator understands the tool produces recommendations, not
mutations.

## Output schema

Per finding:

```json
{
  "resultHash": "IjQ8QoUyChcGwkSE7oLELYPPjFI=",
  "is_vulnerable": true,
  "confidence": 0.86,
  "suggested_state": "CONFIRMED",
  "justification": "The finding is CONFIRMED because ...",
  "agreement_rate": 1.0,
  "sample_count": 3
}
```

- **`is_vulnerable`**: `true` | `false` | `null`. The classification.
  `null` means the agent could not decide (maps to `REFUSED`).
- **`confidence`**: `0.0`–`1.0`. Calibrated, agreement-based (see
  `05-critic-and-self-consistency.md`), not the model's self-report.
- **`suggested_state`**: the disposition — a pure function of the
  two fields above.
- **`agreement_rate`**, **`sample_count`**: diagnostics from the
  self-consistency layer.

## Disposition derivation

`suggested_state` is computed deterministically:

```python
def derive_state(is_vulnerable, confidence):
    if is_vulnerable is None:
        return "REFUSED"
    if is_vulnerable:
        return "CONFIRMED"  # never softened — see below
    if confidence >= CONFIDENCE_THRESHOLD:
        return "NOT_EXPLOITABLE"
    return "PROPOSED_NOT_EXPLOITABLE"
```

Rules:

- **`is_vulnerable=true` → always `CONFIRMED`**, regardless of
  confidence. A false negative (missing a real vulnerability) is the
  worst outcome, so positives are always surfaced. We deliberately
  do **not** add a "PROPOSED_CONFIRMED" — there's no value in hedging
  a positive when the cost model says always surface it.
- **`is_vulnerable=false` + high confidence → `NOT_EXPLOITABLE`**.
- **`is_vulnerable=false` + low confidence → `PROPOSED_NOT_EXPLOITABLE`**.
  The agent leans toward dismissal but isn't confident enough to
  stand behind it; flagged for human attention.
- **`is_vulnerable=null` → `REFUSED`**.

`CONFIDENCE_THRESHOLD` is a single config value. Its initial value
is not knowable a priori — set a conservative placeholder (high
threshold ⇒ more findings routed to `PROPOSED_NOT_EXPLOITABLE`) and
calibrate against the gold-set in Phase 0/1.

## Why this keeps the benchmark clean

The headline insight: **classification metrics are computed on
`is_vulnerable`; the disposition is measured separately as an
operational overlay.** Tuning `CONFIDENCE_THRESHOLD` moves findings
between `NOT_EXPLOITABLE` and `PROPOSED_NOT_EXPLOITABLE` *without
changing the classification metrics at all*. So the core quality
measure does not need re-adapting every time the threshold is tuned.

### Core classification metrics (primary)

Computed on `is_vulnerable` vs the analyst ground truth (binary):

- Precision, recall, F1 — per CWE and overall.
- `is_vulnerable=null` (REFUSED) findings are excluded from
  precision/recall and tracked separately as `refusal_rate`.

These are the numbers that gate every v3 phase.

### Operational metrics (secondary, additive)

Computed on `suggested_state`:

- **`human_review_rate`** — fraction of findings routed to
  `PROPOSED_NOT_EXPLOITABLE`. This is the review-burden knob: lower
  threshold ⇒ fewer escalations ⇒ less review but more risk.
- **`confident_dismissal_precision`** — among findings the tool
  marked `NOT_EXPLOITABLE` (the confident dismissals), the fraction
  that were truly non-exploitable per ground truth. This must be
  very high; it's the number that would matter most *if* write-back
  is ever enabled.
- **`near_miss_save_rate`** — among true positives that the agent
  *classified* as non-exploitable, the fraction that the confidence
  threshold nonetheless routed to `PROPOSED_NOT_EXPLOITABLE` (caught
  before becoming a silent miss).

These are extra columns in the KPI output; they do not alter the
classification metrics.

## Changes required

### 1. `sast_triage/agent_models.py`

```python
class SuggestedState(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    PROPOSED_NOT_EXPLOITABLE = "PROPOSED_NOT_EXPLOITABLE"
    REFUSED = "REFUSED"

class TriageDecision(BaseModel):
    resultHash: str
    is_vulnerable: bool | None
    confidence: float = Field(ge=0.0, le=1.0)
    suggested_state: SuggestedState
    justification: str
    agreement_rate: float | None = None
    sample_count: int | None = None
```

The legacy `assessment_result` / `assessment_confidence` /
`assessment_justification` field names should be migrated to the
above. If any downstream consumer depends on the old names,
provide them as read-only computed aliases during the transition
rather than carrying two sources of truth.

### 2. Verdict assembly

The self-consistency aggregator (`sast_triage/aggregator.py`)
produces `is_vulnerable` + `confidence` + diagnostics. A single
`derive_state(...)` call produces `suggested_state`. One place,
pure function, unit-testable.

### 3. `config.py`

```python
CONFIDENCE_THRESHOLD = 0.85  # placeholder; calibrate on the gold-set
```

### 4. Summary counts

`_build_assessment_output` reports counts for all four
`suggested_state` values plus `refusal_rate`.

### 5. Benchmark

`benchmark/benchmark_metrics.py`:
- Compute precision/recall/F1 on `is_vulnerable`.
- Add `human_review_rate`, `confident_dismissal_precision`,
  `near_miss_save_rate`, `refusal_rate`.
- Surface a confidence-vs-correctness calibration table (ECE) on
  `is_vulnerable` + `confidence`.

## Acceptance criteria

- Output files carry `is_vulnerable`, `confidence`,
  `suggested_state`, and the diagnostics.
- `derive_state` is unit-tested across the truth table (true /
  false-high / false-low / null).
- Benchmark computes classification metrics on `is_vulnerable` and
  the operational metrics on `suggested_state`, and changing
  `CONFIDENCE_THRESHOLD` provably leaves classification metrics
  unchanged (a regression test asserts this).
- Documentation states the read-only constraint plainly.

## Risks / rollback

- **Risk:** downstream tooling expects the old single
  `assessment_result` field. **Mitigation:** computed aliases
  during transition; remove once consumers migrate.
- **Risk:** `human_review_rate` is uncomfortably high at the
  placeholder threshold. **Mitigation:** expected before
  calibration; tune on the gold-set. A high rate pre-calibration is
  a sign the threshold is conservative, which is the safe default.
- **Rollback:** `suggested_state` can collapse
  `PROPOSED_NOT_EXPLOITABLE` → `NOT_EXPLOITABLE` via raising the
  threshold to 0.0, without removing the field.

## Out of scope

- Write-back of any kind to Checkmarx.
- A review UI for the `PROPOSED_NOT_EXPLOITABLE` queue (operators
  use Checkmarx One's UI or a CSV export).
- Time-based auto-decay of `PROPOSED_NOT_EXPLOITABLE`.
