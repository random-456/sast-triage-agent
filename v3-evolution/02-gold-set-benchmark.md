# 02 — Gold-set benchmark (Phase 0)

> Scope: build the measurement infrastructure that gates every
> subsequent v3 phase. Without this, every architectural change is
> guesswork.
>
> Depends on: nothing (this is Phase 0).
> Blocks: every other v3-evolution doc.

## Goal

A reproducible, version-controlled benchmark dataset of human-triaged
SAST findings, plus the harness to run the current code against it
and produce baseline metrics. Every subsequent v3 change is validated
by re-running this benchmark and comparing.

## What we have

- ~100-150 manually triaged Checkmarx findings from:
  - **OWASP Juice Shop** (Node.js/TypeScript, deliberately vulnerable
    web app)
  - **OWASP WebGoat** (Java, deliberately vulnerable web app)
- Findings exported from Checkmarx One as JSON.
- Analyst verdicts (`CONFIRMED` / `NOT_EXPLOITABLE`) per finding.

## What we need to build

### 1. Dataset structure

Follow the existing `benchmark/datasets/<name>.json` shape — already
established by `benchmark/benchmark_models.py`:

```json
{
  "project": "juice-shop",
  "github_url": "https://github.com/juice-shop/juice-shop",
  "findings": [
    {
      "id": "<result hash>",
      "language": "TypeScript",
      "category": "SQL_Injection",
      "queryName": "Node_High_Risk.SQL_Injection",
      "cwe": "CWE-89",
      "severity": "HIGH",
      "complexity": "MEDIUM",
      "analyst_triage": {
        "result": "CONFIRMED",
        "justification": "<analyst note>"
      }
    }
  ]
}
```

New required fields vs the existing datasets: `queryName` and `cwe`. These are
both available from the Checkmarx One API (verify on existing fetched
data — see `utils/checkmarx_helpers.py`). If they're not present in
the user's existing exports, write a small backfill script.

Files to create:
- `benchmark/datasets/juice-shop.json`
- `benchmark/datasets/webgoat.json`
- `benchmark/secret-reports/juice-shop.csv` (Gitleaks — required by
  the existing benchmark harness)
- `benchmark/secret-reports/webgoat.csv`

### 2. TP/FP balance

OWASP test apps skew heavily toward true positives. Production
Checkmarx output skews ~85-95% toward false positives. To make the
gold-set representative:

- Include **at least 30-40 confirmed false-positive findings**
  alongside the true positives. These can come from:
  - Findings the deliberately-vulnerable apps flag but where the
    vulnerable pattern is actually defended elsewhere
  - Findings where the source isn't attacker-controlled in the
    specific deployment
  - Manually-curated findings where Checkmarx is wrong
- Document the curation rationale in `benchmark/datasets/README.md`.

The goal isn't a 50/50 split — it's that *both classes are
represented well enough to measure precision and recall meaningfully*.

### 3. Per-CWE coverage

Aim for **at least 5 findings per CWE in the top 10 CWE bins**:

| Priority | CWE | Expected findings |
|---|---|---|
| 1 | CWE-89 SQL Injection | 15-20 |
| 2 | CWE-79 XSS (any flavor) | 15-20 |
| 3 | CWE-78 Command Injection | 5-10 |
| 4 | CWE-22 Path Traversal | 5-10 |
| 5 | CWE-918 SSRF | 5-10 |
| 6 | CWE-502 Deserialization | 5-10 |
| 7 | CWE-611 XXE | 3-5 |
| 8 | CWE-352 CSRF | 3-5 |
| 9 | CWE-601 Open Redirect | 3-5 |
| 10 | CWE-798 Hardcoded Credentials | 3-5 |

If real curated counts don't match, that's fine — record the actual
distribution and acknowledge per-CWE underpowering for thin bins.

### 4. Benchmark harness updates

`benchmark/benchmark_metrics.py` already computes per-class
precision/recall/F1. Two additions:

1. **Verdict stability metric.** Re-run the same finding 5 times
   (independent agent invocations); count the proportion that
   produce the same verdict. New metric: `verdict_stability_rate`.
2. **Confidence calibration metric.** Bucket findings by reported
   confidence (`< 0.5`, `0.5-0.7`, `0.7-0.9`, `≥ 0.9`); per bucket
   compute actual accuracy. Save as `calibration_table`. Standard
   ECE (Expected Calibration Error) is the single-number version.

Add to `benchmark/benchmark_helpers.py` and surface in the per-dataset
KPI output.

## Implementation steps

1. **Day 1:** Confirm `queryName` and `cwe` fields are in the user's
   exported Checkmarx data. Write backfill script if needed.
2. **Day 1-2:** Curate the dataset. Manually review findings,
   classify TPs and FPs, write justifications. Save as
   `benchmark/datasets/{juice-shop,webgoat}.json`.
3. **Day 2:** Generate matching `gitleaks` reports for each project.
   Save under `benchmark/secret-reports/`.
4. **Day 3:** Add `verdict_stability_rate` and `calibration_table`
   metrics to `benchmark/benchmark_metrics.py`. Update output schema
   in `docs/benchmark.md`.
5. **Day 3-4:** Run the current code (`main` branch) against the
   gold-set 3 times. Record baseline numbers in
   `benchmark/results/baseline.json` and commit.
6. **Day 4:** Write `benchmark/datasets/README.md` documenting the
   curation rationale, TP/FP split, per-CWE coverage, and known
   limitations.

## Acceptance criteria

- Two dataset files committed with valid JSON matching the existing
  schema.
- Each dataset includes at least 15% false positives.
- The full benchmark harness runs end-to-end without errors against
  both datasets.
- Three independent runs of the current code produce a recorded baseline,
  with verdict-stability and calibration numbers included.
- `benchmark/datasets/README.md` documents the dataset honestly,
  including limitations (per-CWE underpowering, OWASP-app TP bias,
  language coverage gaps).

## Risks / rollback

- **Risk:** the gold-set is too small to detect a 5-point F1
  improvement. **Mitigation:** acknowledge in the README;
  prioritize growing the gold-set over time as v3 deployment yields
  more analyst-labeled findings.
- **Risk:** queryName/cwe fields aren't in the Checkmarx exports.
  **Mitigation:** the Checkmarx API does return both; if missing,
  re-fetch via the API.
- **Rollback:** none — this is pure additive infrastructure. The
  worst case is that the gold-set is too small or biased; the
  decision is to fix the gold-set, not roll back.

## Out of scope

- Adding CWE-Bench-Java as a second benchmark. The Java-only
  language coverage and different finding format (no Checkmarx-
  shape JSON) makes it a Phase 5+ enhancement, not a Phase 0
  blocker.
- Continuous integration of the benchmark (running on every PR).
  Useful eventually but adds Vertex AI cost; defer until v3.0
  ships.
