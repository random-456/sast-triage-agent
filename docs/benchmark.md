# Benchmark

## Overview

The benchmark tool evaluates the triage agent against human-reviewed findings to measure classification accuracy and justification quality. It runs the agent on each dataset, compares results to analyst ground truth and produces per-dataset and cross-dataset KPI reports.

The benchmark loads each dataset, runs the same `run_triage` pipeline that production uses (so preprocessing, the per-finding graph and structured outputs all participate), enriches each finding with the agent verdict and a justification score, then writes per-dataset KPIs and a cross-dataset summary.

## Running the Benchmark

```bash
python run_benchmark.py [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--model` | `gemini-2.5-pro` | AI model used for triage |
| `--output` | `output` | Root output directory |
| `--compact-logs` | `false` | Forward `--compact-logs` to each `run_triage` invocation. Dev analysis only. |
| `-v, --verbose` | `false` | Enable debug-level logging |

Each dataset is paired with a Gitleaks CSV report so that secret masking runs as part of the benchmark, mirroring production preprocessing. See [Secret Reports](#secret-reports) below.

## Datasets

Datasets live in `benchmark/datasets/` as JSON files. Each file represents a Checkmarx One project with analyst-reviewed findings:

```json
{
  "project": "CXONE PROJECT NAME",
  "github_url": "GITHUB URL",
  "findings": [
    {
      "id": "FINDING ID",
      "language": "Java",
      "category": "SQL_Injection",
      "severity": "HIGH",
      "complexity": "MEDIUM",
      "analyst_triage": {
        "result": "CONFIRMED",
        "justification": "Direct string concatenation in SQL query"
      }
    }
  ]
}
```

## Secret Reports

Each dataset must be paired with a Gitleaks CSV named after the dataset stem and placed under `benchmark/secret-reports/`:

```
benchmark/datasets/my-project.json
benchmark/secret-reports/my-project.csv
```

The CSV is passed through to `run_triage` as `--gitleaks-report`, so secret masking runs during the benchmark exactly as it does in production. Datasets without a matching CSV are skipped with an error logged to the benchmark run.

## Metrics

The agent output separates the classification (`is_vulnerable`) from the advisory disposition (`suggested_state`). The benchmark mirrors that split: classification quality is measured on `is_vulnerable`, and the disposition is measured separately as an operational overlay. Tuning `CONFIDENCE_THRESHOLD` shifts findings between `NOT_EXPLOITABLE` and `PROPOSED_NOT_EXPLOITABLE`, so it changes the operational metrics but provably leaves the classification metrics unchanged.

### Binary Classification Metrics (primary)

Computed on `is_vulnerable` (positive class = vulnerable) against the analyst ground truth. Findings the agent could not classify (`is_vulnerable` is `null`) are excluded from precision and recall and counted under `refusal_rate`. These are the numbers that gate a go/no-go decision.

| Metric | Description |
|--------|-------------|
| Precision | Vulnerable class: TP / (TP + FP). Equivalent to CONFIRMED precision |
| Recall | Vulnerable class: TP / (TP + FN). Equivalent to CONFIRMED recall |
| F1 score | Harmonic mean of vulnerable-class precision and recall |
| `not_exploitable_precision` | Negative class: TN / (TN + FN). The dismissal-quality gate |
| `not_exploitable_recall` | Negative class: TN / (TN + FP) |
| TP / FP / FN / TN | Confusion counts on `is_vulnerable` |
| Evaluated count | Findings with a non-null classification on both sides |
| Refusal rate | Fraction of findings the agent did not classify |

### Operational Metrics (secondary)

Computed on `suggested_state`. They describe review burden and dismissal safety, not classification quality.

| Metric | Description |
|--------|-------------|
| `human_review_rate` | Fraction routed to `PROPOSED_NOT_EXPLOITABLE` (the review queue) |
| `confident_dismissal_precision` | Among `NOT_EXPLOITABLE` verdicts, the fraction truly non-exploitable. Null when there are no confident dismissals |
| `near_miss_save_rate` | Among true positives the agent classified as non-exploitable, the fraction the threshold rescued into `PROPOSED_NOT_EXPLOITABLE`. Null when there are no such near misses |
| `refusal_rate` | Fraction with `suggested_state` of `REFUSED` |

### Calibration

A confidence-vs-correctness table on `is_vulnerable`. Findings are binned by confidence; each bin reports average confidence, accuracy and count. The Expected Calibration Error (`ece`) is the count-weighted mean absolute gap between confidence and accuracy across bins. A well-calibrated model has an `ece` near 0.

### Legacy Metrics

Accuracy alone is misleading for SAST data. When most findings are not exploitable, a model that dismisses everything still scores high on accuracy while missing every real vulnerability. Use the per-class precision and recall above for go/no-go decisions.

| Metric | Description |
|--------|-------------|
| Average accuracy | Percentage of findings where agent matches analyst result |
| Average score | Mean justification quality score (0-4 scale) |
| Average confidence | Mean agent confidence value |

### Dimensional Breakdowns

Metrics are computed per group for each dimension:

- **Language:** Java, Python, JavaScript and so on.
- **Category:** SQL_Injection, XSS and so on.
- **Complexity:** EASY, MEDIUM, COMPLEX.
- **Severity:** CRITICAL, HIGH, MEDIUM, LOW, INFO.

Each group includes `sample_count`, the binary classification metrics and the legacy metrics.

### Target Thresholds

The table below defines two tiers for a production go/no-go decision. **Minimum** is the hard gate: a model that fails any minimum threshold should not run unsupervised. **Target** represents the level at which the agent can reliably replace manual first-pass triage.

| Metric | Minimum | Target | Rationale |
|--------|---------|--------|-----------|
| CONFIRMED recall | 0.90 | 0.95 | Missing a real vulnerability is the highest-risk failure mode. |
| CONFIRMED precision | 0.60 | 0.70 | Over-flagging is accepted to protect recall; analysts review CONFIRMED items anyway. |
| NOT_EXPLOITABLE precision | 0.90 | 0.95 | When the agent dismisses a finding it must be right; no silent misses. |
| NOT_EXPLOITABLE recall | 0.60 | 0.70 | Mirrors CONFIRMED precision; both reflect the accepted over-confirmation rate. |
| Average accuracy | 75% | 85% | Lower than typical ML targets because the agent is deliberately tuned for over-confirmation. |
| Average score | 2.0 | 2.5 | Justification quality (0-4 scale); 2.0 or above means reasoning is at least adequate. |

**Reading the thresholds:**

- **CONFIRMED recall** is the single most important metric. A value below 0.90 means more than 1 in 10 real vulnerabilities are missed, which is unacceptable for automated post-processing.
- **NOT_EXPLOITABLE precision** is the second priority. When the agent says "not exploitable", that finding leaves the review queue. A false dismissal is a silent miss.
- **CONFIRMED precision** is intentionally relaxed. The agent errs on the side of confirming when uncertain. This is a fail-safe trade-off: more analyst workload on false positives is preferable to missing real vulnerabilities.
- Precision and recall for **REFUSED** are intentionally omitted. REFUSED is a safety valve: the agent should refuse rather than guess. A high REFUSED rate signals low model confidence, not poor classification.

## Output Files

### Per-Dataset KPIs

Saved to `<output>/<project>/<timestamp>_<model>_benchmark_kpis.json`:

```json
{
  "sample_count": 42,
  "binary_classification": {
    "evaluated_count": 38,
    "true_positives": 10,
    "false_positives": 2,
    "false_negatives": 2,
    "true_negatives": 24,
    "precision": 0.83,
    "recall": 0.83,
    "f1_score": 0.83,
    "not_exploitable_precision": 0.92,
    "not_exploitable_recall": 0.92,
    "not_exploitable_f1": 0.92,
    "refusal_rate": 0.0952
  },
  "operational_metrics": {
    "human_review_rate": 0.1429,
    "confident_dismissal_precision": 0.96,
    "near_miss_save_rate": 0.5,
    "refusal_rate": 0.0714
  },
  "calibration": {
    "ece": 0.07,
    "sample_count": 38,
    "bins": [{"range": [0.9, 1.0], "count": 20, "avg_confidence": 0.93, "accuracy": 0.9}]
  },
  "average_accuracy": 90.48,
  "average_score": 2.8,
  "average_confidence": 0.85,
  "language_kpi": [{"Java": {"sample_count": 15, "binary_classification": {}, "average_score": 2.7}}],
  "category_kpi": [],
  "complexity_kpi": [],
  "severity_kpi": []
}
```

### Cross-Dataset Summary

Saved to `<output>/<timestamp>_<model>_benchmark_summary.json`. Same structure as per-dataset KPIs but aggregated across all datasets.

### Raw Results

Saved to `<output>/<project>/<timestamp>_<model>_benchmark_raw_results.json`. Contains the full enriched dataset with agent triage results and justification scores per finding.
