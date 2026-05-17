# 09 — Finding clustering + representative analysis

> Scope: before running the per-finding subgraph, cluster the
> incoming Checkmarx findings by structural signature. Run the full
> subgraph only on one representative per cluster; for
> non-representatives, run a cheap "is this the same shape?"
> validation against the representative's verdict.
>
> Depends on: `07-langgraph-and-stateless.md` (per-finding
> subgraph in place),
> `05-critic-and-self-consistency.md` (the
> per-finding cost we're trying to amortize).

## Goal

Make the 2000-app × ~1000-finding scale tractable. Realistic
clustering reduces total LLM cost by 5-10× on typical real-world
projects.

## Motivation

Without clustering, a codebase with 200 SQLi findings will run the
full per-finding subgraph (researcher → analyst → critic, N
samples) 200 times. In practice:

- Many of those findings share the same source pattern
  (e.g. unsanitized `request.body.X`).
- Many share the same sink pattern (e.g. `executeQuery(...)`).
- Many share the same exact query-construction template.
- A single analytical verdict applies to all of them: "this
  codebase uses raw string concat for query construction, so all
  SQLi findings on this pattern are CONFIRMED."

Running the analyst+critic loop on each separately is wasteful
*and* worse: the agent sometimes flip-flops between findings
because of sampling variance.

## Cluster signature

Group findings by the tuple `(queryName, sink_signature,
source_signature)`:

- **`queryName`** — already available from Checkmarx.
- **`sink_signature`** — derived from the sink dataflow node:
  `(sink_file_basename, sink_function_name, sink_method_called)`.
- **`source_signature`** — derived from the source dataflow node:
  `(source_kind, source_param_or_field)`.

Findings with identical signatures form a cluster.

This is **structural similarity**, not semantic. It uses
Checkmarx's already-emitted dataflow metadata. No embeddings,
no LLM calls for clustering itself.

## Pipeline shape

```
findings = fetch_from_checkmarx()

clusters = group_by_signature(findings)
# clusters: dict[signature → list of findings]

for sig, members in clusters.items():
    representative = pick_representative(members)
    rep_verdict = await per_finding_graph.ainvoke(representative)

    for other in members:
        if other is representative:
            continue
        # Cheap validation: same shape → inherit verdict
        validated = await pattern_match_validate(
            representative, rep_verdict, other
        )
        if validated:
            assign_verdict_with_propagated(other, rep_verdict)
        else:
            # Shape diverged; analyze independently
            other_verdict = await per_finding_graph.ainvoke(other)
            assign_verdict(other, other_verdict)

write_all_back_to_checkmarx()
```

## Representative selection

`pick_representative(members)`:

- Prefer the member with the most-complete dataflow info
  (longest `nodes` array).
- Tiebreaker: highest severity.
- Tiebreaker: shortest `sink_file` path (probably less
  generated code).

The picked representative gets the full subgraph treatment.

## Pattern-match validation

`pattern_match_validate(representative, rep_verdict, other)`:

A single cheap LLM call (temperature 0.1, no critic, no samples).
The model sees:

- The representative's source+sink (10 lines each)
- The representative's verdict + 2-sentence justification
- The candidate finding's source+sink (10 lines each)

Asks one yes/no question:

> "Is the candidate finding structurally equivalent to the
> representative? Specifically: same source pattern, same sink
> pattern, no different intermediate guards. Return JSON: `{is_same:
> bool, divergence_reason: str}`."

If `is_same=True`, inherit the representative's verdict, with a
small confidence penalty (the representative's confidence ×
0.95).

If `is_same=False`, drop out of the cluster and run the full
subgraph on this finding independently. Don't trust the cheap
check alone for a flip-flop.

## Confidence propagation

- Cluster representative verdict: full confidence from the
  subgraph (see `05-critic-and-self-consistency.md`).
- Propagated verdicts on validated members: representative's
  confidence × 0.95.
- Failed validation: finding goes through the full subgraph,
  getting its own confidence.

Track in the output: `clustered_with_representative: str |
None`. Lets analysts see which verdicts were propagated.

## Cost math

Typical real-world project assumption:

- 500 findings
- 10× clustering ratio (50 unique structural patterns)

Without clustering:
- 500 × (full subgraph cost) = 500 × ~$0.50 = $250

With clustering:
- 50 × (full subgraph) = $25
- 450 × (cheap validation, ~$0.005) = $2.25
- Total: ~$27 — about 10× cheaper

At organization scale (2000 apps × 500 findings = 1M findings):
- Without clustering: ~$500K per full sweep
- With 10× clustering: ~$50-100K per full sweep

Real ratios depend heavily on codebase shape — small monorepos
with repetitive patterns benefit most; small varied codebases
benefit least.

## Implementation steps

1. Add `sast_triage/clustering/__init__.py` with
   `group_by_signature` and `pick_representative`.
2. Define `FindingSignature` Pydantic model.
3. Write `pattern_match_validate` as a single LLM call with a
   minimal prompt.
4. Wire into the outer pipeline (in `agent.py` /
   `run_triage.py:_run_triage_analysis`).
5. Add a `--no-clustering` CLI flag to bypass clustering for
   debugging / benchmarking comparisons.
6. Add to the assessment output schema:
   `clustered_with_representative: str | None`,
   `cluster_size: int`.
7. Update `docs/benchmark.md` and `docs/architecture.md`.

## Acceptance criteria

- A synthetic dataset with known repetitive patterns (e.g. 100
  near-identical SQLi findings) demonstrates ≥ 5× cost reduction
  vs no-clustering.
- On the gold-set, clustering doesn't degrade overall F1 (the
  validator is robust enough to catch divergent cases).
- Propagated verdicts are clearly marked in the output and in
  per-finding logs.
- `--no-clustering` bypass works.

## Risks / rollback

- **Risk:** the cheap validator inappropriately approves a
  divergent case → wrong verdict propagated. **Mitigation:** the
  validator's prompt is conservative; it must cite the
  divergence reason for any approval. Gold-set benchmark detects
  systematic errors.
- **Risk:** clusters are unstable across runs (signature hashing
  varies). **Mitigation:** signature is deterministic over
  Checkmarx's output; the only variance source is the API itself.
- **Rollback:** `--no-clustering` flag is the rollback;
  effectively a single config flip.

## Out of scope

- Cross-project clustering. Each project's findings are clustered
  in isolation. Cross-project pattern recognition is a future
  enhancement (and depends on FAISS-style infrastructure that v3
  explicitly defers).
- Embedding-based similarity. Structural signature is sufficient
  and orders-of-magnitude cheaper. Reconsider only if structural
  clustering proves too coarse on the gold-set.
- Cluster merging based on verdict agreement. Adds complexity for
  marginal benefit.
