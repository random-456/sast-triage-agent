# 09 — Finding clustering + representative analysis

> Scope: before running the per-finding subgraph, group incoming
> findings by structural signature. Run the full subgraph on one
> representative per group; for the rest, run a cheap
> structural-equivalence check against the representative and
> propagate its verdict only when the shapes truly match.
>
> Depends on: `07-langgraph-and-stateless.md`,
> `05-critic-and-self-consistency.md`.

## Goal

Avoid re-running the full (and relatively expensive) analyst+critic
+ self-consistency loop on findings that are structurally identical
to one already analyzed. This makes large, repetitive codebases
practical to process. How much it saves is entirely
codebase-dependent: substantial for codebases with many
structurally-identical findings, negligible for highly
heterogeneous ones. No fixed multiplier is claimed.

## Motivation

A single codebase often contains many findings that share the same
vulnerability shape — the same kind of source reaching the same
kind of sink through the same construct, differing only in location.
Analyzing each independently repeats work and, because of sampling
variance, can even produce inconsistent verdicts across findings
that are really the same issue. Clustering analyzes the shape once
and propagates, with a safety check.

## Cluster signature

Findings are grouped by a structural signature derived from the
Checkmarx dataflow. The signature uses the *kind* of source and
sink, **not their location** — so the same pattern in different
files/lines groups together:

```
(queryName, source_fingerprint, sink_fingerprint)
```

- **`queryName`** — the Checkmarx rule (e.g. `SQL_Injection`,
  `Reversible_One_Way_Hash`).
- **`source_fingerprint`** — `(name, domType)` of the first
  dataflow node.
- **`sink_fingerprint`** — `(name, domType)` of the last dataflow
  node.

**Line numbers, file names, and method lines are deliberately NOT
part of the signature.** Including them would prevent identical
patterns in different locations from grouping — the opposite of
what we want. Those fields are used only for *code retrieval*
(see `08-code-retrieval.md`), never for grouping.

All three components must be equal for two findings to share a
candidate cluster.

### Degenerate dataflows

The dataflow comes from Checkmarx (`finding.get("nodes", [])`), so it
can be empty or a single node. Handle both explicitly:

- **No nodes:** the finding cannot be fingerprinted structurally. It
  is never clustered (it forms its own singleton cluster) and always
  goes through full per-finding analysis.
- **One node:** `source_fingerprint == sink_fingerprint ==` that
  node's `(name, domType)`. It clusters normally with other
  single-node findings that share `(queryName, node)`.

The rule is the same as everywhere else in clustering: fail toward
full analysis, never toward propagating a verdict on a degenerate
signature.

### Why first/last node, not "source→sink taint"

Not every Checkmarx finding is a clean attacker-source → dangerous-
sink taint flow. Using the first and last dataflow node's
`name` + `domType` as a generic fingerprint handles both taint
flows and configuration/crypto findings without special-casing.

## Worked examples

### Example A — a crypto-misuse finding (from real Checkmarx output)

```
resultHash:  IjQ8QoUyChcGwkSE7oLELYPPjFI=
queryName:   Reversible_One_Way_Hash      (CWE-328)
dataflow[0]: name="SHA1PRNG"  domType=StringLiteral      (line 50)
dataflow[-1]: name="getInstance" domType=MethodInvokeExpr (line 50)
```

Signature:

```
queryName:           Reversible_One_Way_Hash
source_fingerprint:  ("SHA1PRNG", StringLiteral)
sink_fingerprint:    ("getInstance", MethodInvokeExpr)
```

`fileName` and `line` (50), `methodLine` (39) are excluded. Any
other finding flagging `SHA1PRNG` via `getInstance`, in any file,
shares this cluster.

### Example B — three SQL-injection findings

| Finding | queryName | source_fingerprint | sink_fingerprint | Cluster |
|---|---|---|---|---|
| A | SQL_Injection | `(getParameter, MethodInvokeExpr)` | `(executeQuery, MethodInvokeExpr)` | **1** |
| B | SQL_Injection | `(getParameter, MethodInvokeExpr)` | `(executeQuery, MethodInvokeExpr)` | **1** |
| C | SQL_Injection | `(getParameter, MethodInvokeExpr)` | `(createQuery, MethodInvokeExpr)` | **2** |

A and B share all three components → one cluster. C reaches a
different sink (`createQuery`, JPA, which parameterizes differently)
→ its own cluster, analyzed independently.

## Pipeline shape

```python
findings = fetch_from_checkmarx()
clusters = group_by_signature(findings)   # dict[signature → findings]

for signature, members in clusters.items():
    representative = pick_representative(members)
    rep_verdict = await per_finding_graph.ainvoke(representative)
    assign(representative, rep_verdict)

    for other in members:
        if other is representative:
            continue
        same_shape = await validate_structural_equivalence(
            representative, rep_verdict, other
        )
        if same_shape:
            assign(other, propagate(rep_verdict))   # confidence penalty applied
        else:
            assign(other, await per_finding_graph.ainvoke(other))
```

The outer pipeline stays plain Python (see `01-architecture.md`).

## Representative selection

`pick_representative(members)` prefers, in order:
1. The member with the most complete dataflow (longest `dataflow`).
2. Highest severity.
3. Shortest source file path (less likely to be generated code).

## Structural-equivalence validation (the safety net)

Same signature means same *source/sink kind*, but the path *between*
them can differ — one finding may have a sanitizer the other lacks.
So before propagating a verdict, a cheap check confirms the shapes
truly match:

`validate_structural_equivalence(representative, rep_verdict, other)`
— a single low-temperature LLM call (no critic, no sampling) that
sees the representative's source+sink and verdict, and the
candidate's source+sink, and answers:

```json
{ "is_same": false, "divergence_reason": "candidate passes input
  through encodeForHTML() before the sink; representative does not" }
```

If `is_same` is false, the candidate drops out of the cluster and
goes through the full per-finding subgraph. We never propagate a
verdict across a divergence the cheap check can spot.

## Confidence propagation

- Representative: full confidence from the subgraph.
- Validated members: representative confidence with a small penalty
  (e.g. ×0.95) to reflect the indirection.
- Failed validation: independent verdict with its own confidence.

The output records `clustered_with` (the representative's
`resultHash`, or `null`) and `cluster_size`, so an operator can see
which verdicts were propagated.

## Implementation steps

1. `sast_triage/clustering/__init__.py`: `FindingSignature` model,
   `group_by_signature`, `pick_representative`.
2. `validate_structural_equivalence` as a single minimal LLM call.
3. Wire into the outer pipeline.
4. `--no-clustering` flag to bypass (for debugging and for
   apples-to-apples benchmark comparison).
5. Output schema: `clustered_with`, `cluster_size`.
6. Docs: `docs/clustering.md`, plus the architecture doc.

## Acceptance criteria

- On a synthetic dataset containing many structurally-identical
  findings, total LLM calls drop in proportion to cluster sizes
  (measured, not asserted to a fixed factor), with the
  representative+validation path producing the same verdicts as
  full per-finding analysis on those members.
- On the gold-set, enabling clustering does not change classification
  metrics beyond noise (the validator catches divergent cases).
- Propagated verdicts are clearly marked (`clustered_with`).
- `--no-clustering` bypass works and is used for the benchmark
  baseline.

## Risks / rollback

- **Risk:** the cheap validator approves a divergent case →
  wrong verdict propagated. **Mitigation:** the validator must cite
  a divergence reason to *reject* and is prompted conservatively;
  the gold-set detects systematic propagation errors. When in doubt,
  it should fail to "not same" and trigger full analysis.
- **Risk:** signatures are too coarse (group things that shouldn't)
  or too fine (group nothing). **Mitigation:** the
  first/last-node fingerprint is a starting heuristic; tune on real
  findings. The validator is the backstop against
  too-coarse grouping.
- **Rollback:** `--no-clustering` is effectively a single config
  flip back to per-finding analysis.

## Out of scope

- Cross-project clustering. Findings are clustered within a project.
- Embedding-based similarity. Structural signatures are cheaper and
  sufficient to start; revisit only if they prove too coarse on the
  gold-set.
