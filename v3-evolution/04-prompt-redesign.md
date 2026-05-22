# 04 — Prompt redesign: CWE checklists + mandatory analysis steps

> Scope: replace the single generic system prompt with (a)
> per-CWE evidence checklists selected by `queryName`/`cwe`, and
> (b) mandatory step-by-step analysis protocol in the analyst
> prompt. Highest-leverage prompt-engineering change in v3.
>
> Depends on: `02-gold-set-benchmark.md`,
> `03-llm-backend.md`.

## Goal

Two changes:

1. **Per-CWE checklists.** Each finding's analyst prompt is built
   from a CWE-specific evidence checklist (~15 of these, covering
   80%+ of typical Checkmarx findings).
2. **Mandatory analysis steps.** The analyst prompt enforces a
   numbered protocol (identify source, identify sink, enumerate
   path, enumerate guards, classify each guard) instead of
   freeform "trace the data flow."

These together implement the single highest-leverage finding from
the ZeroFalse paper (CWE-specific prompts) and address Gemini 2.5
Pro's documented preference for explicit step-lists over principles.

## Background — why this works

Published evidence:

- **ZeroFalse (arXiv 2510.02534):** CWE-specialized prompts +
  structured evidence "contracts" hit F1 = 0.912 on OWASP Java
  Benchmark.
- **Gemini 2.5 Pro behavior:** documented preference for explicit
  step-lists over high-level principles, both in community reports
  and in Google's own prompting guidance.

## Part 1 — Checklists

### File layout

```
sast_triage/checklists/
├── _mapping.yaml          # queryName + cwe → checklist file
├── _schema.yaml           # shape every checklist must conform to
├── sqli.yaml              # CWE-89
├── xss_reflected.yaml     # CWE-79 (reflected sub-flavor)
├── xss_stored.yaml        # CWE-79 (stored sub-flavor)
├── xss_dom.yaml           # CWE-79 (DOM sub-flavor)
├── command_injection.yaml # CWE-78, CWE-77
├── path_traversal.yaml    # CWE-22
├── ssrf.yaml              # CWE-918
├── xxe.yaml               # CWE-611
├── csrf.yaml              # CWE-352
├── deserialization.yaml   # CWE-502
├── open_redirect.yaml     # CWE-601
├── code_injection.yaml    # CWE-94
├── hardcoded_credentials.yaml  # CWE-798
├── broken_crypto.yaml     # CWE-327, 326, 328
├── information_exposure.yaml   # CWE-200
├── log_injection.yaml     # CWE-117
└── generic.yaml           # fallback
```

15 vulnerability-specific files + a generic fallback.

### Checklist schema (`_schema.yaml`)

Every checklist file conforms to:

```yaml
checklist_id: string                # internal id, matches filename stem
display_name: string                # human-readable, used in logs
applies_to:
  cwes: [list of strings]           # e.g. ["CWE-89"]
  query_names: [list of strings]    # full Checkmarx queryNames

evidence_required:
  - description: "Source identified and classified as attacker-controlled"
    examples: ["request body", "URL parameter", "header value"]
  - description: "Sink identified and confirmed to match vulnerability type"
    examples: ["string concatenation in JDBC executeQuery"]
  # more...

sanitizer_patterns:
  effective:
    - "parameterized query (PreparedStatement with ?)"
    - "ORM with bound parameters"
  ineffective:
    - "string escape function (e.g. addslashes) — bypassable"
    - "client-side validation only"

investigation_guidance: |
  Multi-line free-form guidance. Quoted code snippets allowed.
  Specific to this CWE family. Aim for ~300-500 words.

common_false_positive_patterns: |
  Why this CWE is often a false positive in production code.
```

### Mapping (`_mapping.yaml`)

```yaml
# queryName → checklist (most specific match wins)
query_name_to_checklist:
  Java_High_Risk.SQL_Injection: sqli
  Java_High_Risk.Stored_XSS: xss_stored
  Java_High_Risk.Reflected_XSS_All_Clients: xss_reflected
  JavaScript_High_Risk.Stored_XSS: xss_stored
  JavaScript_High_Risk.Reflected_XSS: xss_reflected
  JavaScript_High_Risk.DOM_XSS: xss_dom
  # ...continued for top 50-100 most common queryNames

# Fallback by CWE if queryName isn't mapped
cwe_to_checklist:
  CWE-89: sqli
  CWE-79: xss_reflected  # default if subflavor not detectable
  CWE-78: command_injection
  CWE-77: command_injection
  CWE-22: path_traversal
  # ...

# Final fallback
default: generic
```

### Selection logic

`sast_triage/checklists/__init__.py`:

```python
def select_checklist(query_name: str, cwe: str) -> ChecklistDocument:
    mapping = _load_mapping()
    # Most specific to least specific
    if (cl_id := mapping["query_name_to_checklist"].get(query_name)):
        return _load_checklist(cl_id)
    if (cl_id := mapping["cwe_to_checklist"].get(cwe)):
        return _load_checklist(cl_id)
    return _load_checklist(mapping["default"])
```

### Authoring strategy

A capable model with strong security knowledge can author
high-quality checklists. The **full set for all categories is
authored during implementation — not phased** — so a complete
starting point is in place before benchmarking, with later
refinement driven by gold-set results.

Workflow:

1. Engineer hand-writes `_schema.yaml` and one exemplar
   (`sqli.yaml`) to lock the shape and the quality bar.
2. A dedicated authoring subagent drafts the full set, framed as a
   senior security analyst. **The subagent must be briefed with the
   full context** — not just "write a checklist": the goal (triage
   true-positive vs false-positive), the asymmetric cost (a false
   negative is the worst outcome), the Checkmarx setting and the
   dataflow it provides, the two-field output model
   (`06-output-model.md`), the mandatory analysis protocol (Part 2),
   the schema, and the exemplar.
3. A separate **adversarial review pass** challenges each checklist:
   are the "effective sanitizer" patterns actually effective? Are
   there known bypasses? Are the false-positive patterns real? This
   pass exists specifically to catch over-confident or incomplete
   guidance, and should re-question items until they hold up to
   senior-analyst scrutiny.
4. Validate each against representative gold-set findings before
   committing.

### Language scope annotations

Each checklist must state, per item, whether it is
language-agnostic or language/framework-specific. SQLi
parameterization is a universal *principle*, but "use
`PreparedStatement`" is Java-specific while "use parameterized
queries / bound parameters" is the language-agnostic form. Any item
that applies only to a particular framework or runtime must say so.
This keeps guidance correct across the multi-language findings
Checkmarx produces and makes coverage gaps visible.

## Part 2 — Mandatory analysis steps

### Analyst system prompt skeleton

```text
You are a Senior Security Analyst reviewing a SAST finding.

You will receive:
- The finding (queryName, CWE, severity, dataflow nodes)
- An EvidenceBundle gathered by the research phase
- A CWE-specific checklist with required evidence and sanitizer
  patterns

Your task: determine whether the finding is CONFIRMED (exploitable)
or NOT_EXPLOITABLE (false positive). You MUST follow this protocol:

STEP 1 — IDENTIFY SOURCE
Name the exact source line. State why it is or is not
attacker-controlled. Cite the evidence reference.

STEP 2 — IDENTIFY SINK
Name the exact sink line. Confirm the sink type matches the
finding's claim (or differ in same family). Cite the evidence
reference.

STEP 3 — ENUMERATE THE PATH
List every line between source and sink, in execution order.
Mark each as PASSTHROUGH, TRANSFORM, or GUARD.

STEP 4 — CLASSIFY EVERY GUARD
For each GUARD line: cite the implementation. Per the checklist,
classify as EFFECTIVE or INEFFECTIVE for this CWE. State the
reasoning. Do not trust function names — verify implementation.

STEP 5 — VERDICT
Given the chain of guards and transforms, is a malicious payload
reachable from source to sink that triggers the vulnerability?
- If yes → CONFIRMED, is_exploitable=true
- If no, with cited reason → NOT_EXPLOITABLE
- If you cannot determine → list open_questions; the verdict will
  be sent to a critic

CONFIDENCE
Report a confidence level (0.0-1.0). Be honest. If you had to
guess at any step, lower your confidence. Verbal confidence is a
diagnostic — your verdict is what counts.

OUTPUT
Structured JSON matching AnalystVerdict schema.
```

### Pydantic schema

```python
class AnalystVerdict(BaseModel):
    verdict: Literal["CONFIRMED", "NOT_EXPLOITABLE"]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning_steps: list[ReasoningStep]   # one entry per protocol step
    evidence_refs: list[str]                # file:line references
    open_questions: list[str] = []
    is_in_test_code: bool = False
    sanitizer_classification: list[SanitizerCheck] = []
```

Structured output is enforced via Pydantic + LangChain's
`with_structured_output` (works on Gemini via `ChatGoogleGenerativeAI`).

## Implementation steps

1. Write `_schema.yaml` and exemplar `sqli.yaml` by hand.
2. Generate remaining top-5 checklists (with LLM assist).
   Human-review each.
3. Implement `select_checklist` and load test.
4. Update `sast_triage/prompts.py` to build the analyst prompt
   from the checklist content + the mandatory-steps template.
5. Update `AnalystVerdict` schema and the agent's verdict
   extraction.
6. Run the gold-set benchmark. Compare against baseline.
7. (Phase 2) Generate remaining 10 checklists. Re-benchmark.

## Acceptance criteria

- Top 5 checklists committed and validated against gold-set
  findings.
- Analyst prompt builds from checklist + steps template
  deterministically.
- Gold-set benchmark shows ≥ 3-point F1 improvement on average
  (lower on CWEs without a dedicated checklist; higher on covered
  ones).
- No regression worse than -5 F1 on any single CWE bucket.

## Risks / rollback

- **Risk:** an over-prescriptive checklist causes the model to
  ignore valid evidence that doesn't fit the template.
  **Mitigation:** keep an "additional observations" field in
  `AnalystVerdict`; review benchmarked regressions per CWE.
- **Rollback:** the previous generic prompt is preserved in
  `sast_triage/prompts.py` as `GENERIC_TRIAGE_PROMPT` and is
  selected if no checklist matches — so even a partial rollout
  doesn't regress unmapped findings.

## Out of scope

- Per-language checklists (e.g. separate SQLi checklist for Java
  vs Python). Defer until gold-set shows language-specific gaps
  matter — most sanitizers are language-agnostic at the conceptual
  level.
- Auto-tuning checklist content from gold-set errors. Future
  optimization; needs analyst feedback infrastructure first.
