# CWE Evidence Checklists

The agent ships a small set of CWE-keyed evidence checklists that drive what the analyst must verify before reaching a verdict and how the critic frames its review. Each checklist is a YAML file in `sast_triage/checklists/`, validated against a Pydantic schema at load time and selected per finding from the Checkmarx `queryName` and `cweID`.

## Why per-CWE checklists

SAST findings are uniformly shaped (a source, a sink and a path) but the question the analyst has to answer differs sharply by vulnerability class. What counts as an effective guard against SQL injection (bound parameters) is irrelevant to XSS (HTML-context output encoding), and vice versa. A single prompt that covers everything ends up vague; a per-CWE checklist makes the analyst commit to the specific evidence that the class requires.

The checklists also encode the bypassable patterns that look like protection but are not. The analyst is instructed to read the actual implementation rather than trust names like `sanitize()` or `validate()`, and the checklist's `ineffective` list is the reference for that.

## Schema

A checklist conforms to `ChecklistDocument` in `sast_triage/checklists/__init__.py`:

```yaml
checklist_id: string             # internal id, must match the filename stem
display_name: string             # human-readable, used in logs and the prompt

applies_to:
  cwes: [list of strings]        # normalized "CWE-<n>" form
  query_names: [list of strings] # Checkmarx queryName values

evidence_required:
  - description: string          # what the analyst must establish
    examples: [list of strings]  # optional, concrete instances

sanitizer_patterns:
  effective: [list of strings]   # patterns that genuinely neutralize this class
  ineffective: [list of strings] # patterns the analyst must NOT accept

investigation_guidance: string   # free-form, ~300-500 words

common_false_positive_patterns: string
```

`_schema.yaml` in the checklists directory documents the same shape for contributors. It is not loaded at runtime; `ChecklistDocument` is the authoritative validator.

Two helper models are part of the validation:

- `EvidenceItem` (one entry in `evidence_required`) has `description` and `examples`.
- `SanitizerPatterns` (the `sanitizer_patterns` block) has `effective` and `ineffective`.
- `AppliesTo` (the `applies_to` block) has `cwes` and `query_names`.

## Shipped checklists

The active set on `dev`:

| `checklist_id` | `display_name` | Maps from CWE | Maps from `queryName` |
|----------------|----------------|---------------|------------------------|
| `sqli` | SQL Injection (CWE-89) | CWE-89 | `SQL_Injection` |
| `xss_reflected` | Reflected Cross-Site Scripting (CWE-79, reflected) | CWE-79 (default for XSS) | `Reflected_XSS`, `XSS_Evasion_Attack_via_Replace` |
| `xss_stored` | Stored Cross-Site Scripting (CWE-79, stored) | -- | `Stored_XSS` |
| `command_injection` | OS Command Injection (CWE-78, CWE-77) | CWE-77, CWE-78 | -- |
| `path_traversal` | Path Traversal (CWE-22) | CWE-22 | -- |
| `generic` | Generic taint-flow finding | (fallback) | (fallback) |

`generic.yaml` is the fallback for any finding the mapping does not match. It applies a class-agnostic taint-flow protocol so the analyst still gets structured guidance for unfamiliar finding types.

## Selection logic

`select_checklist(query_name, cwe)` in `sast_triage/checklists/__init__.py` runs once per finding when the per-finding state is built. Resolution order, most specific first:

1. **Exact, case-insensitive `queryName`** against the `query_name_to_checklist` map.
2. **Normalized CWE** against the `cwe_to_checklist` map. The input is normalized to `CWE-<n>` form via `normalize_cwe`: integer `89`, string `"89"` and string `"CWE-89"` (any case) all map to `CWE-89`.
3. The configured **default** (`generic` today).

The result is loaded via `load_checklist`, which is `lru_cache`d so repeated finds for the same CWE in a session do not reread the YAML.

**Fail-safe behavior.** A mapped checklist that fails to load (file missing, schema validation error) is replaced by the default with a warning logged. The default failing is fatal: the agent will not silently produce weaker prompts.

The mapping policy in `_mapping.yaml` is intentionally cautious. Sub-flavors that share one CWE (the XSS variants under CWE-79) are the reason the `queryName` layer exists at all. Command injection and path traversal route on CWE alone because no `queryName` has been confirmed for them yet, and CWE is authoritative. `Client_Potential_XSS` (DOM/client XSS) is intentionally absent until an `xss_dom` checklist exists; it falls through to the CWE-79 default.

## `_mapping.yaml`

```yaml
query_name_to_checklist:
  SQL_Injection: sqli
  Reflected_XSS: xss_reflected
  XSS_Evasion_Attack_via_Replace: xss_reflected
  Stored_XSS: xss_stored

cwe_to_checklist:
  CWE-89: sqli
  CWE-79: xss_reflected  # default when the XSS sub-flavor is not detectable
  CWE-78: command_injection
  CWE-77: command_injection
  CWE-22: path_traversal

default: generic
```

`queryName` keys are matched case-insensitively (they are lowercased at load time). `cweID` is normalized to `CWE-<n>` before lookup. Only confirmed `queryName` strings are mapped: a guess at a string would silently steer the wrong checklist into a finding it does not cover.

## What the analyst sees

`render_checklist_section(checklist)` turns the selected checklist into a prompt section that is appended to the analyst's system prompt (and to the critic's system prompt, for the same reason). The shape of the rendered block:

```
### CWE-SPECIFIC CHECKLIST: <display_name>
Apply this checklist while working through the analysis protocol.

REQUIRED EVIDENCE (address each before a verdict):
- <description> (e.g. <example>; <example>)
- ...

EFFECTIVE CONTROLS (these genuinely neutralize this vulnerability):
- <pattern>
- ...

INEFFECTIVE / BYPASSABLE (do NOT accept these as sufficient):
- <pattern>
- ...

INVESTIGATION GUIDANCE:
<investigation_guidance>

COMMON FALSE-POSITIVE PATTERNS:
<common_false_positive_patterns>
```

The same block is included verbatim by the critic so the critic and analyst are reviewing against the same standard. The analyst is told to ground each protocol step in a `file:line` citation; the checklist supplies what to look for and what bypasses to expect.

## Adding a new checklist

1. **Create `<id>.yaml`** in `sast_triage/checklists/`. `<id>` becomes the `checklist_id` and must match the filename stem. Follow the shape in `_schema.yaml`.
2. **Add a mapping** to `_mapping.yaml`. Prefer `cwe_to_checklist` when the CWE alone is enough. Only add `query_name_to_checklist` entries for `queryName` strings you have confirmed from the Checkmarx instance; do not guess.
3. **Run the test suite.** The schema is validated when the checklist is loaded, and tests in `tests/` exercise the selector and render logic. A malformed YAML or a missing required field will surface here.
4. **Test the prompt visually.** `render_checklist_section` produces the section the analyst sees; reading the rendered output is the fastest way to catch awkward phrasing or duplicated guidance.
5. **Watch the agent log.** Each per-finding log entry records which checklist was selected. Spot-check that the new mapping fires where you expect.

A checklist's `investigation_guidance` is the place to put the prose that does not belong in a bullet list (decisive questions, common refactor patterns, characteristic false-positive shapes for this CWE family). Keep the bullet lists tight and the prose substantive.
