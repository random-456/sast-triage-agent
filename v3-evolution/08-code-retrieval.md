# 08 — Code retrieval: dataflow-guided extraction with whole-file fallback

> Scope: serve the researcher targeted code extracts driven by the
> finding's dataflow node locations, using tree-sitter to find
> function boundaries, with a robust whole-file / line-window
> fallback. This replaces "always read the entire file" as the
> primary retrieval path while keeping whole-file reads for the
> cases where they're the right choice.
>
> Depends on: `07-langgraph-and-stateless.md` (the researcher node
> the tools attach to).

## Goal

Give the analyst the *relevant* code — the functions the dataflow
passes through, plus sanitizers and surrounding context — without
forcing whole large files into the context window. Robust across
the languages Checkmarx supports, with a fallback whenever
extraction can't be done cleanly.

## Why not "just read whole files"

The intuition that whole files are safest (a sanitizer might live
far from the finding) is reasonable, and for *small* files it's
true and harmless. But the evidence for a triage task — where the
analyzer already hands us exact source/sink lines — favors targeted
extraction once files get large:

- **"Lost in the End" (FSE 2025, arXiv:2502.06898)** tested whole
  files of varying size on XSS / SQLi / path-traversal and found
  models underperform when the vulnerability sits near the end of
  larger files; trimming input raised recall substantially — i.e.
  less file directly reduced false negatives.
- **Context-rot studies (2025)** show large-window models
  (Gemini-class included) degrade on judgment tasks as input grows,
  even when the relevant span is present.
- The real axis is *relevant context vs noise*, not *whole file vs
  single function*. The right target is the dataflow-relevant slice:
  the functions the flow passes through, the sanitizers on the path,
  and cross-file expansion when the flow leaves the file.

Since large codebases (and large files) are an explicit near-term
target, building targeted extraction now — rather than deferring —
is the right call. The whole-file fallback covers the cases where
targeted extraction isn't needed or isn't possible.

## The retrieval strategy

Checkmarx gives us, per dataflow node: `fileName`, `line`, `method`,
`methodLine` (the line where the enclosing method starts), and
`domType`. That's most of what we need to target extraction.

### Primary: `extract_function`

```python
@tool
def extract_function(
    file_path: str,
    line_number: int,
    context_lines: int = 30,
) -> dict:
    """
    Extract the function enclosing `line_number` from a source file,
    plus imports, the enclosing class signature, and `context_lines`
    of surrounding context. Driven by a dataflow node's file+line.

    Falls back to whole-file or a line-window when extraction can't
    be done cleanly (see fallback rules).
    """
```

Returns the enclosing function body (boundaries found via
tree-sitter), with a small header carrying imports + module-level
constants + the enclosing class signature, and line numbers
preserved. `methodLine` from the Checkmarx node is used as a hint
to locate the function start; tree-sitter's job is mainly to find
the function *end* reliably.

### Fallback: `read_file`

```python
@tool
def read_file(file_path: str, start_line: int | None = None,
              end_line: int | None = None) -> dict:
    """Read a whole file, or a line range when given."""
```

Stays available for: small files, explicit "I need the whole file"
requests, and as the automatic fallback target.

### Fallback rules (in `extract_function`)

1. **Small file** (≤ `WHOLE_FILE_LINE_THRESHOLD`, default 500
   lines): skip extraction, return the whole file. Cheap, harmless,
   captures all context.
2. **Tree-sitter parse failure** on a larger file: return a line
   window of `±LINE_WINDOW` (default 120) lines around
   `line_number` — never the whole large file.
3. **Unsupported language**: same line-window fallback.
4. **Function not found at the line** (e.g. module-level code):
   line-window fallback.

Every fallback is logged with the reason, so benchmark analysis can
see how often extraction succeeded vs fell back.

## Tree-sitter integration

### Dependency

```
tree-sitter>=0.23
tree-sitter-language-pack>=0.4
```

One package, all Checkmarx-relevant languages plus many more. No
language servers, no build artifacts.

### Language detection + node dispatch

```python
LANG_BY_EXTENSION = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".cs": "csharp", ".go": "go", ".rb": "ruby",
    ".php": "php", ".c": "c", ".h": "c", ".cpp": "cpp",
    ".cc": "cpp", ".hpp": "cpp",
}

FUNCTION_NODE_TYPES = {
    "python":     ["function_definition"],
    "javascript": ["function_declaration", "method_definition",
                   "arrow_function", "function_expression"],
    "typescript": ["function_declaration", "method_definition",
                   "arrow_function", "function_expression"],
    "java":       ["method_declaration", "constructor_declaration"],
    "csharp":     ["method_declaration", "constructor_declaration"],
    "go":         ["function_declaration", "method_declaration"],
    "ruby":       ["method", "singleton_method"],
    "php":        ["function_definition", "method_declaration"],
    "c":          ["function_definition"],
    "cpp":        ["function_definition"],
}
```

Find the enclosing function by walking the parse tree for the
deepest node of a function type whose line span contains
`line_number`.

All tree-sitter calls wrapped in try/except → fallback on any error.

## Wiring into the researcher

The researcher (`sast_triage/graph/nodes.py:research_node`) gets
both tools, with `extract_function` listed first and described as
the default ("use this with a dataflow node's file+line to get the
relevant function"), and `read_file` described as "for small files,
imports/constants outside a function, or when you need the whole
file." The researcher iterates over the finding's dataflow nodes
and pulls each enclosing function.

## Testing

`tests/test_extract_function.py`, with a fixture file per language
under `tests/fixtures/extract/`:

- Extract the correct enclosing function for various lines, per
  language.
- Imports + class signature appear in the output.
- Small-file path returns the whole file.
- Parse-failure fixture (syntactically broken file) falls back to a
  line window, not a crash.
- Unsupported extension falls back to a line window.
- Line numbers in the output match the source.

## Implementation steps

1. Add tree-sitter dependencies to `requirements.txt`.
2. Implement `sast_triage/tools/extract_function.py` with dispatch
   + fallback rules.
3. Refactor `read_file` to accept optional `start_line`/`end_line`.
4. Per-language fixtures + tests, including failure fixtures.
5. Attach both tools to the researcher; update its prompt to
   describe when to use each.
6. Run the gold-set; confirm no recall regression and that large
   files are no longer dumped whole.

## Acceptance criteria

- All Checkmarx-relevant languages have passing fixture tests,
  including parse-failure and unsupported-extension fallbacks.
- On the gold-set: no per-CWE recall regression vs the pre-retrieval
  baseline. (Token-cost reduction is expected mainly on large
  files; the gold-set may under-show it if its files are small —
  that's fine, the change is about not degrading on large files we
  know are coming.)
- Every fallback path is exercised by a test and logged with a
  reason at runtime.

## Risks / rollback

- **Risk:** tree-sitter mis-identifies boundaries for an unusual
  construct, returning too little code. **Mitigation:** the
  `context_lines` margin cushions small boundary errors; the
  researcher can always call `read_file` for the whole file.
- **Risk:** a language's grammar names functions unexpectedly.
  **Mitigation:** per-language fixtures catch this; the dispatch
  table is easy to extend.
- **Rollback:** the tool is additive. Dropping `extract_function`
  from the researcher's tool list reverts to whole-file reads with
  no other change.

## Out of scope (for now)

- **Cross-file callers/callees** (`fetch_callers`/`fetch_callees`).
  Reliable cross-file symbol resolution needs an LSP layer
  (e.g. `multilspy`). Add only if benchmark errors show the
  cross-file sanitizer case is hurting recall.
- AST-based chunking for embedding/retrieval at scale (unrelated to
  per-finding extraction).
