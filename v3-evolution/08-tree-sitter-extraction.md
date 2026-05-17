# 08 — Function-level code extraction via tree-sitter

> Scope: replace the current whole-file `read_file` tool as the
> *primary* code retrieval mechanism with an `extract_function`
> tool that returns just the enclosing function plus a configurable
> surrounding context window. `read_file` stays as a small-file
> fallback.
>
> Depends on: nothing structurally; in practice runs after Phase 2
> (LangGraph) is in place so the new tool slots into the
> researcher node cleanly.

## Goal

Reduce per-finding context bloat (and therefore Gemini context-rot
degradation) by serving the researcher targeted function-level
extracts instead of whole files. Cross-language support via
tree-sitter so a single tool covers all 8+ Checkmarx-supported
languages.

## Why this matters

The user's intuition that "whole-file reads are safer because
sanitizers can be 100 lines away" is partially right and partially
wrong:

- **Right:** sanitizers can indeed live far from the
  source/sink. A pure function-only extraction misses them.
- **Wrong:** dumping the whole file does not solve this; it just
  hopes the model finds the sanitizer in the noise. Chroma's 2025
  "context rot" study shows Gemini 2.5 Pro degrades uniformly as
  input length grows even on simple retrieval tasks.

The right fix is **function + context lines (±50 default) + a tool
to expand the window on demand**. Same-file far-away sanitizers are
caught by the context window; cross-file sanitizers are caught by
the researcher requesting another extraction.

## The tool

`sast_triage/tools/extract_function.py`:

```python
@tool
def extract_function(
    file_path: str,
    function_name: str | None = None,
    line_number: int | None = None,
    context_lines: int = 50,
) -> dict:
    """
    Extract a function and surrounding context from a source file.

    Exactly one of function_name or line_number must be provided.
    - function_name: the function to extract (matches first by name)
    - line_number: extract the function enclosing this line
    - context_lines: number of lines before/after the function body

    Returns the function source with line numbers, plus imports,
    module-level constants, and enclosing-class signature if any.
    """
    ...
```

Output shape:

```python
{
    "file": "controllers/user.py",
    "language": "python",
    "function_name": "get_user",
    "function_start_line": 42,
    "function_end_line": 78,
    "imports": [
        "10: import sqlite3",
        "11: from utils import sanitize",
    ],
    "enclosing_class_signature": "16: class UserController(BaseController):",
    "content": [
        "32: # 10 lines of context before",
        ...
        "42: def get_user(self, user_id: str):",
        ...
        "78:     return user",
        "79: # 10 lines of context after",
        ...
    ],
    "total_lines_returned": 87,
}
```

`read_file` stays as a fallback for small files (auto-routed if
file < 400 lines, or explicitly invoked).

## Tree-sitter integration

### Dependency

```
tree-sitter>=0.23
tree-sitter-language-pack>=0.4
```

Single package covers all 8 target languages plus ~290 others.
No language servers, no build artifacts, no compilation.

### Language dispatch

Tree-sitter exposes language-specific grammars. Different
languages name the "function definition" node differently:

```python
FUNCTION_NODE_TYPES_BY_LANGUAGE = {
    "python":      ["function_definition"],
    "javascript":  ["function_declaration", "method_definition",
                    "arrow_function", "function_expression"],
    "typescript":  ["function_declaration", "method_definition",
                    "arrow_function", "function_expression"],
    "java":        ["method_declaration", "constructor_declaration"],
    "csharp":      ["method_declaration", "constructor_declaration"],
    "go":          ["function_declaration", "method_declaration"],
    "ruby":        ["method", "singleton_method"],
    "php":         ["function_definition", "method_declaration"],
    "c":           ["function_definition"],
    "cpp":         ["function_definition"],
}
```

Implementation:

```python
from tree_sitter_language_pack import get_parser

def get_enclosing_function(source: str, language: str, line: int):
    parser = get_parser(language)
    tree = parser.parse(source.encode())
    target_types = FUNCTION_NODE_TYPES_BY_LANGUAGE[language]

    def find(node):
        if (node.start_point[0] <= line <= node.end_point[0]
                and node.type in target_types):
            return node
        for child in node.children:
            if (result := find(child)):
                return result
        return None

    return find(tree.root_node)
```

### Language detection

Map file extension → tree-sitter language:

```python
LANG_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".java": "java",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cc": "cpp",
}
```

For files with unknown extensions, fall back to `read_file`.

## Imports and module-level context

Even with function extraction, the researcher often needs to see
imports and module-level constants to understand types and
sanitizer calls. Extract:

- All top-level `import` / `from ... import` / equivalent.
- Module-level variable definitions (heuristically: any
  `assignment` node at module level).
- The enclosing class signature (just the declaration line,
  not the whole class body).

Add these as a small header to the returned `content`.

## Wiring into the researcher

`sast_triage/graph/nodes.py:research_node` — add
`extract_function` to the available tools, **listed first** in the
tool description so the model prefers it. `read_file` stays
available but described as "for small files or when you need to
see imports/constants outside the function."

## Testing

`tests/test_extract_function.py`:

- Fixture file per language (8 fixtures), each with 3-4 functions.
- Test: `extract_function(file, function_name)` returns the
  right function for each.
- Test: `extract_function(file, line_number=N)` returns the
  enclosing function for various N.
- Test: invalid `function_name` returns helpful error.
- Test: imports and class signatures appear in the output.
- Test: file with unknown extension → fall back to `read_file`.

## Implementation steps

1. Add tree-sitter dependencies to `requirements.txt`.
2. Implement `sast_triage/tools/extract_function.py` with the
   dispatch logic above.
3. Create per-language fixture files in `tests/fixtures/extract/`.
4. Write tests.
5. Add `extract_function` to the researcher's tool list (in
   `sast_triage/graph/nodes.py` or `agent.py`'s successor).
6. Update the researcher's system prompt to describe when to use
   `extract_function` vs `read_file`.
7. Run gold-set benchmark; expect per-finding input tokens to drop
   ~30-50% without recall regression.

## Acceptance criteria

- All 8 target languages have passing fixture tests.
- Gold-set benchmark: average input tokens per finding ≥ 30%
  lower than Phase 2 baseline.
- No regression in any per-CWE F1 bucket > 5 points.
- `read_file` retained and still works for files < 400 lines.

## Risks / rollback

- **Risk:** tree-sitter parsing fails on broken/incomplete code
  files. **Mitigation:** wrap in try/except; on parse error,
  log and fall through to `read_file`. Add a fixture file with
  syntax errors to the test suite.
- **Risk:** function-name resolution is ambiguous (overloads,
  same-named functions in different classes). **Mitigation:**
  return the first match by default; allow `line_number` as a
  more-specific selector.
- **Rollback:** the tool addition is purely additive
  (`read_file` is still there). If the new tool causes problems,
  drop it from the researcher's available tool list — the
  researcher will fall back to `read_file` naturally.

## Out of scope

- **Cross-file callers/callees** (`fetch_callers`,
  `fetch_callees`). Useful but requires LSP / `multilspy` for
  reliable cross-file symbol resolution. Phase 4+ if benchmark
  errors show the cross-file gap is hurting recall.
- **AST-based code chunking for embedding** (e.g. cAST). Useful
  for retrieval at scale; not relevant to per-finding extraction.
- **Per-language scoring of function complexity** (cyclomatic, etc.).
  Future enhancement if it informs research budget.
