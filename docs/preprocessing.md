# Preprocessing

Before findings are analyzed by the LLM, the cloned codebase goes through two preprocessing stages: **obfuscation** and **secret masking**. Both stages modify files in-place and produce structured reports.

## Why Preprocessing?

The codebase is sent to cloud LLM services for analysis. Preprocessing prevents leaking:

- Internal network infrastructure details (IPs, hostnames and MAC addresses).
- Hardcoded secrets, API keys and credentials.

The LLM system prompt instructs the agent to treat preprocessed placeholders as opaque constants that do not affect exploitability analysis.

## Obfuscation

**Module:** `sast_triage/preprocessing/obfuscation.py`

Obfuscation scans all text files in the codebase and replaces infrastructure patterns with typed placeholders.

### Patterns

| Type | Pattern | Placeholder | Example |
|------|---------|-------------|---------|
| IPv4 | `([0-9]{1,3}\.){3}[0-9]{1,3}` | `__IPV4__` | `192.168.1.1` |
| IPv6 | `([0-9a-fA-F]{0,4}:(:)?){2,7}(...)` | `__IPV6__` | `fe80::1` |
| MAC | `([0-9A-Fa-f]{2}[:-]){5}(...)` | `__MAC__` | `00:1A:2B:3C:4D:5E` |
| FQDN | Internal domain patterns | `__FQDN__` | `server.airbus.com` |

### Binary File Handling

Binary files are automatically skipped. Detection uses two methods:

1. **Extension check:** files with known binary extensions (images, archives, executables, fonts, media and databases) are skipped immediately.
2. **Content check:** if the extension is not recognized, the first 8 KB is read and a UTF-8 decode is attempted. Failure indicates a binary file.

### Behavior

- Walks all files recursively in the codebase directory
- Skips binary files and files outside the codebase boundary (symlink protection)
- Applies all pattern replacements in-place
- Produces an `ObfuscationReport` with per-file, per-pattern breakdown

### Report Structure

```python
ObfuscationReport(
    total_files_processed=150,
    total_files_modified=12,
    total_replacements=47,
    replacements_by_type={"IPV4": 30, "FQDN": 15, "MAC": 2},
    entries=[
        ObfuscationEntry(file="src/config.js", line=5, pattern_type="IPV4", original="10.0.0.1"),
        ...
    ]
)
```

## Secret Masking

**Module:** `sast_triage/preprocessing/secret_masking.py`

Secret masking uses a [Gitleaks](https://github.com/gitleaks/gitleaks) CSV report to identify and replace secrets in the codebase.

### Prerequisites

Generate a Gitleaks report for the repository:

```bash
gitleaks detect --source /path/to/repo --report-format csv --report-path gitleaks-report.csv
```

The CSV must contain these columns: `File`, `StartLine`, `EndLine`, `StartColumn`, `EndColumn`. Optional columns: `Secret`, `Description`.

### Behavior

- Loads and validates the Gitleaks CSV (max 10 MB)
- Groups entries by file to minimize I/O
- Validates file paths stay within the codebase directory (path traversal protection)
- Replaces secret regions with `__MASKED_SECRET__` placeholder
- Handles both single-line and multi-line secrets
- Processes entries in reverse order to preserve column positions
- Skips entries where the target file is not found or unreadable

### Report Structure

```python
MaskingReport(
    csv_path="gitleaks-report.csv",
    total_entries_in_csv=25,
    total_secrets_masked=23,
    files_modified=8,
    entries=[
        MaskingEntry(
            file="src/config.py",
            start_line=10,
            end_line=10,
            start_column=15,
            end_column=55,
            description="Generic API Key",
            secret_preview="sk-l***"
        ),
        ...
    ],
    skipped_entries=[
        {"file": "deleted-file.py", "reason": "file not found"},
    ]
)
```

## Pipeline Order

Obfuscation runs before secret masking. This order matters because:

1. Obfuscation may alter line content (e.g., replacing an IP inside a connection string), which could shift column positions.
2. Gitleaks column/line references are based on the original file content, but since obfuscation only replaces inline patterns without changing line counts, the column offsets for secrets on different lines remain valid.

## Skipping Preprocessing

- Obfuscation always runs when a codebase is cloned.
- Secret masking is skipped when `--gitleaks-report none` is passed.
- If the repository clone fails, both stages are skipped and the agent proceeds with analysis using only the finding details (no codebase access).

## Interactive Confirmation

In interactive mode, a preprocessing summary is displayed after both stages complete:

```
==================================================
  Preprocessing Summary
==================================================
  Obfuscation:    47 replacements in 12 files
    - IPV4: 30
    - FQDN: 15
    - MAC: 2
  Secret masking: 23 secrets masked in 8 files
==================================================

? Proceed with triage analysis? (Y/n)
```

The user can review the results and decide whether to proceed or cancel.
