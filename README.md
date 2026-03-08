# Directory Comparison Tool

Compares two directory trees and generates a self-contained HTML report showing all differences: added files, deleted files, and modified files with color-coded unified diffs.

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

## Quick Start

```bash
python compare_dirs.py /path/to/reference /path/to/target -o report.html
open report.html
```

## Terminology

- **Reference** = the baseline/older version of the code
- **Target** = the newer/modified version

The report reads as: "to go from reference to target, apply these changes."

## CLI Reference

```
python compare_dirs.py <reference_dir> <target_dir> [options]
```

| Argument | Default | Description |
|---|---|---|
| `reference` | *(required)* | Path to the baseline directory |
| `target` | *(required)* | Path to the newer directory |
| `-o`, `--output` | `comparison_report.html` | Output HTML file path |
| `--context-lines` | `3` | Number of context lines around each change in diffs |
| `--ignore` | *(none)* | Additional file/directory names to ignore |
| `--max-file-size` | `512` | Skip diffs for files larger than this (in KB) |

### Default Ignores

The tool automatically ignores common non-source entries: `.git`, `__pycache__`, `.DS_Store`, `.venv`, `node_modules`, `*.pyc`, and others.

## Example: Comparing Two Branches

```bash
# Extract branches to temp directories
git archive branch-a | tar -x -C /tmp/ref
git archive branch-b | tar -x -C /tmp/target

# Generate report
python compare_dirs.py /tmp/ref /tmp/target -o diff-report.html

# View
open diff-report.html
```

## Report Features

- Summary cards showing counts of added, deleted, modified, and unchanged files
- Clickable table of contents with per-file line change statistics
- Color-coded unified diffs with line numbers
- Full content display for newly added files
- Filter buttons to show/hide file categories
- Collapsible file sections with expand/collapse all
- Back-to-top button
- Fully self-contained HTML (no external dependencies)
