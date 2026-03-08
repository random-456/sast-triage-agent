#!/usr/bin/env python3
"""
Directory Comparison Tool

Compares two directory trees and produces a self-contained HTML report
showing exactly what changed (added, deleted, modified files with diffs).

Usage:
    python compare_dirs.py <reference_dir> <target_dir> [-o output.html]

Requirements: Python 3.8+ (stdlib only, no pip dependencies)
"""

import argparse
import difflib
import html
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# =============================================================================
# Section 1: Constants
# =============================================================================

DEFAULT_IGNORE_NAMES = {
    ".git",
    "__pycache__",
    ".DS_Store",
    ".venv",
    "venv",
    "env",
    ".env",
    "node_modules",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
    "*.egg-info",
    "dist",
    "build",
    ".eggs",
}

DEFAULT_IGNORE_PATTERNS = {
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.so",
    "*.dylib",
    "*.dll",
    "*.class",
    "*.o",
    "*.obj",
    "*.exe",
    "*.bin",
    "*.swp",
    "*.swo",
    "*~",
    "*.bak",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".webp", ".tiff", ".tif",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".flac", ".wav",
    ".sqlite", ".db", ".sqlite3",
    ".jar", ".war", ".ear",
    ".iso", ".dmg",
    ".pkl", ".pickle", ".npy", ".npz",
}

DEFAULT_MAX_FILE_SIZE_KB = 512
DEFAULT_CONTEXT_LINES = 3

# =============================================================================
# Section 2: Data Classes
# =============================================================================


@dataclass
class DiffResult:
    """Per-file diff information."""
    rel_path: str
    status: str  # "added", "deleted", "modified", "binary_modified"
    diff_lines: List[str] = field(default_factory=list)
    additions: int = 0
    deletions: int = 0
    content: Optional[str] = None  # full content for added files
    is_binary: bool = False
    error: Optional[str] = None
    skipped_reason: Optional[str] = None


@dataclass
class ComparisonResult:
    """Aggregate comparison results."""
    reference_path: str
    target_path: str
    added: List[DiffResult] = field(default_factory=list)
    deleted: List[DiffResult] = field(default_factory=list)
    modified: List[DiffResult] = field(default_factory=list)
    unchanged: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    @property
    def total_files(self) -> int:
        return len(self.added) + len(self.deleted) + len(self.modified) + len(self.unchanged)

    @property
    def total_additions(self) -> int:
        return sum(d.additions for d in self.added) + sum(d.additions for d in self.modified)

    @property
    def total_deletions(self) -> int:
        return sum(d.deletions for d in self.deleted) + sum(d.deletions for d in self.modified)


# =============================================================================
# Section 3: File Utilities
# =============================================================================


def is_binary_file(filepath: Path) -> bool:
    """Check if a file is binary by extension and null-byte detection."""
    if filepath.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)
            return b"\x00" in chunk
    except (OSError, IOError):
        return False


def read_file_safe(filepath: Path) -> Tuple[Optional[str], Optional[str]]:
    """Read file with encoding fallback. Returns (content, error)."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read(), None
    except UnicodeDecodeError:
        try:
            with open(filepath, "r", encoding="latin-1") as f:
                return f.read(), None
        except Exception as e:
            return None, f"Encoding error: {e}"
    except Exception as e:
        return None, f"Read error: {e}"


def should_ignore(name: str, ignore_names: Set[str], ignore_patterns: Set[str]) -> bool:
    """Check if a file or directory name should be ignored."""
    if name in ignore_names:
        return True
    for pattern in ignore_names | ignore_patterns:
        if fnmatch(name, pattern):
            return True
    return False


# =============================================================================
# Section 4: Comparison Engine
# =============================================================================


def collect_files(
    root: Path,
    ignore_names: Set[str],
    ignore_patterns: Set[str],
) -> Set[str]:
    """Recursively collect relative file paths, respecting ignore rules."""
    files = set()
    for dirpath, dirnames, filenames in os.walk(root):
        # Filter directories in-place to prevent descent
        dirnames[:] = [
            d for d in dirnames
            if not should_ignore(d, ignore_names, ignore_patterns)
        ]
        for fname in filenames:
            if should_ignore(fname, ignore_names, ignore_patterns):
                continue
            full_path = Path(dirpath) / fname
            rel_path = full_path.relative_to(root)
            files.add(str(rel_path))
    return files


def generate_diff(
    ref_path: Path,
    tgt_path: Path,
    rel_path: str,
    context_lines: int,
    max_file_size_kb: int,
) -> DiffResult:
    """Generate a unified diff for a single modified file."""
    ref_file = ref_path / rel_path
    tgt_file = tgt_path / rel_path

    # Binary check
    if is_binary_file(ref_file) or is_binary_file(tgt_file):
        return DiffResult(
            rel_path=rel_path,
            status="binary_modified",
            is_binary=True,
        )

    # Size check
    try:
        ref_size = ref_file.stat().st_size
        tgt_size = tgt_file.stat().st_size
        max_bytes = max_file_size_kb * 1024
        if ref_size > max_bytes or tgt_size > max_bytes:
            return DiffResult(
                rel_path=rel_path,
                status="modified",
                skipped_reason=f"File exceeds {max_file_size_kb} KB size limit",
            )
    except OSError as e:
        return DiffResult(rel_path=rel_path, status="modified", error=str(e))

    ref_content, ref_err = read_file_safe(ref_file)
    tgt_content, tgt_err = read_file_safe(tgt_file)

    if ref_err or tgt_err:
        error = ref_err or tgt_err
        return DiffResult(
            rel_path=rel_path,
            status="modified",
            is_binary=True,
            error=error,
        )

    ref_lines = ref_content.splitlines(keepends=True)
    tgt_lines = tgt_content.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        ref_lines,
        tgt_lines,
        fromfile=f"reference/{rel_path}",
        tofile=f"target/{rel_path}",
        n=context_lines,
    ))

    if not diff:
        return DiffResult(rel_path=rel_path, status="unchanged")

    additions = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
    deletions = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))

    return DiffResult(
        rel_path=rel_path,
        status="modified",
        diff_lines=diff,
        additions=additions,
        deletions=deletions,
    )


def compare_directories(
    ref_path: Path,
    tgt_path: Path,
    ignore_names: Set[str],
    ignore_patterns: Set[str],
    context_lines: int,
    max_file_size_kb: int,
) -> ComparisonResult:
    """Compare two directory trees and return structured results."""
    result = ComparisonResult(
        reference_path=str(ref_path.resolve()),
        target_path=str(tgt_path.resolve()),
    )

    ref_files = collect_files(ref_path, ignore_names, ignore_patterns)
    tgt_files = collect_files(tgt_path, ignore_names, ignore_patterns)

    only_in_target = sorted(tgt_files - ref_files)
    only_in_ref = sorted(ref_files - tgt_files)
    common = sorted(ref_files & tgt_files)

    # Added files (in target but not reference)
    for rel_path in only_in_target:
        tgt_file = tgt_path / rel_path
        if is_binary_file(tgt_file):
            result.added.append(DiffResult(
                rel_path=rel_path,
                status="added",
                is_binary=True,
            ))
            continue

        try:
            size = tgt_file.stat().st_size
            if size > max_file_size_kb * 1024:
                result.added.append(DiffResult(
                    rel_path=rel_path,
                    status="added",
                    skipped_reason=f"File exceeds {max_file_size_kb} KB size limit",
                ))
                continue
        except OSError as e:
            result.errors.append(f"{rel_path}: {e}")
            continue

        content, err = read_file_safe(tgt_file)
        if err:
            result.errors.append(f"{rel_path}: {err}")
            result.added.append(DiffResult(
                rel_path=rel_path,
                status="added",
                is_binary=True,
                error=err,
            ))
        else:
            line_count = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
            result.added.append(DiffResult(
                rel_path=rel_path,
                status="added",
                content=content,
                additions=line_count,
            ))

    # Deleted files (in reference but not target)
    for rel_path in only_in_ref:
        ref_file = ref_path / rel_path
        if is_binary_file(ref_file):
            result.deleted.append(DiffResult(
                rel_path=rel_path,
                status="deleted",
                is_binary=True,
            ))
            continue

        content, err = read_file_safe(ref_file)
        line_count = 0
        if content:
            line_count = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
        result.deleted.append(DiffResult(
            rel_path=rel_path,
            status="deleted",
            deletions=line_count,
        ))

    # Common files — diff them
    for rel_path in common:
        try:
            diff_result = generate_diff(
                ref_path, tgt_path, rel_path, context_lines, max_file_size_kb
            )
            if diff_result.status == "unchanged":
                result.unchanged.append(rel_path)
            else:
                result.modified.append(diff_result)
        except Exception as e:
            result.errors.append(f"{rel_path}: {e}")

    return result


# =============================================================================
# Section 5: HTML Report Generator
# =============================================================================


CSS = """
:root {
    --bg: #0d1117;
    --surface: #161b22;
    --surface-hover: #1c2129;
    --border: #30363d;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --accent: #58a6ff;
    --green: #3fb950;
    --green-bg: #12261e;
    --red: #f85149;
    --red-bg: #2d1214;
    --yellow: #d29922;
    --yellow-bg: #2d2305;
    --blue-bg: #0c2d6b;
    --mono: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, 'Liberation Mono', Menlo, monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: var(--sans);
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    padding: 2rem;
    max-width: 1400px;
    margin: 0 auto;
}

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.header {
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
}

.header h1 {
    font-size: 1.5rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
}

.header .meta {
    font-size: 0.85rem;
    color: var(--text-muted);
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.meta code {
    font-family: var(--mono);
    font-size: 0.8rem;
    background: var(--surface);
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
}

/* Summary Cards */
.summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}

.card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    text-align: center;
}

.card .count {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1.2;
}

.card .label {
    font-size: 0.8rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.card.added .count { color: var(--green); }
.card.deleted .count { color: var(--red); }
.card.modified .count { color: var(--yellow); }
.card.unchanged .count { color: var(--text-muted); }

/* Filters */
.filters {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
}

.filter-btn {
    font-family: var(--sans);
    font-size: 0.8rem;
    padding: 0.4rem 0.8rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface);
    color: var(--text);
    cursor: pointer;
    transition: all 0.15s;
}

.filter-btn:hover { background: var(--surface-hover); }
.filter-btn.active { border-color: var(--accent); color: var(--accent); }

/* Table of Contents */
.toc {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    margin-bottom: 2rem;
}

.toc h2 {
    font-size: 1rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
}

.toc-list {
    list-style: none;
    max-height: 400px;
    overflow-y: auto;
}

.toc-list li {
    padding: 0.25rem 0;
    font-size: 0.85rem;
    font-family: var(--mono);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.toc-list li a {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.badge {
    font-family: var(--sans);
    font-size: 0.7rem;
    padding: 0.1rem 0.45rem;
    border-radius: 10px;
    font-weight: 600;
    white-space: nowrap;
    flex-shrink: 0;
}

.badge.added { background: var(--green-bg); color: var(--green); }
.badge.deleted { background: var(--red-bg); color: var(--red); }
.badge.modified { background: var(--yellow-bg); color: var(--yellow); }

.stat {
    font-family: var(--sans);
    font-size: 0.75rem;
    color: var(--text-muted);
    white-space: nowrap;
    flex-shrink: 0;
    margin-left: auto;
}

.stat .plus { color: var(--green); }
.stat .minus { color: var(--red); }

/* File Sections */
.file-section {
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 1rem;
    overflow: hidden;
}

.file-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.6rem 1rem;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    user-select: none;
}

.file-header:hover { background: var(--surface-hover); }

.file-header .chevron {
    font-size: 0.75rem;
    color: var(--text-muted);
    transition: transform 0.15s;
    flex-shrink: 0;
}

.file-header .chevron.collapsed { transform: rotate(-90deg); }

.file-header .filename {
    font-family: var(--mono);
    font-size: 0.85rem;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.file-header .file-stat {
    margin-left: auto;
    font-size: 0.8rem;
    white-space: nowrap;
    flex-shrink: 0;
}

.file-header .file-stat .plus { color: var(--green); font-weight: 600; }
.file-header .file-stat .minus { color: var(--red); font-weight: 600; }

.file-body { display: block; }
.file-body.hidden { display: none; }

.file-info {
    padding: 0.75rem 1rem;
    font-size: 0.85rem;
    color: var(--text-muted);
    font-style: italic;
}

/* Diff Table */
.diff-table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--mono);
    font-size: 0.8rem;
    line-height: 1.4;
    table-layout: fixed;
}

.diff-table td {
    padding: 0 0.75rem;
    vertical-align: top;
    white-space: pre;
    overflow-x: auto;
}

.diff-table .line-num {
    width: 50px;
    min-width: 50px;
    text-align: right;
    color: var(--text-muted);
    user-select: none;
    padding-right: 0.5rem;
    opacity: 0.5;
}

.diff-table .line-content {
    white-space: pre-wrap;
    word-break: break-all;
}

.diff-table tr.diff-add { background: var(--green-bg); }
.diff-table tr.diff-add .line-content { color: var(--green); }
.diff-table tr.diff-del { background: var(--red-bg); }
.diff-table tr.diff-del .line-content { color: var(--red); }
.diff-table tr.diff-hunk {
    background: var(--blue-bg);
}
.diff-table tr.diff-hunk td {
    color: var(--accent);
    font-weight: 600;
    padding-top: 0.3rem;
    padding-bottom: 0.3rem;
}

/* Added file content */
.added-content {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--mono);
    font-size: 0.8rem;
    line-height: 1.4;
    table-layout: fixed;
}

.added-content td {
    padding: 0 0.75rem;
    vertical-align: top;
}

.added-content .line-num {
    width: 50px;
    min-width: 50px;
    text-align: right;
    color: var(--text-muted);
    user-select: none;
    padding-right: 0.5rem;
    opacity: 0.5;
}

.added-content .line-content {
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--green);
}

.added-content tr { background: var(--green-bg); }

/* Errors */
.errors {
    background: var(--red-bg);
    border: 1px solid var(--red);
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 2rem;
}

.errors h2 {
    font-size: 1rem;
    color: var(--red);
    margin-bottom: 0.5rem;
}

.errors ul {
    list-style: disc;
    padding-left: 1.5rem;
    font-size: 0.85rem;
    font-family: var(--mono);
}

/* Back to top */
.back-to-top {
    position: fixed;
    bottom: 2rem;
    right: 2rem;
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    font-size: 1.2rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 0;
    transition: opacity 0.2s;
    z-index: 100;
}

.back-to-top.visible { opacity: 1; }
.back-to-top:hover { background: var(--surface-hover); }

/* Identical message */
.identical-msg {
    text-align: center;
    padding: 3rem;
    color: var(--text-muted);
    font-size: 1.1rem;
}
"""

JS = """
function toggleSection(id) {
    const body = document.getElementById('body-' + id);
    const chevron = document.getElementById('chev-' + id);
    if (body.classList.contains('hidden')) {
        body.classList.remove('hidden');
        chevron.classList.remove('collapsed');
    } else {
        body.classList.add('hidden');
        chevron.classList.add('collapsed');
    }
}

function filterFiles(type) {
    const btns = document.querySelectorAll('.filter-btn');
    const sections = document.querySelectorAll('.file-section');
    const tocItems = document.querySelectorAll('.toc-list li');

    // Toggle button
    const btn = document.querySelector('.filter-btn[data-type="' + type + '"]');
    const wasActive = btn.classList.contains('active');

    if (type === 'all') {
        btns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        sections.forEach(s => s.style.display = '');
        tocItems.forEach(t => t.style.display = '');
        return;
    }

    // Remove 'all' active state
    document.querySelector('.filter-btn[data-type="all"]').classList.remove('active');

    if (wasActive) {
        btn.classList.remove('active');
    } else {
        btn.classList.add('active');
    }

    // Check if any filter is active
    const activeFilters = Array.from(document.querySelectorAll('.filter-btn.active'))
        .map(b => b.dataset.type)
        .filter(t => t !== 'all');

    if (activeFilters.length === 0) {
        // No filters active = show all
        document.querySelector('.filter-btn[data-type="all"]').classList.add('active');
        sections.forEach(s => s.style.display = '');
        tocItems.forEach(t => t.style.display = '');
        return;
    }

    sections.forEach(s => {
        s.style.display = activeFilters.includes(s.dataset.type) ? '' : 'none';
    });

    tocItems.forEach(t => {
        t.style.display = activeFilters.includes(t.dataset.type) ? '' : 'none';
    });
}

function expandAll() {
    document.querySelectorAll('.file-body').forEach(b => b.classList.remove('hidden'));
    document.querySelectorAll('.chevron').forEach(c => c.classList.remove('collapsed'));
}

function collapseAll() {
    document.querySelectorAll('.file-body').forEach(b => b.classList.add('hidden'));
    document.querySelectorAll('.chevron').forEach(c => c.classList.add('collapsed'));
}

// Back to top visibility
window.addEventListener('scroll', () => {
    const btn = document.querySelector('.back-to-top');
    if (btn) {
        btn.classList.toggle('visible', window.scrollY > 300);
    }
});
"""


def _make_id(rel_path: str) -> str:
    """Create a safe HTML id from a file path."""
    return re.sub(r"[^a-zA-Z0-9_-]", "-", rel_path)


def _render_diff_table(diff_lines: List[str]) -> str:
    """Render unified diff lines as an HTML table."""
    rows = []
    old_num = 0
    new_num = 0

    for line in diff_lines:
        if line.startswith("--- ") or line.startswith("+++ "):
            continue

        hunk_match = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)", line)
        if hunk_match:
            old_num = int(hunk_match.group(1)) - 1
            new_num = int(hunk_match.group(2)) - 1
            hunk_info = html.escape(line.rstrip("\n"))
            rows.append(
                f'<tr class="diff-hunk">'
                f'<td class="line-num"></td><td class="line-num"></td>'
                f'<td class="line-content" colspan="1">{hunk_info}</td></tr>'
            )
            continue

        content = html.escape(line.rstrip("\n"))
        # Remove the leading +/- character from displayed content
        display = content[1:] if len(content) > 1 else ""

        if line.startswith("+"):
            new_num += 1
            rows.append(
                f'<tr class="diff-add">'
                f'<td class="line-num"></td>'
                f'<td class="line-num">{new_num}</td>'
                f'<td class="line-content">{display}</td></tr>'
            )
        elif line.startswith("-"):
            old_num += 1
            rows.append(
                f'<tr class="diff-del">'
                f'<td class="line-num">{old_num}</td>'
                f'<td class="line-num"></td>'
                f'<td class="line-content">{display}</td></tr>'
            )
        else:
            old_num += 1
            new_num += 1
            rows.append(
                f'<tr>'
                f'<td class="line-num">{old_num}</td>'
                f'<td class="line-num">{new_num}</td>'
                f'<td class="line-content">{display}</td></tr>'
            )

    return f'<table class="diff-table">{"".join(rows)}</table>'


def _render_added_content(content: str) -> str:
    """Render full file content as an HTML table with line numbers."""
    lines = content.splitlines()
    rows = []
    for i, line in enumerate(lines, 1):
        escaped = html.escape(line)
        rows.append(
            f'<tr>'
            f'<td class="line-num">{i}</td>'
            f'<td class="line-content">{escaped}</td></tr>'
        )
    return f'<table class="added-content">{"".join(rows)}</table>'


def _render_stat(additions: int, deletions: int) -> str:
    """Render +N / -N stat text."""
    parts = []
    if additions:
        parts.append(f'<span class="plus">+{additions}</span>')
    if deletions:
        parts.append(f'<span class="minus">&minus;{deletions}</span>')
    return " / ".join(parts) if parts else ""


def generate_html_report(result: ComparisonResult) -> str:
    """Generate a self-contained HTML report from comparison results."""
    has_changes = result.added or result.deleted or result.modified

    # Build TOC entries + file sections
    toc_entries = []
    file_sections = []
    section_idx = 0

    def add_section(diff_result: DiffResult, section_type: str):
        nonlocal section_idx
        sid = _make_id(diff_result.rel_path)
        stat_html = _render_stat(diff_result.additions, diff_result.deletions)

        # TOC entry
        toc_entries.append(
            f'<li data-type="{section_type}">'
            f'<span class="badge {section_type}">{section_type}</span>'
            f'<a href="#{sid}">{html.escape(diff_result.rel_path)}</a>'
            f'<span class="stat">{stat_html}</span>'
            f'</li>'
        )

        # Section body content
        if diff_result.is_binary:
            body_content = '<div class="file-info">Binary file</div>'
        elif diff_result.skipped_reason:
            body_content = f'<div class="file-info">{html.escape(diff_result.skipped_reason)}</div>'
        elif diff_result.error:
            body_content = f'<div class="file-info">Error: {html.escape(diff_result.error)}</div>'
        elif section_type == "added" and diff_result.content is not None:
            body_content = _render_added_content(diff_result.content)
        elif section_type == "deleted":
            body_content = '<div class="file-info">File removed</div>'
        elif diff_result.diff_lines:
            body_content = _render_diff_table(diff_result.diff_lines)
        else:
            body_content = '<div class="file-info">No displayable content</div>'

        file_sections.append(
            f'<div class="file-section" data-type="{section_type}" id="{sid}">'
            f'<div class="file-header" onclick="toggleSection(\'{sid}\')">'
            f'<span class="chevron" id="chev-{sid}">&#9660;</span>'
            f'<span class="badge {section_type}">{section_type[0].upper()}</span>'
            f'<span class="filename">{html.escape(diff_result.rel_path)}</span>'
            f'<span class="file-stat">{stat_html}</span>'
            f'</div>'
            f'<div class="file-body" id="body-{sid}">{body_content}</div>'
            f'</div>'
        )
        section_idx += 1

    for d in result.added:
        add_section(d, "added")
    for d in result.deleted:
        add_section(d, "deleted")
    for d in result.modified:
        add_section(d, "modified")

    # Errors section
    errors_html = ""
    if result.errors:
        error_items = "".join(f"<li>{html.escape(e)}</li>" for e in result.errors)
        errors_html = (
            f'<div class="errors">'
            f'<h2>Errors ({len(result.errors)})</h2>'
            f'<ul>{error_items}</ul>'
            f'</div>'
        )

    # Identical message
    identical_html = ""
    if not has_changes:
        identical_html = (
            '<div class="identical-msg">'
            'The directories are identical (no differences found).'
            '</div>'
        )

    toc_html = ""
    if toc_entries:
        toc_html = (
            f'<div class="toc">'
            f'<h2>Files Changed ({len(toc_entries)})</h2>'
            f'<ul class="toc-list">{"".join(toc_entries)}</ul>'
            f'</div>'
        )

    filters_html = ""
    if has_changes:
        filters_html = (
            '<div class="filters">'
            '<button class="filter-btn active" data-type="all" onclick="filterFiles(\'all\')">All</button>'
            '<button class="filter-btn" data-type="added" onclick="filterFiles(\'added\')">Added</button>'
            '<button class="filter-btn" data-type="deleted" onclick="filterFiles(\'deleted\')">Deleted</button>'
            '<button class="filter-btn" data-type="modified" onclick="filterFiles(\'modified\')">Modified</button>'
            '&nbsp;|&nbsp;'
            '<button class="filter-btn" onclick="expandAll()">Expand All</button>'
            '<button class="filter-btn" onclick="collapseAll()">Collapse All</button>'
            '</div>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Directory Comparison Report</title>
<style>{CSS}</style>
</head>
<body>
<div class="header">
    <h1>Directory Comparison Report</h1>
    <div class="meta">
        <div>Reference: <code>{html.escape(result.reference_path)}</code></div>
        <div>Target: <code>{html.escape(result.target_path)}</code></div>
        <div>Generated: {html.escape(result.timestamp)}</div>
    </div>
</div>

<div class="summary">
    <div class="card added">
        <div class="count">{len(result.added)}</div>
        <div class="label">Added</div>
    </div>
    <div class="card deleted">
        <div class="count">{len(result.deleted)}</div>
        <div class="label">Deleted</div>
    </div>
    <div class="card modified">
        <div class="count">{len(result.modified)}</div>
        <div class="label">Modified</div>
    </div>
    <div class="card unchanged">
        <div class="count">{len(result.unchanged)}</div>
        <div class="label">Unchanged</div>
    </div>
</div>

{errors_html}
{filters_html}
{toc_html}
{identical_html}

{"".join(file_sections)}

<button class="back-to-top" onclick="window.scrollTo({{top:0,behavior:'smooth'}})">&uarr;</button>
<script>{JS}</script>
</body>
</html>"""


# =============================================================================
# Section 6: CLI Entry Point
# =============================================================================


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare two directory trees and generate an HTML diff report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s ./old-version ./new-version\n"
            "  %(prog)s /path/to/ref /path/to/target -o report.html\n"
            "  %(prog)s dir1 dir2 --context-lines 5 --ignore .mypy_cache .tox\n"
        ),
    )
    parser.add_argument(
        "reference",
        help="Path to the reference (baseline) directory",
    )
    parser.add_argument(
        "target",
        help="Path to the target (newer) directory",
    )
    parser.add_argument(
        "-o", "--output",
        default="comparison_report.html",
        help="Output HTML file path (default: comparison_report.html)",
    )
    parser.add_argument(
        "--context-lines",
        type=int,
        default=DEFAULT_CONTEXT_LINES,
        help=f"Number of context lines in diffs (default: {DEFAULT_CONTEXT_LINES})",
    )
    parser.add_argument(
        "--ignore",
        nargs="+",
        default=[],
        help="Additional file/directory names to ignore",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE_KB,
        help=f"Skip diff for files larger than this (KB, default: {DEFAULT_MAX_FILE_SIZE_KB})",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    ref_path = Path(args.reference).resolve()
    tgt_path = Path(args.target).resolve()

    if not ref_path.is_dir():
        print(f"Error: Reference directory does not exist: {ref_path}", file=sys.stderr)
        return 1
    if not tgt_path.is_dir():
        print(f"Error: Target directory does not exist: {tgt_path}", file=sys.stderr)
        return 1

    ignore_names = DEFAULT_IGNORE_NAMES | set(args.ignore)
    ignore_patterns = DEFAULT_IGNORE_PATTERNS

    print(f"Comparing directories...")
    print(f"  Reference: {ref_path}")
    print(f"  Target:    {tgt_path}")

    result = compare_directories(
        ref_path=ref_path,
        tgt_path=tgt_path,
        ignore_names=ignore_names,
        ignore_patterns=ignore_patterns,
        context_lines=args.context_lines,
        max_file_size_kb=args.max_file_size,
    )

    print(f"\nResults:")
    print(f"  Added:     {len(result.added)}")
    print(f"  Deleted:   {len(result.deleted)}")
    print(f"  Modified:  {len(result.modified)}")
    print(f"  Unchanged: {len(result.unchanged)}")
    if result.errors:
        print(f"  Errors:    {len(result.errors)}")

    report_html = generate_html_report(result)
    output_path = Path(args.output)
    output_path.write_text(report_html, encoding="utf-8")
    print(f"\nReport written to: {output_path.resolve()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
