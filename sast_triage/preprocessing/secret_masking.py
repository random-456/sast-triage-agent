"""
Secret masking module using Gitleaks CSV reports.

Parses a Gitleaks CSV report and replaces identified secrets with
__MASKED_SECRET__ placeholders in the codebase. This prevents sending
real secrets to cloud LLM services during triage analysis.
"""

import csv
import io
import logging
import os
from dataclasses import dataclass, field

import requests

logger = logging.getLogger(__name__)

MASK_PLACEHOLDER = "__MASKED_SECRET__"

_REQUIRED_CSV_COLUMNS = {"File", "StartLine", "EndLine", "StartColumn", "EndColumn"}

_MAX_CSV_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

_URL_FETCH_TIMEOUT_SECONDS = 30


@dataclass
class MaskingEntry:
    """Single secret masking action."""

    file: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    description: str
    secret_preview: str


@dataclass
class MaskingReport:
    """Summary of all masking actions."""

    source: str
    csv_path_or_url: str
    total_entries_in_csv: int = 0
    total_secrets_masked: int = 0
    files_modified: int = 0
    entries: list[MaskingEntry] = field(default_factory=list)
    skipped_entries: list[dict] = field(default_factory=list)


def _build_secret_preview(secret: str) -> str:
    """
    Build a safe preview of a secret: first 4 chars + '***'.

    Args:
        secret: The raw secret value

    Returns:
        Truncated preview string
    """
    if len(secret) <= 4:
        return secret[:2] + "***"
    return secret[:4] + "***"


def _validate_csv_rows(rows: list[dict]) -> None:
    """
    Validate that CSV rows have required columns and valid integer values.

    Args:
        rows: Parsed CSV row dictionaries

    Raises:
        ValueError: If required columns are missing or values are invalid
    """
    if not rows:
        return

    actual_columns = set(rows[0].keys())
    missing = _REQUIRED_CSV_COLUMNS - actual_columns
    if missing:
        raise ValueError(
            f"Gitleaks CSV missing required columns: {', '.join(sorted(missing))}"
        )

    integer_columns = ["StartLine", "EndLine", "StartColumn", "EndColumn"]
    for i, row in enumerate(rows):
        for col in integer_columns:
            value = row.get(col, "").strip()
            if not value:
                raise ValueError(
                    f"Row {i + 1}: empty value for column '{col}'"
                )
            try:
                int(value)
            except ValueError:
                raise ValueError(
                    f"Row {i + 1}: invalid integer '{value}' for column '{col}'"
                )


def _fetch_csv_from_url(url: str) -> str:
    """
    Fetch CSV content from an HTTPS URL.

    Args:
        url: HTTPS URL to fetch

    Returns:
        CSV content as string

    Raises:
        ValueError: If URL is not HTTPS or response is too large
        requests.RequestException: If the HTTP request fails
    """
    if not url.startswith("https://"):
        raise ValueError(
            "Only HTTPS URLs are supported. "
            "For HTTP sources, download the CSV locally first."
        )

    response = requests.get(url, timeout=_URL_FETCH_TIMEOUT_SECONDS)
    response.raise_for_status()

    content_length = len(response.content)
    if content_length > _MAX_CSV_SIZE_BYTES:
        raise ValueError(
            f"CSV response too large: {content_length} bytes "
            f"(max {_MAX_CSV_SIZE_BYTES} bytes)"
        )

    return response.text


def load_gitleaks_csv(source: str) -> list[dict]:
    """
    Load and validate a Gitleaks CSV from a local path or URL.

    Args:
        source: Local file path or HTTPS URL to the CSV

    Returns:
        List of parsed CSV row dictionaries

    Raises:
        ValueError: If CSV structure is invalid
        FileNotFoundError: If local file doesn't exist
        requests.RequestException: If URL fetch fails
    """
    if source.startswith("https://") or source.startswith("http://"):
        csv_text = _fetch_csv_from_url(source)
    else:
        abs_path = os.path.abspath(source)
        if not os.path.isfile(abs_path):
            raise FileNotFoundError(
                f"Gitleaks CSV file not found: {abs_path}"
            )

        file_size = os.path.getsize(abs_path)
        if file_size > _MAX_CSV_SIZE_BYTES:
            raise ValueError(
                f"CSV file too large: {file_size} bytes "
                f"(max {_MAX_CSV_SIZE_BYTES} bytes)"
            )

        with open(abs_path, "r", encoding="utf-8") as f:
            csv_text = f.read()

    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)

    _validate_csv_rows(rows)

    return rows


def _validate_file_path(codebase_dir: str, relative_path: str) -> str | None:
    """
    Validate that a file path from the CSV stays within the codebase directory.

    Args:
        codebase_dir: Absolute path to the codebase root
        relative_path: Relative file path from the CSV

    Returns:
        Absolute file path if valid, None if path traversal detected
    """
    abs_path = os.path.normpath(os.path.join(codebase_dir, relative_path))
    if not abs_path.startswith(codebase_dir + os.sep) and abs_path != codebase_dir:
        logger.warning(
            "Path traversal detected in CSV entry, skipping: %s",
            relative_path,
        )
        return None
    return abs_path


def _mask_lines(
    lines: list[str],
    start_line: int,
    end_line: int,
    start_col: int,
    end_col: int,
) -> list[str]:
    """
    Replace secret characters with the mask placeholder in the given lines.

    Line and column numbers are 1-indexed (as provided by Gitleaks).

    Args:
        lines: File content split into lines
        start_line: 1-indexed start line
        end_line: 1-indexed end line
        start_col: 1-indexed start column
        end_col: 1-indexed end column

    Returns:
        Modified lines list
    """
    for line_num in range(start_line, end_line + 1):
        idx = line_num - 1
        if idx < 0 or idx >= len(lines):
            continue

        line = lines[idx]

        if start_line == end_line:
            # Single-line secret
            col_start = start_col - 1
            col_end = end_col
            lines[idx] = line[:col_start] + MASK_PLACEHOLDER + line[col_end:]
        elif line_num == start_line:
            # First line of multi-line secret
            col_start = start_col - 1
            lines[idx] = line[:col_start] + MASK_PLACEHOLDER
        elif line_num == end_line:
            # Last line of multi-line secret
            col_end = end_col
            lines[idx] = MASK_PLACEHOLDER + line[col_end:]
        else:
            # Middle line of multi-line secret
            lines[idx] = MASK_PLACEHOLDER

    return lines


def mask_secrets(codebase_dir: str, gitleaks_csv_path: str) -> MaskingReport:
    """
    Mask secrets in the codebase based on a Gitleaks CSV report.

    Args:
        codebase_dir: Path to the cloned (and already obfuscated) codebase
        gitleaks_csv_path: Local path or URL to the Gitleaks CSV

    Returns:
        MaskingReport with details of all masking actions

    Raises:
        ValueError: If CSV is invalid or codebase directory doesn't exist
        FileNotFoundError: If CSV file doesn't exist
    """
    abs_codebase = os.path.abspath(codebase_dir)
    if not os.path.isdir(abs_codebase):
        raise ValueError(f"Codebase directory does not exist: {abs_codebase}")

    is_url = gitleaks_csv_path.startswith(("http://", "https://"))
    report = MaskingReport(
        source="url" if is_url else "local",
        csv_path_or_url=gitleaks_csv_path,
    )

    rows = load_gitleaks_csv(gitleaks_csv_path)
    report.total_entries_in_csv = len(rows)

    # Group entries by file to minimize file I/O
    file_entries: dict[str, list[dict]] = {}
    for row in rows:
        relative_path = row["File"]
        file_entries.setdefault(relative_path, []).append(row)

    for relative_path, entries in file_entries.items():
        abs_path = _validate_file_path(abs_codebase, relative_path)
        if abs_path is None:
            for entry in entries:
                report.skipped_entries.append(
                    {"file": relative_path, "reason": "path traversal"}
                )
            continue

        if not os.path.isfile(abs_path):
            for entry in entries:
                report.skipped_entries.append(
                    {"file": relative_path, "reason": "file not found"}
                )
            continue

        try:
            with open(abs_path, "r", encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            logger.warning("Cannot read file %s: %s", abs_path, e)
            for entry in entries:
                report.skipped_entries.append(
                    {"file": relative_path, "reason": str(e)}
                )
            continue

        lines = content.splitlines(keepends=True)

        # Sort entries by start_line descending so later replacements
        # don't shift positions of earlier ones on the same line
        sorted_entries = sorted(
            entries,
            key=lambda e: (int(e["StartLine"]), int(e["StartColumn"])),
            reverse=True,
        )

        file_modified = False
        for entry in sorted_entries:
            start_line = int(entry["StartLine"])
            end_line = int(entry["EndLine"])
            start_col = int(entry["StartColumn"])
            end_col = int(entry["EndColumn"])
            description = entry.get("Description", "")
            secret = entry.get("Secret", "")

            # Strip keepends newlines for masking, then restore
            stripped_lines = [l.rstrip("\n").rstrip("\r") for l in lines]
            endings = [l[len(l.rstrip("\r\n")):] for l in lines]

            stripped_lines = _mask_lines(
                stripped_lines, start_line, end_line, start_col, end_col
            )

            lines = [
                stripped_lines[i] + endings[i]
                for i in range(len(lines))
            ]

            masking_entry = MaskingEntry(
                file=relative_path,
                start_line=start_line,
                end_line=end_line,
                start_column=start_col,
                end_column=end_col,
                description=description,
                secret_preview=_build_secret_preview(secret),
            )
            report.entries.append(masking_entry)
            report.total_secrets_masked += 1
            file_modified = True

        if file_modified:
            report.files_modified += 1
            with open(abs_path, "w", encoding="utf-8") as f:
                f.write("".join(lines))

    return report
