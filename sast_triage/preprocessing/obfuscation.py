"""
Obfuscation module for sensitive infrastructure patterns.

Replaces IP addresses, MAC addresses, and internal FQDNs with placeholder
tokens in all text files within a codebase directory. This prevents leaking
internal network details to external AI services.
"""

import logging
import os
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

OBFUSCATION_PATTERNS = {
    "IPV4": r"([0-9]{1,3}\.){3}[0-9]{1,3}",
    "IPV6": r"([0-9a-fA-F]{0,4}:(:)?){1,7}([0-9a-fA-F]{3,4})",
    "MAC": r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})",
    "FQDN": r"(([a-zA-Z0-9_\-]){1,20}\.){1,5}(abcorg\.com|corp)",
}

BINARY_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".bmp", ".tiff", ".webp",
    ".pdf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".jar", ".war", ".ear",
    ".class", ".pyc", ".pyo",
    ".exe", ".dll", ".so", ".o", ".bin", ".dat",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".webm", ".flac", ".wav",
    ".db", ".sqlite",
})

_BINARY_CHECK_SIZE = 8192


@dataclass
class ObfuscationEntry:
    """Single obfuscation action."""

    file: str
    line: int
    pattern_type: str
    original: str


@dataclass
class ObfuscationReport:
    """Summary of all obfuscation actions."""

    total_files_processed: int = 0
    total_files_modified: int = 0
    total_replacements: int = 0
    replacements_by_type: dict[str, int] = field(default_factory=dict)
    entries: list[ObfuscationEntry] = field(default_factory=list)


def _is_binary_file(file_path: str) -> bool:
    """
    Determine whether a file is binary.

    Checks by extension first, then falls back to reading the first 8 KB
    and attempting UTF-8 decode.

    Args:
        file_path: Absolute path to the file

    Returns:
        True if the file is binary, False otherwise
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext in BINARY_EXTENSIONS:
        return True

    try:
        with open(file_path, "rb") as f:
            chunk = f.read(_BINARY_CHECK_SIZE)
        chunk.decode("utf-8")
        return False
    except (UnicodeDecodeError, OSError):
        return True


def _collect_entries(
    content: str,
    relative_path: str,
    pattern_type: str,
    regex: re.Pattern[str],
) -> list[ObfuscationEntry]:
    """
    Find all matches of a regex pattern in file content and return entries.

    Args:
        content: The file text content
        relative_path: File path relative to codebase root
        pattern_type: Label such as IPV4, MAC, etc.
        regex: Compiled regex pattern

    Returns:
        List of ObfuscationEntry for each match found
    """
    entries: list[ObfuscationEntry] = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        for match in regex.finditer(line):
            entries.append(
                ObfuscationEntry(
                    file=relative_path,
                    line=line_num,
                    pattern_type=pattern_type,
                    original=match.group(0),
                )
            )
    return entries


def _validate_codebase_dir(codebase_dir: str) -> str:
    """
    Validate and return the absolute codebase directory path.

    Args:
        codebase_dir: Path to the codebase directory

    Returns:
        Absolute path to the codebase directory

    Raises:
        ValueError: If the directory does not exist
    """
    abs_dir = os.path.abspath(codebase_dir)
    if not os.path.isdir(abs_dir):
        raise ValueError(f"Codebase directory does not exist: {abs_dir}")
    return abs_dir


def obfuscate_codebase(codebase_dir: str) -> ObfuscationReport:
    """
    Obfuscate sensitive patterns in all text files within the codebase directory.

    Walks all files, skips binaries, applies regex replacements in-place.

    Args:
        codebase_dir: Path to the cloned codebase directory

    Returns:
        ObfuscationReport with details of all replacements made

    Raises:
        ValueError: If codebase_dir does not exist
    """
    abs_codebase = _validate_codebase_dir(codebase_dir)
    report = ObfuscationReport()

    compiled_patterns = {
        name: re.compile(pattern)
        for name, pattern in OBFUSCATION_PATTERNS.items()
    }

    for dirpath, _dirnames, filenames in os.walk(abs_codebase):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)

            # Security: ensure file is within codebase directory
            abs_file = os.path.abspath(file_path)
            if not abs_file.startswith(abs_codebase + os.sep):
                continue

            if _is_binary_file(file_path):
                continue

            report.total_files_processed += 1

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except (OSError, UnicodeDecodeError) as e:
                logger.warning(f"Skipping file {file_path}: {e}")
                continue

            relative_path = os.path.relpath(file_path, abs_codebase)
            file_modified = False

            for pattern_type, regex in compiled_patterns.items():
                entries = _collect_entries(
                    content, relative_path, pattern_type, regex
                )
                if entries:
                    placeholder = f"__{pattern_type}__"
                    content = regex.sub(placeholder, content)
                    report.entries.extend(entries)
                    count = len(entries)
                    report.total_replacements += count
                    report.replacements_by_type[pattern_type] = (
                        report.replacements_by_type.get(pattern_type, 0)
                        + count
                    )
                    file_modified = True

            if file_modified:
                report.total_files_modified += 1
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)

    return report
