"""Cross-platform path helpers for working around Windows MAX_PATH.

Win32 file I/O silently rejects paths longer than 260 chars unless they
carry the ``\\\\?\\`` (or ``\\\\?\\UNC\\`` for shares) prefix. Real
enterprise repos cloned into a nested workspace routinely exceed that
limit, which manifests as ``FileNotFoundError`` on read or rmtree even
though ``os.listdir`` of the parent (just under the limit) succeeded.

Both helpers are no-ops on POSIX.
"""

import os


def io_safe(path: str) -> str:
    """Return ``path`` in a form safe for I/O on the current platform.

    On Windows, returns the absolute path with the long-path prefix so
    Win32 bypasses the legacy MAX_PATH limit. Idempotent.
    """
    if os.name != "nt":
        return path
    path = os.path.abspath(path)
    if path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


def display_path(path: str) -> str:
    """Strip the Windows long-path prefix for display / relpath computation."""
    if os.name != "nt":
        return path
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path
