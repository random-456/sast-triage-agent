"""JSONL event writer for the session log.

The writer opens the log file lazily on the first event, appends one JSON
object per line, flushes after every write so a process crash leaves a
clean prefix of complete events. The file handle is closed at session end
or via an ``atexit`` hook on SIGTERM.

Concurrency: a ``threading.Lock`` guards writes. The triage agent
processes findings serially today, but the lock keeps the writer correct
if callbacks fire from a thread the user did not anticipate.
"""

from __future__ import annotations

import atexit
import logging
import threading
from pathlib import Path
from typing import Optional, TextIO

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class JsonlEventWriter:
    """Append-only JSONL writer.

    Args:
        log_path: Absolute or repo-relative path of the file to write.
            Parent directories are created on first write.
    """

    def __init__(self, log_path: Path) -> None:
        self.log_path = Path(log_path)
        self._fh: Optional[TextIO] = None
        self._lock = threading.Lock()
        self._closed = False
        atexit.register(self._atexit_close)

    def write(self, event: BaseModel) -> None:
        """Serialize an event to JSON and append it as one line.

        Raises:
            RuntimeError: the writer was already closed.
        """
        line = event.model_dump_json()
        with self._lock:
            if self._closed:
                raise RuntimeError("JsonlEventWriter is closed")
            self._ensure_open_locked()
            assert self._fh is not None
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        """Close the file handle. Idempotent."""
        with self._lock:
            self._close_locked()
            self._closed = True

    def _ensure_open_locked(self) -> None:
        if self._fh is None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            # buffering=1 = line-buffered text mode (additional safety layer
            # on top of explicit flush()).
            self._fh = self.log_path.open(
                "a", buffering=1, encoding="utf-8"
            )

    def _close_locked(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Error closing session log: %s", exc)
            finally:
                self._fh = None

    def _atexit_close(self) -> None:
        # atexit handlers run without the caller's lock context;
        # acquire it ourselves and skip if already closed cleanly.
        with self._lock:
            if not self._closed:
                self._close_locked()
                self._closed = True
