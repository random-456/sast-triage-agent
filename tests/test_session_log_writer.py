"""Tests for ``JsonlEventWriter``."""

import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from sast_triage.session_log.writer import JsonlEventWriter


class _StubEvent(BaseModel):
    type: str
    value: int


def _read_lines(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_writer_creates_parent_directory_on_first_write(tmp_path):
    log_path = tmp_path / "logs" / "session.jsonl"
    w = JsonlEventWriter(log_path)
    assert not log_path.parent.exists()
    w.write(_StubEvent(type="t", value=1))
    assert log_path.exists()
    w.close()


def test_writer_appends_one_event_per_line(tmp_path):
    log_path = tmp_path / "session.jsonl"
    w = JsonlEventWriter(log_path)
    for i in range(5):
        w.write(_StubEvent(type="t", value=i))
    w.close()
    lines = _read_lines(log_path)
    assert [entry["value"] for entry in lines] == [0, 1, 2, 3, 4]


def test_writer_close_is_idempotent(tmp_path):
    log_path = tmp_path / "session.jsonl"
    w = JsonlEventWriter(log_path)
    w.write(_StubEvent(type="t", value=1))
    w.close()
    w.close()  # no-op, no exception


def test_writer_after_close_rejects_new_writes(tmp_path):
    log_path = tmp_path / "session.jsonl"
    w = JsonlEventWriter(log_path)
    w.write(_StubEvent(type="t", value=1))
    w.close()
    with pytest.raises(RuntimeError):
        w.write(_StubEvent(type="t", value=2))


def test_writer_appends_to_existing_file(tmp_path):
    log_path = tmp_path / "session.jsonl"
    log_path.write_text(
        '{"type":"earlier","value":-1}\n', encoding="utf-8"
    )
    w = JsonlEventWriter(log_path)
    w.write(_StubEvent(type="t", value=99))
    w.close()
    lines = _read_lines(log_path)
    assert len(lines) == 2
    assert lines[0]["value"] == -1
    assert lines[1]["value"] == 99


def test_writer_flushes_each_event_for_crash_safety(tmp_path):
    """A consumer reading the file mid-session sees prior events without
    waiting for the writer to close.
    """
    log_path = tmp_path / "session.jsonl"
    w = JsonlEventWriter(log_path)
    w.write(_StubEvent(type="t", value=10))
    # Read while the writer is still open: previous line must be visible.
    lines = _read_lines(log_path)
    assert lines == [{"type": "t", "value": 10}]
    w.write(_StubEvent(type="t", value=11))
    lines = _read_lines(log_path)
    assert lines == [
        {"type": "t", "value": 10},
        {"type": "t", "value": 11},
    ]
    w.close()
