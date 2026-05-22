"""Tests for the per-finding graph state and its evidence containers."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from sast_triage.agent_models import AnalystVerdict, CheckmarxFinding
from sast_triage.checklists import load_checklist
from sast_triage.graph import (
    CodeEvidence,
    EvidenceBundle,
    ToolCallRecord,
    TriageState,
)


class TestEvidenceBundle:
    """The CODE BANK accumulates retrieved snippets."""

    def test_starts_empty(self):
        assert EvidenceBundle().items == []

    def test_add_appends_in_order(self):
        bundle = EvidenceBundle()
        bundle.add(CodeEvidence(file_path="a.py", content="x"))
        bundle.add(CodeEvidence(file_path="b.py", content="y"))
        assert [i.file_path for i in bundle.items] == ["a.py", "b.py"]


class TestToolCallRecord:
    """A failed tool call is recorded so it is not retried verbatim."""

    def test_requires_name_and_error(self):
        record = ToolCallRecord(tool_name="read_file", error="not found")
        assert record.arguments == {}
        with pytest.raises(ValueError):
            ToolCallRecord(arguments={"path": "x"})


class TestTriageState:
    """TriageState wires the finding, checklist and accumulating state."""

    def _state(self) -> TriageState:
        return TriageState(
            finding=CheckmarxFinding(resultHash="h", cweID="89"),
            checklist=load_checklist("sqli"),
        )

    def test_defaults_are_independent_per_instance(self):
        first = self._state()
        second = self._state()
        first.evidence.add(CodeEvidence(file_path="a.py", content="x"))
        first.samples.append(
            AnalystVerdict(is_vulnerable=True, confidence=0.9, reasoning="r")
        )
        # Default factories must not share state across instances.
        assert second.evidence.items == []
        assert second.samples == []

    def test_initial_counters_and_terminal_fields(self):
        state = self._state()
        assert state.research_iterations == 0
        assert state.reanalysis_count == 0
        assert state.current_sample_idx == 0
        assert state.failed_tool_calls == []
        assert state.last_critique is None
        assert state.stop_reason is None
        assert state.verdict is None

    def test_finding_requires_result_hash(self):
        with pytest.raises(ValueError):
            TriageState(finding={}, checklist=load_checklist("sqli"))

    def test_invalid_stop_reason_rejected(self):
        with pytest.raises(ValueError):
            TriageState(
                finding=CheckmarxFinding(resultHash="h"),
                checklist=load_checklist("sqli"),
                stop_reason="exploded",
            )
