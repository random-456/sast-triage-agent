"""Tests for CWE checklist selection, loading and rendering."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from sast_triage.checklists import (
    _CHECKLIST_DIR,
    ChecklistDocument,
    ChecklistError,
    load_checklist,
    normalize_cwe,
    render_checklist_section,
    select_checklist,
)

_RESERVED = {"_schema", "_mapping"}


def _shipped_checklist_ids():
    return sorted(
        p.stem
        for p in _CHECKLIST_DIR.glob("*.yaml")
        if p.stem not in _RESERVED
    )


class TestNormalizeCwe:
    """CWE identifiers arrive as ints, digit strings or prefixed strings."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            (89, "CWE-89"),
            ("89", "CWE-89"),
            ("CWE-89", "CWE-89"),
            ("cwe-89", "CWE-89"),
            (" CWE-89 ", "CWE-89"),
        ],
    )
    def test_normalize_cwe_various_forms_returns_canonical(self, raw, expected):
        assert normalize_cwe(raw) == expected

    @pytest.mark.parametrize("raw", [None, "", "   ", "none"])
    def test_normalize_cwe_empty_or_nondigit_returns_none(self, raw):
        assert normalize_cwe(raw) is None


class TestSelectChecklist:
    """Selection prefers queryName, then CWE, then the generic default."""

    def test_select_by_query_name_returns_mapped_checklist(self):
        checklist = select_checklist("SQL_Injection", None)
        assert checklist.checklist_id == "sqli"

    def test_select_by_query_name_is_case_insensitive(self):
        checklist = select_checklist("sql_injection", None)
        assert checklist.checklist_id == "sqli"

    def test_select_by_cwe_when_query_name_unmapped(self):
        checklist = select_checklist("Some_Unmapped_Query", 89)
        assert checklist.checklist_id == "sqli"

    @pytest.mark.parametrize(
        "query_name,expected",
        [
            ("Reflected_XSS", "xss_reflected"),
            ("XSS_Evasion_Attack_via_Replace", "xss_reflected"),
            ("Stored_XSS", "xss_stored"),
        ],
    )
    def test_select_xss_subflavor_by_query_name(self, query_name, expected):
        assert select_checklist(query_name, 79).checklist_id == expected

    @pytest.mark.parametrize(
        "cwe,expected",
        [
            (79, "xss_reflected"),
            (78, "command_injection"),
            (77, "command_injection"),
            (22, "path_traversal"),
        ],
    )
    def test_select_by_cwe_routes_to_family_checklist(self, cwe, expected):
        # No queryName, so routing falls to the CWE map.
        assert select_checklist(None, cwe).checklist_id == expected

    def test_select_query_name_takes_precedence_over_cwe(self):
        # queryName maps to sqli; the unmapped CWE must not override it.
        checklist = select_checklist("SQL_Injection", 999)
        assert checklist.checklist_id == "sqli"

    def test_select_unmapped_finding_falls_back_to_generic(self):
        checklist = select_checklist("Totally_Unknown", 9999)
        assert checklist.checklist_id == "generic"

    def test_select_missing_signals_falls_back_to_generic(self):
        checklist = select_checklist(None, None)
        assert checklist.checklist_id == "generic"


class TestLoadChecklist:
    """Loading validates each file against the ChecklistDocument schema."""

    def test_load_sqli_returns_populated_document(self):
        checklist = load_checklist("sqli")
        assert isinstance(checklist, ChecklistDocument)
        assert checklist.evidence_required
        assert checklist.sanitizer_patterns.effective
        assert checklist.sanitizer_patterns.ineffective

    def test_load_unknown_id_raises_checklist_error(self):
        with pytest.raises(ChecklistError):
            load_checklist("does_not_exist")

    def test_every_shipped_checklist_validates(self):
        for checklist_id in _shipped_checklist_ids():
            assert isinstance(load_checklist(checklist_id), ChecklistDocument)


class TestRenderChecklistSection:
    """The rendered section embeds the checklist into the system prompt."""

    def test_render_includes_display_name_and_sections(self):
        section = render_checklist_section(load_checklist("sqli"))
        assert "SQL Injection (CWE-89)" in section
        assert "REQUIRED EVIDENCE" in section
        assert "EFFECTIVE CONTROLS" in section
        assert "INEFFECTIVE / BYPASSABLE" in section
        assert "INVESTIGATION GUIDANCE" in section
        assert "COMMON FALSE-POSITIVE PATTERNS" in section

    def test_render_lists_an_effective_control(self):
        checklist = load_checklist("sqli")
        section = render_checklist_section(checklist)
        assert checklist.sanitizer_patterns.effective[0] in section


def test_mapping_targets_all_resolve_to_loadable_checklists():
    """Every checklist id referenced by the mapping must have a valid file."""
    from sast_triage.checklists import _load_mapping

    mapping = _load_mapping()
    referenced = set(mapping["query_name_to_checklist"].values())
    referenced |= set(mapping["cwe_to_checklist"].values())
    referenced.add(mapping["default"])

    for checklist_id in referenced:
        assert isinstance(load_checklist(checklist_id), ChecklistDocument)
