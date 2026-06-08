"""Tests for CWE checklist selection, loading and rendering."""

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))

from sast_triage.checklists import (
    _CHECKLIST_DIR,
    ChecklistDocument,
    ChecklistError,
    EvidenceItem,
    SanitizerPatterns,
    load_checklist,
    normalize_cwe,
    render_checklist_section,
    select_checklist,
    select_checklist_with_method,
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

    def test_select_client_potential_xss_routes_to_dom(self):
        # DOM/client XSS has different sources and sinks than reflected XSS and
        # must not inherit the server-Content-Type reasoning.
        assert (
            select_checklist("Client_Potential_XSS", 79).checklist_id
            == "xss_dom"
        )

    def test_select_cwe_116_routes_to_encoding_checklist(self):
        # CWE-116 (improper output encoding) is the output-encoding sibling of
        # XSS; route it to the reflected-XSS encoding guidance, not generic.
        assert select_checklist(None, 116).checklist_id == "xss_reflected"


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


class TestSchemaValidation:
    """The schema rejects weak or malformed checklists so a document that would
    render an empty, guard-removing section cannot load silently."""

    @staticmethod
    def _valid_kwargs():
        return dict(
            checklist_id="x",
            display_name="X",
            evidence_required=[EvidenceItem(description="d")],
            sanitizer_patterns=SanitizerPatterns(
                effective=["e"], ineffective=["i"]
            ),
            investigation_guidance="g",
            common_false_positive_patterns="f",
        )

    def test_valid_document_constructs(self):
        assert ChecklistDocument(**self._valid_kwargs()).checklist_id == "x"

    def test_empty_evidence_required_is_rejected(self):
        kwargs = self._valid_kwargs()
        kwargs["evidence_required"] = []
        with pytest.raises(ValidationError):
            ChecklistDocument(**kwargs)

    def test_empty_ineffective_list_is_rejected(self):
        with pytest.raises(ValidationError):
            SanitizerPatterns(effective=["e"], ineffective=[])

    def test_blank_guidance_is_rejected(self):
        kwargs = self._valid_kwargs()
        kwargs["investigation_guidance"] = "   "
        with pytest.raises(ValidationError):
            ChecklistDocument(**kwargs)


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

    def test_render_includes_every_evidence_and_control(self):
        # Rendering is the only thing the model sees, so silent truncation of a
        # bullet would weaken the prompt without any error.
        for checklist_id in _shipped_checklist_ids():
            checklist = load_checklist(checklist_id)
            section = render_checklist_section(checklist)
            for item in checklist.evidence_required:
                assert item.description in section, checklist_id
            for pattern in checklist.sanitizer_patterns.effective:
                assert pattern in section, checklist_id
            for pattern in checklist.sanitizer_patterns.ineffective:
                assert pattern in section, checklist_id


class TestSelectChecklistWithMethod:
    """The resolution layer that matched is logged as telemetry, so its label
    must be correct, including the fallback when a mapped checklist fails."""

    def test_method_is_query_name_on_query_match(self):
        _, method = select_checklist_with_method("SQL_Injection", None)
        assert method == "query_name"

    def test_method_is_cwe_on_cwe_match(self):
        _, method = select_checklist_with_method(None, 89)
        assert method == "cwe"

    def test_method_is_default_on_no_match(self):
        _, method = select_checklist_with_method(None, 9999)
        assert method == "default"

    def test_mapped_but_unloadable_falls_back_to_default(self, monkeypatch):
        import sast_triage.checklists as cl

        real = cl.load_checklist

        def fake(checklist_id):
            if checklist_id == "sqli":
                raise cl.ChecklistError("boom")
            return real(checklist_id)

        monkeypatch.setattr(cl, "load_checklist", fake)
        doc, method = cl.select_checklist_with_method("SQL_Injection", None)
        assert doc.checklist_id == "generic"
        assert method == "default"


class TestDefaultStance:
    """Every rendered checklist must carry the false-negative-averse stance so
    no per-CWE file can omit or contradict it: the sink is decisive, a source
    whose origin cannot be verified is treated as attacker-controlled, and an
    unestablished control leans CONFIRMED."""

    def test_every_render_states_lean_confirmed(self):
        for checklist_id in _shipped_checklist_ids():
            section = render_checklist_section(load_checklist(checklist_id))
            assert "lean CONFIRMED" in section, checklist_id

    def test_every_render_states_source_provenance_rule(self):
        for checklist_id in _shipped_checklist_ids():
            section = render_checklist_section(load_checklist(checklist_id))
            assert (
                "dismiss on source grounds only when" in section.lower()
            ), checklist_id


class TestNoDismissiveAssumptions:
    """No checklist may license dismissal on an assumed deployment model or an
    assumed (unverified) control: those phrasings lose true positives."""

    def test_generic_does_not_dismiss_on_assumed_tenancy(self):
        section = render_checklist_section(load_checklist("generic"))
        assert "single-tenant" not in section.lower()

    def test_reflected_xss_drops_false_positive_base_rate(self):
        section = render_checklist_section(load_checklist("xss_reflected"))
        assert "most reflected findings false positives" not in section.lower()

    def test_stored_xss_drops_false_positive_base_rate(self):
        section = render_checklist_section(load_checklist("xss_stored"))
        assert (
            "usually makes the finding a false positive" not in section.lower()
        )


def test_mapping_targets_all_resolve_to_loadable_checklists():
    """Every checklist id referenced by the mapping must have a valid file."""
    from sast_triage.checklists import _load_mapping

    mapping = _load_mapping()
    referenced = set(mapping["query_name_to_checklist"].values())
    referenced |= set(mapping["cwe_to_checklist"].values())
    referenced.add(mapping["default"])

    for checklist_id in referenced:
        assert isinstance(load_checklist(checklist_id), ChecklistDocument)
