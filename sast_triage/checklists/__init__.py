"""CWE-specific evidence checklists for the analyst prompt.

A checklist supplies the analyst with the evidence it must gather and the
sanitizer patterns that do (or do not) neutralize a given vulnerability class.
`select_checklist` picks one for a finding by its Checkmarx `queryName` and
`cweID`; `render_checklist_section` turns it into a prompt fragment.

Checklist content lives in the sibling YAML files. `_mapping.yaml` routes a
finding to a checklist; `generic.yaml` is the final fallback so every finding
gets guidance.
"""

import logging
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Tuple

import yaml
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

_CHECKLIST_DIR = Path(__file__).parent
_MAPPING_FILE = "_mapping.yaml"
_DEFAULT_CHECKLIST_ID = "generic"


class ChecklistError(Exception):
    """A checklist or the mapping file is missing or malformed."""


class EvidenceItem(BaseModel):
    """One piece of evidence the analyst must establish."""

    description: str
    examples: List[str] = Field(default_factory=list)

    @field_validator("description")
    @classmethod
    def _description_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("evidence description must not be blank")
        return value


class AppliesTo(BaseModel):
    """Which findings a checklist covers."""

    cwes: List[str] = Field(default_factory=list)
    query_names: List[str] = Field(default_factory=list)


class SanitizerPatterns(BaseModel):
    """Guards split by whether they neutralize this vulnerability class.

    ``ineffective`` is required and non-empty: the "do NOT accept these" list is
    the checklist's false-negative guardrail, so a checklist without one is
    treated as malformed rather than silently rendering no bypass warnings.
    """

    effective: List[str] = Field(default_factory=list)
    ineffective: List[str] = Field(min_length=1)


class ChecklistDocument(BaseModel):
    """A validated CWE-specific evidence checklist."""

    checklist_id: str
    display_name: str
    applies_to: AppliesTo = Field(default_factory=AppliesTo)
    evidence_required: List[EvidenceItem] = Field(min_length=1)
    sanitizer_patterns: SanitizerPatterns
    investigation_guidance: str
    common_false_positive_patterns: str

    @field_validator(
        "checklist_id",
        "display_name",
        "investigation_guidance",
        "common_false_positive_patterns",
    )
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("field must not be blank")
        return value


def normalize_cwe(cwe: Optional[object]) -> Optional[str]:
    """Normalize a CWE identifier to the canonical ``CWE-<n>`` form.

    Accepts an integer (``89``), a digit string (``"89"``) or an already
    prefixed string (``"CWE-89"``, any case). Returns None when the input is
    empty or has no digits.
    """
    if cwe is None:
        return None
    text = str(cwe).strip()
    if not text:
        return None
    digits = "".join(ch for ch in text if ch.isdigit())
    return f"CWE-{digits}" if digits else None


@lru_cache(maxsize=1)
def _load_mapping() -> dict:
    path = _CHECKLIST_DIR / _MAPPING_FILE
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ChecklistError(f"Cannot read checklist mapping: {exc}") from exc
    # Lowercase queryName keys so lookup is case-insensitive.
    query_map = {
        str(k).lower(): v
        for k, v in (data.get("query_name_to_checklist") or {}).items()
    }
    return {
        "query_name_to_checklist": query_map,
        "cwe_to_checklist": data.get("cwe_to_checklist") or {},
        "default": data.get("default", _DEFAULT_CHECKLIST_ID),
    }


@lru_cache(maxsize=None)
def load_checklist(checklist_id: str) -> ChecklistDocument:
    """Load and validate a single checklist by its id (filename stem).

    Raises:
        ChecklistError: the file is missing or does not match the schema.
    """
    path = _CHECKLIST_DIR / f"{checklist_id}.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ChecklistError(
            f"Cannot read checklist '{checklist_id}': {exc}"
        ) from exc
    try:
        return ChecklistDocument.model_validate(data)
    except Exception as exc:
        raise ChecklistError(
            f"Checklist '{checklist_id}' is malformed: {exc}"
        ) from exc


def select_checklist(
    query_name: Optional[str], cwe: Optional[object]
) -> ChecklistDocument:
    """Select the checklist for a finding, most specific match first.

    Resolution order: exact (case-insensitive) ``queryName``, then normalized
    CWE, then the configured default. A mapped-but-unloadable checklist falls
    back to the default with a warning; the default itself failing is fatal.
    """
    checklist, _ = select_checklist_with_method(query_name, cwe)
    return checklist


def select_checklist_with_method(
    query_name: Optional[str], cwe: Optional[object]
) -> Tuple[ChecklistDocument, str]:
    """Like ``select_checklist`` but also returns the resolution layer that
    matched: ``"query_name"``, ``"cwe"`` or ``"default"``.

    When a mapped (non-default) checklist fails to load and the loader
    falls back to the default, the returned method is ``"default"``: the
    label reflects the checklist that was actually applied.
    """
    mapping = _load_mapping()

    checklist_id: Optional[str] = None
    method = "default"
    if query_name:
        checklist_id = mapping["query_name_to_checklist"].get(
            query_name.strip().lower()
        )
        if checklist_id is not None:
            method = "query_name"
    if checklist_id is None:
        normalized = normalize_cwe(cwe)
        if normalized:
            checklist_id = mapping["cwe_to_checklist"].get(normalized)
            if checklist_id is not None:
                method = "cwe"
    if checklist_id is None:
        checklist_id = mapping["default"]

    try:
        return load_checklist(checklist_id), method
    except ChecklistError:
        if checklist_id == mapping["default"]:
            raise
        logger.warning(
            "Checklist '%s' could not be loaded; using default '%s'",
            checklist_id,
            mapping["default"],
        )
        return load_checklist(mapping["default"]), "default"


# Reason: one false-negative-averse stance rendered into every checklist (and
# therefore seen by the research, analyst and critic nodes) so no per-CWE file
# can omit or contradict it. The analyst prompt sets the global "when uncertain,
# choose exploitable" rule; this ties that rule to the source and sink reasoning
# the checklists drive and shifts the burden of proof onto the control, away
# from assuming the source is safe.
_DEFAULT_STANCE = """\
DEFAULT STANCE (this tool minimizes false negatives: a missed vulnerability is the worst outcome):
- The sink is decisive. If a tainted value reaches the sink without an effective, context-correct control on that exact value, established in the evidence, the finding is exploitable. A control that is effective for one position or context (a bound parameter for a value, HTML-body encoding for body text) is not effective for another (an identifier position, or a URL, attribute or script context).
- "Established" means you have read the control and can cite it. A control you assume is present (a framework that "binds by default" or "auto-escapes", a value you label a "plain data argument") is not established: verify it at the exact sink.
- Source provenance: treat a source whose origin you cannot verify from the evidence (another system, a database or store of unknown provenance, a queued message, an import, an upstream response) as attacker-controlled. Dismiss on source grounds only when the evidence proves the value cannot be attacker-influenced: a literal constant, a strict enum, or a value the code itself fixes.
- When no effective control is established on the path, lean CONFIRMED over NOT_EXPLOITABLE. If the evidence is genuinely insufficient to decide, set is_vulnerable null rather than guessing."""


def render_checklist_section(checklist: ChecklistDocument) -> str:
    """Render a checklist as a prompt section appended to the system prompt."""
    lines: List[str] = [
        f"### CWE-SPECIFIC CHECKLIST: {checklist.display_name}",
        "Apply this checklist while working through the analysis protocol.",
        "",
        "REQUIRED EVIDENCE (address each before a verdict):",
    ]
    for item in checklist.evidence_required:
        suffix = (
            f" (e.g. {'; '.join(item.examples)})" if item.examples else ""
        )
        lines.append(f"- {item.description}{suffix}")

    lines += [
        "",
        "EFFECTIVE CONTROLS (these genuinely neutralize this vulnerability):",
    ]
    lines += [f"- {p}" for p in checklist.sanitizer_patterns.effective]
    lines += [
        "",
        "INEFFECTIVE / BYPASSABLE (do NOT accept these as sufficient):",
    ]
    lines += [f"- {p}" for p in checklist.sanitizer_patterns.ineffective]

    lines += [
        "",
        "INVESTIGATION GUIDANCE:",
        checklist.investigation_guidance.strip(),
        "",
        "COMMON FALSE-POSITIVE PATTERNS:",
        checklist.common_false_positive_patterns.strip(),
        "",
        _DEFAULT_STANCE,
    ]
    return "\n".join(lines)
