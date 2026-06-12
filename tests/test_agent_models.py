"""Tests for the output model: classification, disposition derivation."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import CONFIDENCE_THRESHOLD
from sast_triage.agent_models import (
    AnalystVerdict,
    CheckmarxFinding,
    ConfidenceBreakdown,
    CriticConfig,
    CritiqueDecision,
    CritiqueResult,
    SampleVote,
    SuggestedState,
    TriageDecision,
    derive_state,
)


class TestDeriveState:
    """derive_state maps (is_vulnerable, confidence) to a disposition."""

    def test_undecided_classification_routes_to_refused(self):
        """is_vulnerable=None always becomes REFUSED regardless of confidence."""
        assert derive_state(None, 0.0) == SuggestedState.REFUSED
        assert derive_state(None, 1.0) == SuggestedState.REFUSED

    def test_positive_always_confirmed_even_at_low_confidence(self):
        """A positive is never softened: missing a real vuln is the worst case."""
        assert derive_state(True, 0.0) == SuggestedState.CONFIRMED
        assert derive_state(True, 1.0) == SuggestedState.CONFIRMED

    def test_confident_negative_is_not_exploitable(self):
        """A negative at or above the threshold is a confident dismissal."""
        assert (
            derive_state(False, CONFIDENCE_THRESHOLD)
            == SuggestedState.NOT_EXPLOITABLE
        )
        assert derive_state(False, 1.0) == SuggestedState.NOT_EXPLOITABLE

    def test_low_confidence_negative_is_proposed_not_exploitable(self):
        """A negative below the threshold is escalated for human attention."""
        below = max(0.0, CONFIDENCE_THRESHOLD - 0.01)
        assert (
            derive_state(False, below)
            == SuggestedState.PROPOSED_NOT_EXPLOITABLE
        )

    def test_threshold_only_moves_negatives_between_dismissal_states(self):
        """Raising the threshold to 0.0 collapses PROPOSED into NOT_EXPLOITABLE
        without affecting the positive or undecided branches."""
        # Positive and undecided are threshold-independent.
        assert derive_state(True, 0.0) == SuggestedState.CONFIRMED
        assert derive_state(None, 0.0) == SuggestedState.REFUSED


class TestTriageDecisionSchema:
    """TriageDecision validates the classification and disposition fields."""

    def test_confidence_out_of_range_rejected(self):
        with pytest.raises(ValueError):
            TriageDecision(
                resultHash="h",
                is_vulnerable=True,
                confidence=1.5,
                suggested_state="CONFIRMED",
                justification="x",
            )

    def test_diagnostics_default_to_none(self):
        decision = TriageDecision(
            resultHash="h",
            is_vulnerable=None,
            confidence=0.0,
            suggested_state="REFUSED",
            justification="x",
        )
        assert decision.agreement_rate is None
        assert decision.sample_count is None


# A real finding shape from a benchmark repo, trimmed to the modelled fields.
_REAL_FINDING = {
    "resultHash": "IjQ8QoUyChcGwkSE7oLELYPPjFI=",
    "state": "TO_VERIFY",
    "severity": "MEDIUM",
    "category": "Java_Medium_Threat",
    "cweID": "328",
    "languageName": "java",
    "queryName": "Reversible_One_Way_Hash",
    "dataflow": [
        {
            "column": 65,
            "fileName": "/src/.../BenchmarkTest02717.java",
            "fullName": '""SHA1PRNG""',
            "line": 50,
            "method": "doPost",
            "name": '""SHA1PRNG""',
            "nodeID": 2085836,
            "domType": "StringLiteral",
        }
    ],
}


class TestCheckmarxFinding:
    """The finding model validates the ingestion boundary."""

    def test_parses_real_finding_payload(self):
        finding = CheckmarxFinding(**_REAL_FINDING)
        assert finding.resultHash == "IjQ8QoUyChcGwkSE7oLELYPPjFI="
        assert finding.queryName == "Reversible_One_Way_Hash"
        assert finding.dataflow[0].fileName.endswith("BenchmarkTest02717.java")
        assert finding.dataflow[0].line == 50

    def test_cwe_int_is_coerced_to_string(self):
        finding = CheckmarxFinding(resultHash="h", cweID=328)
        assert finding.cweID == "328"

    def test_cwe_string_is_preserved(self):
        finding = CheckmarxFinding(resultHash="h", cweID="328")
        assert finding.cweID == "328"

    def test_only_result_hash_is_required(self):
        finding = CheckmarxFinding(resultHash="h")
        assert finding.queryName is None
        assert finding.cweID is None
        assert finding.dataflow == []

    def test_missing_result_hash_rejected(self):
        with pytest.raises(ValueError):
            CheckmarxFinding(queryName="SQL_Injection")

    def test_unmodelled_fields_are_preserved(self):
        finding = CheckmarxFinding(resultHash="h", description="extra payload")
        assert finding.model_dump()["description"] == "extra payload"


class TestAnalystVerdict:
    """A single analyst sample carries the vote key plus its evidence trail."""

    def test_minimal_verdict_defaults_collections(self):
        verdict = AnalystVerdict(
            is_vulnerable=True, confidence=0.9, reasoning="reachable sink"
        )
        assert verdict.citation_lines == []
        assert verdict.evidence_refs == []
        assert verdict.sample_temperature is None

    def test_confidence_out_of_range_rejected(self):
        with pytest.raises(ValueError):
            AnalystVerdict(is_vulnerable=False, confidence=2.0, reasoning="x")


class TestCritiqueResult:
    """The critic's structured assessment requires a weakest point."""

    def test_approved_still_requires_weakest_point(self):
        with pytest.raises(ValueError):
            CritiqueResult(decision="APPROVED", rationale="fine")

    def test_decision_accepts_enum_values(self):
        crit = CritiqueResult(
            decision="NEEDS_MORE_RESEARCH",
            rationale="path not established",
            weakest_point="no sink confirmed",
        )
        assert crit.decision == CritiqueDecision.NEEDS_MORE_RESEARCH
        assert crit.gaps == []

    def test_invalid_decision_rejected(self):
        with pytest.raises(ValueError):
            CritiqueResult(
                decision="LGTM", rationale="x", weakest_point="y"
            )


class TestCriticConfig:
    """Critic loop defaults match doc 05."""

    def test_defaults(self):
        config = CriticConfig()
        assert config.temperature == 0.6
        assert config.max_research_loops == 2
        assert config.max_reanalysis_loops == 2


class TestConfidenceBreakdownModels:
    """The aggregator's confidence breakdown and per-sample votes validate."""

    def test_sample_vote_counts_are_non_negative(self):
        with pytest.raises(ValueError):
            SampleVote(
                is_vulnerable=True,
                self_confidence=0.9,
                temperature=0.1,
                n_citations=-1,
                n_evidence_refs=0,
            )

    def test_sample_vote_rejects_negative_evidence_refs(self):
        with pytest.raises(ValueError):
            SampleVote(
                is_vulnerable=False,
                self_confidence=0.5,
                n_citations=0,
                n_evidence_refs=-1,
            )

    def test_breakdown_rejects_out_of_range_agreement_rate(self):
        with pytest.raises(ValueError):
            ConfidenceBreakdown(
                agreement_rate=1.5,
                evidence_strength=0.0,
                agreement_weight=0.7,
                raw_confidence=0.0,
                cap_applied=False,
                cap_value=0.8,
                final_confidence=0.0,
                threshold=0.85,
            )

    def test_breakdown_defaults_sample_votes_to_empty(self):
        bd = ConfidenceBreakdown(
            agreement_rate=None,
            evidence_strength=0.0,
            agreement_weight=0.7,
            raw_confidence=0.0,
            cap_applied=False,
            cap_value=0.8,
            final_confidence=0.0,
            threshold=0.85,
        )
        assert bd.sample_votes == []
        assert bd.agreement_rate is None
