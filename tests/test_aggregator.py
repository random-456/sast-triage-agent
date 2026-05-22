"""Tests for self-consistency aggregation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import CONFIDENCE_AGREEMENT_WEIGHT
from sast_triage.agent_models import AnalystVerdict, SuggestedState
from sast_triage.aggregator import (
    aggregate_samples,
    compute_evidence_strength,
    has_majority,
    tally,
)


def _v(is_vulnerable, citations=None, refs=None) -> AnalystVerdict:
    return AnalystVerdict(
        is_vulnerable=is_vulnerable,
        confidence=0.9,
        reasoning="reasoned",
        citation_lines=citations or [],
        evidence_refs=refs or [],
    )


class TestTally:
    def test_unanimous(self):
        value, rate, clear = tally([True, True, True])
        assert value is True
        assert rate == 1.0
        assert clear is True

    def test_two_thirds_majority(self):
        value, rate, clear = tally([True, True, False])
        assert value is True
        assert round(rate, 3) == 0.667
        assert clear is True

    def test_even_split_is_not_a_majority(self):
        _, rate, clear = tally([True, False])
        assert rate == 0.5
        assert clear is False

    def test_three_way_split_is_not_a_majority(self):
        _, _, clear = tally([True, False, None])
        assert clear is False


class TestHasMajority:
    def test_empty_is_false(self):
        assert has_majority([]) is False

    def test_agreeing_pair_is_true(self):
        assert has_majority([_v(True), _v(True)]) is True

    def test_split_pair_is_false(self):
        assert has_majority([_v(True), _v(False)]) is False


class TestEvidenceStrength:
    def test_no_evidence_is_zero(self):
        assert compute_evidence_strength([_v(True)]) == 0.0

    def test_more_evidence_scores_higher(self):
        weak = compute_evidence_strength([_v(True, citations=["a:1"], refs=["a"])])
        strong = compute_evidence_strength(
            [_v(True, citations=["a:1", "b:2", "c:3", "d:4", "e:5"], refs=["a", "b", "c", "d", "e"])]
        )
        assert strong > weak
        assert 0.0 <= strong <= 1.0


class TestAggregateSamples:
    def test_no_samples_refuses(self):
        decision = aggregate_samples("h", [])
        assert decision.is_vulnerable is None
        assert decision.suggested_state == SuggestedState.REFUSED
        assert decision.sample_count == 0
        assert decision.agreement_rate is None

    def test_unanimous_exploitable_confirms(self):
        decision = aggregate_samples("h", [_v(True), _v(True)])
        assert decision.is_vulnerable is True
        assert decision.suggested_state == SuggestedState.CONFIRMED
        assert decision.agreement_rate == 1.0
        assert decision.sample_count == 2

    def test_split_routes_to_refused(self):
        decision = aggregate_samples("h", [_v(True), _v(False)])
        assert decision.is_vulnerable is None
        assert decision.confidence == 0.0
        assert decision.suggested_state == SuggestedState.REFUSED
        # The split level is still reported as a diagnostic.
        assert decision.agreement_rate == 0.5

    def test_confidence_blends_agreement_and_evidence(self):
        # Two-thirds agreement, no evidence -> confidence is agreement * W only.
        samples = [_v(True), _v(True), _v(False)]
        decision = aggregate_samples("h", samples)
        expected = round(CONFIDENCE_AGREEMENT_WEIGHT * (2 / 3), 4)
        assert decision.is_vulnerable is True
        assert decision.confidence == expected

    def test_stop_reason_noted_in_justification(self):
        decision = aggregate_samples("h", [_v(False), _v(False)], stop_reason="max_research")
        assert "max_research" in decision.justification
