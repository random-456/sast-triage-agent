"""Tests for self-consistency aggregation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import (
    CONFIDENCE_AGREEMENT_WEIGHT,
    CONFIDENCE_THRESHOLD,
    NON_CONVERGENT_CONFIDENCE_CAP,
)
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


def _strong(is_vulnerable) -> AnalystVerdict:
    """A lone verdict with maxed-out evidence strength.

    Five distinct files and five citations saturate
    ``compute_evidence_strength``, so a single sample's blended confidence is
    1.0. Used to show a non-convergent dismissal would otherwise clear
    ``CONFIDENCE_THRESHOLD`` were it not clamped.
    """
    return _v(
        is_vulnerable,
        citations=["a:1", "b:2", "c:3", "d:4", "e:5"],
        refs=["a", "b", "c", "d", "e"],
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
        decision, _ = aggregate_samples("h", [])
        assert decision.is_vulnerable is None
        assert decision.suggested_state == SuggestedState.REFUSED
        assert decision.sample_count == 0
        assert decision.agreement_rate is None

    def test_unanimous_exploitable_confirms(self):
        decision, _ = aggregate_samples("h", [_v(True), _v(True)])
        assert decision.is_vulnerable is True
        assert decision.suggested_state == SuggestedState.CONFIRMED
        assert decision.agreement_rate == 1.0
        assert decision.sample_count == 2

    def test_split_routes_to_refused(self):
        decision, _ = aggregate_samples("h", [_v(True), _v(False)])
        assert decision.is_vulnerable is None
        assert decision.confidence == 0.0
        assert decision.suggested_state == SuggestedState.REFUSED
        # The split level is still reported as a diagnostic.
        assert decision.agreement_rate == 0.5

    def test_confidence_blends_agreement_and_evidence(self):
        # Two-thirds agreement, no evidence -> confidence is agreement * W only.
        samples = [_v(True), _v(True), _v(False)]
        decision, _ = aggregate_samples("h", samples)
        expected = round(CONFIDENCE_AGREEMENT_WEIGHT * (2 / 3), 4)
        assert decision.is_vulnerable is True
        assert decision.confidence == expected

    def test_stop_reason_noted_in_justification(self):
        decision, _ = aggregate_samples("h", [_v(False), _v(False)], stop_reason="max_research")
        assert "max_research" in decision.justification


class TestUncorroboratedSampleConfidence:
    """A lone analyst sample is not self-consistency: its agreement_rate is
    trivially 1.0, so confidence must rest on evidence strength alone and the
    agreement diagnostic must not claim a consensus that never happened. A
    positive verdict stays CONFIRMED regardless, so this is recall-safe."""

    def test_single_exploitable_sample_reports_uncorroborated_confidence(self):
        decision, _ = aggregate_samples("h", [_strong(True)])
        assert decision.is_vulnerable is True
        assert decision.suggested_state == SuggestedState.CONFIRMED
        # Agreement over one sample is not credited, so even maxed-out evidence
        # cannot clear the threshold on a single sample.
        assert decision.confidence < CONFIDENCE_THRESHOLD

    def test_single_sample_confidence_excludes_agreement_term(self):
        # One citation and one ref give evidence_strength 0.2; with no agreement
        # credit the confidence is (1 - W) * 0.2.
        sample = _v(True, citations=["a:1"], refs=["a"])
        decision, _ = aggregate_samples("h", [sample])
        expected = round((1 - CONFIDENCE_AGREEMENT_WEIGHT) * 0.2, 4)
        assert decision.confidence == expected

    def test_single_sample_reports_no_agreement_diagnostic(self):
        decision, _ = aggregate_samples("h", [_v(True)])
        assert decision.agreement_rate is None
        assert decision.sample_count == 1

    def test_single_sample_justification_states_no_corroboration(self):
        decision, _ = aggregate_samples("h", [_v(True)])
        assert "single analyst sample" in decision.justification.lower()

    def test_two_agreeing_samples_credit_agreement(self):
        # The corroboration boundary is exactly two samples: with agreement the
        # confidence is W * 1.0 (no evidence here) and the diagnostic reports
        # the real agreement rate.
        decision, _ = aggregate_samples("h", [_v(True), _v(True)])
        assert decision.confidence == round(CONFIDENCE_AGREEMENT_WEIGHT * 1.0, 4)
        assert decision.agreement_rate == 1.0


class TestNonConvergentConfidenceClamp:
    """A verdict reached without genuine critic approval must not dismiss
    confidently: a not-exploitable result is capped below the threshold and
    routed to human review, while a positive result is unaffected."""

    def test_max_research_dismissal_routes_to_human_review(self):
        decision, _ = aggregate_samples(
            "h", [_strong(False)], stop_reason="max_research"
        )
        assert decision.is_vulnerable is False
        assert decision.confidence < CONFIDENCE_THRESHOLD
        assert decision.suggested_state == SuggestedState.PROPOSED_NOT_EXPLOITABLE

    def test_max_reanalysis_dismissal_routes_to_human_review(self):
        decision, _ = aggregate_samples(
            "h", [_strong(False)], stop_reason="max_reanalysis"
        )
        assert decision.is_vulnerable is False
        assert decision.confidence < CONFIDENCE_THRESHOLD
        assert decision.suggested_state == SuggestedState.PROPOSED_NOT_EXPLOITABLE

    def test_non_convergent_exploitable_is_confirmed(self):
        # Recall-safe: a positive verdict is confirmed regardless of the cap.
        decision, _ = aggregate_samples(
            "h", [_strong(True)], stop_reason="max_research"
        )
        assert decision.is_vulnerable is True
        assert decision.suggested_state == SuggestedState.CONFIRMED

    def test_approved_corroborated_dismissal_is_not_clamped(self):
        # A genuine critic approval over corroborating samples may dismiss
        # confidently. A single approved sample cannot reach aggregation in
        # production (APPROVED always collects a second sample), so the
        # realistic confident-dismissal shape is two agreeing samples.
        decision, _ = aggregate_samples(
            "h", [_strong(False), _strong(False)], stop_reason="approved"
        )
        assert decision.is_vulnerable is False
        assert decision.confidence >= CONFIDENCE_THRESHOLD
        assert decision.suggested_state == SuggestedState.NOT_EXPLOITABLE

    def test_max_research_corroborated_dismissal_is_clamped(self):
        # The clamp is load-bearing for multi-sample dismissals: two agreeing
        # not-exploitable samples blend to a high confidence that would reach
        # NOT_EXPLOITABLE, so a non-convergent stop must cap it for human review.
        decision, _ = aggregate_samples(
            "h", [_strong(False), _strong(False)], stop_reason="max_research"
        )
        assert decision.is_vulnerable is False
        assert decision.confidence == NON_CONVERGENT_CONFIDENCE_CAP
        assert decision.suggested_state == SuggestedState.PROPOSED_NOT_EXPLOITABLE

    def test_non_convergent_justification_flags_review(self):
        decision, _ = aggregate_samples(
            "h", [_strong(False)], stop_reason="max_research"
        )
        assert "max_research" in decision.justification
        assert "review" in decision.justification.lower()

    def test_no_progress_dismissal_flags_evidence_unavailable_for_review(self):
        # An evidence stall (no_progress) is non-convergent, so the dismissal is
        # capped to human review and the reason names the unavailable evidence.
        decision, _ = aggregate_samples(
            "h", [_strong(False)], stop_reason="no_progress"
        )
        assert decision.is_vulnerable is False
        assert decision.suggested_state == SuggestedState.PROPOSED_NOT_EXPLOITABLE
        assert "could not obtain" in decision.justification.lower()
        assert "review" in decision.justification.lower()


class TestConfidenceBreakdownOutput:
    """aggregate_samples returns the decision plus a transparent breakdown."""

    def test_returns_decision_and_breakdown_pair(self):
        decision, breakdown = aggregate_samples("h", [_v(True), _v(True)])
        assert decision.confidence == breakdown.final_confidence

    def test_breakdown_records_blend_inputs(self):
        # Two-thirds agreement, no evidence: raw = W * (2/3), no cap.
        _, breakdown = aggregate_samples("h", [_v(True), _v(True), _v(False)])
        assert breakdown.agreement_rate == round(2 / 3, 4)
        assert breakdown.evidence_strength == 0.0
        assert breakdown.agreement_weight == CONFIDENCE_AGREEMENT_WEIGHT
        assert breakdown.raw_confidence == round(CONFIDENCE_AGREEMENT_WEIGHT * (2 / 3), 4)
        assert breakdown.cap_applied is False
        assert len(breakdown.sample_votes) == 3
        assert breakdown.sample_votes[0].is_vulnerable is True

    def test_breakdown_flags_applied_cap(self):
        _, breakdown = aggregate_samples(
            "h", [_strong(False), _strong(False)], stop_reason="max_research"
        )
        assert breakdown.raw_confidence > breakdown.cap_value
        assert breakdown.cap_applied is True
        assert breakdown.final_confidence == NON_CONVERGENT_CONFIDENCE_CAP

    def test_single_sample_breakdown_has_no_agreement(self):
        _, breakdown = aggregate_samples("h", [_v(True)])
        assert breakdown.agreement_rate is None
        assert len(breakdown.sample_votes) == 1

    def test_empty_samples_returns_trivial_breakdown(self):
        _, breakdown = aggregate_samples("h", [])
        assert breakdown.sample_votes == []
        assert breakdown.final_confidence == 0.0
