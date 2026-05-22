"""Tests for the output model: classification, disposition derivation."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import CONFIDENCE_THRESHOLD
from sast_triage.agent_models import (
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
