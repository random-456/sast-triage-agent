"""Self-consistency aggregation: turn N analyst samples into one decision.

Pure functions, no graph or LLM dependency. The final confidence is the
agreement rate across samples (weighted with an evidence-strength term), not
any single model's self-report: a calibrated number rather than the clustered
90/95/100 that verbalized confidence tends to produce.
"""

from collections import Counter
from typing import List, Optional, Tuple

from config import CONFIDENCE_AGREEMENT_WEIGHT, CONFIDENCE_THRESHOLD, NON_CONVERGENT_CONFIDENCE_CAP
from sast_triage.agent_models import (
    AnalystVerdict,
    ConfidenceBreakdown,
    SampleVote,
    SuggestedState,
    TriageDecision,
    derive_state,
)

# Reason: saturating point for the evidence-strength heuristic. Placeholder,
# calibrate against the gold-set alongside CONFIDENCE_THRESHOLD.
_EVIDENCE_SATURATION = 5

# Reason: self-consistency agreement is only meaningful with corroboration. A
# lone sample's agreement_rate is trivially 1.0 (top_count == len == 1), so
# confidence must not credit agreement until a second sample backs the verdict;
# below this the confidence rests on evidence strength alone and the agreement
# diagnostic is reported as undefined. Structural, not a calibration knob.
_MIN_CORROBORATING_SAMPLES = 2


def tally(votes: List[Optional[bool]]) -> Tuple[Optional[bool], float, bool]:
    """Return (plurality value, agreement rate, whether it is a true majority)."""
    counter = Counter(votes)
    top_value, top_count = counter.most_common(1)[0]
    agreement_rate = top_count / len(votes)
    has_majority = top_count > len(votes) / 2
    return top_value, agreement_rate, has_majority


def has_majority(samples: List[AnalystVerdict]) -> bool:
    """Whether the samples' verdicts have a strict majority on is_vulnerable."""
    if not samples:
        return False
    return tally([s.is_vulnerable for s in samples])[2]


def compute_evidence_strength(samples: List[AnalystVerdict]) -> float:
    """A 0..1 proxy for how well grounded the samples are.

    Combines the breadth of files consulted with the average number of
    citations per sample. The saturation constant is a placeholder.
    """
    if not samples:
        return 0.0
    files = set()
    total_citations = 0
    for sample in samples:
        files.update(sample.evidence_refs)
        total_citations += len(sample.citation_lines)
    avg_citations = total_citations / len(samples)
    files_score = min(len(files), _EVIDENCE_SATURATION) / _EVIDENCE_SATURATION
    cite_score = min(avg_citations, _EVIDENCE_SATURATION) / _EVIDENCE_SATURATION
    return 0.5 * files_score + 0.5 * cite_score


def _build_justification(
    samples: List[AnalystVerdict],
    is_vulnerable: Optional[bool],
    agreement_rate: float,
    stop_reason: Optional[str],
) -> str:
    n = len(samples)
    pct = round(agreement_rate * 100)
    if is_vulnerable is None:
        base = (
            f"Self-consistency over {n} samples reached no majority verdict "
            f"({pct}% top agreement); routed for manual review."
        )
    elif n < _MIN_CORROBORATING_SAMPLES:
        base = (
            "A single analyst sample (no self-consistency corroboration) "
            f"classified is_vulnerable={is_vulnerable}. {samples[0].reasoning}"
        )
    else:
        representative = next(
            (s.reasoning for s in samples if s.is_vulnerable == is_vulnerable),
            samples[0].reasoning,
        )
        base = (
            f"Self-consistency over {n} samples: {pct}% agreed "
            f"is_vulnerable={is_vulnerable}. {representative}"
        )
    if stop_reason in ("max_research", "max_reanalysis"):
        base += (
            f" The analysis stopped without critic approval ({stop_reason}); "
            "this verdict is unconfirmed and needs human review."
        )
    elif stop_reason == "no_progress":
        base += (
            " Research could not obtain the information the reviewer requested "
            "within the cloned scope; this verdict is unconfirmed and needs "
            "human review."
        )
    return base


def _earned_confidence(
    confidence: float,
    is_vulnerable: Optional[bool],
    stop_reason: Optional[str],
) -> float:
    """Cap a dismissal that stopped without genuine critic approval.

    A not-exploitable verdict reached on a circuit breaker has not earned a
    confident dismissal: it is often a lone unvalidated sample whose
    agreement_rate is trivially 1.0. Capping it below CONFIDENCE_THRESHOLD
    routes it to PROPOSED_NOT_EXPLOITABLE for human review instead of silently
    marking NOT_EXPLOITABLE. Positive verdicts are untouched (derive_state
    confirms them regardless of confidence), so CONFIRMED recall is unaffected.
    """
    if is_vulnerable is False and stop_reason != "approved":
        return min(confidence, NON_CONVERGENT_CONFIDENCE_CAP)
    return confidence


def _sample_votes(samples: List[AnalystVerdict]) -> List[SampleVote]:
    """Summarize each surviving sample for the confidence breakdown."""
    return [
        SampleVote(
            is_vulnerable=s.is_vulnerable,
            self_confidence=s.confidence,
            temperature=s.sample_temperature,
            n_citations=len(s.citation_lines),
            n_evidence_refs=len(s.evidence_refs),
        )
        for s in samples
    ]


def aggregate_samples(
    result_hash: str,
    samples: List[AnalystVerdict],
    stop_reason: Optional[str] = None,
) -> Tuple[TriageDecision, ConfidenceBreakdown]:
    """Combine analyst samples into the final decision and its breakdown."""
    if not samples:
        decision = TriageDecision(
            resultHash=result_hash,
            is_vulnerable=None,
            confidence=0.0,
            suggested_state=SuggestedState.REFUSED,
            justification=(
                "No analyst samples were produced; manual review required."
            ),
            agreement_rate=None,
            sample_count=0,
        )
        breakdown = ConfidenceBreakdown(
            agreement_rate=None,
            evidence_strength=0.0,
            agreement_weight=CONFIDENCE_AGREEMENT_WEIGHT,
            raw_confidence=0.0,
            cap_applied=False,
            cap_value=NON_CONVERGENT_CONFIDENCE_CAP,
            final_confidence=0.0,
            threshold=CONFIDENCE_THRESHOLD,
            sample_votes=[],
        )
        return decision, breakdown

    votes = [s.is_vulnerable for s in samples]
    majority, agreement_rate, is_clear = tally(votes)
    evidence_strength = compute_evidence_strength(samples)
    corroborated = len(samples) >= _MIN_CORROBORATING_SAMPLES

    if is_clear:
        is_vulnerable: Optional[bool] = majority
        if corroborated:
            raw_confidence = (
                CONFIDENCE_AGREEMENT_WEIGHT * agreement_rate
                + (1 - CONFIDENCE_AGREEMENT_WEIGHT) * evidence_strength
            )
        else:
            # A single sample is not self-consistency: there is no agreement
            # signal, so confidence rests on evidence strength alone.
            raw_confidence = (1 - CONFIDENCE_AGREEMENT_WEIGHT) * evidence_strength
    else:
        # A split is never a confident dismissal: route to human attention.
        is_vulnerable = None
        raw_confidence = 0.0

    confidence = _earned_confidence(raw_confidence, is_vulnerable, stop_reason)
    reported_agreement = round(agreement_rate, 4) if corroborated else None

    decision = TriageDecision(
        resultHash=result_hash,
        is_vulnerable=is_vulnerable,
        confidence=round(confidence, 4),
        suggested_state=derive_state(is_vulnerable, confidence),
        justification=_build_justification(
            samples, is_vulnerable, agreement_rate, stop_reason
        ),
        agreement_rate=reported_agreement,
        sample_count=len(samples),
    )
    breakdown = ConfidenceBreakdown(
        agreement_rate=reported_agreement,
        evidence_strength=round(evidence_strength, 4),
        agreement_weight=CONFIDENCE_AGREEMENT_WEIGHT,
        raw_confidence=round(raw_confidence, 4),
        cap_applied=confidence < raw_confidence,
        cap_value=NON_CONVERGENT_CONFIDENCE_CAP,
        final_confidence=round(confidence, 4),
        threshold=CONFIDENCE_THRESHOLD,
        sample_votes=_sample_votes(samples),
    )
    return decision, breakdown
