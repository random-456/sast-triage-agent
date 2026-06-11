"""The aggregate node: collapse the samples into the final decision.

A pure node (no LLM). It records why the subgraph stopped and produces the
advisory TriageDecision via the self-consistency aggregator. It sets the
classification and confidence; derive_state owns the disposition.
"""

import logging
from typing import Dict

from sast_triage.aggregator import aggregate_samples
from sast_triage.graph.routing import compute_stop_reason
from sast_triage.graph.state import TriageState

logger = logging.getLogger(__name__)


async def aggregate_node(state: TriageState) -> Dict:
    stop_reason = compute_stop_reason(state)
    decision, breakdown = aggregate_samples(
        state.finding.resultHash, state.samples, stop_reason
    )
    return {
        "verdict": decision,
        "confidence_breakdown": breakdown,
        "stop_reason": stop_reason,
    }
