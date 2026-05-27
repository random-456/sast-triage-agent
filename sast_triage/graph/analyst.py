"""The analyst node: produce one verdict sample from the gathered evidence.

The analyst does not call tools. It reasons over the CODE BANK that research
assembled and commits to an `AnalystVerdict`. Self-consistency runs the node
several times at increasing temperature for sample diversity; a fresh entry
appends a new sample, while a critic-driven refinement (REANALYZE or
NEEDS_MORE_RESEARCH) replaces the in-progress sample so `samples` always holds
the latest verdict per slot for the aggregator to vote over.
"""

import logging
from typing import Awaitable, Callable, Dict, List

from langchain_core.messages import HumanMessage, SystemMessage

from config import ANALYST_TEMPERATURES
from sast_triage.agent_models import AnalystVerdict, CritiqueDecision
from sast_triage.checklists import render_checklist_section
from sast_triage.graph.research import format_code_bank
from sast_triage.graph.state import TriageState
from sast_triage.prompts import ANALYST_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

AnalystNode = Callable[[TriageState], Awaitable[Dict]]
_REFINING = {CritiqueDecision.REANALYZE, CritiqueDecision.NEEDS_MORE_RESEARCH}


def _is_refinement(state: TriageState) -> bool:
    return (
        state.last_critique is not None
        and state.last_critique.decision in _REFINING
        and bool(state.samples)
    )


def _temperature_for(slot_index: int) -> float:
    return ANALYST_TEMPERATURES[min(slot_index, len(ANALYST_TEMPERATURES) - 1)]


def build_analyst_messages(state: TriageState) -> List:
    """System prompt + finding + CWE checklist, then CODE BANK and any feedback.

    The CWE checklist is rendered into the system prompt (matching the research
    and critic nodes) so the analyst sees the same per-CWE evidence
    requirements and effective/ineffective control lists that the prompt
    references in step 4 of the analysis protocol.

    The code bank is sent as a ``HumanMessage`` (evidence presented to the
    model) rather than a ``SystemMessage`` so the request always carries at
    least one non-system turn; Gemini rejects requests whose ``contents``
    array is empty with "contents are required".
    """
    system = (
        f"{ANALYST_SYSTEM_PROMPT}\n\n"
        f"## FINDING\n{state.finding.model_dump_json(indent=2)}\n\n"
        f"{render_checklist_section(state.checklist)}"
    )
    messages = [
        SystemMessage(content=system),
        HumanMessage(content=format_code_bank(state)),
    ]
    critique = state.last_critique
    if critique is not None and critique.decision in _REFINING:
        feedback = critique.reanalysis_feedback or critique.rationale
        if critique.required_information:
            feedback = (
                f"{feedback}\nMissing information that has now been gathered: "
                f"{'; '.join(critique.required_information)}"
            )
        messages.append(
            HumanMessage(
                content=(
                    "A reviewer rejected your previous analysis. Address this "
                    f"and produce a corrected verdict:\n{feedback}"
                )
            )
        )
    return messages


def make_analyst_node(
    analyst_llm_for: Callable[[float], object]
) -> AnalystNode:
    """Build the analyst node.

    Args:
        analyst_llm_for: factory returning a structured LLM for a given
            temperature; its ``ainvoke`` returns an ``AnalystVerdict``.
    """

    async def analyst_node(state: TriageState) -> Dict:
        refining = _is_refinement(state)
        slot_index = (len(state.samples) - 1) if refining else len(state.samples)
        temperature = _temperature_for(slot_index)

        llm = analyst_llm_for(temperature)
        verdict: AnalystVerdict = await llm.ainvoke(build_analyst_messages(state))
        verdict.sample_temperature = temperature

        samples = list(state.samples)
        reanalysis_count = state.reanalysis_count
        if refining:
            samples[-1] = verdict
            if state.last_critique.decision == CritiqueDecision.REANALYZE:
                reanalysis_count += 1
        else:
            samples.append(verdict)

        return {
            "samples": samples,
            "current_sample_idx": slot_index,
            "reanalysis_count": reanalysis_count,
        }

    return analyst_node
