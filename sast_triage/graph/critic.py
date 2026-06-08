"""The critic node: an adversarial review of the analyst's latest verdict.

A separate LLM call with an adversarial prompt and a higher temperature than
the analyst, producing a structured `CritiqueResult`. This replaces the old
`verify_analysis` self-check, which ran on the same model in the same context
and rubber-stamped itself.
"""

import logging
from typing import Awaitable, Callable, Dict, List

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig

from sast_triage.agent_models import AnalystVerdict, CritiqueResult
from sast_triage.checklists import render_checklist_section
from sast_triage.graph.research import format_code_bank
from sast_triage.graph.state import TriageState
from sast_triage.prompts import CRITIC_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

CriticNode = Callable[[TriageState, RunnableConfig], Awaitable[Dict]]


def _render_verdict(verdict: AnalystVerdict) -> str:
    return (
        "## ANALYST VERDICT TO CRITIQUE\n"
        f"is_vulnerable: {verdict.is_vulnerable}\n"
        f"confidence: {verdict.confidence}\n"
        f"reasoning: {verdict.reasoning}\n"
        f"citations: {verdict.citation_lines}"
    )


def build_critic_messages(state: TriageState) -> List:
    """Critic prompt + checklist + CODE BANK + the verdict under review.

    The code bank is sent as a ``HumanMessage`` for consistency with the
    research and analyst nodes; the critic already includes a verdict
    ``HumanMessage`` at the end, so this is purely a typing alignment.
    """
    system = (
        f"{CRITIC_SYSTEM_PROMPT}\n\n{render_checklist_section(state.checklist)}"
    )
    return [
        SystemMessage(content=system),
        HumanMessage(content=format_code_bank(state)),
        HumanMessage(content=_render_verdict(state.samples[-1])),
    ]


def make_critic_node(critic_llm) -> CriticNode:
    """Build the critic node.

    Args:
        critic_llm: a structured LLM whose ``ainvoke`` returns a
            ``CritiqueResult``, configured at the critic temperature.
    """

    async def critic_node(
        state: TriageState, config: RunnableConfig
    ) -> Dict:
        critique: CritiqueResult = await critic_llm.ainvoke(
            build_critic_messages(state), config=config
        )
        return {"last_critique": critique}

    return critic_node
