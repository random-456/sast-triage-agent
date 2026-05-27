"""The research node: stateless evidence gathering for one finding.

The researcher reads code with the investigation tools and accumulates it
into the `EvidenceBundle` (CODE BANK). Each LLM turn is rebuilt fresh from
state: system prompt + code bank + only the last tool round. The model never
replays its full chat history, so the per-turn input stays bounded no matter
how long research runs (avoids context rot on long investigations).
"""

import logging
from typing import Awaitable, Callable, Dict, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from config import MAX_TOOL_CALLS_PER_RESEARCH
from sast_triage.checklists import render_checklist_section
from sast_triage.graph.state import CodeEvidence, ToolCallRecord, TriageState
from sast_triage.prompts import RESEARCH_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

ResearchNode = Callable[[TriageState], Awaitable[Dict]]


def _format_failed_calls(records: List[ToolCallRecord]) -> str:
    if not records:
        return ""
    lines = [
        f"- {r.tool_name}({r.arguments}): {r.error}" for r in records
    ]
    body = "\n".join(lines)
    return (
        "\n\n## DO NOT RETRY\n"
        "These tool calls already failed; do not repeat them with the same "
        f"arguments:\n{body}"
    )


def build_research_system_prompt(state: TriageState) -> str:
    """Build the researcher's system prompt fresh from state."""
    return (
        f"{RESEARCH_SYSTEM_PROMPT}\n\n"
        f"## FINDING\n{state.finding.model_dump_json(indent=2)}\n\n"
        f"{render_checklist_section(state.checklist)}"
        f"{_format_failed_calls(state.failed_tool_calls)}"
    )


def format_code_bank(state: TriageState) -> str:
    """Render the accumulated evidence as the CODE BANK message."""
    if not state.evidence.items:
        return "## CODE BANK\nNo evidence gathered yet."
    blocks = []
    for item in state.evidence.items:
        blocks.append(f"=== {item.file_path} ({item.relevance}) ===\n{item.content}")
    return "## CODE BANK\n" + "\n\n".join(blocks)


def build_research_messages(state: TriageState, last_round: List) -> List:
    """The stateless per-turn message list: system + code bank + last round.

    The code bank is sent as a ``HumanMessage`` rather than a ``SystemMessage``
    because it is evidence presented to the model, not behavioral instructions.
    It also ensures the request always carries at least one non-system turn,
    which Gemini requires: requests whose ``contents`` array is empty are
    rejected with "contents are required".
    """
    return [
        SystemMessage(content=build_research_system_prompt(state)),
        HumanMessage(content=format_code_bank(state)),
        *last_round,
    ]


def _is_error(result: object) -> bool:
    return isinstance(result, dict) and "error" in result


def _evidence_from_result(name: str, args: Dict, result: object) -> CodeEvidence:
    if name == "read_file":
        label = args.get("file_path", "")
    elif name == "search_in_files":
        label = f"search:{args.get('pattern', '')}"
    elif name == "list_directory":
        label = f"dir:{args.get('directory_path', '')}"
    else:
        label = name
    return CodeEvidence(file_path=label or name, content=str(result), relevance=name)


def make_research_node(llm_with_tools, tools: List) -> ResearchNode:
    """Build the research node bound to a tool-enabled LLM.

    Args:
        llm_with_tools: an LLM that has the research tools bound (exposes
            async ``ainvoke``).
        tools: the research tool objects, used to execute the model's calls.
    """
    tools_by_name = {t.name: t for t in tools}

    def _run_tool(call: Dict) -> object:
        tool = tools_by_name.get(call["name"])
        if tool is None:
            return {"error": f"Tool {call['name']} not found"}
        try:
            return tool.invoke(call.get("args", {}))
        except Exception as exc:  # surfaced to the model as a failed call
            return {"error": str(exc)}

    async def research_node(state: TriageState) -> Dict:
        evidence = state.evidence.model_copy(deep=True)
        failed: List[ToolCallRecord] = list(state.failed_tool_calls)
        last_round: List = []

        for _ in range(MAX_TOOL_CALLS_PER_RESEARCH):
            working = state.model_copy(
                update={"evidence": evidence, "failed_tool_calls": failed}
            )
            response = await llm_with_tools.ainvoke(
                build_research_messages(working, last_round)
            )
            tool_calls = getattr(response, "tool_calls", None)
            if not tool_calls:
                break

            round_messages = [response]
            for call in tool_calls:
                result = _run_tool(call)
                if _is_error(result):
                    failed.append(
                        ToolCallRecord(
                            tool_name=call["name"],
                            arguments=call.get("args", {}),
                            error=str(result["error"]),
                        )
                    )
                else:
                    evidence.add(
                        _evidence_from_result(
                            call["name"], call.get("args", {}), result
                        )
                    )
                round_messages.append(
                    ToolMessage(content=str(result), tool_call_id=call["id"])
                )
            last_round = round_messages

        return {
            "evidence": evidence,
            "failed_tool_calls": failed,
            "research_iterations": state.research_iterations + 1,
        }

    return research_node
