"""Shared LLM client factory and per-node model/location resolution.

Routes a model name to the right Vertex AI client: Anthropic Claude models go
through ``ChatAnthropicVertex`` (Vertex Model Garden), everything else through
``ChatVertexAI`` (Gemini). Both transports run over gRPC/BoringSSL via
``google-cloud-aiplatform``, so the project's corporate-CA wiring keeps working.

The resolution helpers turn the CLI flags and config defaults into a typed
``TriageLLMConfig`` the agent consumes, so each graph node can run on its own
model and Vertex region.
"""

from dataclasses import dataclass
from typing import Optional

from langchain_google_vertexai import ChatVertexAI
from langchain_google_vertexai.model_garden import ChatAnthropicVertex
from pydantic import BaseModel


class NodeLLMConfig(BaseModel):
    """The resolved model and Vertex region for a single graph node."""

    model: str
    location: str


class TriageLLMConfig(BaseModel):
    """Resolved LLM configuration for the three LLM-using triage nodes."""

    research: NodeLLMConfig
    analyst: NodeLLMConfig
    critic: NodeLLMConfig


@dataclass(frozen=True)
class ModelSelection:
    """Raw model/location overrides as supplied on the CLI.

    ``model`` is the global override applied to every node; the per-node fields
    override just their node. ``None`` means "not supplied".
    """

    model: Optional[str] = None
    research_model: Optional[str] = None
    analyst_model: Optional[str] = None
    critic_model: Optional[str] = None
    research_location: Optional[str] = None
    analyst_location: Optional[str] = None
    critic_location: Optional[str] = None


def build_chat_model(
    model_name: str,
    *,
    project: str,
    location: str,
    temperature: float,
):
    """Build a Vertex AI chat client for ``model_name`` at ``temperature``.

    A model name containing "claude" (case-insensitive) is served by
    ``ChatAnthropicVertex``; any other name by ``ChatVertexAI``.
    """
    if "claude" in model_name.lower():
        return ChatAnthropicVertex(
            model_name=model_name,
            project=project,
            location=location,
            temperature=temperature,
            max_retries=3,
        )
    return ChatVertexAI(
        model_name=model_name,
        project=project,
        location=location,
        temperature=temperature,
        max_retries=3,
    )


def build_triage_llm_config(
    selection: ModelSelection,
    *,
    global_location: str,
    research_model_default: str,
    analyst_model_default: str,
    critic_model_default: str,
    research_location_default: Optional[str] = None,
    analyst_location_default: Optional[str] = None,
    critic_location_default: Optional[str] = None,
) -> TriageLLMConfig:
    """Resolve per-node model and location from CLI selection and defaults.

    Model precedence per node: per-node flag, then global ``--model`` flag, then
    the node's config default. Location precedence per node: per-node flag, then
    the node's config default when set, then the global location.
    """

    def node(
        node_model: Optional[str],
        model_default: str,
        node_location: Optional[str],
        location_default: Optional[str],
    ) -> NodeLLMConfig:
        model = node_model or selection.model or model_default
        location = node_location or location_default or global_location
        return NodeLLMConfig(model=model, location=location)

    return TriageLLMConfig(
        research=node(
            selection.research_model,
            research_model_default,
            selection.research_location,
            research_location_default,
        ),
        analyst=node(
            selection.analyst_model,
            analyst_model_default,
            selection.analyst_location,
            analyst_location_default,
        ),
        critic=node(
            selection.critic_model,
            critic_model_default,
            selection.critic_location,
            critic_location_default,
        ),
    )
