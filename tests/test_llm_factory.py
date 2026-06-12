"""Tests for the shared LLM factory: provider routing and per-node resolution."""

import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.llm_factory import (
    ModelSelection,
    NodeLLMConfig,
    TriageLLMConfig,
    build_chat_model,
    build_triage_llm_config,
)


class TestBuildChatModel:
    """build_chat_model routes by model name: Claude on Vertex vs Gemini."""

    def test_gemini_name_builds_vertex_client(self):
        with patch("utils.llm_factory.ChatVertexAI") as mock_vertex, patch(
            "utils.llm_factory.ChatAnthropicVertex"
        ) as mock_anthropic:
            mock_vertex.return_value = Mock()
            result = build_chat_model(
                "gemini-2.5-pro",
                project="proj-x",
                location="europe-west4",
                temperature=0.3,
            )

        mock_anthropic.assert_not_called()
        _, kwargs = mock_vertex.call_args
        assert kwargs["model_name"] == "gemini-2.5-pro"
        assert kwargs["project"] == "proj-x"
        assert kwargs["location"] == "europe-west4"
        assert kwargs["temperature"] == 0.3
        assert result is mock_vertex.return_value

    def test_claude_name_builds_anthropic_vertex_client(self):
        with patch("utils.llm_factory.ChatVertexAI") as mock_vertex, patch(
            "utils.llm_factory.ChatAnthropicVertex"
        ) as mock_anthropic:
            mock_anthropic.return_value = Mock()
            result = build_chat_model(
                "claude-sonnet-4@20250514",
                project="proj-x",
                location="us-east5",
                temperature=0.6,
            )

        mock_vertex.assert_not_called()
        _, kwargs = mock_anthropic.call_args
        assert kwargs["model_name"] == "claude-sonnet-4@20250514"
        assert kwargs["project"] == "proj-x"
        assert kwargs["location"] == "us-east5"
        assert kwargs["temperature"] == 0.6
        assert result is mock_anthropic.return_value

    def test_claude_routing_is_case_insensitive(self):
        with patch("utils.llm_factory.ChatVertexAI") as mock_vertex, patch(
            "utils.llm_factory.ChatAnthropicVertex"
        ) as mock_anthropic:
            build_chat_model(
                "Claude-3-7-Sonnet",
                project="p",
                location="us-east5",
                temperature=0.1,
            )

        mock_vertex.assert_not_called()
        mock_anthropic.assert_called_once()


class TestBuildTriageLLMConfig:
    """Per-node resolution precedence for model and location."""

    _DEFAULTS = dict(
        global_location="europe-west4",
        research_model_default="gemini-2.5-pro",
        analyst_model_default="gemini-2.5-pro",
        critic_model_default="gemini-2.5-pro",
    )

    def test_empty_selection_uses_config_defaults_and_global_location(self):
        config = build_triage_llm_config(ModelSelection(), **self._DEFAULTS)
        assert config == TriageLLMConfig(
            research=NodeLLMConfig(model="gemini-2.5-pro", location="europe-west4"),
            analyst=NodeLLMConfig(model="gemini-2.5-pro", location="europe-west4"),
            critic=NodeLLMConfig(model="gemini-2.5-pro", location="europe-west4"),
        )

    def test_global_model_flag_overrides_all_nodes(self):
        config = build_triage_llm_config(
            ModelSelection(model="gemini-2.5-flash"), **self._DEFAULTS
        )
        assert config.research.model == "gemini-2.5-flash"
        assert config.analyst.model == "gemini-2.5-flash"
        assert config.critic.model == "gemini-2.5-flash"

    def test_per_node_model_flag_beats_global_model_flag(self):
        config = build_triage_llm_config(
            ModelSelection(
                model="gemini-2.5-flash", critic_model="claude-sonnet-4@20250514"
            ),
            **self._DEFAULTS,
        )
        assert config.research.model == "gemini-2.5-flash"
        assert config.analyst.model == "gemini-2.5-flash"
        assert config.critic.model == "claude-sonnet-4@20250514"

    def test_per_node_location_flag_beats_default_and_global(self):
        config = build_triage_llm_config(
            ModelSelection(critic_location="us-east5"),
            **self._DEFAULTS,
        )
        assert config.research.location == "europe-west4"
        assert config.critic.location == "us-east5"

    def test_per_node_location_default_used_when_no_flag(self):
        config = build_triage_llm_config(
            ModelSelection(),
            critic_location_default="us-east5",
            **self._DEFAULTS,
        )
        assert config.analyst.location == "europe-west4"
        assert config.critic.location == "us-east5"
