"""Tests for the benchmark justification comparison LLM wiring."""

import sys
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmark.justification_check import JustificationAICheck
from config import DEFAULT_JUSTIFICATION_COMPARISON_MODEL


def test_justification_check_builds_client_via_shared_factory():
    """The comparison client is built through build_chat_model, so a Claude
    justification model routes to ChatAnthropicVertex like every other node."""
    with patch("benchmark.justification_check.build_chat_model") as mock_factory:
        mock_factory.return_value = Mock()
        JustificationAICheck(project="proj-x", location="europe-west4")

    args, kwargs = mock_factory.call_args
    assert args[0] == DEFAULT_JUSTIFICATION_COMPARISON_MODEL
    assert kwargs["project"] == "proj-x"
    assert kwargs["location"] == "europe-west4"
