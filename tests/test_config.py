"""Tests for Google GenAI backend resolution."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import DEFAULT_GCP_LOCATION, resolve_genai_backend

_BACKEND_VARS = (
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
    "GOOGLE_API_KEY",
)


@pytest.fixture(autouse=True)
def clear_backend_env(monkeypatch):
    for var in _BACKEND_VARS:
        monkeypatch.delenv(var, raising=False)


class TestResolveGenaiBackend:
    """resolve_genai_backend picks a backend from environment variables."""

    def test_unconfigured_environment_raises(self):
        """No backend variables set fails loudly rather than defaulting."""
        with pytest.raises(RuntimeError):
            resolve_genai_backend()

    def test_api_key_selects_ai_studio(self, monkeypatch):
        """GOOGLE_API_KEY alone selects AI Studio with no project/location."""
        monkeypatch.setenv("GOOGLE_API_KEY", "AIza-test")
        assert resolve_genai_backend() == (False, None, None)

    def test_vertexai_without_project_raises(self, monkeypatch):
        """Vertex mode without GOOGLE_CLOUD_PROJECT fails loudly."""
        monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
        with pytest.raises(RuntimeError):
            resolve_genai_backend()

    def test_vertexai_falls_back_to_default_location(self, monkeypatch):
        """Vertex mode without an explicit location uses the default region."""
        monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
        monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "proj-x")
        assert resolve_genai_backend() == (True, "proj-x", DEFAULT_GCP_LOCATION)

    def test_vertexai_honours_explicit_location(self, monkeypatch):
        """An explicit GOOGLE_CLOUD_LOCATION overrides the default region."""
        monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
        monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "proj-x")
        monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "us-central1")
        assert resolve_genai_backend() == (True, "proj-x", "us-central1")
