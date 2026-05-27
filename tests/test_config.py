"""Tests for Vertex AI configuration resolution."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import DEFAULT_GCP_LOCATION, resolve_vertex_config

_VERTEX_VARS = (
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
)


@pytest.fixture(autouse=True)
def clear_vertex_env(monkeypatch):
    for var in _VERTEX_VARS:
        monkeypatch.delenv(var, raising=False)


class TestResolveVertexConfig:
    """resolve_vertex_config reads the Vertex AI project and location."""

    def test_missing_project_raises(self):
        """No GOOGLE_CLOUD_PROJECT fails loudly rather than defaulting."""
        with pytest.raises(RuntimeError):
            resolve_vertex_config()

    def test_project_only_uses_default_location(self, monkeypatch):
        """GOOGLE_CLOUD_PROJECT alone falls back to the default region."""
        monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "proj-x")
        assert resolve_vertex_config() == ("proj-x", DEFAULT_GCP_LOCATION)

    def test_explicit_location_overrides_default(self, monkeypatch):
        """GOOGLE_CLOUD_LOCATION overrides DEFAULT_GCP_LOCATION."""
        monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "proj-x")
        monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "us-central1")
        assert resolve_vertex_config() == ("proj-x", "us-central1")
