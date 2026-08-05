"""Shared test fixtures.

A master key is injected into the environment at import time (before any module
constructs ``Settings``) so the suite runs with no ``.env`` file and no secrets on
disk. Every test runs on ``MockProvider`` -- no API key, no network.
"""

from __future__ import annotations

import base64
import os
import secrets
from collections.abc import Iterator
from pathlib import Path

import pytest

# Must happen at import time: pytest collects modules that may build Settings.
os.environ.setdefault(
    "SCP_MASTER_KEY", base64.b64encode(secrets.token_bytes(32)).decode("ascii")
)
os.environ.setdefault("SCP_LLM_PROVIDER", "mock")
# Never let a developer's real key leak into a test run.
os.environ.pop("ANTHROPIC_API_KEY", None)

from secure_context_pipeline.config import Settings, get_settings
from secure_context_pipeline.detection.registry import (
    EntityRegistry,
    load_registry,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "entities.yaml"


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    """``get_settings`` is lru_cached; keep tests independent of each other."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings pointed at an isolated per-test data directory."""
    return Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path / "data",
        registry_path=REGISTRY_PATH,
        llm_provider="mock",
    )


@pytest.fixture(scope="session")
def registry() -> EntityRegistry:
    """The real shipped registry -- session-scoped, it is immutable."""
    return load_registry(REGISTRY_PATH)


@pytest.fixture
def master_key() -> bytes:
    return secrets.token_bytes(32)
