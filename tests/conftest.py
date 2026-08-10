"""Shared test fixtures, and the two mechanisms that keep the suite hermetic.

A master key is injected into the environment at import time (before any module
constructs ``Settings``) so the suite runs with no secrets of its own. Every test
runs on ``MockProvider`` -- no API key, no network.

**The developer's real key is kept out of the run by two locks, not one.** The
first is the ``os.environ.pop`` below, which has been here from the start. The
second is new, and it exists because the first one was measurably not enough:
``Settings.model_config`` carries ``env_file=".env"``, so pydantic-settings reads
``ANTHROPIC_API_KEY`` **off disk** whatever the environment says. Measured on this
tree with a live key in ``.env``, after the pop and inside the suite's own import
sequence::

    env has ANTHROPIC_API_KEY: False
    Settings.anthropic_api_key is None: False
    Settings.anthropic_api_key length: 108

So the docstring this file used to carry -- "the suite runs with no ``.env`` file
and no secrets on disk" -- described a machine without a ``.env``, and silently
stopped being true the moment one appeared. Any test that built
``Settings(llm_provider="anthropic")`` and reached the provider would have spent a
real key. :data:`_ENV_FILE_DISABLED` closes that: the dotenv source is switched off
for the whole test process, so the *only* way a key can enter a test run is the
environment, which is the thing the pop controls.

**Opting in deliberately: ``--real-llm``.** ``tests/test_llm.py::test_real_llm_smoke``
is marked ``real_llm`` and guarded by ``skipif(not os.getenv("ANTHROPIC_API_KEY"))``,
a condition evaluated when that module is *imported* -- which happens during
collection, long after the pop above. The test was therefore structurally
unreachable: exporting a key and running ``pytest -m real_llm`` still printed
``SKIPPED [1] ... ANTHROPIC_API_KEY not set``. The marker's own description in
``pyproject.toml`` said "requires ANTHROPIC_API_KEY and network; skipped by
default", which reads as "runs when the key is set". It could not.

Deleting the pop would have made it reachable and made every other test able to
spend the key, so the flag makes reachability explicit instead:

* **no flag** -- the key never enters the environment, the marked test is skipped
  with a reason naming the flag, and nothing in the process can reach the API.
* **``--real-llm``, no ``ANTHROPIC_API_KEY`` exported** -- a *placeholder* is put in
  the environment so the module-level ``skipif`` does not fire on a condition this
  conftest itself created; the run then skips on the honest reason, that no key was
  supplied. (The key is read from the environment only, never from ``.env``: a
  secret that merely sits on disk should not become spendable because someone typed
  a flag.)
* **``--real-llm`` with a key** -- the real value is placed in the environment for
  the duration of the marked test and taken out again afterwards. It is never
  present during collection, and :func:`_hermetic_anthropic_key` asserts its absence
  around **every** other test in the suite, so the opt-in cannot widen past the one
  test that asked for it.
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

from secure_context_pipeline.config import Settings, get_settings
from secure_context_pipeline.detection.registry import (
    EntityRegistry,
    load_registry,
)

# Everything below runs at conftest import time, which is before pytest imports a
# single test module -- and a test module is the first thing in this process that
# constructs ``Settings``. Importing ``config`` does not: ``get_settings`` is
# lru_cached and nothing at that module's top level instantiates the class. So the
# two locks are in place before anything can read a key, and the imports above stay
# where ``E402`` wants them.

#: Lock 2. ``Settings`` reads ``.env`` by default; see this module's docstring for
#: the measurement showing a 108-character live key arriving through it with the
#: environment clean. Switched off for the whole test process. ``tests/test_llm.py``
#: already passes ``_env_file=None`` by hand in one helper -- this is that same
#: correction applied everywhere instead of one call site at a time.
Settings.model_config["env_file"] = None
_ENV_FILE_DISABLED = Settings.model_config["env_file"] is None

#: Lock 1. Never let a developer's real key leak into a test run. Captured rather
#: than discarded, so ``--real-llm`` has something to hand back; module-private and
#: never logged, printed or written into a fixture.
_CAPTURED_ANTHROPIC_KEY: str | None = os.environ.pop("ANTHROPIC_API_KEY", None)

#: The value the environment carries under ``--real-llm`` while the real key is not
#: in play. Its only job is to satisfy ``test_llm.py``'s import-time ``skipif``; it
#: is not a credential and any request made with it fails authentication.
_OPT_IN_PLACEHOLDER = "scp-real-llm-opt-in-placeholder-not-a-key"

#: The pytest option that makes the ``real_llm`` marker reachable at all.
REAL_LLM_FLAG = "--real-llm"

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "entities.yaml"


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the ``real_llm`` opt-in.

    Deliberately a flag and not an environment variable: an environment variable
    is the thing that gets exported once and inherited by every later run in the
    same shell, which is how a "safe by default" suite stops being one.
    """
    parser.addoption(
        REAL_LLM_FLAG,
        action="store_true",
        default=False,
        help=(
            "Run tests marked `real_llm`, which make real Anthropic API calls and "
            "spend a real key. The key is read from the ANTHROPIC_API_KEY "
            "environment variable only -- never from .env -- and is exposed to the "
            "marked tests alone. Without this flag those tests are skipped and the "
            "key is not present in the process at all."
        ),
    )


def _real_llm_requested(config: pytest.Config) -> bool:
    return bool(config.getoption("real_llm"))


def pytest_configure(config: pytest.Config) -> None:
    """Make the ``real_llm`` marker reachable, without exposing the key yet.

    ``test_llm.py``'s ``skipif`` is evaluated at import time, so the environment
    has to look right *before collection*. What goes in here is the placeholder,
    not the credential: the real value is swapped in per-test by
    :func:`_hermetic_anthropic_key`, so no import-time code in any test module ever
    sees it.
    """
    if _real_llm_requested(config) and _CAPTURED_ANTHROPIC_KEY is not None:
        os.environ["ANTHROPIC_API_KEY"] = _OPT_IN_PLACEHOLDER


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Skip ``real_llm`` tests without the flag, with a reason that names the flag.

    Prepended rather than appended: pytest evaluates every ``skipif`` before any
    ``skip``, and within a node in ``own_markers`` order, so a mark added at the
    front is the one whose reason a reviewer sees. Without this the default run
    reports "ANTHROPIC_API_KEY not set", which is true only because this file just
    unset it -- a reason that sends the reader off to export a key that will be
    popped again.
    """
    # Collection has finished, so this is the one place the *import-time* half of
    # the lock is observable. Sabotage says it needs to be: turning the pop above
    # into a `get` leaves every test green, because :func:`_hermetic_anthropic_key`
    # re-pops per test -- and a key present during collection is already spendable
    # by any module that builds `Settings` at import time, which this conftest's
    # own docstring says is why the pop happens at import.
    # Raised as a UsageError rather than asserted: this is a fact about the process
    # the whole session runs in, not about any one test, so it should stop the run
    # with one legible line instead of failing 2,900 times or landing as an
    # INTERNALERROR traceback.
    live = os.environ.get("ANTHROPIC_API_KEY")
    if live not in (None, _OPT_IN_PLACEHOLDER):
        raise pytest.UsageError(
            "a real ANTHROPIC_API_KEY was in the environment throughout collection. "
            "Test modules construct Settings at import time, so the key has to be "
            "removed before pytest imports anything -- see _CAPTURED_ANTHROPIC_KEY"
        )

    if _real_llm_requested(config):
        return
    if live is not None:
        raise pytest.UsageError(
            f"{REAL_LLM_FLAG} was not passed, so nothing in this process should be "
            "able to reach the Anthropic API, yet ANTHROPIC_API_KEY is set"
        )
    reason = (
        f"real_llm: not requested. Pass {REAL_LLM_FLAG} and export ANTHROPIC_API_KEY "
        "to run it; it spends a real key and makes a real network call."
    )
    for item in items:
        if item.get_closest_marker("real_llm") is not None:
            item.add_marker(pytest.mark.skipif(True, reason=reason), append=False)


@pytest.fixture(autouse=True)
def _hermetic_anthropic_key(request: pytest.FixtureRequest) -> Iterator[None]:
    """The per-test half of the lock, and the thing that makes it checkable.

    Every test in the suite runs inside this fixture, so the assertion below is a
    standing witness rather than one test's claim: if a later edit drops the pop,
    re-enables the dotenv source, or widens the opt-in, ~2,900 tests error at once
    instead of one guard going quietly vacuous.
    """
    opted_in = _real_llm_requested(request.config)
    wants_real_key = (
        opted_in
        and request.node.get_closest_marker("real_llm") is not None
        and _CAPTURED_ANTHROPIC_KEY is not None
    )
    before = os.environ.pop("ANTHROPIC_API_KEY", None)
    if wants_real_key:
        os.environ["ANTHROPIC_API_KEY"] = _CAPTURED_ANTHROPIC_KEY or ""
    else:
        assert "ANTHROPIC_API_KEY" not in os.environ, (
            "a real Anthropic key is visible to this test. The suite is supposed to "
            "be incapable of spending one outside a --real-llm run"
        )
        assert _ENV_FILE_DISABLED, (
            "Settings still reads .env, so a key on disk reaches this test whatever "
            "the environment says; see this conftest's docstring for the measurement"
        )
    try:
        yield
    finally:
        os.environ.pop("ANTHROPIC_API_KEY", None)
        if before is not None:
            os.environ["ANTHROPIC_API_KEY"] = before


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
