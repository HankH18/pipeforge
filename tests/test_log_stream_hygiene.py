"""What the two shipped entrypoints are allowed to write to their log streams.

Two defects, one shape: an artifact a reviewer runs directly -- the container and
``python demo.py`` -- putting something in a log stream that does not belong there.
The container's was a disclosure (a credential pair); the demo's was presentational
(an unlabelled record inside the framed output). They are pinned together because
the property is the same one and neither entrypoint had any test over its log
stream at all.

Part 1: the shipped container must not print a credential pair to its log stream.

``SessionRegistry._handle`` (``vault/session_registry.py:103``) logs a truncated
SHA-256 instead of a session ID, and its docstring says why in full: a session ID
is a *credential*, because ``DELETE /sessions/{id}?user_id=...`` needs only the
pair and that deletion is cryptographic erasure -- irreversible, no undo, no
recovery path. The mask exists so that pair never lands in the application's log
stream "where it reaches whatever ships logs off the host".

uvicorn's access logger put it straight back. It writes the request line verbatim,
path *and* query string, to stdout. Measured against the shipped command with the
flag removed::

    INFO: 127.0.0.1:61853 - "DELETE /sessions/fdc6fb4d29e64c32b6af05cc1de9ae46
                             ?user_id=alice HTTP/1.1" 204        (wrapped for width)
    INFO: 127.0.0.1:61854 - "GET /documents/doc-abc123?user_id=alice HTTP/1.1" 404

Two credential pairs, one line each, one line away from the mask that exists to
prevent exactly this. ``docker-compose.yml`` pipes that stdout into the container
log, so the mask was defeated in the artifact a reviewer actually runs.

Why this file is a static audit of the Dockerfile rather than a live server test:
the defect is not in any Python the suite can import. The API behaves correctly --
it is the *process invocation* that discloses, so the invocation is the thing worth
pinning. A live test would also have to boot spaCy's ``en_core_web_lg`` (~25 s here)
to assert a property that is decided entirely by one string in the CMD.

The second test is the one that keeps the first honest. Pinning the Dockerfile CMD
proves nothing if compose overrides it, because compose is how the container is
actually started -- so the premise "the CMD is what runs" is checked rather than
assumed.

Part 2: ``python demo.py`` must not leak an unlabelled record into its own frame.
demo.py configured no logging handler, so the package's records fell through to
``logging.lastResort``, which prints the bare message to stderr with no level and
no logger name. One fires on an ordinary run -- ``EGRESS BLOCKED -- provider call
suppressed`` from section 6c -- and on a tty it landed between the fail-closed
premise and its first ``[PASS]`` row, inside the 80-column frame that is the first
thing a reviewer reads. The records are now buffered and replayed after the frame
closes, which keeps the frame intact without discarding warnings.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path

import pytest

import demo

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"
COMPOSE = REPO_ROOT / "docker-compose.yml"

#: The record that actually fires on an ordinary demo run, quoted from
#: ``egress_gate.py:1162`` so these tests exercise the real string.
EGRESS_WARNING = "EGRESS BLOCKED -- provider call suppressed"


def _shipped_cmd() -> list[str]:
    """The Dockerfile's final ``CMD`` as an argv list.

    The CMD is exec-form JSON split over continuation lines, so the backslash-newline
    pairs are folded before parsing. Parsing rather than substring-matching matters:
    ``"--no-access-log"`` appearing anywhere in the file -- in the block comment that
    explains it, for instance -- must not be mistaken for it being in the argv.
    """
    text = DOCKERFILE.read_text(encoding="utf-8")
    folded = re.sub(r"\\\n\s*", " ", text)
    cmds = [
        line[len("CMD") :].strip()
        for line in folded.splitlines()
        if line.startswith("CMD")
    ]
    assert cmds, "the Dockerfile must declare a CMD"
    argv = json.loads(cmds[-1])
    assert isinstance(argv, list)
    return [str(part) for part in argv]


def test_the_shipped_uvicorn_command_disables_the_access_log() -> None:
    """``--no-access-log`` is in the argv, and it is uvicorn that is being run.

    Both halves are asserted because the flag is only a control if it reaches
    uvicorn: the same string in a CMD that ran something else would be inert.
    """
    argv = _shipped_cmd()
    assert argv[0] == "uvicorn", f"expected the CMD to run uvicorn, got {argv[0]!r}"
    assert "--no-access-log" in argv, (
        "the shipped CMD must pass --no-access-log: without it uvicorn writes "
        "'DELETE /sessions/<id>?user_id=<user>' verbatim to the container log, "
        "which is both halves of an irreversible-erasure credential pair and the "
        f"exact disclosure SessionRegistry._handle exists to prevent -- got {argv}"
    )


def test_compose_does_not_override_the_command_and_drop_the_flag() -> None:
    """Compose must not replace the CMD, or the flag above is decoration.

    ``docker-compose.yml`` is how the container is started (it is the command in the
    README's quickstart), and a ``command:`` key there replaces the image's CMD
    outright rather than appending to it. If one is ever added, it has to carry the
    flag too -- so this fails on a bare override and passes on one that keeps it.

    Deliberately a line-level check and not a YAML parse: the assertion is about the
    top-level service key, and a parse would need PyYAML plus a schema walk to say
    the same thing. ``command:`` nested inside the healthcheck block would be indented
    past column 4, so anchoring on the service's own indent is what makes this exact.
    """
    lines = COMPOSE.read_text(encoding="utf-8").splitlines()
    overrides = [
        line
        for line in lines
        if re.match(r"^\s{4}(command|entrypoint):", line) and not line.lstrip().startswith("#")
    ]
    for line in overrides:
        assert "--no-access-log" in line, (
            "docker-compose.yml overrides the image CMD without --no-access-log, "
            "which re-enables uvicorn's access log and puts session_id+user_id back "
            f"in the container log: {line!r}"
        )


# ---------------------------------------------------------------------------
# Part 2 -- python demo.py
# ---------------------------------------------------------------------------
@pytest.fixture
def _demo_run(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Replace ``run_demo`` with a stub that emits the real egress warning.

    The pipeline itself is not what is under test here -- the demo's *logging
    configuration* is -- and a real run costs a spaCy load. The stub logs through
    the same logger the gate uses, so the record travels the identical path.

    It records, while it is running, whether a handler is attached to the package
    logger. That boolean is the actual mechanism: ``logging.lastResort`` fires only
    when a record finds zero handlers, so "a handler was attached at emit time" is
    precisely what stops the bare line, and it has to be observed mid-run because
    ``main`` detaches the handler on the way out.
    """
    handled_during_run: list[bool] = []

    async def fake_run_demo(args: argparse.Namespace) -> int:
        logger = logging.getLogger("secure_context_pipeline.pipeline.egress_gate")
        handled_during_run.append(bool(logging.getLogger("secure_context_pipeline").handlers))
        logger.warning(EGRESS_WARNING)
        print("  [PASS] EGRESS GATE BLOCKS a payload that still carries an original")
        return 0

    monkeypatch.setattr(demo, "run_demo", fake_run_demo)
    return handled_during_run


def test_demo_does_not_drop_a_package_warning_into_the_frame(
    _demo_run: list[bool], capsys: pytest.CaptureFixture[str]
) -> None:
    """The warning is labelled, on stderr, and after the frame -- not bare, not inside it.

    Four assertions, because the defect had two halves and the fix must not trade one
    for the other: the record must still be *visible* (not silenced), and it must no
    longer be *bare* or *interleaved*.
    """
    assert demo.main([]) == 0
    captured = capsys.readouterr()

    assert _demo_run == [True], (
        "main() must attach a handler to the secure_context_pipeline logger before "
        "running: without one, logging.lastResort prints the bare message to stderr "
        "mid-frame, which is the defect"
    )
    # Visible: silencing the record would also make the frame clean, and would be wrong.
    assert EGRESS_WARNING in captured.err, "the warning must not be discarded"
    # Labelled: lastResort prints the message with no level and no logger name.
    assert "WARNING secure_context_pipeline.pipeline.egress_gate: " + EGRESS_WARNING in (
        captured.err
    ), f"the replayed record must carry level and logger name -- got {captured.err!r}"
    # Not interleaved: the frame is stdout, and the record must stay off it.
    assert EGRESS_WARNING not in captured.out, (
        "the package warning must not appear on stdout, which is where the "
        "80-column frame is printed"
    )


def test_demo_prints_no_log_section_when_the_package_says_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A quiet run stays quiet -- the replay adds no section when there is nothing to replay.

    Guards the obvious over-correction: a fix that always prints a "package log"
    header would put a new empty block on every clean run, which is the same
    presentational defect wearing a label.
    """

    async def silent_run_demo(args: argparse.Namespace) -> int:
        return 0

    monkeypatch.setattr(demo, "run_demo", silent_run_demo)
    assert demo.main([]) == 0
    assert capsys.readouterr().err == ""


def test_demo_replays_the_warning_even_when_the_run_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The failure path is the one where a buffered warning matters most.

    ``main`` replays in a ``finally``. If the replay sat on the success path only, a
    ConfigError would swallow every record the package emitted on the way down --
    exactly the run where the reviewer needs them.
    """
    from secure_context_pipeline.errors import ConfigError

    async def failing_run_demo(args: argparse.Namespace) -> int:
        logging.getLogger("secure_context_pipeline.pipeline.egress_gate").warning(
            EGRESS_WARNING
        )
        raise ConfigError(setting="SCP_MASTER_KEY", problem="not set")

    monkeypatch.setattr(demo, "run_demo", failing_run_demo)
    assert demo.main([]) == demo.EXIT_USAGE
    assert EGRESS_WARNING in capsys.readouterr().err


def test_demo_leaves_the_package_logger_as_it_found_it() -> None:
    """No handler is left behind after ``main`` returns.

    demo.py is imported by the test suite, and a handler that outlived one call
    would accumulate across calls and quietly capture other tests' records.
    """
    logger = logging.getLogger("secure_context_pipeline")
    before = list(logger.handlers)
    assert not any(isinstance(h, demo._LogCapture) for h in before), (
        "a previous demo.main() call leaked its capture handler onto the package logger"
    )
