"""``demo.py``'s own leak scanner -- the one check a reviewer watches run live.

The demo is the first artefact anyone executes, and its leak scan is deliberately
**independent of the egress gate**: plain containment, no boundary rule. That
independence is the point. If it imported the gate's rule it could only ever agree
with the control it exists to re-check, which is precisely how a real leak sat behind
a green ``100/100`` for three audit loops.

Independence has a cost, though, and this module pins how it is paid. Being stricter
than the gate means the scan sees things the gate deliberately ignores -- above all
the ``Brown``/``Browning`` case, where a *generated fake* surname happens to contain a
real vaulted one. Counting that as a leak made the demo fail on roughly one run in a
few hundred, non-deterministically, because pseudonyms are drawn from a random
per-session key. An intermittent red on the artefact a reviewer runs live is the worst
possible failure mode: it is not a leak, and it looks exactly like one.

So a raw hit is *classified*, and both halves are pinned here -- a value readable as
itself is still fatal, and a value present only inside a longer word is reported and
not counted. The second assertion is the one that would have caught the intermittent
failure; the first is the one that stops the fix from becoming a way to hide a leak.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_demo() -> ModuleType:
    """Import ``demo.py`` by path -- it is a root script, not a package member."""
    spec = importlib.util.spec_from_file_location("_demo_under_test", REPO_ROOT / "demo.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["_demo_under_test"] = module
    spec.loader.exec_module(module)
    return module


demo = _load_demo()


def test_a_value_readable_as_itself_is_a_leak_and_is_fatal() -> None:
    """The property the whole demo exists to demonstrate. Must not soften."""
    result = demo.scan_for_originals(
        "Prepared by accountant Brown, reviewed on Tuesday.", frozenset({"Brown"})
    )
    assert result.leaks == 1, result.detail
    assert result.substring_only == 0, result.detail


def test_a_real_value_inside_a_generated_fake_is_reported_but_is_not_a_leak() -> None:
    """The ``Brown``/``Browning`` case -- the intermittent red this pins shut.

    ``Brown`` is a real vaulted surname; ``Browning`` is a fake the pseudonymizer
    generated. The real value is not readable as itself, the egress gate is right not
    to block, and the demo must agree -- while still *saying* it saw it.
    """
    result = demo.scan_for_originals(
        "Prepared by accountant Alan Browning, reviewed on Tuesday.", frozenset({"Brown"})
    )
    assert result.leaks == 0, result.detail
    assert result.substring_only == 1, result.detail
    assert "not counted as a leak" in result.detail


def test_the_two_are_distinguished_in_one_scan() -> None:
    """A payload carrying both must report exactly one leak, not two and not zero."""
    result = demo.scan_for_originals(
        "Accountant Alan Browning met Vandenberg on Tuesday.",
        frozenset({"Brown", "Vandenberg"}),
    )
    assert result.leaks == 1, result.detail
    assert result.substring_only == 1, result.detail


@pytest.mark.parametrize(
    ("haystack", "expected_leaks"),
    [
        ("emphasis _Brown_ here", 1),  # underscore is a boundary, not a word char
        ("tel(415) 555-0123 now", 1),  # punctuation-edged value, per-side guards
        ("a Brownstone facade", 0),  # inside a longer word
        ("nothing relevant here", 0),
    ],
)
def test_classification_matches_the_shared_boundary_rule(
    haystack: str, expected_leaks: int
) -> None:
    """The grading uses the one shared rule, so these follow it rather than a local one."""
    originals = frozenset({"Brown", "(415) 555-0123"})
    assert demo.scan_for_originals(haystack, originals).leaks == expected_leaks


def test_short_values_are_skipped_and_the_exclusion_is_visible() -> None:
    """A sub-floor value is excluded -- and the count is printed, not hidden."""
    result = demo.scan_for_originals("Dr Li saw the patient.", frozenset({"Li"}))
    assert result.skipped_short == 1
    assert result.scanned == 0
    assert "skipped" in result.detail
