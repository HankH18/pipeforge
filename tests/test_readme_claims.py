"""The README's own numbers, re-derived rather than trusted.

The README is the deliverable a reviewer actually reads, and every measured claim
in it rots as the code moves. Four audit loops have now produced the same defect
in it four different ways: a suite count that drifted, a line count re-measured
once and never again, an accounting paragraph whose parts did not sum to its own
total, and a count of leakage boundaries that was three different numbers in
three places. None of those is catchable by reading -- they are all arithmetic
over things that live somewhere else in the tree.

So the numbers get a test, on the same terms the rest of this suite uses:

* Nothing here imports the code under audit to build the expected value. The
  long-line counts are counted line by line rather than taken from ``ruff``; the
  statement totals come from the reporter ``coverage`` builds its own ``Stmts``
  column from; the deviation count comes from the table's rows, not from the
  sentence that counts them.
* And the instrument is validated against a real run rather than spot-checked.
  This is the correction that mattered most: the first version of the statement
  helper was validated on two files, agreed on both, and was over-counting five
  of the package's 52 modules the whole time. It is now checked file by file
  against ``coverage report`` -- 0 mismatches across 52, totals agreeing at
  4,511 when that validation was run and again at **4,778** against the
  ``--cov`` run section 1 pasted at that time (the package has since grown to
  5,014, which is the figure section 1 carries now, and this parenthetical has now
  been re-derived twice for the same reason the number it names exists) -- and the
  exclusion set it depends on has its own tripwire in
  ``test_the_statement_helper_still_reproduces_coverages_own_column``.
* Where two sentences in the README must agree, both are parsed and compared.
  A claim that can only be checked against its own restatement is not checked.

What this file cannot do is run the suite from inside the suite, so the absolute
``N passed`` line in section 1 is not pinned here. What is pinned is that the
number is written down in exactly ONE place, which is what stops the
section-11 checklist from disagreeing with it again.

**On how strict each assertion is, and why the one graded exception went back to
exact.** The first version of this file pinned everything, and turned the whole
suite RED on a two-statement drift in a nineteen-thousand statement total --
0.01%, on a sentence whose claim is a coverage percentage. The response was to
band the one number that moves fastest, the package + tests + fixtures statement
sum, at 0.5%: warn inside the band, fail outside it. The reasoning was sound and
is worth keeping in view -- a number that goes red on every commit trains the next
reader to edit the assertion instead of the prose -- but the conclusion did not
survive being measured against the rest of this file. Every assertion here is now
EXACT, on this argument:

* **The band could not stop the suite going red, because the numbers beside it are
  pinned exactly and move for the same reasons.** Section 1's pasted block contains
  a collected-test count and a package denominator, both EXACT, both moved by any
  commit that adds a test or a line of package code. Replaying the nineteen commits
  that end at ``b82964a`` (``git ls-tree`` + ``git show`` through
  ``coverage.parser``, no checkout) gives, per commit, the movement in package
  statements / three-root statements / lines matching ``def test_`` under
  ``tests/``::

      +0/+0/+0      +1/+36/+6      +0/-1/+0     +2/+13/+1     +0/+12/+2
      +1/+5/+0      +0/+0/+0       +6/+46/+6    +0/+14/+2     +0/+0/+0
      +0/+1463/+155 -3/-6/+0       +18/+35/+2   +1/+83/+4     +17/+561/+41
      +0/+31/+1     +108/+1093/+60 +0/+9/+1     +38/+527/+39

  **Sixteen** of the nineteen moved the banded total at all. **Fifteen** of those
  sixteen also moved the package count or the test count, so on fifteen of them the
  suite was red on an EXACT assertion in this same file whatever the band did. The
  one exception is ``4624411``, a duplicate import deleted, which moved the total by
  **one statement**. So the band bought exactly one green run in nineteen commits,
  and cost an 81-statement blind spot -- which is what it was holding when this was
  re-derived. (An earlier draft of this paragraph said "eighteen of the nineteen",
  which counts every replayed commit as a mover; three of them moved nothing at all
  and four moved no pinned number. Re-derived here rather than carried forward,
  because an argument for exactness that is itself approximate is not one.)
* **A tolerance expressed as a fraction of the thing it guards gets weaker exactly
  as that thing grows.** 0.5% hid 95 statements when it was written and 107 by the
  time it was re-read; nothing in the mechanism ever revisits that. And a band is
  memoryless: it cannot tell "this commit moved the total by 81" from "the
  published number has been 81 wrong for eleven commits", so a per-commit allowance
  used as a standing one is not a band, it is a hole that widens on its own.

So the grades collapse to one rule -- every published number is re-derived and
pinned exactly, and every failure message carries the replacement -- and the way
the suite stays green is the README being correct, which is the property this file
exists to enforce. Nothing was weakened to get there and nothing was deleted; the
one assertion that had been loosened was tightened back, and it keeps the
full-precision correction the banded version reported.

**FACT CHECKS AND SHAPE CHECKS, named.** An audit of this file found several
assertions reading as coverage while being incapable of failing on the defect
their names describe, and the docstrings did not distinguish the two kinds. They
do now, and the register is here so the distinction is visible without reading
thirty docstrings:

*Fact checks* -- the expected value comes from the tree, so the README can be
wrong on its own: the statement totals, the two ``mypy`` file counts, the E501
per-file counts, the fixture sizes, the HTTP surface table, the tier table, the
formatter divergence, the deviation-row count, the ``api/app.py`` line count, the
demo-flows count, the age-error rate, the varied-fixture clause, the Core 6
mangling classes, the section 10 test citations, the two skip figures in the
section 11 checklist, and the two stale-disclosure rigs at the bottom of this
file, which run the tests and query git respectively.

*Shape checks* -- both sides live in the README, so they catch an authoring slip
and nothing else. A shape check cannot notice that the page and the tree have both
moved. These are: the E501 arithmetic, the ``mypy`` error composition, the
whole-repository ``parts + demo == total``, the fixture-block addends, the live
traversal split, the boundary-count agreement, the bottleneck-list cross
references, the next-day plan's hour sum, and the surrogate-tally membership test.
Each says so in its own docstring; none of them is deleted, because an authoring
slip is a real defect and this file has caught four of them.

*Neither, and it matters* -- ``passed + skipped == collected`` in
:func:`test_the_pasted_suite_result_accounts_for_every_test_pytest_collects` binds
the arithmetic and NOT the word "passed"; see its docstring.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import coverage
from coverage.python import PythonFileReporter

from secure_context_pipeline.api.constants import AUDIT_ACCESS_DENIED
from secure_context_pipeline.audit.logger import EVENT_TYPES

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"

#: Number words the README spells out. Kept as a literal map rather than parsed
#: from anywhere, so a rephrase that changes the count goes red.
NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
}

#: ``coverage``'s default exclusion set, as of 7.15, named here rather than
#: rebuilt. This was wrong once and the wrongness was invisible: the constant used
#: to be the ``# pragma: no cover`` regex alone, with a comment asserting that was
#: "the whole exclusion set the reported ``Stmts`` column is computed under". It is
#: not. 7.x also drops ``...`` stub bodies and ``if TYPE_CHECKING:`` blocks by
#: default, which made ``statements()`` over-count every file carrying a Protocol
#: or an abstract method -- 10 statements across 5 of the package's 52 modules, so
#: the "whole-repository total coverage would report" was a number coverage would
#: not report. It went undetected because the two files the helper was validated
#: against (``demo.py``, ``tests/test_crypto.py``) happen to contain neither shape.
#:
#: So the regex is taken from ``coverage``'s own config rather than transcribed,
#: and the transcription is kept only as a tripwire: if an upgrade changes the
#: default set, ``test_the_statement_helper_still_reproduces_coverages_own_column``
#: goes red instead of every statement total quietly moving.
COVERAGE_DEFAULT_EXCLUDE_PATTERNS = (
    r"#\s*(pragma|PRAGMA)[:\s]?\s*(no|NO)\s*(cover|COVER)",
    r"^\s*(((async )?def .*?)?[\])]+(\s*->.*?)?:\s*)?\.\.\.\s*(#|$)",
    r"if (typing\.)?TYPE_CHECKING:",
)

#: The three source roots the README's whole-repository coverage line names, in
#: the order it names them, plus ``demo.py`` which has to be measured separately.
COVERED_ROOTS = ("secure_context_pipeline", "tests", "fixtures")

#: The line-length limit `pyproject.toml` pins and `E501` now enforces.
LINE_LIMIT = 100


#: One configured ``Coverage`` for the whole module. Built once because the
#: exclusion regex is compiled per instance and ``statements()`` is called ~90
#: times; ``_init()`` is what populates the config a reporter reads, and there is
#: no public constructor for "config only, no run".
_COVERAGE = coverage.Coverage(branch=True)
_COVERAGE._init()


def readme_text() -> str:
    return README.read_text(encoding="utf-8")


def flat(text: str) -> str:
    """Whitespace-collapsed view, so a phrase can be matched across a line wrap."""
    return " ".join(text.split())


def one_match(pattern: str, text: str) -> re.Match[str]:
    """Exactly one hit, or fail naming the pattern.

    Anchors that silently stop matching are how a test like this rots into a
    vacuous pass: the sentence gets rewritten, the regex finds nothing, and the
    loop over zero matches asserts nothing. Every anchor here is required to hit
    exactly once.
    """
    hits = re.findall(pattern, text)
    assert len(hits) == 1, f"expected exactly one README match for {pattern!r}, got {len(hits)}"
    match = re.search(pattern, text)
    assert match is not None
    return match


def as_int(raw: str) -> int:
    return int(raw.replace(",", "").replace("*", ""))


def long_lines(path: Path) -> int:
    """Lines over the limit, counted directly rather than asked of ``ruff``.

    ``ruff`` is the thing whose configuration the README paragraph is describing,
    so counting with ``ruff`` would check the paragraph against the tool it is a
    claim about. Deliberately restricted to the two files the README exempts:
    elsewhere ``ruff`` does not flag a line whose only overhang is a trailing
    ``# type: ignore`` pragma, and reproducing that carve-out here would be
    reimplementing ``ruff`` rather than counting.
    """
    return sum(
        1 for line in path.read_text(encoding="utf-8").splitlines() if len(line) > LINE_LIMIT
    )


def python_files(root: Path) -> list[Path]:
    """Every ``.py`` file under ``root``, as the count ``mypy`` prints having checked.

    Counted rather than asked of ``mypy``, for the reason ``long_lines`` is counted
    rather than asked of ``ruff``: the paragraph this feeds is a claim *about*
    ``mypy``, and a cold-cache ``--strict`` pass over the tree is not a cost this
    suite should pay per run. Skips dotted directories (``.venv``, ``.git``),
    ``__pycache__`` and the ``.egg-info`` tree, which is the whole difference
    between a naive walk and what ``mypy`` reports: validated against a real run at
    the commit this was written -- ``52 source files`` for the package and
    ``checked 91 source files`` for the repository, both exact.
    """
    skip = ("__pycache__",)
    return sorted(
        path
        for path in root.rglob("*.py")
        if not any(
            part.startswith(".") or part in skip or part.endswith(".egg-info")
            for part in path.relative_to(root).parts
        )
    )


def statements(path: Path) -> int:
    """Statement count for one file, as ``coverage`` would report it.

    Uses coverage's own reporter rather than its runner: the ``Stmts`` denominator
    is a property of the source, not of a run, so it can be had in milliseconds
    instead of the eight minutes a full ``--cov`` pass over this suite costs.

    ``PythonFileReporter`` is what ``coverage report`` builds its ``Stmts`` column
    from -- it is a ``PythonParser`` under the project's own exclusion regex -- so
    this is the same computation rather than a reimplementation of it. That
    distinction is not pedantry: the earlier version *was* a reimplementation, it
    passed a two-file spot check, and it was over-counting five of the package's
    52 modules. Validated over all 52 against a real ``coverage report`` run: 0
    mismatches, and the totals agreed at 4,511. Re-checked at the total level
    against the ``--cov`` run section 1 now pastes, on a tree 267 statements
    larger: this helper sums the package to **4,778** and ``coverage report``
    prints ``TOTAL 4778``, so the agreement is not an artefact of the tree it was
    first validated on.
    """
    return len(PythonFileReporter(str(path), coverage=_COVERAGE).lines())


# -- the measuring instrument itself ------------------------------------------


def test_the_statement_helper_still_reproduces_coverages_own_column() -> None:
    """The helper every statement total in this file is built on, checked.

    A guard test whose measuring instrument is silently wrong is worse than no
    guard test, because it publishes a wrong number under a green check. That is
    what happened here: ``statements()`` hardcoded ``# pragma: no cover`` as
    coverage's entire default exclusion set, and 7.x also excludes ``...`` stub
    bodies and ``if TYPE_CHECKING:`` blocks. Five of the package's 52 modules
    carry a Protocol or an abstract method, so the helper over-counted the package
    by 10 -- it read 4,499 for a package ``coverage report`` prints 4,511 for, and
    every whole-repository total it derived carried the same kind of surplus.

    Two things are pinned. First, that the repository still configures no
    exclusions of its own -- there is no ``[tool.coverage]`` table and no
    ``.coveragerc``, and adding one silently redefines every number below.
    Second, that the default set is still the three patterns the helper was
    validated against, so an upgrade that adds a fourth is a red test rather than
    a page of totals that all move by a little.
    """
    assert not (REPO_ROOT / ".coveragerc").exists(), (
        "a .coveragerc appeared; every statement total in this file is computed under "
        "coverage's defaults and has to be re-validated against a real report run"
    )
    assert "[tool.coverage" not in (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"), (
        "pyproject.toml now configures coverage; same problem as a .coveragerc"
    )

    assert tuple(_COVERAGE.config.exclude_list) == COVERAGE_DEFAULT_EXCLUDE_PATTERNS, (
        f"coverage's default exclusions are now {_COVERAGE.config.exclude_list}, not the three "
        "this file's statement totals were validated against. Re-run "
        "`pytest -q --cov=secure_context_pipeline --cov-branch` and re-check the totals "
        "against its TOTAL row before updating this tuple"
    )
    assert not _COVERAGE.config.exclude_also, "an exclude_also was configured; see above"


# -- section 1: the suite result, and the one place it is written down --------


def test_the_suite_result_is_pasted_in_exactly_one_place() -> None:
    """Section 11's checklist told a reviewer to expect one red test.

    The suite had none, and section 1 four thousand words earlier said so. The
    two statements were written at different times and neither knew about the
    other, which is what happens whenever a measurement is restated. The fix is
    structural rather than a corrected number: the pass/skip line lives in
    section 1 and nowhere else, and the checklist points at it.
    """
    text = readme_text()
    summaries = re.findall(r"\d+ passed, \d+ skipped", text)
    assert len(summaries) == 1, (
        f"the suite's pass/skip count is restated {len(summaries)} times: {summaries}. "
        "One copy will go stale and contradict the other -- that is exactly the defect "
        "section 11 carried. Keep it in section 1 and cross-reference it."
    )


def test_the_checklist_carves_no_exception_out_of_the_result_section_1_pastes() -> None:
    """The `pytest -q` step of the pre-submission checklist, checked for carve-outs.

    Section 11 is the reproducibility contract -- the one part of the README a
    reviewer runs top to bottom -- and it promised "minus the one stale assertion
    section 1's block names and explains, which is red on this tree" against a
    fully green suite and a section 1 that names no such assertion.

    A test cannot run the suite from inside the suite, so the first half of this is
    a tripwire on the vocabulary a carve-out needs rather than a proof that the
    suite is green; the proof is the reviewer's own run. It bites on the exact
    shape that was wrong: an exception taken out of the result section 1 reports.

    **The vocabulary half is a tripwire and a rephrase walks past it**, which is
    worth saying rather than leaving to be discovered: ``red|stale|minus|except``
    catches "minus the one stale assertion ... which is red on this tree" and
    catches nothing about "with the single documented exclusion below". It is kept
    because it is free and because the four words are the ones a carve-out reaches
    for first, not because it is a proof.

    **The two skip figures are now fact checks**, and they are the half of this
    step that can be derived. The checklist tells a reviewer to expect a specific
    number of skips with ``node`` installed and a different one without, and both
    are properties of the tree:

    * the guaranteed skip is the ``real_llm`` opt-in -- ``tests/conftest.py`` skips
      those items unless ``--real-llm`` is passed, so the pasted figure cannot be
      below that count. A lower bound rather than an equality, because
      ``tests/test_ui_behaviour.py`` skips itself when ``node`` is absent and the
      leakage harness has a runtime skip of its own; asserting equality would make
      this test a report on the reviewer's toolchain.
    * the without-node figure is exact arithmetic on two collections -- every test
      in ``tests/test_ui_behaviour.py`` plus the ``real_llm`` item -- which is the
      composition the sentence itself states.
    """
    text = readme_text()
    start = text.index("pytest -q            #")
    step = text[start : text.index("pytest -m leakage", start)]
    forbidden = re.findall(r"(?i)\b(red|stale|minus|except)\b", step)
    assert not forbidden, (
        f"the checklist's `pytest -q` step carves an exception out of section 1's "
        f"result ({forbidden}). If a test really is red, section 1's pasted block has to "
        "say so first -- a checklist that contradicts the measured block is worse than "
        "either statement alone."
    )
    assert "1 skipped" in step, "the checklist no longer states the skip a reviewer will see"

    real_llm, _total = collect("-m", "real_llm")
    assert real_llm >= 1, (
        "no test carries the `real_llm` marker any more, so the skip the checklist "
        "promises a reviewer has no cause; the checklist and section 1 both need rewriting"
    )
    claimed_skipped = as_int(one_match(r"(\d+) skipped \(the real-network", flat(step)).group(1))
    assert claimed_skipped >= real_llm, (
        f"the checklist promises {claimed_skipped} skipped and the `real_llm` marker alone "
        f"selects {real_llm} tests, every one of which is skipped without --real-llm"
    )

    ui_tests = collect_count("tests/test_ui_behaviour.py")
    without_node = as_int(
        one_match(r"Without node: (\d+) skipped", flat(readme_text())).group(1)
    )
    assert without_node == ui_tests + real_llm, (
        f"the checklist says a reviewer without `node` sees {without_node} skipped; "
        f"tests/test_ui_behaviour.py collects {ui_tests} tests and the real_llm marker "
        f"selects {real_llm}, so the figure is {ui_tests + real_llm}. This number was "
        "pasted once and never re-derived, which is the defect the whole file is for"
    )


def collect(*marker: str) -> tuple[int, int]:
    """``(selected, total collected)`` for a marker expression, by collecting.

    ``--collect-only`` imports the test modules and builds the tree without
    running anything, so this is safe to call from inside the suite and costs
    seconds rather than the eight minutes a run costs. The deselected form prints
    ``N/M tests collected (K deselected)``, which is where both numbers come from
    in one subprocess instead of two.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *marker],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-2000:]
    selected, total = one_match(r"(\d+)/(\d+) tests collected", result.stdout).groups()
    return int(selected), int(total)


def collect_count(*target: str) -> int:
    """How many tests ``pytest`` collects from ``target``, undeselected.

    Separate from :func:`collect` because the two output shapes differ: a marker
    expression prints ``N/M tests collected (K deselected)`` and a bare path prints
    ``N tests collected``. One regex over both would match the first number of
    either and silently mean different things.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *target],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-2000:]
    return int(one_match(r"(?m)^(\d+) tests collected", result.stdout).group(1))


def test_the_pasted_suite_result_accounts_for_every_test_pytest_collects() -> None:
    """The suite count the checklist sends a reviewer to reproduce, derived.

    The count itself cannot be had without running the suite, and running the
    suite from inside the suite is not a thing a test can do. What *can* be had in
    five seconds is the collection, and that is enough to catch the defect this
    number actually has: it goes stale when test modules are added, and both the
    total and the marker split drift together and silently.

    So the arithmetic is closed rather than the run reproduced. On a green tree
    ``pytest -q`` reports every collected test as passed or skipped, so
    ``passed + skipped`` must equal what collection finds -- and the leakage and
    bench tallies in the same comment must equal what their markers select. A
    reviewer's failing run breaks this too, which is the correct signal: the
    pasted block is a claim about a *green* suite, and if the suite is not green
    the block is wrong in a more interesting way than a stale integer.

    EXACT, and it is the assertion that decided the whole-repository total below
    should be exact too: this is the line section 11 step 5 tells a reviewer to
    compare their own output against, so a figure that is close is a figure that
    fails the comparison it was written for -- and because it moves on every
    commit that adds a test, banding the statement total beside it could never
    have kept this block green.

    **What ``passed + skipped == collected`` does NOT bind, said plainly because the
    paragraph above reads as though it does.** It is an accounting identity over
    *collection*. The word "passed" is not attached to anything passing: if 200
    tests went red tomorrow, ``2693 + 1 == 2694`` still holds and this test stays
    green. The docstring above already conceded this in passing ("a reviewer's
    failing run breaks this too") -- which is a claim about the reviewer's run, not
    about this one -- and a concession in prose is not a guard.

    Three things actually bind the greenness, and none of them is here:

    * :func:`test_no_test_the_readme_calls_red_actually_passes` runs any test the
      page names as failing and requires it to fail;
    * :func:`test_the_readme_does_not_disclose_a_failing_test_while_the_suite_is_green`
      catches the pasted ``N failed`` spelling of the same disclosure;
    * the reviewer's own ``pytest -q``, which section 11 step 5 exists to produce.

    The residual hole is a suite that is quietly red while the README says nothing
    at all, and closing it needs a run of the suite from inside the suite, which is
    not a thing a test can do. That is a real limit, stated rather than papered
    over -- the honest reading of a green mark here is "the pasted arithmetic is
    self-consistent with what pytest collects", and nothing wider.
    """
    text = flat(readme_text())
    passed, skipped = (
        as_int(g) for g in one_match(r"(\d+) passed, (\d+) skipped", text).groups()
    )
    claimed_total, claimed_leakage, claimed_bench = (
        as_int(g)
        for g in one_match(
            r"(\d+) collected: (\d+) leakage \+ (\d+) bench \+ rest", text
        ).groups()
    )

    # Two subprocesses, not three: the deselected form reports the grand total
    # alongside the selection, so the unmarked run would be a third full
    # collection for a number the other two already carry. Cross-checking the two
    # totals against each other also catches a collection that is not stable.
    leakage, leakage_total = collect("-m", "leakage")
    bench, bench_total = collect("-m", "bench")
    assert leakage_total == bench_total, (
        f"collection is not stable across markers: {leakage_total} then {bench_total}"
    )
    collected = leakage_total

    assert claimed_total == collected, (
        f"pytest collects {collected} tests; section 1's block says {claimed_total}"
    )
    assert passed + skipped == collected, (
        f"section 1 pastes {passed} passed + {skipped} skipped = {passed + skipped}, but "
        f"pytest collects {collected}. On a green tree those are the same number, so either "
        f"the block is stale (it should read '{collected - skipped} passed, {skipped} skipped') "
        "or the suite is not green -- check which before editing the prose"
    )
    assert (claimed_leakage, claimed_bench) == (leakage, bench), (
        f"the marker split is {leakage} leakage and {bench} bench, not "
        f"{claimed_leakage} and {claimed_bench}"
    )


# -- section 1: the E501 accounting ------------------------------------------


def test_the_e501_accounting_adds_up_and_names_the_files_that_still_have_long_lines() -> None:
    """"Of the 145: 33 are fixed ... the remainder is 88 + 7" -- 17 short of itself.

    145 - 33 is 112, not 95. The missing 17 were fixed inside
    ``tests/test_detection.py`` (24 long lines down to 7) and the paragraph never
    said so, in a paragraph whose stated point is that "we turned the rule on"
    can hide a blanket exemption. Both halves are checked: the arithmetic against
    itself, and the two exempted files against a line-by-line count.
    """
    text = flat(readme_text())

    baseline = as_int(one_match(r"There were \*\*(\d+)\*\* violations", text).group(1))
    fixed, remain = (
        as_int(g)
        for g in one_match(r"Of the \d+, \*\*(\d+) are fixed and (\d+) remain\*\*", text).groups()
    )
    outside = as_int(one_match(r"\*\*(\d+) lay outside", text).group(1))
    inside = as_int(one_match(r"a further \*\*(\d+) inside", text).group(1))
    before, after = (
        as_int(g) for g in one_match(r"from (\d+) long lines to (\d+)\.", text).groups()
    )
    spelled = [
        as_int(g)
        for g in one_match(r"\*\*(\d+) \+ (\d+) \+ (\d+) = (\d+)\*\*", text).groups()
    ]
    fixtures_lines, detection_lines = (
        as_int(g)
        for g in one_match(
            r"`fixtures/\*` \((\d+) long lines\) and `tests/test_detection\.py` \((\d+)\)", text
        ).groups()
    )

    # EXACT, all five. Every one is arithmetic the paragraph does on itself, and the
    # inputs are historical: 145/33/17 are what the tree measured at the commit that
    # turned `E501` on, so they are fixed facts about a past state rather than
    # anything a later commit can move. Only a rewrite of the paragraph can break
    # them, which is exactly the case worth failing on.
    assert outside + inside == fixed, "the two fixed groups do not sum to the fixed total"
    assert fixed + remain == baseline, "fixed plus remaining is not the stated baseline"
    assert spelled == [outside, inside, remain, baseline], "the spelled-out sum drifted"
    assert before - inside == after, "24 - 17 is 7: the test_detection.py split is inconsistent"
    assert fixtures_lines + detection_lines == remain, "the two exemptions do not sum to 95"

    # EXACT, and derived: these two are the live half of the paragraph -- the only
    # figures in it that describe the tree as it stands now. They are per-file
    # counts of two corpus files, not a repository-wide total, so they move only
    # when someone edits a fixture; unbanded is right and the message carries the
    # replacement. Note the coupling: because the exemptions must still sum to 95,
    # adding one long line to either file makes the paragraph unfixable by editing
    # one number. That is deliberate. The 145 baseline is a measurement of a past
    # commit and must not be quietly re-based to absorb a new violation -- the
    # honest repair is to fix or argue the new line, and to say so in the prose.
    measured_fixtures = long_lines(REPO_ROOT / "fixtures" / "generator.py")
    measured_detection = long_lines(REPO_ROOT / "tests" / "test_detection.py")
    assert measured_fixtures == fixtures_lines, (
        f"fixtures/generator.py has {measured_fixtures} lines over {LINE_LIMIT} columns, not "
        f"{fixtures_lines}; a long line was added to or removed from the corpus, and the "
        "exemption paragraph has to account for it rather than re-base its 145"
    )
    assert measured_detection == detection_lines, (
        f"tests/test_detection.py has {measured_detection} lines over {LINE_LIMIT} columns, "
        f"not {detection_lines}; same rule as above"
    )


# -- section 1: the two mypy scopes -------------------------------------------


def test_the_mypy_paragraph_counts_the_files_the_two_scopes_actually_hold() -> None:
    """The `--strict` figures, which had rotted by two in a paragraph that predicted it.

    Section 1 states ``mypy`` twice: ``clean, 52 source files`` in the pasted block
    and ``**package only** -- 52 files`` in the paragraph under it, both describing
    the ``files = ["secure_context_pipeline"]`` pin; then ``90 files and 129
    remaining errors`` for ``mypy --strict .``, which ignores that pin. Measured
    while this was written, the whole-tree run checks **91** files and finds
    **131** errors -- two adrift in each half, on the same commits that moved the
    coverage denominators beside it. The paragraph had already called those two
    "the most rot-prone numbers on this page" and told the reader to re-derive
    them, which is a caveat, not a guard: it was two wrong under it.

    What is derived here is the two FILE counts, because a file count is a property
    of the tree. 52 ``.py`` files under ``secure_context_pipeline/`` and 91 across
    the repository, both agreeing exactly with what ``mypy`` printed on the run the
    paragraph quotes. Nothing here runs ``mypy``: that would check the paste
    against the tool it is a paste of, and would add a cold-cache ``--strict`` pass
    to a suite that already costs eight minutes.

    The error TOTAL is a property of a *run*, like ``missed``/``branches``/
    ``partial`` below, so it is not re-derived. Its composition is not -- that is
    arithmetic the paragraph performs on itself, and it is pinned: 54
    ``attr-defined`` plus 34 ``arg-type`` plus the stated remainder must equal the
    stated total. That is exactly the E501 defect one paragraph up, where a total
    was corrected and the split it had been spelled out as was not.
    """
    text = flat(readme_text())
    block_files = as_int(one_match(r"clean, (\d+) source files", text).group(1))
    # The dash between "package only" and the count is matched as `\S` rather than
    # written out, so this file stays plain ASCII under RUF001/RUF002.
    para_files = as_int(one_match(r"\*\*package only\*\* \S (\d+) files", text).group(1))
    tree_files, errors = (
        as_int(g)
        for g in one_match(r"\*\*(\d+) files and (\d+) remaining errors\*\*", text).groups()
    )
    attr, arg = (
        as_int(one_match(rf"\*\*(\d+)\*\* are `{code}`", text).group(1))
        for code in ("attr-defined", "arg-type")
    )
    rest = as_int(one_match(r"the remaining (\d+) are assorted", text).group(1))

    measured_package = len(python_files(REPO_ROOT / "secure_context_pipeline"))
    measured_tree = len(python_files(REPO_ROOT))

    # EXACT, all three, and the first is the one that matters most: the gate's own
    # scope is restated twice four lines apart, which is the shape that produced
    # the section-1-versus-section-11 contradiction this file opens with.
    assert block_files == para_files, (
        f"the pasted block says mypy checks {block_files} source files and the paragraph "
        f"under it says {para_files}; both describe the same `files` pin"
    )
    assert para_files == measured_package, (
        f"`secure_context_pipeline/` holds {measured_package} .py files, not {para_files}; "
        "both mypy scope statements in section 1 are stale"
    )
    assert tree_files == measured_tree, (
        f"`mypy --strict .` is pointed at {measured_tree} .py files, not {tree_files}; "
        f"re-run it and update the error total beside the file count"
    )
    assert attr + arg + rest == errors, (
        f"{attr} attr-defined + {arg} arg-type + {rest} assorted is {attr + arg + rest}, but the "
        f"paragraph states {errors} errors. The composition is what carries this argument, so a "
        "total corrected without its split is the defect, not a rounding difference"
    )


# -- section 1: whole-repository coverage denominator -------------------------


def test_the_whole_repository_statement_total_is_the_one_coverage_would_report() -> None:
    """The most rot-prone number on the page: it moves with every test module.

    It was 18,988 while the tree measured 19,043 -- 55 statements adrift, from
    test modules added in the commit before. Stating it as its two parts is what
    makes it checkable at all: ``--cov=secure_context_pipeline --cov=tests
    --cov=fixtures`` cannot see ``demo.py`` (the demo tests load it by file path
    under a synthetic module name, so ``--cov=demo`` warns ``module-not-imported``
    and silently drops all 632 of its statements), so the published total is a
    sum of two runs and both addends have to be right.

    All three assertions are EXACT, and the third one has been both ways. It was
    pinned, went red on a two-statement drift, was banded at 0.5% of the measured
    total -- warn inside, fail outside -- and is pinned again. The re-derivation
    that put it back is in this module's docstring and is summarised at the
    assertion; the short version is that the band was found holding 81 statements
    while the suite was already red on the two exact numbers printed beside it.

    * ``parts + demo == total`` -- arithmetic the README performs on itself;
      nothing outside the file can move it, so a mismatch is always an authoring
      mistake and never drift.
    * ``demo.py`` -- one script, one owner, and the figure is load-bearing three
      separate times on the page: it is the number the ``--cov=demo``
      ``module-not-imported`` trap is argued with, so a wrong value makes an
      argument wrong rather than a figure stale.
    * The three-root sum -- the fastest-moving number on the page, and the one this
      test exists for. Exact, with the replacement in the failure message.
    """
    text = flat(readme_text())
    total, parts = (
        as_int(g)
        for g in one_match(
            r"\*\*98%\*\* of \*\*([\d,]+)\*\* statements: \*\*([\d,]+)\*\* for the", text
        ).groups()
    )
    demo_claim = as_int(one_match(r"`demo\.py`'s \*\*(\d+)\*\* on top of that", text).group(1))

    measured_parts = sum(
        statements(path)
        for root in COVERED_ROOTS
        for path in sorted((REPO_ROOT / root).rglob("*.py"))
        if "__pycache__" not in path.parts
    )
    measured_demo = statements(REPO_ROOT / "demo.py")

    # EXACT -- README-internal arithmetic, unmovable from outside the file.
    assert parts + demo_claim == total, "the published total is not the sum of its own parts"
    # EXACT -- a single script, and the figure an argument rests on, not a total.
    assert measured_demo == demo_claim, f"demo.py is {measured_demo} statements, not {demo_claim}"

    # EXACT -- restored from a 0.5% band, which is a tightening and is argued for
    # rather than asserted. Three findings, in the order they landed.
    #
    # 1. The band was holding 81 statements when it was re-read: 21,347 published
    #    against 21,428 measured, inside a band that had grown to 107 and passing
    #    with a warning. Its own docstring had already been re-derived twice by
    #    hand, which is the tell -- a width that has to be re-justified every time
    #    it is breached is not absorbing noise.
    #
    # 2. The band could not buy what it was bought for. Its whole case is that a
    #    number moving on every commit turns the suite red and teaches the reader
    #    to edit the assertion; but section 1's pasted block also carries the
    #    collected-test count and the package denominator, both pinned EXACTLY
    #    here, and both move for the same reasons. Replay of the nineteen commits
    #    ending at `b82964a`, per commit, as package / three-root / `def test_`:
    #
    #        +0/+0/+0       +1/+36/+6      +0/-1/+0     +2/+13/+1     +0/+12/+2
    #        +1/+5/+0       +0/+0/+0       +6/+46/+6    +0/+14/+2     +0/+0/+0
    #        +0/+1463/+155  -3/-6/+0       +18/+35/+2   +1/+83/+4     +17/+561/+41
    #        +0/+31/+1      +108/+1093/+60 +0/+9/+1     +38/+527/+39
    #
    #    SIXTEEN of the nineteen moved this total; FIFTEEN of those sixteen also
    #    moved a number pinned exactly in this same file, so on those the suite was
    #    red whatever the band did. The one exception (`4624411`, a duplicate
    #    import deleted) moved it by ONE statement. So the band bought exactly one
    #    green run in nineteen commits, and the 81 it was hiding sat under a suite
    #    that was red anyway. The "eighteen of nineteen" this comment used to claim
    #    counted every replayed commit as a mover; it is re-derived above.
    #
    # 3. A fraction of the guarded quantity is the wrong shape for a tolerance: it
    #    was ~95 statements when written and 107 when re-read, and it widens on its
    #    own as the tree grows, with nothing in the mechanism to revisit it. It is
    #    also memoryless -- it cannot distinguish one commit that moved 81 from
    #    eleven commits during which the published figure was 81 wrong -- so a
    #    per-commit allowance spent as a standing one never comes back.
    #
    # What is NOT the argument: that exactness is a style. `missed`/`branches`/
    # `partial` below stay banded, because those are properties of a run this file
    # deliberately does not perform. This number is a property of the source, it is
    # re-derived here in full, and the failure message names its replacement.
    correction = (
        f"package + tests + fixtures is {measured_parts} statements, not {parts}; "
        f"section 1's whole-repository total should read "
        f"{measured_parts + measured_demo:,} ({measured_parts:,} + {measured_demo})"
    )
    assert measured_parts == parts, (
        f"{correction}. That is {abs(measured_parts - parts)} statements adrift. This "
        "assertion is exact on purpose: the collected-test count and the package "
        "denominator in the same block are exact and move on the same commits, so a "
        "band here hid drift without ever saving a red run"
    )


def test_the_package_only_coverage_line_states_the_denominator_the_package_has() -> None:
    """The other coverage figure in the pasted block, which had no test and was 96 short.

    Section 1 pastes two coverage lines. The whole-repository one above got a guard
    the moment it drifted; the ``--cov=secure_context_pipeline`` line beside it --
    the one that is actually the configured gate -- got none, and by the time this
    was written it read 4,403 against a package of 4,511. Same failure mode, one
    line up, and the only reason it lasted longer is that nobody had counted it.

    The denominator is pinned EXACTLY, as the whole-repository total above now is
    too. It does move less: over the nineteen commits replayed at that assertion,
    the package moved -3 to +108 statements a commit with a **median of 0** and nine
    of nineteen at exactly 0, against -6 to +1,463 and a median of +14 for package +
    tests + fixtures. ("0 to +18, median 0" is what this docstring said, from the
    earlier eleven-commit window; the nineteen-commit replay contains a +108, so the
    range is quoted from the wider window now.) But "moves less" turned out to be an
    argument for keeping a human's correction cheap, not for tolerating a wrong
    number. The replay that removed the band is recorded at that assertion.

    ``missed``, ``branches`` and ``partial`` are properties of a *run*, not of the
    source, so they cannot be re-derived here without paying the eight minutes a
    ``--cov`` pass over this suite costs -- and re-deriving them by running it would be
    checking the paste against the tool it is a paste of. What is checkable without
    a run is that they are consistent with the headline percentage beside them, and
    that is asserted as a band: coverage's ``BrPart`` column counts partially-taken
    branches, which is a lower bound on missing branch *exits*, so the recomputed
    percentage is an upper bound on the reported one rather than an identity.
    """
    text = flat(readme_text())
    stmts, missed, branches, partial = (
        as_int(g)
        for g in one_match(
            r"([\d,]+) statements, ([\d,]+) missed; ([\d,]+) branches, ([\d,]+) partial", text
        ).groups()
    )
    # The headline sits in the pasted code block, unbolded -- an earlier draft of
    # this anchor asked for `**98%**` and matched nothing, which `one_match` turns
    # into a failure rather than the vacuous pass it would otherwise be.
    claimed_pct = as_int(one_match(r"(\d+)% branch coverage", text).group(1))

    measured = sum(
        statements(path)
        for path in sorted((REPO_ROOT / "secure_context_pipeline").rglob("*.py"))
        if "__pycache__" not in path.parts
    )
    assert stmts == measured, (
        f"`--cov=secure_context_pipeline` covers {measured} statements, not {stmts}; "
        "section 1's package-only coverage comment is stale"
    )

    assert missed < stmts, "more statements missed than exist"
    assert partial < branches, "more partial branches than branches"

    # The recomputation is an UPPER BOUND, not an identity, and getting that
    # direction right is the whole check. Coverage's percentage is
    # ``(executed statements + executed branch exits) / (statements + branches)``,
    # but the column pasted here is ``BrPart`` -- branches taken only one way --
    # and a branch missed entirely contributes two unexecuted exits while showing
    # up as at most one partial. So substituting ``partial`` for the missing exits
    # can only flatter the result. Measured on the run section 1 now pastes:
    # (5014-76+1268-57)/(5014+1268) = 97.9%, which coverage reports as 98%; on the
    # previous run of the same shape (4921-76+1238-57)/(4921+1238) = 97.8%, also
    # reported as 98%; on the run this comment was written against, (4511-65+1126-57)/(4511+1126) =
    # 97.8%, which it also reported as 98% -- the bound is one point wide in the
    # worst case and zero in the best, which is why the second assertion allows one.
    # Hence: the published percentage may not exceed the bound, and may not trail it
    # by more than a point.
    upper_bound = round((stmts - missed + branches - partial) / (stmts + branches) * 100)
    assert claimed_pct <= upper_bound, (
        f"the pasted counts cannot support {claimed_pct}% branch coverage: they bound it "
        f"above at {upper_bound}%, and that bound already assumes every missed branch was "
        "only half-missed"
    )
    assert upper_bound - claimed_pct <= 1, (
        f"the pasted counts bound branch coverage at {upper_bound}% and the headline says "
        f"{claimed_pct}%; one of the two is from a different run"
    )


def test_the_pasted_leakage_tally_is_one_the_readme_says_it_observed() -> None:
    """The one number in section 1 that is not stale but non-deterministic.

    ``[leakage] 100/100 runs clean, 0 leaks (2981 originals ..., 2434 surrogates
    round-tripped)`` sat inside a block headed "output from this repository, not
    an estimate", and 2434 is not a figure any run prints twice. Four runs
    measured for this section gave 2421, 2426, 2426 and 2436 surrogates against an
    unvarying 2981 originals: the tally counts surrogates the mock provider
    happened to echo, and the pseudonyms it echoes are drawn against a per-session
    key. 2434 was in none of them.

    This is a third grade, distinct from the EXACT and BANDED ones elsewhere in
    this file, and it is the right one for a number that is not converging on
    anything: the prose has to enumerate what it actually observed, and the pasted
    line has to be one of those observations rather than a plausible-looking
    number near them. Re-running and pasting a fifth value is a legitimate edit --
    add it to the list in the prose and this stays green.

    The originals figure quoted above is the one this test was written against;
    the tree now prints 2966, and the assertion below carries the current value
    with the argument for changing it. The history is left as written because it
    is the reason the surrogate tally is graded the way it is.

    **Both halves of this test are weaker than they look, and here is which.**

    * The surrogate tally is checked against **a restatement of itself elsewhere in
      the same README**. That is a consistency check, not a fact check: if someone
      pastes a fabricated line into the block and adds the same fabrication to the
      list below it, this passes. It is still worth having -- the defect it caught
      was a number that appeared in *neither* place -- but the module docstring's
      rule ("a claim that can only be checked against its own restatement is not
      checked") applies to it, and it is listed as an exception to that rule rather
      than pretending to satisfy it. What has been added is that the four observed
      values must be **distinct**, because a list that restates one number four
      times satisfies membership while demonstrating none of the variability the
      paragraph's whole argument rests on.
    * ``originals == 2966`` is a **literal in this file**, not a re-derivation. It
      is deliberately a literal -- the paragraph above argues that a change here is
      a finding about the detector rather than an edit -- but the honest description
      is "two numbers that must be typed to match", and if both are typed wrong
      together nothing notices. Re-deriving it means running the 100-run harness:
      100 full pipeline executions through spaCy, which is `tests/leakage/` itself.
      That is the same cost this file refuses to pay for ``missed``/``branches``,
      and for the same reason, so the literal stays and the limitation is named
      instead of implied.
    """
    text = flat(readme_text())
    pasted = as_int(one_match(r"(\d+) surrogates round-tripped", text).group(1))
    originals = as_int(one_match(r"\((\d+) originals vaulted and scanned", text).group(1))
    observed = [
        as_int(g)
        for g in one_match(
            r"did not: \*\*([\d,]+), ([\d,]+), ([\d,]+) and ([\d,]+)\*\* across", text
        ).groups()
    ]

    assert "100/100 runs clean, 0 leaks" in text, "the load-bearing result has moved or changed"
    assert len(set(observed)) == len(observed), (
        f"the paragraph lists {observed} as four separate observations and they are not "
        "four distinct values. The argument the paragraph makes is that this tally "
        "reproduces on no run, so a repeated value is either a transcription slip or "
        "evidence against the argument -- either way it is not four observations"
    )
    assert pasted in observed, (
        f"the pasted block reports {pasted} surrogates round-tripped, which is not one of the "
        f"{observed} the paragraph below says it observed. A tally that reproduces on no run "
        "does not belong in a block headed 'output from this repository, not an estimate' -- "
        "paste a line a run actually printed and add its value to the list"
    )
    # 2981, then 2966, and 3066 now. The literal is updated rather than relaxed, and
    # only ever after the protocol this comment prescribes has actually been run:
    # the harness was RE-RUN four consecutive times on this tree and printed 3066
    # every time, and section 1 records the move as a finding (with the SSN registry
    # backstop of Deviation 71 named as the candidate cause) instead of absorbing it.
    # A band here would have swallowed exactly that signal, which is the whole reason
    # this assertion is a literal.
    assert originals == 3066, (
        f"the originals tally is {originals}, not the 3066 that came back identical on all four "
        "runs measured for this pass. Unlike the surrogate count this one is deterministic, so a "
        "change here is a change in what the detector plants or finds, and is a finding rather "
        "than an edit -- re-run `pytest -m leakage` and record the move in section 1 before "
        "touching this number"
    )


def test_the_benchmark_tables_budget_column_states_the_budgets_the_suite_asserts() -> None:
    """The one column of section 1's benchmark table that is a constant, not a sample.

    FACT CHECK. The table's own prose says it: "the only number this page asserts is
    the budget, because the budget is the only one a test enforces." Nothing checked
    that. ``BUDGET_OBFUSCATE_S``, ``BUDGET_VAULT_P99_MS``, ``BUDGET_RESTORE_MS`` and
    ``BUDGET_PIPELINE_S`` are four floats in ``tests/test_benchmarks.py``, and the
    README publishes them as a column beside seven rows of timings that move with
    the machine -- so the column is the part of that table a reader can rely on, and
    it was the part with no guard.

    Both directions, because both are silent failures: a budget widened in the code
    and not on the page overstates the claim, and a budget on the page the suite
    does not assert is a promise nothing keeps.

    Deliberately separate from
    ``test_benchmarks.py::test_the_readme_benchmark_table_is_the_one_this_run_measured``,
    which checks the same column against the same constants but only after paying
    for a full benchmark run. This one costs an import, so ``pytest
    tests/test_readme_claims.py`` on its own still catches a budget that moved. The
    table *parser* is shared with that module and that is fine: the parser is not
    the thing under audit, the README's cells are, and both checks read the same
    cells to ask different questions.
    """
    from tests.test_benchmarks import (
        BUDGET_OBFUSCATE_S,
        BUDGET_PIPELINE_S,
        BUDGET_RESTORE_MS,
        BUDGET_VAULT_P99_MS,
        parse_readme_bench_table,
    )

    asserted = {
        BUDGET_OBFUSCATE_S,
        BUDGET_PIPELINE_S,
        BUDGET_RESTORE_MS / 1000.0,
        BUDGET_VAULT_P99_MS / 1000.0,
    }
    rows = parse_readme_bench_table(readme_text())
    published = {row.budget_s for row in rows}

    unbacked = sorted(published - asserted)
    assert not unbacked, (
        f"section 1's benchmark table publishes budgets of {unbacked} seconds that no "
        f"constant in tests/test_benchmarks.py asserts; the suite asserts {sorted(asserted)}"
    )
    unpublished = sorted(asserted - published)
    assert not unpublished, (
        f"tests/test_benchmarks.py asserts budgets of {unpublished} seconds that section 1's "
        "table has no row for. A budget the suite enforces and the page does not state is a "
        "guarantee the reviewer is never told about"
    )
    assert len(rows) >= len(asserted), (
        f"the table has {len(rows)} rows for {len(asserted)} distinct budgets"
    )


# -- section 2: the HTTP surface ----------------------------------------------

#: Declared routes the surface table deliberately does not carry a row for, with
#: the prose that documents each instead. A literal set rather than a filter, so a
#: NEW route can never fall into it by accident -- silence is what this section is
#: guarding against, and a rule like "skip anything under /openapi" would have let
#: the next unlisted route in for free.
UNTABLED_ROUTES = {
    # "`/docs` and `/redoc` are off ... `/openapi.json` is served locally."
    ("GET", "/openapi.json"),
    ("HEAD", "/openapi.json"),
}

#: The reverse exception: rows whose route is not an ``APIRoute`` at all. ``GET /``
#: is Starlette's ``Mount``, which carries no ``methods``, so it cannot appear in
#: the declared set and would otherwise read as a stale row.
UNROUTED_TABLE_ROWS = {("GET", "/")}


def route_shape(path: str) -> str:
    """``/fixtures/{name:path}`` -> ``/fixtures/{}``.

    The table writes ``DELETE /sessions/{id}`` where the code declares
    ``/sessions/{session_id}``, and ``GET /fixtures/{name}`` where the code
    declares ``/fixtures/{name:path}``. Comparing on the parameter's *name* would
    make this test a style checker for placeholder spellings; comparing on the
    shape keeps it a check that the route is documented at all, which is the
    property that failed.
    """
    return re.sub(r"\{[^}]*\}", "{}", path)


def documented_routes(text: str) -> set[tuple[str, str]]:
    """``(method, path shape)`` for every row of section 2's surface table."""
    lines = text.splitlines()
    header = [i for i, line in enumerate(lines) if line.startswith("| Method & path |")]
    assert len(header) == 1, f"expected exactly one HTTP-surface table header, found {header}"
    rows: set[tuple[str, str]] = set()
    for line in lines[header[0] + 2 :]:
        if not line.startswith("|"):
            break
        match = re.match(r"\|\s*`([A-Z]+) (/[^`]*)`", line)
        assert match is not None, f"unparsable row in the HTTP-surface table: {line[:80]!r}"
        rows.add((match.group(1), route_shape(match.group(2))))
    return rows


def test_the_http_surface_table_names_every_route_the_app_declares() -> None:
    """The gap this catches is the one it was written for: a route with no row.

    ``GET /fixtures/{name}`` -- the app's only file-serving route and its only
    unauthenticated read -- shipped with tests, an OpenAPI summary and a long
    handler docstring, and **nothing** in section 2's table. A reviewer met it
    first in the code, which for the one route that takes a filename from a caller
    is the worst possible order.

    Reading the table for its own consistency could never have caught that: the
    table was internally perfect and simply short a row. So the expected value
    comes from the application object -- ``create_app()``, the same factory the
    Dockerfile's ``CMD`` names, built in 1.3 s with no settings and no lifespan --
    and the README is the thing under test, which is the only direction in which
    "a route exists that nobody wrote down" is detectable.

    Both directions are asserted, because a stale row is the same defect running
    backwards: a reviewer trusting a row for a route that no longer exists is
    reading fiction. The two exception sets are literals for the same reason the
    fixture allow-list is: a predicate would quietly absorb the next route.
    """
    from secure_context_pipeline.api.app import create_app

    declared = {
        (method, route_shape(route.path))
        for route in create_app().routes
        for method in getattr(route, "methods", None) or ()
    }
    documented = documented_routes(readme_text())

    missing = sorted((declared - documented) - UNTABLED_ROUTES)
    assert not missing, (
        f"the app declares {missing} and section 2's table has no row for them. Add the row "
        "where the other routes are documented -- a reviewer who meets a route in the code "
        "first has been told about it by nobody"
    )
    stale = sorted((documented - declared) - UNROUTED_TABLE_ROWS)
    assert not stale, (
        f"section 2's table has rows for {stale}, which this app does not declare; the routes "
        "it does declare are "
        f"{sorted(declared)}"
    )


def test_the_fixture_route_section_describes_the_documents_the_repo_actually_ships() -> None:
    """The four names, the four sizes and their sum, checked against git and disk.

    Section 2's ``GET /fixtures/{name}`` block is the security argument for the
    only unauthenticated read on this surface, and every load-bearing number in it
    is a property of the tree rather than of a run: which documents are on the
    allow-list, how many there are, and how many bytes the import-time table
    therefore holds. All three rot on a fifth fixture, a deleted one, or a
    regenerated one.

    Derived from ``git ls-files`` and the files' own sizes rather than from
    ``DEMO_FIXTURES``. That is the point of the check: ``test_api_documents.py``
    already pins the allow-list against git, so pinning the README against the
    allow-list would put both claims behind one source. Two independent
    derivations of "what ships" have to agree with the prose instead.

    ``0.206 ms`` and the live-run tallies beside them are properties of a run and
    are deliberately not re-derived here, for the reason ``missed``/``branches``
    are not: re-measuring them in the suite would be checking a paste against the
    tool it is a paste of. What *is* checkable about the live run is its own
    arithmetic, and that is asserted.
    """
    text = flat(readme_text())
    tracked = sorted(
        REPO_ROOT / name
        for name in subprocess.run(
            ["git", "ls-files", "fixtures"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        if name.endswith(".txt")
    )
    assert tracked, "git tracks no .txt fixture at all; this test would be vacuous"

    claimed_count = NUMBER_WORDS[one_match(r"What it serves: (\w+) literals", text).group(1)]
    assert claimed_count == len(tracked), (
        f"git ships {len(tracked)} fixture documents and section 2's fixture block says "
        f"{claimed_count}"
    )

    total, *addends = (
        as_int(g)
        for g in one_match(
            r"\*\*([\d,]+) bytes\*\* \(([\d,]+) \+ ([\d,]+) \+ ([\d,]+) \+ ([\d,]+)\)", text
        ).groups()
    )
    # README-internal arithmetic first: a mismatch here is an authoring slip, never
    # drift, so it gets its own message.
    assert sum(addends) == total, f"the block's own addends sum to {sum(addends)}, not {total}"
    on_disk = sorted(path.stat().st_size for path in tracked)
    assert sorted(addends) == on_disk, (
        f"the four fixtures are {on_disk} bytes on disk and the block lists {sorted(addends)}; "
        f"the resident table is {sum(on_disk):,} bytes"
    )

    for path in tracked:
        assert path.name in text, f"section 2's fixture block never names {path.name}"

    # The live traversal run: 36 request lines, split 32 refused / 3 stated
    # individually / 1 positive control. Not re-run here -- but a split that does
    # not add up is the tell that one of the four numbers was edited alone.
    sent, refused, stated, control = (
        as_int(g)
        for g in one_match(
            r"\*\*(\d+)\*\* request lines, which account for themselves as \*\*(\d+)\*\* \+ "
            r"\*\*(\d+)\*\* \+ \*\*(\d+)\*\*",
            text,
        ).groups()
    )
    assert refused + stated + control == sent, (
        f"the live traversal run is written as {refused} + {stated} + {control} = {sent}, which "
        f"is {refused + stated + control}"
    )
    assert control == 1, "a corpus with no single positive control cannot prove the rig serves"

    corpus = len(traversal_corpus())
    claimed_corpus = as_int(
        one_match(r"`TRAVERSALS` in `tests/test_api_documents\.py`: \*\*(\d+)\*\* names", text)
        .group(1)
    )
    assert claimed_corpus == corpus, (
        f"`TRAVERSALS` holds {corpus} names and section 2 says {claimed_corpus}"
    )
    assert corpus <= sent, (
        f"the live re-run sent {sent} request lines against a committed corpus of {corpus}; the "
        "prose presents the live run as the wider of the two"
    )


def traversal_corpus() -> list[str]:
    """The committed adversarial corpus, read as source rather than imported.

    ``ast`` rather than ``from tests.test_api_documents import TRAVERSALS`` because
    importing that module drags in the app fixtures and the store, and because the
    thing being counted is a literal in a file -- ``literal_eval`` on the
    assignment is the whole computation, with no chance of counting a corpus some
    conftest extended at collection time.
    """
    source = (REPO_ROOT / "tests" / "test_api_documents.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "TRAVERSALS" for target in node.targets
        ):
            names = ast.literal_eval(node.value)
            assert isinstance(names, list) and all(isinstance(n, str) for n in names)
            return names
    raise AssertionError("tests/test_api_documents.py no longer defines TRAVERSALS")


# -- the four leakage boundaries ---------------------------------------------


def boundary_count_claims(text: str) -> dict[str, int]:
    """Every sentence in the README that states how many boundaries there are."""
    anchors = {
        "opening claim": r"subject to (\w+) named boundaries this design does not close",
        "opening list lead-in": r"the (\w+) boundaries are stated here rather than",
        "opening cross-reference": r"all (\w+) are detailed under \*Leakage harness\* below",
        "ten-minute index": r"the (\w+) boundaries it does \*\*not\*\* claim",
        "leakage harness heading": (
            r"The (\w+) boundaries named at the top of this file are stated rather than closed"
        ),
        "traceability table": r"the (\w+) stated boundaries are pinned by",
    }
    return {name: NUMBER_WORDS[one_match(p, text).group(1)] for name, p in anchors.items()}


def test_every_statement_of_how_many_boundaries_there_are_agrees_with_the_list() -> None:
    """It was four, a different four, and three -- in one document.

    The opening section names four (partial value, glued into a longer word,
    homoglyph, the 8-alphanumeric separator floor). The Leakage-harness list said
    "four" and then listed a different four, because it still counted the
    combining-mark shape it had already retired as CLOSED and never mentioned the
    separator floor at all. The traceability table said three. A reviewer asking
    "how many shapes does this design concede?" got three answers.

    The authority is the numbered list itself; every sentence that counts it is
    compared against that, not against another sentence.
    """
    text = readme_text()
    opening = text[
        text.index("boundaries are stated here rather than") : text.index(
            "Each is pinned by a named test"
        )
    ]
    numbered = re.findall(r"^\d+\. \*\*", opening, re.MULTILINE)
    assert len(numbered) >= 3, "the opening numbered list of boundaries has moved"

    # EXACT, and nothing here hard-codes four: the list is the authority and every
    # sentence is compared to it, so closing a boundary is a legitimate edit that
    # this test walks you through rather than blocks. What it will not tolerate is
    # six sentences disagreeing, which is the state it was written for.
    for name, claimed in boundary_count_claims(flat(text)).items():
        assert claimed == len(numbered), (
            f"the {name} says {claimed} boundaries; the numbered list in the opening "
            f"section has {len(numbered)}"
        )


def test_no_entry_in_the_leakage_boundary_list_is_one_the_readme_calls_closed() -> None:
    """A closed shape counted as a stated boundary is a false concession.

    The combining-mark entry was closed in the code and left in the list, which
    is how the list came to say "four" over a set of four that did not match the
    four in the opening section. The entry is worth keeping -- the argument for
    leaving it open was wrong in an instructive way -- but not as a member of the
    count, so it is demoted out of the bold-bulleted list rather than deleted.
    """
    text = readme_text()
    start = text.index("named at the top of this file are stated rather than closed")
    end = text.index("are blind spots", start)
    entries = re.split(r"^- ", text[start:end], flags=re.MULTILINE)[1:]

    counted = [entry for entry in entries if entry.startswith("**")]
    assert len(counted) == boundary_count_claims(flat(text))["leakage harness heading"], (
        f"the Leakage-harness list has {len(counted)} bold-bulleted entries, which is not "
        "the number of boundaries its own heading claims"
    )
    for entry in counted:
        assert "CLOSED" not in entry, (
            f"a boundary the README calls CLOSED is still counted as a stated boundary: "
            f"{entry.splitlines()[0]!r}"
        )
    assert any("CLOSED" in entry for entry in entries), (
        "the retired combining-mark record has gone; it is kept deliberately, and if it "
        "was deleted this assertion is the wrong one to relax -- say where it went"
    )

    # Counting both lists is not enough, and the original defect proves it: the two
    # lists were both four long and were four *different* things. The claim under
    # audit is "all four are detailed under Leakage harness below", which is a claim
    # about correspondence, so correspondence is what gets asserted -- in order, so a
    # list that drops one shape and gains another cannot pass by staying the same
    # length. The shape words are a literal table for the same reason NUMBER_WORDS
    # is: parsing them out of either list would make each list check itself.
    shapes = ("partial", "glued", "homoglyph", "separator")
    opening = text[
        text.index("boundaries are stated here rather than") : text.index(
            "Each is pinned by a named test"
        )
    ]
    numbered_bodies = re.split(r"^\d+\. ", opening, flags=re.MULTILINE)[1:]
    assert len(numbered_bodies) == len(shapes), (
        f"the opening list has {len(numbered_bodies)} boundaries and this test knows "
        f"{len(shapes)} shape words; a boundary was added or closed, so name it here too"
    )
    for shape, opening_entry, harness_entry in zip(shapes, numbered_bodies, counted, strict=True):
        assert shape in opening_entry.lower(), (
            f"the opening list no longer describes the {shape!r} boundary in the position "
            f"this test expects it: {opening_entry.splitlines()[0]!r}"
        )
        assert shape in harness_entry.lower(), (
            f"the opening section names a {shape!r} boundary that the Leakage-harness list "
            f"does not detail in the same position -- so 'all four are detailed under "
            f"Leakage harness below' is false again: {harness_entry.splitlines()[0]!r}"
        )


# -- audit event types --------------------------------------------------------


def test_every_event_type_count_in_the_readme_names_the_set_it_counts() -> None:
    """13 in section 2, twelve in Deviation 26 and Q5, and section 2 knew.

    Section 2 said "which is why Deviation 26's original count is out of date"
    and the Deviations row was then left out of date. Neither number was
    describable on its own: ``EVENT_TYPES`` holds exactly twelve and
    ``AUDIT_ACCESS_DENIED`` is deliberately outside it, so the only true sentence
    is "twelve members of the vocabulary plus a thirteenth emitted beside it".

    The rule this pins is therefore not a number but a qualification: a count of
    event types has to say which set it counts, close enough to be read with it.
    """
    # EXACT, and this one is a genuine spec pin rather than a measurement: twelve is
    # what the build document froze, so the right behaviour when a thirteenth member
    # is added is a red test, not an absorbed drift.
    assert len(EVENT_TYPES) == 12, "the build doc's fixed vocabulary is twelve"
    assert AUDIT_ACCESS_DENIED not in EVENT_TYPES, (
        "AUDIT_ACCESS_DENIED is in EVENT_TYPES now; section 2's 'a thirteenth, outside that "
        "frozenset' is no longer true and the README has to change with it"
    )

    text = flat(readme_text())
    counted = 0
    for match in re.finditer(r"(\*\*\d+(?:th)?\*\*|\b[a-z]+\b) event type", text):
        token = match.group(1).replace("*", "").removesuffix("th")
        if token in NUMBER_WORDS:
            value = NUMBER_WORDS[token]
        elif token.isdigit():
            value = int(token)
        else:
            continue
        counted += 1
        assert value in (len(EVENT_TYPES), len(EVENT_TYPES) + 1), (
            f"the README states {value} event types; the code has {len(EVENT_TYPES)} in "
            f"EVENT_TYPES plus one emitted outside it"
        )
        context = text[max(0, match.start() - 240) : match.end() + 240]
        assert "EVENT_TYPES" in context or "frozenset" in context, (
            f"'{match.group(0)}' does not say which set it counts within 240 characters. "
            "Twelve-in-the-vocabulary and thirteen-emitted are both true and they are "
            f"different claims: {context[:160]!r}"
        )

    assert counted >= 1, "no counted event-type claim found; the anchor has rotted"

    members = re.findall(r"(\w+) members of `EVENT_TYPES`", text)
    assert len(members) >= 2, "section 5 Q5 and Deviation 26 should both name the frozenset"
    for word in members:
        assert NUMBER_WORDS[word] == len(EVENT_TYPES)


# -- section 5 Q1: the bottleneck list ---------------------------------------


def test_the_bottleneck_list_uses_the_numbers_its_own_measurement_table_states() -> None:
    """The one part of Q1 headed "corrected by measurement" that was not corrected.

    Four paragraphs above it, the section retracts pass 1's old timing in so many
    words -- "13x and 5x what this README used to claim (21.3 ms and 0.36 ms)" --
    and the Aho-Corasick bullet was still sized against the retracted 21 ms, out
    of a 7,160 ms total that appears nowhere else on the page. The second-pass
    share was ~37%, where the table's own numbers give 43%. All three are read
    back out of the table rather than restated.
    """
    text = flat(readme_text())
    end_to_end_s = float(one_match(r"mock provider: \*\*([\d.]+) s end to end\*\*", text).group(1))
    pass_1 = as_int(one_match(r"\| Pass 1 [^|]*\| ([\d,]+) ms \|", text).group(1))
    pass_2 = as_int(one_match(r"\| Pass 2 [^|]*\| ([\d,]+) ms \|", text).group(1))
    end_to_end_ms = end_to_end_s * 1000

    # EXACT on the cross-references, BANDED only where the README rounds. The two
    # tolerances (<1 point, <0.1 point) are the rounding the prose itself applies --
    # "~43%" and "4.3%" -- not slack.
    #
    # **SHAPE CHECK, and this is the sentence that named the whole problem.** It used
    # to read "the bench figures are a pasted measurement, not a re-derivation, so
    # nothing here drifts under a later commit", offered as a *reassurance*. Read
    # again it is the defect: every assertion below reads two places in this one file
    # and compares them, so the Q1 stage table can be wrong by any factor at all and
    # this stays green as long as the bullet under it quotes the same wrong numbers.
    # That is exactly what happened to the section 1 benchmark table, which nothing
    # bound until `tests/test_benchmarks.py::
    # test_the_readme_benchmark_table_is_the_one_this_run_measured` was written: it
    # published a warm restore at 93.3x headroom while the module measured it in
    # single digits.
    #
    # This one stays a shape check, deliberately and not by omission. The Q1 stage
    # table is a *profile* -- per-stage millisecond splits of one instrumented run --
    # and re-deriving it here would mean re-running the pipeline under instrumentation
    # inside this module, which is the eight-minute cost this file declines everywhere
    # else. The bench table was different: those numbers already get measured on every
    # run, so binding them cost nothing. Where a re-derivation is free, take it; where
    # it is not, say the check is internal.
    share, share_ms, share_s = one_match(
        r"~(\d+)% of end-to-end wall time \(([\d,]+) ms of the ([\d.]+) s above", text
    ).groups()
    assert as_int(share_ms) == pass_2, "the bullet's pass-2 figure is not the table's"
    assert float(share_s) == end_to_end_s, "the bullet's end-to-end figure is not the section's"
    assert abs(int(share) - pass_2 / end_to_end_ms * 100) < 1.0, (
        f"the second spaCy pass is {pass_2 / end_to_end_ms * 100:.1f}% of wall time, "
        f"not ~{share}%"
    )

    scan_ms, scan_of, scan_pct = one_match(
        r"would optimise \*\*([\d,]+) ms out of ([\d,]+)\*\*, i\.e\. ([\d.]+)%", text
    ).groups()
    assert as_int(scan_ms) == pass_1, (
        "the Aho-Corasick bullet is sized against a pass-1 figure this section retracts"
    )
    assert as_int(scan_of) == end_to_end_ms, "the bullet's denominator is not the measured total"
    assert abs(float(scan_pct) - pass_1 / end_to_end_ms * 100) < 0.1


# -- counts of things elsewhere in the tree -----------------------------------


def test_the_ten_minute_index_states_the_number_of_deviation_rows_the_table_has() -> None:
    """57 numbered rows, counted as 56 in the first table a reviewer reads."""
    text = readme_text()
    claimed = as_int(one_match(r"Deviations \((\d+), each with a reason\)", text).group(1))

    header = "| # | Deviation | Rationale |"
    assert header in text, "the Deviations table header has moved or been renamed"
    table = text.split(header, 1)[1].split("\n\n", 1)[0]
    numbers = [int(n) for n in re.findall(r"^\| (\d+) \|", table, re.MULTILINE)]

    # EXACT: both sides live in this one file, so the count and the thing counted
    # move together in a single edit. There is no drift to band -- only a writer
    # adding a row and not touching the index, which is precisely the defect.
    assert numbers == list(range(1, len(numbers) + 1)), "the Deviations rows are not 1..N"
    assert claimed == len(numbers), (
        f"the ten-minute index says {claimed} deviations; the table has {len(numbers)} rows"
    )


def test_the_line_count_the_readme_quotes_for_api_app_is_the_one_wc_l_reports() -> None:
    """"307 lines (`wc -l`, and it moves with any edit)" -- and it had moved, twice.

    The parenthetical predicted the rot and did not prevent it. ``wc -l`` counts
    newlines, so that is what is counted here rather than ``splitlines()``, which
    would disagree by one on a file with no trailing newline.
    """
    text = flat(readme_text())
    claimed = as_int(one_match(r"\*\*(\d+) lines\*\* \(`wc -l`", text).group(1))
    source = (REPO_ROOT / "secure_context_pipeline" / "api" / "app.py").read_text(encoding="utf-8")
    newlines = source.count("\n")
    # EXACT, deliberately, even though the README itself says it "moves with any
    # edit". It is one file, and the claim it supports in gap 8 is that the module
    # is now small enough to read in a sitting -- a claim that a band would let
    # survive the file doubling. The message names the replacement, so correcting
    # it is a one-token edit rather than a measurement.
    assert claimed == newlines, (
        f"api/app.py is {newlines} lines by wc -l; the README says {claimed}"
    )


def test_the_demo_flows_test_count_the_readme_quotes_is_the_one_pytest_collects() -> None:
    """"That file is now 53 tests" -- pytest collects 54.

    Counted by collecting, not by counting ``def test_`` lines: the file is
    parametrised, and a count of definitions would agree with the README for the
    wrong reason.
    """
    text = flat(readme_text())
    claimed = as_int(one_match(r"That file is now (\d+) tests\.", text).group(1))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_demo_flows.py",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-2000:]
    collected = one_match(r"(\d+) tests collected", result.stdout)
    # EXACT: one file, collected rather than counted, and the sentence around it is
    # an argument about how thoroughly demo.py is now tested. A band here would let
    # the file lose a third of its tests without a word changing.
    assert claimed == int(collected.group(1)), (
        f"pytest collects {collected.group(1)} tests from tests/test_demo_flows.py; "
        f"the README says {claimed}"
    )


# -- the four spec-conformance claims section 10, 6 and 7 now carry ------------
#
# These are not arithmetic over the tree the way the block above is; they are
# claims the README makes about what the repository *contains*, each of which was
# either absent or wrong in the direction that costs marks when this pass started.
# The rule is the same one the module docstring states: the expected value comes
# from the thing being described, never from another sentence in the README.


def test_the_fifth_performance_benchmark_is_mapped_rather_than_deferred() -> None:
    """Section 10 used to hand the fifth benchmark back to the reader.

    The row read "Four are automated. **The fifth is a human check.**" and the
    prose under it read "if it is a throughput or concurrency figure, nothing here
    measures it yet". The fifth benchmark is zero PII leakage over 100 automated
    runs on varied fixture documents, and that is exactly what
    ``tests/leakage/test_leakage_harness.py`` does -- so the page was conceding a
    requirement it satisfies. That is the only failure mode of a traceability
    table that costs marks for nothing, which is why it gets its own pin.

    The old hedge is still on the page, once, in quotation marks -- this document
    records what it used to say rather than editing itself silently -- so the check
    is that the quote is *answered* rather than that it is gone. A revert deletes
    the answer, which is what rot looks like here.
    """
    text = flat(readme_text())

    hedge = one_match(r"nothing here measures it yet", text)
    answered = text[hedge.end() : hedge.end() + 200]
    assert "It is not a throughput figure and it is measured" in answered, (
        "section 10 quotes the old hedge about the fifth performance benchmark and no "
        f"longer answers it; what follows the quote is {answered!r}"
    )
    assert "The fifth is a human check" not in text, (
        "the traceability row has gone back to calling the fifth benchmark a human check"
    )

    row = one_match(r"\| \*\*Performance benchmarks \(all 5\)\*\* \|([^|]*\|[^|]*)\|", text)
    body = row.group(1)
    assert "All five are automated" in body, (
        f"the performance-benchmark row no longer claims all five are automated: {body!r}"
    )
    assert "test_no_original_ever_leaves_the_process" in body, (
        "the row claims the fifth benchmark is automated without naming the test that "
        f"automates it, which is the one thing this table exists to require: {body!r}"
    )

    # And the human-check section below it is now singular, so a reader counting
    # rows against the prose gets one answer rather than two.
    assert "### The row a human has to close" in readme_text()
    assert "### The two rows a human has to close" not in readme_text()


def test_the_varied_clause_of_the_fifth_benchmark_is_the_one_the_harness_runs() -> None:
    """"100 runs, 100 distinct seeds, 100 distinct documents, all six pairs".

    The claim that costs marks if it is decorative is *varied*: a harness that ran
    one document a hundred times would satisfy "100 automated test runs" and fail
    the requirement. So the four numbers section 10 pastes are re-derived from the
    harness and the generator rather than read back out of the prose, and the
    documents are actually generated rather than assumed to differ -- three kinds
    times two strategies is a plan, and a plan is not evidence that ``generate``
    honours the seed.

    Imported inside the test: the harness pulls the orchestrator and the fixture
    generator in with it, and this module is otherwise import-cheap.
    """
    from fixtures import generator
    from tests.leakage import test_leakage_harness as harness

    plans = [harness.plan_run(index) for index in range(harness.RUNS)]
    seeds = {seed for seed, _, _ in plans}
    pairs = {(kind, strategy) for _, kind, strategy in plans}
    documents = {generator.generate(seed, kind) for seed, kind, _ in plans}

    measured = (harness.RUNS, len(seeds), len(documents), len(pairs))

    text = flat(readme_text())
    claimed = tuple(
        as_int(g)
        for g in one_match(
            r"# -> (\d+) (\d+) (\d+) (\d+)\b",
            text,
        ).groups()
    )
    # EXACT, and every element is a different failure: the run count, the seed
    # count (one seed reused is one document repeated), the document count (the
    # generator ignoring the seed would show up here and nowhere else), and the
    # (kind, strategy) coverage. The message carries the replacement line.
    assert claimed == measured, (
        f"section 10 pastes `-> {' '.join(str(n) for n in claimed)}` for the varied-fixture "
        f"clause; the harness and the generator produce `-> {' '.join(str(n) for n in measured)}`"
    )

    assert len(documents) == harness.RUNS, (
        f"{harness.RUNS} runs produced only {len(documents)} distinct documents, so the "
        "'varied fixture documents' clause of the fifth benchmark is not satisfied"
    )
    assert pairs == {
        (kind, strategy) for kind in harness.KINDS for strategy in harness.STRATEGIES
    }, f"the run plan does not reach every (kind, strategy) pair: {sorted(pairs)}"


#: Section 6's comparison table, by the row label each line starts with. The
#: README requirement is "a comparison of tokenization vs pseudonymization for at
#: least two entity types", and the table is titled for two -- NAME and DOB -- so
#: a row that discusses only one of them is half a row against a named
#: requirement. Four of the six were NAME-only when this was written.
_COMPARISON_ROW_LABELS = (
    "Reversibility",
    "LLM reasoning utility",
    "Inference surface",
    "Restore robustness",
    "Failure mode",
)


def comparison_rows() -> dict[str, str]:
    """The body of each row of the "NAME and DOB, compared directly" table."""
    text = readme_text()
    start = text.index("### NAME and DOB, compared directly")
    end = text.index("### Graceful degradation", start)
    rows = {}
    for line in text[start:end].splitlines():
        match = re.match(r"\|\s*\*\*([^*]+)\*\*", line)
        if match:
            rows[match.group(1).strip()] = line
    return rows


def test_both_entity_types_the_comparison_table_names_appear_in_every_row() -> None:
    """The table is titled for two entity types and carried one.

    "A comparison of tokenization vs pseudonymization for at least two entity
    types" is a named README requirement. The table that answers it is headed
    "NAME and DOB, compared directly", and four of its six rows carried only NAME
    content while DOB appeared in a single cell -- so the requirement was met by
    the heading rather than by the table.

    Checked per row rather than over the section, because the section-level check
    is the one that passed the whole time: DOB *was* mentioned, once.
    """
    rows = comparison_rows()
    missing = [label for label in _COMPARISON_ROW_LABELS if label not in rows]
    assert not missing, f"section 6's comparison table has lost rows: {missing}"

    for label in _COMPARISON_ROW_LABELS:
        body = rows[label]
        assert "DOB" in body, (
            f"the {label!r} row of section 6's comparison compares the two strategies for "
            "NAME only; the table is titled for NAME *and* DOB and the DOB half is the "
            "requirement being answered"
        )
        assert "NAME" in body, f"the {label!r} row has lost its NAME half"


def test_the_dob_rows_carry_the_two_arguments_that_are_specific_to_a_date() -> None:
    """A DOB half that only restates the NAME half is not a comparison.

    Two arguments belong to DOB and to nothing else on the page, and both were
    missing from the row meant to compare the strategies for it. First, a
    tokenized date is opaque, so the model loses temporal reasoning outright --
    it cannot compute an age or an interval, because the operands are hashes --
    while the Tier-2 shift preserves intervals exactly. That argument existed one
    screen above, in the tier table, and never landed in the comparison. Second,
    the failure-mode row gave only the NAME hazard (a human reads the fake as
    real); the DOB analogue is a clinician acting on a number *derived* from a
    shifted date, which restoration cannot repair because the number is prose.

    Pinned by content rather than by shape, because the shape check above passes
    on a row that says "DOB: likewise" -- and pinned **per cell**, because it also
    passes on a row that makes the whole argument on one side of the comparison.
    Splitting the row is what makes the two halves independent: "the model loses
    temporal reasoning" belongs to tokenization and "intervals are preserved"
    belongs to pseudonymization, and a comparison that puts both in one cell has
    not compared anything.
    """
    rows = comparison_rows()

    def cells(row: str) -> tuple[str, str]:
        parts = [part.strip() for part in row.strip().strip("|").split("|")]
        assert len(parts) == 3, f"expected label + two strategy cells, got {len(parts)}: {row!r}"
        return parts[1], parts[2]

    tokenization, pseudonymization = cells(rows["LLM reasoning utility"])
    assert "temporal reasoning" in tokenization, (
        "the tokenization side of the reasoning-utility row does not say what a tokenized "
        "date costs: the model loses temporal reasoning over it outright"
    )
    assert "age" in tokenization, (
        "the tokenization side does not name the concrete loss -- an age or an interval it "
        "can no longer compute, because the operands are hashes"
    )
    assert "interval" in pseudonymization, (
        "the pseudonymization side of the reasoning-utility row does not mention intervals, "
        "which is the whole Tier-2 argument for shifting a date rather than tokenizing it"
    )

    tokenization, pseudonymization = cells(rows["Failure mode"])
    for needle in ("age", "derived"):
        assert needle in pseudonymization, (
            f"the pseudonymization side of the failure-mode row is missing {needle!r}: the "
            "DOB hazard is a number computed off a shifted date, which restoration cannot "
            "repair because the number is prose rather than a surrogate"
        )
    assert "audited" in tokenization or "visible" in tokenization.lower(), (
        "the tokenization side of the failure-mode row no longer says its failure is the "
        "visible one, which is the contrast the whole row turns on"
    )


def test_the_age_error_rate_the_dob_row_quotes_is_the_one_the_shift_produces() -> None:
    """"45.1% of (DOB, session-shift) pairs change the integer age".

    The sharpest sentence in the new DOB half is a measurement, so it is measured
    here rather than trusted. Re-derived from ``derive_date_shift_days`` itself
    over its whole reachable domain -- not from the formula in its docstring,
    which is the thing the number is a property of.

    The domain is collected by hashing rather than enumerated, because the
    function takes a session key and not a residue; the size is asserted first, so
    an incomplete domain fails loudly instead of silently reporting a percentage
    over part of it. 50,000 draws reach all 541 values in about a tenth of a
    second, against a coupon-collector expectation an order of magnitude below
    that.
    """
    import hashlib
    from datetime import date, timedelta

    from secure_context_pipeline.crypto.keys import derive_date_shift_days

    shifts = {
        derive_date_shift_days(hashlib.sha256(i.to_bytes(8, "big")).digest())
        for i in range(50_000)
    }
    assert len(shifts) == 541, (
        f"only {len(shifts)} of the shift function's 541 reachable values were drawn, so the "
        "percentage below would be measured over part of the domain"
    )

    today = date(2026, 8, 8)

    def age(born: date) -> int:
        return today.year - born.year - ((today.month, today.day) < (born.month, born.day))

    total = 0
    changed = 0
    intervals_held = True
    other = date(2024, 7, 1)
    for offset in range(365):
        born = date(1985, 1, 1) + timedelta(days=offset)
        true_age = age(born)
        for shift in shifts:
            total += 1
            if age(born + timedelta(days=shift)) != true_age:
                changed += 1
            # The other half of the same claim: the interval between two dates
            # *inside* the document is untouched, which is why the row can say the
            # loss is confined to reasoning that reaches outside it.
            shifted_gap = (other + timedelta(days=shift)) - (born + timedelta(days=shift))
            intervals_held = intervals_held and shifted_gap == other - born

    assert intervals_held, "a constant shift moved an interval, which Tier 2 exists to preserve"

    measured = round(100 * changed / total, 1)
    text = flat(readme_text())
    claimed = float(
        one_match(r"\*\*([\d.]+)% of \(DOB, session-shift\) pairs change the integer age\*\*", text)
        .group(1)
    )
    # EXACT to the published precision. The complement is published beside it, so
    # both are checked -- a sentence that gives a rate and its remainder can be
    # half wrong.
    assert claimed == measured, (
        f"the DOB failure-mode row says {claimed}% of (DOB, shift) pairs change the integer "
        f"age; over the shift function's whole domain it is {measured}%"
    )
    complement = float(one_match(r"The other ([\d.]+)% are right by luck", text).group(1))
    assert round(claimed + complement, 1) == 100.0, (
        f"{claimed}% + {complement}% is not 100% -- the DOB row's two rates disagree"
    )


def next_day_plan() -> str:
    """Section 7's day-scoped subsection, which is a named README requirement."""
    text = readme_text()
    start = text.index("### With one more day")
    return text[start : text.index("## 8. Deviations", start)]


def test_section_7_answers_the_next_day_question_its_own_heading_asks() -> None:
    """"What you would build next with an additional day" was unanswered.

    Section 7 is headed "Known gaps & next day" and was a 24-item register with no
    day-scoped statement anywhere in the file -- ``grep -i 'additional day\\|one
    more day'`` returned nothing. A register is not a plan: the requirement asks
    for a selection out of it, in an order, with a cost.

    Shape is checked here and openness in the test below, because the two rot
    differently: this one goes red on a deleted subsection, that one on a plan
    that proposes work already finished.
    """
    plan = next_day_plan()

    picks = re.findall(r"^\d+\. \*\*", plan, re.MULTILINE)
    assert 4 <= len(picks) <= 5, (
        f"the next-day plan names {len(picks)} items; the point of it is a defensible "
        "selection out of the register, and a list of everything is the register again"
    )

    hours = re.findall(r"~(\d+) h\b", plan)
    assert len(hours) == len(picks), (
        f"{len(picks)} items in the next-day plan carry {len(hours)} hour costs; an "
        "unpriced item is not a plan for a day"
    )
    total = sum(int(h) for h in hours)
    claimed_total = NUMBER_WORDS[one_match(r"Roughly ([a-z]+) hours", flat(plan)).group(1)]
    assert claimed_total == total, (
        f"the plan's items add up to {total} hours and the paragraph under them says "
        f"{claimed_total}"
    )

    assert "What I would deliberately not do" in plan, (
        "the next-day plan does not say what it is leaving alone, which is the half a "
        "reviewer uses to judge the half it does"
    )
    excluded = re.findall(r"^- \*\*", plan, re.MULTILINE)
    assert len(excluded) >= 4, (
        f"the plan excludes only {len(excluded)} things explicitly; naming the omissions is "
        "what makes the selection defensible rather than arbitrary"
    )


def test_the_next_day_plan_proposes_only_work_that_is_still_open() -> None:
    """A plan that proposes finished work is worse than no plan.

    Several section 7 items were closed during this build -- gap 8's two
    structural debts are paid and both sides of gap 9's composite-span defect are
    fixed -- so "pick from the list" is not safe on its own. Two checks, and the
    second is the one that binds:

    * every gap the plan cites by number exists in the register and is not one the
      register itself describes as paid;
    * the two claims of openness that are cheap to re-derive are re-derived **from
      the code**, not from the register. If another change closes them, this test
      goes red on the sentence that is now wrong, which is the coupling worth
      having: the README should not survive its own gaps being fixed.
    """
    plan = next_day_plan()
    register = readme_text()[
        readme_text().index("## 7. Known gaps") : readme_text().index("### With one more day")
    ]
    entries = {
        int(match.group(1)): match.group(0)
        for match in re.finditer(
            r"^(\d+)\. \*\*.*?(?=^\d+\. \*\*|\Z)", register, re.MULTILINE | re.DOTALL
        )
    }

    # Scanned from the first numbered pick onwards, not from the top of the
    # subsection: the intro paragraph deliberately names gaps 8 and 9 as *closed*,
    # which is the sentence this test would otherwise read as a proposal.
    proposals = plan[plan.index("\n1. **") :]

    # "gap 4", "gaps 5 and 6", "gaps 13, 16 and 18" -- every run of numbers that
    # follows the word, so a citation cannot hide behind a list separator.
    cited: set[int] = set()
    for run in re.findall(r"gaps?((?:\s+\d+(?:,|\s+and)?)+)", proposals):
        cited |= {int(n) for n in re.findall(r"\d+", run)}
    assert cited, "the next-day plan cites no gap by number, so it cannot be checked at all"

    for number in sorted(cited):
        assert number in entries, (
            f"the next-day plan cites gap {number} and section 7's register has no such item"
        )
        assert "since paid" not in entries[number], (
            f"the next-day plan proposes gap {number}, which the register above it describes "
            "as already paid"
        )

    # The binding half. Pass 3 is the gate's only independent limb; the plan's
    # second item says it covers one of the four blocking types, and that is a
    # property of two constants rather than of this page.
    from secure_context_pipeline.pipeline.egress_gate import (
        _INDEPENDENT_PATTERNS,
        HIGH_SEVERITY_TYPES,
    )

    independent = {entity_type for entity_type, _ in _INDEPENDENT_PATTERNS}
    assert independent < HIGH_SEVERITY_TYPES, (
        "pass 3 now covers every high-severity type, so the next-day plan's second item is "
        "proposing work that is already done -- rewrite it and this assertion together"
    )
    assert len(independent) == 1 and len(HIGH_SEVERITY_TYPES) == 4, (
        f"pass 3 covers {sorted(independent)} of {sorted(HIGH_SEVERITY_TYPES)}; the plan and "
        "section 7 gap 5 both describe it as one of four"
    )

    # And the plan's first item, the same way: the omission it proposes to close
    # is a live default, not a historical one.
    from secure_context_pipeline.store.document_store import _validate_category

    assert _validate_category(None) is None, (
        "an absent doc_category is no longer waved through, so the next-day plan's first "
        "item is proposing a fix that has landed"
    )


#: The two mangling classes section 10's Core 6 row names as newly covered, and
#: the residual it names as still open. Kept as a literal table here rather than
#: parsed out of the row, because the row is the thing under audit -- a claim that
#: supplies its own expected value checks nothing.
_CORE6_RESTORES = (
    "[PHI_NAME_1a2b3c4d]",  # the canonical form, as the control
    "[phi_name_1a2b3c4d]",  # re-cased: lower
    "[Phi_Name_1a2b3c4d]",  # re-cased: title
    "[phi_name_1A2B3C4D]",  # re-cased both ways at once
    "[PHI_NAME_\n1a2b3c4d]",  # a line wrap at the second separator
    "[PHI\n_NAME_1a2b3c4d]",  # ... and at the first
    "[PHI_NAME_ 1a2b3c4d]",  # a plain space where the wrap would be
)

_CORE6_RESIDUAL = "[PHI_NAME_1a2b\n3c4d]"


async def test_the_two_mangling_classes_this_row_names_restore_through_the_real_restorer() -> None:
    """Core 6 claims restoration of mangled forms; this drives the restorer.

    The row was over-claiming until this week: a re-cased token and a token
    wrapped at one of its two ``_`` separators both failed to match ``TOKEN_RE``
    at all, so the surrogate reached the user's answer intact -- the one outcome
    the requirement names in its own words. Both are fixed in ``surrogates.py``,
    and this is the pin that stops the row drifting back into a claim.

    Driven through :class:`Restorer` rather than asserted against ``TOKEN_RE``,
    on purpose. A regex match is not restoration: the restorer has to key on the
    hash, resolve it against the vault, splice the value in and then pass its own
    residual sweep, and the row promises all four. Matching the grammar and
    leaving the token in place would satisfy a regex assertion and fail the
    requirement.

    The residual is asserted in the same breath, because §7 gap 25 states it and a
    gap register that quietly closes is as wrong as one that quietly opens. If a
    later change makes the split hash restore, this test goes red on the entry
    that is now stale rather than letting gap 25 stand as a false concession.
    """
    import tempfile

    from secure_context_pipeline.audit.logger import AuditLogger
    from secure_context_pipeline.config import Settings
    from secure_context_pipeline.deobfuscation.restorer import Restorer
    from tests.test_deobfuscation import SESSION, TOKENS, FakeVault

    value = TOKENS["1a2b3c4d"]

    with tempfile.TemporaryDirectory() as directory:
        audit = await AuditLogger.open(Path(directory) / "audit.db")
        try:
            settings = Settings(
                master_key="A" * 43 + "=",
                anthropic_api_key="sk-ant-not-a-real-key",
                data_dir=Path(directory),
            )
            restorer = Restorer(vault=FakeVault(tokens=TOKENS), settings=settings, audit=audit)

            for form in _CORE6_RESTORES:
                result = await restorer.restore(
                    SESSION, f"The chart lists {form} today.", strategy="tokenization"
                )
                assert result.text == f"The chart lists {value} today.", (
                    f"section 10's Core 6 row claims {form!r} restores; the restorer produced "
                    f"{result.text!r}"
                )
                assert result.restored_count == 1, (
                    f"{form!r} produced {result.restored_count} restorations, not 1"
                )
                assert result.vault_misses == 0, f"{form!r} took a vault miss"

            residual = await restorer.restore(
                SESSION, f"The chart lists {_CORE6_RESIDUAL} today.", strategy="tokenization"
            )
            assert value not in residual.text, (
                f"{_CORE6_RESIDUAL!r} now restores, so §7 gap 25 is a false concession: the "
                "gap entry and section 10's Core 6 residual sentence both need rewriting"
            )
        finally:
            await audit.close()


def test_the_core_6_row_names_the_residual_it_still_has() -> None:
    """A traceability row that lists only its wins is the failure this table exists for.

    Cheap, and it is the half a rewrite loses first: the row can name two closed
    classes and drop the sentence pointing at the one that is open, and every
    other test in this file would still pass.
    """
    text = flat(readme_text())
    row = one_match(r"\| \*\*Core 6\*\* — ([^|]*\|[^|]*\|[^|]*)\|", text).group(1)

    proof = "test_the_two_mangling_classes_this_row_names_restore_through_the_real_restorer"
    assert proof in row, (
        "the Core 6 row claims the two newly covered mangling classes without citing the test "
        f"that drives them through the restorer: {row!r}"
    )
    assert "gap 25" in row, (
        "the Core 6 row no longer points at the residual it still has, which is the sentence "
        f"that keeps it a result rather than a claim: {row!r}"
    )


def defined_tests() -> dict[str, set[str]]:
    """``test_name -> {relative path of every file defining it}``."""
    found: dict[str, set[str]] = {}
    for path in sorted((REPO_ROOT / "tests").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        for name in re.findall(r"^(?:async )?def (test_\w+)", source, re.MULTILINE):
            found.setdefault(name, set()).add(str(path.relative_to(REPO_ROOT / "tests")))
    return found


def traceability_section() -> str:
    text = readme_text()
    return text[
        text.index("## 10. Requirements traceability") : text.index("## 11. Pre-submission")
    ]


def test_every_test_section_10_names_exists_and_lives_where_the_row_says() -> None:
    """The third column is the whole point of the table, and it is unchecked prose.

    Section 10 promises "the test that proves it" for every requirement, and the
    proof is a *name* -- so a renamed, deleted or relocated test turns a proving
    row into a citation of nothing, with the row still reading as evidence. Two
    failures, checked separately because they look identical to a reader and
    different to a runner:

    * **Existence.** Every backticked ``test_*`` identifier in the section is
      defined somewhere under ``tests/``.
    * **Attribution.** Rows use a ``file.py::name`` then a run of bare ``::name``
      continuations, which inherit the file. Two of them had drifted onto the
      wrong file: ``::test_the_byte_limb_and_the_query_limb_of_the_audit_scan_
      see_different_things`` and ``::test_the_round_trip_expectation_does_not_
      share_the_restorer_s_blind_spots`` both sat after ``test_egress_gate.py``
      and both live in ``leakage/test_leakage_harness.py``. A reviewer following
      the citation opens the wrong file and finds nothing, which is worse than an
      empty cell because it looks like a result.
    """
    section = traceability_section()
    defined = defined_tests()

    named = set(re.findall(r"`(?:[\w/]+\.py)?(?:::)?(test_\w+)`", section))
    missing = sorted(name for name in named if name not in defined)
    assert not missing, (
        f"section 10 cites {len(missing)} test(s) that are not defined anywhere under tests/: "
        f"{missing}"
    )

    # Attribution. Walk the section in order so a bare `::name` inherits the last
    # *test* file named before it -- which is exactly what a reader does.
    current: str | None = None
    wrong: list[str] = []
    for match in re.finditer(r"`([\w/]*test_\w+\.py)(?:::(test_\w+))?`|`::(test_\w+)`", section):
        if match.group(1):
            current = match.group(1)
        name = match.group(2) or match.group(3)
        if name is None:
            continue
        assert current is not None, f"`::{name}` appears before any test file is named"
        if current not in defined[name]:
            wrong.append(f"{current}::{name} is actually in {sorted(defined[name])}")
    detail = "\n  ".join(wrong)
    assert not wrong, f"section 10 attributes tests to files that do not hold them:\n  {detail}"


def test_the_tier_table_in_section_6_lists_every_entity_the_registry_tiers() -> None:
    """The sibling of the comparison-table gap: a table titled for a set it under-covers.

    Section 6's tier table is the per-entity justification Core 3 is graded on, and
    it is hand-written prose beside a config file. An entity added to
    ``entities.yaml`` with a ``tier:`` and not added here is a justification the
    reviewer is told exists and cannot find; an entity listed here and deleted
    there is a justification for nothing.

    Swept rather than spot-checked when the DOB half of the comparison table was
    filled in, and this one was already correct -- 18 tiered entities in four rows,
    exact both ways. It is pinned so it stays that way, because the failure is
    silent in both directions and the file it drifts from is owned by a different
    part of this build.

    ``CASE_STRATEGY`` and ``PRIVILEGED_MARKER`` carry no ``tier:`` -- they are the
    two engine-level actions the bullets under the table cover -- so they are
    excluded here and their presence in those bullets is asserted instead.
    """
    import yaml

    spec = yaml.safe_load((REPO_ROOT / "entities.yaml").read_text(encoding="utf-8"))
    entities = spec.get("entities", spec)
    by_tier: dict[int, set[str]] = {}
    untiered: set[str] = set()
    for name, body in entities.items():
        tier = body.get("tier") if isinstance(body, dict) else None
        if tier is None:
            untiered.add(name)
        else:
            by_tier.setdefault(int(tier), set()).add(name)

    text = readme_text()
    table = text[text.index("| Tier | Entities |") : text.index("**Rejected alternatives")]
    listed: dict[int, set[str]] = {}
    for row in re.finditer(r"^\| \*\*(\d+) — [^*]+\*\* \| ([^|]+) \|", table, re.MULTILINE):
        listed[int(row.group(1))] = {name.strip() for name in row.group(2).split(",")}

    assert listed.keys() == by_tier.keys(), (
        f"section 6's tier table has rows for tiers {sorted(listed)}; entities.yaml uses "
        f"{sorted(by_tier)}"
    )
    for tier in sorted(by_tier):
        assert listed[tier] == by_tier[tier], (
            f"section 6's Tier {tier} row lists {sorted(listed[tier])}; entities.yaml tiers "
            f"{sorted(by_tier[tier])} at that level"
        )

    for name in sorted(untiered):
        assert f"`{name}`" in text, (
            f"{name} carries no tier, so the engine-level actions under the tier table are the "
            "only place it is justified -- and it is not named there"
        )


def test_the_formatter_divergence_section_1_states_is_the_one_ruff_reports() -> None:
    """"37 files would be reformatted (55 already formatted)" -- it is 39 and 53.

    The only number in section 1's tooling block that had no guard, and it is
    quoted three times: in the `ruff` paragraph, in the sentence that calls the
    divergence the one thing `ruff` is not gating, and in section 7's next-day
    plan as the thing not worth a reviewer's attention. All three are compared
    against one measurement here, so they cannot drift apart from each other the
    way the boundary counts once did.

    Measured by running the formatter, which is the one shape of check this module
    otherwise avoids -- the long-line counts are counted by hand rather than asked
    of ``ruff`` precisely so the paragraph is not checked against the tool it
    describes. The exception is deliberate and narrow: this claim *is* "``ruff
    format --check`` prints these two integers", so there is no independent
    derivation to prefer, and reimplementing the formatter to get one would be
    absurd. Same precedent as the demo-flows count, which collects with ``pytest``
    because the claim is about what ``pytest`` collects.
    """
    result = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--check", "."],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    reformat, formatted = (
        as_int(g)
        for g in one_match(
            r"(\d+) files? would be reformatted, (\d+) files? already formatted",
            result.stdout + result.stderr,
        ).groups()
    )

    text = flat(readme_text())
    claimed_reformat, claimed_formatted = (
        as_int(g)
        for g in one_match(
            r"reports \*\*(\d+) files\*\* that would be reformatted \((\d+) already formatted\)",
            text,
        ).groups()
    )
    # EXACT, for the reason every other number in this block is: it is quoted as a
    # measurement inside a section headed "output from this repository, not an
    # estimate", and the failure message carries the replacement.
    assert (claimed_reformat, claimed_formatted) == (reformat, formatted), (
        f"`ruff format --check .` reports {reformat} files would be reformatted and "
        f"{formatted} already formatted; section 1 says {claimed_reformat} and "
        f"{claimed_formatted}"
    )

    restated = {as_int(n) for n in re.findall(r"(\d+)-file `?ruff format`? divergence", text)}
    restated |= {as_int(n) for n in re.findall(r"remaining (\d+)-file formatter divergence", text)}
    assert restated, "the two sentences that restate the formatter divergence have been reworded"
    assert restated == {reformat}, (
        f"the formatter divergence is restated as {sorted(restated)} elsewhere on the page "
        f"and measured at {reformat}"
    )


def test_the_readme_does_not_disclose_a_failing_test_while_the_suite_is_green() -> None:
    """A stale "one test is failing" disclosure is worse than no disclosure.

    Section 1 used to carry a paragraph naming
    `test_the_page_serves_its_own_favicon_so_a_load_logs_no_console_error` as red,
    telling the reader to "expect `2688 passed, 1 failed, 1 skipped`" and to treat
    anything else as a finding. The test was then rewritten for the real
    same-origin `ui/favicon.png` and went green -- and the paragraph stayed. So the
    page instructed a reviewer to expect a failure that could not occur, and the
    honest-disclosure paragraph had become the least accurate thing on the page.

    Nothing caught it. The sibling assertion `passed + skipped == collected`
    already implied a green tree, but arithmetic in one section cannot contradict
    prose in another loudly enough to fail a suite -- so the two drifted apart for
    as long as nobody re-read them together. This test is that re-reading.

    It is deliberately about the SHAPE of the claim rather than about the favicon:
    any future "expect N passed, M failed" is caught the moment the failure it
    describes is fixed. Which is the moment it becomes a lie, and also exactly the
    moment everyone's attention has moved on.

    **What it does not catch, measured rather than supposed.** This test is ONE
    REGEX -- ``\\d+ passed, \\d+ failed, \\d+ skipped`` -- and on the tree this
    paragraph was written for it had **0** matches, while the prose spelling of the
    same defect had **1**: a Deviations row asserting a named test was "**red on
    this tree**" when that test passed, beside a claim that a tracked file was
    "**untracked**" when ``git ls-files`` listed it. This guard was green the whole
    time. That is the third recurrence of this defect class in this project, and
    each recurrence used different words, which is the actual lesson: a disclosure
    can be stale in any spelling, and a tripwire on one spelling only ever catches
    the spelling that was already fixed.

    So it is kept -- the pasted-summary form is real and cheap to check -- and the
    two rigs below check the *fact* instead of the phrasing:
    :func:`test_no_test_the_readme_calls_red_actually_passes` runs the tests the
    page names as failing, and
    :func:`test_no_path_the_readme_calls_untracked_is_actually_tracked` asks git
    about the paths it names as absent. Those two are fact checks; this one is a
    shape check, and saying which is which is the point.
    """
    text = flat(readme_text())

    live_failure_claims = re.findall(r"\d+ passed, (\d+) failed, \d+ skipped", text)
    disclosed = [int(count) for count in live_failure_claims]

    assert not any(count > 0 for count in disclosed), (
        "the README tells a reviewer to expect a failing suite "
        f"({live_failure_claims}), but `passed + skipped == collected` is asserted "
        "in this same file, so the tree is green. Delete the disclosure with the "
        "fix that made it stale -- a reviewer who trusts it will discount a real "
        "regression as the one they were told to expect."
    )


# -- stale disclosures, checked against the tree rather than against a spelling --
#
# Three times now this project has shipped a README sentence that disclosed a
# defect which no longer existed. Each time the sentence was written honestly, the
# defect was then fixed, and the sentence stayed. Each time the guard that existed
# was a tripwire on the *previous* spelling and stayed green.
#
# So the unit of checking here is a CLAIM, not a line and not a phrase: the README
# is cut into blocks (paragraph, table row, list item), a present-tense claim of
# brokenness is located inside one, and the subject of that claim -- a backticked
# test identifier, a backticked path -- is taken from the text immediately around
# it. Then the tree is asked. The two rigs below share that machinery and differ
# only in what they ask.

#: How far from the claim phrase its subject may sit, in characters, inside the
#: same block. Derived, not guessed: on the tree these were written for, the true
#: claim's subject sat 1 and 88 characters before its phrase, and the nearest
#: false-positive subject -- four test names in a long paragraph whose "stays
#: broken" is about a *value* -- sat 503. Anything from ~120 to ~450 separates the
#: two; 200/120 is the middle of that gap rather than either edge of it.
_CLAIM_LOOKBEHIND = 200
_CLAIM_LOOKAHEAD = 120

#: Present-tense assertions that something is failing NOW. Deliberately excludes
#: the conditional and past forms this document is full of and should stay full of:
#: "goes red", "would go red", "turns red rather than unnoticed" are descriptions
#: of a guard working, and "they were untracked" is a record of a fixed defect.
#: Only a claim about the CURRENT tree can be stale, so only those are collected.
_RED_CLAIM = re.compile(
    r"\b(?:is|are)\s+(?:\*\*)?(?:still\s+|currently\s+)?(?:\*\*)?(?:red|failing|broken)\b"
    r"|\b(?:remains?|stays?)\s+(?:\*\*)?(?:red|failing|broken)\b"
    r"|\b(?:still|currently)\s+(?:\*\*)?(?:red|failing|fails|failed|broken)\b"
    r"|\b(?:red|failing|fails|failed|broken)\s+(?:\*\*\s*)?on this tree\b"
    r"|\bknown\s+(?:failure|to\s+fail)\b"
    r"|\bexpected?\s+(?:it\s+)?to\s+fail\b"
    r"|\b\d+\s+failed\b",
    re.IGNORECASE,
)

#: The same, for a claim that something is not in git.
_UNTRACKED_CLAIM = re.compile(
    r"\b(?:is|are|remains?|stays?)\s+(?:\*\*)?(?:still\s+)?(?:\*\*)?"
    r"(?:untracked|uncommitted"
    r"|not\s+(?:\*\*)?(?:tracked|committed|in\s+git|under\s+version\s+control))\b"
    r"|\b(?:still|currently)\s+(?:\*\*)?(?:untracked|uncommitted)\b",
    re.IGNORECASE,
)

#: A backticked test identifier, with or without a file prefix:
#: ``test_x``, ``test_file.py::test_x``, ``tests/leakage/test_h.py::test_x``.
_TEST_IDENT = re.compile(r"`([\w/]*\.py)?(?:::)?(test_\w+)`")

#: A backticked path: anything with a ``/`` or a dot in it. Wider than it needs to
#: be on purpose -- a non-path caught here is discarded by git, whereas a path
#: missed here is a claim nobody checks.
_PATH_IDENT = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_./-]*[/.][A-Za-z0-9_./-]*)`")


def readme_claim_units(text: str) -> list[str]:
    """The README cut into the blocks a single claim can live in.

    Paragraph, table row, list item -- whitespace-collapsed, so a claim survives
    the hard wrap. Sentence splitting was tried first and is wrong here: this
    document writes ``i.e.`` mid-sentence and cites ``file.py::test_name``, so a
    split on ``.`` cuts claims off from their own subjects. A line split is wrong
    for the same reason at 100 columns.
    """
    units: list[str] = []
    for block in re.split(r"\n\s*\n", text):
        stripped = block.lstrip()
        if stripped.startswith("|"):
            units.extend(" ".join(row.split()) for row in block.splitlines())
        elif re.match(r"[-*+] |\d+\. ", stripped):
            units.extend(
                " ".join(part.split())
                for part in re.split(r"\n(?=\s*(?:[-*+] |\d+\. ))", block)
            )
        else:
            units.append(" ".join(block.split()))
    return [unit for unit in units if unit]


def _subjects_near(
    unit: str, phrase: re.Match[str], pattern: re.Pattern[str]
) -> list[tuple[str, ...]]:
    """Every ``pattern`` group-tuple within the claim window around ``phrase``."""
    found = []
    for match in pattern.finditer(unit):
        distance = phrase.start() - match.end()
        if -_CLAIM_LOOKAHEAD <= distance <= _CLAIM_LOOKBEHIND:
            found.append(match.groups())
    return found


def claimed_red_tests(text: str) -> dict[str, str]:
    """``test name -> the claim`` for every test the README says is failing now."""
    claims: dict[str, str] = {}
    for unit in readme_claim_units(text):
        for phrase in _RED_CLAIM.finditer(unit):
            for _file, name in _subjects_near(unit, phrase, _TEST_IDENT):
                claims.setdefault(name, unit)
    return claims


def claimed_untracked_paths(text: str) -> dict[str, str]:
    """``path -> the claim`` for every path the README says git does not hold."""
    claims: dict[str, str] = {}
    for unit in readme_claim_units(text):
        for phrase in _UNTRACKED_CLAIM.finditer(unit):
            for (path,) in _subjects_near(unit, phrase, _PATH_IDENT):
                claims.setdefault(path, unit)
    return claims


#: The two rigs must not run themselves: a README that named one of them as red
#: would otherwise recurse until the process died.
_SELF = (
    "test_no_test_the_readme_calls_red_actually_passes",
    "test_no_path_the_readme_calls_untracked_is_actually_tracked",
)

#: Ceiling on how many node ids one run will execute. A stale-disclosure paragraph
#: names one or two tests; a page naming twenty has a different problem, and this
#: file should say so rather than turn into a suite runner.
_MAX_RED_CLAIMS = 8


def _run_node_id(node_id: str) -> int:
    """Run one test in its own pytest and return the exit code."""
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", node_id],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    ).returncode


#: Canned claims the extractors must still find. These are the tripwire on the
#: instrument itself, and they are not decoration: both rigs return quietly when
#: they find no claim, which is correct on a clean README and indistinguishable
#: from a regex that has stopped matching. This file already learned that lesson
#: once -- ``one_match`` exists because an anchor that silently stops matching turns
#: a loop over zero matches into a vacuous pass -- and a rig whose whole job is to
#: catch a claim is worth exactly nothing the day it stops recognising one.
_RED_PROBE = "`tests/nowhere.py::test_probe_the_red_claim_extractor` is still failing today."
_UNTRACKED_PROBE = "The file `probe/only/for/the/extractor.txt` is untracked as this is written."


def check_no_stale_red_test_claim(text: str) -> None:
    """The rig, as a function of the text, so it can be exercised on a synthetic one."""
    assert "test_probe_the_red_claim_extractor" in claimed_red_tests(_RED_PROBE), (
        "the red-claim extractor no longer recognises a plainly-worded claim, so this "
        f"rig now passes on every README. Probe: {_RED_PROBE!r}"
    )

    claims = claimed_red_tests(text)
    if not claims:
        return
    assert len(claims) <= _MAX_RED_CLAIMS, (
        f"the README names {len(claims)} tests as currently failing: {sorted(claims)}. "
        "That is not a disclosure, it is a broken tree -- fix it or stop shipping it"
    )

    defined = defined_tests()
    still_green: list[str] = []
    uncited: list[str] = []
    for name, claim in sorted(claims.items()):
        if name in _SELF:
            continue
        if name not in defined:
            uncited.append(f"{name}: named as failing, defined in no file under tests/")
            continue
        node_id = f"tests/{sorted(defined[name])[0]}::{name}"
        code = _run_node_id(node_id)
        if code == 0:
            still_green.append(f"{node_id} PASSES; the README says: {claim[:220]!r}")
        elif code == 5:
            uncited.append(f"{node_id}: collected nothing, so the citation is dead")

    assert not still_green, (
        "the README discloses a failing test that is not failing:\n  "
        + "\n  ".join(still_green)
        + "\n\nA disclosure outlives its defect by default -- the fix lands, the "
        "sentence stays, and a reviewer discounts the next real regression as the "
        "one they were told to expect. Delete the disclosure with the fix."
    )
    assert not uncited, "the README calls a test red and the citation does not resolve:\n  " + (
        "\n  ".join(uncited)
    )


def check_no_stale_untracked_claim(text: str) -> None:
    """As above, for "this path is not in git"."""
    assert "probe/only/for/the/extractor.txt" in claimed_untracked_paths(_UNTRACKED_PROBE), (
        "the untracked-claim extractor no longer recognises a plainly-worded claim, so "
        f"this rig now passes on every README. Probe: {_UNTRACKED_PROBE!r}"
    )

    claims = claimed_untracked_paths(text)
    if not claims:
        return
    tracked: list[str] = []
    for path, claim in sorted(claims.items()):
        listed = subprocess.run(
            ["git", "ls-files", "--", path],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if listed.returncode == 0 and listed.stdout.strip():
            names = listed.stdout.split()
            tracked.append(
                f"{path} IS tracked ({len(names)} file(s), e.g. {names[0]}); "
                f"the README says: {claim[:220]!r}"
            )

    assert not tracked, (
        "the README tells a reviewer a path is missing from git, and git has it:\n  "
        + "\n  ".join(tracked)
        + "\n\nThis is the same defect class as a stale red-test disclosure and it "
        "shipped in the same paragraph: the file was committed and the sentence "
        "warning that a clean clone would not have it was left behind."
    )


def test_no_test_the_readme_calls_red_actually_passes() -> None:
    """Every test the README names as currently failing is run, and must fail.

    The first of the two rigs that replace a vocabulary tripwire with a fact. It
    exists because the tripwire beside it -- one regex on ``N passed, M failed, K
    skipped`` -- had **0** matches on a tree whose README asserted, in prose,
    ``tests/test_ui_behaviour.py::test_the_page_serves_its_own_favicon_so_a_load_
    logs_no_console_error`` was "**red on this tree**". That test passed. The
    guard was green.

    **What binds it:** the node id is extracted from the page and *executed*. There
    is no shared helper, no shared regex and no restatement between the claim and
    the check -- the README supplies the subject and pytest supplies the verdict,
    which is the one arrangement in this file where the two sides cannot rot
    together. A dead citation (nothing collected) fails too, because a reviewer
    following it finds nothing either way.

    **What it does not catch:** a red claim written without a backticked test
    identifier ("the favicon test is red"), or one phrased so it reads as a future
    or hypothetical failure. The phrase list is present-tense-only by design --
    "goes red", "would go red" and "was red" are how this document correctly
    describes guards working and defects fixed, and matching those would make the
    rig fire on every honest paragraph on the page. So this catches a stale
    disclosure *with a subject*, which is what all three recurrences were.
    """
    check_no_stale_red_test_claim(readme_text())


def test_no_path_the_readme_calls_untracked_is_actually_tracked() -> None:
    """Every path the README says git does not hold is put to ``git ls-files``.

    The sibling defect, and it shipped in the same Deviations row as the one above:
    "``secure_context_pipeline/ui/favicon.png`` is **untracked** as this row is
    written -- the file exists in the working tree and matches no ignore rule, and
    until it is committed a clean clone is back to the 404 this row closes." The
    file was tracked. This project has already been bitten once by the *opposite*
    error -- an unanchored ``data/`` in ``.gitignore`` silently untracking the two
    gazetteers a clean clone needs -- so a sentence about what a clean clone gets
    is load-bearing here, and a wrong one is worse than none.

    Asked of ``git ls-files -- <path>`` rather than ``--error-unmatch`` so a claim
    about a *directory* is answered too: ``--error-unmatch`` is a per-pathspec
    check, while a non-empty listing means "git holds something here" for a file
    and a tree alike.

    **What it does not catch:** the reverse claim -- "this file IS tracked" when it
    is not -- which needs no rig, because a missing file fails the tests that read
    it. And a past-tense record ("they were untracked, and a fresh clone could not
    start") is deliberately not matched: that is history, and history does not go
    stale.
    """
    check_no_stale_untracked_claim(readme_text())
