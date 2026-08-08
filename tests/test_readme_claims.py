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
  ``--cov`` run section 1 currently pastes -- and the exclusion set it depends on
  has its own tripwire in
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
"""

from __future__ import annotations

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

    A test cannot run the suite from inside the suite, so this is a tripwire on
    the vocabulary a carve-out needs rather than a proof that the suite is green;
    the proof is the reviewer's own run. It bites on the exact shape that was
    wrong: an exception taken out of the result section 1 reports.
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
    # (4778-61+1216-56)/(4778+1216) = 98.0%, which coverage reports as 98%; on the
    # earlier run this comment was written against, (4511-65+1126-57)/(4511+1126) =
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
    assert pasted in observed, (
        f"the pasted block reports {pasted} surrogates round-tripped, which is not one of the "
        f"{observed} the paragraph below says it observed. A tally that reproduces on no run "
        "does not belong in a block headed 'output from this repository, not an estimate' -- "
        "paste a line a run actually printed and add its value to the list"
    )
    assert originals == 2981, (
        f"the originals tally is {originals}, not the 2981 that came back identical on all four "
        "runs. Unlike the surrogate count this one is deterministic, so a change here is a "
        "change in what the detector plants or finds, and is a finding rather than an edit"
    )


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

    # EXACT on the cross-references, BANDED only where the README rounds. The bench
    # figures are a pasted measurement, not a re-derivation, so nothing here drifts
    # under a later commit: every assertion reads two places in this one file and
    # compares them. The two tolerances (<1 point, <0.1 point) are the rounding the
    # prose itself applies -- "~43%" and "4.3%" -- not slack.
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
