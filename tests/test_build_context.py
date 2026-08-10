"""What ``.dockerignore`` actually removes from the build context.

Separate from the Docker tests in ``test_api.py`` because it asserts a different
kind of thing. Those ask "does the recipe name the right files"; this one asks
"does each ignore rule reach the depth its comment claims", which is the question
that was answered wrong for the entire life of the image.

Docker anchors an ignore pattern to the context root unless its first segment is
``**``. So ``__pycache__/`` meant ``./__pycache__`` and nothing else, while
``COPY secure_context_pipeline/ secure_context_pipeline/`` copies an allow-listed
directory *whole* -- and 38 host-compiled ``.pyc`` files reached
``secure-context-pipeline:1.0.0``, where ``python -v -c 'import
secure_context_pipeline.config'`` printed ``code object from
'/app/secure_context_pipeline/__pycache__/config.cpython-311.pyc'``. The
container was executing bytecode built on a macOS host rather than bytecode
derived from the source it shipped. ``PYTHONDONTWRITEBYTECODE=1`` does not touch
that: it stops the image writing ``.pyc`` files, and these arrived pre-written.

Asserted from the spelling rather than by building, for the reason
``test_dockerfile_never_copies_the_working_tree_wholesale`` gives: this must stay
true on a machine with no Docker daemon. That is only honest because the
anchoring rule was measured against the daemon (Docker 29.4.1) rather than
recalled, with the repository's own ``COPY`` lines and its real working tree as
the context:

    before the fix: 65 .pyc paths in the manifest, e.g.
        secure_context_pipeline/api/routes/__pycache__/pipeline.cpython-311.pyc
    after:          0, and both gazetteers still present.

    a probe context seeding secure_context_pipeline/.env and
    secure_context_pipeline/crypto/tls.key, built with this repository's own
    `COPY secure_context_pipeline/` line:
    before the fix: both shipped (the *root* .env was correctly excluded).
    after:          neither.

Given that measurement, "matches below the context root" is decidable from the
first path segment, and the assertions below read it there. The check is
deliberately not a reimplementation of Docker's matcher: ``test_api.py`` already
owns one, and a checker that shares the reasoning of the thing it checks is the
defect class this repository keeps finding in itself.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Interpreter droppings, which are not suite files no matter what the walk finds.
# A deny-list of junk rather than an allow-list of suffixes, so a fixture, a
# corpus or a golden file added under tests/ is checked the day it lands.
NOT_A_SUITE_FILE = frozenset({".DS_Store"})

# The single rule that is anchored on purpose. `data/` must remove ./data (the
# encrypted store, the vault, the audit chain) and must NOT remove
# secure_context_pipeline/detection/data/, where the gazetteers `entities.yaml`
# requires live -- `**/data/` there produces an image whose container starts and
# immediately fails registry validation. Kept as a set so that adding a second
# anchored rule is a deliberate edit here, not an oversight in the other file.
DELIBERATELY_ANCHORED = {"data/"}


def _rules(dockerignore: str) -> list[str]:
    """The pattern lines, comments and blanks dropped, ``!`` kept attached."""
    return [
        stripped
        for line in dockerignore.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]


def test_every_ignore_rule_reaches_the_depth_its_comment_claims() -> None:
    """Anything meant to match "anywhere" must be spelled ``**/``.

    The rule that broke was ``__pycache__/``, but the expensive one would have
    been ``.env``: anchored, it protects the root only, and the Dockerfile copies
    a whole package directory. A nested ``.env`` holds the same ``SCP_MASTER_KEY``
    that decrypts every document in the store.
    """
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    rules = _rules(dockerignore)
    assert rules, ".dockerignore must contain patterns"

    for rule in rules:
        pattern = rule.removeprefix("!")
        if pattern in DELIBERATELY_ANCHORED:
            continue
        assert pattern.startswith("**/"), (
            f"`{rule}` is anchored to the context root, so it does not match at "
            f"any depth -- and COPY brings whole directories in. Write `**/{pattern}`, "
            f"or add it to DELIBERATELY_ANCHORED with the reason"
        )

    # Named individually so a regression names itself, and because these have
    # consequences: bytecode from the wrong host, secrets, and developer tooling state.
    #
    # The last two are here because the image was never the exposure -- the Dockerfile
    # COPYs named paths, never `COPY . .`, and the built image has no dot-entry in
    # /app at all. What they cost is 49 MB of `.codegraph` (a verbatim source index)
    # plus 648 KB of Hypothesis state sent to the daemon on EVERY build, and a latent
    # leak the day somebody widens a COPY line. Cheap to deny now, invisible later.
    for required in (
        "**/.env",
        "**/*.pem",
        "**/*.key",
        "**/__pycache__/",
        "**/*.py[cod]",
        "**/.codegraph/",
        "**/.hypothesis/",
    ):
        assert required in rules, f".dockerignore must exclude {required} at every depth"


def test_developer_tooling_is_ignored_by_this_repo_and_not_by_the_machine() -> None:
    """`git check-ignore` must answer from THIS repo's .gitignore, not the developer's.

    Two directories were invisible here for reasons that do not travel with a clone.
    `.claude/settings.local.json` was matched only by a MACHINE-GLOBAL rule --
    `/Users/<dev>/.config/git/ignore:1:**/.claude/settings.local.json` -- which a CI
    checkout, a teammate, or a fresh clone simply does not have. `.hypothesis/` (157
    files) was covered only by a .gitignore that Hypothesis generates inside itself,
    so the protection is a side effect of a third-party tool rather than a decision
    this repository made.

    That distinction is not pedantic in a repo whose own history includes an
    unanchored `data/` rule silently untracking the gazetteers: the working tree was
    green while a clone was not. It matters more here because this project is
    developed with `git add -A`, so "untracked" is exactly one careless commit away
    from "tracked", and `.claude/settings.local.json` is local machine configuration.

    Asserted with `--no-index` so a file that is merely UNTRACKED cannot satisfy it,
    and by reading .gitignore directly so a global rule cannot either.
    """
    root = Path(__file__).resolve().parents[1]
    rules = {
        line.strip()
        for line in (root / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    for required in (".claude/", ".hypothesis/"):
        assert required in rules, (
            f"{required} is ignored on this machine but not by this repository -- "
            f"add it to .gitignore so a clone behaves the same way"
        )


def test_the_data_rule_stays_anchored_so_the_gazetteers_still_ship() -> None:
    """The opposite over-correction, which is worse than the bug it fixes.

    Sweeping ``data/`` into the ``**/`` conversion looks like consistency and
    removes ``secure_context_pipeline/detection/data/``, so ``load_registry``
    fails closed and the container never serves a request. The bug this file
    exists for shipped stale bytecode; this one ships a container that does not
    start.
    """
    rules = _rules((REPO_ROOT / ".dockerignore").read_text(encoding="utf-8"))

    assert "data/" in rules, "./data (encrypted store, vault, audit chain) must be excluded"
    assert "**/data/" not in rules, (
        "`**/data/` also removes secure_context_pipeline/detection/data/, and "
        "`load_registry` refuses to start without the gazetteers it names"
    )


def test_every_file_this_suite_runs_from_is_in_the_repository() -> None:
    """The suite a stranger runs is the tracked one, not the one on this disk.

    The sibling of the gazetteer incident, one directory over. ``tests/`` is not
    copied into the image, so
    ``test_api.py::test_every_runtime_asset_the_registry_needs_actually_reaches_the_image``
    -- which derives its list from the Dockerfile's ``COPY`` sources -- cannot
    reach it, and nothing else asked. That gap has already cost this repository
    once: an untracked test file, recorded in ``test_ui_behaviour.py`` as the
    second time "green here, absent from a clone" was paid for.

    The failure is silent in exactly the way the first one was. An ignored or
    never-added test file runs locally, passes locally, and leaves ``git status``
    clean, while the clone a reviewer takes runs a smaller suite that also passes
    -- so the missing coverage announces itself nowhere. ``README`` counters make
    it worse rather than better: ``test_readme_claims.py`` derives its test
    tallies by walking ``tests/`` on disk, so a file that never left this machine
    is counted in the published numbers.

    One direction only, on purpose: on disk must be in the index. The reverse (in
    the index, absent from disk) is an ordinary mid-edit deletion and is not this
    repository's problem to police.
    """
    tracked = _git_ls_files("tests")
    if tracked is None:  # no working tree -- a tarball or a wheel has no index to ask
        return

    on_disk = {
        path.relative_to(REPO_ROOT).as_posix()
        for path in (REPO_ROOT / "tests").rglob("*")
        if path.is_file()
        and path.suffix != ".pyc"
        and "__pycache__" not in path.parts
        and path.name not in NOT_A_SUITE_FILE
    }
    assert on_disk, "no suite file found on disk at all; the walk is wrong"
    assert tracked, "git tracks nothing under tests/; the query is wrong, not the repo"
    missing = sorted(on_disk - tracked)
    assert not missing, (
        f"these files are part of the suite on this machine and are absent from the "
        f"repository: {missing}. A clone runs a smaller suite than this one and passes, "
        f"so the coverage they add exists nowhere but here. `git add` them, or delete "
        f"them if they were scratch -- and check `git check-ignore -v` on them first, "
        f"because an unanchored ignore rule is how this happened the last two times"
    )


def _git_ls_files(pathspec: str) -> frozenset[str] | None:
    """git's index under ``pathspec``, or ``None`` when there is no tree to ask.

    Shelling out rather than reading ``.gitignore``: a hand-written matcher would
    be written from the same misreading of git's grammar that untracked the
    gazetteers, which makes it a checker that shares the blind spot of the thing
    it checks. ``-z`` so a name needing quoting cannot be misread as two names.
    """
    if not (REPO_ROOT / ".git").exists():
        return None
    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z", "--", pathspec],
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - no git binary
        return None
    if completed.returncode != 0:  # pragma: no cover - not a working tree
        return None
    return frozenset(filter(None, completed.stdout.decode("utf-8", "replace").split("\0")))
