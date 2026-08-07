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

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

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

    # Named individually so a regression names itself, and because these five are
    # the ones with consequences: bytecode from the wrong host, and secrets.
    for required in ("**/.env", "**/*.pem", "**/*.key", "**/__pycache__/", "**/*.py[cod]"):
        assert required in rules, f".dockerignore must exclude {required} at every depth"


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
