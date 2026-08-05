"""De-obfuscation robustness (build doc sections 9.7, 10.7).

The unit under test is the last stage before a human reads the answer, so these
tests are organised around the two ways it can fail a user:

* it fails to restore something the model mangled -- the user sees a token; or
* it "restores" something it should not, or lets a token slip through -- the
  post-restore assertion is what makes that loud instead of silent.

The vault is faked here on purpose. ``FakeVault`` implements exactly the three
frozen methods the real ``SessionVault`` exposes, so a restorer bug cannot hide
behind a vault bug (and vice versa); the real vault has its own property tests in
``tests/test_vault.py``. The audit log, by contrast, is the *real* one: "emits a
VAULT_MISS event" is only worth asserting against the real hash-chained writer.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import AsyncIterator, Mapping
from pathlib import Path

import pytest

from secure_context_pipeline.audit.logger import DEOBFUSCATE, VAULT_MISS, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.deobfuscation.restorer import (
    _MAX_LABEL_LEN,
    MISS_FABRICATED,
    MISS_INDETERMINATE,
    MISS_LOST,
    PSEUDONYMIZATION,
    TOKENIZATION,
    UNRESOLVED_ENTITY,
    Restorer,
    RestoreResult,
    _compile_surrogate_pattern,
)
from secure_context_pipeline.errors import ConfigError, PipelineError, VaultMissError
from secure_context_pipeline.llm.mock_provider import (
    MUTATION_CLASSES,
    MockProvider,
    plan_mutations,
)
from secure_context_pipeline.pipeline import egress_gate
from secure_context_pipeline.surrogates import (
    MAX_ENTITY_TYPE_LEN,
    TOKEN_RE,
    format_surrogate,
)

SESSION = "sess-deobf-1"
RUN = "run-deobf-1"

NAME_ID = "1a2b3c4d"
NAME_VALUE = "John Smith"
MED_ID = "2f4a1b3c"
MED_VALUE = "Metformin"
MRN_ID = "9c8d7e6f"
MRN_VALUE = "MRN-4471902"

TOKENS = {NAME_ID: NAME_VALUE, MED_ID: MED_VALUE, MRN_ID: MRN_VALUE}


# --------------------------------------------------------------------------
# Fakes and fixtures
# --------------------------------------------------------------------------


class FakeVault:
    """Dict-backed stand-in for ``SessionVault`` -- the three frozen methods only.

    Session scoping is enforced, not assumed: a lookup with the wrong session ID
    misses exactly as the real vault's AAD binding would, so a test cannot pass
    by accidentally reading another session's row.
    """

    def __init__(
        self,
        session_id: str = SESSION,
        tokens: Mapping[str, str] | None = None,
        surrogates: Mapping[str, str] | None = None,
    ) -> None:
        self.session_id = session_id
        self.tokens = dict(tokens or {})
        self.surrogates = dict(surrogates or {})
        self.token_calls: list[str] = []
        self.surrogate_calls: list[str] = []

    async def get_by_token(self, session_id: str, token_id: str) -> str:
        self.token_calls.append(token_id)
        if session_id != self.session_id or token_id not in self.tokens:
            raise VaultMissError(session_id=session_id, token_id=token_id)
        return self.tokens[token_id]

    async def get_by_surrogate(self, session_id: str, surrogate: str) -> str:
        self.surrogate_calls.append(surrogate)
        if session_id != self.session_id or surrogate not in self.surrogates:
            raise VaultMissError(session_id=session_id)
        return self.surrogates[surrogate]

    def originals_for_session(self, session_id: str) -> frozenset[str]:
        if session_id != self.session_id:
            return frozenset()
        return frozenset(self.tokens.values()) | frozenset(self.surrogates.values())


class LeakyVault(FakeVault):
    """A broken vault: every lookup hands back something still token-shaped.

    Stands in for any bug -- upstream double-obfuscation, a corrupted row, a
    mis-wired strategy -- that would put a live token into the user's answer.
    """

    async def get_by_token(self, session_id: str, token_id: str) -> str:
        return "[PHI_NAME_5e6f7a8b]"


@pytest.fixture
async def audit(tmp_path: Path) -> AsyncIterator[AuditLogger]:
    log = await AuditLogger.open(tmp_path / "audit.db")
    try:
        yield log
    finally:
        await log.close()


@pytest.fixture
def vault() -> FakeVault:
    return FakeVault(tokens=TOKENS)


@pytest.fixture
def restorer(vault: FakeVault, settings: Settings, audit: AuditLogger) -> Restorer:
    return Restorer(vault=vault, settings=settings, audit=audit)


def sentence(fragment: str) -> str:
    """Embed a token form in prose -- spacing bugs only show up in context."""
    return "The chart lists " + fragment + " today."


# --------------------------------------------------------------------------
# 10.7 -- every mangled form the model can produce must restore
# --------------------------------------------------------------------------

MANGLED_FORMS = [
    # (fragment as the model wrote it, expected restored fragment)
    ("[PHI_NAME_1a2b3c4d]'s", "John Smith's"),
    ("**[PHI_NAME_1a2b3c4d]**", "John Smith"),
    ("[PHI_NAME_1A2B3C4D]", "John Smith"),
    ("PHI_NAME_1a2b3c4d", "John Smith"),
    ("[PHI_NAME_1a2b3c4d ]", "John Smith"),
    ("`[PHI_NAME_1a2b3c4d]`", "John Smith"),
    ("{PHI_NAME_1a2b3c4d}", "John Smith"),
    ("[PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]", "Metformin"),
    ("[PHI_MEDICATION_2f4a1b3c]", "Metformin"),
    ("[PHI_MEDICATION_2f4a1b3c|MANGLED-HINT]", "Metformin"),
    # Section 9.6 names "one bracket dropped" as a mutation class; section 10.7's
    # example drops both. Half-dropped is the form 9.6 actually describes and it
    # was not covered, so both halves are pinned here.
    ("[PHI_NAME_1a2b3c4d", "John Smith"),
    ("PHI_NAME_1a2b3c4d]", "John Smith"),
    # Section 9.7: TOKEN_RE tolerates "stray whitespace". 10.7 lists it only on
    # the closing side; the opening side is the same failure.
    ("[ PHI_NAME_1a2b3c4d ]", "John Smith"),
    ("[ PHI_NAME_1a2b3c4d]", "John Smith"),
    # Section 9.7's grammar spaces the hint separator (`\\s*\\|\\s*`).
    ("[PHI_MEDICATION_2f4a1b3c | oral-antidiabetic]", "Metformin"),
    # A hint the model *lengthened* past the emitted 24-char bound: TOKEN_RE stops
    # at the bound, and the mop-up has to take the remainder or the user reads
    # "Metformin-past-the-bound]".
    ("[PHI_MEDICATION_2f4a1b3c|a-hint-mangled-well-past-the-bound]", "Metformin"),
    # Beyond the listed set, from the same failure family:
    ("__[PHI_NAME_1a2b3c4d]__", "John Smith"),
    ("(PHI_NAME_1a2b3c4d)", "John Smith"),
    ("`PHI_NAME_1a2b3c4d`", "John Smith"),
    ("**[PHI_NAME_1a2b3c4d]**'s", "John Smith's"),
    ("PHI_NAME_1a2b3c4d's", "John Smith's"),
    ("[PHI-NAME-1a2b3c4d]", "John Smith"),
    # Mismatched brackets: the grammar accepts any opener with any closer, and it
    # should -- a model that mangles one bracket often mangles the pair.
    ("{PHI_NAME_1a2b3c4d]", "John Smith"),
]


@pytest.mark.parametrize(("fragment", "expected"), MANGLED_FORMS, ids=[f[0] for f in MANGLED_FORMS])
async def test_mangled_token_forms_restore(
    restorer: Restorer, fragment: str, expected: str
) -> None:
    result = await restorer.restore(SESSION, sentence(fragment), strategy=TOKENIZATION, run_id=RUN)

    assert result.text == sentence(expected)
    assert result.restored_count == 1
    assert result.vault_misses == 0
    assert result.unresolved == ()
    assert TOKEN_RE.search(result.text) is None


# --------------------------------------------------------------------------
# Where the shipped grammar departs from the build doc's literal TOKEN_RE.
#
# Section 9.7 prints TOKEN_RE with unbounded `\s*`, `[A-Z0-9_]*` and `[a-z0-9-]+`.
# Every one of those is bounded in `surrogates.TOKEN_RE` because the same pattern
# runs on untrusted text inside the EgressGate, where an unbounded quantifier was
# a measured denial of service and an unbounded hint was a confidentiality hole
# (see that module's docstring). The bounds are deliberate; what they cost is
# pinned here rather than left to be discovered by a reviewer.
# --------------------------------------------------------------------------


async def test_whitespace_beyond_the_bound_still_restores_the_value(
    restorer: Restorer,
) -> None:
    """DEVIATION PIN: >4 spaces inside a token leaves a bracket, never a value.

    The doc's `\\s*` would have absorbed the whole run; the shipped `\\s{0,4}`
    stops early, so the closing bracket falls outside the match and survives into
    the answer. What matters is the ordering of harms, and it is the right way
    round: the *value* is restored, no token grammar survives, nothing leaks, and
    the residue is a stray bracket a reader can ignore. A model has to emit five
    consecutive spaces inside a token to reach this at all.
    """
    text = "The chart lists [PHI_NAME_1a2b3c4d     ] today."

    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION)

    assert NAME_VALUE in result.text
    assert result.restored_count == 1
    assert TOKEN_RE.search(result.text) is None
    # The cost, stated exactly rather than approximately.
    assert result.text == "The chart lists John Smith     ] today."


def test_the_docs_shortened_example_token_is_not_matchable() -> None:
    """DEVIATION PIN: `[PHI_MEDICATION_2f4a|...]` (4-hex) does not match.

    Section 10.7 lists that literal string among the forms that must restore, and
    the shipped grammar will not match it. The build doc contradicts itself here
    and the normative half wins: section 8 fixes token IDs at
    ``hexdigest()[:8]`` and section 9.7's own regex demands ``{8}``, so `2f4a` is
    prose shorthand for an ID that cannot be minted. Asserted in both directions
    -- unmatchable *and* unissuable -- because "we can't restore it" is only
    acceptable while "we can't emit it" also holds.

    Widening to ``{4,8}`` would also be a security regression, not just a
    tolerance change: the egress gate skips spans matching this grammar, so a
    shorter hash widens the skip-list over ordinary document text.
    """
    shorthand = "[PHI_MEDICATION_2f4a|oral-antidiabetic]"
    assert TOKEN_RE.search(shorthand) is None

    with pytest.raises(ConfigError) as excinfo:
        format_surrogate("PHI", "MEDICATION", "2f4a", "oral-antidiabetic")
    assert excinfo.value.detail["reason"] == "malformed_token_id"

    # The 8-hex form of the same example is the one that restores (above).
    assert TOKEN_RE.search("[PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]") is not None


async def test_an_unmatchable_shorthand_token_never_trips_the_residue_assertion(
    restorer: Restorer,
) -> None:
    """And it degrades safely: passed through, not restored, not a false alarm.

    A 4-hex look-alike was never issued, so there is nothing behind it to leak;
    leaving it verbatim is the correct outcome and must not raise.
    """
    text = "Prescribed [PHI_MEDICATION_2f4a|oral-antidiabetic] yesterday."

    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION)

    assert result.text == text
    assert result.restored_count == 0
    assert result.vault_misses == 0


async def test_hint_is_ignored_for_lookup(restorer: Restorer, vault: FakeVault) -> None:
    """Restore keys on the 8-hex hash alone -- the hint never reaches the vault."""
    text = "Take [PHI_MEDICATION_2f4a1b3c|MANGLED-HINT] and [PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]."

    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION)

    assert result.text == "Take Metformin and Metformin."
    # One distinct hash -> one lookup, whatever the hints said.
    assert vault.token_calls == [MED_ID]


async def test_uppercase_hash_is_looked_up_lowercased(vault: FakeVault, restorer: Restorer) -> None:
    await restorer.restore(SESSION, "[PHI_NAME_1A2B3C4D]", strategy=TOKENIZATION)

    assert vault.token_calls == [NAME_ID]


async def test_markdown_leaves_no_orphans(restorer: Restorer) -> None:
    text = (
        "Bold **[PHI_NAME_1a2b3c4d]**, code `[PHI_MEDICATION_2f4a1b3c]`, "
        "underscored __[PHI_MRN_9c8d7e6f]__, possessive **[PHI_NAME_1a2b3c4d]**'s."
    )

    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION)

    assert "**" not in result.text
    assert "`" not in result.text
    assert "__" not in result.text
    assert result.text == (
        "Bold John Smith, code Metformin, underscored MRN-4471902, possessive John Smith's."
    )


async def test_unpaired_closing_emphasis_is_left_alone(restorer: Restorer) -> None:
    """Only markdown mirrored on both sides is stripped.

    A trailing ``**`` with nothing hugging the left of the token belongs to
    emphasis opened earlier in the sentence; eating it would create the orphan
    the stripping exists to prevent.
    """
    result = await restorer.restore(
        SESSION, "**Patient [PHI_NAME_1a2b3c4d]** is stable.", strategy=TOKENIZATION
    )

    assert result.text == "**Patient John Smith** is stable."


UNPAIRED_OPENING = [
    # (as the model wrote it, expected) -- emphasis that OPENS at the token and
    # closes later in the sentence. The mirror image of the case above, and the
    # same rule has to hold: strip nothing, or the user gets a dangling closer.
    ("**[PHI_NAME_1a2b3c4d] is stable** today.", "**John Smith is stable** today."),
    ("`[PHI_NAME_1a2b3c4d] code` block", "`John Smith code` block"),
    ("__[PHI_NAME_1a2b3c4d] under__ score", "__John Smith under__ score"),
    (
        "**[PHI_NAME_1a2b3c4d] and [PHI_MEDICATION_2f4a1b3c]** noted.",
        "**John Smith and Metformin** noted.",
    ),
    ("**[PHI_NAME_1a2b3c4d][PHI_MEDICATION_2f4a1b3c]**", "**John SmithMetformin**"),
    # Nested, closed only part-way: the inner pair collapses, the outer opener stays.
    ("**__[PHI_NAME_1a2b3c4d]__ rest", "**John Smith rest"),
]


@pytest.mark.parametrize(
    ("text", "expected"), UNPAIRED_OPENING, ids=[case[0] for case in UNPAIRED_OPENING]
)
async def test_unpaired_opening_emphasis_is_left_alone(
    restorer: Restorer, text: str, expected: str
) -> None:
    """Stripping is mirrored in BOTH directions, not just right-to-left.

    Walking left over ``**`` unconditionally would delete the opener and leave
    ``John Smith is stable** today.`` -- a dangling closer in the user's answer.
    """
    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION)

    assert result.text == expected


async def test_possessive_inside_stripped_emphasis_survives(restorer: Restorer) -> None:
    """``**[TOKEN]'s**`` -- the possessive sits *between* the token and the closer.

    This is the one shape where possessive handling is load-bearing: the ``'s``
    has to be lifted out of the span before the mirrored ``**`` can be matched,
    or the emphasis is left unstripped and the user sees the raw markdown.
    """
    result = await restorer.restore(
        SESSION, "**[PHI_NAME_1a2b3c4d]'s** chart was reviewed.", strategy=TOKENIZATION
    )

    assert result.text == "John Smith's chart was reviewed."


async def test_adjacent_tokens_keep_their_separators(restorer: Restorer) -> None:
    text = "PHI_NAME_1a2b3c4d takes PHI_MEDICATION_2f4a1b3c daily."

    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION)

    assert result.text == "John Smith takes Metformin daily."


# Everything after a token is the model's own prose. The mangled-hint mop-up may
# not delete any of it: a silently shortened answer is a correctness failure the
# user cannot even see, while a visible "|MANGLED HINT]" remnant is cosmetic.
PROSE_AFTER_A_MANGLED_HINT = [
    (
        "Take [PHI_NAME_1a2b3c4d| and call the doctor about it] now.",
        "call the doctor about it",
    ),
    ("See [PHI_NAME_1a2b3c4d|note (about the case) here] end.", "(about the case) here"),
    # A ')' from an unrelated parenthetical must not close a '['-opened token.
    (
        "Take [PHI_MEDICATION_2f4a1b3c|oral-antidiabetic (see note) daily.",
        "(see note) daily.",
    ),
    # A second token can never be swallowed by the first one's tail.
    ("Give [PHI_NAME_1a2b3c4d|[PHI_MEDICATION_2f4a1b3c]] today.", "Metformin"),
]


@pytest.mark.parametrize(
    ("text", "must_survive"),
    PROSE_AFTER_A_MANGLED_HINT,
    ids=[case[0][:40] for case in PROSE_AFTER_A_MANGLED_HINT],
)
async def test_mangled_hint_mopup_never_eats_the_models_prose(
    restorer: Restorer, text: str, must_survive: str
) -> None:
    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION)

    assert must_survive in result.text, result.text
    assert TOKEN_RE.search(result.text) is None


# --------------------------------------------------------------------------
# 10.6 -- spec-mandated case (exact test name)
# --------------------------------------------------------------------------


async def test_vault_miss_on_deobfuscation(
    restorer: Restorer, vault: FakeVault, audit: AuditLogger
) -> None:
    """Unknown token -> ``[UNRESOLVED_ENTITY]`` + ``VAULT_MISS`` audit, no crash."""
    text = "Contact [PHI_NAME_1a2b3c4d] about [PHI_NAME_deadbeef] before Friday."

    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION, run_id=RUN)

    assert result.text == f"Contact John Smith about {UNRESOLVED_ENTITY} before Friday."
    assert result.restored_count == 1
    assert result.vault_misses == 1
    assert result.unresolved == ("deadbeef",)
    # The one legitimate residue must not trip the post-restore assertion.
    assert TOKEN_RE.search(result.text) is None

    misses = await audit.query(session_id=SESSION, event_type=VAULT_MISS)
    assert [event.token_id for event in misses] == ["deadbeef"]
    assert misses[0].run_id == RUN
    assert misses[0].entity_type == "PHI_NAME"
    assert misses[0].detail["stage"] == "deobfuscate"
    assert await audit.verify_chain() is True


async def test_repeated_unknown_token_audits_once_and_never_crashes(
    restorer: Restorer, audit: AuditLogger
) -> None:
    text = "[PHI_NAME_deadbeef] and [PHI_NAME_deadbeef] and [PHI_NAME_DEADBEEF]."

    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION, run_id=RUN)

    assert result.text == f"{UNRESOLVED_ENTITY} and {UNRESOLVED_ENTITY} and {UNRESOLVED_ENTITY}."
    assert result.vault_misses == 3  # three occurrences
    assert result.unresolved == ("deadbeef",)  # one distinct ID
    assert len(await audit.query(session_id=SESSION, event_type=VAULT_MISS)) == 1


# --------------------------------------------------------------------------
# Which kind of vault miss was it? The user sees one placeholder; the operator
# must not.
# --------------------------------------------------------------------------


async def test_a_miss_is_indeterminate_when_the_caller_says_nothing(
    restorer: Restorer, audit: AuditLogger
) -> None:
    """No ``issued`` set means the audit row says so, rather than guessing.

    ``fabricated`` and ``lost`` both empty while ``unresolved`` is not is the
    signal -- it must never be read as "we checked, and nothing was lost".
    """
    result = await restorer.restore(
        SESSION, "[PHI_NAME_deadbeef]", strategy=TOKENIZATION, run_id=RUN
    )

    assert result.unresolved == ("deadbeef",)
    assert result.fabricated == ()
    assert result.lost == ()

    misses = await audit.query(session_id=SESSION, event_type=VAULT_MISS)
    assert misses[0].detail["classification"] == MISS_INDETERMINATE
    # The observation code is unchanged; the diagnosis is the new field.
    assert misses[0].detail["reason"] == "token_not_in_vault"


async def test_a_token_the_run_never_issued_is_classified_fabricated(
    restorer: Restorer, audit: AuditLogger
) -> None:
    """The model invented a placeholder. Nothing was lost -- and that is sayable."""
    result = await restorer.restore(
        SESSION,
        "Contact [PHI_NAME_1a2b3c4d] about [PHI_NAME_deadbeef].",
        strategy=TOKENIZATION,
        issued=[NAME_ID, MED_ID],
        run_id=RUN,
    )

    assert result.text == f"Contact John Smith about {UNRESOLVED_ENTITY}."
    assert result.fabricated == ("deadbeef",)
    assert result.lost == ()

    misses = await audit.query(session_id=SESSION, event_type=VAULT_MISS)
    assert [event.detail["classification"] for event in misses] == [MISS_FABRICATED]

    summary = await audit.query(session_id=SESSION, event_type=DEOBFUSCATE)
    assert summary[0].detail["unresolved_fabricated"] == 1
    assert summary[0].detail["unresolved_lost"] == 0


async def test_a_token_the_run_did_issue_is_classified_lost(
    settings: Settings, audit: AuditLogger
) -> None:
    """The other incident entirely: we minted it and the vault cannot give it back.

    Same ``[UNRESOLVED_ENTITY]`` to the user -- degrade, never fail -- but this
    one means a value the user was entitled to is gone, so it has to be
    distinguishable in the audit trail from a model that made a token up.
    """
    # The vault knows about MED_ID only; NAME_ID was issued and has vanished.
    restorer = Restorer(
        vault=FakeVault(tokens={MED_ID: MED_VALUE}), settings=settings, audit=audit
    )

    result = await restorer.restore(
        SESSION,
        "[PHI_NAME_1a2b3c4d] takes [PHI_MEDICATION_2f4a1b3c].",
        strategy=TOKENIZATION,
        issued=[NAME_ID, MED_ID],
        run_id=RUN,
    )

    assert result.text == f"{UNRESOLVED_ENTITY} takes Metformin."
    assert result.lost == (NAME_ID,)
    assert result.fabricated == ()

    misses = await audit.query(session_id=SESSION, event_type=VAULT_MISS)
    assert [event.detail["classification"] for event in misses] == [MISS_LOST]
    assert misses[0].token_id == NAME_ID

    summary = await audit.query(session_id=SESSION, event_type=DEOBFUSCATE)
    assert summary[0].detail["unresolved_lost"] == 1
    assert summary[0].detail["unresolved_fabricated"] == 0


async def test_both_kinds_of_miss_are_separated_in_one_response(
    settings: Settings, audit: AuditLogger
) -> None:
    restorer = Restorer(
        vault=FakeVault(tokens={MED_ID: MED_VALUE}), settings=settings, audit=audit
    )

    result = await restorer.restore(
        SESSION,
        "[PHI_NAME_1a2b3c4d], [PHI_MEDICATION_2f4a1b3c] and [PHI_NAME_deadbeef].",
        strategy=TOKENIZATION,
        issued=[NAME_ID, MED_ID],
        run_id=RUN,
    )

    assert result.vault_misses == 2
    assert set(result.unresolved) == {NAME_ID, "deadbeef"}
    assert result.lost == (NAME_ID,)
    assert result.fabricated == ("deadbeef",)

    by_token = {
        event.token_id: event.detail["classification"]
        for event in await audit.query(session_id=SESSION, event_type=VAULT_MISS)
    }
    assert by_token == {NAME_ID: MISS_LOST, "deadbeef": MISS_FABRICATED}


async def test_issued_matches_a_case_mangled_hash(
    settings: Settings, audit: AuditLogger
) -> None:
    """The model upper-cases hashes; classification must not flip because of it."""
    restorer = Restorer(vault=FakeVault(), settings=settings, audit=audit)

    result = await restorer.restore(
        SESSION, "[PHI_NAME_1A2B3C4D]", strategy=TOKENIZATION, issued=["1A2B3C4D"], run_id=RUN
    )

    assert result.lost == (NAME_ID,)
    assert result.fabricated == ()


async def test_a_lost_token_is_logged_louder_than_a_fabricated_one(
    settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """Severity is the only thing an operator sees without querying the audit DB."""
    restorer = Restorer(vault=FakeVault(), settings=settings)
    caplog.set_level(logging.WARNING, logger="secure_context_pipeline.deobfuscation.restorer")

    await restorer.restore(
        SESSION,
        "[PHI_NAME_1a2b3c4d] and [PHI_NAME_deadbeef].",
        strategy=TOKENIZATION,
        issued=[NAME_ID],
    )

    levels = {
        getattr(record, "classification", None): record.levelno
        for record in caplog.records
        if record.getMessage() == "vault miss during restore"
    }
    assert levels == {MISS_LOST: logging.ERROR, MISS_FABRICATED: logging.WARNING}
    # And still no value anywhere in the log stream.
    assert NAME_VALUE not in caplog.text


async def test_a_surrogate_miss_is_always_a_lost_one(
    settings: Settings, audit: AuditLogger
) -> None:
    """A fake cannot be fabricated into this branch, so it needs no ``issued`` set.

    The alternation is compiled from the caller's own map, so anything it matches
    was issued by this run by construction. Classifying it :data:`MISS_LOST`
    unconditionally is a derivation, not an assumption.
    """
    restorer = Restorer(vault=FakeVault(), settings=settings, audit=audit)

    result = await restorer.restore(
        SESSION,
        "Torres signed off.",
        strategy=PSEUDONYMIZATION,
        surrogates={"Torres": ""},
        run_id=RUN,
    )

    assert result.surrogate_misses == 1
    misses = await audit.query(session_id=SESSION, event_type=VAULT_MISS)
    assert misses[0].detail["classification"] == MISS_LOST
    assert misses[0].detail["reason"] == "surrogate_not_in_vault"
    assert misses[0].token_id is None

    summary = await audit.query(session_id=SESSION, event_type=DEOBFUSCATE)
    assert summary[0].detail["surrogate_misses"] == 1
    # A fake never enters the result's ID lists, whatever it is classified as.
    assert result.unresolved == ()
    assert result.lost == ()


async def test_classification_never_changes_what_the_user_reads(
    settings: Settings,
) -> None:
    """``issued`` is diagnostics. It must not touch a single character of output."""
    text = "[PHI_NAME_1a2b3c4d] and [PHI_NAME_deadbeef] and Torres."
    surrogates = {"Torres": "Nguyen"}

    without = await Restorer(vault=FakeVault(tokens=TOKENS), settings=settings).restore(
        SESSION, text, strategy=PSEUDONYMIZATION, surrogates=surrogates
    )
    with_issued = await Restorer(vault=FakeVault(tokens=TOKENS), settings=settings).restore(
        SESSION,
        text,
        strategy=PSEUDONYMIZATION,
        surrogates=surrogates,
        issued=[NAME_ID, "deadbeef"],
    )

    assert without.text == with_issued.text
    assert without.restored_count == with_issued.restored_count
    assert without.vault_misses == with_issued.vault_misses
    # Only the diagnosis differs.
    assert without.lost == () and with_issued.lost == ("deadbeef",)


async def test_unresolved_carries_token_ids_only(restorer: Restorer) -> None:
    """``unresolved`` is an ID list, never a value list -- checked, not assumed."""
    text = "[PHI_NAME_1a2b3c4d] and [PHI_NAME_deadbeef]."

    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION)

    assert all(len(token_id) == 8 for token_id in result.unresolved)
    assert all(int(token_id, 16) >= 0 for token_id in result.unresolved)
    for original in TOKENS.values():
        assert original not in result.unresolved


# --------------------------------------------------------------------------
# Post-restore assertions -- in code, not just in tests
# --------------------------------------------------------------------------


async def test_post_restore_assertion_fires_on_residual_token(
    settings: Settings, audit: AuditLogger
) -> None:
    """A broken vault that re-emits a token must fail loudly, not reach the user."""
    restorer = Restorer(vault=LeakyVault(tokens=TOKENS), settings=settings, audit=audit)

    with pytest.raises(PipelineError) as excinfo:
        await restorer.restore(
            SESSION, "Seen by [PHI_NAME_1a2b3c4d].", strategy=TOKENIZATION, run_id=RUN
        )

    assert excinfo.value.detail["reason"] == "residual_token_after_restore"
    assert excinfo.value.detail["residual"] == 1
    assert excinfo.value.detail["sample_token_id"] == "5e6f7a8b"

    events = await audit.query(session_id=SESSION, event_type=DEOBFUSCATE)
    assert [event.detail["outcome"] for event in events] == ["assertion_failed"]
    assert events[0].detail["reason"] == "residual_token_after_restore"


async def test_post_restore_assertion_fires_on_residual_surrogate(
    settings: Settings, audit: AuditLogger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same guarantee on the pseudonymization side.

    The surrogate pass is sabotaged into a no-op so the fake survives into the
    output; only the in-code assertion stands between that and the user.
    """
    import secure_context_pipeline.deobfuscation.restorer as module

    async def no_op_pass(
        self: Restorer, session_id: str, text: str, **kwargs: object
    ) -> module._SurrogatePass:
        return module._SurrogatePass(text, 0, 0, 0, ())

    monkeypatch.setattr(module.Restorer, "_restore_surrogates", no_op_pass)
    restorer = Restorer(vault=FakeVault(), settings=settings, audit=audit)

    with pytest.raises(PipelineError) as excinfo:
        await restorer.restore(
            SESSION,
            "Dr. Torres signed off.",
            strategy=PSEUDONYMIZATION,
            surrogates={"Torres": "Smith"},
            run_id=RUN,
        )

    assert excinfo.value.detail["reason"] == "residual_surrogate_after_restore"


async def test_assertion_message_carries_no_original(settings: Settings) -> None:
    """Exceptions carry IDs and counts. Never a value."""
    restorer = Restorer(vault=LeakyVault(tokens=TOKENS), settings=settings)

    with pytest.raises(PipelineError) as excinfo:
        await restorer.restore(SESSION, "[PHI_NAME_1a2b3c4d]", strategy=TOKENIZATION)

    rendered = f"{excinfo.value}{excinfo.value!r}"
    for original in TOKENS.values():
        assert original not in rendered


async def test_unknown_strategy_is_rejected(restorer: Restorer) -> None:
    with pytest.raises(PipelineError) as excinfo:
        await restorer.restore(SESSION, "text", strategy="rot13")

    assert excinfo.value.detail["reason"] == "unknown_strategy"


# --------------------------------------------------------------------------
# Pseudonymization
# --------------------------------------------------------------------------


async def test_longest_surrogate_wins(settings: Settings, audit: AuditLogger) -> None:
    """A short fake that is a substring of a longer one must not corrupt it.

    Both candidates start at the same offset in ``Torres-Blake``/``Lee Ann``, so
    only ordering the alternation longest-first keeps the longer replacement.
    """
    surrogates = {
        "Torres-Blake": "Smithson",
        "Torres": "Smith",
        "Lee Ann": "Nguyen Marie",
        "Lee": "Nguyen",
    }
    restorer = Restorer(vault=FakeVault(), settings=settings, audit=audit)
    text = "Dr. Torres-Blake and Lee Ann reviewed the notes from Torres and Lee."

    result = await restorer.restore(
        SESSION, text, strategy=PSEUDONYMIZATION, surrogates=surrogates
    )

    assert result.text == (
        "Dr. Smithson and Nguyen Marie reviewed the notes from Smith and Nguyen."
    )
    assert result.restored_count == 4
    for surrogate in surrogates:
        assert surrogate not in result.text


async def test_surrogate_possessives_restore(settings: Settings) -> None:
    restorer = Restorer(vault=FakeVault(), settings=settings)
    text = "Torres's chart, Torres' prior notes, and Torres in person."

    result = await restorer.restore(
        SESSION, text, strategy=PSEUDONYMIZATION, surrogates={"Torres": "Smith"}
    )

    assert result.text == "Smith's chart, Smith' prior notes, and Smith in person."
    assert result.restored_count == 3


# A surrogate wrapped in markdown emphasis. `_` is a regex `\w`, so the old
# unconditional `(?<!\w)...(?!\w)` refused to match the underscore forms -- which
# are exactly what a model emits when it italicises or bolds a name.
EMPHASISED_SURROGATE = [
    "_Maria Torres_ signed the consent form.",
    "__Maria Torres__ signed the consent form.",
    "*Maria Torres* signed the consent form.",
    "**Maria Torres** signed the consent form.",
    "`Maria Torres` signed the consent form.",
    "The chart was countersigned by _Maria Torres_.",
]


@pytest.mark.parametrize("text", EMPHASISED_SURROGATE, ids=EMPHASISED_SURROGATE)
async def test_an_emphasised_surrogate_is_restored(settings: Settings, text: str) -> None:
    """Markdown around a fake must not make the fake invisible to the matcher.

    Underscore is prose punctuation, not a word character, so it is a boundary --
    the rule imported from the egress gate. The old ``\\w``-based lookarounds
    disagreed, and the consequence here was worse than a missed restoration: the
    post-restore assertion re-scans with the *same* pattern, so it was blind in
    exactly the same way and could not fire. The pseudonym reached the user with
    nothing raised and nothing logged.
    """
    restorer = Restorer(vault=FakeVault(), settings=settings)

    result = await restorer.restore(
        SESSION, text, strategy=PSEUDONYMIZATION, surrogates={"Maria Torres": "Jane Alderton"}
    )

    assert "Maria Torres" not in result.text
    assert "Jane Alderton" in result.text
    assert result.restored_count == 1
    # The emphasis itself is the model's formatting and is left alone.
    assert result.text == text.replace("Maria Torres", "Jane Alderton")


async def test_a_surrogate_whose_edge_is_punctuation_is_restored(
    settings: Settings,
) -> None:
    """A boundary assertion on a punctuation edge asks a meaningless question.

    ``(?<!\\w)`` before the ``(`` of ``(415) 555-0123`` is not a word-boundary
    test at all, and it made ``tel(415) 555-0123`` un-restorable. Per-side
    assertions -- applied only where the surrogate's own edge is alphanumeric --
    are what the gate and the engine's sweep use, so the restorer uses them too.
    """
    restorer = Restorer(vault=FakeVault(), settings=settings)
    surrogates = {"(415) 555-0123": "(212) 555-9999", "Ph.D.": "M.D."}

    result = await restorer.restore(
        SESSION,
        "Reach them on tel(415) 555-0123; her Ph.D.degree is on file.",
        strategy=PSEUDONYMIZATION,
        surrogates=surrogates,
    )

    assert result.text == "Reach them on tel(212) 555-9999; her M.D.degree is on file."
    assert result.restored_count == 2


async def test_the_residue_assertion_is_not_blind_where_the_matcher_was(
    settings: Settings, audit: AuditLogger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard must fire on an emphasised fake, not share the matcher's blind spot.

    This is the regression that made the bug silent rather than loud. With the
    surrogate pass sabotaged into a no-op, an underscore-wrapped fake survives
    into the output; the assertion has to see it.
    """
    import secure_context_pipeline.deobfuscation.restorer as module

    async def no_op_pass(
        self: Restorer, session_id: str, text: str, **kwargs: object
    ) -> module._SurrogatePass:
        return module._SurrogatePass(text, 0, 0, 0, ())

    monkeypatch.setattr(module.Restorer, "_restore_surrogates", no_op_pass)
    restorer = Restorer(vault=FakeVault(), settings=settings, audit=audit)

    with pytest.raises(PipelineError) as excinfo:
        await restorer.restore(
            SESSION,
            "_Maria Torres_ signed off.",
            strategy=PSEUDONYMIZATION,
            surrogates={"Maria Torres": "Jane Alderton"},
            run_id=RUN,
        )

    assert excinfo.value.detail["reason"] == "residual_surrogate_after_restore"


def test_the_restorer_and_the_gate_agree_on_what_counts_as_an_occurrence() -> None:
    """Differential test: a fourth copy of the boundary rule must not drift.

    The restorer imports the gate's ``_ALNUM`` but assembles the assertions
    itself (they have to straddle an optional possessive), so the shared constant
    alone does not keep the two honest. This pins the *behaviour* against
    ``egress_gate._occurs_as_a_unit`` the way ``tests/test_obfuscation.py`` pins
    the engine's sweep against it.
    """
    needles = [
        "John Smith", "Brown", "Ann", "MRN: 4471902", "(415) 555-0123",
        "$1,234.56", "Ph.D.", "123-45-6789", "Case No. 1:23-cv-45678", "O'Brien",
    ]
    haystacks = [
        "{}", "_{}_", "*{}*", "__{}__", "a{}", "{}z", "({})", "[{}]", " {} ",
        "x{}y", "{}.", ".{}", "tel{}", "USD{}", "{}degree", "-{}-", "{}_", "_{}",
        "\n{}\n", "1{}", "{}9",
    ]
    disagreements: list[tuple[str, str]] = []
    for needle in needles:
        pattern = _compile_surrogate_pattern([needle])
        assert pattern is not None
        for template in haystacks:
            haystack = template.format(needle)
            mine = pattern.search(haystack) is not None
            theirs = egress_gate._occurs_as_a_unit(needle, haystack)
            if mine != theirs:
                disagreements.append((needle, haystack))
    assert disagreements == [], (
        f"restorer and gate disagree on {len(disagreements)} case(s): {disagreements[:5]}"
    )
    # And the specific regression, in both directions.
    emphasised = _compile_surrogate_pattern(["John Smith"])
    assert emphasised is not None
    assert emphasised.search("_John Smith_")
    assert egress_gate._occurs_as_a_unit("John Smith", "_John Smith_")


async def test_longest_first_survives_the_left_edge_partition(
    settings: Settings,
) -> None:
    """Hoisting the left assertion splits the alternation. Ordering must survive it.

    The partition is by first-character class, and two surrogates can only
    compete at one offset if they share a first character -- so contenders always
    land in the same group. This exercises that with both classes present at once,
    including a pair where the longer candidate is a strict extension of the
    shorter.
    """
    surrogates = {
        "(415) 555-0123 ext 9": "(212) 555-9999 ext 4",
        "(415) 555-0123": "(212) 555-9999",
        "Torres-Blake": "Smithson",
        "Torres": "Smith",
    }
    restorer = Restorer(vault=FakeVault(), settings=settings)
    text = "Call (415) 555-0123 ext 9 or (415) 555-0123; ask for Torres-Blake, not Torres."

    result = await restorer.restore(
        SESSION, text, strategy=PSEUDONYMIZATION, surrogates=surrogates
    )

    assert result.text == (
        "Call (212) 555-9999 ext 4 or (212) 555-9999; ask for Smithson, not Smith."
    )
    assert result.restored_count == 4


def test_the_surrogate_matcher_stays_linear_on_a_large_session() -> None:
    """The left assertion is hoisted for speed; this is the floor it must hold.

    Written per branch instead, the lookbehind destroys CPython's
    first-character prefilter and a 300-surrogate pattern took 683 ms over 160 KB
    -- past the whole 500 ms restore budget (build doc section 12) on the matcher
    alone. Generous margin here; the hoisted form measures ~17 ms.
    """
    surrogates = [f"Fakename{index:04d} Surrogate" for index in range(250)]
    surrogates += [f"(415) 555-{index:04d}" for index in range(50)]
    pattern = _compile_surrogate_pattern(surrogates)
    assert pattern is not None

    # A near-miss haystack: shares the leading letter everywhere, matches nothing.
    haystack = "Fakenames " * 16_000
    started = time.perf_counter()
    assert pattern.search(haystack) is None
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    assert elapsed_ms < 200.0, f"surrogate scan took {elapsed_ms:.0f} ms over {len(haystack):,} chars"


async def test_surrogate_respects_word_boundaries(settings: Settings) -> None:
    restorer = Restorer(vault=FakeVault(), settings=settings)

    result = await restorer.restore(
        SESSION,
        "Torresville is not Torres.",
        strategy=PSEUDONYMIZATION,
        surrogates={"Torres": "Smith"},
    )

    assert result.text == "Torresville is not Smith."


async def test_date_surrogate_restores_in_emitted_format(settings: Settings) -> None:
    """Date surrogates are matched in the shape the strategy emitted."""
    restorer = Restorer(vault=FakeVault(), settings=settings)
    surrogates = {"03/14/1985": "07/02/1985", "2019-11-04": "2019-08-23"}

    result = await restorer.restore(
        SESSION,
        "DOB 03/14/1985; admitted 2019-11-04.",
        strategy=PSEUDONYMIZATION,
        surrogates=surrogates,
    )

    assert result.text == "DOB 07/02/1985; admitted 2019-08-23."


async def test_surrogate_falls_back_to_vault_lookup(settings: Settings) -> None:
    """A candidate the caller could not resolve is looked up in the vault."""
    vault = FakeVault(surrogates={"Torres": "Smith"})
    restorer = Restorer(vault=vault, settings=settings)

    result = await restorer.restore(
        SESSION,
        "Torres signed the consent form.",
        strategy=PSEUDONYMIZATION,
        surrogates={"Torres": ""},
    )

    assert result.text == "Smith signed the consent form."
    assert vault.surrogate_calls == ["Torres"]


async def test_unresolvable_surrogate_degrades_without_crashing(
    settings: Settings, audit: AuditLogger
) -> None:
    restorer = Restorer(vault=FakeVault(), settings=settings, audit=audit)

    result = await restorer.restore(
        SESSION,
        "Torres signed off.",
        strategy=PSEUDONYMIZATION,
        surrogates={"Torres": ""},
        run_id=RUN,
    )

    assert result.text == f"{UNRESOLVED_ENTITY} signed off."
    assert result.vault_misses == 1
    # Surrogate misses have no token ID, so they never enter `unresolved`.
    assert result.unresolved == ()
    misses = await audit.query(session_id=SESSION, event_type=VAULT_MISS)
    assert misses[0].detail["reason"] == "surrogate_not_in_vault"
    assert misses[0].token_id is None


async def test_pseudonymization_also_restores_tier3_tokens(settings: Settings) -> None:
    """Pseudonym mode still emits tokens for some tiers, so both passes must run."""
    vault = FakeVault(tokens=TOKENS)
    restorer = Restorer(vault=vault, settings=settings)
    text = "Torres was prescribed [PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]."

    result = await restorer.restore(
        SESSION, text, strategy=PSEUDONYMIZATION, surrogates={"Torres": "Smith"}
    )

    assert result.text == "Smith was prescribed Metformin."
    assert result.restored_count == 2
    assert result.surrogates_seen == 1
    assert result.tokens_seen == 1


async def test_a_fake_that_is_another_fake_plus_a_possessive_is_not_confused(
    settings: Settings,
) -> None:
    """Two issued fakes where one is the other wearing an apostrophe-s.

    ``_split_surrogate_match`` checks the whole match against the issued set
    *before* it tries peeling a possessive, and that ordering is the only thing
    standing between these two entities. Peel first and ``St. Mary's`` is read as
    ``St. Mary`` + ``'s``: the alternation matched the longer fake, the split
    resolved the shorter one, and the hospital's original is spliced in where the
    person's belonged -- cross-contamination between two originals that share a
    prefix, with nothing raised and nothing logged.
    """
    surrogates = {"St. Mary's": "Holy Cross Medical", "St. Mary": "Adaeze Okafor"}
    restorer = Restorer(vault=FakeVault(), settings=settings)

    result = await restorer.restore(
        SESSION,
        "Admitted to St. Mary's after St. Mary signed the consent.",
        strategy=PSEUDONYMIZATION,
        surrogates=surrogates,
    )

    assert result.text == (
        "Admitted to Holy Cross Medical after Adaeze Okafor signed the consent."
    )
    assert result.restored_count == 2
    # Specifically: the longer fake did not resolve through the shorter one.
    assert "Adaeze Okafor's" not in result.text


# The matcher is case-sensitive, and that is a decision with a cost on each side.
# Both sides are pinned here so the boundary is reviewable rather than discovered.
CASE_VARIANT_FAKES = [
    ("TORRES REPORT\nTorres signed.", "TORRES REPORT\nSmith signed."),
    ("torres signed; Torres too.", "torres signed; Smith too."),
    ("The Torreses arrived; Torres did too.", "The Torreses arrived; Smith did too."),
]


@pytest.mark.parametrize(
    ("text", "expected"), CASE_VARIANT_FAKES, ids=[case[0][:24] for case in CASE_VARIANT_FAKES]
)
async def test_a_case_or_number_variant_fake_is_left_alone(
    settings: Settings, text: str, expected: str
) -> None:
    """LIMITATION PIN: only the exact surface form of a fake is restored.

    A model that upper-cases a name in a heading, lower-cases it, or pluralises it
    produces a string the matcher does not claim -- so the *fake* reaches the user
    in place of the original. The answer is degraded, never wrong about anything
    else and never a disclosure (a fake is what the model saw, and the original was
    never exposed to it), but it is a real gap and it is silent: the residue
    assertion re-scans with this same pattern, so it cannot see what the matcher
    could not.
    """
    restorer = Restorer(vault=FakeVault(), settings=settings)

    result = await restorer.restore(
        SESSION, text, strategy=PSEUDONYMIZATION, surrogates={"Torres": "Smith"}
    )

    assert result.text == expected


def test_case_insensitive_matching_would_splice_an_original_into_prose() -> None:
    """Why the gap above is not closed by folding case: the cure is worse.

    Fakes are drawn from a realistic name space, and a large part of that space is
    also ordinary English -- ``Long``, ``Brown``, ``Young``, ``Case``, ``May``.
    Folding case makes every one of those match its lowercase common-word twin, and
    the restorer then splices a *real original* into the middle of a sentence the
    model wrote about nothing in particular. Failing to restore a shouted fake is a
    degraded answer; inventing an attribution is a wrong one, and it is the failure
    mode that puts a real name next to a claim nobody made about that person.
    """
    prose = "The patient has a long history of care; Long counter-signed."
    pattern = _compile_surrogate_pattern(["Long"])
    assert pattern is not None
    folded = re.compile(pattern.pattern, re.IGNORECASE)

    assert [m.group(0) for m in pattern.finditer(prose)] == ["Long"]
    assert [m.group(0) for m in folded.finditer(prose)] == ["long", "Long"]


async def test_the_entity_type_label_copied_from_untrusted_text_is_bounded(
    settings: Settings, audit: AuditLogger
) -> None:
    """The one field an audit row takes from the model's own bytes has a ceiling.

    ``entity_type`` on a ``VAULT_MISS`` row is parsed out of the response, so its
    width is attacker-influenced. The grammar already caps a type at 64 characters
    and ``AuditEvent`` caps every label column at 128, but the restorer clamps at
    its own, tighter bound rather than relying on either -- a defence that is only
    a defence while something checks it.
    """
    widest = "A" + "B" * (MAX_ENTITY_TYPE_LEN - 1)
    restorer = Restorer(vault=FakeVault(), settings=settings, audit=audit)

    result = await restorer.restore(
        SESSION, f"[LEGAL_{widest}_deadbeef]", strategy=TOKENIZATION, run_id=RUN
    )

    assert result.text == UNRESOLVED_ENTITY
    misses = await audit.query(session_id=SESSION, event_type=VAULT_MISS)
    label = misses[0].entity_type
    assert label is not None
    # The untruncated label would be 70 characters, so the clamp really did fire.
    assert len(f"LEGAL_{widest}") > _MAX_LABEL_LEN
    assert len(label) == _MAX_LABEL_LEN
    assert label == f"LEGAL_{widest}"[:_MAX_LABEL_LEN]


async def test_restored_original_may_contain_another_fake(settings: Settings) -> None:
    """A restored original that happens to contain another entity's fake is fine.

    Fakes are drawn from the same name space as real values, so this collision is
    routine. The assertion scopes itself to text the model wrote, so a correctly
    restored run is not failed for it.
    """
    restorer = Restorer(vault=FakeVault(), settings=settings)

    result = await restorer.restore(
        SESSION,
        "Ana Lopez chaired the review.",
        strategy=PSEUDONYMIZATION,
        surrogates={"Ana Lopez": "Maria Torres", "Torres": "Smith"},
    )

    assert result.text == "Maria Torres chaired the review."


# --------------------------------------------------------------------------
# The real adversary, wired straight to the matcher
# --------------------------------------------------------------------------

#: What the pseudonymization strategy actually puts on the wire: Tier-1 realistic
#: fakes in prose *and* Tier-3 class-annotated tokens, in one payload. Getting this
#: shape right is the whole point -- a payload that is all tokens or all fakes
#: exercises one pass and hides the other.
MIXED_TIER_PAYLOAD = "\n".join(
    (
        "Patient record under review.",
        "Name: Marisol Ferraro, seen at Northgate Family Medicine on 04/11/2019.",
        "Therapy: [PHI_MEDICATION_2f4a1b3c|oral-antidiabetic] for [PHI_DIAGNOSIS_aabbccdd].",
        "Summarise the encounter.",
    )
)

MIXED_TOKENS = {MED_ID: MED_VALUE, "aabbccdd": "type 2 diabetes mellitus"}
MIXED_FAKES = {
    "Marisol Ferraro": "Jane Alderton",
    "Northgate Family Medicine": "Riverbend Clinic",
    "04/11/2019": "11/27/2019",
}


async def test_the_mock_providers_own_answer_restores_through_both_passes(
    settings: Settings, audit: AuditLogger
) -> None:
    """The shipped adversary drives the shipped matcher, with no pipeline between.

    This is the coverage the mock's token-vs-fakes branch used to withhold: a
    realistic pseudonymization payload carries both shapes, the old mock took the
    token branch and never quoted a fake, and the surrogate pass therefore had
    nothing to match in any end-to-end run. Asserting on ``surrogates_seen`` here
    is asserting that the anchors exist at all.
    """
    answer = await MockProvider().complete("system", MIXED_TIER_PAYLOAD, model="mock-1")

    # Premise first: if the mock stopped quoting the fakes this test would go on
    # passing while measuring only the token pass.
    for fake in MIXED_FAKES:
        assert fake in answer, fake

    restorer = Restorer(
        vault=FakeVault(tokens=MIXED_TOKENS, surrogates=MIXED_FAKES),
        settings=settings,
        audit=audit,
    )
    result = await restorer.restore(
        SESSION,
        answer,
        strategy=PSEUDONYMIZATION,
        surrogates=MIXED_FAKES,
        issued=tuple(MIXED_TOKENS),
        run_id=RUN,
    )

    assert result.tokens_seen > 0, "the token pass had nothing to do"
    assert result.surrogates_seen > 0, "the surrogate pass had nothing to do"
    assert result.restored_count == result.tokens_seen + result.surrogates_seen
    assert result.vault_misses == 0

    for original in (*MIXED_TOKENS.values(), *MIXED_FAKES.values()):
        assert original in result.text, original
    for fake in MIXED_FAKES:
        assert fake not in result.text, fake
    assert TOKEN_RE.search(result.text) is None
    assert UNRESOLVED_ENTITY not in result.text


async def test_every_mutation_the_mock_emits_survives_restoration(
    settings: Settings,
) -> None:
    """Whatever mutation class the mock assigns, the value comes back.

    ``plan_mutations`` is exported precisely so this can be asserted against the
    mock's real assignment rather than against a hand-copied list that drifts.
    """
    tokens = {
        f"{index:08x}": f"Value {index}"
        for index in range(len(MUTATION_CLASSES) + 2)
    }
    payload = "\n".join(
        f"Field {index}: [PHI_NAME_{token_id}]" for index, token_id in enumerate(tokens)
    )
    # One annotated token, so the hint_stripped class is reachable.
    payload += "\nTherapy: [PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]"
    tokens[MED_ID] = MED_VALUE

    plan = plan_mutations(payload)
    assert {mutation for _, mutation in plan} == set(MUTATION_CLASSES), "catalogue shrank"

    answer = await MockProvider().complete("system", payload, model="mock-1")
    restorer = Restorer(vault=FakeVault(tokens=tokens), settings=settings)

    result = await restorer.restore(
        SESSION, answer, strategy=TOKENIZATION, issued=tuple(tokens), run_id=RUN
    )

    assert result.vault_misses == 0
    assert result.lost == ()
    assert result.fabricated == ()
    for original in tokens.values():
        assert original in result.text, original
    assert TOKEN_RE.search(result.text) is None


# --------------------------------------------------------------------------
# Co-reference -- deliberately NOT solved (locked decision #8, section 13.4 Q2)
# --------------------------------------------------------------------------


async def test_coreference_sentence_passes_through_unchanged(restorer: Restorer) -> None:
    """No co-reference resolver, by design.

    Under tokenization the model paraphrased a token, so the referent behind
    "the patient" was never exposed: nothing leaks and nothing needs restoring.
    """
    text = "The patient's condition remains stable."

    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION)

    assert result.text == text
    assert result.restored_count == 0
    assert result.tokens_seen == 0


async def test_coreference_survives_alongside_a_restored_token(restorer: Restorer) -> None:
    text = "[PHI_NAME_1a2b3c4d] was seen today. The patient's condition remains stable."

    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION)

    assert result.text == (
        "John Smith was seen today. The patient's condition remains stable."
    )


# --------------------------------------------------------------------------
# Round-trip completeness and audit hygiene
# --------------------------------------------------------------------------


async def test_round_trip_completeness(restorer: Restorer) -> None:
    """Every obfuscated original reappears; no token or placeholder survives."""
    response = (
        "**[PHI_NAME_1a2b3c4d]**'s record (`[PHI_MRN_9c8d7e6f]`) shows that "
        "PHI_NAME_1a2b3c4d started [PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]. "
        "Reordering the tokens: {PHI_MRN_9c8d7e6f} and [PHI_MEDICATION_2f4a1b3c]."
    )

    result = await restorer.restore(SESSION, response, strategy=TOKENIZATION, run_id=RUN)

    for original in TOKENS.values():
        assert original in result.text
    assert TOKEN_RE.search(result.text) is None
    assert UNRESOLVED_ENTITY not in result.text
    assert result.restored_count == 6
    assert result.vault_misses == 0


async def test_audit_records_counts_and_no_originals(
    restorer: Restorer, audit: AuditLogger
) -> None:
    text = "[PHI_NAME_1a2b3c4d] takes [PHI_MEDICATION_2f4a1b3c]; [PHI_NAME_deadbeef] does not."

    result = await restorer.restore(SESSION, text, strategy=TOKENIZATION, run_id=RUN)

    events = await audit.query(session_id=SESSION)
    assert [event.run_id for event in events] == [RUN, RUN]

    summary = next(event for event in events if event.event_type == DEOBFUSCATE)
    assert summary.detail["restored"] == result.restored_count == 2
    assert summary.detail["vault_misses"] == 1
    assert summary.detail["strategy"] == TOKENIZATION
    assert summary.detail["outcome"] == "ok"

    dumped = json.dumps([event.model_dump() for event in events])
    for original in TOKENS.values():
        assert original not in dumped
    assert await audit.verify_chain() is True


async def test_result_repr_masks_the_restored_text(restorer: Restorer) -> None:
    """``f"{result}"`` in a log line must not leak the answer."""
    result = await restorer.restore(SESSION, "[PHI_NAME_1a2b3c4d]", strategy=TOKENIZATION)

    assert isinstance(result, RestoreResult)
    assert NAME_VALUE not in f"{result}"
    assert NAME_VALUE not in repr(result)


async def test_wrong_session_cannot_read_another_sessions_tokens(
    restorer: Restorer,
) -> None:
    result = await restorer.restore("other-session", "[PHI_NAME_1a2b3c4d]", strategy=TOKENIZATION)

    assert result.text == UNRESOLVED_ENTITY
    assert NAME_VALUE not in result.text


# --------------------------------------------------------------------------
# Performance (build doc section 12: 500-token response < 500 ms)
# --------------------------------------------------------------------------


async def test_500_token_response_restores_under_500ms(
    settings: Settings, audit: AuditLogger
) -> None:
    token_count = 500
    tokens = {f"{index:08x}": f"Patient Number {index}" for index in range(token_count)}
    restorer = Restorer(vault=FakeVault(tokens=tokens), settings=settings, audit=audit)
    response = " ".join(
        f"Note {index}: **[PHI_NAME_{index:08x}]**'s review is complete; the patient is stable."
        for index in range(token_count)
    )

    started = time.perf_counter()
    result = await restorer.restore(SESSION, response, strategy=TOKENIZATION, run_id=RUN)
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    assert result.restored_count == token_count
    assert result.vault_misses == 0
    assert TOKEN_RE.search(result.text) is None
    # Generous margin against the 500 ms budget; typical run is ~5 ms.
    assert elapsed_ms < 500.0, f"restore took {elapsed_ms:.1f} ms for {token_count} tokens"
