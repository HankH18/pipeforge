"""Zero-PII-in-transit leakage harness (build doc section 10.5). Marker: ``leakage``.

This is the headline security artifact. The claim it underwrites is not "the
detector found everything" -- no NER model has perfect recall, and a guarantee
resting on recall is not a guarantee. The claim is an **egress property**: across
100 independent pipeline runs over freshly generated documents, in both
obfuscation strategies, no original value ever reached the outbound payload, the
audit log, or the process log, and everything the model actually referred to came
back intact.

**Both halves of the payload carry originals, and one of them did not until recently.**
The outbound payload is ``{system prompt} + {user prompt} + {obfuscated document}``,
and for its whole history this module sent one module-level constant --
``"Summarise this record and list the key parties, dates and figures."`` -- as the
prompt on all 100 runs. So the third of the payload a *user* writes was PII-free by
construction, and every "100/100 clean" ever quoted was a statement about the document
half with nothing to say about the other. Each run now draws a real planted literal out
of its own fixture and puts it in the prompt, rotating a name, an email address and a
phone number across the runs; see :func:`prompt_for`.

Four assertions per run (build doc section 10.5):

1. **Outbound payload holds zero originals**, checked against the vault's own
   ``originals_for_session`` in raw, normalised, invisible-character-folded and
   combining-mark-skeleton form, plus the unbounded identifier needles, plus those
   four forms again per constituent of a composite original -- the same **six**
   comparisons ``EgressGate._scan_originals`` makes, over the same two views of the
   payload it makes them against (as sent, and transport-decoded), so the harness
   cannot pass on a form the gate would catch -- and with no minimum length, so a short
   value the gate skips still fails here. **Exactly one span is exempt**, and its
   width is eight characters: the hexadecimal id of a token *this run issued*, matched
   by exact string occurrence and blanked before any limb reads the payload
   (:func:`_harness_mask_own_ids`). That id is an HMAC under the session key truncated
   to eight hex characters, so a needle found inside one is a coincidence with a random
   string rather than a disclosure -- and the unbounded limbs, which have no adjacency
   requirement by design, were reporting those coincidences as *"original present in
   the outbound payload"*. Nothing else the pipeline wrote is excused. A pseudonym in
   particular is not: a fake that reproduces a real value verbatim puts that value on
   the wire wherever it sits, and this harness has caught exactly that once. The run
   additionally asserts that no surrogate equals the value it replaces.
2. **Audit DB and captured log output hold zero originals.** The audit side is
   queried through :meth:`AuditLogger.query` and, as defence in depth, the raw
   SQLite files are scanned as bytes -- a value that never survives the query API
   but sits in a page of the DB file is still a leak. Both audit views resolve JSON
   ``\\uXXXX`` escapes, because ``canonical_json`` is ``ensure_ascii=True`` and an
   accented original is otherwise stored, and re-serialised, in a form no raw scan
   matches. The log side is every record the package emitted at ``DEBUG``,
   **including its ``extra=`` fields** -- ``caplog.text`` renders none of them, and
   this package logs almost every variable it has through ``extra``.

3. **Round-trip completeness.** For every surrogate the model actually mentioned,
   the original is back in the restored text. The expected set is derived from
   ``result.raw_llm_response``, which is the only correct formulation: the mock
   quotes a *subset* of the document's entities, so "every vaulted original
   appears in the restored text" is unsatisfiable by construction and would be a
   false failure rather than a finding.
4. **Nothing surrogate-shaped survives.** Zero ``TOKEN_RE`` matches and zero
   issued surrogates left in the restored text -- a token that reaches the user
   is a broken answer, and a surviving pseudonym is a silently wrong one.

**What this harness measures, and what it does not.** The claim is about *whole
vaulted values*, per channel, per session. Four boundaries are deliberate, and are
stated here rather than left to be discovered. Each is pinned by a test, so a change
that closes one is a red rather than a silent widening of the headline claim.

There used to be five. The one that left -- *a combining mark spliced into a value* --
did not leave because it was closed here; it left because **the gate had closed it and
this file had not noticed**, and was still printing a paragraph explaining why the gate
could not. That paragraph's reasoning ("folding marks out would make ``José`` and
``Jose`` the same value") is a statement about the *needle*, and the gate strips marks
from the **haystack** only, which collapses nothing. The harness was therefore weaker
than the code it measures, and arguing on the record for a limitation the code no
longer had. See :func:`test_the_scan_sees_a_combining_mark_spliced_into_a_value`:

* **Partial disclosure is out of scope**, with one carve-out named below. If a splice
  bug leaves one component of a
  multi-word original behind -- the surname of a vaulted full name -- neither this
  harness nor the gate reports it, because both ask whether the *value* occurs. A
  word-level scan is not safely assertable: fixture originals include ordinary
  clinical phrases and Faker surnames that are ordinary English words, so it would
  manufacture reds indistinguishable from the real thing. See
  :func:`test_a_partial_value_leak_is_outside_what_this_harness_claims`, which pins
  the boundary so it cannot be forgotten.

  **The carve-out is a *composite* original, and it is a different question from a
  partial one.** A vault original is whatever the detector called one span, and spaCy
  returns ``03/11/2024, 09/17/2024`` as a single ``DATE`` -- so the "value" both
  scanners ask about is a string the document contains but which nobody wrote as a
  unit, and one of the dates in it is a whole value in its own right rather than a
  component of one. That distinction is what makes it safely assertable where the
  surname is not: a constituent qualifies only when the original splits on an English
  list delimiter (never on whitespace) into pieces that *each* carry seven digits, so
  no ordinary word can become a needle. Both the gate and :func:`find_in_text` now
  scan for those constituents (:func:`_composite_needles`). It matters more than a
  boundary usually does because this pipeline can **manufacture** the fragment: a
  third date shifted by the session delta renders as a verbatim slice of the
  composite. Detection also splits such spans upstream now, so the composite should
  no longer be vaulted at all -- this limb is the second opinion on that.
* **A NAME glued into a longer word is out of scope -- on the text channels.**
  ``xJohn Smithx`` carries the original byte for byte and is not reported by
  :func:`find_in_text`, because :func:`_occurs_as_a_unit` asserts a word boundary on
  each side whose adjacent needle character is alphanumeric. Removing that assertion
  is what makes ``Brown`` match inside ``Browning``; restricting the relaxation to
  multi-word originals does not help either, because ``chronic low back pains``
  contains ``chronic low back pain``.
  See :func:`test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims`.

  **The word NAME is load-bearing and used to be missing.** The false-positive
  argument above is a *word-list* argument -- ``Browning`` is a real word containing
  ``Brown`` -- and it does not transfer to an identifier: ``batch47-1234567Alpha`` is
  not a real anything containing a taxpayer ID. The gate drew that distinction and
  this harness did not, so ``47-1234567`` inside ``batch47-1234567Alpha`` was a value
  the **gate blocked and the harness called clean**. :func:`find_in_text` now carries
  the gate's :func:`_identifier_needles`, so any value with seven or more digits is
  additionally compared as a bare substring with no adjacency requirement at all. See
  :func:`test_the_scan_sees_an_identifier_glued_into_a_longer_run`.

  It bites hardest on the audit *file*, where it is a boundary of one **limb** rather
  than of the whole assertion. SQLite writes a record's column values end to end with
  no delimiter, so an original in any label column is always glued between
  alphanumerics -- ``...EGRESS_BLOCKMarguerite Vandenbergdeadbeef...`` -- and
  :func:`find_in_bytes` reports a file containing the value byte for byte as clean.
  :func:`find_in_text` over the *query* view of the same rows sees
  ``"entity_type": "Marguerite Vandenberg"``, where JSON quoting supplies the
  boundaries, and catches it; assertion 2 applies both. Loosening the byte limb so it
  could carry the case alone was tried and reverted -- ``8.2`` is an ordinary vaulted
  lab value and ``{"elapsed_ms":18.25}`` then reads as a leak. See
  :func:`test_the_byte_limb_and_the_query_limb_of_the_audit_scan_see_different_things`.
* **Cross-session leakage is out of scope here.** Each run scans only its own
  session's originals. Cross-session isolation is a cryptographic property, proven
  in ``test_vault.py::test_aad_binding_across_sessions`` and
  ``integration/test_pipeline.py::test_concurrent_session_isolation``, rather than a
  scan-form question.
* **Homoglyph substitution is out of scope**, for the same reason it is out of scope
  in the gate: catching Cyrillic U+043E for Latin ``o`` needs a confusables table,
  not another normalisation form.

The first, second and fourth share one cause and it is worth naming: they are the
shapes for which the harness and the gate are blind **together**, because both resolve
to the same occurrence rule. Where the gate is a second opinion that failure is
survivable; on the audit database and the process log, where nothing else looks, it is
not -- which is why they are recorded here as claims the harness does not make rather
than as cases it happens not to have hit.

**Blind together is the survivable case. Blind alone is not, and it is the one that
keeps happening.** Every time the gate has gained a limb, this file has been a release
behind it, and each gap was a real hole rather than a stylistic one: the gate gained
the invisible-character fold and the harness reported clean through a U+200B; the gate
gained :func:`_deaccent` and the harness reported clean through a combining mark; the
gate gained :func:`_identifier_needles` and the harness reported clean through
``batch47-1234567Alpha``. On the payload those are survivable -- the gate still blocks.
On the audit database and the process log **the harness is the only opinion there is**,
so each one was a complete bypass of the "zero originals in the audit log" half of the
headline claim for as long as it lasted.
:func:`test_the_harness_scan_is_never_weaker_than_the_gate_scan` now drives both
implementations over the same inputs and fails on any payload the gate blocks and this
file calls clean, so the next limb the gate grows is a red here rather than a silence.

**The one time the asymmetry ran the other way, and what it cost.** Every entry above
is the gate gaining reach and this file lagging. The own-token-id exclusion is the
mirror image: the gate *narrowed*, dropping a false ``EGRESS_BLOCKED`` refusal on runs
where a vaulted digit run happened to appear inside one of our own HMAC ids, and this
file did not follow -- so the identical non-event stopped failing at the gate and
started failing on **assertion 1**, which reads as "an original reached the provider".
That is a worse red for the same nothing, and it is the one direction where being
stricter than the gate is not free: a ~1-per-suite false positive on the headline claim
is a claim nobody can quote. Closed here by :func:`_harness_mask_own_ids`, and
deliberately **not** by importing the gate's ``_mask_own_tokens``: the exemption is
derived from the vault's own issued-surrogate map, and
:func:`test_the_own_id_exclusion_does_not_ask_the_gate_for_its_answer` stubs the gate's
whole exemption dead and requires this module to exclude anyway -- the same sabotage
:func:`_harness_separator_hit` and :func:`_reference_skeleton` each already earned.

Then one adversarial run that removes detection from the argument entirely: a
value of a shape **no recogniser in the registry matches** is planted in the
document and injected into the vault's originals set, so the detector is provably
blind to it and the value rides through to the payload untouched. The gate must
still block, the block must be audited, and the provider must never be called.
That is the fail-closed property, proven independent of detection recall.

**What a green run here is evidence of, and what it is not.** The summary line is the
product claim README section 1 quotes, so the reliability of *this file* is part of the
claim and is stated with it rather than left to be inferred. A clean execution is
evidence that on 100 freshly generated documents, in that process, no original reached
the outbound payload, the audit database or the process log, inside the boundaries
listed above. It is **not** evidence that this module is deterministic, and N of them in
a row is not either. The identifier limbs compare unbounded digit needles against
digit-dense haystacks that are re-drawn on every process, so they collide by birthday at
a rate that is measured rather than argued -- :data:`_FALSE_RED_PER_SUITE`, currently
9.4e-03 spurious reds per suite, with the per-channel arithmetic and the narrowing
decisions in :data:`_HARNESS_RUN_FLOOR`. The residual is **one-sided**: a collision adds
a reported occurrence, so it can turn a clean run red and can never turn a leaking run
green. ``0 leaks`` therefore means exactly what it says; what the streak of greens does
not establish is that the next run will agree, and by the rule of three it takes about
:data:`_CLEAN_SUITES_TO_BOUND` clean executions before a green streak bounds that rate
at all. The bounded forms are a fifth channel that is bounded by observation rather than
computed -- at most 1.5e-02 per suite, from a cross-run null over the 116 vaulted
originals of six characters or fewer -- and it is declared beside that total rather than
added to it, for the reason :data:`_HARNESS_RUN_FLOOR` gives. :meth:`Ledger.summary`
prints all of that beside the tally, because a residual recorded only in a docstring is
a residual the reader of the result never sees.

Run it with ``pytest -m leakage``. **94-102 s** on this machine, measured rather than
remembered -- six consecutive invocations of ``pytest tests/leakage/ -q -s`` took
94.44, 95.46, 102.05, 101.98, 98.71 and 96.05 s, of which the 100 runs themselves were
88.5, 88.9, 95.2, 95.2, 91.6 and 89.8 s. A range rather than a point because three
earlier invocations of the same file took 93.10/93.49/93.81 s: the spread is other work
on the machine, which these six were deliberately taken under, and quoting the
fastest one as *the* number is how the last two figures went stale. The spaCy analyzer
and the whole component graph are built once for the module and every run gets a fresh
session. The number in this sentence had drifted to "40 s" while the suite actually took
53 s, and then to "57 s" while it took 95; that is harmless here and is the same habit
that makes a stale claim about a *limit* dangerous, so it is re-measured when quoted.
"""

from __future__ import annotations

import ast
import base64
import json
import linecache
import logging
import re
import secrets
import time
import unicodedata
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from html import unescape
from pathlib import Path
from types import SimpleNamespace
from typing import Any, NamedTuple, cast
from urllib.parse import unquote

import pytest
import pytest_asyncio
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fixtures import generator
from secure_context_pipeline.audit.logger import EGRESS_BLOCK, AuditLogger, canonical_json
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import normalize
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection.detector import Detector
from secure_context_pipeline.detection.registry import EntityRegistry, load_registry
from secure_context_pipeline.errors import EgressBlockedError
from secure_context_pipeline.llm.base import LLMResponse
from secure_context_pipeline.llm.mock_provider import MockProvider
from secure_context_pipeline.models import (
    MAX_AUDIT_LABEL_LEN,
    MAX_DETAIL_VALUE_LEN,
    AuditEvent,
    Detection,
    PipelineResult,
    TokenRecord,
)
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline import egress_gate
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import (
    MIN_JOINED_ALNUM_LEN,
    MIN_ORIGINAL_LEN,
    EgressGate,
    _composite_needles,
    _digits_only,
    _identifier_needles,
    _regrouped_identifier_needle,
)
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import EncryptedDocumentStore
from secure_context_pipeline.surrogates import TOKEN_RE, extract_token_ids
from secure_context_pipeline.textrules import (
    occurs_as_a_unit as _textrules_occurs_as_a_unit,
)
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault

pytestmark = pytest.mark.leakage

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = REPO_ROOT / "entities.yaml"

#: Section 10.5 fixes the run count. If this harness gets slow, shrink the
#: documents -- never the run count.
RUNS = 100

USER_ID = "leakage-user"

#: The instruction half of every prompt. Carries no PII and never did -- which was
#: the whole problem, see :func:`prompt_for`.
BASE_PROMPT = "Summarise this record and list the key parties, dates and figures."

#: Used only by the two adversarial tests below, where the planted value is the
#: subject of the test and the prompt is deliberately inert. The 100 runs use
#: :func:`prompt_for`.
PROMPT = BASE_PROMPT

#: Both strategies alternate across the runs; three document kinds rotate under
#: them, so every (strategy, kind) pair is exercised many times over.
STRATEGIES = ("tokenization", "pseudonymization")
KINDS = ("medical", "legal", "financial")
DOC_CATEGORY = {"medical": "medical", "legal": "legal", "financial": "financial"}

#: Seed offset. Each run gets its own seed, so the 100 runs are 100 *different*
#: documents rather than one document scanned 100 times.
SEED_BASE = 90_000

#: A value whose shape no recogniser in ``entities.yaml`` matches -- no digits in
#: a pattern-bearing position, not a person, not a place, not a case number.
#:
#: The obvious candidate shape for this -- alphanumeric groups separated by
#: hyphens with a run of digits in the middle -- is NOT blind to the shipped
#: registry: ``CASE_ID``'s second pattern, ``\b\d{2}-[A-Z]{1,4}-\d{3,6}\b``,
#: claims that substring at score 0.70, so the engine would obfuscate the value
#: and the gate would never see it, making the adversarial case prove nothing.
#: The all-alphabetic grouping below avoids it, and
#: ``test_planted_value_is_invisible_to_the_detector`` asserts that blindness in
#: every document category rather than assuming it.
UNKNOWN_SHAPE_VALUE = "ZXQQ-KLM-RSTV-WYNP"

#: Where the planted value is put. It reads like an internal reference code,
#: which is exactly the class of value a registry-driven detector misses.
PLANT_TEMPLATE = "\n\nVendor control marker: {}\nRouting is keyed on this marker only.\n"


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


def plan_run(index: int) -> tuple[int, str, str]:
    """``(seed, kind, strategy)`` for run ``index``. Pure, so IDs are stable."""
    return SEED_BASE + index, KINDS[index % len(KINDS)], STRATEGIES[index % len(STRATEGIES)]


def run_id_for(index: int) -> str:
    seed, kind, strategy = plan_run(index)
    return f"{index:03d}-{kind}-{strategy}-seed{seed}"


#: Rotated across the runs so the prompt half carries a different *shape* of original
#: each time: a person's name (NER-typed), an email address (pattern-typed), and a
#: phone number -- which is ten digits, so it is also the one that puts the gate's
#: :func:`_identifier_needles` limb on the prompt channel. Every fixture kind plants
#: all three at every seed, asserted in :func:`test_the_prompt_carries_a_real_original`.
PROMPT_ENTITY_TYPES = ("NAME", "EMAIL", "PHONE")

#: A lower-case role noun immediately before the value. Not decoration: ``fixtures``
#: documents that bare object-position names are dropped by spaCy often enough to
#: matter, and its own documents place every person behind one of these for that
#: reason. The prompt is a nine-word string with no clinical context, which is the
#: worst case NER ever sees, so it gets the same treatment.
PROMPT_ROLE_NOUN = {"medical": "patient", "legal": "client", "financial": "customer"}

PROMPT_FRAMES = {
    "NAME": "Pay particular attention to the entries for {role} {value}.",
    "EMAIL": "Cross-check any correspondence sent to {value}.",
    "PHONE": "Confirm the contact number {value} against the rest of the file.",
}


def drawn_original(seed: int, kind: str, entity_type: str) -> str:
    """One planted literal of ``entity_type`` from the document run ``seed``/``kind``.

    Read out of :func:`fixtures.generator.expected_entities`, which returns the exact
    strings the generator interpolated, so this is the same value the vault will hold
    rather than something re-parsed out of the rendered text.

    The longest candidate, tie-broken by position, so ``NAME`` yields ``Marguerite
    Vandenberg`` rather than the bare surname the generator also plants -- a full name
    is what a user actually types, and the surname is a substring of it anyway.
    """
    candidates = generator.expected_entities(seed, kind).get(entity_type, [])
    if not candidates:
        raise AssertionError(
            f"fixtures plant no {entity_type} in {kind}/seed {seed}, so the prompt for "
            "this run would carry no original and the run would silently go back to "
            "measuring a PII-free constant"
        )
    return sorted(candidates, key=lambda v: (-len(v), candidates.index(v)))[0]


def prompt_for(index: int) -> str:
    """The user prompt for run ``index`` -- **carrying a real original from the document**.

    Until this existed the module held a single constant, ``"Summarise this record and
    list the key parties, dates and figures."``, and used it for all 100 runs. The
    payload is ``{system prompt} + {user prompt} + {obfuscated document}``, so a third
    of the outbound bytes -- and the only third a *user* writes -- was PII-free by
    construction on every run behind the headline number. "No original reached the
    payload" was therefore a claim about the document half only, and nothing in the
    file said so.

    That is not a small gap, because the prompt is the input a person types. The
    natural prompt for this product is *"summarise this record for Marguerite
    Vandenberg"* or *"cross-check the 03/12/1985 admission"*: real deployments put the
    same values in the prompt that are in the document, and a pipeline that obfuscates
    only the document ships them straight to the provider. A harness that only ever
    sends a constant cannot tell the difference between a pipeline that handles that
    and a pipeline that does not.

    So every run now draws a real planted literal from its own document and puts it in
    the prompt, rotating through three shapes (:data:`PROMPT_ENTITY_TYPES`). What that
    buys, per run and on both strategies:

    * the prompt half of assertion 1 is no longer vacuous -- there is a value in it
      that must not reach the provider;
    * the value is one the *document* also vaults, so the round trip has to keep the
      user's own cross-reference intact rather than merely surviving it;
    * one run in three puts a ten-digit phone number in the prompt, which is the
      identifier shape :func:`_identifier_needles` exists for.

    The value is deliberately **not** invented: it is drawn from the fixture, so if the
    pipeline ever stops treating the prompt as an input to obfuscate, all 100 runs
    block at the gate rather than 100 runs quietly passing on a prompt that never
    contained anything. Fail-loud is the correct direction for that regression, and
    :func:`test_the_prompt_carries_a_real_original` states the premise directly so the
    failure names its own cause.
    """
    seed, kind, _strategy = plan_run(index)
    entity_type = PROMPT_ENTITY_TYPES[index % len(PROMPT_ENTITY_TYPES)]
    value = drawn_original(seed, kind, entity_type)
    frame = PROMPT_FRAMES[entity_type].format(role=PROMPT_ROLE_NOUN[kind], value=value)
    return f"{BASE_PROMPT} {frame}"


# ---------------------------------------------------------------------------
# Provider wrapper -- proves the call never fired
# ---------------------------------------------------------------------------


class CountingProvider:
    """``MockProvider`` plus a call counter and the exact strings it was handed.

    Two claims need a provider-side observer, and neither can be made from the
    orchestrator's own return value:

    * *the network call never happened* (the adversarial case) -- only a call
      counter at the boundary can say that;
    * *the string the gate scanned is the string that was sent*. The gate scans
      :attr:`ContextInjector.Payload.serialized`, and the provider is handed
      ``(system, user)`` separately. Those are two different expressions of the
      same bytes, and nothing in the type system keeps them equal --
      ``context_injector`` says so in as many words ("if the provider call ever
      stops sending exactly these two strings, this property must change with
      it"). Recording both halves here lets the run below check that the
      egress guarantee attaches to the real outbound payload rather than to a
      reconstruction of it.
    """

    name = "mock"

    def __init__(self) -> None:
        self._inner = MockProvider()
        self.calls = 0
        self.last_system: str | None = None
        self.last_user: str | None = None

    @property
    def last_payload(self) -> str | None:
        """The outbound payload as the provider received it, re-serialized.

        Built the way :meth:`ContextInjector.Payload.serialized` builds it, so an
        equality check against ``result.obfuscated_payload`` is meaningful.
        """
        if self.last_system is None or self.last_user is None:
            return None
        return f"{self.last_system}\n\n{self.last_user}"

    async def complete(self, system: str, user: str, *, model: str, timeout_s: float = 60.0) -> str:
        response = await self.complete_detailed(system, user, model=model, timeout_s=timeout_s)
        return response.text

    async def complete_detailed(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> LLMResponse:
        self.calls += 1
        self.last_system = system
        self.last_user = user
        return await self._inner.complete_detailed(system, user, model=model, timeout_s=timeout_s)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Harness:
    settings: Settings
    registry: EntityRegistry
    detector: Detector
    store: EncryptedDocumentStore
    sessions: SessionRegistry
    vault: SessionVault
    audit: AuditLogger
    provider: CountingProvider
    orchestrator: PipelineOrchestrator
    audit_db: Path

    def audit_bytes(self) -> bytes:
        """The audit DB as raw bytes, including the WAL sidecar.

        Scanning the file rather than the query result is what makes "no
        originals in the audit log" a statement about the *storage*, not about
        the accessor we happen to use.
        """
        blob = b""
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.audit_db) + suffix)
            if path.is_file():
                blob += path.read_bytes()
        return blob


def _run_label(index: int) -> str:
    """``run 086 (financial/tokenization, seed 90086, id 086-financial-...)``.

    Spelled out rather than left as the parametrize id, because the four facts are
    what a reader acts on and the id is what they paste into ``-k``. Both, once.
    """
    seed, kind, strategy = plan_run(index)
    return f"run {index:03d} ({kind}/{strategy}, seed {seed}, id {run_id_for(index)})"


def _failure_site(exc: BaseException) -> str:
    """Where a run died, as ``line N: <source>``, carrying **no exception message**.

    The message is deliberately left out. Everything this module raises itself is
    already ``mask``-ed, but an exception out of the *package* is arbitrary text
    that has been near the document -- and this string is printed by the summary,
    which is the one line a reviewer copies out of the run. A file, a line number
    and the source text of the statement are enough to name the assertion, cost
    nothing to produce, and cannot carry an original by construction. The full
    message is not lost either way: pytest still prints the failing run's own
    traceback directly above the summary.

    The quoted statement is *source*, which is the only reason quoting it is safe:
    it can carry a value only if that value is hardcoded in this file, and every
    original here is drawn from the generator at runtime. Pinned from the other
    side by ``test_a_run_that_dies_before_record_is_named_with_its_reason``, which
    raises through a local so a literal cannot supply the string it looks for.

    Two frames matter and they are usually different. The deepest frame *in this
    file* is the harness statement that failed -- for a pipeline exception that is
    the ``orchestrator.run`` call, which is exactly the fact worth recording. The
    deepest frame overall says which module actually raised, which is what tells a
    gate timeout apart from a failed assertion two lines later.
    """
    here = ""
    deepest = ""
    tb = exc.__traceback__
    while tb is not None:
        filename = tb.tb_frame.f_code.co_filename
        deepest = f"{Path(filename).name}:{tb.tb_lineno}"
        if Path(filename).name == Path(__file__).name:
            source = linecache.getline(filename, tb.tb_lineno).strip()
            here = f"harness line {tb.tb_lineno}: {source[:80]}"
        tb = tb.tb_next
    if not here:
        return f"raised in {deepest or '<no traceback>'}"
    if deepest.startswith(Path(__file__).name):
        return here
    return f"{here} -- raised in {deepest}"


@dataclass(frozen=True, slots=True)
class RunFailure:
    """One run that did not reach :meth:`Ledger.record`, and what it was doing.

    This exists because the harness failed exactly once, on run 086 under heavy
    concurrent load (two uvicorn servers and browser automation on the same
    machine), and the *failure* was diagnosable only from a traceback nobody had
    kept: what survived was ``99 == 100`` from the summary and
    ``Ledger(runs=99, leaks=0, ...)``, which says a run vanished and says nothing
    at all about which one or why. ``leaks=0`` even rules out the interesting
    answer, so the surviving evidence could not distinguish a gate timeout from a
    fixture error from an assertion three lines from the end.

    Four facts make the next occurrence answerable without a rerun: the run's
    identity (``run_id_for`` carries index, kind, strategy and seed), the
    exception *type*, the statement it came out of, and how long the run had been
    going. The last one is not padding -- the one observed failure was on a loaded
    machine, so "was this run 30x slower than its neighbours" is the first
    question to ask, and only the harness can answer it after the fact.

    Two failure modes in the pipeline are triggered by *load specifically*, both
    raise straight out of ``orchestrator.run``, and both leave exactly the residue
    that was observed -- no leak, no tally, no explanation:

    * ``DetectionError(reason="detect_deadline")`` -- ``Detector.detect`` refuses
      to *start* a chunk more than ``detect_timeout_s`` (30 s) in;
    * ``EgressBlockedError(reason="gate_exception")`` -- ``EgressGate.check`` wraps
      itself in ``asyncio.timeout(DEFAULT_TIMEOUT_S)``, also 30 s, and a gate that
      times out blocks rather than releasing.

    Neither is a hypothesis this file can confirm after the fact for run 086, and
    neither is being asserted here. They are named because the failure line now
    distinguishes them on sight: the exception type, the module that raised it
    (``raised in detector.py:NNN`` versus ``egress_gate.py:NNN``) and an
    ``elapsed_s`` past 30 s against the ~2.5 s a healthy run takes. Any of the
    ordinary assertions in the run body prints its own ``harness line NNNN:
    assert ...`` instead. Verified by forcing the second of the two: with the
    gate's budget temporarily set to 0.5 ms, the summary printed ``run 000
    (medical/tokenization, seed 90000, ...) raised EgressBlockedError after 1.08s
    at harness line NNNN: result = await harness.orchestrator.run(... -- raised in
    egress_gate.py:552``.
    """

    index: int
    exc_type: str
    where: str
    elapsed_s: float

    def __str__(self) -> str:
        return (
            f"{_run_label(self.index)} raised {self.exc_type} after "
            f"{self.elapsed_s:.2f}s at {self.where}"
        )


#: What one clean execution of this module is worth, as a number rather than a mood.
#:
#: The expected count of **spurious** reds per 100-run suite, by channel, measured on
#: the current tree; :data:`_HARNESS_RUN_FLOOR` carries the method, the raw window
#: counts and the per-channel narrowing decisions. Two replays gave 9.43e-03 and
#: 8.89e-03 in total and the larger is quoted here, because the conservative direction
#: for a false-positive rate is up.
#:
#: **The residual is one-sided, and that is the half a reader must not lose.** Every
#: entry is a needle colliding with a haystack, so each one can turn a run that leaked
#: nothing red. None of them can turn a run that leaked green -- a collision only ever
#: *adds* a reported occurrence. So the number below is not a discount on ``0 leaks``;
#: it is the rate at which this module cries wolf, and the only thing it takes away is
#: the inference "the harness went green four times, therefore it is deterministic".
#:
#: Spelled as a dict rather than a single float so the summary cannot quote a total
#: whose parts nobody can check, and so a channel that gets narrowed later has a line
#: to delete rather than a constant to edit.
_FALSE_RED_PER_SUITE: dict[str, float] = {
    # Fires as EgressBlockedError inside orchestrator.run -- the run dies before this
    # module scans anything, and surfaces through Ledger.diagnosis as a missing run.
    "payload (gate pass 1: regrouped + identifier limbs)": 6.53e-03,
    "audit query view (find_in_digit_heavy_text)": 1.03e-03,
    "DEBUG log haystack (find_in_digit_heavy_text)": 1.87e-03,
}

_FALSE_RED_TOTAL = sum(_FALSE_RED_PER_SUITE.values())

#: How many consecutive clean executions it takes before a green streak says anything
#: about :data:`_FALSE_RED_TOTAL` at all.
#:
#: The rule of three: seeing zero events in ``n`` trials bounds the rate at ``3/n`` with
#: 95% confidence and at nothing tighter. So one clean suite bounds this rate at 3 --
#: which is to say, at nothing -- and it takes ``3 / rate`` of them before "no false red
#: yet" is even *consistent* with the measured rate being real. Printed beside the tally
#: because the four-green-runs argument is the one this file has actually seen made.
_CLEAN_SUITES_TO_BOUND = round(3 / _FALSE_RED_TOTAL)


@dataclass(slots=True)
class Ledger:
    """Accumulates the run tally so the module can print one summary line."""

    runs: int = 0
    leaks: int = 0
    originals_vaulted: int = 0
    round_trip_checked: int = 0
    notes: list[str] = field(default_factory=list)
    #: Indices that entered the run body, and those that finished it. The
    #: difference is the set the old ``99 != 100`` could only count.
    entered: set[int] = field(default_factory=set)
    completed: set[int] = field(default_factory=set)
    failures: list[RunFailure] = field(default_factory=list)
    #: ``(seconds, index)`` for the slowest run, and the wall time of all of them.
    slowest: tuple[float, int] | None = None
    elapsed_total: float = 0.0

    @contextmanager
    def watching(self, index: int) -> Iterator[None]:
        """Wrap one run so that dying inside it is a recorded fact rather than a gap.

        Three bookkeeping lines and a ``try`` around a run that takes ~1.3 s, so the
        cost of doing this 100 times is not measurable against the 135 s the module
        takes. The ``except`` clause is ``BaseException`` on purpose: a timeout, a
        cancellation and a ``KeyboardInterrupt`` are exactly the outcomes that leave
        a run unrecorded, and catching only ``Exception`` would miss all three. It
        re-raises unconditionally -- **nothing here converts a red run into a green
        one**, and a run whose exception is swallowed would still be missing from
        :attr:`completed`, so the summary would still fail.
        """
        self.entered.add(index)
        started = time.perf_counter()
        try:
            yield
        except BaseException as exc:
            self.failures.append(
                RunFailure(
                    index=index,
                    exc_type=type(exc).__name__,
                    where=_failure_site(exc),
                    elapsed_s=time.perf_counter() - started,
                )
            )
            raise
        finally:
            elapsed = time.perf_counter() - started
            self.elapsed_total += elapsed
            if self.slowest is None or elapsed > self.slowest[0]:
                self.slowest = (elapsed, index)

    def record(self, *, index: int, originals: int, restored: int) -> None:
        self.runs += 1
        self.completed.add(index)
        self.originals_vaulted += originals
        self.round_trip_checked += restored

    def summary(self) -> str:
        """The tally, and what the tally is and is not evidence of.

        **The second half is not a disclaimer, it is the finding that a green run does
        not carry.** This line is the product claim quoted in README section 1, and for
        its whole history it said ``100/100 runs clean, 0 leaks`` and stopped -- which
        reads as *this harness is deterministic and it agreed with itself again*. It is
        not: :data:`_FALSE_RED_PER_SUITE` is a measured, seed-irreproducible channel that
        turns a clean run red about once in 110 executions, so *"it went green four times
        in a row"* is not evidence about this module's reliability. It takes
        :data:`_CLEAN_SUITES_TO_BOUND` clean executions before it is evidence at all, and
        that number belongs beside the tally rather than in a docstring nobody opens at
        the moment they are reading the result.

        The direction is stated as explicitly as the rate, because the honest caveat is
        narrow and an over-broad one would be its own dishonesty: the residual is a
        false-**red** channel. It can never explain a green, so ``0 leaks`` means what it
        says; what it cannot do is promise the next run says the same.

        Returned as one string of four lines rather than four calls, so that "the
        summary" cannot be copied without the sentence that qualifies it. The first line
        is byte-for-byte what it always was -- ``test_readme_claims`` parses it and the
        README quotes it -- and the qualification is added rather than substituted.
        """
        width = max(len(name) for name in _FALSE_RED_PER_SUITE)
        channels = "\n".join(
            f"            {name.ljust(width)}  {rate:.1e}"
            for name, rate in _FALSE_RED_PER_SUITE.items()
        )
        return (
            f"[leakage] {self.runs}/{RUNS} runs clean, {self.leaks} leaks "
            f"({self.originals_vaulted} originals vaulted and scanned, "
            f"{self.round_trip_checked} surrogates round-tripped)\n"
            "[leakage] evidence: for each run counted above -- a freshly generated "
            "document, in\n          THIS process -- no original reached the outbound "
            "payload, the audit DB or\n          the process log, inside the four "
            "boundaries this module's docstring declares.\n"
            "[leakage] NOT evidence: that this module is deterministic. Measured "
            f"{_FALSE_RED_TOTAL:.1e} spurious\n          reds per suite from the "
            "unbounded digit limbs -- one-sided (a collision\n          manufactures a "
            "red; it never turns a leak green), reproducible by no seed:\n"
            f"{channels}\n          the bounded limbs add an unquantified <=1.5e-02, "
            "bounded by observation only.\n"
            "[leakage] so N clean runs bound that rate at 3/N and no tighter (rule of "
            f"three):\n          ~{_CLEAN_SUITES_TO_BOUND} consecutive clean suites "
            "before a green streak is evidence about it.\n          Derivation: "
            "_HARNESS_RUN_FLOOR."
        )

    def timing(self) -> str:
        """The load line. Printed every time, because it is only useful *before* the fault.

        A run that fails under contention is diagnosed by comparing it against the
        runs that did not, and that comparison needs the healthy numbers to have
        been printed on the healthy days too.
        """
        if self.slowest is None:
            return "[leakage] no run was timed"
        seconds, index = self.slowest
        entered = len(self.entered)
        mean = self.elapsed_total / entered if entered else 0.0
        return (
            f"[leakage] {self.elapsed_total:.1f}s in {entered} run(s), "
            f"mean {mean:.2f}s, slowest {run_id_for(index)} at {seconds:.2f}s"
        )

    def diagnosis(self, expected: frozenset[int] = frozenset()) -> list[str]:
        """One line per run that was expected and never recorded. Empty when all did.

        ``expected`` is the selected set, so a run that never even entered the body
        -- a fixture error, a collection-time crash -- is reported as that, rather
        than being invisible the way it was when the only evidence was a count.
        """
        by_index = {failure.index: failure for failure in self.failures}
        lines = []
        for index in sorted((set(expected) | self.entered) - self.completed):
            failure = by_index.get(index)
            if failure is not None:
                lines.append(str(failure))
            elif index in self.entered:
                lines.append(
                    f"{_run_label(index)} entered the body, raised nothing and recorded "
                    "nothing -- an early return, or a deleted record() call"
                )
            else:
                lines.append(
                    f"{_run_label(index)} never entered the body -- it was selected but its "
                    "setup did not complete (fixture error, or the process died first)"
                )
        return lines


@pytest.fixture(scope="module")
def registry() -> EntityRegistry:
    return load_registry(REGISTRY_PATH)


@pytest.fixture(scope="module")
def leak_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    return Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path_factory.mktemp("leakage-data"),
        registry_path=REGISTRY_PATH,
        llm_provider="mock",
    )


@pytest.fixture(scope="module")
def detector(registry: EntityRegistry, leak_settings: Settings) -> Detector:
    """Built ONCE for the module -- and per-run scope would not undo that.

    The original reason given here was that "constructing it loads spaCy", which
    is only true the first time in a process: the ``AnalyzerEngine`` behind it is
    memoised in ``detection.detector._ANALYZERS``, a module-level dict keyed by
    spaCy model name, so the second ``Detector(...)`` in a process shares the
    first one's engine. Measured in one process: the first construction takes
    360 ms and its first ``detect`` a further 3.4 s; the second construction takes
    **1 ms**.

    That matters for the isolation question rather than for the timing one. The
    engine is the most-shared mutable object in this module -- up to
    ``detect_concurrency`` (4) worker threads call ``analyze`` on it at once -- and
    changing this fixture to per-run scope would not give a run its own copy of
    it. See :func:`harness` for what per-run scope would and would not buy.
    """
    return Detector(registry, leak_settings)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def harness(
    registry: EntityRegistry,
    leak_settings: Settings,
    detector: Detector,
    tmp_path_factory: pytest.TempPathFactory,
) -> Any:
    """The whole component graph, built once and reused; each run gets a fresh session.

    Everything is closed in the teardown: an unclosed aiosqlite connection keeps a
    non-daemon thread alive and hangs interpreter exit.

    **Module scope is not isolation, so the question of whether one run can perturb
    another was examined rather than assumed.** It came up because the harness
    failed once, on run 086, only under heavy concurrent load, and "the runs share
    everything" is the first thing anyone looks at. What the reading found:

    * **Every value in every assertion is keyed by the run's own session id.** Each
      run calls ``sessions.create``, and the needles come from
      ``vault.originals_for_session(session_id)``, which reads
      ``SessionVault._caches[session_id]``. ``get_by_original`` is scoped the same
      way, and pseudonymization's collision guard unions *that* set with the
      current document's own originals and nothing else. So no run can see, reuse
      or shift another run's values, and a session is never reused: the ids are
      fresh and the TTL (3600 s) is two orders of magnitude past the module's
      runtime, so nothing is swept mid-module either.
    * **Nothing outlives a run.** No ``create_task`` or ``ensure_future`` exists
      anywhere in the package -- every audit write, vault write and
      ``asyncio.to_thread`` offload is awaited before ``orchestrator.run`` returns
      -- so the shared event loop carries no work from one run into the next. The
      single exception is documented in ``Detector.detect``: after a
      ``detect_deadline`` its worker threads cannot be cancelled and keep burning
      CPU. That can only make the *next* run slower, and only after a run has
      already gone red, so it amplifies a visible failure rather than creating a
      silent one.
    * **One real coupling: the audit DB is one file for all 100 runs.** Assertion
      2a's byte limb scans ``audit_bytes()``, so run *n* scans every earlier run's
      rows as well as its own. The direction is strictly more haystack, never
      less, which makes it a strengthening rather than a hole -- with two
      consequences worth naming. Cost: the blob reaches **5.5 MB** after 100 runs
      (0.9 MB of database plus a WAL that saturates near 4.1 MB at SQLite's
      1000-page auto-checkpoint), and ``find_in_bytes`` over it measures **150 ms**
      against **1.6 ms** over the first run's 50 KB -- about 27 ms/MB, linear. End
      to end that shows up as **2.51 s mean for the first ten runs and 3.07 s for
      the last ten** on one 100-run invocation: real, bounded, and nowhere near a
      30 s budget. Attribution: a value that leaks in run *n* is reported again by
      every later run whose fixture plants the same string, so the first red is the
      guilty run and the rest are echoes.
    * **The shared object that per-run fixtures would not un-share** is the spaCy
      ``AnalyzerEngine``, memoised process-wide in ``detector._ANALYZERS``. See
      :func:`detector`.

    **What per-run fixtures would cost, measured, since that is the usual argument
    for keeping these.** Rebuilding the registry, the ``Detector`` and the three
    SQLite databases takes 60 ms (13 ms + 1 ms + 47 ms) once the process is warm,
    so 100 of them is ~6 s on a module that takes 135 s -- about 4%, which is not
    the reason to keep module scope. The reason is that it would buy no isolation
    the session id does not already provide, would leave the one genuinely shared
    mutable object shared anyway, and would change the artifact the README quotes.
    If a future finding shows a real cross-run mechanism, the cost of switching is
    4% and this paragraph is the evidence that it is affordable.
    """
    root = tmp_path_factory.mktemp("leakage-db")
    audit_db = root / "audit.db"
    audit = await AuditLogger.open(audit_db)
    store = await EncryptedDocumentStore.open(leak_settings)
    sessions = SessionRegistry(leak_settings)
    vault = await SessionVault.open(root / "vault.db", sessions)
    provider = CountingProvider()
    orchestrator = PipelineOrchestrator(
        store=store,
        detector=detector,
        engine=ObfuscationEngine(
            registry=registry,
            vault=vault,
            session_registry=sessions,
            settings=leak_settings,
            audit=audit,
        ),
        injector=ContextInjector(),
        gate=EgressGate(vault=vault, detector=detector, settings=leak_settings, audit=audit),
        provider=provider,
        restorer=Restorer(vault=vault, settings=leak_settings, audit=audit),
        vault=vault,
        settings=leak_settings,
        audit=audit,
    )
    try:
        yield Harness(
            settings=leak_settings,
            registry=registry,
            detector=detector,
            store=store,
            sessions=sessions,
            vault=vault,
            audit=audit,
            provider=provider,
            orchestrator=orchestrator,
            audit_db=audit_db,
        )
    finally:
        await vault.close()
        await store.close()
        await audit.close()


@pytest.fixture(scope="module")
def ledger(request: pytest.FixtureRequest) -> Iterator[Ledger]:
    """Tally across the module, printed once at teardown for the README.

    Three lines now, not one. The README quotes :meth:`Ledger.summary` and
    ``test_readme_claims.py`` parses it, so that line is unchanged; the timing line
    and any diagnosis lines are printed beside it. They go through the same
    capture-disabled path, because the only run that ever needed them was one
    whose per-test output a reviewer no longer had.
    """
    book = Ledger()
    yield book
    lines = [book.summary(), book.timing(), *book.diagnosis()]
    text = "\n" + "\n".join(lines)
    capture = request.config.pluginmanager.getplugin("capturemanager")
    if capture is not None:
        with capture.global_and_fixture_disabled():
            print(text)
    else:  # pragma: no cover -- capture plugin is always present under pytest
        print(text)


# ---------------------------------------------------------------------------
# Scan helpers
# ---------------------------------------------------------------------------


def mask(value: str) -> str:
    """A failure-message-safe shape descriptor.

    Fixture data is synthetic, but the habit of never rendering an original into
    output is the whole point of the exercise, so the harness keeps it too.
    """
    return f"<{len(value)} chars starting {value[:2]!r}>"


#: The occurrence rule, **imported** from the EgressGate rather than restated here.
#:
#: This file used to carry its own copy: ``(?<!\w)needle(?!\w)``. That copy was
#: wrong, and the way it was wrong is the most instructive thing in this module.
#:
#: ``_`` is a regex ``\w``. So for a payload containing ``_John Smith_`` -- ordinary
#: markdown emphasis, which the mock provider emits and a real model emits
#: constantly -- the harness **did not match its own planted original**, and
#: assertion 1 below passed on a payload carrying that value byte for byte. The
#: same hole swallowed every value whose first or last character is punctuation:
#: ``tel(415) 555-0123`` and ``USD$1,234.56`` both contain the original verbatim
#: and both read as clean, because the rule asked whether the character before
#: ``(`` was a word character, which is not a question about word boundaries.
#:
#: It was the **third** independent copy of that rule. The gate and the engine's
#: residual sweep held the other two, and all three agreed -- so the gate did not
#: block, the sweep did not mask, and the harness did not report. A green
#: ``100/100`` was measuring three copies of one bug agreeing with each other,
#: which is strictly worse than having no harness at all: it launders the claim.
#:
#: Importing is therefore not a tidiness preference. A renamed or re-scoped helper
#: is now an ImportError instead of a silent divergence, and there is exactly one
#: definition of what "this value appears in this text" means across the gate, the
#: engine, the restorer and this harness -- :mod:`secure_context_pipeline.textrules`,
#: a leaf module every consumer depends on *downward*. It was previously the gate's
#: own private copy, which fixed the divergence but inverted the layering and shared
#: only the alphabet: the engine and the restorer imported ``_ALNUM`` and then
#: reassembled the assertions by hand, so a rename raised ImportError while an edit
#: to the rule still had to be made in three places.
#: :func:`test_the_occurrence_rule_has_no_fourth_copy` checks that single definition
#: against an independently written reference, so the shared rule is still verified
#: rather than merely shared.
occurs_as_a_unit = _textrules_occurs_as_a_unit


def _digit_skeleton_hit(folded: str, digits_hay: str) -> bool:
    """Whether ``folded``'s digit skeleton occurs in the payload's."""
    needle = _regrouped_identifier_needle(folded)
    return needle is not None and needle in digits_hay


#: A tag-shaped run: ``<b>``, ``<br/>``, ``</span>``. Substituted with a **space**
#: rather than deleted -- deleting would glue the two halves of ``Jane<br/>Doe`` into
#: one alphanumeric run, and what the separators between components really are is the
#: whole question this view exists to answer.
_TRANSPORT_TAG_RE = re.compile(r"<[^>]*>")


def _decode_transport_encodings(text: str) -> str:
    """``text`` with percent-escapes, character references and tags resolved.

    The transports a document travels do not carry a space as a space. A note pasted
    out of a portal URL carries ``Jane%20Doe``; one round-tripped through HTML or Word
    carries ``Jane&nbsp;Doe``, ``Jane&#32;Doe`` or ``Jane<br/>Doe``. Every one of those
    is the vaulted value on the wire -- a model reads all of them as the name -- and
    every one defeats a separator rule written in terms of *non-alphanumeric*
    characters, because ``20``, ``nbsp``, ``32`` and ``br`` are alphanumeric.

    Applied as an **additional** view, never a replacement, for the same reason
    :func:`_unescape_json_unicode` is: this is a tag pattern applied to text that need
    not be markup, so ``a < b Marguerite Vandenberg > c`` loses its middle here and
    keeps it in the raw view. Decoding can therefore hide a match, and
    :func:`find_in_text` scans both views rather than choosing one.

    Cheap on the common input, which matters because the 100 runs scan megabyte-scale
    haystacks: each step is skipped outright when its marker character is absent, and a
    payload carrying none of ``%``, ``&`` or ``<`` is returned unchanged without a pass
    over it.

    The local is called ``resolved`` rather than ``decoded`` for a reason a reader will
    otherwise trip over. A membership test against a local of that name is one of
    :data:`_FORBIDDEN_MEMBERSHIP_SNIPPETS` -- it is how ``find_in_bytes`` once decided a
    leak with a bare ``in`` -- and the marker checks below would match it as source text.
    They decide whether a transform is worth running rather than whether a value leaked,
    so renaming the local is the honest fix; widening the guard to let them through is
    not, because the guard is a rule about what this file may contain at all.
    """
    resolved = unquote(text) if "%" in text else text
    if "&" in resolved:
        resolved = unescape(resolved)
    if "<" in resolved:
        resolved = _TRANSPORT_TAG_RE.sub(" ", resolved)
    return resolved


#: The joined-alphanumeric floor for this module's own separator limb.
#:
#: ``min`` of two numbers, and neither half is decorative. Taking the gate's constant
#: means the day the gate LOWERS its floor does not leave this module behind -- the
#: harness must never be the weaker of the two. Keeping this module's own 8 means the
#: day the gate RAISES its floor does not take the harness blind along with it, which
#: is the exact failure this limb was rewritten to end: two views of one number are
#: not two opinions.
_HARNESS_JOINED_ALNUM_FLOOR = min(8, MIN_JOINED_ALNUM_LEN)


def _alnum_components(value: str) -> list[str]:
    """``value`` split into its maximal alphanumeric runs, by index arithmetic.

    :meth:`str.isalnum` and a loop rather than ``groupby`` or a regex, because this is
    half of a second opinion -- see :func:`_harness_separator_hit`.
    """
    parts: list[str] = []
    current: list[str] = []
    for ch in value.strip():
        if ch.isalnum():
            current.append(ch)
        elif current:
            parts.append("".join(current))
            current = []
    if current:
        parts.append("".join(current))
    return parts


def _harness_separator_hit(value: str, haystack: str) -> bool:
    """``value`` present in ``haystack`` with its interior separators spelled anyhow.

    **This module's own derivation, deliberately sharing nothing with the gate's.** It
    answers the same question as ``egress_gate._occurs_with_flexible_separator`` and it
    is written the other way round on purpose: explicit :meth:`str.find` walking and
    :meth:`str.isalnum` here, a compiled ``[\\W_]*`` join there -- the same relationship
    :func:`_reference_occurs_as_a_unit` has to the boundary rule.

    **The import it replaces was a measured defect, not an untidiness.** This limb used
    to *call* the gate's helper, so gate and harness were one opinion wearing two names.
    The gate's own test file records the consequence: deleting ``_separator_needles``
    outright "left the full suite green, including all 128 leakage tests". And the
    inherited blind spot was live rather than theoretical --
    :func:`test_the_scan_sees_a_separator_the_payload_transport_encoded` is four
    payloads carrying a whole vaulted name that this module reported ``[]`` on, because
    it was asking the gate.

    The rule, in words, so the two derivations can be read against each other: *every
    alphanumeric component of the value occurs in the haystack, in order, with nothing
    but non-alphanumeric characters between consecutive components, and the characters
    immediately outside the first and last components are not alphanumeric.*

    Two guards before the walk, both floors rather than rules. A single-component value
    has no interior separator to vary, so this limb has nothing to add to the bounded
    forms; and a value whose components join to fewer than
    :data:`_HARNESS_JOINED_ALNUM_FLOOR` alphanumerics is short enough that relaxing its
    separators collides with ordinary prose.

    The ``in`` pre-filter is a *filter*, not a decision: the walk below requires every
    component as a literal, so the absence of the longest one is a sufficient reject,
    and one C-level scan turns the overwhelmingly common miss away before the loop is
    entered at all.
    """
    parts = _alnum_components(value)
    if len(parts) < 2 or sum(len(p) for p in parts) < _HARNESS_JOINED_ALNUM_FLOOR:
        return False
    if max(parts, key=len) not in haystack:
        return False
    head, rest = parts[0], parts[1:]
    start = 0
    while True:
        left = haystack.find(head, start)
        if left < 0:
            return False
        start = left + 1
        if left > 0 and haystack[left - 1].isalnum():
            continue  # inside a longer run: the outer boundary rule denies it
        pos = left + len(head)
        for part in rest:
            skip = pos
            while skip < len(haystack) and not haystack[skip].isalnum():
                skip += 1
            if not haystack.startswith(part, skip):
                break
            pos = skip + len(part)
        else:
            if pos >= len(haystack) or not haystack[pos].isalnum():
                return True


# ---------------------------------------------------------------------------
# The skeleton fold, re-derived here rather than imported
# ---------------------------------------------------------------------------
#
# This module used to import the gate's ``_skeleton`` and ``_deaccent``, on an
# argument written into ``_haystack_forms`` that looked airtight: a *fold* is
# applied to the haystack only, so it can only ever WIDEN what the scan sees,
# and sharing it costs nothing.
#
# **That argument is false, and a released payload is what proved it.** The fold
# DELETES characters, and the forms that consume it decide with
# :func:`occurs_as_a_unit`, a word-boundary rule evaluated on the folded string.
# A combining mark sitting immediately beside a vaulted value is a
# non-alphanumeric character -- a valid boundary. Remove it and the value is
# glued to the neighbouring word, so the boundary rule now REJECTS the very
# occurrence the skeleton exists to find. A fold feeding a decision is part of
# the decision.
#
# The cost of having imported it was exact: when the gate's mark selection was
# widened from combining CLASS to category ``M``, this module inherited the
# change silently, went blind in the same 42 payloads, and still printed
# ``100/100 runs clean, 0 leaks``. The headline number was not evidence about
# the skeleton at all.
#
# So the semantics are re-derived below from :mod:`unicodedata` directly. The
# ORDERING is copied deliberately and the reasoning restated -- that is the part
# a second opinion should agree with, and getting it wrong made this module
# weaker than the gate once already (see :func:`_haystack_forms`). The
# IMPLEMENTATION is this module's own, so a future change to the gate's fold
# makes the two disagree loudly instead of quietly.


def _reference_is_mark(ch: str) -> bool:
    """Every Unicode combining mark: general category ``M``. 2,408 codepoints."""
    return unicodedata.category(ch)[0] == "M"


def _reference_is_reordering_mark(ch: str) -> bool:
    """Marks with a non-zero canonical combining class. A strict subset: 912."""
    return unicodedata.combining(ch) != 0


def _reference_is_invisible(ch: str) -> bool:
    """Codepoints that render as nothing, so a payload can carry them for free.

    Category ``Cf`` is the bulk of it. The rest are the zero-width codepoints
    Unicode files under other categories -- fillers, variation selectors, the
    combining grapheme joiner -- listed by name rather than borrowed.
    """
    if unicodedata.category(ch) == "Cf":
        return True
    return ch in _REFERENCE_EXTRA_INVISIBLE


#: Zero-width codepoints that are NOT category Cf, so the check above misses them.
_REFERENCE_EXTRA_INVISIBLE: frozenset[str] = frozenset(
    "\u034f"  # combining grapheme joiner
    "\u115f\u1160"  # Hangul choseong/jungseong fillers
    "\u17b4\u17b5"  # Khmer inherent vowels
    "\u180b\u180c\u180d\u180e\u180f"  # Mongolian variation selectors
    "\u3164"  # Hangul filler
    "\uffa0"  # halfwidth Hangul filler
    + "".join(chr(cp) for cp in range(0xFE00, 0xFE10))  # variation selectors
    + "".join(chr(cp) for cp in range(0xE0100, 0xE01F0))  # variation selectors sup.
)


def _reference_is_spacing_diacritic(ch: str) -> bool:
    """Renders as a diacritic but is not a mark -- U+00B4, U+00A8 and their block.

    Identified by the compatibility decomposition Unicode gives them, ``<compat>
    0020 XXXX``: a space followed by the combining form. One property lookup, so
    restating it here is a genuine second derivation rather than a copy.
    """
    return unicodedata.decomposition(ch).startswith("<compat> 0020 ")


def _reference_fold_digits(value: str) -> str:
    """Every Unicode decimal digit rewritten in its ASCII spelling."""
    if value.isascii():
        return value
    return "".join(
        str(digit) if (digit := unicodedata.decimal(ch, None)) is not None else ch
        for ch in value
    )


def _reference_skeleton(
    value: str, *, is_mark: Callable[[str], bool] = _reference_is_mark
) -> str:
    """``value`` reduced to the shape a spliced-in mark cannot hide inside.

    The ordering is load-bearing and is the half worth agreeing with the gate
    about, so it is restated rather than re-invented:

    1. **Spacing diacritics first.** NFKC expands ``U+00B4`` into a space plus a
       combining acute, so stripping marks after normalising leaves the injected
       space behind and the needle still does not match.
    2. **Marks off the RAW text next.** ``normalize`` collapses whitespace, and a
       mark sitting between two spaces keeps them apart until it is removed --
       measured on vaulted ``00000  0`` against payload ``00000 <U+0301> 0``,
       where deriving in the other order reported CLEAN on a payload the gate
       blocked.
    3. Normalise, strip invisibles, then strip marks a **second** time, because
       NFKC's own compatibility decompositions introduce marks that were not in
       the raw text.
    4. Fold non-ASCII decimal digits last.
    """
    without_spacing = "".join(
        ch for ch in value if not _reference_is_spacing_diacritic(ch)
    )
    raw_deaccented = "".join(ch for ch in without_spacing if not is_mark(ch))
    normalised = normalize(raw_deaccented)
    visible = "".join(ch for ch in normalised if not _reference_is_invisible(ch))
    return _reference_fold_digits("".join(ch for ch in visible if not is_mark(ch)))


def _reference_strip_invisible(value: str) -> str:
    """The folded form: invisibles removed, marks and case-folding left alone."""
    return "".join(ch for ch in value if not _reference_is_invisible(ch))


class _HaystackForms(NamedTuple):
    """One haystack, in the five shapes the comparisons below need.

    Derived once per view rather than once per original: the 100 runs scan
    megabyte-scale blobs, and ``_digits_only`` alone is a full pass over one.
    """

    raw: str
    normalized: str
    folded: str
    skeleton: str
    #: The same skeleton under the combining-CLASS selection, which KEEPS the
    #: 1,496 class-0 marks the category selection removes. Both views are needed
    #: and neither is a superset: the category view catches a mark spliced INSIDE
    #: a value, and this one keeps a mark BESIDE a value readable as the word
    #: boundary it is. Deleting it glues the value to its neighbour and the
    #: boundary rule then denies the occurrence. Mirrors the gate's
    #: ``_Haystacks.boundary_skeleton``, derived independently.
    boundary_skeleton: str
    digits: str


def _haystack_forms(haystack: str) -> _HaystackForms:
    """The five derived shapes of ``haystack``. Names match the gate's ``_Haystacks``.

    The skeleton is **this module's own** (:func:`_reference_skeleton`), and the
    ordering below is the part deliberately agreed with the gate. This module once
    derived it as
    ``_deaccent(_strip_invisible(normalize(text)))``; the gate deaccents the RAW text
    first, because ``normalize`` collapses whitespace and a mark sitting between two
    spaces keeps them apart until it is removed. Measured, on the payload the fuzz below
    shrank to -- vaulted ``00000  0``, payload ``00000 <U+0301> 0``::

        this module's own ordering -> '00000  0'   (needle absent: two spaces)
        the gate's ordering        -> '00000 0'    (needle present: gate blocks)

    So the gate blocked a payload this module reported CLEAN, which is the exact
    asymmetry :func:`test_the_harness_is_never_weaker_than_the_gate_on_generated_input`
    exists to catch -- and it caught it.

    That paragraph used to end by arguing importing was right *here* and wrong one
    function down, because "a fold is applied to the haystack only and can therefore
    only widen what the scan sees". **The argument was false and a released payload
    proved it** -- see the block above :class:`_HaystackForms`. A fold that DELETES
    characters can destroy a word boundary, and the forms consuming it decide with
    :func:`occurs_as_a_unit`, so the fold is part of the decision. Fold and decision are
    now both this module's own; see :func:`_harness_separator_hit` for what the same
    lesson cost the separator limb, and :func:`_reference_occurs_as_a_unit` for how the
    boundary rule pays it back.
    """
    norm_hay = normalize(haystack)
    folded_hay = _reference_strip_invisible(norm_hay)
    skeleton_hay = _reference_skeleton(haystack)
    return _HaystackForms(
        raw=haystack,
        normalized=norm_hay,
        folded=folded_hay,
        skeleton=skeleton_hay,
        boundary_skeleton=_reference_skeleton(
            haystack, is_mark=_reference_is_reordering_mark
        ),
        digits=_digits_only(skeleton_hay),
    )


#: Length of a token id, as :func:`issued_token_id` parses one. Spelled here rather
#: than imported from ``surrogates`` for the same reason that function is hand-written:
#: the whole value of this exclusion is that it is decided without the production
#: grammar, and a length is part of the decision.
_HARNESS_ID_LEN = 8

#: What each character of one of **our own** emitted token ids is rewritten to before
#: any scan in this module reads the haystack. See :func:`_harness_mask_own_ids`.
#:
#: Three properties make this character inert, and they are the reason it is not a
#: decorative choice:
#:
#: * **alphanumeric**, so it cannot move a word boundary in either direction: a
#:   neighbour that was glued to a token id is still glued to it, and a neighbour that
#:   was separated from it by our ``_`` or ``]`` still is. Every bounded form in this
#:   module decides with :func:`occurs_as_a_unit`, which keys on
#:   :data:`~secure_context_pipeline.textrules.ALNUM_RE`, so a mask of a *different*
#:   class would be a fold that deletes a boundary -- the exact mistake
#:   :func:`_haystack_forms` records having made once already;
#: * **not a digit**, which is the entire point: the limbs this exclusion exists for
#:   read digit runs, and a token id's digits are what they were colliding with;
#: * **not hexadecimal**, so a mask can never be read back as a token id, and
#:   **ASCII, NFKC-stable, casefold-stable, not a mark and not invisible**, so every
#:   derived form (:func:`normalize`, :func:`_reference_strip_invisible`,
#:   :func:`_reference_skeleton`, :func:`_digits_only`,
#:   :func:`_decode_transport_encodings`) leaves it exactly as it is.
#:
#: It is the same character the gate masks with, and that agreement is deliberate in
#: the way :func:`_haystack_forms` calls its fold ordering deliberate: the two scans
#: are compared against each other, so the harness must not be the one that manufactures
#: a hole the gate does not have. A vaulted original of eight ``q``\\ s would be
#: reported by both -- a false red here and a false block there, which is the strict
#: direction on both sides. The *decision* -- which strings, which span -- is derived
#: below without reading a line of the gate, and that is the half that has to be
#: independent.
_HARNESS_ID_MASK_CHAR = "q"


def _harness_own_id_mask(surrogate: str) -> str | None:
    """``surrogate`` with its own 8-hex id blanked, or ``None`` if it is not one of ours.

    **Written here rather than imported, and that is the whole point of it.** The gate
    gained the identical exemption (``_own_token_mask`` / ``_mask_own_tokens``) and its
    docstring names this module as the sibling instance it does not close. Importing
    those would close it by making this module agree with the code it checks by
    construction -- which is the mistake ``_harness_separator_hit`` and
    :func:`_reference_skeleton` both exist because of, each after a released payload
    proved it. :func:`test_the_own_id_exclusion_does_not_ask_the_gate_for_its_answer`
    is the sabotage that says so out loud.

    Ownership is decided by :func:`issued_token_id`, this module's own hand-written
    parse of a surrogate -- no :data:`~secure_context_pipeline.surrogates.STRICT_TOKEN_RE`,
    no ``ENTITY_TYPE_RE``, no category alternation. It returns ``None`` for a
    **pseudonym**, which is the narrowing that keeps the dangerous half of the set
    scanned: a fake drawn as ``Rachel Medina`` while ``Medina`` is a real original puts
    that surname verbatim on the wire, and exempting it would hide a real leak. This
    harness has caught exactly that once.

    **The span is the id and nothing else.** Not the token, not the core, not the
    ``|hint`` tail -- the hint alphabet ``[a-z0-9-]`` spells an SSN and a hint is looked
    up *by the original's own text*, so it is the one field of a token that is derived
    from the value. The id is not: it is an HMAC under the session key truncated to
    eight hex characters, so a needle found inside one is a coincidence with a random
    string rather than a disclosure. Every other character -- our ``[``, our ``_``, the
    category and type literals, the hint, our ``]`` -- keeps being read.

    The span is recomputed from the parse rather than taken on trust: ``core`` is what
    :func:`issued_token_id` split, its last :data:`_HARNESS_ID_LEN` characters are the
    id, and the slice is asserted equal to the id that function returned. A surrogate
    whose spelling ever stops satisfying that is left unmasked, which is the strict
    direction.
    """
    token_id = issued_token_id(surrogate)
    if token_id is None:
        return None
    core = surrogate[1:-1].split("|", 1)[0]
    end = 1 + len(core)
    start = end - _HARNESS_ID_LEN
    if start < 1 or surrogate[start:end].lower() != token_id:
        return None
    return surrogate[:start] + _HARNESS_ID_MASK_CHAR * _HARNESS_ID_LEN + surrogate[end:]


def _harness_mask_own_ids(haystack: str, issued: frozenset[str]) -> str:
    """``haystack`` with the ids of the tokens **this run issued** blanked.

    **The false positive this removes**, measured on the real functions rather than
    reasoned about. The unbounded limbs -- :func:`_identifier_needles` and the
    digit-skeleton limb -- have no adjacency requirement at all, which is exactly what
    lets them catch a glued or regrouped identifier. So they read our own tokens as if
    they were payload text, and a token id is eight hex characters whose digits
    sometimes *are* a vaulted value's digits::

        find_in_text({'8390244'}, 'Account [FIN_ACCOUNT_NUMBER_8390244f] closed.')
            -> ['8390244']
        find_in_digit_heavy_text({'8390244'}, ...the same string...)
            -> ['8390244']

    Nothing leaked in either case: the ``8390244`` on the wire is a slice of a digest
    the pipeline wrote itself. The gate used to turn the same coincidence into an
    ``EgressBlockedError`` and stopped doing so; the reading on the harness side is
    *worse*, because the assertion it fails says "original present in the outbound
    payload" -- the headline claim of this repository -- about a run in which nothing
    left. The gate measured its own rate at 1.3e-02 spurious blocks per 100-run suite,
    seen twice in 27 executions. Re-measured from this side and after this exclusion, the
    payload channel is 6.5e-03 per suite -- the same order, and still the largest of the
    four channels in :data:`_FALSE_RED_PER_SUITE`, because what is left of it is the
    *regrouped* limb rather than the id coincidence this function removes.

    **Two narrowings, and each one is a hole if it is dropped.**

    1. **Exact string occurrence, never a grammar.** What is blanked is
       ``str.replace`` of the surrogates the run actually issued, read out of the vault
       (``SessionVault.surrogates_for_session``). A grammar over token-shaped text
       would let an *uploaded document* carry ``[PHI_MRN_5567281a]`` and have this
       module skip a vaulted MRN inside it -- the payload is assembled from a document
       the uploader wrote, so a rule keyed on shape is a rule an attacker can satisfy.
    2. **The id, not the token** (:func:`_harness_own_id_mask`). The replacement is
       per-character, length-preserving and alphanumeric, so no boundary anywhere moves
       or changes class. A vaulted value beside a token, glued to a token, or split
       across one is still read by every limb -- which is the complement, and it is
       pinned by :func:`test_a_vaulted_value_glued_to_our_own_token_is_still_found` and
       :func:`test_a_vaulted_value_spanning_a_token_boundary_is_still_found`.

    Longest surrogate first, so a token that is a substring of another is not blanked
    out from under the longer one. A surrogate this fails to blank is the old
    behaviour, which is the strict direction.

    ``issued`` defaults to empty at every call site that does not have a run to draw
    it from, and with it empty this is the identity function -- so the differential
    fuzz against the gate still compares two *unexempted* scans, and this module stays
    exactly as wide as the gate there.
    """
    if not issued:
        return haystack
    masked = haystack
    for surrogate in sorted(issued, key=len, reverse=True):
        replacement = _harness_own_id_mask(surrogate)
        if replacement is None:
            continue
        masked = masked.replace(surrogate, replacement)
    return masked


def _harness_strip_own_tokens(haystack: str, issued: frozenset[str]) -> str:
    """``haystack`` with our own tokens **removed**, hint and all. For digits only.

    Deletion, not masking, and for exactly one consumer: the digit stream the
    regrouped-identifier limb (:func:`_digit_skeleton_hit`) reads. Deleting text is
    unsafe in general -- it glues the neighbours together and takes a word boundary
    with them, which is the mistake :func:`_haystack_forms` records -- but a
    digits-only projection has no boundaries left to lose, so removing a token and
    removing only its digits are the same operation there.

    **This exists because masking alone LOST a real leak, measured on this module's own
    functions rather than reasoned about.** The regrouped limb catches a vaulted
    all-digit value that the payload writes with different grouping, by comparing two
    digits-only streams. Our own token ids are digits in that stream too, so masking
    them is the point -- but a token can also sit *inside* a disclosure and split it::

        vault  {'987714668699'}
        wire   'ledger filed 98771466869[PII_ADDRESS_989aa4fe|lab-panel-3]9 today'

        find_in_text(...)                       -> ['987714668699']   # before
        find_in_text(..., issued={that token})   -> []                # masking only

    All twelve digits are on the wire. The pre-exclusion scan reported it -- but only
    by luck, because it was reading the ``989`` out of the id: re-draw the id as
    ``c3f7003f`` and the same payload reported clean either way. So the second stream
    is not a concession to the old behaviour, it is the answer the old behaviour was
    reaching by accident, and the ``3`` of ``lab-panel-3`` is why deleting the whole
    token rather than only its id is what the stream needs.

    Same ownership test as :func:`_harness_mask_own_ids`, through the same
    :func:`_harness_own_id_mask`: a pseudonym's digits stay in the stream, because
    nothing about a fake makes its characters ours.
    """
    if not issued:
        return haystack
    stripped = haystack
    for surrogate in sorted(issued, key=len, reverse=True):
        if _harness_own_id_mask(surrogate) is None:
            continue
        stripped = stripped.replace(surrogate, "")
    return stripped


def find_in_text(
    originals: frozenset[str], haystack: str, issued: frozenset[str] = frozenset()
) -> list[str]:
    """Every original occurring in ``haystack``, in **every** comparison the gate makes.

    Four bounded forms and then one unbounded limb -- the same five comparisons, in
    the same order, as ``EgressGate._scan_originals``:

    1. **raw** -- the byte-exact value;
    2. **normalised** -- NFKC, whitespace collapsed, casefolded, so a value split
       across a line break or re-cased by a splice bug still trips;
    3. **folded** -- normalised with zero-width, soft-hyphen and bidi format
       characters removed;
    4. **skeleton** -- the folded needle against a folded haystack with every
       *combining mark* stripped (:func:`_deaccent`). Asymmetric on purpose, and the
       asymmetry is the whole reason it is safe: only the haystack is stripped, so a
       mark spliced into a mark-free vaulted value is caught while a vaulted ``José``
       still does not match a payload that says ``Jose``;
    5. **identifier needles** (:func:`_identifier_needles`) -- a bare substring test
       with **no adjacency requirement at all**, for values carrying a run of at least
       :data:`MIN_IDENTIFIER_DIGITS` digits.
    6. **composite constituents** (:func:`_composite_needles`) -- forms 1-4 again, per
       constituent, when the original is itself a *list* of digit-bearing values. A
       vault original is whatever the detector called one span, and spaCy returns
       ``03/11/2024, 09/17/2024`` as a single ``DATE``: forms 1-4 then look for a
       string nobody wrote as a unit, and form 5 contributes nothing at all because
       the longest contiguous digit run in it is four. Both limbs go quiet on a
       payload carrying one of the dates, which this pipeline can *manufacture* by
       shifting a third date onto it.

    **Forms 4, 5 and 6 are the ones this function did not have while the gate did**, and
    that asymmetry is the single defect this module exists to prevent, in its most
    dangerous direction. On the outbound payload the gate is a second opinion, so a
    leak this function missed would still be blocked. On the **audit database and the
    process log this function also scans, the harness is the only opinion there is**
    -- nothing else looks at those bytes. Measured on the real functions before the
    fix, not reasoned about:

        find_in_text({"47-1234567"}, '{"detail":{"note":"batch47-1234567Alpha"}}')
            -> []                                   # the harness reported clean
        _identifier_needles("47-1234567")
            -> ('47-1234567', '1234567')            # the gate blocks this payload

    The same shape hid a combining mark: a mark spliced into ``John Smith`` read
    clean here while the gate's skeleton form blocked it. Both are pinned below --
    :func:`test_the_scan_sees_an_identifier_glued_into_a_longer_run` and
    :func:`test_the_scan_sees_a_combining_mark_spliced_into_a_value`.

    Forms 5 and 6 keep the gate's own functions rather than restating their rules, for
    exactly the reason form 1-4's occurrence rule is imported: a re-derived copy is a
    copy that can drift, and this file has already paid for four of those.

    No minimum length on the bounded forms, deliberately: the gate skips originals
    shorter than
    :data:`~secure_context_pipeline.pipeline.egress_gate.MIN_ORIGINAL_LEN`, and the
    harness does not, so a short value the gate would wave through still fails here.
    That is the one direction in which the harness *should* be stricter than the
    gate, and it stays that way.

    **Every one of them runs over two VIEWS of the haystack: as it arrived, and
    transport-decoded.** A separator that carries word characters -- ``%20``,
    ``&nbsp;``, ``&#32;``, ``<br/>`` -- defeats every one of them at once on the raw
    view: the bounded forms keep the separator inside the needle, and the
    separator-invariant limb describes a separator as *non-alphanumeric*, which ``20``,
    ``nbsp``, ``32`` and ``br`` are not. A whole vaulted name spelled that way read
    CLEAN through this module while it was on the wire --
    ``?patient=Marguerite%20Vandenberg&view=summary`` -- and
    :func:`test_the_scan_sees_a_separator_the_payload_transport_encoded` is the four
    spellings of it.

    Every limb sees the decoded view, not only the separator one, because once
    ``Jane%20Doe`` decodes it is the *bounded* forms that see ``Jane Doe``. The view is
    **additional**, never a replacement: :func:`_decode_transport_encodings` applies a
    tag pattern to text that need not be markup, so it can destroy a match the raw view
    holds, and a second view cannot lose a hit. It is applied here and not in
    :func:`find_in_digit_heavy_text`, whose channels are a different false-positive
    surface (see :data:`_HARNESS_RUN_FLOOR` for what that surface has already cost this
    module) that this view has not been measured against.

    **``issued`` is the one exclusion this scan makes, and it is not an exemption for
    anything the pipeline wrote** -- it is the eight-hex ids of the tokens *this run*
    put on the wire, blanked by exact string occurrence
    (:func:`_harness_mask_own_ids`, which carries the measurement and the two
    narrowings it rests on). Everything else the pipeline wrote is still read,
    pseudonyms first among them. It defaults to empty, so every call that has no run
    behind it -- the differential corpus, the fuzz, the sabotage tests -- gets the
    unexempted scan, and this module stays exactly as wide as the gate where
    :func:`test_the_harness_is_never_weaker_than_the_gate_on_generated_input` compares
    them. That default is why this is a parameter rather than the boolean flag
    :func:`find_in_digit_heavy_text` argues against: a boolean says *scan less*, and
    the mistaken default silently narrows the payload scan; a set of strings says
    *these exact spans are ours*, and the mistaken default is the strict scan.
    """
    masked = _harness_mask_own_ids(haystack, issued)
    views = [_haystack_forms(masked)]
    decoded = _decode_transport_encodings(masked)
    if decoded != masked:
        views.append(_haystack_forms(decoded))
    # Every digit stream the regrouped limb reads: a UNION, never a swap. Each view
    # sees a payload the others cannot and OR-ing projections of one haystack can only
    # add hits. The extra one is the haystack with our tokens DELETED rather than
    # masked, and :func:`_harness_strip_own_tokens` carries the leak that measured it
    # -- a vaulted value split by one of our own tokens, which masking alone reported
    # clean. Built at most once, skipped when the run issued nothing and when deletion
    # changed nothing, and de-duplicated when two streams agree.
    digit_streams = [view.digits for view in views]
    excised = _harness_strip_own_tokens(haystack, issued)
    if excised != haystack:
        digit_streams.append(_digits_only(_reference_skeleton(excised)))
    digit_views = tuple(dict.fromkeys(digit_streams))

    def bounded(value: str) -> bool:
        """Forms 1-4, for a whole original or for one composite constituent.

        Written once rather than twice for the same reason the gate factors it out:
        two copies of the four forms are two places to edit the day a fifth is added,
        and "the harness has every limb the gate has" is the one property this file
        cannot afford to hold only by habit.
        """
        normalised = normalize(value)
        folded = _reference_strip_invisible(normalised)
        return any(
            occurs_as_a_unit(value, view.raw)
            or occurs_as_a_unit(normalised, view.normalized)
            or occurs_as_a_unit(folded, view.folded)
            or occurs_as_a_unit(folded, view.skeleton)
            or occurs_as_a_unit(folded, view.boundary_skeleton)
            for view in views
        )

    def unbounded(folded: str) -> bool:
        """Forms 5-7, which need no boundary and are therefore per-view substring work."""
        return any(
            any(
                needle in view.skeleton or needle in view.boundary_skeleton
                for needle in _identifier_needles(folded)
            )
            # The separator-invariant limb. Mirrors the gate's fifth comparison:
            # a multi-component original whose interior separator the payload
            # spells differently -- or not at all -- defeats all four bounded
            # forms, because every one of them keeps the separator in the needle.
            # Without this limb the harness is weaker than the gate, and
            # ``test_the_harness_is_never_weaker_than_the_gate_on_generated_input``
            # is what says so out loud.
            # BOTH haystacks, accent-preserving first. Handing this limb only the
            # deaccented one made it dead for every accented original -- the needle
            # keeps its accent by design, so it cannot occur in a deaccented
            # haystack. This module used to import the gate's own helper, so it
            # inherited that blind spot exactly and reported 100/100 CLEAN on
            # payloads the gate was releasing. The decision is now this module's
            # own -- :func:`_harness_separator_hit` -- rather than a second call
            # into the thing under test. The transport-encoded separator this limb
            # also used to miss is the DECODED view rather than a wider separator
            # class: widening the class to admit alphanumerics would make
            # `John Smith` match `JohnQSmith`, which is a false leak report on the
            # headline assertion.
            or _harness_separator_hit(folded, view.folded)
            or _harness_separator_hit(folded, view.skeleton)
            or _harness_separator_hit(folded, view.boundary_skeleton)
            for view in views
        ) or any(
            # The digit-skeleton limb. Mirrors the gate's comparison for a
            # letter-free identifier: any regrouping of the same digits collapses
            # to the same string on both sides, which is what catches a vaulted
            # `100200300400` written on the wire as `1002-0030-0400`. Without it
            # this harness is weaker than the gate, and
            # `test_the_harness_is_never_weaker_than_the_gate_on_generated_input`
            # is what said so -- it went red the moment the gate gained the limb.
            #
            # Lifted out of the per-view loop because it reads `digit_views`, which
            # is the per-view streams PLUS the token-excised one -- the extra stream
            # is a property of the whole haystack, not of one view of it.
            _digit_skeleton_hit(folded, digits)
            for digits in digit_views
        )

    found: list[str] = []
    for original in originals:
        folded_original = _reference_strip_invisible(normalize(original))
        if (
            bounded(original)
            or unbounded(folded_original)
            or any(bounded(part) for part in _composite_needles(original))
        ):
            found.append(original)
    return sorted(found)


#: This module's own floor for the unbounded identifier limb, on the channels where
#: **this module is the only opinion there is**. Seven, where the gate's run floor is
#: six, and the gap is deliberate, measured, and narrow.
#:
#: These used to be one number, and that was the defect: a threshold whose entire
#: justification is *this file's* false-positive budget on the audit database was also
#: setting the *gate's* security floor on the outbound payload. The two channels have
#: collision surfaces that differ by more than an order of magnitude, so one number
#: could not be right for both, and the number that shipped was right for this one.
#:
#: Measured on the real 3.6 MB audit/vault/document DBs a suite leaves behind, by
#: counting the distinct digit windows actually present in them::
#:
#:     distinct 6-digit windows: 15055  -> p(a given 6-digit needle collides) = 1.5e-2
#:     distinct 7-digit windows:  9366  -> p(a given 7-digit needle collides) = 9.4e-4
#:
#: The 100 runs contribute roughly 100 identifier needles, so at six digits that is
#: order-of-one spurious "an original reached the audit database" **per suite**, and at
#: seven it is ~0.09. The anchoring on these limbs was introduced to remove a 1e-6
#: false-red rate, on the argument that a rare false red on the headline assertion is
#: worse than its frequency suggests. 1.5e-2 is four orders the wrong side of that
#: line; 9.4e-4 is the side it was drawn for.
#:
#: **What it costs is stated rather than hidden**: a vaulted six-digit MRN core glued
#: into an alphanumeric run, in the audit database or the process log, is not reported
#: by this module. The gate does block that shape on the payload -- that is what
#: ``MIN_IDENTIFIER_RUN_DIGITS`` is for -- so the uncovered case is specifically the
#: two channels the gate never sees. Pinned by
#: :func:`test_the_scan_sees_an_identifier_glued_into_a_longer_run`.
#:
#: **The channel that measurement belongs to was the wrong one, and re-measuring it is
#: what explains an intermittent red nobody could reproduce.** The 3.6 MB figure above
#: is the surface of the database *files*, which this function never reads --
#: :func:`find_in_bytes` reads those, and it declines these needles outright. What
#: :func:`find_in_digit_heavy_text` is actually handed is one much smaller haystack and
#: one much larger one, and the two were once quoted as::
#:
#:     audit query view (one session's rows)         99 windows -> 2.1e-03 per suite
#:     DEBUG log haystack (log_haystack(caplog))  7,574 windows -> 1.7e-01 per suite
#:
#: **Those two figures are stale, and re-measuring them on the current tree is the only
#: reason to trust any number here.** Several exemptions have landed since they were
#: taken; one of them is 45x out and the other is 2x out in the conservative direction.
#: The method, spelled out so the next reader can redo it rather than believe it: two
#: full 100-run replays with both scan entry points wrapped, taking -- for each needle
#: the limb *actually* used, in the haystack view it is *actually* compared against --
#: the count of distinct windows of that needle's own shape, and summing
#: ``windows / 10 ** digits`` over every needle of every run. That is the birthday
#: estimate per suite. The 100 runs produce 266 pure-digit needles (100 of them exactly
#: seven digits, one per run) and 1,130 separator-bearing ones::
#:
#:     channel                       distinct 7-digit windows/run   replay A   replay B
#:     payload, regrouped limb       (digit-only projection)        6.43e-03   6.43e-03
#:     payload, identifier limb        5                            1.02e-04   1.02e-04
#:     audit query view               97 / 92                       1.03e-03   9.50e-04
#:     DEBUG log haystack            169 / 129                      1.87e-03   1.41e-03
#:                                                                  --------   --------
#:     expected spurious reds per 100-run suite                     9.43e-03   8.89e-03
#:
#: One execution of this module therefore reds with nothing leaked about **once every
#: 110 executions**. :data:`_FALSE_RED_PER_SUITE` carries that total into
#: :meth:`Ledger.summary`, because a residual nobody prints is a residual nobody knows.
#:
#: **What moved, per channel, and what did not.** The audit view's *window count*
#: reproduced (99 then, 92 and 97 now); its *rate* halved because the old arithmetic
#: multiplied the 7-digit window count by all 203 pure-digit needles, including the 9-,
#: 10-, 12- and 13-digit ones, which collide 100x to 1e6x less often -- an error in the
#: safe direction, but an error. The log figure fell 45x and **the cause is not
#: established**; what is established is what it is *not*. The natural guess is the
#: own-id exclusion, which landed on this channel in the meantime, and that guess is
#: measurably wrong: see :func:`find_in_digit_heavy_text` for the 12,905-vs-12,905
#: count. The current figure rests on two independent replays that agree to within the
#: run-to-run spread of the log itself, which is the only evidence offered for it.
#:
#: **The payload row is not this module's red to make.** The harness's payload scan is
#: by construction at least as wide as pass 1, so a payload-side collision fires the
#: *gate* first: the run dies inside ``orchestrator.run`` with ``EgressBlockedError``
#: and surfaces through :meth:`Ledger.diagnosis` as a run that never recorded, never as
#: "an original reached the outbound payload". Measured rather than assumed -- the extra
#: digit stream this module has and the gate does not (:func:`_harness_strip_own_tokens`)
#: contributed nothing at all to the estimate: 6.426e-03 with it and 6.426e-03 without.
#: It is listed because it is a spurious red *of this suite*, which is what the summary
#: line is about, and because it is the largest of the four and the one that cannot be
#: narrowed here: :func:`find_in_text` must stay exactly as wide as the gate, and
#: :func:`test_the_harness_is_never_weaker_than_the_gate_on_generated_input` fails if it
#: does not.
#:
#: **The log haystack: measured and declared, not narrowed.** It is the largest channel
#: this module owns, so the narrowing question was asked of it directly and answered
#: three ways. (1) The narrowing the payload got is *already applied* here and buys
#: nothing -- measured, zero windows removed. (2) Extending it to blank the bare
#: ``token_id`` the package also logs is refused: a bare ``1234567a`` in the log is
#: either one of our ids or a vaulted ``1234567`` with a letter glued to it, which is
#: the exact shape this limb exists for, and nothing in the string separates them.
#: (3) A digest exemption is the only other one available, and it is refused twice
#: over. 8,132 of the log's 12,905 windows and 8,132 of the audit view's 9,231 sit
#: inside a 64-character run of nothing but lowercase hex -- the audit chain hash, the
#: same set on both channels -- so exempting it would take the audit view to ~1.1e-04
#: and the log to ~8.6e-04. Keyed on *shape*, that is precisely the rule narrowing 1 of
#: :func:`_harness_mask_own_ids` refuses, because an uploaded document can satisfy a
#: shape. Keyed on *exact string* it is defensible on the audit view alone, and it is
#: still not taken: it buys 9% of a 9e-03 total, on the channel that is already the
#: smallest, at the price of a second exemption to defend on the two channels where
#: this module is the only opinion there is.
#:
#: **The bounded limbs are a fourth channel, and it is the one this file cannot put a
#: measured number on.** They carry no minimum length by design -- the gate skips an
#: original shorter than ``MIN_ORIGINAL_LEN`` and this module deliberately does not --
#: and the suite's shortest vaulted original is **four characters**, with 116 of 2,966
#: at six or fewer. A four-character needle compared word-bounded against a 580 KB log
#: haystack is not a safe bet on paper, and a green suite says nothing about it: the
#: values that were vaulted are exactly the ones that did not collide.
#:
#: So it was measured against a **cross-run null** -- each run's short originals against
#: every *other* run's two haystacks, which is realistic needles in realistic haystacks
#: where a hit cannot possibly be a real disclosure. 116 x 99 x 2 = 22,968 trials, run
#: twice: 18 hits and then 31 (the spread is the pseudonym draw, which is keyed per
#: session). **Every hit in both replays was alphabetic, and every one landed inside one
#: of the target run's own pseudonyms** -- a short surname of one document matching the
#: fake Faker drew for another.
#:
#: That is emphatically *not* a false-positive rate for a suite, and reading it as one
#: would be the same error in the other direction: **in-suite the identical event is a
#: real finding**, because a fake that reproduces an original verbatim puts that value on
#: the wire, and pseudonymization's collision guard forbids the pairing inside one
#: document anyway. What the null does bound is the other half -- a short original
#: matching ordinary log text, a lab value against a latency, a bare year against a
#: timestamp. Of those there were **zero in 45,936 trials across the two replays**, which
#: by the rule of three is 6.5e-05 per trial and 1.5e-02 per suite over the 232 (short
#: original, channel) pairs a suite makes. That is an upper bound of the same order as
#: the whole identifier total above, and it is a bound rather than a measurement, so this
#: channel is declared here and deliberately **not** folded into
#: :data:`_FALSE_RED_PER_SUITE`: adding a guess to a measured number is how ``1.7e-01``
#: came to be quoted for three commits.
#:
#: All of it is live rather than theoretical. Run 099 (medical/pseudonymization, seed
#: 90099) failed assertion 2a on a seven-digit MRN with ``identifier`` as the only limb
#: that fired, once in 24 executions of the identical 100 runs and never again -- which
#: is what a coincidence against per-process random hex looks like from the outside, and
#: is not something a seed can reproduce.
#:
#: Narrowing either limb -- a higher floor, a boundary on the needle, dropping a
#: haystack -- is a real loss of reach on the two channels where this module is the
#: only opinion there is, so the trade is recorded here rather than taken unilaterally.
#: What is taken here is the free half: :func:`describe_hits` now names the *kind of
#: run* an ``identifier``-only hit landed in, so the next occurrence is one line to
#: classify instead of an afternoon to reproduce.
_HARNESS_RUN_FLOOR = 7


def _harness_identifier_needles(value: str) -> tuple[str, ...]:
    """:func:`_identifier_needles`, narrowed to :data:`_HARNESS_RUN_FLOOR`.

    A *filter* over the gate's own output rather than a re-derivation of its rule.
    That distinction is the whole point: a re-derived copy is a copy that can drift,
    and this file has already paid for four of those. Narrowing what the gate returns
    keeps the relationship between the two exactly one fact wide -- this module drops
    needles carrying fewer than seven digits, and nothing else -- so a reader can
    check the claim by reading six lines instead of comparing two rules.
    """
    return tuple(
        needle
        for needle in _identifier_needles(value)
        if sum(1 for ch in needle if "0" <= ch <= "9") >= _HARNESS_RUN_FLOOR
    )


def find_in_digit_heavy_text(
    originals: frozenset[str], haystack: str, issued: frozenset[str] = frozenset()
) -> list[str]:
    """:func:`find_in_text` for the audit database and the process log.

    Identical in its four bounded forms **and in its composite limb**; the only
    difference is that the unbounded identifier limb uses
    :func:`_harness_identifier_needles` instead of the gate's own, i.e. it stops at
    :data:`_HARNESS_RUN_FLOOR` digits rather than at the gate's run floor.
    :data:`_HARNESS_RUN_FLOOR` carries the measurement and the cost.

    That sentence used to say "the only difference is the identifier limb" while the
    composite limb was in fact absent here, which made the docstring the thing that
    hid the gap. Measured before the fix, on the audit-detail shape this scan exists
    for::

        c    = "03/11/2024, 09/17/2024"          # one spaCy DATE span, one original
        hay  = '{"detail":{"note":"re-scheduled from 03/11/2024"}}'
        find_in_text          -> ['03/11/2024, 09/17/2024']
        find_in_digit_heavy   -> []

    The constituent is in the audit database, the payload scan reports it, and this
    scan -- the **only** opinion on that channel -- reported clean. The four bounded
    forms all look for the composite, which nobody wrote as a unit, and the
    identifier limb contributes nothing because the longest contiguous digit run in
    it is four. So every limb went quiet at once, which is exactly the failure
    :func:`find_in_text`'s form 6 was added for.

    The limb is deliberately cheap here rather than re-derived: it reuses the gate's
    :func:`_composite_needles`, which only yields needles when the value splits into
    two or more constituents that *each* carry at least ``MIN_IDENTIFIER_DIGITS``
    digits, and every needle is compared word-bounded. That is what keeps it off this
    channel's false-positive surface -- it cannot fire on an ordinary English word,
    which is the risk :data:`_HARNESS_RUN_FLOOR` exists to manage for the *unbounded*
    limb. Measured: adding it changed no run's verdict across the 100-run suite.

    Kept as a separate function rather than a flag on :func:`find_in_text`, because
    the payload scan **must** stay exactly as wide as the gate -- that is the property
    :func:`test_the_harness_is_never_weaker_than_the_gate_on_generated_input` fuzzes,
    and a boolean parameter is one mistaken default away from silently narrowing it.

    **``issued`` is the same own-id exclusion :func:`find_in_text` takes, and this
    channel needs it for a measured reason rather than for symmetry.** Every token the
    run emits reaches ``log_haystack(caplog)`` verbatim: ``aiosqlite`` logs each
    statement it executes at DEBUG *with its bound parameters*, and the vault binds the
    surrogate. Counted over six runs of the real harness -- 31, 4, 37, 14, 36 and 14
    token-shaped surrogates issued, and **every one of them present in the log
    haystack**, against **zero** in the audit query view and zero in the audit DB bytes.
    So the coincidence the gate stopped blocking lands here too, and at this
    function's own floor: :data:`_HARNESS_RUN_FLOOR` is seven digits and an 8-hex id
    holds two seven-character windows.

    **On this channel the exclusion nonetheless removes no collision surface at all, and
    that is measured rather than expected.** Distinct 7-digit windows in the skeleton
    this limb reads, with the exclusion applied and with it disabled: 145/145, 117/117,
    121/121 and 124/124 over the first four runs, and **12,905 against 12,905** summed
    over a full 100-run replay. The cause is that our ids reach this haystack by two
    routes and the exclusion only closes one: the vault binds ``token_id`` as a column
    of its own and the audit logger puts it in ``extra=``, so each id that carries a
    seven-digit window occurs **17 times in the log and only 4 of those inside the whole
    surrogate** -- the exclusion blanks those 4, and the other 13 keep the same eight hex
    characters in the haystack a few hundred bytes away. Blanking the bare id instead is
    refused for the reason :data:`_HARNESS_RUN_FLOOR` gives: a bare ``1234567a`` in a log
    line is either one of our ids or a vaulted ``1234567`` with a letter glued to it, and
    that is the shape this limb exists for. The exclusion stays because it is right in
    the payload sense -- the span inside a token *is* ours -- and because removing it
    would widen a scan for no gain; it is simply not the reason this channel's rate is
    1.4e-03 rather than 1.7e-01.

    That is why the run passes ``issued`` on the log limb and **not** on the two audit
    limbs. Where the channel measurably carries none of our tokens the exclusion is the
    identity function, and an identity function is still a claim somebody has to
    defend; the audit scans stay unexempted, which is the strict direction on the
    channel where this module is the only opinion there is.
    """
    haystack = _harness_mask_own_ids(haystack, issued)
    norm_hay = normalize(haystack)
    folded_hay = _reference_strip_invisible(norm_hay)
    skeleton_hay = _reference_skeleton(haystack)

    def bounded(value: str) -> bool:
        """The four bounded forms, for a whole original or one composite constituent.

        Factored for the same reason :func:`find_in_text` factors its own: two copies
        of the four forms are two places to edit the day a fifth is added, and this
        function having every limb the payload scan has is the property that was
        already lost once by writing them out twice.
        """
        normalised = normalize(value)
        folded = _reference_strip_invisible(normalised)
        return (
            occurs_as_a_unit(value, haystack)
            or occurs_as_a_unit(normalised, norm_hay)
            or occurs_as_a_unit(folded, folded_hay)
            or occurs_as_a_unit(folded, skeleton_hay)
        )

    found: list[str] = []
    for original in originals:
        folded = _reference_strip_invisible(normalize(original))
        if (
            bounded(original)
            or any(needle in skeleton_hay for needle in _harness_identifier_needles(folded))
            or any(bounded(part) for part in _composite_needles(original))
        ):
            found.append(original)
    return sorted(found)


#: The characters a lowercase hexadecimal run is made of. Spelled here rather than
#: reusing ``_HEX`` below, which accepts both cases: every haystack this is applied to
#: has been through ``normalize``, so an upper-case digest has already been casefolded,
#: and accepting ``A-F`` here would let ``ALPHA`` read as hexadecimal.
_LOWER_HEX = frozenset("0123456789abcdef")


def _identifier_site(folded: str, skeleton_hay: str) -> str:
    """What kind of run an ``identifier``-limb hit landed in. A **shape**, never content.

    The one fact missing from an ``identifier``-only red, and the reason such a red
    used to cost an afternoon. That limb is a bare substring test with no adjacency
    requirement (see :data:`_HARNESS_RUN_FLOOR`), so it has two completely different
    causes and the failure line could not tell them apart:

    * the pipeline wrote a vaulted identifier into the channel and glued a letter to it
      -- ``batch47-1234567Alpha``, the case the limb exists for. A **real leak**;
    * the seven digits fell inside a run of process-random hexadecimal -- a chain hash,
      a session, run or document ID -- or inside a longer decimal run such as an epoch
      timestamp. A **coincidence**, re-tossed on every process, reproducible by no seed.

    The enclosing maximal alphanumeric run separates them on sight: 64 or 32 characters
    of nothing but hex digits is a digest or an ID, and no document value is one.

    Rendered as a length and a character class and nothing else, so this is safe on the
    one channel it is printed to. ``mask`` withholds the needle for build doc section
    16's reason; quoting the *haystack* around a hit would hand back the whole value the
    masking just withheld, plus whatever else sits beside it. A length and the word
    ``hexadecimal`` cannot carry either.

    Uses ``str.find`` rather than a membership test, because the answer needed here is
    *where*, and because a bare ``in`` deciding anything about a value in this file is
    the mistake :func:`test_no_leak_comparison_in_this_module_bypasses_the_shared_rule`
    exists to stop. Nothing here decides whether a value leaked -- that decision was
    already made by :func:`find_in_digit_heavy_text`; this only describes it.
    """
    for needle in _identifier_needles(folded):
        at = skeleton_hay.find(needle)
        if at < 0:
            continue
        start, end = at, at + len(needle)
        while start > 0 and skeleton_hay[start - 1].isalnum():
            start -= 1
        while end < len(skeleton_hay) and skeleton_hay[end].isalnum():
            end += 1
        run = skeleton_hay[start:end]
        if run == needle:
            return "standing alone"
        if all(character in _LOWER_HEX for character in run):
            kind = "hexadecimal"
        elif run.isdigit():
            kind = "decimal"
        else:
            kind = "mixed"
        return f"inside a {len(run)}-char {kind} run"
    return "site not located"


def describe_hits(originals: list[str], haystack: str) -> list[str]:
    """Failure-message text for a leak: the value **masked**, plus which limb fired.

    Same reasoning as
    :func:`test_the_audit_scan_catches_a_label_column_original_and_says_which_limb_did`,
    applied to the runtime failure rather than to a test: a report that says only "an
    original reached the audit log" leaves the reader to work out whether they are
    looking at a splice bug, a normalisation, or the identifier limb matching seven
    digits inside a hex run ID. Those need completely different responses, and the
    distinction is free at the point of failure and expensive an hour later.

    It matters most for the two limbs added last. ``identifier`` is the only one that
    can fire on something innocent -- it is a bare substring test, and this module has
    a measured false-positive rate for it on digit-heavy channels (see
    :func:`find_in_bytes`) -- so a red naming ``['identifier']`` alone is the one a
    reader should check the arithmetic on before believing, and a red naming ``['raw']``
    is one they should not.

    "Check the arithmetic" was the whole instruction until an ``identifier``-only red
    actually happened, and it turned out not to be an instruction anybody could follow:
    the arithmetic says a coincidence is possible, and says nothing at all about whether
    *this* hit was one. So an ``identifier``-only hit now also carries
    :func:`_identifier_site` -- the shape of the run the seven digits landed in, which
    is the fact that decides it.

    Never renders the value: :func:`mask` gives a length and two characters, which is
    build doc section 16's rule and applies to test output like everything else. The
    site is a length and a character class for the same reason.
    """
    norm_hay = normalize(haystack)
    folded_hay = _reference_strip_invisible(norm_hay)
    skeleton_hay = _reference_skeleton(haystack)
    described: list[str] = []
    for original in originals:
        normalised = normalize(original)
        folded = _reference_strip_invisible(normalised)
        limbs = [
            name
            for name, fired in (
                ("raw", occurs_as_a_unit(original, haystack)),
                ("normalised", occurs_as_a_unit(normalised, norm_hay)),
                ("folded", occurs_as_a_unit(folded, folded_hay)),
                ("skeleton", occurs_as_a_unit(folded, skeleton_hay)),
                (
                    "identifier",
                    any(needle in skeleton_hay for needle in _identifier_needles(folded)),
                ),
            )
            if fired
        ]
        # Only when ``identifier`` fired ALONE: every other limb is boundary-anchored,
        # so it cannot fire on a coincidence and the site would be noise beside it.
        site = f" {_identifier_site(folded, skeleton_hay)}" if limbs == ["identifier"] else ""
        described.append(f"{mask(original)} via {limbs or ['byte-limb-only']}{site}")
    return described


#: A JSON ``\uXXXX`` escape. See :func:`_unescape_json_unicode`.
_JSON_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _unescape_json_unicode(text: str) -> str:
    """Resolve JSON ``\\uXXXX`` escapes so a non-ASCII original is visible again.

    :func:`~secure_context_pipeline.audit.logger.canonical_json` and
    :func:`json.dumps` both default to ``ensure_ascii=True``, so an audit ``detail``
    holding ``"José"`` is *stored in SQLite* -- and re-serialised by the query path
    -- as the ASCII text ``"Jos\\u00e9"``. Both of this module's audit scans were
    therefore blind to any original containing a non-ASCII character: the value is
    genuinely in the log, in a form any JSON reader decodes back to the original,
    and neither the raw byte scan nor the query-API scan could see it.

    Accented surnames are not an edge case in the documents this system exists to
    protect, so this was a live hole in the headline claim rather than a
    hypothetical. Applied as an *additional* view rather than a replacement, so the
    scan only ever widens.
    """
    return _JSON_UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


#: Attributes every :class:`logging.LogRecord` carries. Anything outside this set
#: arrived via ``extra=`` and is therefore *not* rendered into ``caplog.text``.
_STANDARD_LOGRECORD_ATTRS: frozenset[str] = frozenset(
    vars(logging.LogRecord("n", 0, "p", 0, "m", None, None))
) | {"message", "asctime", "taskName"}


def log_haystack(caplog: pytest.LogCaptureFixture) -> str:
    """Everything the package logged, **including the ``extra=`` fields**.

    ``caplog.text`` renders records through pytest's default formatter, which is
    ``"%(levelname)-8s %(name)s:%(filename)s:%(lineno)s %(message)s"``. That format
    contains no ``extra`` fields, and this package puts **almost every variable it
    logs into ``extra=``** -- ``session_id``, ``run_id``, ``entity_type``,
    ``token_id``, counts, latencies, error types. A scan of ``caplog.text`` alone
    therefore checked the *constant* half of every log line and none of the
    variable half.

    That is precisely the shape a logging leak takes. ``logger.debug("obfuscated a
    span", extra={"value": original})`` is the natural mistake, it is invisible to
    ``caplog.text``, and it is fully rendered by any production JSON formatter --
    which is what a deployment actually runs. So the harness was asserting "no
    originals in the logs" against a view of the logs that structurally could not
    contain one.

    Verified rather than assumed: ``test_the_log_scan_sees_structured_extra_fields``
    below plants a value in an ``extra`` field and fails if this function cannot
    find it.
    """
    parts: list[str] = [caplog.text]
    for record in caplog.records:
        parts.append(record.getMessage())
        parts.extend(
            f"{key}={value!r}"
            for key, value in vars(record).items()
            if key not in _STANDARD_LOGRECORD_ATTRS
        )
    return "\n".join(parts)


def find_in_bytes(originals: frozenset[str], haystack: bytes) -> list[str]:
    """Every original present in a raw byte blob (the audit DB file on disk).

    Decoded and then run through the **same** occurrence rule as
    :func:`find_in_text`, rather than a bare ``bytes.__contains__``. The naive
    version was an unanchored substring test sitting underneath the headline claim
    "the audit database contains zero originals", and it had a real false-positive
    path: three fixture originals are pure six-digit decimals (``382892``,
    ``390538``, ``364896``) and every audit row carries a 32-character hex
    ``run_id``, so a decimal original can appear *inside* a run ID by chance and be
    reported as a leak. Roughly 1e-6 per run -- but on this particular assertion a
    one-in-a-million false red is worse than the arithmetic suggests, because the
    next genuine red gets waved away as "that flaky audit check".

    **What this limb does and does not see, since it is the half that is easy to
    overrate.** SQLite writes a record's column values end to end with no delimiter,
    so an original in a label column sits in the file as
    ``...EGRESS_BLOCKMarguerite Vandenbergdeadbeef...`` -- alphanumeric on both
    edges, which is the "glued into a longer word" shape this module documents as
    out of scope. Measured, not reasoned: emitting one event with a name in
    ``entity_type`` produces exactly that layout and this function returns nothing.

    That is a boundary and not a hole, because it is not the only limb.
    :func:`find_in_text` over the **query view** of the same rows sees the identical
    value as ``"entity_type": "Marguerite Vandenberg"``, where JSON quoting supplies
    the boundaries, and the run below applies both -- so a label-column original is
    caught, by the other half of assertion 2. What this limb uniquely covers is bytes
    the query view cannot reach: freed pages, WAL remnants, superseded row images.
    :func:`test_the_audit_scan_catches_a_label_column_original_and_says_which_limb_did`
    pins the division of labour, so neither half can be quietly deleted on the
    assumption that the other one is doing the work.

    Loosening this limb to plain containment was tried and reverted: it re-opens the
    exact false-positive class above with interest. A lab value like ``8.2`` is an
    ordinary vaulted original and every audit row carries an ``elapsed_ms`` -- so
    ``{"elapsed_ms":18.25}`` reports a leak that is not there. Measured before
    shipping, not after.

    **This limb deliberately does NOT carry the gate's identifier needles, and that
    is a decision with a number behind it rather than an omission.**
    :func:`find_in_text` gained :func:`_identifier_needles` -- a bare substring test
    for values carrying seven or more digits -- because the gate has it and a checker
    weaker than the code it checks launders the claim. Putting the same limb *here*
    was measured first, on the real 1.8 MB audit blob a full 100-run session
    accumulates, and it fails the standard this very docstring sets three paragraphs
    up:

        pure-digit identifier needles across the 100 runs, by length:
            7 digits: 100   9: 34   10: 33   12: 66   13: 33
        p(a random needle of that length occurs somewhere in the final blob):
            7 digits: 9.7e-04   8: 6.0e-05   9: 3.7e-06   10: 2.3e-07   12: 8.8e-10
        => expected spurious reds per full 100-run suite: 0.049
           i.e. ~4.7% chance of a false "original in the audit database" per run

    Almost all of it is the seven-digit MRN: an audit *file* is 1.8 MB of hex run
    IDs, sha256 digests and float timestamps, which is four orders of magnitude more
    digit surface than the 8-hex token ID the gate's own risk arithmetic reasons about
    (see :data:`MIN_IDENTIFIER_DIGITS`). 4.7% per suite is ~4,700x the 1e-6 rate this
    limb's anchoring was introduced to remove, on the one assertion where a rare false
    red is most expensive -- it teaches the reader to disbelieve the next genuine one.

    What that costs is bounded, because this limb is not where the identifier case
    lands. A glued identifier in a **live** audit row is caught by the query limb,
    which is :func:`find_in_text` and does carry the needles; what is uncovered is a
    glued identifier in bytes only this limb can reach -- a freed page, a WAL remnant,
    a superseded row image -- which is the same stated boundary this limb already has
    for a glued *name*. Pinned, with the arithmetic, by
    :func:`test_the_byte_limb_declines_the_identifier_needles_and_says_what_that_costs`.

    ``errors="replace"`` is what makes decoding safe here: an invalid byte becomes
    U+FFFD, which is not alphanumeric and therefore acts as a boundary, so binary
    garbage can never glue itself onto a needle and manufacture a match. Valid
    UTF-8 -- which is what SQLite actually stores text as -- decodes exactly.

    The blob is scanned in **two** views: as decoded, and with JSON ``\\uXXXX``
    escapes resolved. The ``detail`` column is written by ``canonical_json``, which
    is ``ensure_ascii=True``, so a non-ASCII original sits in the file as literal
    backslash-u text that a raw scan cannot match -- see
    :func:`_unescape_json_unicode`.
    """
    decoded = haystack.decode("utf-8", errors="replace")
    unescaped = _unescape_json_unicode(decoded)
    return sorted(
        o for o in originals if occurs_as_a_unit(o, decoded) or occurs_as_a_unit(o, unescaped)
    )


class _NoVault:
    """Satisfies the gate's ``VaultLike``. Never consulted -- see :func:`_gate_scan_hits`."""

    def originals_for_session(self, session_id: str) -> frozenset[str]:
        return frozenset()


class _NoDetector:
    """Satisfies the gate's ``DetectorLike``. Never consulted -- pass 1 does not detect."""

    async def detect(self, text: str, doc_category: str | None = None) -> Sequence[Detection]:
        return ()


@lru_cache(maxsize=1)
def _reference_gate() -> EgressGate:
    """One gate instance for the scan-comparison tests. Its collaborators are stubs.

    ``EgressGate._scan_originals`` is a pure function of ``(payload, originals)`` --
    it reads nothing off ``self`` -- so the vault, detector and settings handed in
    here exist only to satisfy the constructor.

    The key is generated here rather than left to ``Settings()``'s environment lookup.
    A bare ``Settings()`` works under pytest only because ``tests/conftest.py`` injects
    ``SCP_MASTER_KEY`` at import time, which makes this helper depend on a fixture file
    it never mentions -- and the failure mode is a ``ConfigError`` from the middle of a
    scan comparison, which reads like a gate bug rather than a missing env var.
    """
    return EgressGate(
        vault=_NoVault(),
        detector=_NoDetector(),
        settings=Settings(
            master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            registry_path=REGISTRY_PATH,
            llm_provider="mock",
        ),
    )


def _gate_scan_hits(
    originals: frozenset[str], payload: str, issued: frozenset[str] = frozenset()
) -> int:
    """How many originals the **real gate** reports in ``payload``. Pass 1, entire.

    Every "and the gate agrees" claim in this module goes through here, and that is a
    correction rather than a convenience. Those claims used to be made against
    :func:`_occurs_as_a_unit` -- **one limb of a five-limb scan** -- and the
    consequence was not hypothetical: when the gate grew ``_deaccent``, a test whose
    name promised the gate could not see a combining mark went on passing, because the
    limb it interrogated was not the limb that had changed. A checker that asks the
    thing it checks a narrower question than the one it reports on has not checked it.

    ``issued`` is the gate's own emitted-surrogate set, and it defaults to empty for
    the same reason ``find_in_text``'s does: the differential corpus and the fuzz
    compare two *unexempted* scans, which is the comparison "never weaker than the
    gate" is written about. It is supplied only where a test's subject is the
    exemption itself.
    """
    return _reference_gate()._scan_originals(payload, originals, issued)


async def surrogate_map(
    harness: Harness, session_id: str, result: PipelineResult
) -> dict[str, str]:
    """``surrogate -> original`` for everything this run issued.

    Read back out of the vault rather than carried along the run, so the map is
    the vault's own view of what it handed out.
    """
    mapping: dict[str, str] = {}
    for span in result.detections:
        if span.surrogate and span.surrogate not in mapping:
            mapping[span.surrogate] = await harness.vault.get_by_surrogate(
                session_id, span.surrogate
            )
    return mapping


_HEX = frozenset("0123456789abcdefABCDEF")


def issued_token_id(surrogate: str) -> str | None:
    """The 8-hex ID of a surrogate **we** issued, parsed without the production grammar.

    Hand-written string surgery rather than ``STRICT_TOKEN_RE`` on purpose -- see
    :func:`expected_round_trip` for why every predicate that decides *what must come
    back* is derived independently of the code that puts it back. The input is our
    own vault's key, not model output, so it needs no tolerance: strip the brackets,
    drop the optional ``|hint``, take the last underscore-separated component, and
    require exactly eight hex digits.

    Returns ``None`` for a pseudonym, which carries no ID and is matched as a
    literal instead.
    """
    if not (surrogate.startswith("[") and surrogate.endswith("]")):
        return None
    core = surrogate[1:-1].split("|", 1)[0]
    tail = core.rsplit("_", 1)[-1]
    if len(tail) == 8 and all(character in _HEX for character in tail):
        return tail.lower()
    return None


def expected_round_trip(raw_llm_response: str, mapping: dict[str, str]) -> set[str]:
    """Originals that MUST be back in the restored text.

    **This function deliberately shares no predicate with the restorer**, and that
    is the entire point of it. Leak detection and round-trip completeness pull in
    opposite directions, and this module used to run both through the same two
    production predicates:

    * ``extract_token_ids`` -- i.e. ``surrogates.TOKEN_RE``, which is also how the
      restorer decides what to replace;
    * ``_occurs_as_a_unit`` -- the egress gate's occurrence rule.

    For **leak detection** sharing is correct and is enforced by
    :func:`test_no_leak_comparison_in_this_module_bypasses_the_shared_rule`: a scan
    laxer than the gate would report clean through a leak the gate blocks.

    For **completeness** it is exactly wrong, because it makes the expectation
    agree with the thing it is checking. If ``TOKEN_RE`` cannot see a token the
    model emitted, then: ``expected`` silently omits the original, the restorer
    silently leaves the token in the answer, assertion 4's residual scan (also
    ``TOKEN_RE``) cannot see it either, all three agree, and the only visible
    effect is that ``round_trip_checked`` in the summary line gets *smaller*. A
    shrinking denominator is not a failure signal; nobody reads it as one. The
    user gets an answer with a dangling ``1a2b3c4d`` in it and the harness reports
    100/100 clean.

    So the expectation is derived from an independent reading of the model's own
    words: the 8-hex ID as a plain case-insensitive substring (:func:`_mentions`),
    and pseudonyms through :func:`_reference_occurs_as_a_unit`, the
    independently-written occurrence rule this module already keeps for
    differential testing. Both are *at least as broad* as the production grammar,
    which is the direction that makes a restorer miss a red instead of a rounding
    error.

    A bare ID substring cannot manufacture a false expectation in practice: the IDs
    are ``sha256[:8]`` and the only place they appear in a response is inside the
    token the payload carried. If one ever did collide, the resulting red is still
    an answer with an unrestored ID in it.

    The pseudonym branch stays boundary-anchored: a short Faker surname sitting
    inside a longer ordinary word is not the model *mentioning* that surrogate, and
    treating it as one puts an original into ``expected`` that the restorer was
    never asked to produce.

    Takes the response text rather than a :class:`PipelineResult` so it can be
    exercised directly with hand-built model output -- which is what
    :func:`test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots`
    does.
    """
    expected: set[str] = set()
    for surrogate, original in mapping.items():
        token_id = issued_token_id(surrogate)
        if token_id is not None:
            if _mentions(token_id, raw_llm_response):
                expected.add(original)
        elif _reference_occurs_as_a_unit(surrogate, raw_llm_response):
            expected.add(original)
    return expected


def _mentions(token_id: str, raw_llm_response: str) -> bool:
    """Did the model refer to this token ID at all? Decided without ``TOKEN_RE``.

    Case-insensitive and unanchored, because the question is "did the model say
    this ID", not "did it emit a well-formed token" -- the second question is the
    restorer's, and asking the restorer's question here is what made the
    expectation collapse whenever the restorer was wrong.
    """
    return token_id.lower() in raw_llm_response.lower()


# ---------------------------------------------------------------------------
# 0. The scan can still see a leak
# ---------------------------------------------------------------------------


def test_the_leak_scan_bites() -> None:
    """The harness's own instrument, checked before it is trusted 100 times.

    ``find_in_text`` is the one place this file could quietly stop measuring
    anything, so its two failure modes are pinned directly: it must fire on a
    value that is genuinely present in any of the shapes the pipeline could leave
    it in, and it must not fire on a longer word that merely contains it -- the
    false positive that is indistinguishable from a real leak until somebody
    spends an hour on it.
    """
    planted = "Marguerite Vandenberg"
    surname = "Brown"

    # Present verbatim.
    assert find_in_text(
        frozenset({planted}), f"<DOCUMENT>\nThe client {planted} signed.\n</DOCUMENT>"
    ) == [planted]

    # Present but case-mangled and re-wrapped across a line break: the raw scan
    # misses it, the normalised scan does not. This is the shape a splice bug or
    # a detector miss actually leaves behind.
    wrapped = "<DOCUMENT>\nThe client MARGUERITE\nVANDENBERG signed.\n</DOCUMENT>"
    assert planted not in wrapped
    assert find_in_text(frozenset({planted}), wrapped) == [planted]

    # Absent: a longer word that merely contains the value is not an occurrence.
    assert not find_in_text(
        frozenset({surname}), "<DOCUMENT>\nCounsel Browning filed the motion.\n</DOCUMENT>"
    )
    assert find_in_text(
        frozenset({surname}), "<DOCUMENT>\nCounsel Brown filed the motion.\n</DOCUMENT>"
    ) == [surname]

    # Absent entirely.
    assert not find_in_text(frozenset({planted}), "<DOCUMENT>\n[PII_NAME_1a2b3c4d]\n</DOCUMENT>")

    # And the byte-level scan used on the audit database file.
    assert find_in_bytes(frozenset({planted}), b"\x00\x01" + planted.encode()) == [planted]
    assert not find_in_bytes(frozenset({planted}), b"\x00\x01nothing here")


def test_the_failure_message_names_the_limb_and_never_the_value() -> None:
    """:func:`describe_hits` runs **only** when a run is already failing. So test it.

    Code on the failure path is the code nothing exercises, and when it breaks it does
    so at the worst possible moment: an exception raised while formatting an assertion
    message replaces a precise "an original reached the audit log" with a
    ``TypeError`` from a test module, which is exactly the report that gets dismissed
    as harness flakiness.

    Two properties, and the second is build doc section 16 rather than ergonomics:

    * the limb attribution is **correct** -- a reader deciding whether a red is a real
      splice bug or the identifier limb catching seven digits inside a hex run ID is
      making that call off this string;
    * no original is ever rendered into it, however alarming the failure.

    The identifier case additionally pins :func:`_identifier_site`, because "check the
    arithmetic before believing this red" is not an instruction anybody can act on --
    see :func:`test_an_identifier_only_hit_says_which_kind_of_run_the_digits_landed_in`
    for the red that proved it. The shape of the enclosing run is the fact that decides
    it, and a message that dropped it would be back to unactionable.
    """
    name = "Marguerite Vandenberg"
    tax_id = "47-1234567"

    assert describe_hits([name], f"The client {name} signed.") == [
        f"{mask(name)} via ['raw', 'normalised', 'folded', 'skeleton']"
    ]

    # The one limb whose reds a reader should check before believing -- and the run
    # shape that tells them which way to decide. ``mixed``, not ``hexadecimal``: the
    # digits are glued to ``batch``/``Alpha``, so this is the real leak the limb exists
    # for rather than a collision inside a digest.
    identifier_only = describe_hits([tax_id], "routing tag batch47-1234567Alpha here")
    assert identifier_only == [
        f"{mask(tax_id)} via ['identifier'] inside a 20-char mixed run"
    ], identifier_only

    # A value the byte limb found and the query view does not carry is labelled, not
    # silently rendered as an empty list.
    assert describe_hits([name], "nothing to see here") == [f"{mask(name)} via ['byte-limb-only']"]

    # Section 16: the value never appears, in any of the three shapes.
    for rendered in (
        *describe_hits([name], f"The client {name} signed."),
        *identifier_only,
        *describe_hits([name], "nothing to see here"),
    ):
        assert name not in rendered and tax_id not in rendered, (
            f"the failure message renders an original: {rendered!r}"
        )


def test_the_scan_sees_markdown_and_punctuation_wrapped_originals() -> None:
    """The regression cases the previous occurrence rule was blind to.

    Every literal below carries its original **byte for byte**, and every one of
    them read as clean under the old ``(?<!\\w)...(?!\\w)`` rule. They are pinned
    individually rather than folded into a loop because each is a distinct way of
    being wrong, and a reviewer should be able to see the shape of the miss:

    * ``_John Smith_`` -- ``_`` is a regex ``\\w``, so the left assertion failed on
      the emphasis marker. Markdown emphasis is not exotic; the mock provider emits
      it and real models emit it constantly.
    * ``tel(415) 555-0123`` and ``USD$1,234.56`` -- the needle *begins* with
      punctuation, so asking whether the preceding character is a word character
      is not a boundary question at all. It has no meaning on that side, and
      answering it anyway suppressed the match.

    A phone number and a dollar figure are exactly the values this pipeline
    exists to keep off the wire, so this was not a corner case.
    """
    name = "John Smith"
    phone = "(415) 555-0123"
    amount = "$1,234.56"

    for haystack in (
        f"_{name}_",
        f"__{name}__",
        f"**{name}**",
        f"the memo names _{name}_ as counsel",
        f"x_{name}",
    ):
        assert find_in_text(frozenset({name}), haystack) == [name], (
            f"the scan is blind to {haystack!r}, which contains the original verbatim"
        )

    assert find_in_text(frozenset({phone}), f"tel{phone}") == [phone]
    assert find_in_text(frozenset({amount}), f"USD{amount}") == [amount]

    # And the false positive the rule exists to prevent is still prevented.
    assert not find_in_text(frozenset({"Brown"}), "Counsel Browning filed the motion.")


def test_the_byte_scan_does_not_invent_leaks_inside_run_ids() -> None:
    """A six-digit original inside a 32-hex ``run_id`` is not a leak.

    Three fixture originals are pure decimals and every audit row carries a hex
    ``run_id``, so an unanchored ``bytes`` containment test has a genuine -- if
    rare -- false-positive path on the assertion behind "the audit database holds
    zero originals". Rare false reds on a headline claim are expensive out of
    proportion to their frequency: they teach the reader to disbelieve the next
    one.
    """
    original = "382892"
    run_id = b"a3f2382892c14e7b9d0e5a6182f4cc71"
    assert original.encode() in run_id, "premise: the decimal really is inside the hex ID"
    assert not find_in_bytes(frozenset({original}), b"\x02\x00run_id=" + run_id)

    # A real occurrence in the same blob is still caught.
    assert find_in_bytes(
        frozenset({original}), b"\x02\x00value=" + original.encode() + b"\x00"
    ) == [original]

    # Undecodable bytes become U+FFFD, which is a boundary rather than a letter,
    # so binary noise cannot glue itself to a needle and manufacture a match.
    assert find_in_bytes(frozenset({original}), b"\xff\xfe" + original.encode()) == [original]


def test_the_byte_limb_and_the_query_limb_of_the_audit_scan_see_different_things() -> None:
    """Assertion 2 has two limbs and neither is redundant. Which is which, exactly.

    SQLite writes a record's column values end to end with no delimiter, so an
    original in a label column lands in the *file* as
    ``…EGRESS_BLOCKMarguerite Vandenbergdeadbeef…`` -- alphanumeric on both edges,
    which is the "glued into a longer word" shape the anchored rule deliberately does
    not match. The **byte** limb is therefore blind to it. The **query** limb sees the
    identical value as ``"entity_type": "Marguerite Vandenberg"``, where JSON quoting
    supplies the boundaries, and catches it.

    Both directions are asserted here because the tempting simplification is wrong in
    both directions. Loosening the byte limb to plain containment so it could carry
    this case alone was tried and reverted: ``8.2`` is an ordinary vaulted lab value
    and every audit row carries an ``elapsed_ms``, so ``{"elapsed_ms":18.25}`` reports
    a leak that is not there -- the same false-positive class the anchoring exists to
    prevent, on a channel where a rare false red teaches the reader to disbelieve the
    next genuine one. And deleting the byte limb because the query limb covers this
    case is equally wrong: the byte limb is the only thing that sees bytes the query
    view cannot reach -- freed pages, WAL remnants, superseded row images.

    So the division of labour is pinned, rather than each limb being assumed to be
    doing the other's job.
    """
    name = "Marguerite Vandenberg"
    glued = b"sess-a1b2run-c3d4EGRESS_BLOCK" + name.encode() + b'deadbeef{"count":1}'
    quoted = json.dumps([{"entity_type": name, "detail": {"count": 1}}], ensure_ascii=False)

    assert name.encode() in glued, "premise: the value really is in the file, verbatim"
    assert not find_in_bytes(frozenset({name}), glued), (
        "if this now fires the byte limb gained glued-word detection -- good, but the "
        "false-positive path below must be re-measured before it ships"
    )
    assert find_in_text(frozenset({name}), quoted) == [name], (
        "the query limb is what actually catches a label-column original; if this "
        "stops firing, assertion 2 is blind to it on both limbs"
    )

    # The false positive that reverted the obvious "just loosen the byte limb" fix.
    latency_row = b'detail{"elapsed_ms":18.25,"count":3}'
    assert b"8.2" in latency_row, "premise: an ordinary latency contains this lab value"
    assert not find_in_bytes(frozenset({"8.2"}), latency_row), (
        "a vaulted lab value of 8.2 is being reported as a leak because an audit "
        "latency happened to contain those three characters"
    )

    # ...and the hex-in-run_id false positive the anchoring was introduced for.
    assert not find_in_bytes(
        frozenset({"382892"}), b"\x02\x00run_id=a3f2382892c14e7b9d0e5a6182f4cc71"
    )
    assert find_in_bytes(frozenset({"4823910"}), b'detail{"v":"MRN 4823910"}') == ["4823910"]


def test_the_byte_limb_declines_the_identifier_needles_and_says_what_that_costs() -> None:
    """The one place :func:`find_in_text` is stricter than :func:`find_in_bytes`, on purpose.

    :func:`find_in_text` gained the gate's :func:`_identifier_needles` -- a bare
    substring test, no adjacency requirement, for values carrying at least
    :data:`MIN_IDENTIFIER_DIGITS` digits -- because the gate has it and a checker
    weaker than the code it checks launders the claim. The byte limb did **not**, and
    that asymmetry is a decision with a measurement behind it rather than an oversight
    of the same kind this module keeps finding.

    What was measured: the real audit blob a full 100-run session accumulates is
    1.8 MB of hex run IDs, sha256 digests and float timestamps. Counting the distinct
    seven-digit windows actually present in it gives p = 9.7e-4 that *any* given
    seven-digit needle occurs somewhere by chance, and the 100 runs contribute exactly
    100 seven-digit needles (one MRN each). That is 0.049 expected spurious reds per
    suite -- a ~4.7% chance, per run of the headline artifact, of a false "an original
    reached the audit database".

    The anchoring on this limb was introduced to remove a **1e-6** false-red rate, on
    the argument that a rare false red on this assertion is worse than its frequency
    suggests because it teaches the reader to disbelieve the next genuine one. 4.7% is
    four orders of magnitude the wrong side of that line, so the limb stays anchored
    and the cost is written down instead.

    The cost is bounded: a glued identifier in a **live** audit row is caught by the
    query limb, which is :func:`find_in_text` and does carry the needles. What is
    uncovered is a glued identifier in bytes only this limb reaches -- a freed page, a
    WAL remnant, a superseded row image -- which is the same boundary this limb
    already has for a glued name.

    Both halves are asserted, so neither the decision nor its cost can rot into an
    assumption.
    """
    mrn = "MRN: 5567281"
    digits = "5567281"

    # The cost, stated as a fact about the code rather than as prose.
    glued_bytes = b"sess-a1b2EGRESS_BLOCKchartMRN5567281Bdeadbeef"
    assert digits.encode() in glued_bytes, "premise: the digits really are in the file"
    assert not find_in_bytes(frozenset({mrn}), glued_bytes), (
        "the byte limb has gained the identifier needles -- if that is deliberate, "
        "re-measure the seven-digit false-positive rate against a real 1.8 MB audit "
        "blob first; it was 4.7% per suite when this was last measured"
    )

    # ...and the limb that does carry the case, on the query view of the same row.
    quoted = json.dumps([{"entity_type": "chartMRN5567281B"}], ensure_ascii=False)
    assert find_in_text(frozenset({mrn}), quoted) == [mrn], (
        "the query limb is what covers a glued identifier in a live audit row; if it "
        "stops firing, assertion 2 is blind to the shape on both limbs"
    )

    # The false positive the decision is protecting, made concrete: a seven-digit
    # value really can sit inside an ordinary 32-hex run ID.
    run_id = b"run_id=a3f25567281c14e7b9d0e5a6182f4cc71"
    assert digits.encode() in run_id, "premise: the collision is real, not theoretical"
    assert not find_in_bytes(frozenset({mrn}), run_id)


def test_an_identifier_only_hit_says_which_kind_of_run_the_digits_landed_in() -> None:
    """The fact that separates a real glued identifier from a hex coincidence.

    The limb the test above declines on the byte channel is still applied to the audit
    query view and to the process log, where the same arithmetic gives 2.1e-3 and
    1.7e-1 expected spurious reds per suite respectively
    (:data:`_HARNESS_RUN_FLOOR`). Both numbers are small enough to be invisible in
    development and large enough to fire on the headline assertion eventually, and one
    of them did: run 099 went red on a seven-digit MRN with ``identifier`` as the only
    limb, once in 24 executions of the identical 100 runs.

    What made that expensive was not the frequency, it was that the failure line said
    ``via ['identifier']`` and stopped. A reader then has the same two candidates the
    limb has -- a real leak or a coincidence -- and no way to choose between them
    without re-running a process whose random material is already gone.

    So both shapes are asserted here: the coincidence must be named as a run of
    hexadecimal, and the real leak the limb exists for must NOT be. And the message
    must still refuse to render the value or the text around it -- a site that quoted
    its context would hand back exactly what ``mask`` withheld.
    """
    mrn = "8390244"

    # The coincidence: seven digits inside a 64-character sha256 chain hash. Not a
    # disclosure -- no document value is a hex digest -- and the message must say so.
    digest = "a8390244" + "f" * 56
    assert len(digest) == 64, "premise: this is digest-shaped, which is the whole point"
    hashed = json.dumps([{"entry_hash": digest}], ensure_ascii=False)
    assert find_in_digit_heavy_text(frozenset({mrn}), hashed) == [mrn], (
        "premise: the identifier limb really does fire on a digest collision -- if it "
        "no longer does, this module's audit false-positive rate has changed and "
        "_HARNESS_RUN_FLOOR's arithmetic needs re-measuring"
    )
    described = describe_hits([mrn], hashed)
    assert described == [f"{mask(mrn)} via ['identifier'] inside a 64-char hexadecimal run"], (
        f"an identifier-only hit no longer names the run it landed in: {described}"
    )

    # The real leak: the same seven digits glued to a letter in an audit label. The
    # enclosing run is not hexadecimal, and the message must not let a reader dismiss
    # it as one.
    glued = json.dumps([{"entity_type": "batch8390244Alpha"}], ensure_ascii=False)
    assert find_in_digit_heavy_text(frozenset({mrn}), glued) == [mrn]
    (reported,) = describe_hits([mrn], glued)
    assert reported.endswith("inside a 17-char mixed run"), (
        f"a genuine glued identifier is being described as something else: {reported}"
    )
    assert "hexadecimal" not in reported, (
        "a real leak that reads as a hex coincidence is worse than no site at all"
    )

    # A bare identifier core, where the vaulted value carries a label the channel does
    # not. Every bounded form misses -- they look for the whole original -- and the
    # identifier limb is again the only one, so the site is what says the digits are
    # sitting on their own rather than buried in a digest.
    labelled = "MRN: 8390244"
    alone = json.dumps([{"detail": {"note": mrn}}], ensure_ascii=False)
    (standalone,) = describe_hits([labelled], alone)
    assert standalone.endswith("via ['identifier'] standing alone"), standalone

    # ...and where the bounded forms DO fire there is no site, because a
    # boundary-anchored limb cannot fire on a coincidence and the shape would be noise.
    (anchored,) = describe_hits([mrn], alone)
    assert anchored == f"{mask(mrn)} via ['raw', 'normalised', 'folded', 'skeleton', 'identifier']"

    # Nothing rendered but a shape: not the value, not its neighbours.
    for line in (*described, reported, standalone, anchored):
        assert mrn not in line, "the site leaked the value the mask withheld"
        assert "batch" not in line and digest[:8] not in line, (
            f"the site quoted its haystack: {line}"
        )


def test_the_scan_sees_an_invisible_character_bypass() -> None:
    """One U+200B must not make an original invisible to this module.

    The gate folds zero-width, soft-hyphen and bidi format characters out before
    its third comparison; this module used to compare only two forms while its own
    docstring asserted it compared "the same two forms the EgressGate scans". The
    gate had three. A checker weaker than the code it checks reports clean through
    a leak the code would have blocked -- and on the audit and log channels, where
    the gate never looks, there was nothing else to catch it.

    Found by sabotage: a real pipeline run with one U+200B spliced into a real
    vaulted original read 100/100 clean here while the gate blocked it.
    """
    name = "Marguerite Vandenberg"
    for invisible in ("​", "­", "﻿", "‍", "⁠"):
        haystack = f"The client Marguerite{invisible} Vandenberg signed."
        assert name not in haystack, "premise: the raw value is genuinely not present"
        assert find_in_text(frozenset({name}), haystack) == [name], (
            f"the scan is blind to U+{ord(invisible):04X} inside the original, which "
            "renders identically to a human and to the model"
        )

    # The gate agrees, which is the property that was broken: harness and gate must
    # not disagree about whether this is an occurrence.
    zero_width = "The client Marguerite​ Vandenberg signed."
    assert occurs_as_a_unit(
        _reference_strip_invisible(normalize(name)),
        _reference_strip_invisible(normalize(zero_width)),
    ), "the gate's folded comparison must see this too, or the two have diverged again"

    # And the false positive is still prevented in the folded form.
    assert not find_in_text(frozenset({"Brown"}), "Counsel Brow​ning filed the motion.")


def test_the_audit_scan_sees_json_escaped_non_ascii() -> None:
    """An accented original in the audit log is not hidden by ``ensure_ascii``.

    ``canonical_json`` -- the function that writes the ``detail`` column, and whose
    determinism the hash chain depends on -- is ``ensure_ascii=True``, and
    ``test_audit.py::test_canonical_json_is_deterministic_and_parseable`` pins that
    behaviour deliberately. The consequence for *this* module is that ``"José"``
    reaches SQLite as the ASCII text ``"Jos\\u00e9"``, so both audit scans were
    blind to it: the value is genuinely in the log, any JSON reader decodes it back,
    and neither the byte scan nor the query-API scan could match it.

    Accented surnames are ordinary in the documents this system protects, so this
    was a live hole in "the audit database contains zero originals" rather than a
    hypothetical one.
    """
    accented = "José Muñoz"

    escaped = canonical_json({"leaked": accented})
    assert accented not in escaped, "premise: ensure_ascii really does hide it"
    assert "Jos\\u00e9" in escaped

    # Byte scan of the DB file.
    assert find_in_bytes(frozenset({accented}), escaped.encode("utf-8")) == [accented]
    # Query-path scan: the run below serialises with ensure_ascii=False for this
    # reason, but the unescaping view must catch it either way.
    assert find_in_bytes(
        frozenset({accented}), json.dumps({"detail": {"v": accented}}).encode("utf-8")
    ) == [accented]

    # Unescaping must not manufacture matches out of ordinary text.
    assert not find_in_bytes(frozenset({accented}), b'{"detail":{"v":"nothing here"}}')


def test_the_audit_and_log_scan_sees_one_constituent_of_a_composite_original() -> None:
    """The composite limb must be on :func:`find_in_digit_heavy_text`, not only on the payload scan.

    A vault original is whatever the detector called one span, and spaCy returns
    ``03/11/2024, 09/17/2024`` as a single ``DATE``. So the vaulted value is a string
    nobody wrote as a unit, and a channel carrying just *one* of the two dates defeats
    every other limb at once: the four bounded forms look for the composite, and the
    unbounded identifier limb contributes nothing because the longest contiguous digit
    run in it is four, one short of any run floor. That is the hole
    :func:`_composite_needles` was added to :func:`find_in_text` to close.

    It was closed on the payload only. The audit database and the process log are the
    two channels where **this module is the only opinion there is** -- the gate never
    sees them -- so the limb was missing from precisely the scan that has no backstop,
    while ``find_in_digit_heavy_text``'s own docstring said the identifier floor was
    the only difference between the two.

    The negative half is not decoration. ``_composite_needles`` is a *widening*, and a
    widening on these channels is where this module has already paid for a false
    positive once (see :data:`_HARNESS_RUN_FLOOR`); the constituent needles are
    word-bounded and digit-floored, so an unrelated date and a substring occurrence
    must both stay quiet.
    """
    composite = "03/11/2024, 09/17/2024"
    haystack = '{"detail":{"note":"re-scheduled from 03/11/2024"}}'

    # Premise: the vaulted value itself is genuinely absent, so no bounded form can
    # fire and this test is really about the composite limb.
    assert composite not in haystack
    assert not any(
        needle in _reference_skeleton(haystack)
        for needle in _harness_identifier_needles(composite)
    ), "premise: the identifier limb contributes nothing -- longest digit run is four"

    assert find_in_text(frozenset({composite}), haystack) == [composite]
    assert find_in_digit_heavy_text(frozenset({composite}), haystack) == [composite], (
        "the audit/log scan must see a constituent of a composite original: it is the "
        "only opinion on these two channels, and every other limb goes quiet here"
    )

    # A date that is not one of the constituents must not fire.
    assert not find_in_digit_heavy_text(
        frozenset({composite}), '{"detail":{"note":"re-scheduled from 07/04/2021"}}'
    )
    # Nor may a constituent match without a word boundary, which is what keeps this
    # limb off the false-positive surface the unbounded limb has to be careful about.
    assert not find_in_digit_heavy_text(
        frozenset({composite}), '{"detail":{"note":"batch103/11/20240"}}'
    )


def test_the_log_scan_sees_structured_extra_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A value logged through ``extra=`` must not be invisible to the log scan.

    ``caplog.text`` formats records as ``"%(levelname)s %(name)s:%(file)s:%(line)s
    %(message)s"``. No ``extra`` field appears in that format -- and this package
    routes almost every variable it logs through ``extra``: ``session_id``,
    ``run_id``, ``entity_type``, ``token_id``, counts, latencies.

    So the natural logging leak -- ``logger.debug("...", extra={"value": original})``
    -- was structurally invisible to the assertion that exists to catch it, while
    being fully rendered by the JSON formatter a production deployment runs. The
    harness was scanning the constant half of every log line.
    """
    caplog.set_level(logging.DEBUG)
    planted = "Marguerite Vandenberg"
    logging.getLogger("secure_context_pipeline.probe").info(
        "obfuscated a span", extra={"leaked_value": planted}
    )

    assert planted not in caplog.text, (
        "premise: caplog.text renders no extra fields -- if this ever fails, "
        "pytest's default log format changed and this test's premise needs revisiting"
    )
    assert find_in_text(frozenset({planted}), log_haystack(caplog)) == [planted]

    # The message body is still scanned too.
    caplog.clear()
    logging.getLogger("secure_context_pipeline.probe").info("value is %s", planted)
    assert find_in_text(frozenset({planted}), log_haystack(caplog)) == [planted]


def test_the_prompt_carries_a_real_original() -> None:
    """The prompt half of the payload is not a PII-free constant. Checked, not assumed.

    For all 100 runs the prompt was one module-level string -- *"Summarise this record
    and list the key parties, dates and figures."* -- so the third of the outbound
    payload a **user** writes contained nothing any scan could have found. Every
    "100/100 runs clean" ever quoted was a statement about the document half.

    :func:`prompt_for` fixed that by drawing a real planted literal out of each run's
    own fixture. This test is what stops that quietly reverting, because the failure
    mode is silent by construction: if the draw ever returns something the document
    does not vault -- a fixture edit, a renamed entity type, a span boundary moving --
    the prompt goes back to being unscanned bytes and every assertion downstream still
    passes.

    So the properties the 100 runs depend on are asserted here directly: the value is
    non-empty, it really is one of the fixture's planted literals for that exact run,
    all three rotated shapes are reachable at every seed, and the prompt actually
    contains it. The run itself then asserts the other half -- that the value is in the
    session vault, so the payload scan is hunting for it.
    """
    seen_types: set[str] = set()
    for index in range(RUNS):
        seed, kind, _strategy = plan_run(index)
        entity_type = PROMPT_ENTITY_TYPES[index % len(PROMPT_ENTITY_TYPES)]
        seen_types.add(entity_type)

        value = drawn_original(seed, kind, entity_type)
        planted = generator.expected_entities(seed, kind)
        assert value in planted[entity_type], (
            f"run {index}: the prompt value is not one of the literals the generator "
            f"planted in this document, so the vault will not hold it ({mask(value)})"
        )
        assert len(value) >= MIN_ORIGINAL_LEN, (
            f"run {index}: the prompt value is shorter than the gate's floor, so the "
            f"gate would skip it and the prompt half of the scan is decorative"
        )

        prompt = prompt_for(index)
        assert value in prompt, f"run {index}: prompt_for dropped the value it drew"
        assert prompt.startswith(BASE_PROMPT), (
            f"run {index}: the instruction half of the prompt changed shape"
        )

    assert seen_types == set(PROMPT_ENTITY_TYPES), (
        f"only {sorted(seen_types)} of {sorted(PROMPT_ENTITY_TYPES)} prompt shapes are "
        "reachable across the runs, so the rotation is not rotating"
    )

    # The rotation must actually vary the bytes, or this is the old constant wearing a
    # function. Compared across the first six runs, which cover every (kind, shape).
    prompts = {prompt_for(i) for i in range(6)}
    assert len(prompts) == 6, f"the per-run prompts are not distinct: {len(prompts)}/6"


def test_a_partial_value_leak_is_outside_what_this_harness_claims() -> None:
    """The boundary of the claim, pinned so it cannot be quietly forgotten.

    If a splice bug leaves one *component* of a multi-word original behind --
    ``Vandenberg`` from ``Marguerite Vandenberg`` -- neither this harness nor the
    egress gate reports it. Both ask whether the vaulted **value** occurs, and it
    does not. Confirmed by sabotage against a real pipeline: a partial leak of a
    real vaulted original passes the gate *and* reads clean here.

    It is pinned rather than fixed because the fix is not safely assertable. Fixture
    originals include ordinary clinical phrases (``chronic low back pain``) and
    Faker surnames that are ordinary English words (``Brown``, ``Rich``), so a
    word-level scan manufactures reds that are indistinguishable from real leaks --
    which is the exact failure mode, in the exact file, that cost this build the
    most time (see ``test_a_short_surrogate_inside_a_longer_word_has_not_survived``).

    The honest form of the guarantee is therefore "no whole vaulted value reaches
    the payload, the audit log or the process log", and that is what the README
    says. This test exists so that sentence stays true rather than becoming a
    sentence nobody re-reads.
    """
    original = "Marguerite Vandenberg"
    surname_only = "The client Vandenberg signed the release."

    assert original not in surname_only
    assert not find_in_text(frozenset({original}), surname_only), (
        "if this now fires, the harness has gained component-level detection -- "
        "good, but the README's stated boundary and this test must change with it"
    )

    # The whole value is of course still caught, so this is a boundary and not a hole
    # in the primary claim.
    assert find_in_text(frozenset({original}), f"The client {original} signed the release.") == [
        original
    ]


def test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims() -> None:
    """The second stated boundary: adjacency to a letter on either side suppresses the match.

    ``xJohn Smithx`` carries the original **byte for byte**, and neither this
    harness nor the gate reports it -- both resolve to :func:`_occurs_as_a_unit`,
    which applies a word-boundary assertion on each side whose adjacent needle
    character is alphanumeric. Found by sabotage, not by reading: a real vaulted
    original was spliced into a real payload in this shape with the gate's pass 1
    blinded, and all six runs read clean; with the gate live the value reached the
    provider.

    It is a boundary rather than a bug because the alternative is worse in a way
    this file has already paid for. Dropping the assertion makes ``Brown`` match
    inside ``Browning`` -- a red that is indistinguishable from a real leak until
    somebody spends an hour on it, and one that appears and vanishes between runs
    because pseudonyms derive from a random per-session key. Restricting the
    relaxation to multi-word originals does not rescue it either: fixture originals
    include ordinary clinical phrases, and ``chronic low back pains`` contains
    ``chronic low back pain`` verbatim, so the plural alone would manufacture a red.

    What makes the residual risk small is that the shapes the *pipeline* can
    actually emit do not land here. Every surrogate ends in ``]`` and every
    redaction marker does too, so a splice that leaves an original adjacent to our
    own output has a non-alphanumeric character between them and is caught -- which
    :func:`test_the_scan_sees_markdown_and_punctuation_wrapped_originals` pins from
    the other direction. This test exists so the boundary is a decision on the
    record rather than a surprise in a live review.
    """
    original = "John Smith"

    for haystack in (
        f"Reference: x{original}x confirmed.",
        f"Reference: x{original} confirmed.",
        f"Reference: {original}x confirmed.",
    ):
        assert original in haystack, "premise: the original really is present verbatim"
        assert not find_in_text(frozenset({original}), haystack), (
            f"if this now fires, the occurrence rule has gained glued-word detection "
            f"for {haystack!r} -- good, but the README's stated boundary must change "
            "with it, and the Brown/Browning false positive must be re-checked"
        )

    # The false positive the rule exists to prevent, and the plural form that rules
    # out the obvious "relax it for multi-word needles" fix.
    assert not find_in_text(frozenset({"Brown"}), "Counsel Browning filed the motion.")
    assert not find_in_text(
        frozenset({"chronic low back pain"}), "notes chronic low back pains today"
    )

    # Separated by anything non-alphanumeric -- including our own output's ``]`` --
    # it is caught, which is the case the pipeline can actually produce.
    assert find_in_text(frozenset({original}), f"[PII_NAME_1a2b3c4d]{original} confirmed.") == [
        original
    ]


def test_the_scan_sees_a_combining_mark_spliced_into_a_value() -> None:
    """A boundary that stopped being one, and the stale argument that hid it.

    This test used to be called
    ``test_a_combining_mark_inside_a_value_is_outside_what_this_harness_claims`` and
    asserted the opposite of what it asserts now. It was wrong, and the *way* it was
    wrong is the recurring defect of this project in its purest form: it argued, at
    length and persuasively, that the gate could not catch this either -- while the
    gate had already been catching it for a release.

    The argument was: ``_INVISIBLE_RE`` folds 145 format codepoints and stops short of
    combining marks on purpose, because folding marks would make ``José`` and ``Jose``
    the same value. That sentence is true, and it is about the **needle**.
    ``EgressGate._deaccent`` strips marks from the **haystack** only, which collapses
    nothing: a vaulted ``José`` keeps its accent and therefore still does not match a
    payload saying ``Jose``. The old test never noticed because it checked the gate's
    agreement against ``_occurs_as_a_unit`` on the *folded* forms -- one limb of a
    five-limb scan, and not the limb that had changed. Checking a sub-limb and
    reporting it as the gate's verdict is how a checker convinces itself it is not
    weaker than the thing it checks.

    So all three claims are now made against the real functions:

    * :func:`find_in_text` catches a mark spliced into a mark-free vaulted value;
    * the gate's whole ``_scan_originals`` catches the same payload -- read off the
      real gate, not off one of its limbs;
    * ``José`` and ``Jose`` remain **different values**, which is the property the
      old argument was actually protecting and which nothing had ever asserted.
    """
    original = "John Smith"
    mark = unicodedata.lookup("COMBINING ACUTE ACCENT")
    mutated = f"Reference: {original[0]}{mark}{original[1:]} confirmed."

    assert original not in mutated, "premise: the raw value is genuinely not present"
    assert find_in_text(frozenset({original}), mutated) == [original], (
        "a combining mark spliced into a vaulted value hides it from this scan again, "
        "while EgressGate._deaccent still catches it -- the harness is weaker than the "
        "code it measures, which is the one thing this module may not be"
    )

    # The gate's real verdict, off the whole scan rather than one limb of it.
    assert _gate_scan_hits(frozenset({original}), mutated) == 1, (
        "premise: the gate blocks this payload -- if it no longer does, the gate lost "
        "_deaccent and that is a finding about the gate, not about this test"
    )

    # The property the old argument was protecting, which nothing ever asserted:
    # stripping marks from the haystack does NOT collapse two distinct originals.
    assert not find_in_text(frozenset({"José"}), "the client Jose signed the release"), (
        "`José` and `Jose` have been collapsed into one value -- that is the false "
        "positive the gate's asymmetric _deaccent exists to avoid"
    )
    assert _gate_scan_hits(frozenset({"José"}), "the client Jose signed the release") == 0

    # NFKC composes, so a decomposed rendering of an accented original is caught too.
    accented = "José Ruiz"
    decomposed = unicodedata.normalize("NFD", accented)
    assert accented not in f"client {decomposed} signed", "premise: NFD is a distinct string"
    assert find_in_text(frozenset({accented}), f"client {decomposed} signed") == [accented]


def test_the_scan_sees_an_identifier_glued_into_a_longer_run() -> None:
    """The gate's :func:`_identifier_needles` limb, which this file did not have.

    The boundary rule refuses to call ``Brown`` inside ``Browning`` an occurrence, and
    it is right to -- that is a word-list argument about *names*. It does not transfer
    to a nine-digit identifier, and the document body is written by whoever uploads
    the file. The gate drew that distinction; this harness did not, so for one release
    these were values the **gate blocked and this file called clean**:

        find_in_text({"47-1234567"}, '{"detail":{"note":"batch47-1234567Alpha"}}') -> []

    On the payload that is survivable, because the gate blocks anyway. On the audit
    query view and the process log -- which this function also scans and the gate never
    sees -- it was a straight hole in the "zero originals in the audit log" claim.

    The needles are the gate's own function, not a restatement of its rule, so the two
    cannot drift; what is asserted here is that they are actually *applied*.
    """
    tax_id = "47-1234567"
    mrn = "MRN: 5567281"

    glued = '{"detail":{"note":"batch47-1234567Alpha"}}'
    assert tax_id in glued, "premise: the identifier is present byte for byte"
    assert not occurs_as_a_unit(tax_id, glued), (
        "premise: the boundary rule alone still refuses this -- that is why the "
        "identifier limb has to exist"
    )
    assert find_in_text(frozenset({tax_id}), glued) == [tax_id]

    # The label-carrying half: the vaulted span includes its own label, so the whole
    # value never appears -- but the digits do, and the digits are the secret.
    chart = "chart row MRN5567281B reconciled"
    assert mrn not in chart, "premise: the vaulted value itself is genuinely absent"
    assert find_in_text(frozenset({mrn}), chart) == [mrn]

    # The gate agrees on both, read off the whole scan.
    assert _gate_scan_hits(frozenset({tax_id}), glued) == 1
    assert _gate_scan_hits(frozenset({mrn}), chart) == 1

    # And the limb stays off values it is not for: a name has no digits.
    assert not _identifier_needles("Marguerite Vandenberg")
    assert not find_in_text(frozenset({"Marguerite Vandenberg"}), "reviewer=Marguerite Vandenbergx")

    # A six-digit run IS in scope for the gate, and is NOT in scope for this module.
    # That is the one place this file is deliberately narrower than the gate, and it
    # is a measured decision rather than drift -- see _HARNESS_RUN_FLOOR, which is
    # what the next two assertions are really about.
    assert _identifier_needles("382892") == ("382892",), (
        "the gate scans six-digit runs unbounded (a six-digit MRN core is a real "
        "registry shape); if this stops being true the gate has regressed"
    )
    assert not _harness_identifier_needles("382892"), (
        f"this module's own floor is {_HARNESS_RUN_FLOOR} digits, because it scans "
        "the audit database where a 32-hex run_id gives a six-digit needle 27 "
        "landing sites -- the false positive this module has already paid for once"
    )
    # And pinned from ABOVE, which the assertion before it cannot do. A floor is a
    # window, and only its lower edge was held: `not _harness_identifier_needles(...)`
    # gets *more* true as the floor rises, so raising _HARNESS_RUN_FLOOR from 7 to 99 --
    # which disables the identifier limb on the audit database and the process log
    # entirely, the two channels where this module is the only opinion -- left all 137
    # tests in this file green, 100/100 runs clean. Seven digits must still BE a needle,
    # so the limb's own reason to exist is what goes red if the number drifts upward.
    assert _harness_identifier_needles("3828921") == ("3828921",), (
        f"a {_HARNESS_RUN_FLOOR}-digit run must still be a needle: if it is not, the "
        "unbounded identifier limb is switched off on the audit database and the "
        "process log, and this module reports clean because it stopped looking"
    )


#: Ordinary spellings of a single space, in the transports a document actually travels
#: through: a portal URL, an HTML mail body, a Word round-trip. Each of them carries
#: **word characters**, which is what makes them invisible to a separator rule written
#: as a character class -- ``20``, ``nbsp``, ``32`` and ``br`` are alphanumeric.
_TRANSPORT_ENCODED_SPACES: tuple[tuple[str, str], ...] = (
    ("percent-escape", "%20"),
    ("named character reference", "&nbsp;"),
    ("numeric character reference", "&#32;"),
    ("markup break", "<br/>"),
)


def test_the_scan_sees_a_separator_the_payload_transport_encoded() -> None:
    """A whole vaulted name on the wire, and this module reported CLEAN on it.

    Not a hypothetical shape: ``?patient=Marguerite%20Vandenberg&view=summary`` is what
    an uploaded portal note contains, the pipeline transports the document verbatim as
    advertised, and the name reaches the provider entire. All four spellings below do
    the same thing through a different transport.

    Every limb in :func:`_find_in_one_view` misses it at once, which is why it survived
    128 leakage tests. The four bounded forms keep the separator inside the needle, so
    they are looking for a string the payload does not contain; the separator-invariant
    limb relaxes the separator to *any non-alphanumeric run*, and ``20``, ``nbsp``,
    ``32`` and ``br`` are alphanumeric. The identifier and composite limbs never look at
    a letters-only name at all.

    Asserted against **this module's own scan only**, deliberately: whether the gate
    also blocks these is the gate's own test to keep, and the property that matters here
    is that the harness does not depend on the answer. That was the whole defect -- this
    limb used to be a call into the gate, so the two were one opinion wearing two names.
    """
    original = "Marguerite Vandenberg"
    for label, separator in _TRANSPORT_ENCODED_SPACES:
        payload = f"?patient=Marguerite{separator}Vandenberg&view=summary"
        assert original not in payload, (
            f"premise for {label}: the vaulted value is genuinely absent byte for byte, "
            "so nothing here is caught by a plain substring test"
        )
        assert not occurs_as_a_unit(original, payload), f"premise for {label}: bounded forms miss"
        folded = _reference_strip_invisible(normalize(original))
        assert not _harness_separator_hit(folded, _reference_strip_invisible(normalize(payload))), (
            f"premise for {label}: the separator limb alone misses it on the undecoded "
            "haystack -- the decoded view is what closes this, not a wider separator "
            "class, which would make `John Smith` match `JohnQSmith`"
        )
        assert find_in_text(frozenset({original}), payload) == [original], (
            f"the {label} spelling of a space carries the whole vaulted name to the "
            "provider, and this module is what reports whether it did"
        )


def test_the_separator_limb_does_not_ask_the_gate_for_its_answer() -> None:
    """Sabotage the gate's separator machinery; this module must not go blind with it.

    The recorded failure, from the gate's own test file: deleting ``_separator_needles``
    outright "left the full suite green, including all 128 leakage tests", because the
    harness *called* ``_occurs_with_flexible_separator``. Gate and harness lost the limb
    in lockstep, so the check that exists to disagree with the gate could not.

    ``test_the_harness_is_never_weaker_than_the_gate_on_generated_input`` cannot see
    that: "never weaker" is satisfied when both are equally blind. This test asserts the
    other half -- the harness is not merely as strong as the gate, its answer is *its
    own* -- by killing the gate's separator limb outright and requiring this module to
    go on reporting the leak.

    Monkeypatched rather than edited: ``_separator_needles`` reads
    ``_INTERIOR_SEPARATOR`` at call time, so stubbing the module attribute to a pattern
    that can never match is the same thing as deleting the limb, and it is undone at
    teardown.

    **What each payload is doing here.** The first is the separator limb's own shape,
    and it carries the two premises that make the sabotage mean something: the live gate
    blocks it, and the stubbed gate does not. The second is the transport-encoded
    spelling, asserted about **this module only** -- the gate's handling of that shape is
    the gate's own business and its own test, and pinning a premise on it here would
    couple this file to the thing it exists to disagree with all over again. The gate's
    transport decode is stubbed alongside, ``raising=False``, so that if the gate does
    hold such a limb it cannot be the reason anything below passes.
    """
    original = "Marguerite Vandenberg"
    separator_payload = "reviewer Marguerite/Vandenberg filed"
    encoded_payload = "?patient=Marguerite%20Vandenberg"

    assert _gate_scan_hits(frozenset({original}), separator_payload) == 1, (
        f"premise: the live gate blocks {separator_payload!r}. If it does not, this test "
        "is sabotaging a limb that is already gone -- a finding about the gate"
    )

    with pytest.MonkeyPatch.context() as patch:
        # `(?!)` is the empty negative lookahead: a valid pattern that matches nothing,
        # whatever it is joined to. Anything the gate builds from it is dead.
        patch.setattr(egress_gate, "_INTERIOR_SEPARATOR", "(?!)")
        patch.setattr(egress_gate, "_decode_transport_escapes", lambda value: None, raising=False)

        assert _gate_scan_hits(frozenset({original}), separator_payload) == 0, (
            "premise: with its interior-separator pattern stubbed dead the gate is blind "
            f"to {separator_payload!r}. It is not, so the sabotage missed the mechanism "
            "and nothing below is evidence"
        )
        for payload in (separator_payload, encoded_payload):
            assert find_in_text(frozenset({original}), payload) == [original], (
                "this module reports a leak only because the gate does -- which is the "
                "defect: 128 leakage tests stayed green through a whole vaulted name "
                "on the wire, because the checker was asking the thing it checks"
            )


# ---------------------------------------------------------------------------
# The own-token-id exclusion: the coincidence it removes, and everything it must
# go on reporting. See _harness_mask_own_ids.
# ---------------------------------------------------------------------------

#: ``(vaulted value, the token WE issued, the payload)`` for the two coincidences the
#: gate reproduced when it took the same exemption. Copied from its docstring on
#: purpose: they are the exact strings that named this module as the sibling instance
#: the gate fix did not close, so the ledger and the fix quote the same evidence.
#:
#: In both, every digit of the vaulted value sits inside an eight-hex id the pipeline
#: drew itself -- an HMAC under the session key, truncated -- and nowhere else in the
#: payload. :func:`test_the_own_id_coincidence_is_the_only_landing_site` asserts that
#: "nowhere else" rather than trusting it, because the whole exclusion is only as
#: defensible as the claim that the exempted characters carry no secret.
_OWN_ID_COINCIDENCES: tuple[tuple[str, str, str], ...] = (
    (
        "8390244",
        "[FIN_ACCOUNT_NUMBER_8390244f]",
        "<DOCUMENT>\nAccount {} closed.\n</DOCUMENT>",
    ),
    ("552140", "[PHI_MRN_a552140f]", "Chart: {} reviewed."),
)


@pytest.mark.parametrize("value,token,frame", _OWN_ID_COINCIDENCES)
def test_the_own_id_coincidence_is_the_only_landing_site(
    value: str, token: str, frame: str
) -> None:
    """Premise for everything below: the digits are in our id and in nothing else.

    Without this, every "the exclusion removes it" assertion in this section could be
    satisfied by an exclusion that blanks far more than an eight-hex id -- the whole
    token, the whole payload -- and the tests would read exactly the same. Asked
    against :func:`_reference_contains`, which is written to the compliance question
    (*is the value in the text?*) rather than to this module's occurrence rule, so a
    bug in the occurrence rule cannot make this premise pass.
    """
    payload = frame.format(token)
    assert _reference_contains(value, payload), (
        f"premise: {mask(value)} is in this payload at all -- inside our own id"
    )
    assert not _reference_contains(value, payload.replace(token, "")), (
        f"premise: {mask(value)} occurs ONLY inside the token this run issued. It occurs "
        "somewhere else too, so this payload is a real disclosure and is the wrong "
        "evidence for an exclusion"
    )


@pytest.mark.parametrize("value,token,frame", _OWN_ID_COINCIDENCES)
def test_the_own_id_exclusion_removes_the_coincidence_the_gate_relocated(
    value: str, token: str, frame: str
) -> None:
    """The reported defect, closed -- with the pre-fix behaviour asserted beside it.

    The gate's own exemption removed these as ``EgressBlockedError`` refusals and its
    docstring names this module as the half it did not close: *"verified, not inferred
    -- on the two payloads at the top of this docstring it returns ``['8390244']`` and
    ``['552140']``"*. Reproduced here before it was fixed, on the real functions::

        find_in_text({'8390244'}, 'Account [FIN_ACCOUNT_NUMBER_8390244f] closed.')
            -> ['8390244']

    So the flake was **relocated**, not removed: the same non-event that used to stop
    the run at the gate landed on assertion 1 instead, where it reads as *"original
    present in the outbound payload"* -- the headline claim of this repository -- about
    a run in which nothing left.

    The un-excluded call is asserted in the same test rather than left implicit. An
    exclusion whose "before" is not pinned is an exclusion that could be doing nothing,
    and the assertion below it would still be green.
    """
    payload = frame.format(token)
    originals = frozenset({value})

    assert find_in_text(originals, payload) == [value], (
        "premise: with no exclusion this module still reports the coincidence. If it "
        "does not, the limb this fix is about has gone missing and the assertion below "
        "is measuring nothing"
    )
    assert find_in_text(originals, payload, issued=frozenset({token})) == [], (
        f"the own-id exclusion did not remove {mask(value)}: assertion 1 still reports "
        "the pipeline's own HMAC digest as an original on the wire"
    )


def test_the_own_id_exclusion_reaches_the_log_channel_too() -> None:
    """The same coincidence on the channel where this module is the only opinion.

    ``aiosqlite`` logs every statement it executes at DEBUG *with its bound
    parameters*, and the vault binds the surrogate -- so every token a run emits is in
    ``log_haystack(caplog)`` verbatim. Counted over six real runs: 31/31, 4/4, 37/37,
    14/14, 36/36 and 14/14 token-shaped surrogates present, against 0 in the audit
    query view and 0 in the audit DB bytes. Assertion 2b therefore carries the identical
    false positive, at this function's own floor -- :data:`_HARNESS_RUN_FLOOR` is seven
    digits and an eight-hex id holds two seven-character windows.

    Only the seven-digit coincidence is exercised: the six-digit one is below this
    channel's floor and reports clean either way, which would make it a test of the
    floor rather than of the exclusion.
    """
    value, token, frame = _OWN_ID_COINCIDENCES[0]
    payload = frame.format(token)
    originals = frozenset({value})

    assert find_in_digit_heavy_text(originals, payload) == [value], (
        "premise: the log/audit scan reports the coincidence with no exclusion"
    )
    assert find_in_digit_heavy_text(originals, payload, issued=frozenset({token})) == [], (
        "the own-id exclusion did not reach the log channel, so the relocated flake is "
        "still live on assertion 2b"
    )


@pytest.mark.parametrize("value,token,frame", _OWN_ID_COINCIDENCES)
def test_the_own_id_exclusion_does_not_ask_the_gate_for_its_answer(
    monkeypatch: pytest.MonkeyPatch, value: str, token: str, frame: str
) -> None:
    """Sabotage the gate's exemption machinery; this module must exclude anyway.

    The prescription for this fix was explicit that it must **not** be
    ``from egress_gate import _mask_own_tokens``, and the reason is a bill this file
    has already paid twice. :func:`_harness_separator_hit` exists because deleting the
    gate's ``_separator_needles`` "left the full suite green, including all 128 leakage
    tests"; :func:`_reference_skeleton` exists because two successive gate fold changes
    each moved this module in lockstep and it printed ``100/100 runs clean, 0 leaks``
    through both. A checker that inherits its exemption from the code it checks has
    stopped being a second opinion, and the way that failure looks from the outside is
    *nothing at all*.

    So every function the gate's exemption is built from is stubbed dead at once --
    ``_own_token_mask`` returning ``None`` for everything, ``_mask_own_tokens`` and
    ``_strip_own_tokens`` returning their input -- and this module must go on excluding.
    All three rather than only the one under discussion: a checker that survives
    because it happened to call a *different* borrowed helper is not independent
    either. ``raising=False`` on none of them, deliberately: if one is renamed this test
    must go red rather than silently sabotage nothing.

    The two premises make the sabotage mean something. With the gate intact and its
    surrogate set supplied, the gate exempts the coincidence (0 hits); with the gate
    stubbed, it blocks again (1 hit). If the second premise ever fails, the stub missed
    the mechanism and nothing below is evidence.
    """
    payload = frame.format(token)
    originals = frozenset({value})
    issued = frozenset({token})

    assert _gate_scan_hits(originals, payload, issued) == 0, (
        "premise: the live gate exempts this coincidence. If it does not, the defect "
        "this test is about was never relocated and the ledger is wrong"
    )

    monkeypatch.setattr(egress_gate, "_own_token_mask", lambda surrogate: None)
    monkeypatch.setattr(egress_gate, "_mask_own_tokens", lambda payload, surrogates: payload)
    monkeypatch.setattr(egress_gate, "_strip_own_tokens", lambda payload, surrogates: payload)

    assert _gate_scan_hits(originals, payload, issued) == 1, (
        "premise: with its exemption stubbed dead the gate blocks this payload again. "
        "It does not, so the sabotage missed the mechanism"
    )
    assert find_in_text(originals, payload, issued=issued) == [], (
        "this module excludes the coincidence only because the gate does -- which is "
        "the defect the prescription for this fix named in advance: a checker that "
        "inherits its exemption from the code it checks is not a second opinion"
    )
    assert find_in_digit_heavy_text(originals, payload, issued=issued) == []


#: A vaulted value, a token **we** issued, and a payload putting the two in contact.
#: Every one of these must still be REPORTED: the exclusion is eight characters wide
#: and the value is not inside those eight characters.
#:
#: The last two are the ones that make it an *exact-span* exclusion rather than a
#: grammar over token-shaped text. ``ACCOUNT_NUMBER`` is a registry literal sitting
#: inside our own token, and ``panel`` is inside the ``|hint`` tail -- which is the one
#: field of a token derived from the original's own text (``hint_for`` passes
#: ``detection.text`` to the gazetteer), so masking it would be masking a projection of
#: the secret. Both are word-bounded inside the token because ``_``, ``[``, ``]`` and
#: ``-`` are not alphanumeric.
_GLUED_TO_OUR_TOKEN: tuple[tuple[str, str, str, str], ...] = (
    (
        "value immediately after our token",
        "8390244",
        "[FIN_ACCOUNT_NUMBER_a1b2c3d4]",
        "Account [FIN_ACCOUNT_NUMBER_a1b2c3d4]8390244 closed.",
    ),
    (
        "value immediately before our token",
        "8390244",
        "[FIN_ACCOUNT_NUMBER_a1b2c3d4]",
        "Account 8390244[FIN_ACCOUNT_NUMBER_a1b2c3d4] closed.",
    ),
    (
        "value in the payload and a token elsewhere",
        "Marguerite Vandenberg",
        "[PII_NAME_a1b2c3d4]",
        "The client Marguerite Vandenberg signed; see [PII_NAME_a1b2c3d4].",
    ),
    (
        "registry literal inside our own token",
        "ACCOUNT_NUMBER",
        "[FIN_ACCOUNT_NUMBER_a1b2c3d4]",
        "Account [FIN_ACCOUNT_NUMBER_a1b2c3d4] closed.",
    ),
    (
        "value inside our own hint tail",
        "panel",
        "[PII_ADDRESS_989aa4fe|lab-panel-3]",
        "Site [PII_ADDRESS_989aa4fe|lab-panel-3] sampled.",
    ),
)


@pytest.mark.parametrize("label,value,token,payload", _GLUED_TO_OUR_TOKEN)
def test_a_vaulted_value_glued_to_our_own_token_is_still_found(
    label: str, value: str, token: str, payload: str
) -> None:
    """The complement: the exclusion is eight characters wide and not one more.

    An exclusion is only as good as the list of things it does **not** cover, and the
    cheap way to close the reported false positive is to skip anything token-shaped --
    which would take a vaulted value glued to a token, sitting in a token's hint, or
    spelled like a registry literal off the wire with it. The gate calls these its
    three narrowings; this is the same claim asserted against this module's own scan.

    The value is asserted present with the exclusion **on**, which is the only version
    of this test worth having: with it off every case passes trivially.
    """
    found = find_in_text(frozenset({value}), payload, issued=frozenset({token}))
    assert found == [value], f"the own-id exclusion swallowed a real leak: {label}"


def test_a_vaulted_value_spanning_a_token_boundary_is_still_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A disclosure our own token sits in the middle of, and the stream that finds it.

    This is the case masking alone gets **wrong**, and it was found by writing the
    complement rather than by reading the fix. All twelve digits of the value are on
    the wire, split by a token this run issued::

        vault  {'987714668699'}
        wire   'ledger filed 98771466869[PII_ADDRESS_989aa4fe|lab-panel-3]9 today'

        find_in_text(...)                      -> ['987714668699']   # before the fix
        find_in_text(..., issued={the token})  -> []                 # masking alone

    The regrouped limb compares digits-only streams, so with the id blanked the stream
    reads ``98771466869`` + ``3`` (from the hint) + ``9`` and the needle is gone. The
    second stream -- our tokens **deleted** rather than masked
    (:func:`_harness_strip_own_tokens`) -- is what puts it back.

    Worth naming that the pre-fix scan reported this payload only by **luck**: it was
    reading the ``989`` out of the id, and the same payload with the id ``c3f7003f``
    reported clean before the fix and reports the leak after it. So the second stream
    is not a concession to the old behaviour, it is the answer the old behaviour was
    reaching by accident. Both ids are exercised below for exactly that reason.

    The second half sabotages **this module's own** fix: with
    :func:`_harness_strip_own_tokens` stubbed to the identity function the leak must
    disappear. Without that, an implementation that deleted nothing would satisfy the
    first half through the lucky id and fail silently on the unlucky one.
    """
    value = "987714668699"
    for token_id in ("989aa4fe", "c3f7003f"):
        token = f"[PII_ADDRESS_{token_id}|lab-panel-3]"
        payload = f"ledger filed 98771466869{token}9 today"
        assert find_in_text(frozenset({value}), payload, issued=frozenset({token})) == [value], (
            f"a vaulted value split by one of our own tokens went unreported (id {token_id})"
        )

    token = "[PII_ADDRESS_c3f7003f|lab-panel-3]"
    payload = f"ledger filed 98771466869{token}9 today"
    # ``setitem`` on this module's own globals: :func:`find_in_text` resolves the name
    # at call time, so replacing the binding is the same thing as deleting the stream,
    # and it needs no import path that a file move could invalidate.
    monkeypatch.setitem(globals(), "_harness_strip_own_tokens", lambda haystack, issued: haystack)
    assert find_in_text(frozenset({value}), payload, issued=frozenset({token})) == [], (
        "the token-excised digit stream is not what finds the straddling leak, so the "
        "test above is passing for some other reason and this fix is unpinned"
    )


def test_the_own_id_exclusion_refuses_a_token_the_run_did_not_issue() -> None:
    """Narrowing 1: string equality against the emitted set, never a grammar.

    The payload is assembled from a document the **uploader** wrote, so a rule keyed on
    "looks like one of our tokens" is a rule an attacker can satisfy: paste
    ``[FIN_ACCOUNT_NUMBER_8390244f]`` into an uploaded record and the scan stops reading
    a vaulted account number inside it. The exclusion is ``str.replace`` of surrogates
    this run actually issued, so a token-shaped string that is not in that set is
    ordinary payload text.

    Both halves are asserted: the set with a *different* token in it changes nothing,
    and an empty set changes nothing. A membership test that had silently degenerated
    into a grammar would pass the second and fail the first.
    """
    value, token, frame = _OWN_ID_COINCIDENCES[0]
    payload = frame.format(token)
    originals = frozenset({value})
    other = "[FIN_ACCOUNT_NUMBER_deadbeef]"

    assert issued_token_id(other) is not None, (
        "premise: the decoy is itself a well-formed token, so what distinguishes it is "
        "membership and nothing else"
    )
    assert find_in_text(originals, payload, issued=frozenset({other})) == [value]
    assert find_in_text(originals, payload, issued=frozenset()) == [value]


def test_the_own_id_exclusion_refuses_a_pseudonym() -> None:
    """Narrowing 2: the grammar as well as the set, which keeps the fakes scanned.

    A pseudonym is in the emitted set and carries no id, and it is the half of that set
    that can hide a **real** leak: a fake drawn as ``Rachel Medina`` while ``Medina`` is
    a real original in the same document puts that surname verbatim on the wire. This
    harness has caught exactly that once. So membership alone must not exempt anything
    -- :func:`_harness_own_id_mask` returns ``None`` for a surrogate this module cannot
    parse as one of our tokens, and that value goes on being read.

    Asserted at both levels: the helper's own answer, and the scan's.
    """
    fake = "Rachel Medina"
    assert _harness_own_id_mask(fake) is None, (
        "a pseudonym parsed as one of our tokens; every fake in the emitted set is now "
        "exempt and the collision guard is the only thing left between a real surname "
        "and the provider"
    )
    payload = "Contact Rachel Medina about the transfer."
    assert find_in_text(frozenset({"Medina"}), payload, issued=frozenset({fake})) == ["Medina"]


def test_the_own_id_exclusion_masks_the_id_and_leaves_the_token_the_same_shape() -> None:
    """The mask is length-preserving and alphanumeric, so no boundary anywhere moves.

    Every bounded form in this module decides with :func:`occurs_as_a_unit`, a rule
    that keys on whether the adjacent character is alphanumeric. A mask of a different
    class -- a space, a bracket, deletion -- would be a fold that MOVES a word boundary,
    and this file has already shipped that mistake once: widening the gate's mark fold
    glued ``Brightwater`` to ``Corporation`` and the boundary rule then denied a real
    occurrence (:func:`_haystack_forms`). Asserted structurally rather than left to the
    behavioural cases, because those can all pass while the property is one edit from
    being lost.
    """
    for _value, token, _frame in _OWN_ID_COINCIDENCES:
        masked = _harness_own_id_mask(token)
        assert masked is not None
        assert len(masked) == len(token), "the mask changed the token's length"
        differing = [i for i, (a, b) in enumerate(zip(token, masked, strict=True)) if a != b]
        assert len(differing) <= _HARNESS_ID_LEN, (
            f"the mask rewrote {len(differing)} characters; the exclusion is the "
            f"{_HARNESS_ID_LEN}-character id and nothing else"
        )
        token_id = issued_token_id(token)
        assert token_id is not None
        assert masked.replace(_HARNESS_ID_MASK_CHAR * _HARNESS_ID_LEN, token_id) == token, (
            "the mask changed something outside the id span"
        )
        for index in differing:
            # ``str.isalnum`` rather than the package's ``ALNUM_RE``, matching
            # :func:`_reference_occurs_as_a_unit`: the two agree on every ASCII
            # character and this module's habit is to decide with its own primitives.
            assert masked[index].isalnum(), (
                "the mask is not alphanumeric, so it can move a word boundary and the "
                "bounded forms will disagree with themselves"
            )
            assert masked[index] not in _LOWER_HEX, (
                "the mask is hexadecimal, so a masked id can be read back as a token id"
            )


#: Payloads the gate's pass 1 blocks, one per comparison it makes, with the limb each
#: one exists to exercise. Named rather than generated so a reader can see which limb
#: is which, and so a limb that stops existing is a red with a name attached.
#:
#: The ``(only)`` entries were added after measuring, not after reading. Deleting one
#: limb at a time from :func:`find_in_text` and re-running this file showed that
#: removing the **raw** limb and removing the **normalised** limb both left every test
#: green: the ordinary corpus entries satisfy two or three limbs at once, so any one of
#: them can leave without a red. That is the same trap the gate documents about its own
#: three bounded forms -- "a suite whose probes all satisfy two forms at once cannot see
#: the third leave" -- and this corpus had walked straight into it. Each limb now has at
#: least one payload that *only* it can catch.
#:
#: The sabotage matrix, for the next person who edits :func:`find_in_text`:
#: raw and normalised are held by the ``(only)`` entries here; folded is held by the
#: fuzz below (its ``é`` needles are the ones deaccenting breaks); skeleton and
#: identifier are held by both; **composite is held only by the entry here**, and has
#: to be, because the fuzz cannot reach it -- a composite needle wants a delimiter and
#: seven digits on each side of it, and no ``_FUZZ_VALUES`` alphabet carries a comma.
_GATE_BLOCKING_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("raw", "Marguerite Vandenberg", "The client Marguerite Vandenberg signed."),
    # The payload ONLY the raw form catches. NFKC expands U+2120 to ``SM``, which glues
    # an alphanumeric onto the needle in all three derived forms, so the byte-exact
    # comparison is the last one standing. The gate keeps its own test for this
    # (`test_the_raw_form_is_the_only_thing_that_sees_some_leaks`); without the entry
    # here, deleting the raw limb from find_in_text left this whole file green.
    ("raw (only)", "Dr Smith", "the note names Dr Smith℠ throughout"),
    ("normalised", "Marguerite Vandenberg", "client MARGUERITE\nVANDENBERG signed"),
    # The payload ONLY the normalised form catches, and the reason the gate keeps three
    # near-identical bounded forms: re-cased with a zero-width space on each side, so
    # folding them out glues ``x`` onto the needle and the folded and skeleton forms
    # both go quiet. Without this entry, deleting the normalised limb from find_in_text
    # left every other test in this file green -- measured, by doing it.
    ("normalised (only)", "John Smith", "x​JOHN SMITH​x"),
    ("folded (zero width)", "Marguerite Vandenberg", "client Marguerite​ Vandenberg signed"),
    ("folded (tag character)", "John Smith", "client Joh\U000e0041n Smith signed"),
    ("skeleton (combining mark)", "John Smith", "client Joh́n Smith signed"),
    # The payload ONLY the skeleton's ORDERING catches, and the entry that says the
    # ordering out loud. The mark sits between the value's two spaces, so a haystack
    # that is normalised before it is deaccented keeps two spaces where the needle has
    # one -- `normalize` collapses whitespace, and at that point the mark is still
    # holding the run apart. This module derived its skeleton that way and read CLEAN
    # while the gate blocked; see :func:`_haystack_forms`. A lab value rather than a
    # name because the separator-invariant limb has an eight-alphanumeric floor, so a
    # two-component value below it leaves the skeleton as the only limb in play -- with
    # `John  Smith` here instead, the old ordering left this file green.
    ("skeleton (ordering)", "HDL  28", "chart HDL ́ 28 flagged"),
    ("identifier (whole value)", "47-1234567", "routing tag batch47-1234567Alpha here"),
    ("identifier (digit run)", "MRN: 5567281", "chart row MRN5567281B reconciled"),
    ("identifier (bare run elsewhere)", "Account No. 100200300400", "ref 100200300400 posted"),
    ("markdown emphasis", "John Smith", "the memo names _John Smith_ as counsel"),
    ("punctuation-edged needle", "(415) 555-0123", "tel(415) 555-0123 on file"),
    # The payload ONLY the composite limb catches, and the one the gate can
    # *manufacture*. spaCy returns two dates as a single DATE span, so the joined
    # string is one vault original: the four bounded forms look for a string that is
    # not in the payload, and the identifier limb contributes no run needle at all
    # because the longest contiguous digit run in it is `2024`. A third date in the
    # same document, shifted by the session delta, renders as exactly this slice.
    (
        "composite constituent (only)",
        "03/11/2024, 09/17/2024",
        "re-scheduled from 03/11/2024 at the patient's request",
    ),
)


def test_the_harness_scan_is_never_weaker_than_the_gate_scan() -> None:
    """The rule that would have caught all three of the last three misses at once.

    This module's history is one defect repeated: the gate grows a limb, this file
    does not, and for one release the harness reports clean through a payload the gate
    blocks. It happened with the invisible-character fold, again with ``_deaccent``,
    and again with :func:`_identifier_needles`. Each time it was found by a human
    reading two files side by side, and each time the fix was to copy the missing limb
    across -- which fixes the instance and leaves the mechanism intact.

    On the outbound payload the consequence is survivable: the gate blocks whatever
    this file misses. On the **audit database and the process log the harness alone
    scans**, it is a straight bypass of half the headline claim, and it lasts until
    somebody happens to diff the two files again.

    So the relationship is asserted instead of maintained. The property is one-way and
    that direction is the whole point:

        gate blocks  =>  harness reports

    The converse is deliberately *not* asserted. The harness is allowed to be stricter
    and is: it applies no ``MIN_ORIGINAL_LEN`` floor, so a two-character value the gate
    waves through still fails here. Asserting equality would make the harness's one
    deliberate advantage over the gate into a test failure.

    Driven off :func:`_gate_scan_hits`, which calls the gate's whole ``_scan_originals``
    rather than any one of its limbs -- that distinction is exactly what the previous
    version of the combining-mark test got wrong.
    """
    missed: list[str] = []
    for limb, original, payload in _GATE_BLOCKING_PAYLOADS:
        originals = frozenset({original})
        blocked = _gate_scan_hits(originals, payload)
        assert blocked == 1, (
            f"premise for the {limb} case: the gate is supposed to block {payload!r}. "
            "It does not, so either the gate lost a limb -- a finding about the gate -- "
            "or this corpus entry no longer describes the shape it was written for"
        )
        if not find_in_text(originals, payload):
            missed.append(f"{limb}: {mask(original)} in {mask(payload)}")

    assert not missed, (
        f"{len(missed)} payload(s) block at the egress gate and read CLEAN through this "
        f"module's own scan: {missed}. On the payload the gate covers for that; on the "
        "audit database and the process log nothing does, so each one is a hole in the "
        "'zero originals in the audit log' claim until it is closed"
    )


#: How a generated payload mutates the value spliced into it. One entry per limb the
#: gate's pass 1 has, so a payload that only that limb can catch is reachable by
#: construction rather than by luck.
_MUTATIONS = (
    "verbatim",
    "upper",
    "combining_mark",
    "zero_width",
    "line_break",
    # Re-cased AND wrapped in zero-widths. The one shape that reaches the *normalised*
    # form on its own: folding the wrappers out glues the affixes onto the needle, so
    # the folded and skeleton comparisons both go quiet and only the normalised one is
    # left. Without it the fuzz stayed green through deleting that limb.
    "upper_zero_width_wrap",
    # One interior separator re-spelled the way a transport spells it (`%20`, `&nbsp;`,
    # `&#32;`, `<br/>`). Added because no other mutation here can reach the decoded view
    # `find_in_text` scans: no `_FUZZ_VALUES` alphabet carries `%`, `&` or `<`, so no
    # generated payload could ever hold a transport escape and the fuzz was structurally
    # unable to see that view leave. Measured by deleting the decoded view outright:
    # without this entry the test reported "3000 passing, 0 failing" and stayed green;
    # with it, red, shrunk to original='00000 0' under this mutation.
    "transport_escape",
)


def _mutate(value: str, mutation: str, at: int) -> str:
    """``value`` as a payload might carry it, under one mutation, at offset ``at``."""
    if not value:
        return value
    cut = at % len(value)
    if mutation == "upper":
        return value.upper()
    if mutation == "upper_zero_width_wrap":
        return f"​{value.upper()}​"
    if mutation == "combining_mark":
        return value[: cut + 1] + "́" + value[cut + 1 :]
    if mutation == "zero_width":
        return value[: cut + 1] + "​" + value[cut + 1 :]
    if mutation == "line_break":
        return value[: cut + 1] + "\n" + value[cut + 1 :]
    if mutation == "transport_escape":
        # The FIRST non-alphanumeric character, re-spelled. A value that has none is
        # returned unchanged, which is a `verbatim` draw rather than a wasted one.
        for index, ch in enumerate(value):
            if not ch.isalnum():
                escape = _TRANSPORT_ENCODED_SPACES[at % len(_TRANSPORT_ENCODED_SPACES)][1]
                return value[:index] + escape + value[index + 1 :]
        return value
    return value


#: Values to splice in. Two branches, because one strategy cannot reach both halves of
#: pass 1. Prose-shaped draws exercise the four bounded forms; digit-shaped draws are
#: what make :func:`_identifier_needles` reachable at all -- a needle needs seven ASCII
#: digits before that limb looks at it, and a general text strategy over an alphabet
#: with one digit character produces such a needle essentially never. Measured: with
#: the prose branch alone, deleting the identifier limb outright left this test green
#: through 3,000 examples while the corpus test above named three failures.
_FUZZ_VALUES = st.one_of(
    st.text(alphabet="ab1_ .-é", min_size=1, max_size=9),
    st.text(alphabet="0123456789", min_size=6, max_size=11),
    st.text(alphabet="0123456789-() ", min_size=7, max_size=14),
    st.text(alphabet="0123456789A-: ", min_size=7, max_size=14),
)


@given(
    original=_FUZZ_VALUES,
    prefix=st.text(alphabet="ab1_ .-", max_size=6),
    suffix=st.text(alphabet="ab1_ .-", max_size=6),
    mutation=st.sampled_from(_MUTATIONS),
    at=st.integers(min_value=0, max_value=12),
)
@settings(max_examples=3_000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_the_harness_is_never_weaker_than_the_gate_on_generated_input(
    original: str, prefix: str, suffix: str, mutation: str, at: int
) -> None:
    """The same one-way property, past the ten shapes somebody thought of.

    :func:`test_the_harness_scan_is_never_weaker_than_the_gate_scan` compares the two
    scans over a hand-written corpus, and a hand-written corpus encodes the limbs its
    author already knew about -- which is precisely the thing that has been wrong three
    times running here. Each miss was a limb nobody had written a case for *yet*.

    **The payload is built from the value rather than drawn beside it, and that is not a
    convenience.** The first version of this test drew ``original`` and ``payload`` as
    two independent strings over a shared alphabet, on the reasoning that a tiny
    alphabet makes them collide often. Measured against a deliberate sabotage -- the
    skeleton and identifier limbs deleted from :func:`find_in_text`, which the corpus
    test above catches in four places -- it stayed **green through 2,000 examples**. Two
    independent draws collide on a three-character needle a couple of percent of the
    time, and then have to collide *again* on the mark or the zero-width character in
    the right position, which is a probability small enough that the test was decorative.

    So the value is spliced in: ``prefix + mutate(original) + suffix``, with one mutation
    per limb (:data:`_MUTATIONS`) -- verbatim, re-cased, a combining mark inserted, a
    zero-width space inserted, a line break inserted -- and the affixes supply the
    adjacency the boundary rule and :func:`_identifier_needles` disagree about. Every
    draw now exercises a limb instead of almost every draw being a trivial non-match.

    The value strategy has a digit-shaped branch for the same measured reason
    (:data:`_FUZZ_VALUES`): the identifier limb does not look at a needle until it
    carries seven ASCII digits, so a prose alphabet never reaches it and the test was
    blind to that limb's removal even after the splicing fix.

    A failure is a payload hypothesis has shrunk to a minimal pair, which is the part a
    hand-written corpus cannot do at all.
    """
    payload = prefix + _mutate(original, mutation, at) + suffix
    originals = frozenset({original})
    if _gate_scan_hits(originals, payload):
        assert find_in_text(originals, payload) == [original], (
            "the egress gate blocks this payload and this module's scan calls it clean, "
            "so any leak of this shape into the audit database or the process log would "
            "be reported as 100/100 runs clean"
        )


def test_a_short_surrogate_inside_a_longer_word_has_not_survived() -> None:
    """A Faker draw that is a substring of an ordinary word is not a live surrogate.

    The restorer replaces surrogates on word boundaries, so a checker using a bare
    ``in`` disagrees with the code it is checking. Because pseudonyms are seeded
    from a random per-session key, the resulting red appeared and disappeared
    between runs -- the worst kind of failure on the file that carries the headline
    number.
    """
    answer = "The report names Richardson and Browning as counsel of record."

    # Present only as a substring of a longer word: not a surviving surrogate.
    assert "Rich" in answer and "Brown" in answer, "premise: both are substrings"
    assert not [s for s in ("Rich", "Brown") if occurs_as_a_unit(s, answer)]

    # Genuinely present as a word: still caught.
    assert occurs_as_a_unit("Rich", "The client Rich signed the release.")


def _reference_occurs_as_a_unit(needle: str, haystack: str) -> bool:
    """A second derivation of the occurrence rule. **It can only catch divergence.**

    Deliberately shares no machinery with the implementation it checks: explicit
    index arithmetic and :meth:`str.isalnum` instead of regex lookarounds. The
    rule it encodes is the intended one, in words -- *the needle is present, and on
    each side where the needle's own edge character is alphanumeric, the character
    beyond it is not.*

    **Read that sentence next to :func:`_occurs_as_a_unit`'s docstring: it is the same
    specification.** Two derivations of one spec agreeing is evidence that neither was
    mistyped. It is not evidence that the spec is right, and this file's entire defect
    history is spec error rather than transcription error -- ``_`` counting as a word
    character, a needle whose first character is punctuation, a value glued between two
    SQLite column values, an identifier inside ``batch47-1234567Alpha``. Every one of
    those would have been reproduced faithfully by *both* derivations, and the 220-pair
    differential and the 2,000-example fuzz would have stayed green through all of them.
    They did stay green through all of them.

    So this function is kept for what it is genuinely good at -- catching the day
    somebody edits one copy of the rule and not the other -- and the spec-error
    question is asked somewhere else, by a reference written to a **different**
    specification entirely: see :func:`_reference_contains` and
    :func:`test_every_occurrence_this_module_declines_to_report_is_named_on_the_record`.

    It is also the pseudonym predicate for round-trip *completeness*
    (:func:`expected_round_trip`), which is a different job again and the reason it is
    not simply deleted: there the requirement is a predicate the restorer does not
    share, and plain containment would be wrong -- a short Faker draw inside an
    ordinary word is not the model mentioning that surrogate.
    """
    if not needle:
        return False
    start = haystack.find(needle)
    while start != -1:
        end = start + len(needle)
        left_ok = not needle[0].isalnum() or start == 0 or not haystack[start - 1].isalnum()
        right_ok = not needle[-1].isalnum() or end == len(haystack) or not haystack[end].isalnum()
        if left_ok and right_ok:
            return True
        start = haystack.find(needle, start + 1)
    return False


#: Realistic originals, including the punctuation-edged shapes the old rule missed.
_DIFFERENTIAL_NEEDLES = (
    "John Smith",
    "Brown",
    "MRN: 4823910",
    "(415) 555-0123",
    "$1,234.56",
    "47-1234567",
    "Case No. 3:24-cv-01188",
    "ada.brown@example.com",
    "HbA1c of 8.2",
    "O'Brien",
)

#: Every wrapping that has ever mattered here: markdown, brackets, adjacency on
#: each side by a letter, a digit, an underscore and a full stop, and prose.
_DIFFERENTIAL_WRAPPERS = (
    "{}",
    " {} ",
    "_{}_",
    "__{}__",
    "**{}**",
    "`{}`",
    "({})",
    "[{}]",
    "<DOCUMENT>{}</DOCUMENT>",
    "the client {} signed the release",
    "x{}",
    "{}x",
    "x{}x",
    "_{}",
    "{}_",
    "1{}",
    "{}1",
    ".{}",
    "{}.",
    "line one\n{}\nline three",
    "{} and again {}",
    "nothing to see here",
)


def test_the_occurrence_rule_has_no_fourth_copy() -> None:
    """The shared rule, checked against an independent restatement of it.

    The gate, the engine's residual sweep and this harness now all resolve to one
    function, which removes the *divergence* risk that produced a false 100/100 --
    but sharing a definition is not the same as verifying it. If the single
    remaining copy is wrong, everything downstream is uniformly wrong and uniformly
    silent, which is precisely the failure mode that made the original bug so
    expensive to find.

    So the shared implementation is compared against
    :func:`_reference_occurs_as_a_unit` across every needle in every wrapping --
    220 pairs. A disagreement means one of the two is wrong and neither can be
    trusted until it is resolved, so the failure message names the exact pair.
    """
    disagreements: list[tuple[str, str, bool, bool]] = []
    pairs = 0
    for needle in _DIFFERENTIAL_NEEDLES:
        for wrapper in _DIFFERENTIAL_WRAPPERS:
            haystack = wrapper.replace("{}", needle)
            pairs += 1
            shared = occurs_as_a_unit(needle, haystack)
            reference = _reference_occurs_as_a_unit(needle, haystack)
            if shared != reference:
                disagreements.append((needle, haystack, shared, reference))

    assert pairs == len(_DIFFERENTIAL_NEEDLES) * len(_DIFFERENTIAL_WRAPPERS)
    assert not disagreements, (
        f"{len(disagreements)} of {pairs} needle/haystack pairs disagree between the "
        f"shared occurrence rule and the independent reference: "
        f"{[(n, h, f'shared={s}', f'ref={r}') for n, h, s, r in disagreements[:5]]}"
    )

    # The corpus has to exercise both answers, or agreement is trivial.
    positives = sum(
        _reference_occurs_as_a_unit(n, w.replace("{}", n))
        for n in _DIFFERENTIAL_NEEDLES
        for w in _DIFFERENTIAL_WRAPPERS
    )
    assert 0 < positives < pairs, (
        f"the differential corpus is degenerate: {positives}/{pairs} positive"
    )


#: Every package module allowed to name a raw boundary assertion. Only the module that
#: *defines* the rule may write one; everywhere else it must arrive by import.
_BOUNDARY_RULE_OWNER = "textrules.py"

#: The two assertions, written as they appear in source. Matched as text on purpose:
#: the property being protected is "nobody re-derives this", and a re-derivation is a
#: textual act. An AST check would miss an f-string, which is exactly how the previous
#: three copies were spelled.
_RAW_GUARD_SNIPPETS = ("(?<!", "(?!")


def test_no_module_reassembles_the_boundary_guards_by_hand() -> None:
    """The rule must arrive by import everywhere, not be rebuilt from the alphabet.

    This is the check the previous arrangement could not express. When the consumers
    imported ``_ALNUM`` from the gate, the *alphabet* was shared but the *decision*
    was not: ``engine.py`` and ``restorer.py`` each wrote

        left = f"(?<!{_ALNUM})" if _ALNUM_RE.match(value[0]) else ""

    themselves. A rename raised ImportError as advertised, and an edit to the rule
    silently had to be made in three places -- which is the failure this whole
    apparatus exists to prevent, surviving inside the fix for it.

    So: no package module except the owner may contain a lookaround built next to an
    alphabet reference. ``textrules`` may, because it is the definition; the restorer
    composes ``LEFT_GUARD``/``RIGHT_GUARD`` around a possessive, which is its own
    concern and reads as a *use* of the shared decision rather than a restatement of
    it -- so the constants are permitted, the raw assertions are not.
    """
    package = Path(__file__).resolve().parents[2] / "secure_context_pipeline"
    offenders: list[tuple[str, int, str]] = []
    for path in sorted(package.rglob("*.py")):
        if path.name == _BOUNDARY_RULE_OWNER:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0]
            if "ALNUM" not in code:
                continue
            if any(snippet in code for snippet in _RAW_GUARD_SNIPPETS):
                offenders.append((str(path.relative_to(package)), number, line.strip()))

    assert not offenders, (
        "a boundary assertion is being rebuilt from the alphabet outside "
        f"{_BOUNDARY_RULE_OWNER}; import the rule instead: {offenders}"
    )


def _reference_contains(needle: str, haystack: str) -> bool:
    """A reference written to a **different specification**: *is the value in the text?*

    Not another derivation of the occurrence rule -- a different question, and the
    difference is the point. :func:`_reference_occurs_as_a_unit` restates the rule the
    implementation already encodes, so the two can only ever disagree about
    *transcription*. This asks the question a compliance reviewer asks, which is the
    one the headline claim is written in: **the payload either carries the value or it
    does not.**

    Every place the two answers differ is a place this module knows the value is there
    and has decided not to report it. That set is a design decision -- the
    ``Brown``/``Browning`` trade -- and a design decision is only on the record if it is
    written down: :data:`_DECLINED_BY_DESIGN` enumerates it pair by pair, and
    :func:`test_every_occurrence_this_module_declines_to_report_is_named_on_the_record`
    fails on any *unlisted* difference.

    That is the check the two same-spec derivations structurally cannot make. A spec
    error does not look like a disagreement between two copies of the spec; it looks
    like a value that is plainly present and quietly unreported. Against this
    reference, that is exactly what it looks like.
    """
    return bool(needle) and needle in haystack


#: The one reason this module ever declines to report a value it can see. Named, so
#: that a second reason cannot be added without somebody typing a second name.
_GLUED = (
    "adjacent to an alphanumeric on a side where the needle's own edge is alphanumeric "
    "-- the Brown/Browning trade, which does not apply to digit-carrying values "
    "(_identifier_needles) and is stated as a boundary in this module's docstring"
)

#: **Every** (needle, haystack) pair in the differential corpus where the value is
#: present and :func:`find_in_text` reports nothing. Enumerated rather than described,
#: because a description is a rule and a rule is what keeps turning out to be wrong.
#: An entry here is a suppression somebody signed for; a suppression that is *not* here
#: is a spec error, and that is what the test below is looking for.
_DECLINED_BY_DESIGN: dict[tuple[str, str], str] = {
    # Every pair here still holds after the separator-invariant limb was added, and
    # that is a deliberate property of the limb rather than a coincidence: it relaxes
    # the separator BETWEEN a value's components and keeps the word boundaries at its
    # outer edges, so glue -- which is an alphanumeric NEIGHBOUR, not a different
    # separator -- is still declined. An earlier draft dropped the outer boundaries
    # too; it removed the ten `John Smith`/`ada.brown@example.com` rows below and
    # simultaneously re-manufactured the `chronic low back pain` plural false
    # positive this module already names. See `_separator_needles`.
    ("John Smith", "xJohn Smith"): _GLUED,
    ("John Smith", "John Smithx"): _GLUED,
    ("John Smith", "xJohn Smithx"): _GLUED,
    ("John Smith", "1John Smith"): _GLUED,
    ("John Smith", "John Smith1"): _GLUED,
    ("ada.brown@example.com", "xada.brown@example.com"): _GLUED,
    ("ada.brown@example.com", "ada.brown@example.comx"): _GLUED,
    ("ada.brown@example.com", "xada.brown@example.comx"): _GLUED,
    ("ada.brown@example.com", "1ada.brown@example.com"): _GLUED,
    ("ada.brown@example.com", "ada.brown@example.com1"): _GLUED,
    ("Brown", "xBrown"): _GLUED,
    ("Brown", "Brownx"): _GLUED,
    ("Brown", "xBrownx"): _GLUED,
    ("Brown", "1Brown"): _GLUED,
    ("Brown", "Brown1"): _GLUED,
    ("$1,234.56", "$1,234.56x"): _GLUED,
    ("$1,234.56", "x$1,234.56x"): _GLUED,
    ("$1,234.56", "$1,234.561"): _GLUED,
    ("Case No. 3:24-cv-01188", "xCase No. 3:24-cv-01188"): _GLUED,
    ("Case No. 3:24-cv-01188", "Case No. 3:24-cv-01188x"): _GLUED,
    ("Case No. 3:24-cv-01188", "xCase No. 3:24-cv-01188x"): _GLUED,
    ("Case No. 3:24-cv-01188", "1Case No. 3:24-cv-01188"): _GLUED,
    ("Case No. 3:24-cv-01188", "Case No. 3:24-cv-011881"): _GLUED,
    ("HbA1c of 8.2", "xHbA1c of 8.2"): _GLUED,
    ("HbA1c of 8.2", "HbA1c of 8.2x"): _GLUED,
    ("HbA1c of 8.2", "xHbA1c of 8.2x"): _GLUED,
    ("HbA1c of 8.2", "1HbA1c of 8.2"): _GLUED,
    ("HbA1c of 8.2", "HbA1c of 8.21"): _GLUED,
    ("O'Brien", "xO'Brien"): _GLUED,
    ("O'Brien", "O'Brienx"): _GLUED,
    ("O'Brien", "xO'Brienx"): _GLUED,
    ("O'Brien", "1O'Brien"): _GLUED,
    ("O'Brien", "O'Brien1"): _GLUED,
}


def test_every_occurrence_this_module_declines_to_report_is_named_on_the_record() -> None:
    """The differential that can catch a **spec error**, which the other two cannot.

    :func:`test_the_occurrence_rule_has_no_fourth_copy` and its fuzz compare
    :func:`_occurs_as_a_unit` against :func:`_reference_occurs_as_a_unit`. Those two are
    written to the *same specification* -- compare their docstrings, the sentences are
    the same sentence -- so the pair can detect a mistyped implementation and can never
    detect a mistaken rule. Four for four, a mistaken rule is what this file has
    actually shipped, and the differential was green through every one of them.

    This one compares the module's real leak decision, :func:`find_in_text`, against
    :func:`_reference_contains`: *is the value in the text, yes or no*. That is the
    question the headline claim is written in, and it is not derived from the
    implementation at all. Wherever the two differ, this module can see a value and is
    choosing not to report it, and every such choice has to be in
    :data:`_DECLINED_BY_DESIGN` **by name**.

    Both directions fail loudly, and the second one matters as much as the first:

    * an **unlisted** suppression is a value the module quietly stopped reporting. That
      is what a spec error looks like from the outside, and it is the only view from
      which it looks like anything at all;
    * a **listed** pair that is now reported means the ledger has rotted into fiction.
      Left alone it would grow into a list of things that used to be true, which is
      worse than no list, because the next reader trusts it.

    A third assertion keeps the corpus from going degenerate: containment and the
    module's scan must each answer both ways over it, or agreement is vacuous.
    """
    unlisted: list[tuple[str, str]] = []
    stale: list[tuple[str, str]] = []
    present = 0
    reported = 0

    for needle in _DIFFERENTIAL_NEEDLES:
        for wrapper in _DIFFERENTIAL_WRAPPERS:
            haystack = wrapper.replace("{}", needle)
            in_text = _reference_contains(needle, haystack)
            found = bool(find_in_text(frozenset({needle}), haystack))
            present += in_text
            reported += found
            if in_text and not found and (needle, haystack) not in _DECLINED_BY_DESIGN:
                unlisted.append((needle, haystack))
            if found and (needle, haystack) in _DECLINED_BY_DESIGN:
                stale.append((needle, haystack))

    assert not unlisted, (
        f"{len(unlisted)} occurrence(s) are present in the text and reported by nothing "
        f"in this module, and are not on the record as a deliberate suppression: "
        f"{[(mask(n), mask(h)) for n, h in unlisted[:5]]}. Either the scan lost a limb "
        "-- which is a leak in the audit and log channels, where it is the only opinion "
        "-- or the suppression is intended, in which case add it to "
        "_DECLINED_BY_DESIGN with a reason and change the module docstring's stated "
        "boundaries to match"
    )
    assert not stale, (
        f"{len(stale)} pair(s) in _DECLINED_BY_DESIGN are now reported after all: "
        f"{[(mask(n), mask(h)) for n, h in stale[:5]]}. The scan got stricter -- good -- "
        "but delete these entries, or the ledger becomes a list of limitations this "
        "module no longer has and the next reader believes it"
    )

    # ...and the corpus is not degenerate in either direction.
    pairs = len(_DIFFERENTIAL_NEEDLES) * len(_DIFFERENTIAL_WRAPPERS)
    assert 0 < reported < present < pairs, (
        f"the containment differential is degenerate: {present}/{pairs} pairs carry the "
        f"value and {reported} are reported, so it is not exercising both answers"
    )
    assert _DECLINED_BY_DESIGN, "an empty ledger cannot fail; the corpus must reach the trade"


#: A small alphabet with one character from each class the occurrence rule cares
#: about: letters, a digit, an underscore (a regex ``\w`` that is *not* alphanumeric
#: -- the exact character the original bug turned on), a space, and punctuation on
#: both sides of a needle. Deliberately tiny so generated needles actually collide
#: with generated haystacks; a wide alphabet makes every draw a trivial non-match.
_FUZZ_ALPHABET = "ab1_ .[]$-"


@given(
    needle=st.text(alphabet=_FUZZ_ALPHABET, min_size=1, max_size=6),
    haystack=st.text(alphabet=_FUZZ_ALPHABET, max_size=24),
)
@settings(max_examples=2_000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_the_shared_occurrence_rule_agrees_with_the_reference_on_generated_input(
    needle: str, haystack: str
) -> None:
    """The differential test, generalised past the 220 pairs somebody thought of.

    :func:`test_the_occurrence_rule_has_no_fourth_copy` compares the shared rule
    against :func:`_reference_occurs_as_a_unit` over a hand-written corpus. Hand-
    written corpora encode the cases their author already knew about, and every
    version of this bug so far has been a case nobody thought of -- ``_`` counting as
    a word character, a needle whose first character is punctuation, an invisible
    codepoint, a value glued between two SQLite column values. Four for four, the
    corpus was extended *after* the miss.

    So the same comparison is driven with generated input over an alphabet built from
    the character classes the rule turns on. A disagreement means one of the two is
    wrong and neither can be trusted until it is resolved; hypothesis shrinks it to a
    minimal pair, which is the part a hand-written corpus cannot do at all.

    This is the one place in the suite where the *shared* rule is checked rather than
    merely shared, so it is worth the couple of seconds it costs.
    """
    assert occurs_as_a_unit(needle, haystack) == _reference_occurs_as_a_unit(needle, haystack)


#: Membership tests this module must never contain again. Each is a bare ``in``
#: against a string the pipeline produced, and every one of them was a real defect:
#: two hid leaks by being stricter than the code, two invented leaks by being
#: looser. They are matched as source text because the property being protected is
#: "nobody writes a fifth convention", which is a fact about the file rather than
#: about any one run.
_FORBIDDEN_MEMBERSHIP_SNIPPETS = (
    "in result.restored_text",
    "in result.raw_llm_response",
    "in sent_payload",
    "in decoded",
    '.encode("utf-8") in haystack',
)


def test_no_leak_comparison_in_this_module_bypasses_the_shared_rule() -> None:
    """No bare ``in`` decides whether a value **leaked**, anywhere in this file.

    Four separate call sites here have now been wrong in exactly this way, in both
    directions, and each one sat directly underneath a headline assertion:

    * the payload scan (stricter than the gate) -- missed markdown-wrapped leaks;
    * ``find_in_bytes`` (looser) -- a six-digit original inside a hex ``run_id``
      reads as a leak in the audit database;
    * the round-trip check (looser) -- an original inside a longer word reads as
      restored when it was not;
    * the surviving-surrogate check (looser) -- a short Faker draw inside an
      ordinary word reads as a surrogate that escaped restoration.

    A behavioural test catches the *instance* it was written for. This catches the
    **class**, which is the only thing that has actually worked on this bug: every
    *leak* decision in this module has to route through :data:`occurs_as_a_unit`,
    so the next person to add a scan cannot quietly invent a fifth convention that
    agrees with nothing.

    **The scope of this rule is leak detection, and that is a narrowing rather than
    a loophole.** It used to be stated as "no comparison anywhere in this module",
    which sounded stronger and was actively harmful in one place: the round-trip
    *expectation* must NOT share a predicate with the restorer, or it agrees with
    the code it is checking and shrinks silently whenever that code is wrong. The
    **It also used to scan only the first two-thirds of the file**, which is worth
    naming because it made the rule vacuous exactly where it mattered. The scanned
    region was ``source.split("_FORBIDDEN_MEMBERSHIP_SNIPPETS = (")[0]`` -- a way of
    stopping the tuple below from matching itself -- and the 100-run function is
    defined *after* that tuple. So three of the four historical bugs sat in a region
    this rule never looked at. Measured, not spotted by reading: putting
    ``[o for o in originals if o in sent_payload]`` back into the payload scan left
    this test **green**. The exclusion is now computed from the parsed module, so the
    only regions skipped are the tuple itself and this function's own body.

    The two rules pull opposite ways, and pretending they were one rule is what kept
    the expectation tied to ``TOKEN_RE``. The other direction is enforced by
    :func:`test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots`,
    which fails if the completeness path starts using the shared rule again.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = ast.parse(source)

    # Everything except the snippet tuple and this function, which quote the
    # forbidden text by construction. Computed from the parse, so the covered region
    # cannot silently shrink again.
    skip: set[int] = set()
    for node in ast.walk(tree):
        named_tuple = isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "_FORBIDDEN_MEMBERSHIP_SNIPPETS"
            for t in node.targets
        )
        this_test = (
            isinstance(node, ast.FunctionDef)
            and node.name == "test_no_leak_comparison_in_this_module_bypasses_the_shared_rule"
        )
        if (named_tuple or this_test) and node.end_lineno is not None:
            skip.update(range(node.lineno, node.end_lineno + 1))
    body = "\n".join(line for n, line in enumerate(lines, start=1) if n not in skip)

    assert "async def test_no_original_ever_leaves_the_process" in body, (
        "the scanned region no longer includes the 100-run function, which is where "
        "three of the four historical bugs actually lived"
    )

    offenders = [snippet for snippet in _FORBIDDEN_MEMBERSHIP_SNIPPETS if snippet in body]
    assert not offenders, (
        "these membership tests bypass the shared occurrence rule and will disagree "
        f"with the gate, the engine and the restorer: {offenders}. Use "
        "occurs_as_a_unit(needle, haystack) instead."
    )

    # The rule really is the one thing in use: every leak-scan helper calls it.
    for helper in ("def find_in_text", "def find_in_bytes"):
        start = body.index(helper)
        end = body.index("\ndef ", start + 1)
        assert "occurs_as_a_unit(" in body[start:end], (
            f"{helper} no longer routes through the shared occurrence rule"
        )

    # Both limbs of the audit assertion must still be applied by the run. Loosening
    # the byte limb so it could carry the label-column case alone was tried and
    # reverted (see find_in_bytes); deleting either limb on the assumption that the
    # other one covers it is the same mistake in the other direction.
    # Anchored on the DEFINITION, with a line-anchored regex rather than `.index`.
    #
    # `source.index("async def test_no_original_ever_leaves_the_process")` resolved
    # to line 2481 -- a string literal inside this function's own earlier assertion
    # -- and not to the definition at 2604. So `source[run_start:]` began *above*
    # the tuple below, and each needle matched its own text in that tuple. The
    # guard could not fail.
    #
    # It was also not checking what it said: `find_in_text(originals, audit_json)`
    # does not appear in the run body at all -- the audit limb calls
    # `find_in_digit_heavy_text`, which is the digit-floored variant. A guard
    # anchored correctly but still spelling that needle would go red immediately,
    # which is how the staleness surfaced.
    match = re.search(r"^async def test_no_original_ever_leaves_the_process", source, re.M)
    assert match is not None, "the 100-run body has been renamed; this guard is stale"
    run_body = source[match.start() :]
    following = re.search(r"\n(?:async )?def ", run_body[1:])
    if following is not None:
        run_body = run_body[: following.start()]
    for limb in (
        "find_in_digit_heavy_text(originals, audit_json)",
        "find_in_bytes(originals, harness.audit_bytes())",
    ):
        assert limb in run_body, (
            f"the audit assertion no longer applies {limb} -- the two limbs see "
            "different things and neither is redundant"
        )

    # The outbound payload and the process log, pinned the same way -- and it is an
    # asymmetry worth naming that they were not, because assertion 1 is the most
    # important assertion in this repository. It is the only check anywhere that reads
    # the bytes the provider was actually handed, and assertion 2b is the only opinion
    # on the process log; the gate never sees either. Both were structurally
    # unprotected while the audit limbs were named, so an edit that dropped the payload
    # scan would have left 100 green runs asserting nothing about the wire, and the
    # summary would still have printed "100/100 runs clean, 0 leaks".
    #
    # The scan AND its assertion, not just the scan: computing `payload_leaks` and not
    # asserting on it is the cheaper mistake of the two -- it leaves the tally
    # incrementing and every line looking present -- and naming only the call cannot
    # see it. That is what these four needles hold that the two above do not.
    #
    # The two scan needles now spell the `issued=` argument as well, which is a
    # STRENGTHENING of this guard rather than an accommodation of a signature change.
    # `issued` is the only thing that narrows either scan, and it is derived per run:
    # a body that dropped the argument would silently go back to reporting the
    # pipeline's own token ids as originals on the wire, and a body that passed a
    # constant or an empty set there would look identical from here without it. So the
    # argument is named, and the local it must come from is named with it.
    for limb in (
        "issued_surrogates = frozenset(harness.vault.surrogates_for_session(session_id))",
        "payload_leaks = find_in_text(originals, sent_payload, issued=issued_surrogates)",
        "assert not payload_leaks",
        "log_leaks = find_in_digit_heavy_text(originals, logged, issued=issued_surrogates)",
        "assert not log_leaks",
    ):
        assert limb in run_body, (
            f"the 100-run body no longer contains `{limb}` -- nothing else in this "
            "repository scans the bytes the provider received or the lines the package "
            "logged, so removing it makes the headline result vacuous"
        )


#: Production predicates the round-trip *expectation* must never be built from.
#: Each is a predicate the restorer itself uses, so an expectation phrased in terms
#: of one cannot disagree with the restorer -- which is the only thing it is for.
_RESTORER_PREDICATES = ("extract_token_ids", "STRICT_TOKEN_RE", "TOKEN_RE", "occurs_as_a_unit")


def test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots() -> None:
    """Completeness is checked against an *independent* reading of the model's words.

    Two halves, and the behavioural one is the point.

    **Structural.** ``expected_round_trip`` and ``issued_token_id`` must not *use*
    any predicate the restorer uses. This is the direction the sibling rule above
    deliberately does not cover. Checked over the parsed AST rather than the source
    text, so the names can still be discussed in a docstring -- which they have to
    be, since the reason they are forbidden is the whole content of this rule.

    **Behavioural.** A token shape ``TOKEN_RE`` cannot match -- here the bare 8-hex
    ID, which a model writes constantly when it paraphrases rather than quotes --
    must still land in ``expected``. Under the old derivation it did not: the
    expectation was built with ``extract_token_ids``, so a token the production
    grammar could not see was dropped from the expectation, left alone by the
    restorer, and missed by assertion 4's residual scan, all three agreeing. The
    only trace was a smaller ``round_trip_checked`` in the summary line, and a
    denominator quietly shrinking is not a signal anybody acts on.

    Asserted with the production regex on the same input, so the premise -- that
    this really is a shape ``TOKEN_RE`` misses -- is measured rather than claimed.
    """
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    checked = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name not in ("expected_round_trip", "issued_token_id", "_mentions"):
            continue
        checked += 1
        used = {inner.id for inner in ast.walk(node) if isinstance(inner, ast.Name)}
        used |= {inner.attr for inner in ast.walk(node) if isinstance(inner, ast.Attribute)}
        borrowed = sorted(used & set(_RESTORER_PREDICATES))
        assert not borrowed, (
            f"{node.name} is built from {borrowed}, which the restorer also uses -- so "
            "the expectation cannot disagree with the restorer and a token the "
            "production grammar misses will vanish from both at once"
        )
    assert checked == 3, (
        f"expected to check 3 completeness helpers, found {checked} -- one was "
        "renamed or removed without this rule being reconsidered"
    )

    surrogate = "[PHI_NAME_1a2b3c4d]"
    original = "Marguerite Vandenberg"
    mapping = {surrogate: original}

    quoted = f"The record names {surrogate} as the patient."
    assert expected_round_trip(quoted, mapping) == {original}

    # The shape the production grammar cannot see, which a model does emit.
    paraphrased = "The record names the patient (internal ref 1a2b3c4d) throughout."
    assert not extract_token_ids(paraphrased), (
        "premise: TOKEN_RE really is blind to a bare ID -- if it now matches, this "
        "test needs a shape that is still outside the grammar"
    )
    assert expected_round_trip(paraphrased, mapping) == {original}, (
        "the model referred to a token the restorer's grammar cannot see; if the "
        "restorer leaves it, the answer carries a dangling hex ID and this harness "
        "must report it rather than quietly expect less"
    )

    # Upper-cased, as the mock's own upper_hash mutation renders it.
    assert expected_round_trip("ref 1A2B3C4D", mapping) == {original}

    # And it does not invent expectations out of nothing.
    assert expected_round_trip("The record names nobody in particular.", mapping) == set()
    assert expected_round_trip("ref deadbeef", mapping) == set()

    # A pseudonym carries no ID, so it is matched as a literal -- and still
    # boundary-anchored, or a short Faker draw inside an ordinary word becomes an
    # expectation the restorer was never asked to satisfy.
    fake_map = {"Brown": "Vandenberg"}
    assert expected_round_trip("Counsel Brown filed the motion.", fake_map) == {"Vandenberg"}
    assert expected_round_trip("Counsel Browning filed the motion.", fake_map) == set()


# ---------------------------------------------------------------------------
# 1. The 100 runs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio(loop_scope="module")
@pytest.mark.parametrize("index", range(RUNS), ids=run_id_for)
async def test_no_original_ever_leaves_the_process(
    harness: Harness,
    ledger: Ledger,
    caplog: pytest.LogCaptureFixture,
    index: int,
) -> None:
    seed, kind, strategy = plan_run(index)
    # Everything below runs under ``ledger.watching``. A run that dies before
    # ``ledger.record()`` used to leave the summary with a bare ``99 != 100`` and no
    # way to say which run or why; see :class:`RunFailure`. The block re-raises
    # everything it sees, so no failure here becomes a pass.
    with ledger.watching(index):
        caplog.set_level(logging.DEBUG)

        document = generator.generate(seed, kind)
        doc_id = await harness.store.put(
            USER_ID, f"{kind}-{seed}.txt", document.encode("utf-8"), DOC_CATEGORY[kind]
        )
        session_id, _expires_at = await harness.sessions.create("test-user")
        calls_before = harness.provider.calls
        # A per-run prompt carrying a real original from THIS document -- see prompt_for.
        # The prompt is a third of the outbound payload and the only third a user writes,
        # and it was a PII-free module constant on all 100 runs until this.
        prompt = prompt_for(index)
        result = await harness.orchestrator.run(session_id, USER_ID, doc_id, prompt, strategy)

        # The payload this test scans has to be the payload that was actually sent.
        # `result.obfuscated_payload` is the orchestrator's own record of it; the
        # provider wrapper holds the two strings the provider was really handed. If
        # those ever diverge the whole file measures a string nobody transmitted, so
        # the identity is asserted rather than assumed, and everything below scans
        # the boundary-captured copy.
        assert harness.provider.calls == calls_before + 1, (
            f"run {index}: expected exactly one provider call, saw "
            f"{harness.provider.calls - calls_before}"
        )
        sent_payload = harness.provider.last_payload
        assert sent_payload is not None
        assert sent_payload == result.obfuscated_payload, (
            f"run {index}: the payload the gate scanned is not the payload the provider "
            f"received ({len(result.obfuscated_payload)} chars scanned, {len(sent_payload)} sent)"
        )

        originals = harness.vault.originals_for_session(session_id)
        assert originals, (
            f"run {index} vaulted nothing, so every leak scan below would be vacuous "
            f"(kind={kind}, seed={seed})"
        )

        # The prompt's own value has to be one of the values the scans below hunt for, or
        # the prompt half of assertion 1 is decorative. Asserted rather than assumed: the
        # value is drawn from the fixture's planted literals, and if the vault ever stops
        # holding exactly that string -- a fixture edit, a span boundary moving -- the
        # prompt would go back to being unscanned bytes and nothing else would say so.
        prompt_value = drawn_original(seed, kind, PROMPT_ENTITY_TYPES[index % 3])
        assert prompt_value in originals, (
            f"run {index}: the value this run put in the user prompt is not in the session "
            f"vault, so the payload scan is not looking for it and the prompt half of this "
            f"test measures nothing (kind={kind}, seed={seed}, {mask(prompt_value)})"
        )

        mapping = await surrogate_map(harness, session_id, result)

        # The exact strings this run spliced in, read out of the VAULT's own issued
        # map. Not out of the gate, and not out of ``mapping``: the gate is the code
        # these scans exist to disagree with, and ``mapping`` is built from
        # ``result.detections``, which is ``obf.spans`` -- the DOCUMENT half only. A
        # surrogate the prompt contributed and the document did not would be missing
        # from it, and an incomplete exclusion set is a flake that comes back on one
        # channel out of three. ``surrogates_for_session`` is the session cache the
        # vault fills on every ``put``, so it has both halves, and the session is fresh
        # per run.
        issued_surrogates = frozenset(harness.vault.surrogates_for_session(session_id))
        assert mapping.keys() <= issued_surrogates, (
            f"run {index}: {len(mapping.keys() - issued_surrogates)} surrogate(s) this run "
            "spliced into the payload are absent from the vault's issued map, so the own-id "
            "exclusion below is derived from an incomplete set and would blank the wrong spans"
        )

        def scanned(text: str) -> str:
            """A haystack as the scans below actually saw it, for the failure messages.

            ``describe_hits`` names the limb that fired by re-running the limbs, so
            handing it the *unmasked* string can name a limb that did not -- the exact
            misdirection a reviewer cannot afford at the moment assertion 1 goes red.
            Called only from inside an ``assert`` message, which Python evaluates only
            on failure, so the clean path pays nothing for it.
            """
            return _harness_mask_own_ids(text, issued_surrogates)

        # --- 0. no surrogate stands for itself ---------------------------------
        # The pseudonymization collision guard rejects a fake that shares a word with
        # any original in the document. The degenerate failure of that guard is a
        # "surrogate" equal to the value it replaces -- the payload would then carry
        # the real value under cover of being obfuscated, and every later check in
        # this test would happily pass. Compared on normalised forms, so a
        # case-mangled or re-spaced identity is caught too.
        identity = sorted(
            s for s, original in mapping.items() if normalize(s) == normalize(original)
        )
        assert not identity, (
            f"run {index}: {len(identity)} surrogate(s) are identical to the value they "
            f"replace, so the value was never obfuscated at all: {[mask(v) for v in identity]}"
        )

        # --- 1. the outbound payload -------------------------------------------
        # Scanned on the bytes captured at the PROVIDER boundary (asserted identical
        # to the string the gate saw, above), with exactly ONE exclusion: the eight-hex
        # ids of the tokens this run issued, blanked by exact string occurrence
        # (``_harness_mask_own_ids``). Those ids are HMAC digests the pipeline drew
        # itself, and the unbounded limbs read them as payload digits -- reproduced,
        # not theorised: ``find_in_text({'8390244'}, 'Account
        # [FIN_ACCOUNT_NUMBER_8390244f] closed.')`` returned ``['8390244']``.
        #
        # NOTHING ELSE the pipeline wrote is excused, and the pseudonyms are the
        # reason: a fake that reproduces a real value verbatim puts that value on the
        # wire no matter which span it sits in, so ``_harness_own_id_mask`` returns
        # ``None`` for every surrogate that is not one of our tokens and this scan
        # reads it exactly as it always has. The literals, the ``|hint`` tail, our
        # brackets and every character beside, glued to or straddling a token are all
        # still read.
        payload_leaks = find_in_text(originals, sent_payload, issued=issued_surrogates)
        if payload_leaks:
            ledger.leaks += len(payload_leaks)
        assert not payload_leaks, (
            f"run {index} ({kind}/{strategy}, seed {seed}): {len(payload_leaks)} original(s) "
            "present in the outbound payload: "
            # Described against the string that was SCANNED, not the raw payload: the
            # limb names come from re-running the limbs, and re-running them over an
            # unmasked payload can name a limb that did not fire.
            f"{describe_hits(payload_leaks, scanned(sent_payload))}"
        )

        # --- 2a. the audit trail, through the query API and on disk -------------
        events = await harness.audit.query(session_id=session_id, limit=10_000)
        assert events, f"run {index} emitted no audit events"
        # ``ensure_ascii=False``: the default escapes every non-ASCII character to
        # ``\uXXXX``, which would hide an accented original from the scan below in a
        # haystack that provably contains it. See ``_unescape_json_unicode``.
        audit_json = json.dumps(
            [event.model_dump() for event in events], default=str, ensure_ascii=False
        )
        audit_leaks = find_in_digit_heavy_text(originals, audit_json)
        audit_leaks += [
            value
            for value in find_in_bytes(originals, harness.audit_bytes())
            if value not in audit_leaks
        ]
        if audit_leaks:
            ledger.leaks += len(audit_leaks)
        assert not audit_leaks, (
            f"run {index}: {len(audit_leaks)} original(s) reached the audit log: "
            f"{describe_hits(audit_leaks, audit_json)} (a value listed as 'byte-limb-only' "
            "was found in the raw DB file and not in the query view)"
        )

        # --- 2b. every log line the package emitted, at DEBUG -------------------
        # ``log_haystack`` rather than ``caplog.text``: the default formatter renders
        # no ``extra=`` fields, and that is where this package puts every variable it
        # logs. Scanning ``caplog.text`` alone checked the constant half of each line.
        #
        # Carries the same own-id exclusion assertion 1 does, and for a measured
        # reason: ``aiosqlite`` logs every statement it executes at DEBUG *with its
        # bound parameters*, and the vault binds the surrogate -- so every token this
        # run emitted is in this haystack verbatim (31/31, 4/4, 37/37, 14/14, 36/36,
        # 14/14 over six runs). The audit limbs above deliberately do NOT get it: the
        # same count over the same six runs is 0 in the query view and 0 in the DB
        # bytes, so there the exclusion would be an identity function claiming to be a
        # safety argument.
        logged = log_haystack(caplog)
        log_leaks = find_in_digit_heavy_text(originals, logged, issued=issued_surrogates)
        if log_leaks:
            ledger.leaks += len(log_leaks)
        assert not log_leaks, (
            f"run {index}: {len(log_leaks)} original(s) reached the log output: "
            f"{describe_hits(log_leaks, scanned(logged))}"
        )

        # --- 3. round-trip completeness ----------------------------------------
        # Both predicates here are the INDEPENDENT ones -- see expected_round_trip.
        # Leak detection above must never be laxer than the gate; completeness must
        # never share a predicate with the restorer. Those are different rules, and
        # running both through one shared helper is what let a token TOKEN_RE could
        # not see disappear from the expectation, the answer and the residual scan at
        # the same time.
        expected = expected_round_trip(result.raw_llm_response, mapping)
        assert expected, (
            f"run {index}: the model referenced no surrogate at all, so the round-trip "
            f"assertion would be vacuous (kind={kind}, seed={seed})"
        )
        not_restored = sorted(
            o for o in expected if not _reference_occurs_as_a_unit(o, result.restored_text)
        )
        assert not not_restored, (
            f"run {index}: {len(not_restored)} of {len(expected)} referenced surrogate(s) were not "
            f"restored to their originals: {[mask(v) for v in not_restored]}"
        )

        # --- 4. nothing surrogate-shaped survives ------------------------------
        residual = [match.group(0) for match in TOKEN_RE.finditer(result.restored_text)]
        assert not residual, f"run {index}: residual token pattern(s) in the answer: {residual[:5]}"
        # Boundary-anchored, because the restorer replaces surrogates on word
        # boundaries and a checker that disagrees with the code it checks is wrong in
        # whichever direction it disagrees. A bare ``in`` here reported a short Faker
        # draw (``"Rich"``) as a surviving surrogate because it sat inside an ordinary
        # word -- and since pseudonyms derive from a random per-session key, that red
        # appeared and vanished between runs. This is Deviation 13's asymmetry pointing
        # the other way: there the checker was stricter than the code and hid leaks;
        # here it was looser and invented one.
        surviving = sorted(s for s in mapping if occurs_as_a_unit(s, result.restored_text))
        assert not surviving, (
            f"run {index}: {len(surviving)} issued surrogate(s) survived into the answer: "
            f"{surviving[:5]}"
        )

        ledger.record(index=index, originals=len(originals), restored=len(expected))


# ---------------------------------------------------------------------------
# 2. Adversarial: fail-closed independent of detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio(loop_scope="module")
async def test_planted_value_is_invisible_to_the_detector(harness: Harness) -> None:
    """The premise of the adversarial case, asserted rather than assumed.

    If any recogniser fired on the planted value the next test would prove
    nothing -- the engine would obfuscate it and the gate would never see it.
    """
    document = "Internal Reference Sheet\n" + PLANT_TEMPLATE.format(UNKNOWN_SHAPE_VALUE)
    start = document.index(UNKNOWN_SHAPE_VALUE)
    end = start + len(UNKNOWN_SHAPE_VALUE)
    for doc_category in ("medical", "legal", "financial", "general"):
        hits = await harness.detector.detect(document, doc_category)
        overlapping = [h.entity_type for h in hits if h.start < end and h.end > start]
        assert not overlapping, (
            f"{UNKNOWN_SHAPE_VALUE!r} is recognised as {overlapping} in a {doc_category} "
            "document; pick a shape the registry genuinely does not know"
        )


@pytest.mark.asyncio(loop_scope="module")
async def test_unknown_shape_value_blocks_egress_and_the_call_never_fires(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail-closed, proven without the detector.

    A value of an unknown shape is planted in the document *and* injected into the
    vault's originals set. The detector is blind to it (asserted above), so the
    engine leaves it in place and it rides through into the payload. Pass 1 of the
    gate -- the original-value scan, which never consults the detector -- has to
    catch it. Nothing here depends on detection recall.
    """
    document = generator.generate(SEED_BASE + RUNS, "financial") + PLANT_TEMPLATE.format(
        UNKNOWN_SHAPE_VALUE
    )
    doc_id = await harness.store.put(USER_ID, "planted.txt", document.encode("utf-8"), "financial")
    session_id, _expires_at = await harness.sessions.create("test-user")

    real_originals = harness.vault.originals_for_session

    def blinded(target_session: str) -> frozenset[str]:
        known = real_originals(target_session)
        if target_session == session_id:
            return known | {UNKNOWN_SHAPE_VALUE}
        return known

    monkeypatch.setattr(harness.vault, "originals_for_session", blinded)

    calls_before = harness.provider.calls
    with pytest.raises(EgressBlockedError) as excinfo:
        await harness.orchestrator.run(session_id, USER_ID, doc_id, PROMPT, "tokenization")

    error = excinfo.value
    assert error.detail["reason"] == "vault_original"
    assert isinstance(error.detail["hit_count"], int) and error.detail["hit_count"] >= 1
    # The error itself must not carry the value it blocked on (section 16).
    assert UNKNOWN_SHAPE_VALUE not in str(error)
    assert UNKNOWN_SHAPE_VALUE not in repr(error)

    # The whole point: the provider was never reached.
    assert harness.provider.calls == calls_before, (
        "the provider was called on a blocked run -- the gate is not fail-closed"
    )

    blocks = await harness.audit.query(session_id=session_id, event_type=EGRESS_BLOCK)
    assert len(blocks) == 1, f"expected exactly one EGRESS_BLOCK event, got {len(blocks)}"
    assert blocks[0].detail["reason"] == "vault_original"
    assert UNKNOWN_SHAPE_VALUE not in json.dumps(blocks[0].model_dump(), default=str)


#: Every shape ``surrogates.TOKEN_RE`` accepts, with the mutation class the mock
#: uses to produce it -- or ``None`` where the mock never produces it at all.
#: ``MockProvider`` defines six mutation classes and both the round-trip test and
#: this harness were written against exactly those six, so the ``None`` rows are the
#: tolerance nothing had ever exercised: the adversary was written by the defender.
_TOKEN_SHAPES: tuple[tuple[str, str, str | None], ...] = (
    ("canonical", "[PHI_NAME_1a2b3c4d]", "verbatim"),
    ("upper_hash", "[PHI_NAME_1A2B3C4D]", "upper_hash"),
    ("bracket_dropped", "PHI_NAME_1a2b3c4d", "bracket_dropped"),
    ("brace_brackets", "{PHI_NAME_1a2b3c4d}", None),
    ("paren_brackets", "(PHI_NAME_1a2b3c4d)", None),
    ("hyphen_separators", "[PHI-NAME-1a2b3c4d]", None),
    ("hyphen_no_brackets", "PHI-NAME-1a2b3c4d", None),
    ("mismatched_brackets", "[PHI_NAME_1a2b3c4d}", None),
    ("interior_whitespace", "[ PHI_NAME_1a2b3c4d ]", None),
    ("mixed_case_hash", "[PHI_NAME_1A2b3C4d]", None),
)


@pytest.mark.asyncio(loop_scope="module")
async def test_every_token_shape_the_grammar_accepts_restores_not_just_the_six_the_mock_emits(
    harness: Harness,
) -> None:
    """The surplus tolerance, exercised -- because the adversary was written by us.

    ``MockProvider`` defines exactly six mutation classes, and the round-trip
    assertion in this module was written against exactly those six. ``TOKEN_RE``
    tolerates considerably more: ``{}`` and ``()`` brackets, ``-`` separators, a
    mismatched bracket pair, up to four whitespace characters inside the token, and
    any casing of the hash. Every one of those is something a real model does and the
    mock never does, so the 100 runs say nothing about them -- the suite was grading
    the pipeline against a mangler the pipeline's own author wrote.

    That gap is not cosmetic. A shape the grammar advertises but the restorer fumbles
    is a token that reaches the **user** un-restored, and the shape most likely to be
    fumbled is exactly the one no test ever sent. So each shape goes through the real
    :class:`Restorer` against a real vault record, with the mock removed from the
    loop entirely.

    Three things are asserted per shape, because "the original came back" is not the
    whole contract: the original is present, the count says the restorer believes it
    did the work, and nothing token-shaped survives -- a half-restored answer carrying
    both is worse than either.
    """
    session_id, _expires_at = await harness.sessions.create("test-user")
    original = "Marguerite Vandenberg"
    surrogate = "[PHI_NAME_1a2b3c4d]"
    await harness.vault.put(
        session_id,
        TokenRecord(
            session_id=session_id,
            token_id="1a2b3c4d",
            entity_type="PHI_NAME",
            category="PHI",
            surrogate=surrogate,
            created_at=1.0,
        ),
        original,
    )
    restorer = Restorer(vault=harness.vault, settings=harness.settings, audit=harness.audit)

    unexercised = [name for name, _shape, mutation in _TOKEN_SHAPES if mutation is None]
    assert len(unexercised) >= 6, (
        "this table no longer describes any shape the mock cannot produce, so it has "
        "stopped testing the surplus tolerance it exists for"
    )

    for name, shape, _mutation in _TOKEN_SHAPES:
        assert TOKEN_RE.search(shape), (
            f"premise: {name} is supposed to be inside the grammar -- if TOKEN_RE no "
            "longer accepts it, the grammar narrowed and this table must say so"
        )
        text = f"The record names {shape} as the patient of record."
        result = await restorer.restore(
            session_id,
            text,
            strategy="tokenization",
            surrogates={surrogate: original},
            issued={"1a2b3c4d"},
        )
        assert original in result.text, (
            f"{name} ({shape!r}) is accepted by TOKEN_RE and was NOT restored, so a "
            "model emitting it hands the user a raw token"
        )
        assert result.restored_count == 1, (
            f"{name}: restored_count is {result.restored_count}, so the answer is right "
            "by accident rather than by the restorer having done the substitution"
        )
        assert not TOKEN_RE.search(result.text), (
            f"{name}: something token-shaped survived into the answer alongside the "
            f"restored original: {result.text!r}"
        )


@pytest.mark.asyncio(loop_scope="module")
async def test_the_audit_scan_catches_a_label_column_original_and_says_which_limb_did(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """The audit log CAN physically hold an original. This is what stops it.

    Worth stating in a test because the claim is easy to overstate in a live review
    and the overstatement is checkable in one line. The size ceilings -- 128
    characters on the label columns, 64 on a ``detail`` value -- make the log
    incapable of holding *content*, which is the bulk-exfiltration shape. They do not
    and cannot make it incapable of holding a name or an MRN: ``"Marguerite
    Vandenberg"`` is 21 characters and ``"MRN 4823910"`` is 11, so both pass the
    write-boundary guard untouched and land verbatim in the raw SQLite bytes. That is
    asserted here rather than argued, on a real ``AuditLogger`` and a real file.

    What actually holds is narrower and is *measured*: no call site in the package
    passes a value to ``emit`` -- every field is a token ID, a type name, a count, a
    latency or a digest -- and assertion 2 scans both the query view of the rows and
    the raw audit file, against every vaulted original, on all 100 runs. The half
    nothing pinned was that the scan would **catch** such a write if a call site ever
    started making one, which is the property the other 100 tests rely on and which
    would fail silently if either limb were narrowed.

    So the value is planted through the real writer and then hunted exactly the way
    the run hunts it -- and the result is attributed to a limb rather than to "the
    scan", because the two limbs do not see the same thing. The **query** limb catches
    a label-column original (JSON quoting supplies the boundaries the anchored rule
    needs); the **byte** limb does not, because SQLite stores column values with no
    delimiter between them. Left unattributed, this test would read as evidence for a
    property the byte limb does not have, and deleting the query limb would then look
    safe. See
    :func:`test_the_byte_limb_and_the_query_limb_of_the_audit_scan_see_different_things`.

    The reverse is checked too: a log full of ordinary audit traffic must not report
    a leak, or the instrument proves nothing by firing.
    """
    root = tmp_path_factory.mktemp("audit-value-probe")
    db = root / "audit.db"
    name = "Marguerite Vandenberg"
    mrn = "MRN 4823910"

    log = await AuditLogger.open(db)
    try:
        # Ordinary traffic first: the scan must be quiet on this.
        for i in range(5):
            await log.emit(
                AuditEvent(
                    ts=1_700_000_000.0 + i,
                    session_id="sess-probe",
                    run_id="run-probe",
                    event_type=EGRESS_BLOCK,
                    entity_type="PHI_NAME",
                    token_id=f"{i:08x}",
                    detail={"count": i, "elapsed_ms": 1.5},
                )
            )
        clean = frozenset({name, mrn})
        assert not find_in_bytes(clean, _audit_file_bytes(db)), (
            "the byte scan fires on a log carrying nothing but token IDs and counts"
        )

        # Now the write the ceilings do not stop. This is the overclaim, disproven.
        assert len(name) <= MAX_AUDIT_LABEL_LEN and len(mrn) <= MAX_DETAIL_VALUE_LEN
        await log.emit(
            AuditEvent(
                ts=1_700_000_100.0,
                session_id="sess-probe",
                run_id="run-probe",
                event_type=EGRESS_BLOCK,
                entity_type=name,
                token_id="deadbeef",
                detail={"v": mrn},
            )
        )
    finally:
        await log.close()

    blob = _audit_file_bytes(db)
    assert name.encode("utf-8") in blob and mrn.encode("utf-8") in blob, (
        "premise: a short original really does reach the file verbatim -- if this "
        "fails the schema gained a guard and the README's wording should say so"
    )

    # Assertion 2 exactly as the run performs it: both limbs, unioned.
    planted = frozenset({name, mrn})
    reopened = await AuditLogger.open(db)
    try:
        events = await reopened.query(limit=10_000)
        audit_json = json.dumps(
            [event.model_dump() for event in events], default=str, ensure_ascii=False
        )
    finally:
        await reopened.close()

    query_limb = find_in_text(planted, audit_json)
    byte_limb = find_in_bytes(planted, blob)
    caught = sorted(set(query_limb) | set(byte_limb))
    assert caught == sorted([mrn, name]), (
        "an original written into the audit log was not reported by assertion 2 -- "
        f"query limb saw {query_limb}, byte limb saw {byte_limb}"
    )

    # ...and which limb did the work, so the attribution cannot rot.
    assert name in query_limb and name not in byte_limb, (
        "the label-column case is the query limb's to catch; if the byte limb now "
        "catches it too, check the elapsed_ms false positive before celebrating"
    )
    assert mrn in query_limb and mrn in byte_limb, (
        "a detail value is JSON-quoted in both views, so both limbs must see it"
    )


def _audit_file_bytes(db: Path) -> bytes:
    """The audit DB plus its WAL sidecar, as raw bytes. Mirrors ``Harness.audit_bytes``."""
    blob = b""
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(db) + suffix)
        if path.is_file():
            blob += path.read_bytes()
    return blob


# ---------------------------------------------------------------------------
# 3. Summary
# ---------------------------------------------------------------------------


def _selected_run_indices(request: pytest.FixtureRequest) -> frozenset[int]:
    """*Which* of the 100 parametrized runs this pytest invocation actually selected.

    Read off ``session.items`` -- the post-filter collection -- so it reflects
    ``-k``, ``-m``, ``--deselect`` and an explicit node-id list, which is the whole
    point: the summary needs to tell "the runs were never asked for" apart from
    "the runs were asked for and did not happen". Those are different facts and
    only the second one is a finding.

    This used to return a *count*, which was one fact short. Subtracting a count
    from a count says a run is missing; subtracting a set from a set says **which**
    one, and that is the difference between ``99 != 100`` and ``run 086 never
    entered the body``.

    Both facts this reads -- ``originalname`` and ``callspec.params`` -- are pytest
    internals, and reading them through ``getattr`` means a pytest that stops
    exposing either yields an *empty* selection rather than an error. That is only
    safe because :func:`_selected_run_item_count` derives the same population from
    ``nodeid``, which shares nothing with either attribute, and the caller asserts
    the two agree. See that function for why counting the same way in both places
    would have made the guard unable to fire.
    """
    selected: set[int] = set()
    for item in request.session.items:
        if getattr(item, "originalname", None) != "test_no_original_ever_leaves_the_process":
            continue
        callspec = getattr(item, "callspec", None)
        index = None if callspec is None else callspec.params.get("index")
        if isinstance(index, int):
            selected.add(index)
    return frozenset(selected)


#: How a run item is recognised **without** touching a pytest-internal attribute.
#:
#: File-qualified, so a same-named test in another module cannot inflate the count,
#: and ``[`` on the end so only the parametrized items match. ``nodeid`` is the one
#: string pytest guarantees on every collected item.
_RUN_NODEID_MARK = f"{Path(__file__).name}::test_no_original_ever_leaves_the_process["


def _selected_run_item_count(request: pytest.FixtureRequest) -> int:
    """The same population as :func:`_selected_run_indices`, read off a **different fact**.

    This is the check on that function, so it must not be able to fail the same way
    -- and for one revision it could. It filtered on ``getattr(item, "originalname",
    None)``, exactly what the function it checks filters on, which made the two agree
    by construction in the case that matters: if ``originalname`` ever stopped being
    there, both went to zero together, the caller's ``len(selected) == collected``
    read ``0 == 0``, and :func:`test_leakage_summary` took the "nothing was selected"
    branch and **skipped**. The expectation would have shrunk to nothing silently,
    which is the one outcome that guard exists to make impossible.

    ``nodeid`` shares no machinery with ``originalname`` or with ``callspec.params``,
    so either of those going away now shows up as ``0 != 100`` on the guard rather
    than as a green, empty run. Pinned by
    :func:`test_the_selected_run_expectation_cannot_shrink_silently`.
    """
    return sum(1 for item in request.session.items if _RUN_NODEID_MARK in item.nodeid)


@pytest.mark.asyncio(loop_scope="module")
async def test_leakage_summary(
    harness: Harness, ledger: Ledger, request: pytest.FixtureRequest
) -> None:
    """The line quoted in the README, backed by the tally the runs actually produced.

    **This assertion is the one that stops the README quoting a number nothing
    produced**, so it is deliberately not satisfiable by a harness that ran nothing.
    It is also the assertion most likely to be met by someone running a subset, and
    those two needs pull in opposite directions unless the test can see what was
    selected.

    So it distinguishes three cases explicitly rather than collapsing them into one
    ``ledger.runs == RUNS``:

    * **none selected** -- somebody ran ``-k`` or a node id that filtered the runs
      out entirely. There is no measurement to summarise and no finding to report;
      skip, and say so. Previously this raised ``expected 100 completed runs,
      recorded 0``, which reads exactly like the harness silently measuring nothing
      -- the most alarming failure this file can produce -- for what is in fact an
      ordinary filtered invocation.
    * **partially selected** -- ``n`` of 100 were collected. This is the dangerous
      middle, because a summary computed over a subset would still *look* like the
      headline result. The tally must match the selection exactly or this fails.
    * **fully selected** -- the ``pytest -m leakage`` case the README quotes. Full
      strength: every one of the 100 runs must have recorded, and the count is
      checked against ``RUNS`` rather than against the selection, so deselecting a
      run cannot lower the bar it is measured against.

    The check is therefore strictly stronger than the one it replaces: it now also
    catches a *partial* selection reporting a summary, which the old form did not.

    **The missing-run limb names the run and the reason.** It used to be
    ``ledger.runs == selected``, and when it fired for real -- once, on run 086,
    under heavy concurrent load -- it printed ``assert 99 == 100`` and nothing
    else. That is the least useful true statement this file can make: it says a
    run vanished, and the three facts needed to act on it (which run, what
    exception, from which statement) were all recoverable only from a traceback
    that was no longer on screen. :meth:`Ledger.diagnosis` supplies those three
    facts.

    **The set limb is not the old condition restated, and saying it was would have
    been the wrong reason to trust it.** Implication runs one way only:
    ``Ledger.runs`` is incremented nowhere but ``record()``, which also adds the
    index to ``completed``, so ``runs >= len(completed)`` always -- a short count
    therefore *forces* a selected index to be missing from the set, and the set limb
    catches everything the old one caught. The converse is false, which is exactly
    why the count comparison is asserted immediately after rather than instead: a
    double ``record()`` for one index leaves the set complete and only the count
    short. Nothing is relaxed, and two states the old assertion passed now fail --
    one index recorded twice while another recorded not at all, and every run
    recording under a single hardcoded index.
    """
    selected = _selected_run_indices(request)
    collected = _selected_run_item_count(request)
    assert len(selected) == collected, (
        f"{collected} run item(s) were collected but only {len(selected)} carried a "
        "parametrized index, so the expected set is smaller than the selection and "
        "a missing run could hide in the gap"
    )
    if not selected:
        pytest.skip(
            "the 100 leakage runs were filtered out of this invocation, so there is "
            "no tally to summarise. Run `pytest -m leakage` for the README number."
        )

    missing = ledger.diagnosis(selected)
    assert not missing, (
        f"{len(selected)} leakage run(s) were selected but {len(missing)} never reached "
        "ledger.record(), so the summary is being computed over fewer runs than were "
        "asked for. Each one, with the statement it died on:\n  " + "\n  ".join(missing)
    )
    assert ledger.runs == len(selected), (
        f"{len(selected)} leakage run(s) were selected but the tally counts "
        f"{ledger.runs} -- every selected index recorded, so one of them recorded twice"
    )
    assert len(selected) == RUNS, (
        f"only {len(selected)} of {RUNS} leakage runs were selected, so this tally is a "
        "subset and must not be quoted as the headline result"
    )
    assert ledger.runs == RUNS, f"expected {RUNS} completed runs, recorded {ledger.runs}"
    assert ledger.leaks == 0, f"{ledger.leaks} leak(s) found across {ledger.runs} runs"
    assert await harness.audit.verify_chain() is True, "audit hash chain broken"
    print("\n" + ledger.summary() + "\n" + ledger.timing())


def test_a_run_that_dies_before_record_is_named_with_its_reason() -> None:
    """The regression test for the one failure this harness has ever had.

    Run 086 failed under heavy concurrent load and produced two useless lines:
    ``99 == 100`` and ``Ledger(runs=99, leaks=0, ...)``. It has not reproduced in
    seven full-suite runs since, so the *ghost* is not what can be pinned down --
    what can be pinned down is that the next occurrence answers the three
    questions the last one could not, and that is what this asserts, by killing a
    run exactly the way the load killed that one.

    The negative assertion is not decoration. ``mask`` exists because this module
    never renders an original into output, and a failure line assembled from an
    arbitrary exception is the obvious place for that habit to break: the
    exception could have come out of the engine holding a span of the document.
    So the line carries the exception's *type* and never its message, and this
    proves it with a message that would be a leak if it were copied through.
    """
    # Held in a local rather than written into the ``raise``, because the failure
    # line quotes the *source* of the failing statement and a literal there would
    # be quoted legitimately. That is the actual boundary of the guarantee and it
    # is worth stating: source text can only carry a value that is hardcoded in
    # this file, and every original here comes out of the generator at runtime.
    message = "Marguerite Vandenberg"
    book = Ledger()
    with pytest.raises(RuntimeError):
        with book.watching(86):
            raise RuntimeError(message)

    lines = book.diagnosis(frozenset({86}))
    assert len(lines) == 1, f"one dead run, one line: {lines}"
    line = lines[0]

    # Which run -- index, kind, strategy and seed, which is everything needed to
    # re-run it alone: `pytest -k 086-financial-tokenization-seed90086`.
    for fact in ("086", "financial", "tokenization", "90086"):
        assert fact in line, f"the failure line does not say {fact!r}: {line}"
    # Why, and from where. The line number is this file's, and the source text is
    # the statement, so the reader knows whether it was an assertion or the pipeline.
    assert "RuntimeError" in line, line
    assert "harness line" in line, line
    assert "raise RuntimeError(message)" in line, f"the failing statement is not quoted: {line}"
    # And never the value.
    assert "Vandenberg" not in line, (
        "the failure line carries the exception message, which is arbitrary text from "
        f"a process that has been handling originals: {line}"
    )

    # The tally still says the run did not happen -- watching() re-raised, and a
    # caught exception is not a recorded run.
    assert book.runs == 0 and book.completed == set()
    assert "086-financial-tokenization-seed90086" in book.timing(), book.timing()


def test_the_summary_distinguishes_a_run_that_died_from_one_that_never_started() -> None:
    """Two different faults, two different lines, and neither is a bare count.

    A run missing from the tally has exactly two causes and they call for opposite
    responses: the body raised (look at the statement) or setup never finished
    (look at the fixtures). The old assertion could not tell them apart because it
    subtracted one integer from another.
    """
    book = Ledger()
    never_started = book.diagnosis(frozenset({7}))
    assert len(never_started) == 1 and "never entered the body" in never_started[0]
    assert run_id_for(7) in never_started[0], never_started

    # A run that entered, raised nothing, and did not record -- an early return, or
    # a deleted record() call. Distinct from both of the above.
    with book.watching(7):
        pass
    silent = book.diagnosis(frozenset({7}))
    assert len(silent) == 1 and "raised nothing" in silent[0], silent

    # And a run that finished is not reported at all.
    book.record(index=7, originals=3, restored=2)
    assert book.diagnosis(frozenset({7})) == []


def test_the_summary_assertion_prints_the_per_run_diagnosis() -> None:
    """The diagnosis has to reach the assertion message, not just exist.

    Structural, because the behavioural half above cannot reach it: the summary is
    an async test over the module-scoped harness, and a second copy of it built to
    be failed would be a second harness. What is checkable here is that the limb
    which fires when a run is missing is the one built from
    :meth:`Ledger.diagnosis` -- if someone puts the count comparison back in front
    of it, the message a reviewer sees goes back to ``99 == 100``.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    match = re.search(r"^async def test_leakage_summary", source, re.M)
    assert match is not None, "the summary test has been renamed; this guard is stale"
    body = source[match.start() :]
    following = re.search(r"\n(?:async )?def ", body[1:])
    if following is not None:
        body = body[: following.start()]

    assert "missing = ledger.diagnosis(selected)" in body, (
        "the summary no longer computes the per-run diagnosis, so a vanished run is "
        "back to being reported as a difference between two integers"
    )
    diagnosis_at = body.index("assert not missing")
    count_at = body.index("assert ledger.runs == len(selected)")
    assert diagnosis_at < count_at, (
        "the count comparison now fires before the diagnosis, so the message a "
        "reviewer sees for a vanished run is a bare integer mismatch again"
    )


def test_the_summary_says_what_a_full_clean_suite_does_and_does_not_establish() -> None:
    """The tally may not be printed without the sentence that says what it is worth.

    Built on a **full, clean** ledger on purpose: 100 of 100, zero leaks is the exact
    state in which the caveat is least welcome and most needed, and a summary that
    qualified only its failures would be worse than one that qualified nothing.

    Four facts are pinned, and each one is a separate way the line has been read wrong:

    * the tally line is **byte-for-byte** what it was. ``test_readme_claims`` parses this
      text and README section 1 pastes it, so widening the claim is not licence to
      reword the number -- the qualification is *added*, never substituted;
    * the rate is **quoted, not gestured at**, and quoted per channel, so a reader can
      check the parts against :data:`_HARNESS_RUN_FLOOR` instead of taking a total on
      trust;
    * the residual is named as **one-sided**. Without that sentence the caveat reads as
      a discount on ``0 leaks``, which would be a different and false statement: a
      collision adds a reported occurrence and can only manufacture a red;
    * the rule-of-three number is present, because *"it went green four times"* is the
      specific argument this whole finding was raised against, and the answer to it is
      an integer.
    """
    book = Ledger()
    for index in range(RUNS):
        book.record(index=index, originals=30, restored=24)
    lines = book.summary().splitlines()

    assert lines[0] == (
        "[leakage] 100/100 runs clean, 0 leaks (3000 originals vaulted and scanned, "
        "2400 surrogates round-tripped)"
    ), f"the README-quoted tally line has changed shape: {lines[0]!r}"

    # Whitespace-flattened for the prose assertions: the line is wrapped for a reader,
    # and a test that pinned the wrap points would fail on a re-flow rather than on a
    # lost claim. The channel rows below keep the raw text, where the alignment lives.
    caveat = " ".join("\n".join(lines[1:]).split())
    assert caveat, (
        "the summary prints the tally with nothing qualifying it, which is the state "
        "that let four green runs be quoted as evidence that this harness is "
        "deterministic -- it carries a measured false-red channel and must say so"
    )
    for fact in (
        "NOT evidence",
        "deterministic",
        f"{_FALSE_RED_TOTAL:.1e}",
        str(_CLEAN_SUITES_TO_BOUND),
        "_HARNESS_RUN_FLOOR",
        # The fifth channel, which is bounded by observation rather than computed and is
        # deliberately outside the total above. Naming the total without it would read as
        # a complete accounting of the residual, and it is not one.
        "the bounded limbs add an unquantified",
    ):
        assert fact in caveat, f"the summary no longer states {fact!r}: {caveat!r}"

    assert "never turns a leak green" in caveat, (
        "the caveat no longer says the residual is one-sided, so it now reads as a "
        "discount on `0 leaks` rather than a statement about reproducibility"
    )
    for name, rate in _FALSE_RED_PER_SUITE.items():
        row = re.compile(rf"{re.escape(name)}\s+{re.escape(f'{rate:.1e}')}")
        assert row.search(caveat), (
            f"the {name!r} channel is in the measured total but is not printed beside "
            "its own rate, so the total cannot be checked against its parts"
        )


def test_the_false_red_rate_the_prose_quotes_is_the_one_the_code_computes() -> None:
    """The three places that number appears must not be able to drift apart.

    It lives in :data:`_FALSE_RED_PER_SUITE` (the parts), in the module docstring (the
    prose a reviewer reads first) and in :data:`_CLEAN_SUITES_TO_BOUND` (the consequence
    a reader acts on). Two of the three were prose until this test existed, and prose
    quoting a measurement is exactly how ``1.7e-01`` survived three commits after the
    exemption that was supposed to explain it turned out to remove nothing.

    The rule-of-three arithmetic is asserted rather than the literal, so lowering the
    rate without recomputing the bound -- the flattering direction -- is red.
    """
    assert all(0.0 < rate < 1.0 for rate in _FALSE_RED_PER_SUITE.values()), (
        f"a channel rate is not a probability: {_FALSE_RED_PER_SUITE}"
    )
    assert _CLEAN_SUITES_TO_BOUND == round(3 / _FALSE_RED_TOTAL), (
        "the rule-of-three bound is no longer derived from the rate it bounds"
    )
    doc = __doc__ or ""
    assert f"{_FALSE_RED_TOTAL:.1e}" in doc, (
        f"the module docstring quotes a false-red rate other than the measured "
        f"{_FALSE_RED_TOTAL:.1e} the summary prints, so one of the two is stale"
    )


def test_the_selected_run_expectation_cannot_shrink_silently() -> None:
    """The two readings of "which runs were selected" must not be able to fail together.

    :func:`_selected_run_indices` reads pytest internals through ``getattr``, so an
    attribute that goes away yields an *empty* selection rather than an error. The
    only thing between that and a summary which quietly skips is
    ``assert len(selected) == collected``, and that guard is worth nothing if the
    count is derived from the same attribute -- which is what it was: both filtered
    on ``originalname``, so both would have gone to zero together and the guard would
    have read ``0 == 0`` while :func:`test_leakage_summary` took the "nothing was
    selected" branch. A green run measuring nothing is the worst outcome this file
    has, and it would have printed no README line to say so.

    Asserted on the disagreement directly: an item carrying a run's ``nodeid`` and
    none of the attributes must be seen by the count and missed by the index reader,
    which is what makes the guard fire.
    """
    nodeid = f"tests/leakage/{_RUN_NODEID_MARK}007-medical-tokenization-seed90007]"

    def as_request(*items: Any) -> pytest.FixtureRequest:
        session = SimpleNamespace(items=list(items))
        return cast(pytest.FixtureRequest, SimpleNamespace(session=session))

    healthy = SimpleNamespace(
        nodeid=nodeid,
        originalname="test_no_original_ever_leaves_the_process",
        callspec=SimpleNamespace(params={"index": 7}),
    )
    assert _selected_run_indices(as_request(healthy)) == frozenset({7})
    assert _selected_run_item_count(as_request(healthy)) == 1

    # pytest stops exposing what the index reader needs. The count must NOT follow it
    # down: 0 == 1 is a red summary, 0 == 0 is a skipped one.
    stripped = SimpleNamespace(nodeid=nodeid)
    assert _selected_run_indices(as_request(stripped)) == frozenset()
    assert _selected_run_item_count(as_request(stripped)) == 1, (
        "the run-item count is derived from the same attribute the index reader uses, "
        "so the two collapse together, `len(selected) == collected` reads 0 == 0, and "
        "the summary skips -- the expectation shrinks to nothing with nothing red"
    )

    # And the count stays file-qualified: a same-named test in another module is not
    # one of these 100 runs, and counting it would fire the guard for no reason.
    elsewhere = SimpleNamespace(
        nodeid="tests/other/test_elsewhere.py::test_no_original_ever_leaves_the_process[0]",
        originalname="test_no_original_ever_leaves_the_process",
    )
    assert _selected_run_item_count(as_request(elsewhere)) == 0


#: A vaulted value, and two payloads carrying it that ONLY a skeleton view finds.
#:
#: ``_INSIDE`` splices U+0E31 THAI CHARACTER MAI HAN-AKAT -- a category-``Mn`` mark
#: with combining class **0** -- into the middle of the value. ``_BESIDE`` carries an
#: interior U+0301 (class 230) *and* a class-0 U+0903 immediately after the value,
#: followed by a letter. The second is the shape that regressed when the gate's fold
#: was widened to category ``M``: removing the trailing mark glues ``Brightwater`` to
#: ``Corporation``, and the word-boundary rule then denies the occurrence.
_SKELETON_ONLY_VALUE = "Nathaniel Brightwater"
_SKELETON_ONLY_PAYLOADS = (
    # Written as escapes, not literals: these payloads exist to carry ONE exact
    # codepoint each, and a literal makes the interesting character invisible in
    # review (ruff RUF001 also flags U+0903, which renders like a colon).
    (
        "mark spliced inside the value",
        "Attending: Nathan\u0e31iel Brightwater",  # Mn, combining class 0
    ),
    (
        "mark beside the value",
        "Contact Nathanie\u0301l Brightwater\u0903Corporation.",  # class 230 + class 0
    ),
)


@pytest.mark.parametrize("label,payload", _SKELETON_ONLY_PAYLOADS)
def test_the_skeleton_limb_does_not_ask_the_gate_for_its_answer(
    monkeypatch: pytest.MonkeyPatch, label: str, payload: str
) -> None:
    """The harness must find a mark-spliced original with the gate's folds disabled.

    This module imported the gate's ``_skeleton`` and ``_deaccent`` and justified it
    in ``_haystack_forms`` with an argument that reads well and is wrong: a *fold* is
    haystack-only, so it "can only widen what the scan sees". A fold that DELETES
    characters cannot only widen -- the forms consuming it decide with
    :func:`occurs_as_a_unit`, a word-boundary rule evaluated on the folded string, and
    a deleted mark beside a value glues it to the next word so the rule denies it.

    The bill came in two parts. The gate's mark selection tested combining CLASS, so
    1,496 category-``M`` codepoints with class 0 were never stripped and a mark spliced
    inside a vaulted value defeated pass 1 -- and this module, importing the same fold,
    printed ``100/100 runs clean, 0 leaks`` on the payloads the gate was releasing.
    Then the selection was widened to category ``M`` and 42 payloads that HEAD had
    blocked began to release, for the boundary reason above -- and this module inherited
    that too, still clean, still 0 leaks. Twice the headline number was not evidence
    about the skeleton at all.

    So the derivation is now :func:`_reference_skeleton`, written here from
    :mod:`unicodedata` primitives. The ordering is deliberately the gate's and the
    docstring says so -- that is the part a second opinion should agree with. The
    implementation is this module's, which is what makes disagreement loud.

    Modelled on :func:`test_the_separator_limb_does_not_ask_the_gate_for_its_answer`,
    which exists because the separator limb learned the identical lesson first. Every
    fold on the gate is replaced with identity, not just the one under discussion: a
    checker that survives only because it happened to call a *different* borrowed
    helper is not independent either. Measured -- with all five gate folds stubbed, the
    harness still returns the original for both payloads; before this change it
    returned ``[]`` for both with the gate fully intact.
    """
    for fold in ("_deaccent", "_skeleton", "_strip_invisible", "_strip_spacing_marks"):
        monkeypatch.setattr(egress_gate, fold, lambda value, **kwargs: value)
    monkeypatch.setattr(egress_gate, "_skeleton_views", lambda value: (value, None))

    assert find_in_text(frozenset({_SKELETON_ONLY_VALUE}), payload) == [
        _SKELETON_ONLY_VALUE
    ], f"the harness lost {label!r} when the gate's folds were disabled"


@pytest.mark.parametrize("label,payload", _SKELETON_ONLY_PAYLOADS)
def test_the_harness_reports_the_mark_payloads_the_gate_blocks(
    label: str, payload: str
) -> None:
    """Non-vacuity for the test above: these payloads are found with the gate intact.

    Without this, a `_reference_skeleton` that returned its input unchanged would still
    satisfy the sabotage test if the payloads happened to be findable some other way.
    They are not: every one of the raw, normalised and folded forms misses them, which
    is asserted here rather than assumed.
    """
    normalised = normalize(_SKELETON_ONLY_VALUE)
    folded = _reference_strip_invisible(normalised)
    assert not occurs_as_a_unit(_SKELETON_ONLY_VALUE, payload)
    assert not occurs_as_a_unit(normalised, normalize(payload))
    assert not occurs_as_a_unit(folded, _reference_strip_invisible(normalize(payload)))

    assert find_in_text(frozenset({_SKELETON_ONLY_VALUE}), payload) == [
        _SKELETON_ONLY_VALUE
    ], f"premise: {label!r} is a leak the harness must see"
