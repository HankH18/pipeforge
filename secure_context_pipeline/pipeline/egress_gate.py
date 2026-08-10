"""EgressGate -- the fail-closed leak scanner (build doc section 9.5.3).

This is the security centerpiece. The zero-PII-in-transit guarantee is an
**egress property, not a detection property**: no detector has 100% recall, so the
claim cannot rest on the detector having found everything. Instead, every byte
that is about to leave the process is checked against the set of values we *know*
are sensitive, and anything unexplained blocks the call.

Three passes, of which only the first two were ever independent of the detector:

1. **Original-value scan.** The fully serialized outbound payload is searched for
   every original in the session vault, in raw, normalised, format-character-folded
   (which also writes every Unicode decimal digit in its ASCII spelling) and
   combining-mark-folded form, plus -- for values whose disclosure is carried by
   a long digit run -- with no word-boundary requirement at all
   (:func:`_identifier_needles`), plus -- for an original that is itself a *list* of
   digit-bearing values -- the same four bounded forms again per constituent
   (:func:`_composite_needles`). This catches a splice bug, an un-obfuscated echo,
   or a value the engine missed after detection found it.
2. **Detector re-scan**, skipping spans that are our own surrogates. This catches
   values the detector found *this* time but the engine never vaulted -- and, in
   the adversarial test, values planted directly into the originals set.
3. **Independent-pattern scan** (:data:`_INDEPENDENT_PATTERNS`), over the same
   unprotected text pass 2 examines but with recognisers the detector does not use.
   Pass 2 alone is not a second opinion -- it re-runs the *same* Detector, so a value
   the detector misses is invisible to it for the same reason it was invisible at
   detect time, and pass 1 never learned about it either. Measured, not argued:
   Presidio's ``UsSsnRecognizer.invalidate_result`` scores the canonical example SSNs
   (``123-45-6789``, ``987-65-4320``, ``078-05-1120``), every ``000``/``666`` area
   number, every all-zero group and every mismatched-delimiter spelling at **0.0**, so
   ``Member SSN 123-45-6789`` was never vaulted, never obfuscated, and reached the
   provider in the clear with all three passes silent.

   **What this pass covers is two SSN spellings, and this entry used to claim the
   hole rather than the patch.** It said pass 3 closed the invalidated-SSN hole and
   cited ``Member SSN 123-45-6789`` as the case. The pattern it pointed at required a
   *delimiter*, so what it actually closed was the delimited subset. The same document
   with the same nine digits written bare -- ``Member SSN 123456789`` -- was detected by
   nothing, vaulted by nothing, matched by nothing here, and reached the provider
   verbatim under both strategies with ``EGRESS_PASS`` recorded. A docstring that
   describes a class of defect while the code handles one spelling of it is worse than
   silence, because it is where the next reader stops looking. Pass 3 now carries two
   patterns: the separated spelling unconditionally, and any nine-digit SSN spelling --
   bare included -- introduced by an SSN or ITIN label. The registry carries a label
   rule of its own as a detection backstop (``entities.yaml`` -> ``SSN.patterns``),
   which is what turns those documents from *blocked* into *vaulted, obfuscated and
   restorable*; this pass is the copy that a registry edit cannot switch off.

   The two rules are separately authored, so what they owe each other is
   **containment, not equality**: everything this pass would block on a labelled SSN,
   the registry must already claim. It did not, for one revision -- the gate's
   separator class was ``[^0-9A-Za-z]{0,24}`` and the registry's was ``[\\s:#.\\-]*+``,
   so ordinary intake spellings (``Member SSN, 123456789``, ``Social Security Number
   (SSN): 123456789``) were blocked rather than vaulted. The registry class is now the
   superset ``[^0-9A-Za-z]*+`` and two tests hold the containment; the full account is
   above :data:`_INDEPENDENT_PATTERNS`.

   The residual is stated rather than left to be inferred: nine digits with **no** SSN
   label near them are not claimed by either pattern, here or in the registry. Presidio
   scores that shape 0.05, an ordinary document writes far more order numbers and ledger
   references in it than SSNs, and a block is a denial. See README Deviation 58 and
   :meth:`~secure_context_pipeline.detection.detector.Detector._floor_for`.

The skip-list in pass 2 is load-bearing. Pseudonyms are PII-shaped *by design*: a
fake name is still a name. Without the skip-list every pseudonymization run would
false-positive on its own output.

**Fail-closed** means exactly that: an internal exception in this module blocks
the call. There is no path through ``check()`` that returns normally without both
passes having completed *and* the ``EGRESS_PASS`` record having been written --
every exit is enumerated in :meth:`EgressGate.check`. The second half of that
sentence is conditional on there being a log to write to, and saying so is not a
loophole: ``audit=None`` is a constructor argument, not a runtime state, so it is a
decision an embedder makes once and visibly. Every path that builds this class in
anger passes one (``api/app.py``, ``demo.py``); ``None`` is the no-sink shape unit
tests use, and it changes nothing about either scan.

**What a pass clears is a string, not a request.** The gate is handed bytes and
returns a report identifying those bytes by digest; it has no way to observe what
its caller does next. "The gate ran before the provider call" is therefore a
weaker property than "the gate cleared what the provider received", and only the
second one is the guarantee. Holding the second is the caller's job, and
:meth:`~secure_context_pipeline.pipeline.orchestrator.PipelineOrchestrator._verify_release`
is where this pipeline does it -- by re-deriving the digest from the exact
arguments it hands the provider and refusing to send on a mismatch.

**Every path by which a byte can reach the provider**, enumerated, because "the
gate covers the normal path" is not the claim -- one unmediated path and the
headline guarantee is gone. There are eight, and the first is the only one that
carries payload bytes:

1. *The call itself.* ``PipelineOrchestrator.run`` step 7 is the sole invocation of
   a provider anywhere in this package; ``llm/`` is also the only subtree that
   imports a network library at all. It is preceded, in that order, by ``check()``
   and by ``_verify_release``.
2. *Retries.* ``AnthropicProvider`` builds ``system`` and ``messages`` once, before
   the attempt loop, and re-sends the same objects. A retry is the same cleared
   bytes again, never new ones, and every attempt is downstream of one gate pass.
3. *Streaming.* There is none. The non-streaming Messages API is used, and the
   absence of ``stream`` from the request body is asserted on the wire in
   ``tests/test_llm.py``. There is no chunk boundary for a value to straddle.
4. *Timeout and cancellation.* Both abort an in-flight request; neither composes a
   new one. Inside ``check()`` a cancelled scan is an unfinished scan -- see below.
5. *Exceptions.* ``LLMTransportError``/``LLMRefusalError``/``LLMResponseError``
   carry a model name, a machine reason, an attempt count and an HTTP status.
   ``EgressBlockedError`` and the audit rows this module writes carry counts,
   digests and reason codes. No exception, log line or audit detail in this
   module or the orchestrator interpolates payload, original or surrogate text.
6. *Third-party logging.* The SDK logs the whole serialized request body at DEBUG;
   importing ``llm/anthropic_provider.py`` installs a filter that drops it, so a
   host application's ``basicConfig(level=DEBUG)`` cannot turn a log into an egress
   path.
7. *Provider-side transformation after the check.* The only one is the SDK's JSON
   serialization, which is lossless and reversible: it encodes the exact strings the
   gate cleared, and ``tests/test_llm.py`` parses the request body back out of an
   ``httpx.MockTransport`` and compares. It can neither conceal a value the gate saw
   nor introduce one it did not.
8. *The wire dump.* ``demo.py --dump-wire`` captures ``request.content`` and scans
   the literal bytes against the vault's originals before writing them anywhere.

**What pass 1 does and does not promise**, stated as residual risk rather than
implied by omission. It blocks whenever a vaulted original appears in the payload
as a standalone run of text, in any of the compared forms -- including next
to punctuation, markdown, brackets and currency symbols, and including a value
interrupted by any character that renders as nothing: every Unicode format (``Cf``)
codepoint and every default-ignorable, from the zero-width space to the tag block
that carries the ASCII-smuggling vector (see :data:`_INVISIBLE_RE`). It *also*
blocks four shapes that used to walk through, each of which was reachable from an
ordinary uploaded document and each of which was reproduced end-to-end before being
closed:

1. *An identifier glued into a longer alphanumeric run.* ``Brown`` inside
   ``Browning`` is still not an occurrence of ``Brown`` -- treating it as one blocks
   every pseudonymization run on its own well-formed output -- but that boundary rule
   was for years the **only** occurrence test, and the document body is
   attacker-controlled. A vaulted ``TAX_ID`` of ``47-1234567``, detected and
   tokenized from its clean mention, rode out to the provider byte-for-byte inside
   ``batch47-1234567Alpha``; ``MRN: 5567281`` did the same inside ``MRN5567281B``.
   The false-positive trade that justifies the boundary rule is a *name* argument
   (``Brown``/``Browning``), and it does not transfer to a nine-digit identifier, so
   :func:`_identifier_needles` now scans digit-carrying values with no adjacency
   requirement at all. See that function for the exact rule and its cost.
2. *A mark spliced into a value.* ``Nathaniel Brightwater`` was vaulted
   from its clean mention and reached the provider as ``Nathaniél
   Brightwater`` -- a different string to every one of the three original forms, and
   identical to ``Nathaniel Brightwater`` for a human reader and for the model. The
   *payload* is now compared in a mark-stripped skeleton form as well
   (:func:`_deaccent`); the needle is deliberately not stripped, which is what keeps
   ``José`` and ``Jose`` distinct values.

   This entry said "combining mark", and the fold behind it was closed for 912 of
   the 2,408 marks in this interpreter's Unicode database -- which is worse than an
   overstatement, because nothing anywhere reported the other 1,496. It selected on
   :func:`unicodedata.combining`, the canonical *combining class*, and 1,063 ``Mn``,
   420 ``Mc`` and 13 ``Me`` codepoints answer that question with ``0``. Measured on
   the real gate with one mark spliced into the vaulted name above: U+0E31 THAI
   CHARACTER MAI HAN-AKAT, U+0903 DEVANAGARI SIGN VISARGA and U+20DD COMBINING
   ENCLOSING CIRCLE each walked it to the provider with ``EGRESS_PASS`` recorded,
   while U+0301 blocked. Two instances of one wrong question: casefold *rewrites*
   U+0345 into a Greek letter, so a mark of combining class 240 survived as well --
   which is why the strip now also runs on the raw payload, ahead of normalisation
   (:func:`_skeleton`).

   Widening that selection to the general category was **not a pure widening**, and
   the same reproduction that closed the splice opened a second shape before it was
   caught: the occurrence test on the stripped string is a word-boundary rule, so a
   class-0 mark sitting *beside* the value was a boundary character until the fold
   deleted it and glued the value to its neighbour. Measured by differential fuzz on
   ``_scan_originals``, 60,000 randomized cases: the widened rule blocked 16,429
   payloads the old one released and released **212** the old one blocked. Both
   halves reproduce end to end -- ``Contact Nathanie<U+0301>l
   Brightwater<U+0903>Corporation`` was ``EGRESS_BLOCKED`` before the widening and
   ``EGRESS_PASS`` after it. The payload is therefore skeletonised under **both**
   selections and compared against both (:func:`_skeleton_views`); a union of two
   haystack-only folds is strictly additive, and the fuzz reports 0 regressions
   against either baseline. See :func:`_deaccent`, :func:`_skeleton` and
   :func:`_skeleton_views`.
3. *One constituent of a composite original.* A vault original is whatever the
   detector called one span, and a span is not always one value: spaCy returns
   ``03/11/2024, 09/17/2024`` as a single ``DATE``, so a string the document contains
   but nobody wrote as a unit became one original -- and every comparison above then
   asked about the composite rather than about the dates in it. This pipeline can
   *manufacture* the fragment, which is what made it worth closing here rather than
   only upstream: a different date in the same document, shifted by the session's
   constant delta, renders as a verbatim word-bounded slice of that original, so a real
   patient date reached the provider inside a string this pipeline invented with pass 1
   and the leakage harness both reporting clean and both correct by their own
   definitions. Detection now splits such a span into one detection per date
   (:func:`~secure_context_pipeline.daterules.split_composite_date`); this pass does not
   rely on that, and derives a needle per constituent itself. The rule is narrow on
   purpose -- see :func:`_composite_needles` for exactly what is excluded and what each
   exclusion costs if it is dropped.
4. *An identifier restated in another decimal digit script.* A vaulted MRN
   ``5567281`` reached the provider as the same seven digits written in Arabic-Indic,
   extended Arabic-Indic, Devanagari, Bengali, N'Ko or Osmanya, with all three passes
   silent, while the fullwidth spelling of the same number blocked -- because NFKC
   folds compatibility variants and leaves 580 of the 660 codepoints that carry a
   decimal value exactly as they are. It is not the homoglyph gap below and the
   confusables table named there would not have closed it: these are not look-alikes
   of ASCII digits, they are different characters with the same numeric value. Both
   sides of the comparison now write decimal digits in ASCII
   (:func:`_fold_decimal_digits`).

5. *A separator written as a transport escape.* ``Marguerite Vandenberg``, vaulted
   and tokenised out of the ``Patient:`` line, rode out in the same payload's chart
   link as ``?patient=Marguerite%20Vandenberg``. Every bounded form keeps the space;
   the separator-relaxing limb keeps only "non-alphanumeric", and ``%20``,
   ``&nbsp;``, ``&#32;`` and ``<br/>`` all carry word characters, so a character
   class cannot span one. The payload is now also compared in a **decoded** view
   (:func:`_decode_transport_escapes`). This was filed as residual gap 2 below, and
   the argument that it was unreachable was the wrong half of the question -- see
   there.

Three gaps remain:

1. *Homoglyph substitution.* Cyrillic U+043E for Latin ``o`` is different bytes;
   catching it needs a confusables table, not another normalisation form. This is
   the same class as the mark above and is the obvious next thing to close; the
   difference is that a UTS-39 confusables table is data this project does not ship,
   while ``unicodedata`` already knows what a mark is.
2. *A lossy or re-writing encoding layer* (base64, a summarizer) applied to
   outbound text. This pipeline applies none -- the payload
   is assembled from the obfuscated document verbatim -- so this is reachable only
   if some future stage adds one, which would have to bring the gate with it. The
   SDK's JSON serialization is not that stage and is worth saying so out loud,
   because it is the first thing a reviewer points at: it encodes *the exact string
   the gate cleared*, losslessly and reversibly, and the provider decodes it back to
   that string. It can therefore neither conceal a value the gate saw nor introduce
   one it did not. Verified on the wire in ``tests/test_llm.py``, where the request
   body is parsed back out of ``httpx.MockTransport`` and compared to the strings
   handed to the provider.

   **Percent-encoding used to be filed here, and filing it here was the defect.**
   The reachability argument above is about an encoding applied *on the way out*,
   and an encoded value does not need one: it only has to be **present in the
   uploaded document**, which is user-controlled input the pipeline then transports
   verbatim exactly as advertised. ``%20`` in a portal URL and ``&nbsp;``/``<br/>``
   in anything round-tripped through HTML or Word are ordinary spellings of a space
   in an ordinary ``.md``, ``.txt`` or ``.docx`` upload. That is shape 5 above; it
   was reproduced end to end with the API returning 200 and
   ``egress_rescan_warnings`` at zero, and it is closed. What stays here is the other
   half -- an encoding this pipeline would itself apply -- which is hypothetical in a
   way the inbound half never was.
3. *A mark inside a vaulted value AND a reordering mark immediately beside it.*
   Removing a mark takes a word boundary with it, so the payload is skeletonised
   under both mark selections (shape 2 above) -- but a mark whose combining class is
   non-zero is deleted by *both* selections by construction, so it glues the value to
   its neighbour in both and the boundary rule denies the occurrence. Measured with
   ``Brightwater`` vaulted, one U+0301 spliced in, and each of the 2,408 marks in
   turn immediately outside: 1,230 block, 1,178 do not. It predates the widening --
   the rule that shipped before it releases the same payload -- and closing it needs
   the removed character to survive as a boundary *token* rather than to be deleted,
   i.e. a sentinel that
   :func:`~secure_context_pipeline.textrules.occurs_as_a_unit` knows to skip. See
   :func:`_skeleton_views`, which states the cost of that change and why the union
   was taken instead.

The first two are detection-recall and upstream-integrity questions rather than
scan-form questions; passes 2 and 3 and the vault are what cover them. The third is a
scan-form question, and the reason it is filed rather than closed is an interface
change to a module four components share, not an argument that it is unreachable.

**What the guarantee is, stated so it cannot be read as more than it is.** Pass 1
backstops every value the pipeline *vaulted*, whatever the detector's recall was on
the rest of the document. Passes 2 and 3 backstop high-severity pattern shapes,
whether or not anything vaulted them. What no pass can backstop is a value that is
neither vaulted nor of a shape any recogniser here knows: "zero PII in transit" is
an egress property with respect to the vault, and a recall property with respect to
everything else. Pass 3 exists because the difference between those two sentences
was, until it was added, the whole distance between the headline claim and the code.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import logging
import re
import time
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from itertools import groupby
from typing import Final, NamedTuple, Protocol
from urllib.parse import unquote

from secure_context_pipeline.audit.logger import EGRESS_BLOCK, EGRESS_PASS, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import normalize
from secure_context_pipeline.errors import MAX_DETAIL_VALUE_LEN, EgressBlockedError
from secure_context_pipeline.models import AuditEvent, Detection, EgressReport
from secure_context_pipeline.surrogates import REDACTION_RE, STRICT_TOKEN_RE
from secure_context_pipeline.textrules import (
    ALNUM_RE,
    boundary_guards,
    delimited_parts,
    occurs_as_a_unit,
)

__all__ = [
    "AUDIT_EMIT_TIMEOUT_S",
    "DEFAULT_TIMEOUT_S",
    "HIGH_SEVERITY_TYPES",
    "MIN_IDENTIFIER_DIGITS",
    "MIN_IDENTIFIER_RUN_DIGITS",
    "MIN_JOINED_ALNUM_LEN",
    "MIN_ORIGINAL_LEN",
    "EgressGate",
]

logger = logging.getLogger(__name__)

# The entity types a re-scan hit BLOCKS on. NER-typed re-hits (names the fake
# generator produced contextually) are logged as warnings instead -- blocking on
# those would make pseudonymization unusable without improving the guarantee.
#
# THE COMMENT IS WHAT CHANGED HERE, NOT THE SET, and the note is worth more than the
# edit. It used to read "pattern-typed entities with near-zero false-positive rates",
# which is a rule this set does not follow: `INSURANCE_ID` (`\b[A-Z]{2,6}\d{7,12}\b`)
# and `CASE_ID` are pattern-typed too and are not members. Stating a rule the
# membership contradicts is worse than stating none, because the next reader either
# widens the set to match the sentence or assumes an omission. Both are wrong. The
# real rule is two-part, and both parts are load-bearing:
#
# 1. **The value is a direct identifier issued to a person by a government, a payer or
#    a bank** -- the ones whose appearance in a third-party payload is the disclosure
#    this pipeline exists to prevent.
# 2. **The recogniser buys its specificity from a LABEL in identifier position, from a
#    validator, or from a digit grouping no other identifier uses** -- never from
#    "some capital letters welded to some digits". A block is a denial, so the pattern
#    behind it has to be one an ordinary business document does not trip.
#
# `INSURANCE_ID` and `CASE_ID` pass (1) and fail (2), measured rather than asserted.
# Over sixteen ordinary non-PII strings (part numbers, SKUs, firmware builds, shipping
# container IDs, air waybills, Bates stamps, model numbers, licence plates, GL codes,
# cost centres, change tickets, ISO/DIN standard numbers, drawing revisions):
#
#     INSURANCE_ID  claims  8/16   ABC12345678, XLGE9087412, FW20240115093,
#                                  MSKU4412093, AWB12345678901, DEF00012345,
#                                  CAT9088123, ABC1234567
#     CASE_ID       claims  6/16   CC-2024-118, CHG-2024-4471, ISO-9001-2015,
#                                  REV-2024-118, 12-abc-4471, DIN-1234-567
#
# Half of an ordinary parts list would 422. `CASE_ID` has a second, independent reason:
# a docket number is a PUBLIC record, so refusing a payload that carries one buys no
# confidentiality and costs the caller their request. Both stay out, both stay
# detected, vaulted and restorable, and a re-scan hit on either is still recorded --
# as an advisory `rescan_warnings` count rather than as a block.
HIGH_SEVERITY_TYPES = frozenset({"SSN", "MRN", "ACCOUNT_NUMBER", "TAX_ID"})

# Originals shorter than this are not scanned for. A one- or two-character value
# carries no re-identification signal on its own and would match inside almost any
# payload, blocking every call. Stated as a known limitation in the README.
#
# Applied TWICE in _scan_originals, and the two are different questions. On the
# vaulted value it is measured after ``.strip()``, because " ab " is four characters
# of which two are signal and neither of its own ends is alphanumeric -- so no
# boundary assertion applies and it matches inside "The lab ab test", blocking every
# such payload. On each derived form it is measured raw, because normalising and
# folding both shrink a needle and can drop it below the floor after the fact.
MIN_ORIGINAL_LEN = 3

#: How many ASCII digits a vaulted value must carry **in total** before pass 1 scans
#: the whole value as a bare substring -- see :func:`_identifier_needles` for the rule
#: and :func:`_occurs_as_a_unit` for the word-boundary rule being switched off.
#:
#: This floor governs the *whole-value* needle only, the one that keeps separators:
#: ``512-24-8710``, ``(415) 555-0123``. Seven rather than six is what keeps two very
#: common low-entropy shapes out of an unbounded comparison, and both are aggregates
#: of short runs rather than identifiers: a two-digit-year date (``03/12/85``, six
#: digits) and an amount under ``$99,999.99`` (``$1,234.56``, six digits). Scanning
#: those without an adjacency rule blocks on ``Filed 03/12/850`` and
#: ``Line item $1,234.567``, which are ordinary text, not disclosures. Both are pinned
#: by ``test_a_value_below_the_identifier_floor_keeps_the_boundary_rule``.
MIN_IDENTIFIER_DIGITS: Final = 7

#: How long one **contiguous** run of ASCII digits must be before pass 1 scans that
#: run as a bare substring. Six, and it is deliberately *lower* than
#: :data:`MIN_IDENTIFIER_DIGITS` because it answers a different question.
#:
#: These were one constant, and that was a defect of the exact kind this module keeps
#: finding: **one number chosen for one channel's false-positive budget was silently
#: setting another channel's security floor.** Seven was justified against the shapes
#: above -- dates and amounts -- which are aggregates of 2- and 3-digit runs. A
#: *contiguous* six-digit run is not that shape. It is an identifier core, and the
#: shipped registry says so: ``MRN``'s pattern is ``\\K\\d{6,10}``, so the detector
#: vaults six-digit MRNs and the gate then declined to scan them unbounded.
#:
#: That was a live leak, not a theoretical one. Measured on the real detector, the
#: real registry and the real gate, with ``552140`` -- the first row of
#: ``DEV_IDENTIFIER_POSITIVES`` in ``tests/test_detection.py``, a value the detector is
#: *required* to find and vault::
#:
#:     payload:  "Internal routing tag: MRN552140B must match the ledger."
#:     pass 1 bounded forms: miss (the trailing ``B`` denies the right boundary)
#:     pass 1 unbounded:     miss (six digits, below the old single floor)
#:     pass 2:               miss (``MRN``'s pattern ends in ``\\b``, denied by ``B``)
#:     pass 3:               miss (SSN only)
#:     -> RELEASED, with a real vaulted MRN on the wire byte for byte.
#:
#: The false-positive arithmetic at six is run against the right channel this time.
#: :meth:`EgressGate._scan_originals` reads the **outbound payload** and nothing else,
#: and the only run of ``[0-9a-f]`` the pipeline emits into a payload is an 8-hex token
#: ID. A specific six-digit needle lands inside a random 8-hex ID with probability
#: ~3x16^-6 = 1.8e-7; a 251-entity document carries ~251 of them, so a document with
#: five six-digit originals expects 2.2e-4 spurious blocks. A spurious block is also
#: the direction this gate is allowed to be wrong in -- it denies a request, it does
#: not release a value.
#:
#: **That budget has since been spent and then reclaimed, and the paragraph above is
#: kept because the arithmetic in it is what sized the defect.** "Allowed to be wrong
#: in" was doing more work than it looks: measured on the shipped corpus, the token-ID
#: channel cost 1.3e-02 spurious blocks per 100-run suite -- observed twice in 27
#: executions and the cause of a long-standing intermittent failure in the leakage
#: harness -- and each one told a caller its own correct output was a PII leak. It is
#: closed at the source rather than by moving this floor: pass 1 no longer reads our
#: own emitted token IDs at all (:func:`_mask_own_tokens`), so the 8-hex ID is no
#: longer one of the landing sites this arithmetic counts. The floor stays at six
#: because the leak it exists for is unchanged.
#:
#: **The 32-hex ``run_id`` arithmetic that argued for seven belongs to a different
#: scanner.** It is the leakage harness that scans the audit database, where run IDs
#: give a six-digit needle 27 landing sites instead of 3; that floor now lives in
#: ``tests/leakage/test_leakage_harness.py`` under its own name, measured on its own
#: channel. Neither file inherits the other's budget by accident any more.
#:
#: Pinned in both directions: ``test_a_six_digit_identifier_core_glued_to_a_letter_is
#: _blocked`` (the leak above, end to end through the real gate) and
#: ``test_no_shipped_identifier_pattern_can_match_below_the_gate_s_run_floor`` (the
#: registry and this constant can no longer disagree without a red).
MIN_IDENTIFIER_RUN_DIGITS: Final = 6

#: How many alphanumeric characters a **multi-component** original must have, with its
#: separators removed, before :func:`_separator_needles` builds a needle for it. One
#: floor, applied to every multi-component value regardless of composition.
#:
#: **This docstring described a different design until it was re-read against the
#: code.** It claimed three branches -- an all-digit join reusing
#: :data:`MIN_IDENTIFIER_DIGITS`, an all-alphabetic join using this constant, and a
#: mixed letter-and-digit join getting no needle at all -- and none of that is what
#: runs. `_separator_needles` tests `len(_alnum_only(stripped)) < MIN_JOINED_ALNUM_LEN`
#: and nothing else: `1:23-cv-04567` and `MRN A-5567281` both get needles, and
#: `MIN_IDENTIFIER_DIGITS` is never consulted here. It also described the comparison
#: as a bare substring against an alnum-stripped payload projection, which was the
#: FIRST design and was replaced precisely because it re-opened the
#: `chronic low back pain` / `pains` false positive. What ships keeps the outer word
#: boundaries and relaxes only the interior separator.
#:
#: The three-branch story was not harmless: it is the kind of prose a reviewer checks
#: the behaviour against, and it told them a narrower rule protects them than the one
#: that runs.
#:
#: **What eight buys, and what it costs -- both re-measured**, because the three counts
#: that stood here (8,143 planted / 8,073 multi-component / 343 excluded) reproduce as
#: none of those, and a number a reader cannot re-derive is worse than no number. On the
#: generator corpus -- 26 seeds x four document kinds -- there are 8,462 distinct planted
#: values (8,472 distinct type-and-value pairs, so ten values are planted under two
#: types). 8,390 of them are multi-component, and the floor excludes **358**: 4.3%.
#:
#: **What is in that residual matters more than its size, and the composition was wrong
#: too.** It was described as "overwhelmingly lab values like ``HDL 28``". Counted by
#: entity type it is 286 ``AMOUNT``, 69 ``LAB_RESULT`` and 3 ``NAME`` -- and the floor is
#: not the last word on any of them, so the number that actually states the exposure is
#: how many are left with only the four bounded forms:
#:
#:     267 of the 358 still get an unbounded needle from another limb -- every
#:         seven-digit amount (``$10,107.07`` is seven digits, so
#:         :func:`_identifier_needles` takes the whole value and
#:         :func:`_regrouped_identifier_needle` takes its skeleton)
#:      91 get nothing beyond the bounded forms: 19 ``AMOUNT`` under seven digits
#:         (``$1,370.22``), 69 ``LAB_RESULT`` (``HDL 28``, letters and two digits) and
#:         3 ``NAME`` -- ``Gene Lee``, ``Paul Lee``, ``Ryan Ray``
#:
#: The three names are the part that matters, and they are not a corpus accident:
#: ordinary two-word person names sit under this floor generally -- ``Amy Cox`` and
#: ``Ann Lee`` are six alphanumerics, ``Jo Ann`` is five -- so for all of them this limb
#: is dead and a payload that respells the space walks the whole name out. A digit-free
#: value below the floor keeps the four bounded forms and nothing else; the digit-bearing
#: majority above does not, which is why "4.3% excluded" on its own reads as a much
#: larger hole than the one that ships. That name-shaped residual is a real open boundary
#: and it is named as the fourth entry in the README's list rather than left implied here.
#:
#: **It is not closeable by lowering the number, and that was measured rather than
#: assumed.** Real short names and common English phrases occupy the same length
#: range, so no floor separates them:
#:
#:     floor 5 -> covers 6 of 6 test names, and gives ``of the``/``in the``/``to the``
#:               needles that match the shipped fixtures 67 / 95 / 53 times
#:     floor 6 -> covers 2 of 6, still matches 5 common phrases
#:     floor 8 -> covers 0 of 6, matches 0 common phrases
#:
#: A phrase-shaped original reaching the vault is not hypothetical here: confidence-band
#: redactions are handed to the gate as needles (see ``SessionVault.note_unrestorable``),
#: and a prose entity can be one. So lowering the floor trades a narrow leak for a broad
#: outage -- every document containing the phrase would be denied.
#:
#: What would actually close it is the entity TYPE, which this limb cannot see: build
#: doc section 9.4 fixes ``originals_for_session`` as ``frozenset[str]``, so the gate is
#: handed strings with no way to tell ``Amy Cox`` from ``of the``. Threading types
#: through would let the limb apply to identifier and name types and skip prose ones.
#: That is the fix, and it is a change to the vault interface the specification pins,
#: so it is recorded in README section 7 rather than made here.
#:
#: Pinned in both directions by
#: ``test_the_joined_alnum_floor_is_the_one_the_limb_applies``; before that test the
#: constant did not appear in the suite at all and could be lowered to 1 in silence.
MIN_JOINED_ALNUM_LEN: Final = 8

#: Wall-clock budget for one whole ``check()``. Exceeding it blocks, because a
#: detector that never returns is indistinguishable from one that has not finished
#: yet, and "hold the request open forever" is not a safe answer to either. The
#: budget is generous by well over an order of magnitude: 20k originals against a
#: 54 KB payload complete pass 1 in roughly one second.
DEFAULT_TIMEOUT_S: Final = 30.0

#: Budget for one audit write made *by the gate*. Separate from
#: :data:`DEFAULT_TIMEOUT_S` because the block-path write in
#: :meth:`EgressGate._emit_block` runs from inside ``check()``'s exception handler,
#: which is outside the ``asyncio.timeout`` block and therefore had no budget at
#: all: a wedged audit writer -- an ``asyncio.Lock`` held by a hung coroutine, a
#: stalled fsync -- held the request open forever *after* the decision to block had
#: already been made. Nothing leaks in that state, but "blocked" and "never
#: answered" are different outcomes and only one of them is a security control.
#:
#: The *number* is part of the control, not decoration. The two tests that exercise
#: the wrapper monkeypatch this to 0.05 so they finish quickly, which for a while
#: left the shipped value pinned by nothing at all: raising it to an hour kept the
#: whole gate suite green while restoring exactly the unbounded wait the wrapper was
#: added to remove. ``test_the_block_path_audit_budget_is_short_enough_to_be_a_budget``
#: now reads back the budget the block path actually installs and holds it to a
#: ceiling stated in the test file.
AUDIT_EMIT_TIMEOUT_S: Final = 5.0


class VaultLike(Protocol):
    """The only vault capability the gate needs -- sync and O(1) on the hot path."""

    def originals_for_session(self, session_id: str) -> frozenset[str]: ...


class DetectorLike(Protocol):
    """The only detector capability the gate needs."""

    async def detect(
        self, text: str, doc_category: str | None = None
    ) -> Sequence[Detection]: ...


class EgressGate:
    def __init__(
        self,
        *,
        vault: VaultLike,
        detector: DetectorLike,
        settings: Settings,
        audit: AuditLogger | None = None,
        high_severity: Iterable[str] | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._vault = vault
        self._detector = detector
        self._settings = settings
        self._audit = audit
        self._high_severity = frozenset(high_severity) if high_severity else HIGH_SEVERITY_TYPES
        self._timeout_s = timeout_s

    async def check(
        self,
        payload: str,
        session_id: str,
        *,
        surrogates: frozenset[str] = frozenset(),
        run_id: str | None = None,
    ) -> EgressReport:
        """Scan the outbound payload. Returns on pass; raises on ANY doubt.

        NOTE (deviation from the build doc's ``def check(...)`` signature): this is
        ``async`` because pass 2 runs the detector, which offloads spaCy to a worker
        thread. A synchronous gate would either block the event loop or skip the
        re-scan; both are worse than the signature change.

        Every exit from this method is enumerated here, and only the first releases
        the payload:

        * both passes clean *and* ``EGRESS_PASS`` recorded -> return an ``EgressReport``;
        * pass 1 or pass 2 hit -> ``EgressBlockedError(vault_original|detector_rescan)``;
        * anything else raised inside -- vault, detector, audit, the timeout, a bug
          in this module -> ``EgressBlockedError(gate_exception)``;
        * ``asyncio.CancelledError`` -- a ``BaseException``, so neither ``except``
          clause here can absorb it -- propagates, and there is no ``return`` on
          that path either. A cancelled scan is an unfinished scan, never a pass.

        Both ``except`` clauses are exhaustive over ``Exception`` by construction:
        the first re-raises the one error type that already *is* a block, and the
        second converts everything else into one. ``BaseException`` is deliberately
        not caught -- catching it would be the only way to turn an abort into a
        release, and there is no code here that does.

        Recording the pass is inside the guarded region deliberately. A payload whose
        release we cannot evidence is a payload we do not release, so an audit failure
        blocks rather than releasing silently.

        The block-path audit write is *not* inside the ``asyncio.timeout`` block --
        it runs from the exception handler -- so it carries its own budget; see
        :data:`AUDIT_EMIT_TIMEOUT_S`.

        Returning normally is not the only thing a caller must check: it clears
        *these bytes*. The report's ``payload_sha256`` is what a caller uses to
        prove the string it goes on to send is the string that was cleared, which
        :meth:`~secure_context_pipeline.pipeline.orchestrator.PipelineOrchestrator._verify_release`
        does before the provider call.
        """
        started = time.perf_counter()
        try:
            async with asyncio.timeout(self._timeout_s):
                report, warned_types = await self._run_passes(
                    payload, session_id, surrogates, run_id, started
                )
                await self._emit_pass(session_id, run_id, report, warned_types)
        except EgressBlockedError:
            raise
        except Exception as exc:
            logger.error(
                "egress gate failed internally; blocking",
                extra={"session_id": session_id, "run_id": run_id, "error": type(exc).__name__},
            )
            await self._emit_block(session_id, run_id, reason="gate_exception", hit_count=0)
            raise EgressBlockedError(
                session_id=_clamp(session_id),
                reason="gate_exception",
                hit_count=0,
                run_id=None if run_id is None else _clamp(run_id),
            ) from exc

        return report

    # ------------------------------------------------------------------
    async def _run_passes(
        self,
        payload: str,
        session_id: str,
        surrogates: frozenset[str],
        run_id: str | None,
        started: float,
    ) -> tuple[EgressReport, list[str]]:
        """Run the three passes. Returns the report and the pass-2 warning TYPES.

        The types travel beside the report rather than on it because
        :class:`~secure_context_pipeline.models.EgressReport` is the shape the
        orchestrator turns into run stats, and a warning type is audit-trail
        material: it names what the gate saw, which is a question asked after the
        fact, by someone reading the log. See :meth:`_emit_pass`.
        """
        originals = self._vault.originals_for_session(session_id)

        # --- pass 1: known originals, raw and normalised -------------------
        # Offloaded to a worker thread, and that is a correctness fix rather than a
        # performance one. Two things were false while this ran inline:
        #
        # 1. :data:`DEFAULT_TIMEOUT_S` says it is a "budget for one whole check()".
        #    ``asyncio.timeout`` can only fire at a suspension point, and a synchronous
        #    CPU-bound loop has none, so the budget bounded pass 2 and nothing else.
        #    Measured: a 0.5 s budget against a 60k-original scan returned after
        #    **7.35 s**. With the await here, the budget is real for pass 1 too, which
        #    is what makes "hold the request open forever is not a safe answer" true
        #    rather than aspirational.
        # 2. The stall was process-wide, not request-local. This is an ASGI app, so a
        #    scan on the event loop is head-of-line blocking for every concurrent
        #    request: an unrelated coroutine observed a **7.36 s** scheduling gap
        #    during one gate check.
        #
        # The scan is pure -- it reads two immutable arguments and returns an int --
        # so there is nothing to synchronise. A thread cannot be killed mid-scan, so on
        # timeout the request is blocked at the budget while the worker finishes and is
        # discarded; that is the intended semantics, since the alternative is releasing
        # a payload whose scan never completed. Pinned by
        # ``test_the_timeout_bounds_pass_one_and_not_only_the_detector`` and
        # ``test_a_long_pass_one_does_not_stall_unrelated_coroutines``.
        # ``surrogates`` reaches pass 1 for ONE purpose: the cores of the tokens this
        # run emitted are not payload text, so the unbounded limbs must not read a
        # vaulted digit run out of an HMAC-derived token id and call it a leak. The
        # argument, the three narrowings that keep it exact-span, and why a pseudonym
        # in the same set is NOT exempted are all at :func:`_mask_own_tokens`.
        leaked_count = await asyncio.to_thread(self._scan_originals, payload, originals, surrogates)
        if leaked_count:
            await self._emit_block(
                session_id, run_id, reason="vault_original", hit_count=leaked_count
            )
            raise EgressBlockedError(
                session_id=_clamp(session_id),
                reason="vault_original",
                hit_count=leaked_count,
                run_id=None if run_id is None else _clamp(run_id),
            )

        # The spans that are our own output. Computed once and handed to both of the
        # payload-side passes: they ask different questions of the same text, and a
        # hole in one that is not a hole in the other would be a bug in the harder
        # direction to see.
        #
        # Built in two pieces rather than by re-running the matchers, so the two lists
        # cannot drift: ``protected`` is exactly ``bracketed`` plus the surrogate
        # occurrences. Pass 2 needs the split because only the bracketed half carries
        # the argument for excusing a merely-overlapping detection.
        bracketed = self._bracketed_spans(payload)
        protected = bracketed + self._surrogate_spans(payload, surrogates)

        # --- pass 2: detector re-scan, minus our own surrogates ------------
        blocked_types, warnings, warned_types = await self._rescan(payload, protected, bracketed)
        if blocked_types:
            types = _clamp(",".join(sorted(set(blocked_types))))
            await self._emit_block(
                session_id,
                run_id,
                reason="detector_rescan",
                hit_count=len(blocked_types),
                entity_types=types,
            )
            raise EgressBlockedError(
                session_id=_clamp(session_id),
                reason="detector_rescan",
                hit_count=len(blocked_types),
                entity_types=types,
                run_id=None if run_id is None else _clamp(run_id),
            )

        # --- pass 3: recognisers the detector does not use -----------------
        # Deliberately last, so a payload both passes object to keeps the pass-2
        # reason code it has always had and no existing expectation moves.
        independent = _independent_hits(payload, protected)
        if independent:
            types = _clamp(",".join(sorted(set(independent))))
            await self._emit_block(
                session_id,
                run_id,
                reason="independent_pattern",
                hit_count=len(independent),
                entity_types=types,
            )
            raise EgressBlockedError(
                session_id=_clamp(session_id),
                reason="independent_pattern",
                hit_count=len(independent),
                entity_types=types,
                run_id=None if run_id is None else _clamp(run_id),
            )

        return (
            EgressReport(
                payload_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                payload_chars=len(payload),
                originals_scanned=len(originals),
                rescan_warnings=warnings,
                elapsed_ms=(time.perf_counter() - started) * 1000.0,
            ),
            warned_types,
        )

    def _scan_originals(
        self, payload: str, originals: frozenset[str], surrogates: frozenset[str] = frozenset()
    ) -> int:
        """Count originals present in the payload. Never records WHICH value matched.

        Scans the payload with **one** exemption, and the exemption is exactly the
        eight-hex ids of the tokens this run emitted (:func:`_mask_own_tokens`, which
        carries the whole argument and the three narrowings it rests on). ``surrogates``
        defaults to empty, and with it empty this is byte-for-byte the scan it has
        always been -- the mask is the identity function, so a caller that does not
        supply the set gets the strict behaviour rather than a silent hole.

        **The exemption is a token-core exemption, not a surrogate exemption**, and
        that distinction is the lesson this docstring used to record as an absolute.
        An earlier version masked out its own surrogates *wholesale* so that a
        coincidental pseudonym collision would not block, and that was a mistake worth
        keeping: a fake drawn as "Rachel Medina" while "Medina" is a real original
        puts that surname verbatim on the wire, and masking the surrogate span *hid*
        the leak instead of explaining it. The 100-run harness caught it. A pseudonym
        is still scanned here, in full, for exactly that reason -- it is text a
        gazetteer chose, it can equal a real original, and only the *upstream*
        collision guard can make its absence true rather than assumed. What is
        exempted is a string every character of which is ours: a registry literal and
        an HMAC-derived id no uploader can steer.

        Pass 2 keeps its own wider skip-list because a *detector* re-hit on a
        well-formed fake is a different question from a byte-exact original.

        Each original is compared in five bounded forms -- seven haystacks, since two
        of them are derived under both mark selections -- and any one of them counts
        as a hit. Each additional form only ever *widens* the scan:

        1. **raw** -- the byte-exact value;
        2. **normalised** -- NFKC, whitespace collapsed, casefolded, so a splice bug
           that changed case or broke a value across a line still trips;
        3. **folded** -- normalised with every character that renders as nothing
           removed (:data:`_INVISIBLE_RE`) and every Unicode decimal digit rewritten
           in its ASCII spelling (:func:`_fold_decimal_digits`). The first half is
           invisible to a human reader and to the model, so ``Joh<U+200B>n Smith`` on
           the wire discloses exactly what ``John Smith`` discloses; without it, one
           zero-width space is a complete bypass of pass 1. The second half is
           visible and still the same disclosure: a vaulted MRN restated in
           Arabic-Indic or Devanagari digits is the same number, and NFKC does not
           fold those. That fold is applied to the needle as well, which is the one
           deliberate exception to the rule the next form states -- see
           :func:`_fold_decimal_digits` for why digits earn it and marks do not.
        4. **skeleton** -- the folded needle against a folded payload with every mark
           removed (:func:`_deaccent`, applied both before and after normalisation --
           see :func:`_skeleton`), which is what catches a mark spliced into a value.
           Derived **twice, under both definitions of "mark"** and compared against
           both (:func:`_skeleton_views`): the general category, which is the whole
           class of 2,408 and the one that sees a splice, and the canonical combining
           class, which is the 912-codepoint subset and the one that keeps the other
           1,496 as the word boundaries they are when they sit *beside* the value
           rather than inside it. Selecting on the category alone closed the first
           shape and opened the second; the union closes both and cannot regress
           either, since both are haystack-only folds of the same payload. Asymmetric
           on purpose: only the *haystack* is stripped, so ``José`` in the vault still
           does not match ``Jose`` on the wire. Skipped outright when the payload
           carries no mark at all, which is the common case and makes this form free
           there, and the second view is skipped again whenever it agrees with the
           first.
        5. **decoded** -- the folded needle against the skeleton of a payload whose
           percent-escapes, HTML character references and tags have been resolved
           (:func:`_decode_transport_escapes`). ``Marguerite%20Vandenberg`` is the
           whole vaulted name on the wire and no form above sees it, because every
           one of them keeps the separator and the separator-relaxing limb below
           allows only non-alphanumeric characters between components. Skipped
           outright when the payload carries no ``%``, ``&`` or ``<``, and again when
           decoding changed nothing.

        The first three are **not** redundant, and assuming they were is how the
        middle one nearly disappeared unnoticed: on text with no invisible characters,
        folded and normalised are the same needle against the same haystack, so a
        suite whose probes all satisfy two forms at once cannot see the third leave.
        Each has a payload only it can catch, named in a test of its own -- raw:
        ``test_the_raw_form_is_the_only_thing_that_sees_some_leaks`` (``Dr Smith℠``,
        where NFKC expands the symbol and glues an alphanumeric onto the needle in
        both derived forms); normalised:
        ``test_the_normalised_form_is_the_only_thing_that_sees_some_leaks`` (case
        changed, zero-width spaces on both sides, so folding glues the neighbours on);
        folded: the zero-width and default-ignorable parametrizations; skeleton:
        ``test_a_combining_mark_spliced_into_a_value_no_longer_reaches_the_provider``.

        Then, and only for a value that failed all four, the **unbounded identifier
        forms** (:func:`_identifier_needles`): a bare substring test with no adjacency
        requirement, for the digit runs whose disclosure a neighbouring character
        cannot undo. That is a separate step rather than a fifth entry in ``forms``
        because it is the one comparison that is *not* an occurrence-as-a-unit
        question, and writing it as one would hide that.

        Last, for a value that is a **composite** -- two or more values an English list
        glued into one span -- the same four bounded forms again, per constituent
        (:func:`_composite_needles`). A vaulted original is not always one value: the
        detector can hand the engine ``03/11/2024, 09/17/2024`` as a single span, and
        every question above is then being asked about a string the document contains
        but nobody wrote as a unit. Detection now splits that shape upstream
        (:func:`~secure_context_pipeline.daterules.split_composite_date`), which is the
        real fix; this limb is here because the gate's whole posture is that it does
        not trust detection, and "the detector no longer produces composites" is a
        claim about the detector. Constituents go through
        :func:`_occurs_in_any_bounded_form` -- the identical function the whole value
        uses -- so there is no separate question of which forms this limb compares in.

        O(payload x entities), with a C-level substring pre-filter in
        :func:`_occurs_as_a_unit` doing the rejecting; the scale answer is an
        Aho-Corasick automaton built incrementally per session (README Q1).
        """
        unmasked = payload
        payload = _mask_own_tokens(payload, surrogates)
        payload_norm = normalize(payload)
        payload_folded = _fold_decimal_digits(_strip_invisible(payload_norm))
        payload_skeleton, payload_boundary = _skeleton_views(payload)
        # Every mark-folded view of the payload, for the two limbs below that read a
        # skeleton directly rather than through `_occurs_in_any_bounded_form`. Both
        # of them used to read the one skeleton there was, and both inherit the
        # boundary defect `_skeleton_views` documents -- the separator limb through
        # `_occurs_as_a_unit`'s guards, the identifier limb through a needle that
        # carries a class-0 mark of its own and can only be found in a haystack that
        # kept it.
        decoded = _decode_transport_escapes(payload)
        if decoded is None:
            payload_decoded: str | None = None
            payload_decoded_boundary: str | None = None
        else:
            payload_decoded, payload_decoded_boundary = _skeleton_views(decoded)
            if payload_decoded == payload_skeleton:
                payload_decoded = None
            if payload_decoded_boundary == payload_boundary:
                payload_decoded_boundary = None
        # ONE tuple of every skeleton-family haystack, and every limb below iterates
        # THIS rather than picking its own subset.
        #
        # That is a fix for a class, not for the instance that exposed it. The
        # instance: `skeletons` held the two `_skeleton_views` forms and the decoded
        # views were offered separately, so the separator limb was handed
        # `decoded` and never `decoded_boundary` -- the one haystack that can see a
        # value whose payload carries BOTH a transport escape and a class-0 mark
        # beside it. Measured over 300,000 differential cases, that left 25 payloads
        # the pre-widening rule blocked and this code released:
        #
        #     vault  {'Nathaniel Brightwater'}
        #     wire   'Portal: /q?v=lab%20NathanielBrightwater<U+0903>Ref -- ...'
        #     combining-class rule : BLOCKED     shipped code : RELEASED
        #
        # The class: four haystacks and three limbs is twelve decisions to keep in
        # step by hand, and the eleven that were right made the twelfth invisible.
        # Iterating one tuple makes "which limb sees which haystack" unanswerable in
        # the wrong direction -- a new haystack reaches every limb the day it is
        # added, and a new limb gets all of them.
        #
        # The identifier limb gains the decoded views here too. It never had them
        # under any of the three behaviours, so it was not part of the regression,
        # but it is the same omission: a vaulted identifier written `%20`-separated
        # is a true occurrence, and finding it is what the decoded view is for.
        scan_skeletons: tuple[str, ...] = tuple(
            dict.fromkeys(
                form
                for form in (
                    payload_skeleton,
                    payload_boundary,
                    payload_decoded,
                    payload_decoded_boundary,
                )
                if form is not None
            )
        )
        haystacks = _Haystacks(
            raw=payload,
            normalized=payload_norm,
            folded=payload_folded,
            skeleton=payload_skeleton,
            marked=payload_skeleton != payload_folded,
            boundary_skeleton=payload_boundary,
            decoded=payload_decoded,
            decoded_boundary=payload_decoded_boundary,
        )
        payload_digit_views: tuple[str, ...] | None = None
        hits = 0
        for original in originals:
            if len(original.strip()) < MIN_ORIGINAL_LEN:
                continue
            if _occurs_in_any_bounded_form(original, haystacks):
                hits += 1
                continue
            folded = _fold_decimal_digits(_strip_invisible(normalize(original)))
            if any(
                needle in skeleton
                for needle in _identifier_needles(folded)
                for skeleton in scan_skeletons
            ):
                hits += 1
                continue
            # Offered BOTH the accent-preserving haystack and the deaccented one,
            # and the first is not optional: with only the skeleton, this limb was
            # dead for every original carrying a diacritic. The needle is
            # deliberately never deaccented (that is what keeps `José` and `Jose`
            # distinct values), so an accented component simply does not occur in a
            # deaccented haystack -- `_occurs_with_flexible_separator`'s substring
            # pre-filter rejected it before the regex ever ran. `José Ruiz` vaulted
            # from a clean mention reached the provider as `José-Ruiz` while the
            # unaccented control `Jose-Ruiz` blocked, which is the exact shape this
            # limb was added to close.
            #
            # Adding the folded haystack costs nothing and preserves the asymmetry:
            # needle `josé ruiz` still does not match a payload that says `jose
            # ruiz`, because the needle keeps its accent in both comparisons.
            #
            # And the DECODED haystack, because the limb's own claim -- that it
            # relaxes any spelling of the interior separator -- is false against a
            # separator that carries word characters (`%20`, `&nbsp;`, `<br/>`).
            # `_INTERIOR_SEPARATOR` is a character class and cannot span one. See
            # `_decode_transport_escapes` for the reproduction.
            if (
                _occurs_with_flexible_separator(folded, haystacks.folded)
                or any(
                    _occurs_with_flexible_separator(folded, s) for s in scan_skeletons
                )
            ):
                hits += 1
                continue
            regrouped = _regrouped_identifier_needle(folded)
            if regrouped is not None:
                if payload_digit_views is None:
                    payload_digit_views = _digit_views(payload_folded, unmasked, surrogates)
                if any(regrouped in view for view in payload_digit_views):
                    hits += 1
                    continue
            if any(
                _occurs_in_any_bounded_form(part, haystacks)
                for part in _composite_needles(original)
            ):
                hits += 1
        return hits

    async def _rescan(
        self, payload: str, protected: list[tuple[int, int]], bracketed: list[tuple[int, int]]
    ) -> tuple[list[str], int, list[str]]:
        """Re-detect on the payload, ignoring spans that are our own output.

        Takes the protected spans rather than the surrogate set because pass 3 needs
        the same list, and computing it twice would let the two passes disagree about
        what our own output is -- the exact class of divergence this module keeps
        finding in itself. ``bracketed`` is the subset of ``protected`` that carries
        the leniency argument below; see :meth:`_protected_spans` for why the two
        halves cannot share one rule.

        **This pass is not an independent opinion, and that is why pass 3 exists.**
        It runs the same ``Detector`` that ran at detect time, over text derived from
        the same document, so every blind spot it had then it has again here: a value
        no recogniser anchors on is invisible to detection, never vaulted, therefore
        invisible to pass 1, and invisible here for the third time. That is not a
        hypothetical -- see :data:`_INDEPENDENT_PATTERNS`. What this pass genuinely
        adds is a verdict on text the detector never saw in that arrangement: the
        assembled payload, where obfuscation, splicing and the system prompt have
        moved things around.

        Two properties of this pass are easy to misread, so both are stated here.

        **The detector runs over the whole payload, and the skip-list is applied to
        its output rather than to its input.** That ordering is the safe one and it
        was measured rather than assumed. Excising the protected spans first -- the
        obvious optimisation, and the one README Q1 used to promise -- changes what
        the detector finds in the text that *remains*: spaCy NER is conditioned on
        surrounding tokens, this project's own ``_resolve_builtin`` picks between
        claimant entity types using character-distance context windows, and removing
        ~23% of the payload's characters moves every chunk boundary. Measured across
        both strategies and three fixtures, the excised scan lost a finding the
        full-payload scan makes in four of six configurations and *gained* one in
        another, so it is a different scan, not a cheaper one. It is also worth
        little: protected spans cover 16-26% of a payload (not the ~95% previously
        claimed) and excision saves 5-6% of this pass, ~2% of end-to-end wall time.
        Finally, the protected-span set is partly derived by matching a grammar over
        the *uploaded document*, so letting it decide what the detector ever sees
        would hand an uploader a lever on the gate's input -- a strictly larger
        version of the two bypasses :meth:`_protected_spans` exists to close.

        **The re-scan asks with no category** (``doc_category`` is ``None``): the
        payload is not a document and carries no category, and claiming one would be
        guessing. **That used to cost a coverage gap and no longer does**, which is
        worth stating because this docstring asserted the opposite until the
        ``doc_category`` fail-open was closed. It read: "the cost is that entities
        declared ``only_in_doc_categories`` are not re-detected here -- today
        ``DATE``, ``AMOUNT``, ``CLIENT_IDENTITY`` and ``CASE_STRATEGY``." Since
        :meth:`Detector._scoped_types` returns the *union* of every category's rules
        on ``None`` rather than the unscoped subset, they are. Measured on a payload
        carrying one of each, the re-scan returns ``['AMOUNT', 'DATE', 'NAME']``: the
        scoped types come back, and ``CLIENT_IDENTITY`` resolves to ``NAME`` because
        both claim the same span and there is no legal category to prefer the legal
        type with -- a label difference, not a coverage one.

        The old sentence was stale in the *safe* direction (it under-claimed what
        pass 2 sees) and is corrected rather than deleted, because a comment that
        under-claims still teaches the next reader the wrong model of this pass.
        None of the four is in :data:`HIGH_SEVERITY_TYPES`, so no *blocking* decision
        turns on any of it either way, and pass 1 still covers every one of them that
        was vaulted. That last sentence is a claim about a *config file* made in a
        *source file*, which is exactly the shape that goes quietly stale, so
        ``test_no_high_severity_entity_is_scoped_out_of_the_rescan``
        re-derives both sets from the shipped registry and this constant and fails the
        day someone gives a high-severity entity an ``only_in_doc_categories``.

        **A detection is skipped on any overlap with a BRACKETED protected span, and
        only on containment for a surrogate one.** The lenient direction is the
        deliberate one for the bracketed halves: the detector legitimately returns
        spans a shade wider than ours -- it claims the whole ``[PII_NAME_1a2b3c4d]``
        including the closing bracket, while the protected core stops at the hash --
        so demanding containment there would false-block every tokenized run on its
        own placeholders, and a gate that blocks everything protects nothing. What
        makes that leniency affordable is that such a span is bounded on both sides by
        characters we chose: it is ``[`` plus one unbroken word run, so a value
        straddling its edge would have to be one the detector reads *through* our
        bracket or our category literal.

        **That argument does not extend to the surrogate limb, and applying it there
        released a high-severity finding.** A surrogate span is matched by bare string
        equality (:meth:`_protected_spans`) -- no bracket, no category literal, no
        minimum length -- so a pseudonym is spliced into the document's own prose with
        the document's own characters on both sides, and a longer value can straddle
        its edge with nothing anomalous about it. Measured on the shipped detector and
        registry: with ``5551234`` in the surrogate set, ``Vendor account 5551234567
        remains open.`` is ``ACCOUNT_NUMBER@1.00`` over ``[15:25]`` against a protected
        ``[15:22]``; the overlap excused it and the gate released a payload its own
        detector had just typed as a high-severity identifier. Containment is the right
        rule there and costs nothing the bracketed argument was buying: what pass 2 must
        never re-flag is text *we wrote*, and a detection reaching past the end of a
        string we wrote is by definition not that.
        ``test_a_high_severity_hit_outside_our_own_output_always_blocks`` already
        computes its oracle with containment over the emitted set, so this makes the
        gate agree with the property that was already being asserted of it.
        """
        detections = await self._detector.detect(payload, None)

        blocked: list[str] = []
        warned: list[str] = []
        for det in detections:
            # Two different questions, and they had one threshold between them.
            #
            # A high-severity re-hit is a *deny* decision, so it is floored at
            # ``threshold_redact`` -- the lowest score at which this pipeline
            # considers a span worth acting on at all. Everything else is a
            # *warning*, and stays at ``threshold_obfuscate``.
            #
            # Using ``threshold_obfuscate`` for both was a live release, not a
            # style point. It is the same number the engine bands on, so the two
            # blind spots coincided exactly: a value scoring in
            # ``[redact, obfuscate)`` is redacted (hence never vaulted, so pass 1
            # has no needle) and was then dropped here for the same numeric
            # reason. Measured on the shipped detector and registry: Presidio's
            # ``UsSsnRecognizer`` scores a bare nine-digit run at 0.05 and the
            # context enhancer floors a context-boosted hit at 0.40, so
            # ``Member SSN 452189376 verified against payer records.`` is typed
            # ``SSN@0.40`` -- and this gate released it while its own detector
            # said SSN. The perverse part is the direction: the more clearly the
            # document labelled the SSN, the less protected it was.
            #
            # The floor is ``threshold_redact`` rather than zero on purpose: it makes
            # the gate act wherever the ENGINE would have acted, which is the property
            # that closes the band. An unlabelled nine-digit run scores 0.05 and is
            # left alone, so an invoice or part number does not deny every payload it
            # appears in.
            #
            # What that does NOT mean -- and an earlier version of this comment
            # implied it -- is that a hit at or above the floor is the detector
            # "claiming it is an SSN". Presidio's score here is context-derived, and
            # :meth:`_protected_spans` exempts our own output from being a *finding*
            # but not from being *context*: a ``[PII_SSN_...]`` token or a
            # ``[REDACTED_SSN]`` marker this pipeline printed lifts any bare
            # nine-digit run in the same payload to 0.40 and denies the request.
            # Measured: 0 such denials across 64 corpus documents, because the
            # generator's nine-digit values are themselves planted entities and get
            # tokenised -- but a real document carrying a handled SSN *and* an
            # untyped claim or invoice number is denied. Fail-closed, and disclosed in
            # README section 7 rather than left for a reviewer to find.
            #
            # Pinned by ``test_a_high_severity_hit_in_the_redact_band_blocks``.
            floor = (
                self._settings.threshold_redact
                if det.entity_type in self._high_severity
                else self._settings.threshold_obfuscate
            )
            if det.score < floor:
                continue
            if _explained_by_our_output(det.start, det.end, protected, bracketed):
                continue
            if det.entity_type in self._high_severity:
                blocked.append(det.entity_type)
            else:
                # NER-typed re-hit: a fake name the generator produced contextually.
                # Logged, not blocked -- blocking here would make pseudonymization
                # unusable without improving the guarantee. The TYPE is kept because
                # the count alone is undiagnosable: ``egress_rescan_warnings 3`` on a
                # panel whose claim is "nothing original got out" reads as three near
                # leaks, and nothing recorded what they were. Types only, never
                # values, so the warning discloses nothing the payload did not.
                warned.append(det.entity_type)
        return blocked, len(warned), warned

    @staticmethod
    def _protected_spans(payload: str, surrogates: frozenset[str]) -> list[tuple[int, int]]:
        """Spans that are our own output: tokens, redaction markers, and surrogates.

        A protected span is a hole in pass 2 -- whatever it covers is never
        re-examined -- so it must cover our output and *only* our output. Two
        independent narrowings are needed to keep that true, because the outbound
        payload is assembled from an *uploaded document* and anything token-shaped in
        that document lands here too.

        **1. The grammar is the one we emit, not the one we tolerate.** The matcher
        is :data:`~secure_context_pipeline.surrogates.STRICT_TOKEN_RE` -- the exact
        shape :func:`~secure_context_pipeline.surrogates.format_surrogate` produces --
        and *not* the tolerant ``TOKEN_RE``. ``TOKEN_RE`` accepts wrong brackets, stray
        whitespace (including at both separators), any casing of the category, the
        entity type and the hash, and ``-`` where we write ``_``, and it accepts them
        for one reason: the restorer reads text an LLM mangled. Nothing on this path
        has been near an LLM. Every token in the payload was written by
        ``format_surrogate`` milliseconds earlier, so here the tolerance buys nothing
        and costs a hole -- one that was open and is worth naming exactly, because it
        is the same shape as the ``|hint`` bypass below, one field to the left. The
        hyphen is the whole mechanism: ``_`` is a regex word character and ``-`` is
        not, so writing the separator as ``-`` manufactures the ``\\b`` that
        ``ACCOUNT_NUMBER``'s pattern needs. An uploaded document containing::

            PII-ACCOUNT12345678-deadbeef

        is a 1.00-confidence ``ACCOUNT_NUMBER`` to the shipped detector, and the
        tolerant matcher excused all of it. Under the strict grammar a protected core
        is ``[`` followed by one unbroken run of word characters beginning with a
        category literal, so it contains no *interior* word boundary at all -- and
        every high-severity recogniser in play, the three registry patterns and
        Presidio's ``US_SSN``, anchors on ``\\b``. That last sentence is a claim about
        a config file and a third-party library, so it is not left as prose:
        ``test_a_high_severity_hit_outside_our_own_output_always_blocks`` runs the
        shipped detector over these shapes and demands the gate's verdict match what
        the detector actually found, which goes red if either side changes.

        **2. The span is the core, never the ``|hint`` tail.** The hint alphabet is
        ``[a-z0-9-]``, which spells an SSN, an EIN and a phone number, so a crafted
        upload containing::

            [PHI_NAME_deadbeef|123-45-6789]

        used to be absorbed as one token match and excluded from the re-scan
        wholesale -- and pass 1 is blind to it too whenever the detector missed that
        value in that odd context, so nothing was left looking at it. Bounding the
        hint to 24 characters shrinks the window; refusing to protect it removes it.

        Re-scanning our own hints costs nothing: a hint is a gazetteer class label we
        chose (``oral-antidiabetic``), not a value, so a detector hit on one is a
        finding worth having rather than a false positive worth suppressing.

        Neither narrowing can cost us a false block on a real token, and the reason is
        deliberately **not** "``format_surrogate`` validates its fields, so its output
        is a ``STRICT_TOKEN_RE`` match by construction". That argument is the tempting
        one and it is not what this rests on: it is a claim about one module's
        validators holding a property that this module needs, with nothing joining
        them. It was once false -- the validators anchored with ``$``, which in Python
        also matches just before a trailing newline, so ``"NAME\\n"`` was an accepted
        entity type that produced a token this matcher rejects, and ``load_registry``
        would take it from a config file. ``surrogates.py`` now anchors ``\\A``/``\\Z``
        and validates with ``fullmatch``, and ``load_registry`` calls
        ``validate_entity_type`` at load, so all three doors are shut.

        The history is recorded in README §8 rather than re-argued here, because a
        docstring that describes a *past* bug has to be re-verified on every refactor
        and nothing re-verifies it. What belongs here is the current contract.

        What the property actually rests on is the other leg: the orchestrator hands
        ``check()`` the exact surrogate strings this run emitted, and those are
        protected in full below by **string equality** -- a stronger claim than any
        regex, since the span then cannot absorb text we did not write, and one no
        grammar drift can weaken.
        ``test_a_surrogate_the_strict_grammar_rejects_is_still_protected`` pins that
        leg on a token this pattern does not recognise, so the mechanism is checked
        rather than asserted.

        The strict matcher is the belt to that pair of braces, and it is what protects
        the token printed in the tokenization system prompt, which belongs to no run.
        One thing it protects with no backstop at all is the **redaction marker**:
        markers are not in the surrogate set, so :data:`REDACTION_RE` is the only
        thing standing behind ``[REDACTED_<TYPE>]``. An entity name that grammar
        rejects leaves our own marker in the re-scan -- more scrutiny rather than
        less, and inert unless the name itself reads as a high-severity identifier --
        but it is a grammar-only guarantee, and the point of writing this down is that
        the token half is not.

        The list is unordered, and deliberately so: :func:`_overlaps` scans it in
        full for every detection, so a sort would cost O(n log n) per call and buy
        nothing. Ordering only starts to matter if that linear scan is ever replaced
        by a search, which is the change that should introduce the sort.

        **The two halves are also built separately**, because pass 2 does not apply
        the same overlap rule to both: see :meth:`_bracketed_spans` and
        :meth:`_rescan`. This method is the union of them, in that order, and it is
        what pass 3 uses -- there, every span is a string we wrote and the question is
        only whether a pattern hit is one of them.
        """
        return EgressGate._bracketed_spans(payload) + EgressGate._surrogate_spans(
            payload, surrogates
        )

    @staticmethod
    def _bracketed_spans(payload: str) -> list[tuple[int, int]]:
        """The half of :meth:`_protected_spans` whose edges are characters we chose.

        On the left, our ``[``; on the right, our token hash (the span stops at group
        3, before the closing bracket and any ``|hint``) or our closing bracket for a
        redaction marker. Both ends being ours is the whole of the argument
        that lets pass 2 skip a detection merely *overlapping* one: a value straddling
        such an edge would have to be one the detector read through our bracket or our
        category literal. Kept as its own list so the argument travels with the spans
        it is true of, rather than being applied to the surrogate half, where it is
        false.
        """
        spans: list[tuple[int, int]] = [
            (m.start(), m.end(3)) for m in STRICT_TOKEN_RE.finditer(payload)
        ]
        spans.extend(m.span() for m in REDACTION_RE.finditer(payload))
        return spans

    @staticmethod
    def _surrogate_spans(payload: str, surrogates: frozenset[str]) -> list[tuple[int, int]]:
        """Every occurrence of a string this run emitted. String equality, nothing else.

        No grammar and no minimum length: the orchestrator hands ``check()`` the exact
        surrogates the engine issued, so the span cannot absorb text we did not write.
        That strength is also the reason pass 2 demands *containment* against these --
        a fake is spliced into the document's own prose, so both of its edges are the
        document's characters and a longer value can straddle one with nothing
        anomalous about it.
        """
        spans: list[tuple[int, int]] = []
        for surrogate in surrogates:
            if not surrogate:
                continue
            idx = payload.find(surrogate)
            while idx != -1:
                spans.append((idx, idx + len(surrogate)))
                idx = payload.find(surrogate, idx + 1)
        return spans

    # ------------------------------------------------------------------
    async def _emit_pass(
        self,
        session_id: str,
        run_id: str | None,
        report: EgressReport,
        warned_types: list[str],
    ) -> None:
        """Record the release, including WHAT pass 2 warned about.

        ``rescan_warnings`` alone is undiagnosable and sits on a panel whose whole
        claim is "nothing original got out": ``egress_rescan_warnings 3`` reads as
        three near-misses, and until this row carried the types there was nowhere to
        look them up -- ``_rescan`` incremented a counter and dropped
        ``det.entity_type`` on the floor. Measured on the shipped medical fixture,
        the three are ``ADDRESS,ADDRESS,ADDRESS``: the detector re-typing "MD" and
        "RN" out of the pseudonymized clinician lines, which is a false positive
        rather than a near leak, and one nobody could see.

        Sorted, deduplicated and comma-joined, mirroring ``entity_types`` on the
        block path, and clamped to the audit detail ceiling the same way. **Types
        only, never values** -- an audit row that quoted the warned text would put
        payload content into the log the gate exists to keep values out of.
        """
        if self._audit is None:
            return
        await self._audit.emit(
            AuditEvent(
                ts=time.time(),
                session_id=session_id,
                run_id=run_id,
                event_type=EGRESS_PASS,
                detail={
                    # sha256 hex is exactly 64 chars -- fits the audit detail ceiling.
                    "payload_sha256": report.payload_sha256,
                    "payload_chars": report.payload_chars,
                    "originals_scanned": report.originals_scanned,
                    "rescan_warnings": report.rescan_warnings,
                    "rescan_warning_types": _clamp(",".join(sorted(set(warned_types)))),
                    "elapsed_ms": round(report.elapsed_ms, 3),
                },
            )
        )

    async def _emit_block(
        self,
        session_id: str,
        run_id: str | None,
        *,
        reason: str,
        hit_count: int,
        entity_types: str = "",
    ) -> None:
        """Record the block. **Never raises, and never blocks for long.**

        This runs on the way to raising ``EgressBlockedError``, so an exception
        escaping here would replace a well-typed block carrying its reason with
        whatever the audit layer threw. The call is stopped either way, but the
        caller (the API's 422 ``EGRESS_BLOCKED`` handler) would see an internal
        error instead of a block, and the reason code would be lost. The block
        itself is already guaranteed by the raise; recording it is best-effort, and
        a failure is loud in the process log.

        The write is bounded by :data:`AUDIT_EMIT_TIMEOUT_S` for the same reason it
        is wrapped at all. On the ``gate_exception`` path this coroutine is awaited
        from ``check()``'s exception handler, which sits *outside* the
        ``asyncio.timeout`` block, so an audit writer that hangs rather than fails
        used to hold the request open indefinitely with the block already decided.
        ``TimeoutError`` is an ``Exception``, so it lands in the same handler as any
        other audit failure and the block proceeds unchanged.
        """
        logger.warning(
            "EGRESS BLOCKED -- provider call suppressed",
            extra={
                "session_id": session_id,
                "run_id": run_id,
                "reason": reason,
                "hit_count": hit_count,
            },
        )
        if self._audit is None:
            return
        try:
            async with asyncio.timeout(AUDIT_EMIT_TIMEOUT_S):
                await self._audit.emit(
                    AuditEvent(
                        ts=time.time(),
                        session_id=_clamp(session_id),
                        run_id=None if run_id is None else _clamp(run_id),
                        event_type=EGRESS_BLOCK,
                        detail={
                            "reason": reason,
                            "hit_count": hit_count,
                            "entity_types": entity_types,
                        },
                    )
                )
        except Exception as exc:  # the block must survive an audit-layer failure
            logger.error(
                "egress block could not be audited; the block itself still stands",
                extra={
                    "session_id": session_id,
                    "run_id": run_id,
                    "reason": reason,
                    "error": type(exc).__name__,
                },
            )


def _clamp(value: str) -> str:
    """Trim an identifier to the shared 64-character detail ceiling.

    ``PipelineError`` refuses any detail string longer than this, so an oversized
    ``session_id`` would turn the ``EgressBlockedError`` construction itself into a
    ``ValueError`` -- the payload is still withheld, but the caller sees an internal
    error rather than ``EGRESS_BLOCKED`` and the reason code never reaches the audit
    trail.
    """
    return value[:MAX_DETAIL_VALUE_LEN]


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < s_end and end > s_start for s_start, s_end in spans)


def _explained_by_our_output(
    start: int, end: int, protected: list[tuple[int, int]], bracketed: list[tuple[int, int]]
) -> bool:
    """Whether a pass-2 detection is accounted for by something this pipeline wrote.

    Two rules, because the two kinds of protected span earn different ones and giving
    them one rule released a high-severity finding -- the argument is at
    :meth:`EgressGate._rescan`. A ``bracketed`` span (token core, redaction marker) is
    bounded by characters we chose, so any *overlap* excuses the detection. Everything
    else -- the surrogate occurrences, matched by bare string equality inside the
    document's own prose -- excuses it only by *containment*.

    ``bracketed`` is a subset of ``protected``, so the containment test covers the
    bracketed spans too; it is the weaker of the two there and never the deciding one.
    """
    if _overlaps(start, end, bracketed):
        return True
    return any(s_start <= start and end <= s_end for s_start, s_end in protected)


#: What each character of one of our own emitted **token ids** is rewritten to before
#: pass 1 reads the payload. See :func:`_mask_own_tokens`.
#:
#: An ASCII lowercase letter, and the three properties that make this one inert are
#: the reason it is not a more decorative choice:
#:
#: * it is **alphanumeric** under :data:`~secure_context_pipeline.textrules.ALNUM_RE`,
#:   which is the alphabet the word-boundary rule and ``_INTERIOR_SEPARATOR`` both
#:   key on, so a neighbour that was glued to a token is still glued to it and a
#:   neighbour that was bounded by our ``[`` is still bounded by it. The mask cannot
#:   move a boundary, in either direction;
#: * it is **not a digit**, which is the whole point -- the digit-run, whole-value and
#:   regrouped limbs read digits, and a token id's digits are what they were colliding
#:   with;
#: * it is **ASCII, NFKC-stable, casefold-stable, not a mark and not invisible**, so
#:   every derived haystack (``normalize``, :func:`_strip_invisible`,
#:   :func:`_fold_decimal_digits`, :func:`_skeleton_views`,
#:   :func:`_decode_transport_escapes`) leaves it exactly as it is, and an ASCII
#:   payload stays ASCII -- so none of their fast paths is lost.
#:
#: ``q`` rather than ``a`` or ``e`` because it is outside the hex alphabet the id it
#: replaces is drawn from, so a mask can never be read back as a token id, and no
#: English word runs it three times (:data:`MIN_ORIGINAL_LEN`). A vaulted original of
#: ``qqq`` would collide with the mask, which is a *block*, not a release.
_OWN_ID_MASK_CHAR: Final = "q"


def _own_token_mask(surrogate: str) -> str | None:
    """``surrogate`` with its 8-hex token id blanked, or ``None`` if it is not ours.

    ``None`` for every surrogate that is not a :data:`STRICT_TOKEN_RE` **fullmatch**,
    and that conjunction -- *in the emitted set* **and** *shaped like a token we
    emit* -- is the whole safety argument of the exemption; :func:`_mask_own_tokens`
    states it. Neither half is dropped for the other's sake: the set alone would
    exempt pseudonyms, the grammar alone would exempt anything token-shaped in the
    uploaded document.

    **The span is group 3 and nothing else** -- the id, not the whole token core that
    :meth:`EgressGate._bracketed_spans` protects in pass 2. The exemption is only as
    defensible as the argument that the exempted characters cannot carry a secret, so
    it is cut to exactly the field that argument is about:
    :func:`~secure_context_pipeline.crypto.keys.derive_token_id` is an HMAC under the
    session key, truncated to eight hex characters -- unsteerable, unpredictable, and
    carrying no projection of the original. Every other field keeps being read:

    * the **category and type literals** (``PII``, ``ACCOUNT_NUMBER``) are ours, but
      they are ours by *configuration*, and a vault holding a value spelled like a
      registry type is a coincidence this gate can keep blocking on for free -- see
      :func:`_mask_own_tokens` for the measurement, which is why this is a residual
      rather than a second exemption;
    * the ``|hint`` tail, which is :meth:`EgressGate._protected_spans` narrowing 2 and
      is *stronger* here than it is there: the hint alphabet ``[a-z0-9-]`` spells an
      SSN, and a hint is looked up **by the original's own text**
      (``StrategyBase.hint_for`` passes ``detection.text`` to the gazetteer), so it is
      the one field of a token that is derived from the value. Masking it would be
      masking a projection of the secret;
    * our ``[``, ``_`` and ``]``, which are the boundary characters every occurrence
      test keys on.

    Per-character rather than ``_OWN_ID_MASK_CHAR * 8`` so that the mask preserves
    :data:`~secure_context_pipeline.textrules.ALNUM_RE` class per character even if
    the id alphabet ever admits something that is not alphanumeric; today ``[0-9a-f]``
    makes the two spellings identical.
    """
    match = STRICT_TOKEN_RE.fullmatch(surrogate)
    if match is None:
        return None
    start, end = match.start(3), match.end(3)
    masked = "".join(
        _OWN_ID_MASK_CHAR if ALNUM_RE.match(ch) else ch for ch in surrogate[start:end]
    )
    return surrogate[:start] + masked + surrogate[end:]


def _mask_own_tokens(payload: str, surrogates: frozenset[str]) -> str:
    """The payload with our own emitted token IDs blanked, for pass 1 only.

    **The defect this closes.** The unbounded limbs -- :func:`_identifier_needles` and
    the regrouped digit skeleton -- have no adjacency or boundary requirement, which
    is exactly what lets them catch a regrouped or glued identifier. So they read our
    own surrogates as if they were payload text, and a token id is eight hex
    characters whose digits sometimes *are* the vaulted digits::

        vault  {'8390244'}
        wire   'Account [FIN_ACCOUNT_NUMBER_8390244f] closed.'   -> 1 hit
        vault  {'552140'}
        wire   'Chart: [PHI_MRN_a552140f] reviewed.'             -> 1 hit

    Both are ``EgressBlockedError(reason="vault_original")`` on a run in which
    nothing leaked: the caller is told its own correct output is a PII leak. The
    per-landing-site arithmetic is at :data:`MIN_IDENTIFIER_RUN_DIGITS`
    (~1.8e-7 for a six-digit needle in one 8-hex id); the rate that made it worth
    fixing is an *observation* rather than a derivation from that -- 1.3e-02 spurious
    blocks per 100-run suite, seen twice in 27 executions of the leakage harness --
    and it is recorded here as one, because nothing in this file re-derives it.

    **What this removes is the landing sites that are ours, which is not the whole
    channel**, and the difference is measured rather than glossed. Two limbs read
    digits without an adjacency rule, and they have very different surfaces: the
    identifier needle looks *inside one 8-hex id* (all of which this now blanks), and
    the regrouped needle looks inside the payload's whole digit stream -- **7,078
    digits** on the shipped corpus's 104 documents, of which our token ids are around
    2%. So a vaulted all-digit value can still meet its own digits by coincidence in
    the *document's* dates, amounts and figures, and that is untouched here: measured
    over those 104 documents with every planted value tokenised out, zero spurious
    digit-stream hits either way. What this function is entitled to claim is the
    narrow thing: the pipeline no longer blocks a run because of a string the pipeline
    itself wrote.

    **Why an exemption is defensible in pass 1 at all**, given that
    :meth:`EgressGate._scan_originals` spent years arguing the opposite. The argument
    it was making is about *pseudonyms* and it is still correct: a fake drawn as
    ``Rachel Medina`` while ``Medina`` is a real original puts that surname verbatim
    on the wire, and exempting the fake **hides a real leak**. The 100-run harness
    caught that once already. Nothing here relaxes it -- a pseudonym is not a
    :data:`STRICT_TOKEN_RE` fullmatch, so :func:`_own_token_mask` returns ``None`` for
    it and pass 1 reads it exactly as it always has.

    What the **id** has and a pseudonym does not is that it is a projection of nothing:
    :func:`~secure_context_pipeline.crypto.keys.derive_token_id` is an HMAC under the
    session key truncated to eight hex characters. An uploader cannot steer it, cannot
    predict it and cannot encode anything in it -- so a needle found inside one is a
    coincidence with a random string, never a disclosure, and re-drawing the id makes
    the hit go away. That last sentence is the *test* this rests on rather than a
    figure of speech: the differential fuzz classifies every case the exemption
    releases by re-drawing the id 16 times from the same distribution and demanding
    the pre-exemption scanner agree each time.

    "Cannot steer it" is worth one line of adversarial arithmetic rather than
    assertion, since the id *is* a function of a value an uploader chooses:
    ``HMAC-SHA256(session_key, entity_type || 0x00 || normalize(value))`` truncated
    to 32 bits. Choosing the input does not choose the output without the key, so
    aiming one id at another value's digits is a 2^32 search against a secret,
    per-session key with one upload per attempt -- and what it would buy is that pass
    1 stops reading **eight characters** that are on the wire either way. It buys
    nothing about the target value itself: if that value is anywhere else in the
    payload, every limb still finds it there, which is what the placement tests pin.

    **Three narrowings keep that true**, and each one is a hole if it is dropped:

    1. **String equality against the emitted set, never a grammar over the payload.**
       The strings blanked are the ones the orchestrator hands ``check()``, i.e. the
       ones this run actually spliced in. A grammar-only rule would let an *uploaded
       document* carry token-shaped text and have pass 1 skip it -- the payload is
       assembled from a document the uploader wrote.
    2. **The grammar as well as the set**, which is the narrowing in the other
       direction: it is what keeps the pseudonym half of the same set scanned.
    3. **Exact span, and the span is the ID.** Not the token, not the core pass 2
       protects: only group 3 of the string we emitted (:func:`_own_token_mask`). The
       replacement is per-character and length-preserving and every other character --
       our ``[``, our ``_``, the literals, the ``|hint`` tail, our ``]`` -- is kept
       verbatim, so the mask is the same *shape* as what it replaces and no boundary
       anywhere in the payload moves or changes class. That is what makes this a hole
       of exactly eight characters per token and not one more: a vaulted value beside
       a token, glued to a token, straddling its bracket, or split across it is still
       read by every limb. Pinned by
       ``test_a_vaulted_value_glued_to_our_own_token_still_blocks``.

    **What the fuzz found the exemption also removes**, stated because it is a real
    behaviour change and not the headline one: a *letter-carrying* identifier whose
    digits the payload regroups -- ``K563704`` vaulted, ``5637-04`` on the wire -- was
    sometimes blocked by an id collision and now is not. No limb covers that shape on
    purpose (:func:`_regrouped_identifier_needle` refuses a value with letters in it,
    because identifier shapes collide by prefix), so the block was never the rule
    working; it was the rule being wrong in a lucky direction. 46 cases in 120,000
    differential ones, every one of them gone when the id is re-drawn.

    **What that leaves open, measured rather than argued.** A vaulted value spelled
    like a category or an entity type -- ``ACCOUNT_NUMBER``, ``NAME``, ``PII`` -- is
    word-bounded inside every token of that type (``_`` is a boundary,
    :data:`~secure_context_pipeline.textrules.ALNUM`), so pass 1 still blocks on it.
    That is the pre-existing behaviour and it is deliberately not fixed here: the
    literals are ours by *configuration*, which is a weaker claim than the HMAC one
    and not one worth spending an exemption on. Over the shipped registry's 20 entity
    types times four categories -- every token core the pipeline can emit -- and the
    10,355 originals the generator plants across 26 seeds x 4 kinds, the number of
    planted values that occur word-bounded in any of them is **zero**. Pinned by
    ``test_the_id_only_exemption_leaves_the_registry_literals_scanned``.

    **Redaction markers are deliberately NOT exempted**, though they are the other
    half of :meth:`EgressGate._protected_spans`. Two reasons, and the first is
    decisive:

    * a marker is protected there by :data:`REDACTION_RE` **alone** -- markers are not
      in the surrogate set, so there is no string-equality leg to stand on, and a
      grammar-only exemption in pass 1 is precisely the hole narrowing 1 exists to
      refuse. ``REDACTION_RE``'s type body is ``[A-Z][A-Z0-9_]*``, so an uploaded
      document containing ``[REDACTED_MRN5567281]`` would blank a vaulted MRN. The
      marker grammar is guessable in a way an HMAC id is not, which is the entire
      difference between the two halves;
    * a marker carries no hex and therefore none of the collision this function
      exists to remove. ``[REDACTED_<TYPE>]`` is a registry type name, so the only
      value it can collide with is one that *is* a bounded word of that name --
      measured over the shipped registry and generator corpus: zero.

    Scanning our own markers costs a block we could have avoided only for a vault
    holding a value spelled like an entity type, which is the direction this gate is
    allowed to be wrong in. ``test_pass_one_still_reads_inside_a_redaction_marker``
    pins the refusal.

    **THE SIBLING INSTANCE THIS DOES NOT CLOSE, named here because closing one half
    of a two-instance defect and calling it fixed is how it comes back.** The leakage
    harness scans the outbound payload with its *own* independently derived scan
    (``tests/leakage/test_leakage_harness.py::find_in_text``, applied to
    ``sent_payload`` in ``test_no_original_ever_leaves_the_process``), and that scan
    carries the same unbounded identifier and digit-skeleton limbs with **no surrogate
    exemption at all**. Verified, not inferred -- on the two payloads at the top of
    this docstring it returns ``['8390244']`` and ``['552140']``. So the same
    coincidence that used to stop the run here now reaches the harness's assertion
    instead, and reads as *"original present in the outbound payload"*, which is a
    worse-looking red for the same non-event. That file belongs to the harness and the
    fix belongs there rather than here, and it is deliberately **not** "import
    ``_mask_own_tokens``": a checker that inherits the exemption from the code it
    checks has stopped being a second opinion. What it needs is its own exclusion,
    derived from the ``TokenRecord``s the run issued.

    Cost: one ``str.replace`` pass per emitted token, all at C level, and skipped
    outright when the run emitted nothing (redaction-only runs, and every existing
    caller that passes no surrogates -- for which this is the identity function and
    pass 1 is byte-for-byte the scan it always was). Measured on a 54 KB payload
    carrying 251 distinct tokens in 230 places: **3.5 ms** for this function, and
    **38.6 ms -> 51.5 ms** for a whole pass 1 over 202 originals. The rest of that
    difference is the second digit view (:func:`_digit_views`), which is the other
    half of the exemption and is priced there.
    """
    if not surrogates:
        return payload
    masked = payload
    # Longest first, so a token that is a substring of another (a hinted token
    # contains no other token, but nothing here depends on that) is not blanked out
    # from under the longer one. A surrogate we fail to blank is the old behaviour,
    # which is the strict direction.
    for surrogate in sorted(surrogates, key=len, reverse=True):
        replacement = _own_token_mask(surrogate)
        if replacement is None:
            continue
        masked = masked.replace(surrogate, replacement)
    return masked


def _strip_own_tokens(payload: str, surrogates: frozenset[str]) -> str:
    """The payload with our own emitted tokens **removed**, hint and all.

    Deletion rather than masking, and for exactly one consumer: the digit stream
    :func:`_digit_views` builds. Deleting text is not safe in general -- it glues the
    neighbours together and takes a word boundary with them, which is the defect
    :func:`_skeleton_views` exists to work around -- but the digit stream has no
    boundaries to lose. :func:`_digits_only` already discards every non-digit
    character, so removing a whole token from it and removing only that token's
    digits are the same operation, and neither can move anything else.

    Same membership test as :func:`_mask_own_tokens`: emitted **and** a
    :data:`STRICT_TOKEN_RE` fullmatch. A pseudonym's digits stay in the stream, since
    a fake is not covered by the argument that makes any of this safe.
    """
    stripped = payload
    for surrogate in sorted(surrogates, key=len, reverse=True):
        if _own_token_mask(surrogate) is None:
            continue
        stripped = stripped.replace(surrogate, "")
    return stripped


def _digit_views(folded: str, unmasked: str, surrogates: frozenset[str]) -> tuple[str, ...]:
    """Every digit stream :func:`_regrouped_identifier_needle` is compared against.

    A **union of two views**, never a swap -- the pattern :func:`_skeleton_views` uses
    for the same reason: each view sees a payload the other cannot, and OR-ing two
    projections of one payload can only ever add hits.

    1. **The masked payload's digits.** Our token ids are gone (they are what the
       exemption is for), and everything else -- including a ``|hint``'s digits -- is
       still payload. That view is what keeps the ``|hint`` bypass closed here: a hint
       spelled ``123-45-6789`` and a vaulted ``123456789`` are found by *no other
       limb*, since the bounded forms want the separators and the identifier needle
       wants them absent.
    2. **The payload with our tokens deleted outright.** Necessary because view 1
       leaves our own non-id digits in the stream, and they can *break* a genuine
       disclosure rather than create one. Measured, and this is the whole reason this
       function exists rather than a single stream::

           vault  {'987714668699'}
           wire   'ledger filed 98771466869[PII_ADDRESS_989aa4fe|lab-panel-3]9 ...'

       The value's twelve digits are all there, split by one of our tokens. With only
       view 1, the ``3`` of ``lab-panel-3`` lands between them and the needle is
       absent. The pre-exemption scanner blocked this payload -- but only by luck:
       it was reading the ``9`` out of the id, and the same payload with the id
       ``c3f7003f`` was released. So view 2 is not a concession to the old behaviour,
       it is the answer the old behaviour was reaching by accident.

    The second view costs a deletion pass plus a ``normalize`` over the payload, and
    is built at most once per scan, lazily, and only when some vaulted value has a
    regrouped needle at all -- i.e. only for an all-digit original carrying
    :data:`MIN_IDENTIFIER_DIGITS` digits. It is skipped entirely when the run emitted
    no tokens, and de-duplicated when the two views agree. Measured on the payload
    :func:`_mask_own_tokens` prices -- 54 KB, 251 tokens, 202 originals of which 200
    have a regrouped needle, i.e. the worst case for this path: 4.2 ms for
    :func:`_strip_own_tokens` and ~5 ms for the projection, inside a pass 1 that goes
    from 38.6 ms to 51.5 ms once the whole exemption is on.
    """
    views = [_digits_only(folded)]
    if surrogates:
        excised = _strip_own_tokens(unmasked, surrogates)
        if excised != unmasked:
            views.append(_digits_only(_fold_decimal_digits(_strip_invisible(normalize(excised)))))
    return tuple(dict.fromkeys(views))


#: Characters that render as nothing, so a value carrying one discloses exactly what
#: the clean value discloses -- ``John`` and ``Joh<U+200B>n`` are the same disclosure
#: to any reader and to the model. Stripping them before the folded comparison closes
#: what is otherwise a **one-character complete bypass** of pass 1.
#:
#: The set is defined by a Unicode property rather than by taste: every general
#: category ``Cf`` (format) codepoint, plus every non-``Cf`` member of
#: ``Default_Ignorable_Code_Point`` -- variation selectors, the Hangul and Khmer
#: fillers, the combining grapheme joiner. A hand-picked list is the wrong shape here
#: and shipped as one: it named the bidi *overrides* (U+202A-U+202E) but not the bidi
#: *isolates* (U+2066-U+2069) that replaced them, and it named no tag character at
#: all, so ``Joh<U+E0041>n Smith`` -- the standard ASCII-smuggling vector -- walked
#: through the fold and out to the provider. 145 format codepoints were uncovered.
#:
#: Widening only ever *widens*: a stripped form is one more needle OR'd into the
#: comparison in :meth:`EgressGate._scan_originals`, never a replacement for the raw
#: one, so nothing that blocked before stops blocking. It is bounded in the other
#: direction too -- no letter, digit, space or combining *diacritic* is in here, so
#: ``Jos\u00e9`` and ``Jose`` remain different values.
#:
#: Ranges are widened to whole reserved runs (U+2060-U+206F, U+FFF0-U+FFFB,
#: U+13430-U+1343F, U+E0000-U+E0FFF) so a Unicode release that assigns a format
#: character inside one is covered the day it lands rather than the day someone
#: notices. ``test_every_unicode_format_character_is_folded`` re-derives the ``Cf``
#: set from :mod:`unicodedata` and fails on anything this class still misses -- the
#: expectation comes from the Unicode database, not from a copy of this literal.
#:
#: That sweep can only see the ``Cf`` half, because Python ships no
#: ``Default_Ignorable_Code_Point`` query, and the other half is where a hand-picked
#: list actually goes wrong: a variation selector is ``Mn`` and ``U+3164`` is
#: classed as a *letter*, so neither looks like a control to anyone reading this.
#: ``test_every_default_ignorable_code_point_is_folded`` covers them from a
#: transcription of the standard's own ``DerivedCoreProperties`` ranges.
#:
#: Written as escapes on purpose: a literal zero-width character in this source file
#: would be invisible to the next reader of the very guard that removes it.
_INVISIBLE_RE = re.compile(
    "["
    r"\u00ad"  # soft hyphen
    r"\u034f"  # combining grapheme joiner
    r"\u0600-\u0605\u06dd\u070f\u0890-\u0891\u08e2"  # Arabic/Syriac subtending marks
    r"\u061c"  # Arabic letter mark
    r"\u115f-\u1160"  # Hangul choseong/jungseong fillers
    r"\u17b4-\u17b5"  # Khmer inherent vowels
    r"\u180b-\u180f"  # Mongolian variation selectors + vowel separator
    r"\u200b-\u200f"  # zero-width space/joiners, LRM, RLM
    r"\u202a-\u202e"  # bidi embeddings and overrides
    r"\u2060-\u206f"  # word joiner, invisible operators, bidi isolates, deprecated
    r"\u3164"  # Hangul filler
    r"\ufe00-\ufe0f"  # variation selectors 1-16
    r"\ufeff"  # zero-width no-break space / BOM
    r"\uffa0"  # halfwidth Hangul filler
    r"\ufff0-\ufffb"  # reserved + interlinear annotation anchors
    r"\U000110bd\U000110cd"  # Kaithi number signs
    r"\U00013430-\U0001343f"  # Egyptian hieroglyph format controls
    r"\U0001bca0-\U0001bca3"  # shorthand format controls
    r"\U0001d173-\U0001d17a"  # musical beam/phrase controls
    r"\U000e0000-\U000e0fff"  # language tags, tag characters, VS supplement
    "]"
)


def _strip_invisible(value: str) -> str:
    return _INVISIBLE_RE.sub("", value)


#: Characters that RENDER as a diacritic but are not combining marks -- U+00B4
#: ACUTE ACCENT, U+00A8 DIAERESIS, U+02D8 BREVE and the rest of the spacing
#: modifier block. Identified by their compatibility decomposition, which is a
#: space followed by the combining mark they draw: ``<compat> 0020 0301``. That is
#: the definition rather than a hand-picked list, so a codepoint added by a future
#: Unicode release is covered the day it lands.
def _is_spacing_diacritic(ch: str) -> bool:
    return unicodedata.decomposition(ch).startswith("<compat> 0020 ")


def _strip_spacing_marks(value: str) -> str:
    """``value`` with spacing diacritics removed. Applied to the HAYSTACK only.

    :func:`_deaccent` folds *marks* and closes the splice it was written
    for. It cannot close this one, and the reason is an ordering problem rather
    than an oversight: by the time ``_deaccent`` runs, the payload has been through
    NFKC, which expands ``U+00B4`` into a space plus a combining acute. Stripping
    the mark then leaves the **space** behind, so ``Nathan<U+00B4>iel`` becomes
    ``nathan iel`` -- a different string from ``nathaniel``, and one no later form
    recovers. Measured on the real gate: a vaulted ``Nathaniel Brightwater`` and a
    vaulted ``MRN 5567281`` both reached the provider through four spacing marks
    while the combining-mark control blocked.

    So this runs on the RAW payload, before ``normalize``, and removes the
    character outright rather than letting NFKC turn it into whitespace.

    Asymmetric for the same reason :func:`_deaccent` is: only the haystack is
    stripped, so a vaulted value that legitimately contains a modifier letter is
    still a distinct value from one that does not.
    """
    if not any(_is_spacing_diacritic(ch) for ch in value):
        return value
    return "".join(ch for ch in value if not _is_spacing_diacritic(ch))


def _is_mark(ch: str) -> bool:
    """Whether ``ch`` is a mark -- the general category, i.e. the whole class.

    2,408 codepoints in this interpreter's database, and this is the selection
    :func:`_deaccent` uses by default. See :func:`_is_reordering_mark` for the other
    one and :func:`_skeleton_views` for why the module needs both rather than the
    wider one alone.
    """
    return unicodedata.category(ch)[0] == "M"


def _is_reordering_mark(ch: str) -> bool:
    """Whether canonical ordering *reorders* ``ch`` -- combining class not 0.

    A strict subset of :func:`_is_mark`: every one of the 2,408 category-``M``
    codepoints answers :func:`unicodedata.combining` with something, 912 of them with
    a non-zero class, and **no codepoint outside category ``M`` has a non-zero class
    at all** (measured over the full 0x110000 range on Unicode 14.0.0, the version
    this interpreter carries). So this selects 912 marks and nothing else, and
    ``_is_reordering_mark(ch)`` implies ``_is_mark(ch)``.

    That containment is the whole reason this predicate is kept rather than deleted
    as the superseded one. Removing a mark is not a pure widening -- see
    :func:`_skeleton_views`.
    """
    return unicodedata.combining(ch) != 0


def _deaccent(value: str, *, is_mark: Callable[[str], bool] = _is_mark) -> str:
    """``value`` with every mark (general category ``M``) removed. HAYSTACK only.

    :data:`_INVISIBLE_RE` folds characters that render as nothing and deliberately
    stops short of combining diacritics, because a diacritic is *visible* and
    ``José`` and ``Jose`` are two different people. That reasoning is right about the
    needle and wrong about the haystack, and the gap it left was reproduced
    end-to-end rather than argued about: ``Nathaniel Brightwater`` was detected and
    vaulted from a clean mention, a second mention carrying one U+0301 between the
    two names was missed by NER (so never independently vaulted), and it reached the
    provider reading identically to ``Nathaniel Brightwater`` for any human and for
    the model. NFKC does not help -- it *composes*, so ``l`` + U+0301 becomes ``ĺ``,
    which is simply a different letter.

    Stripping only the payload is what makes this safe to add. The comparison
    ``needle in deaccent(payload)`` fires when a mark was spliced into a mark-free
    vaulted value -- the demonstrated attack -- and does not fire when the payload
    legitimately says ``Jose`` and the vault holds ``José``, because the needle keeps
    its accent and ``josé`` is not a substring of ``jose``. Stripping both sides
    would collapse those two into one value and manufacture false blocks on any
    document carrying both spellings, which is the trade
    ``tests/leakage/test_leakage_harness.py`` names and refuses.

    What the asymmetry costs, said plainly: a vaulted value that *itself* carries a
    mark (``José Ruiz``) is not protected against a second mark being spliced into
    it, because the needle is never stripped. That is a strictly smaller residual
    than the one it replaces, and closing it needs the same confusables table the
    homoglyph gap needs.

    NFD-then-strip-then-NFC rather than a character class: the mark can arrive
    precomposed (``ĺ``, U+013A) or as a base plus U+0301, and only decomposition
    makes those the same question. Two fast paths return ``value`` itself. An ASCII
    string cannot contain a mark and is its own NFD, so it never enters the
    decomposition at all -- ``str.isascii`` is a flag check on the string object, the
    same one :func:`_fold_decimal_digits` opens with, and it matters because
    :func:`_skeleton` calls this twice per haystack: on a 63 KB ASCII payload the
    second call was 31 ms of guaranteed-nothing. The wider path returns ``value``
    when decomposition finds no mark, which is every non-ASCII payload not carrying
    one, without touching NFC.

    **"Is this a mark" is the general category, not the canonical combining class,
    and for two years this function asked the wrong one.** It selected on
    :func:`unicodedata.combining`, which answers "how does this codepoint reorder
    under canonical ordering" -- a question 1,496 of the 2,408 category-``M``
    codepoints in this interpreter's Unicode database answer with ``0`` (1,063
    ``Mn``, 420 ``Mc``, 13 ``Me``). Every one of them survived the fold untouched,
    so the whole class the module docstring called closed was closed for the
    subset of marks that happen to reorder. Measured on the real gate, one mark
    spliced into a vaulted ``Nathaniel Brightwater``: U+0301 (ccc 230) and U+0316
    (ccc 220) blocked, while U+0E31 THAI CHARACTER MAI HAN-AKAT (``Mn``, ccc 0),
    U+0903 DEVANAGARI SIGN VISARGA (``Mc``, ccc 0) and U+20DD COMBINING ENCLOSING
    CIRCLE (``Me``, ccc 0) all walked the vaulted original to the provider with
    ``EGRESS_PASS`` recorded. The selection is now ``category()[0] != "M"``, which
    is the property the docstring always claimed.

    The asymmetry is unaffected by the widening -- only the haystack is stripped
    either way, so ``José``/``Jose`` stay distinct, which is pinned by
    ``test_the_skeleton_form_does_not_collapse_jose_and_jose``.

    **The widening was not free, and ``is_mark`` is what pays for it.** Deleting a
    character is not a pure widening of a scan whose occurrence test is a
    *word-boundary* rule: a mark sitting immediately before or after a value was a
    non-alphanumeric character, i.e. a valid boundary, and removing it glues the
    value to the neighbouring run so that :func:`_occurs_as_a_unit` then rejects the
    very occurrence this fold exists to find. The caller therefore derives the
    haystack under **both** selections and compares against both; see
    :func:`_skeleton_views` for the measured regression and the union argument.
    """
    if value.isascii():
        return value
    decomposed = unicodedata.normalize("NFD", value)
    stripped = "".join(ch for ch in decomposed if not is_mark(ch))
    if len(stripped) == len(decomposed):
        return value
    return unicodedata.normalize("NFC", stripped)


#: The characters that can begin a transport escape of a separator. A payload
#: carrying none of them decodes to itself, so :func:`_decode_transport_escapes`
#: can return ``None`` without touching it.
_TRANSPORT_ESCAPE_HINT_RE: Final = re.compile(r"[%&<]")

#: One HTML/XML tag, collapsed to a space rather than to nothing: ``<br/>`` between
#: two components of a name is a rendered *break*, so the space is the faithful
#: reading and it is also the one that keeps the four bounded forms able to see the
#: result (``Marguerite Vandenberg``, not ``MargueriteVandenberg``). ``[^<>]`` so a
#: stray ``<`` in prose cannot make this span half a paragraph.
_MARKUP_TAG_RE: Final = re.compile(r"<[^<>]*>")


def _decode_transport_escapes(value: str) -> str | None:
    """``value`` with percent-escapes, character references and tags decoded.

    Applied to the HAYSTACK only, like every other fold here except the digit one.

    **The shape this closes, and why the module's residual gap 2 was the wrong
    half of the question.** That gap files "a lossy or re-writing encoding layer
    applied to outbound text" as unreachable because *this pipeline applies none*.
    That is true and it is beside the point: the encoding does not have to be
    applied on the way out, it only has to be **present in the uploaded document**,
    which is user-controlled input the pipeline then transports verbatim exactly as
    advertised. ``%20`` in a portal URL and ``&nbsp;``/``&#32;``/``<br/>`` in
    anything round-tripped through HTML or Word are ordinary spellings of a space in
    an ordinary ``.md``, ``.txt`` or ``.docx`` upload.

    Reproduced end to end before this was written, on a one-page encounter note:
    ``Marguerite Vandenberg`` was detected, vaulted and tokenised out of the
    ``Patient:`` line, and the same whole name rode out to the provider inside
    ``?patient=Marguerite%20Vandenberg&view=summary`` -- with ``orchestrator.run``
    returning normally, the provider called once, ``egress_rescan_warnings`` at
    zero and the API returning 200. Under pseudonymization it is worse than a leak:
    the prose says ``Megan Padilla`` while the URL in the same payload says
    ``Marguerite%20Vandenberg``, so the model is handed the real identity *and* a
    decoy.

    **Why this is a haystack fold rather than a wider separator class.**
    :func:`_separator_needles` already relaxes the interior separator, but
    :data:`_INTERIOR_SEPARATOR` is a character class and no character class can span
    ``%20`` or ``&nbsp;`` -- each carries word characters. Widening the class to
    admit alphanumerics is the wrong repair: it would make ``John Smith`` match
    ``JohnQSmith``. Decoding the payload instead keeps the needle untouched, which
    is what keeps every asymmetry this module depends on.

    **What it costs, measured on a 36 KB clinical payload** rather than argued from
    the shape of the code, because this is a second full haystack derivation and
    those are the expensive part of pass 1:

    * no ``%``, ``&`` or ``<`` anywhere -- 0.28 ms, one regex search, ``None``;
    * ``&`` and ``<`` present but nothing actually decodes (``Smith & Jones``,
      ``Dose < 5 mg``: no valid entity, no closing ``>``) -- 0.32 ms, ``None``. This
      is the case that matters, because an ampersand in prose is ordinary and a
      naive implementation would pay the full second derivation for every one;
    * one real escape present -- 0.46 ms here plus 18.4 ms for the
      :func:`_skeleton` pass the caller then runs on the result.

    **Where it over-reads, said plainly.** ``_MARKUP_TAG_RE`` is a tag pattern
    applied to text that is not necessarily markup, so ``a < b Jane Doe > c`` loses
    its middle, and ``unquote`` will read ``50%20`` in prose as ``50`` plus a space.
    Both make the decoded view *lose* text, so both can only hide a match this view
    would otherwise make -- never invent one -- and the four undecoded forms are
    compared regardless. That is the direction this gate is allowed to be wrong in.

    Returns ``None`` -- meaning "nothing new to compare" -- when the payload carries
    no escape character at all, and again when decoding was a no-op.
    """
    if not _TRANSPORT_ESCAPE_HINT_RE.search(value):
        return None
    decoded = _MARKUP_TAG_RE.sub(" ", html.unescape(unquote(value)))
    return decoded if decoded != value else None


def _skeleton(value: str, *, is_mark: Callable[[str], bool] = _is_mark) -> str:
    """The most-folded haystack form: marks, invisibles and digit scripts all gone.

    Factored out because two haystacks need it -- the payload and its
    transport-decoded twin -- and the derivation is an ordering argument that must
    not be restated in two places.

    ``is_mark`` selects *which* characters count as marks and is the only difference
    between the two skeletons :func:`_skeleton_views` derives. Everything else about
    the derivation -- the order, the double application, the digit fold -- is shared,
    which is what makes the pair a union of two views rather than two rules.

    ``_deaccent`` runs **twice, and the first one is on the raw payload**, before
    :func:`~secure_context_pipeline.crypto.keys.normalize`. That is the same reason
    :func:`_strip_spacing_marks` already runs there, and it is not symmetry for its
    own sake: ``normalize`` casefolds, and casefold *rewrites* U+0345 COMBINING
    GREEK YPOGEGRAMMENI into a Greek iota **letter**. After that no mark-based rule
    can see it -- measured, ``_deaccent(normalize("Nathan\\u0345iel"))`` is
    ``"nathan\\u03b9iel"``, the mark gone from the category but the character still
    breaking the value, while ``_deaccent`` on the raw string yields
    ``"Nathaniel"``. The second application is still needed because NFKC's own
    compatibility decompositions introduce marks that were not there in the raw.
    """
    return _fold_decimal_digits(
        _deaccent(
            _strip_invisible(normalize(_deaccent(_strip_spacing_marks(value), is_mark=is_mark))),
            is_mark=is_mark,
        )
    )


def _skeleton_views(value: str) -> tuple[str, str | None]:
    """The skeleton under BOTH mark selections: ``(category, combining-class)``.

    The second element is ``None`` when the two agree, which is every payload that
    carries no combining-class-0 mark -- so the extra comparison it buys is skipped
    exactly as ``_Haystacks.marked`` skips the skeleton on a payload with no mark.

    **What the second derivation costs**, measured on a 36 KB clinical payload rather
    than argued from the shape of the code, because a whole extra ``normalize`` pass
    is the expensive part of pass 1's setup:

    * ASCII -- **+0.18 ms**, one flag check on the string object and no second pass
      at all (the fast path below), and this is the common payload;
    * non-ASCII whose marks all reorder -- **+13.1 ms**, the second pass runs and
      returns a string equal to the first, so the per-original cost stays at one
      skeleton;
    * non-ASCII carrying a class-0 mark -- **+9.0 ms**, and one more haystack in the
      comparison for each original.

    Against a pass 1 that takes roughly a second at 20k originals and a
    :data:`DEFAULT_TIMEOUT_S` of 30, all three are noise. The middle one is the case
    a cheaper guard would remove, and there is no cheap guard: deciding whether a
    payload carries a class-0 mark means asking :mod:`unicodedata` about every
    character, which costs about what the derivation costs.

    **Why two views rather than the wider one.** Widening :func:`_deaccent` from
    :func:`unicodedata.combining` to :func:`unicodedata.category` closed a real leak
    -- 1,496 of Unicode's 2,408 marks have combining class 0 and every one of them
    survived the old fold, so a mark spliced *inside* a vaulted value defeated pass 1
    -- and it opened another one in the same stroke, because **removing a mark is not
    a pure widening**. The occurrence test on the stripped string is
    :func:`_occurs_as_a_unit`, a word-boundary rule. A class-0 mark sitting
    immediately before or after the value used to be a non-alphanumeric character,
    which *is* a boundary; deleting it glues the value to the neighbouring
    alphanumeric run and the boundary rule then denies the occurrence.

    Measured by differential fuzz over ``_scan_originals``, identical randomized
    inputs to the old and the widened rule -- 60,000 cases, a vaulted original with
    one to three marks drawn from the whole category spliced into random positions
    and random text glued on either side:

        widened blocks more: 16,429 cases      widened blocks LESS: 212 cases

    Minimised, and both halves are real. Vault holds ``Nathaniel Brightwater``::

        "Contact Nathanie<U+0301>l Brightwater<U+0903>Corporation for details."
            combining-class skeleton: "...nathaniel brightwater<U+0903>corporation..."
                -> the class-0 mark is still there, still a boundary  -> HIT
            category skeleton:        "...nathaniel brightwatercorporation..."
                -> glued to "corporation", boundary denied            -> MISS
        "Contact Nathanie<U+0903>l Brightwater today."
            combining-class skeleton: "...nathanie<U+0903>l brightwater..."  -> MISS
            category skeleton:        "...nathaniel brightwater..."          -> HIT

    End to end through :meth:`EgressGate.check` with a vault holding only that name,
    the first payload was ``EgressBlockedError(vault_original)`` under the old rule
    and ``EGRESS_PASS``, released, under the widened one. Replacing the class-0 mark
    with a space blocks under both, which is the tell: the defect is the *boundary*,
    not the mark.

    So the repair is a union rather than a third rule. Both elements are
    haystack-only folds of the same payload, the needle is untouched, and pass 1
    hits if the value occurs as a unit in *either*.

    **That is a property of the union, not of the module, and the difference cost a
    live release.** This docstring used to say the union "can only ever find more
    than either view alone and cannot regress either direction", and cited 0
    regressions over 100,000 cases on three seeds. The claim was true of
    :func:`_occurs_in_any_bounded_form`, which is the only limb the union was
    actually threaded through. The separator limb was handed ``decoded`` and never
    ``decoded_boundary``; the identifier limb saw neither decoded view. An
    independent differential fuzz over 300,000 cases then found **25 payloads the
    pre-widening combining-class rule blocked and this code released** -- every one
    of them carrying a transport escape *and* a class-0 mark, the combination that
    needs the one haystack no limb was offered::

        vault  {'Nathaniel Brightwater'}
        wire   'Portal: /q?v=lab%20NathanielBrightwater<U+0903>Ref -- summarise.'
        combining-class rule : BLOCKED (vault_original)
        the union as shipped : RELEASED, EGRESS_PASS recorded

    Two lessons, and the second is the one worth keeping. A union is only
    non-regressing where it is *applied* -- "additive by construction" says nothing
    about a limb that was never given the second view. And a fuzz proves a property
    only over the shapes it generates: the generator that reported 0 regressions did
    mix transport escapes in, but never crossed one with a class-0 mark in the same
    payload, so the interaction was outside the space it searched. A clean fuzz is
    evidence about its generator before it is evidence about the code.

    :meth:`EgressGate._scan_originals` now builds ONE ``scan_skeletons`` tuple that
    every limb iterates, so the omission cannot recur limb by limb. Re-measured
    against both baselines over 120,000 cases on three seeds after that change:
    0 regressions against either, blocking ~3,600 more than the old rule and ~2,100
    more than the widened one. Pinned by
    ``test_every_skeleton_haystack_reaches_every_limb_that_scans_one``, which fails
    if any limb is handed a subset.

    The alternative considered and not taken was replacing each mark with a
    non-alphanumeric sentinel and teaching the needle match to skip it. That is
    structurally tidier -- one view, and ``Nathanie<mark>l`` reads as one word while
    ``Brightwater<mark>Corporation`` reads as two -- but the skeleton is not only
    fed to :func:`_occurs_as_a_unit`: :func:`_identifier_needles` tests it with a
    bare ``in`` and :func:`_occurs_with_flexible_separator` runs a regex over it, and
    a sentinel is invisible to neither. It would have to be threaded through
    :func:`~secure_context_pipeline.textrules.occurs_as_a_unit`, which four
    components share by design, to fix one component's haystack. The sentinel is also
    not inert in the derivation: it sits in the string across ``normalize``, where it
    blocks NFKC composition and stops a whitespace run collapsing, so the sentinel
    view is *not* the deleting view plus sentinels and the substring pre-filter that
    keeps pass 1 off the critical path stops being exact. The union is provably
    non-regressing in a way a new matcher is not.

    **What this union does not close, measured rather than implied by omission.** A
    mark inside the value plus a mark *beside* it whose combining class is non-zero:
    both views delete the outside one by definition, so both glue the value to its
    neighbour. Measured on the real gate with ``Brightwater`` vaulted and one U+0301
    spliced in, sweeping every one of the 2,408 marks through the outside position:
    1,230 block and 1,178 do not -- the 912 that reorder, plus 266 class-0 marks that
    another declared fold removes first (U+034F and the Mongolian free variation
    selectors are default-ignorable, so :data:`_INVISIBLE_RE` takes them; U+0F73
    NFKC-decomposes into two marks that both reorder). This is **older than the
    widening rather than opened by it**: the combining-class rule this gate shipped
    before released it too. U+0345 is the case that shows a mark-preserving view can
    never be the whole answer, since casefold turns it into a Greek iota *letter*
    that glues the words whether or not any fold removes it. Closing the class needs
    the removed character to survive as a boundary token, which is the sentinel
    design above and the interface change it implies. Pinned by
    ``test_a_reordering_mark_beside_a_spliced_value_is_a_declared_boundary``.
    """
    skeleton = _skeleton(value)
    if value.isascii():
        # No mark can survive in an ASCII string and no fold here can introduce one,
        # so the two selections cannot disagree and the second derivation -- a full
        # normalize pass, the expensive half of pass 1's setup -- is skipped
        # outright. This is the common payload.
        return skeleton, None
    bounded = _skeleton(value, is_mark=_is_reordering_mark)
    return skeleton, (None if bounded == skeleton else bounded)


def _fold_decimal_digits(value: str) -> str:
    """``value`` with every Unicode decimal digit rewritten in its ASCII spelling.

    The one fold in this module applied to the NEEDLE and the HAYSTACK alike, and the
    asymmetry the others keep is not being relaxed here -- digits are a different
    question. :func:`_deaccent` strips one side only because ``José`` and ``Jose`` are
    two different people, so collapsing them would manufacture blocks on documents
    carrying both spellings. U+0665 ARABIC-INDIC DIGIT FIVE and ``5`` are not two
    different anything: a decimal digit's identity *is* its numeric value, so two
    values that fold together denote the same number and a block on either is a true
    positive. Folding both sides is also what makes this cover the reverse direction --
    a value vaulted from a document written in Devanagari digits, restated in ASCII.

    **The leak this closes was reproduced end to end before it was written.** A vaulted
    MRN ``5567281`` reached the provider inside ``Chart cross-reference ... filed with
    billing.`` with its seven digits written in Arabic-Indic, and all three passes
    silent -- and the same again through extended Arabic-Indic, Devanagari, Bengali,
    N'Ko and Osmanya (which is outside the BMP). An ``ACCOUNT_NUMBER`` of
    ``100200300400`` walked out the same way. The model reads every one of those as the
    number, and so does a human reading the wire dump.

    **This is not the declared homoglyph boundary, and that boundary's stated remedy
    would not have closed it.** These codepoints are not visual confusables of ASCII
    digits -- they are differently-drawn characters with the same decimal value -- so a
    UTS-39 confusables table has nothing to say about them. The remedy is a property
    :mod:`unicodedata` already ships.

    **Why NFKC did not already do it**, measured against the Unicode 14.0 database this
    interpreter carries: 660 codepoints have a decimal value, and NFKC folds 80 of them
    to the ASCII digit -- the ASCII digits themselves, the fullwidth forms, the five
    mathematical alphabets and the segmented digits, all of which are *compatibility*
    variants. The other 580, across 58 digit families, it leaves untouched, because a
    Devanagari digit is not a compatibility variant of anything. That is exactly the
    shape the reproduction had: the fullwidth spelling of the vaulted MRN blocked and
    the Devanagari spelling of the same seven digits did not, so the payload that looked
    more contrived was the one already caught.

    The class comes from a Unicode property rather than a hand-picked list, for the
    reason :data:`_INVISIBLE_RE` and :func:`_is_spacing_diacritic` give: a script a
    future release adds is covered the day it lands. :func:`unicodedata.decimal` is
    the *decimal* property specifically -- the digits that carry positional notation --
    so it takes Arabic-Indic and Devanagari and leaves alone Ethiopic ``፭``, which
    has a digit value but is an additive numeral with no zero, and the enclosed forms
    (``⑴``), which NFKC has already rewritten to ``(1)`` by the time this runs.

    The map is one codepoint to one codepoint, which is what makes it safe to apply
    inside the folded forms rather than as a fifth one: it preserves length, so no
    :data:`MIN_ORIGINAL_LEN` check moves, and it maps alphanumeric to alphanumeric, so
    no boundary assertion in :func:`_occurs_as_a_unit` changes class. A needle that
    occurred in a haystack before therefore still occurs in it after.

    **Where it does not reach**, stated rather than left to be discovered:
    :func:`_composite_needles` splits the *raw* original, so a detector span that is a
    list of values written in a non-ASCII script yields no constituent needles -- it
    keeps the whole-value forms and nothing more.

    Free on the payloads that do not need it, and cheap on the ones that do:
    ``str.isascii`` is a flag check on the string object, so every ASCII payload and
    every ASCII original returns the *same object* before the loop is entered -- 0.2
    microseconds on a 54 KB payload. One carrying a single accent takes the loop, at
    3.0 ms for the same 54 KB; that is twice per ``check()`` (the folded and skeleton
    haystacks) and once per original, against a pass 1 that takes roughly a second at
    20k originals and a budget of :data:`DEFAULT_TIMEOUT_S`.
    """
    if value.isascii():
        return value
    folded = "".join(
        str(digit) if (digit := unicodedata.decimal(ch, None)) is not None else ch
        for ch in value
    )
    return value if folded == value else folded


class _Haystacks(NamedTuple):
    """The payload forms pass 1 compares against, derived once per scan.

    Five forms, up to seven strings: the skeleton and the decoded skeleton are each
    derived under both mark selections (:func:`_skeleton_views`), and the second of
    each pair is ``None`` whenever it cannot differ from the first.

    A tuple rather than seven positional arguments because they are always passed
    together and getting two of them the wrong way round is a silent widening or
    narrowing of the scan rather than a type error.
    """

    raw: str
    normalized: str
    folded: str
    skeleton: str
    #: Whether the payload carries a mark at all. When it does not, the skeleton
    #: form is the folded form and comparing it again buys nothing.
    marked: bool
    #: The same skeleton derived under the *combining-class* mark selection
    #: (:func:`_skeleton_views`), or ``None`` when the two selections agree. It keeps
    #: class-0 marks, so a mark next to the value is still a word boundary there --
    #: which is the occurrence ``skeleton`` loses by removing it.
    boundary_skeleton: str | None
    #: The skeleton of the payload with transport escapes decoded
    #: (:func:`_decode_transport_escapes`), or ``None`` when the payload carries no
    #: escape at all or decoding changed nothing -- in which case comparing it again
    #: buys nothing, exactly as ``marked=False`` says of the skeleton.
    decoded: str | None
    #: ``decoded`` under the combining-class selection, on the same terms as
    #: ``boundary_skeleton``: the decoded view has the same boundary defect, since it
    #: is the same fold applied to a different string.
    decoded_boundary: str | None


def _occurs_in_any_bounded_form(value: str, haystacks: _Haystacks) -> bool:
    """``value`` present in the payload as a unit, in any of the compared forms.

    They are documented at :meth:`EgressGate._scan_originals`; this function is
    where they are *applied*, and it exists so that both things pass 1 asks about --
    a whole vaulted original and one constituent of a composite one -- ask in exactly
    the same words. The alternative was a second inline copy of the ``forms`` list for
    the composite limb, i.e. two places that would each have to be edited the next time
    a form is added, which is how this file's siblings acquired the divergences their
    docstrings now record.

    :data:`MIN_ORIGINAL_LEN` is re-checked per *derived* form, not once on the input:
    normalising and folding both shrink a needle and can drop it below the floor after
    the fact. The digit fold is the one derivation that cannot move that floor, because
    it replaces a codepoint rather than removing one.
    """
    normalized = normalize(value)
    folded = _fold_decimal_digits(_strip_invisible(normalized))
    forms = [
        (value, haystacks.raw),
        (normalized, haystacks.normalized),
        (folded, haystacks.folded),
    ]
    if haystacks.marked:
        forms.append((folded, haystacks.skeleton))
    if haystacks.boundary_skeleton is not None:
        forms.append((folded, haystacks.boundary_skeleton))
    if haystacks.decoded is not None:
        forms.append((folded, haystacks.decoded))
    if haystacks.decoded_boundary is not None:
        forms.append((folded, haystacks.decoded_boundary))
    return any(
        len(needle) >= MIN_ORIGINAL_LEN and _occurs_as_a_unit(needle, haystack)
        for needle, haystack in forms
    )


#: One maximal run of ASCII digits long enough to be an identifier on its own.
_DIGIT_RUN_RE = re.compile(rf"[0-9]{{{MIN_IDENTIFIER_RUN_DIGITS},}}")
_ANY_DIGIT_RE = re.compile(r"[0-9]")

#: What :func:`_separator_needles` allows *between* two components of a
#: multi-component original: any run of non-alphanumeric characters, including none
#: at all. Spelled ``[\W_]`` rather than ``\W`` because ``\W`` treats underscore as a
#: word character, and underscore is one of the substitutions demonstrated to walk a
#: value out -- here it has to count as a separator, not as content.
_INTERIOR_SEPARATOR: Final = r"[\W_]*"


def _identifier_needles(value: str) -> tuple[str, ...]:
    """Forms of ``value`` that disclose it **whatever they are glued to**.

    :func:`_occurs_as_a_unit` refuses to call ``Brown`` inside ``Browning`` an
    occurrence, and it is right to: a generated fake that contains a real surname is
    not a leak, and blocking on it makes pseudonymization unusable. But that argument
    is about *names*, and for years it was the only occurrence test pass 1 had. It
    does not survive contact with a nine-digit identifier, and the document body is
    written by whoever uploads the file:

        The taxpayer EIN 47-1234567 is on file.
        Internal routing tag: batch47-1234567Alpha must match the ledger.

    ``47-1234567`` is detected and tokenized out of line 1, and rides out to the
    provider byte-for-byte in line 2 -- neither swept (the engine's residual sweep
    applies the same boundary rule) nor blocked (pass 1 did too) nor re-detected
    (``TAX_ID``'s pattern anchors on ``\\b``, which ``batch`` denies it). ``batch`` in
    front of it conceals nothing from a reader and nothing from the model.

    So a digit-carrying value is also compared as a bare substring, in two shapes --
    and the two have **different floors**, because they are different claims:

    * **the whole value**, when it contains no letter at all and it carries at least
      :data:`MIN_IDENTIFIER_DIGITS` digits in total -- ``512-24-8710``,
      ``47-1234567``, ``(415) 555-0123``. The separators are part of what is
      disclosed, so the needle keeps them. The floor is seven here because six-digit
      *totals* are mostly dates and amounts (``03/12/85``, ``$1,234.56``), which are
      aggregates of short runs rather than identifiers.
    * **each contiguous digit run of at least :data:`MIN_IDENTIFIER_RUN_DIGITS`**,
      whatever else the value contains. This is the half that matters for a vaulted
      span that includes its own label: ``MRN: 5567281`` never appears in
      ``MRN5567281B``, but ``5567281`` does, and the digits are the secret. It also
      covers ``Account No. 100200300400`` against a bare ``100200300400`` elsewhere
      in the document, and ``BCBS123456789`` against a bare ``123456789``. The floor
      is six here because the shipped registry vaults six-digit MRNs
      (``\\K\\d{6,10}``) and a contiguous six-digit run is an identifier core, not a
      date. See :data:`MIN_IDENTIFIER_RUN_DIGITS` for the leak that proved the two
      floors had to be separate numbers.

    The false-positive risk this accepts is the one the boundary rule was avoiding,
    and it is a different size here. For a name it is ordinary -- Brown/Browning is a
    word list away. For a seven-digit run it needs another number in the payload that
    contains those exact digits contiguously; the arithmetic on the one such run this
    pipeline emits itself (an 8-hex token ID) is in :data:`MIN_IDENTIFIER_DIGITS`.
    Where it does fire on something innocent the result is a blocked request, which
    is the direction this gate is allowed to be wrong in.

    What is in scope is worth stating exactly, because the first draft of this
    docstring said "identifiers" and meant it, and the code says something broader
    and simpler. A value contributes a whole-value needle whenever it is made of
    digits and separators alone and carries seven of them -- which is true of a date
    with a four-digit year (``03/12/1985``, eight digits), of a phone number
    (``(415) 555-0123``), and of an amount over ``$99,999.99``. Those are all values
    a glued neighbour discloses just as completely as it discloses an SSN, and every
    one of them is a HIPAA identifier in a medical record, so the wider rule is the
    right one; it is documented here rather than narrowed because the narrowing
    would have to be a list of shapes, and a list of shapes is the thing this module
    keeps finding it got wrong.

    Values that contribute nothing at all and keep exactly the four bounded forms:
    every name and every value with no digits; short dates (``03/12/85`` -- six
    digits in total, but its longest run is two); amounts below seven digits
    (``$1,234.56`` -- longest run three); docket numbers (``1:23-cv-04567`` --
    letters, and no run reaches six); lab values (``A1C 7.4``).
    """
    if not _ANY_DIGIT_RE.search(value):
        return ()
    stripped = value.strip()
    needles: list[str] = []
    if (
        sum(1 for ch in stripped if "0" <= ch <= "9") >= MIN_IDENTIFIER_DIGITS
        and not any(ch.isalpha() for ch in stripped)
        and len(stripped) >= MIN_ORIGINAL_LEN
    ):
        needles.append(stripped)
    needles.extend(_DIGIT_RUN_RE.findall(stripped))
    return tuple(dict.fromkeys(needles))


def _alnum_only(value: str) -> str:
    """``value`` reduced to its letters and digits.

    Used as a **length measure only** -- :func:`_separator_needles` calls it to decide
    whether a value clears :data:`MIN_JOINED_ALNUM_LEN`. No payload is ever passed
    through it.

    This said "Applied to BOTH sides. Symmetric, unlike ``_deaccent``", which was
    true of the first design: that one compared a joined needle against a joined
    payload projection. That design was replaced because it re-opened a false
    positive, and the comment outlived it.
    """
    return "".join(ch for ch in value if ch.isalnum())


def _separator_needles(value: str) -> tuple[str, ...]:
    """The components of a MULTI-COMPONENT original, joined with nothing.

    **The shape this closes, which the four bounded forms could not see.** All four
    compare a needle that keeps its interior separator against a payload that has
    changed it. ``Marguerite Vandenberg`` was vaulted from a clean mention; the
    payload carried ``Marguerite<U+200B>Vandenberg``; and every form missed:

    * *raw* -- different bytes;
    * *normalised* -- U+200B is not ``\\s``, so collapsing whitespace does not touch
      it and the needle still carries a space the haystack does not;
    * *folded* -- stripping the invisible **glues the two words together**
      (``margueritevandenberg``) while the needle still says ``marguerite
      vandenberg``;
    * *skeleton* -- same, plus mark-stripping, which is not the difference here.

    It is worth being exact about the mechanism, because the first diagnosis was that
    the fold *caused* the miss and that is wrong: deleting the space outright, or
    writing ``-``, ``_`` or ``.`` in its place, all miss identically and none of them
    involves the fold. The real property is that **any alteration of a multi-word
    original's interior separator defeats every form that keeps the separator in the
    needle.** So this form keeps none of it, on either side.

    **What "any" is worth here, stated exactly, because it was overclaimed.** This
    form relaxes the separator to :data:`_INTERIOR_SEPARATOR`, which is a *character
    class* -- so what it actually tolerates is any run of non-alphanumeric
    characters, and a separator carrying word characters is outside it by
    construction. ``%20``, ``&nbsp;``, ``&#32;`` and ``<br/>`` are all of that shape,
    all are ordinary transport spellings of a space that a ``.md``/``.txt``/``.docx``
    upload carries verbatim, and all four walked a whole vaulted
    ``Marguerite Vandenberg`` to the provider while the hyphen and zero-width
    controls in the same probe blocked. Widening the class is the wrong repair --
    admitting alphanumerics between components would make ``John Smith`` match
    ``JohnQSmith`` -- so the haystack is decoded instead
    (:func:`_decode_transport_escapes`) and this limb is run against that view too.
    The claim above is therefore true of the *separator*, and true of the value only
    once the payload has been decoded first.

    That is also why the obvious repair -- strip ``\\s`` from both sides and keep the
    word-boundary rule -- does not work. Removing the separator makes the neighbours
    alphanumeric, so :func:`_occurs_as_a_unit` then rejects the very match it was
    asked to find (``...MargueriteVandenbergRN...``). This comparison is therefore
    unbounded, and the floors below are what pay for that.

    **The outer word boundaries are kept, and only the INTERIOR separator is
    relaxed.** That distinction is the whole design, and the first version of this
    function got it wrong in a way this repository had already paid for once. Dropping
    the boundaries entirely -- comparing a fully joined needle against a fully joined
    payload -- does close the demonstrated leak, and it also re-opens two false
    positives the module docstring and
    ``test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims``
    both name explicitly: ``chronic low back pain`` matching inside ``chronic low back
    pains``, and ``John Smith`` inside ``xJohn Smithx``. The plural one is the
    instructive one, because it is not exotic -- fixture originals include ordinary
    clinical phrases, and a red that appears and vanishes between runs is
    indistinguishable from a real leak until somebody spends an hour on it.

    With the outer boundaries kept, every one of those resolves correctly, because in
    each the *neighbour* is alphanumeric rather than the *separator* being different:

    * ``Marguerite<U+200B>Vandenberg RN`` -- interior separator changed, outer
      neighbours are ``:`` and a space. **Blocks**, which is the leak this closes.
    * ``chronic low back pains`` -- separators intact, a letter follows the last
      component. **Does not block.**
    * ``xJohn Smithx`` -- separators intact, letters on both outer edges. **Does not
      block**, so the second declared boundary is unchanged rather than quietly
      rewritten.
    * ``Filed 03/12/850`` against ``03/12/85``, and ``$1,234.567`` against
      ``$1,234.56`` -- a digit follows. **Does not block**, which is what lets this
      limb accept mixed letter-and-digit values that a joined comparison had to
      exclude for prefix collisions (``1:23-cv-045678`` no longer threatens
      ``1:23-cv-04567``).

    **What it catches beyond the demonstrated case**, re-measured rather than
    asserted: a vaulted ``512-24-8710`` against a bare ``512248710`` (9 joined
    characters), and ``MRN: 5567281`` against ``MRN 5567281`` (10). Those are
    separator *variants* of an identifier, which :func:`_identifier_needles` covers
    only when a single contiguous run already clears its floor.

    This list previously also claimed ``5,567,281`` against ``5567281``, and it is not
    this limb's example -- but the correction that replaced it was wrong in turn, which
    is worth recording rather than quietly fixing: a paragraph whose whole job is to
    stop a reader trusting a wrong example had been the wrong example twice.

    Neither direction produces a needle **here**, for two different reasons. Vaulted
    ``5567281`` is a single component, so the ``len(parts) < 2`` return fires before any
    floor is consulted; vaulted ``5,567,281`` has three components that join to seven
    characters, one below :data:`MIN_JOINED_ALNUM_LEN`.

    The correction said :func:`_identifier_needles` covers it, "whose digit-run floor is
    six". It does not, in either direction, and that is measured rather than reasoned
    about: the needles are ``('5567281',)`` and ``('5,567,281',)`` respectively -- the
    whole value, plus digit runs, and ``5,567,281``'s longest run is three -- so the
    needle from each spelling is absent from the other. What covers it is
    :func:`_regrouped_identifier_needle`, added later than that paragraph: both
    spellings reduce to the digit skeleton ``5567281``, seven digits with no letter.
    Pinned in both directions, limb by limb, by
    ``test_the_comma_grouped_identifier_blocks_in_both_directions`` -- an attribution
    that only prose asserts is one that goes stale the next time a limb moves.

    Returns a **pattern source string**, not a literal, because "any separator or
    none" is not expressible as a substring. It is the one needle in pass 1 with no
    ``in`` pre-filter available, so it is applied last and only to values that reached
    it -- see :meth:`EgressGate._scan_originals`.
    """
    stripped = value.strip()
    # Split on the SAME predicate the pattern below rejoins on, via groupby rather
    # than a regex: `\w` and `str.isalnum()` disagree at the edges (underscore, some
    # marks), and a needle built by one rule from a split made by the other is the
    # kind of quiet divergence this module keeps finding in itself.
    parts = ["".join(run) for keep, run in groupby(stripped, key=str.isalnum) if keep]
    if len(parts) < 2:
        # Single component: there is no interior separator to alter, so the bounded
        # forms already cover it and there is nothing for this limb to add.
        return ()
    if len(_alnum_only(stripped)) < MIN_JOINED_ALNUM_LEN:
        return ()
    # Guards come from `textrules`, the module that owns the single definition of
    # "as a unit" -- not restated here. Every component begins and ends alphanumeric
    # by construction (that is what groupby split on), so both guards are always
    # meaningful and `boundary_guards` is asked about the components rather than
    # about the original, whose own edges may be punctuation.
    left, right = boundary_guards(parts[0][0]), boundary_guards(parts[-1][-1])
    return (left[0] + _INTERIOR_SEPARATOR.join(re.escape(p) for p in parts) + right[1],)


def _occurs_with_flexible_separator(value: str, haystack: str) -> bool:
    """``value`` present in ``haystack`` with its interior separators spelled anyhow.

    The applied form of :func:`_separator_needles`, and the only thing that should
    call it: the pattern that function returns has no substring pre-filter of its own,
    and applying it directly to a large originals set is a measurable regression
    rather than a theoretical one. ``test_a_long_pass_one_does_not_stall_unrelated
    _coroutines`` drives 60k originals through pass 1 and went from passing to a
    ``gate_exception`` timeout the moment the raw ``re.search`` was added.

    The pre-filter is exact, not heuristic: the pattern requires every component to be
    present as a literal, in order, so the absence of **any one** of them is a
    sufficient reject. The longest component is used because it is the most selective,
    and one C-level ``in`` rejects the overwhelmingly common miss before the regex
    engine is entered at all -- the same trick, for the same reason, as
    :func:`~secure_context_pipeline.textrules.occurs_as_a_unit`.
    """
    patterns = _separator_needles(value)
    if not patterns:
        return False
    parts = ["".join(run) for keep, run in groupby(value.strip(), key=str.isalnum) if keep]
    if max(parts, key=len) not in haystack:
        return False
    return any(re.search(pattern, haystack) for pattern in patterns)


def _digits_only(value: str) -> str:
    """``value`` reduced to its ASCII digits."""
    return "".join(ch for ch in value if "0" <= ch <= "9")


def _regrouped_identifier_needle(value: str) -> str | None:
    """The digit skeleton of an identifier, for a payload that RE-GROUPS it.

    :func:`_separator_needles` relaxes the separator *between* a value's components,
    which tolerates a payload carrying FEWER separators than the vaulted form
    (``47-1234567`` against ``471234567``). It is one-directional: it returns nothing
    for a single-component value, so it could not tolerate a payload carrying MORE
    separators than the vaulted form. A vaulted ``100200300400``, detected and
    tokenised from its clean mention, therefore rode out to the provider byte for
    byte as ``1002-0030-0400`` -- every digit, in order, with three dashes inserted --
    past all four bounded forms, both identifier needles and the composite limb.

    Comparing digit skeletons closes both directions at once, because the projection
    is applied to the needle and the payload alike: any regrouping, spacing or
    punctuation of the same digits collapses to the same string.

    Floored at :data:`MIN_IDENTIFIER_RUN_DIGITS`, and unbounded like
    :func:`_identifier_needles` -- for the same reason. The payload projection
    concatenates every digit in the document, so a short needle acquires landing
    sites the document never wrote; six is where that stops being likely and is
    already this module's answer to "how much digit content is specific enough to
    compare without an adjacency rule".
    """
    # The same two conditions `_identifier_needles` applies to its whole-value
    # needle, and both were learned the hard way rather than chosen.
    #
    # NO LETTERS: a value mixing letters and digits is an identifier shape, and
    # identifier shapes collide by PREFIX -- the digit skeleton of `1:23-cv-04567` is
    # contained in that of the companion docket `1:23-cv-045678`, so an unbounded
    # comparison denies a payload that merely cites the neighbouring case.
    #
    # SEVEN digits, not six: a digit TOTAL is not a contiguous run.
    # `MIN_IDENTIFIER_RUN_DIGITS` was tried here first and re-broke the shapes
    # `test_a_value_below_the_identifier_floor_keeps_the_boundary_rule` exists to
    # protect -- `$1,234.56` totals six digits, and its skeleton is contained in that
    # of the ordinary text `$1,234.567`.
    stripped = value.strip()
    if any(ch.isalpha() for ch in stripped):
        return None
    digits = _digits_only(stripped)
    if len(digits) < MIN_IDENTIFIER_DIGITS:
        return None
    return digits


def _composite_needles(value: str) -> tuple[str, ...]:
    """The constituents of ``value`` when ``value`` is a *list* of digit-bearing values.

    **The shape this exists for.** A vault original is whatever the detector called one
    span, and a detector span is not always one value. spaCy returns
    ``03/11/2024, 09/17/2024`` as a single ``DATE``, so that composite string -- which
    the document contains but which nobody wrote as a unit -- becomes one original, and
    every other comparison in pass 1 then asks about the composite rather than about
    the dates in it. ``_identifier_needles`` does not rescue it either: its whole-value
    needle is the composite again, and its digit-run needles need six *contiguous*
    digits, while the longest run in that string is four (``2024``). So a payload
    carrying ``03/11/2024`` on its own -- which this pipeline can *manufacture*, by
    shifting a different date in the same document onto it -- passed pass 1 clean, and
    correctly so by pass 1's own definition.

    Detection now splits that span upstream, which is the actual fix. This limb is the
    second opinion: the gate does not get to assume the detector did anything, and
    "composites no longer reach the vault" is a statement about the detector.

    **The rule, and it is deliberately narrow because a block is a denial.** ``value``
    is split on
    :data:`~secure_context_pipeline.textrules.DELIMITER_RE` -- the same grammar
    detection splits on, shared rather than restated -- and contributes needles only
    when it yields **two or more** constituents *and* **every** one of them carries at
    least :data:`MIN_IDENTIFIER_DIGITS` ASCII digits. The needles then keep the
    word-boundary rule; nothing here is compared unbounded.

    **What is excluded, and why each exclusion is load-bearing.** This gate is
    fail-closed, so a false positive is a denied request that looks exactly like a
    leak, and every one of these would have produced them:

    * **Constituents that do not reach the digit floor -- which is every common word.**
      ``April 2024`` must not make ``April`` a needle and ``Park Avenue, Springfield``
      must not make ``Park`` one; a word-bounded needle on an ordinary English word
      denies every payload that happens to use it. Seven digits is not a proxy for
      "identifier" and is not claimed as one -- it is the floor at which a constituent
      stops being a word. It is :data:`MIN_IDENTIFIER_DIGITS` rather than a new number
      because it is the same question that constant already answers: how much digit
      content makes a string specific enough to compare on its own.
    * **Partial qualification.** One constituent below the floor refuses the *whole*
      value, rather than contributing needles for the ones above it. Without that,
      ``Jan 5, 2024`` -- a single date with a comma in it -- would contribute ``2024``,
      and ``2024`` as a word-bounded needle denies essentially every document in the
      corpus. All-or-nothing is also what makes this limb agree with the upstream
      split, which refuses for the same reason.
    * **Bare components of a *non*-composite original.** Vaulted ``John Smith``,
      payload containing ``Smith``, is a real disclosure and is **not** covered here.
      It needs per-entity policy -- a surname is a word, and the leakage harness names
      partial disclosure as outside what it claims for exactly that reason. The
      delimiter requirement is what keeps this rule away from it: whitespace is not a
      delimiter (see :data:`~secure_context_pipeline.textrules.DELIMITER_RE`), so a
      multi-*word* value contributes nothing at all here.
    * **Recursive splitting.** A constituent is taken as it stands and is never split
      again, so no needle here is a fragment of a fragment.
    * **Unbounded comparison.** A constituent is not necessarily an identifier core, so
      it keeps the ``Brown``/``Browning`` boundary rule. The unbounded question is
      :func:`_identifier_needles`'s, and it already reaches inside a composite for any
      digit run long enough to deserve it.

    **The false-positive cost is measured, not asserted.** Over 30 freshly generated
    fixture documents (10 medical, 10 legal, 10 financial) the shipped detector
    returned **1345** spans, of which **211 carried a list delimiter** and **0
    contributed a composite needle** -- because the delimiter-bearing ones are names
    (``Smith, John``), addresses, drug lists and clinical prose, and none of those
    carry seven digits in *every* part. ``$1,234,567.89`` splits into ``$1``, ``234``
    and ``567.89``, all below the floor, which matters because it is an ordinary
    vaulted ``AMOUNT``. The 100-run leakage harness is the thing a spurious block
    would turn red; it was run eight times over this change, 100/100 clean each time.

    That measurement is also the honest summary of what this limb is *for*: on a
    corpus where detection is behaving, it fires on nothing at all. It earns its place
    on the day detection does not.
    """
    if not _ANY_DIGIT_RE.search(value):
        return ()
    parts = delimited_parts(value)
    if len(parts) < 2:
        return ()
    needles: list[str] = []
    for start, end in parts:
        part = value[start:end]
        if sum(1 for ch in part if "0" <= ch <= "9") < MIN_IDENTIFIER_DIGITS:
            return ()
        needles.append(part)
    return tuple(dict.fromkeys(needles))


#: Pass 3's recognisers: high-severity shapes matched by patterns the **detector does
#: not use**, so that a detector miss is not automatically a gate miss.
#:
#: Pass 2 re-runs the same ``Detector`` that ran at detect time. That makes it a
#: second *look*, not a second *opinion*, and the difference is measurable. Presidio's
#: ``UsSsnRecognizer`` scores every candidate through ``invalidate_result``, which
#: returns True -- a hard 0.0, not a low score -- for::
#:
#:     123-45-6789   987-65-4320   078-05-1120     (published example SSNs)
#:     000-xx-xxxx   666-xx-xxxx                   (never-issued area numbers)
#:     xxx-00-xxxx   xxx-xx-0000                   (all-zero group or serial)
#:     111-11-1111                                 (all one digit)
#:     123-45.6789                                 (mismatched delimiters)
#:
#: ``Member SSN 123-45-6789 verified against records.`` therefore reached the provider
#: fully in the clear: never detected, so never vaulted, so nothing for pass 1 to look
#: for, and pass 2 asked the recogniser that had already said no. The registry's own
#: MRN comment admits the general shape of this ("a value neither pattern anchors on
#: is invisible to both"); this constant is the part that stops it being true of the
#: *egress* gate as well as of detection.
#:
#: That sentence was true and incomplete for as long as this constant held one entry,
#: and the incompleteness was the live defect: ``invalidate_result`` rejects the same
#: nine digits written **bare**, and the one entry required a delimiter, so
#: ``Member SSN 123456789 verified against payer records.`` was released with the digits
#: in the payload verbatim while its delimited twin was blocked. Both are now claimed --
#: here, and (as detection rather than denial) by ``SSN.patterns`` in ``entities.yaml``.
#:
#: Scope is deliberately narrow, because pass 3 blocks and a block is a denial. The
#: first entry claims one spelling and the second buys its specificity from a label:
#:
#: * **Unlabelled: the separated spelling only.** A bare ``\\b[0-9]{9}\\b`` rule with
#:   no label requirement would fire on every zip+4, order number and invoice ID in an
#:   ordinary document -- the registry rejects a bare-digit MRN rule for exactly that
#:   reason -- and it would fire on text this pipeline had already handled correctly.
#: * **Labelled: any nine-digit spelling, bare included.** Once an SSN or ITIN noun
#:   phrase introduces the digits, the delimiter is carrying no specificity that the
#:   label is not already carrying, and requiring one only separated the *denied*
#:   spellings from the *leaked* one. See the second half of this note.
#: * The separator class is ``[-. ]``: Presidio's own, deliberately, because the job
#:   here is to remove Presidio's *validation* blind spot rather than to invent
#:   shapes it never claimed. A spelling outside that class (``123/45/6789``) is not
#:   claimed and is named as residual rather than left to be discovered.
#: * Mismatched separators *are* matched, because rejecting them is one of Presidio's
#:   invalidation rules and therefore one of its blind spots.
#:
#: The space separator was left out of the first version of this constant, on the
#: reasoning that ``100 25 1000`` is a table row and blocking it would be a denial
#: reachable from an ordinary financial document. That reasoning was wrong, and it
#: was wrong in a way worth recording because it is the same mistake this module
#: keeps making -- reasoning about a checker without running the thing it checks.
#: Measured on the shipped detector::
#:
#:     'Ledger row totals 100 25 1000 posted this quarter.'  -> SSN:0.50, BLOCKED
#:     'Member SSN 123 45 6789 verified against records.'    -> nothing,   PASSED
#:
#: Presidio's ``SSN5`` pattern already claims the space spelling at 0.5, so a
#: space-separated table row that is a *valid* SSN has always blocked this pipeline
#: via pass 2. Excluding spaces here therefore bought no false-positive protection at
#: all; all it did was leave the **invalidated** subset -- exactly the example SSNs
#: pass 3 exists for -- able to leave the process, and leave the gate more permissive
#: precisely where Presidio had decided the number was fake. The residual false
#: positives the space class adds are the rows Presidio invalidates and nothing else:
#: an all-zero middle column (``100 00 1000``), an all-zero tail, or a row of one
#: repeated digit.
#:
#: Our own output is exempt by span (:meth:`EgressGate._protected_spans`), which is
#: what keeps a pseudonymized fake SSN -- SSN-shaped by design -- from blocking every
#: run that produces one.
#:
#: **The second entry, and why the first one alone was not the fix it was written as.**
#: The paragraph above argued a bare ``\b[0-9]{9}\b`` rule out of this constant and was
#: right to; what it then did was leave the *labelled* bare spelling uncovered as well,
#: which is not the same decision. Measured on the shipped pipeline, both strategies,
#: with the provider payload inspected byte for byte::
#:
#:     'Member SSN 123-45-6789 verified against payer records.'  -> EGRESS_BLOCKED
#:     'Member SSN 123456789 verified against payer records.'    -> RELEASED, and the
#:                                                                  nine digits are in
#:                                                                  the payload verbatim
#:
#: Same document, same missing detection, opposite outcomes, and the *worse* outcome on
#: the spelling this pattern was supposed to be about: ``invalidate_result`` rejects the
#: canonical example whether or not it carries delimiters, so the delimiter requirement
#: separated a denial from a leak rather than separating a leak from a benign number.
#:
#: The second entry therefore drops the delimiter requirement and buys the specificity
#: back from the *label* instead: an SSN or ITIN noun phrase in identifier position,
#: within a short non-alphanumeric run of the digits. That is the grammar the registry
#: uses for every numeric identifier it recognises (see the note above ``MRN`` in
#: ``entities.yaml``), and it is what keeps every probe in
#: ``test_pass_three_is_narrow_enough_to_ship`` -- a zip+4, an order number, an invoice
#: reference -- outside this pattern while ``Member SSN 123456789`` is inside it.
#:
#: **It is deliberately a second copy of a rule the registry also states**, written here
#: in this module's own dialect against ``re`` rather than imported from
#: ``entities.yaml``. Detection is config; the gate is the guarantee. Importing the
#: registry's spelling would mean a one-line edit to a YAML file could blind the gate at
#: the same moment it blinds the detector, which is the single failure mode pass 3
#: exists to rule out.
#:
#: **What the two copies must satisfy is CONTAINMENT, not equality, and this note used
#: to claim equality while the code did not deliver it.** It said "same rule, ``re``
#: instead of ``regex``". That was false when it was written. The separator classes
#: were different languages::
#:
#:     registry (entities.yaml)   [\s:#.\-]*+          -- whitespace, colon, hash, dot, hyphen
#:     gate (here)                [^0-9A-Za-z]{0,24}   -- ANY non-alphanumeric run
#:
#: and the gate's was the wider one, which is the direction that costs availability.
#: A value both layers claim is vaulted and restorable. A value only *this* pattern
#: claims was never detected, so it was never vaulted, so pass 3 blocks: ``422
#: EGRESS_BLOCKED``, ``demo.py --file`` exit 1. Every spelling in the gap was a working
#: document the pipeline refused -- ``Member SSN, 123456789``, ``Social Security Number
#: (SSN): 123456789``, ``Applicant SSN [123456789]``, ``Member SSN=``, ``SSN/``,
#: ``SSN --``, ``Member SSN?`` -- all measured red at ``--category financial``. That is
#: the same "a reviewer's own document turns the demo red" defect the second entry was
#: added to fix, relocated from hyphenated placeholders to intake-form punctuation.
#:
#: The repair widened the REGISTRY to ``[^0-9A-Za-z]*+`` -- a strict superset of both
#: classes -- and deliberately did **not** narrow this one, because narrowing the gate
#: would make the two agree by re-opening the leak pass 3 exists to catch. The invariant
#: is therefore one-directional and stated as such:
#:
#:     anything pass 3 would block on a LABELLED SSN, the detector already claims,
#:     vaults and can restore.
#:
#: The converse is allowed on purpose: the registry may claim more than this pattern
#: does, because detection is best-effort and the gate is the guarantee.
#:
#: Two tests hold it, and they compare the two LANGUAGES rather than the two texts --
#: a string comparison would pass the instant someone pasted one pattern into the other
#: file and would say nothing about ``regex``-vs-``re`` dialect differences:
#: ``test_egress_gate.py::test_every_labelled_ssn_the_gate_claims_the_registry_claims_too``
#: generates a corpus spanning both separator classes, both delimiter conventions and
#: both quantifier bounds and asserts gate-claims ⊆ registry-claims span for span, and
#: ``::test_the_registry_ssn_separator_class_is_not_narrower_than_the_gates`` asserts the
#: character-class containment directly so it survives a corpus that stopped being
#: representative. Separately, ``::test_an_ssn_the_shipped_detector_scores_at_zero_still_blocks``
#: and ``::test_pass_three_blocks_a_labelled_bare_nine_digit_ssn`` build the gate against
#: a registry whose SSN backstop has been deleted, which is what proves this copy still
#: works when the config one is switched off.
#:
#: (An earlier revision of this note named a test
#: ``test_pass_three_still_blocks_a_labelled_ssn_with_detection_removed`` that was never
#: written. Naming a guard that does not exist is worse than naming none, because it is
#: where the next reader stops looking -- the same defect this module documents in
#: itself twice above.)
#:
#: ---------------------------------------------------------------------------------
#: **THE OTHER THREE HIGH-SEVERITY TYPES, AND WHY THEY WERE MISSING.**
#:
#: Everything above argued the case for ``SSN`` and then shipped ``SSN`` alone, while
#: :data:`HIGH_SEVERITY_TYPES` named four types a pass-2 re-hit *blocks* on. For the
#: other three the only recogniser in the whole system was the single registry pattern,
#: consulted identically at detect time and again in pass 2 -- so "defence in depth" was
#: two layers sharing one brain, and the argument this constant was built on was
#: answered for 25% of the blocking surface. That is not hypothetical: it is the exact
#: shape of the cleartext SSN leak the notes above record, and it was open for
#: ``MRN``, ``ACCOUNT_NUMBER`` and ``TAX_ID`` at the same time. Reproduced first, on
#: the shipped ``demo.py --file`` with the mock provider, ORIGINAL DOCUMENT beside
#: OUTBOUND PAYLOAD, all three ``EXIT=0`` with ``EGRESS_PASS`` audited::
#:
#:     Patient MRN [4471902] was reconciled ...   -> Patient MRN [4471902] was ...
#:     Please credit account [100200300400] ...   -> Please credit account [1002...
#:     The EIN 123456789 is recorded on the ...   -> The EIN 123456789 is record...
#:
#: **Each new entry is derived from the requirement, not from the registry.** None of
#: them imports ``entities.yaml``; each is hand-written here against ``re`` from what
#: the identifier *is* -- a medical record number is a 6-10 digit chart number
#: introduced by a noun phrase naming a medical record; a US bank account number is an
#: 8-17 digit run (or four 4-digit groups) introduced by a noun phrase naming an
#: account; an EIN is nine digits, canonically ``NN-NNNNNNN``, either standing alone in
#: that grouping or introduced by a noun phrase naming a taxpayer identification
#: number. That the label vocabularies then *overlap* the registry's is not a failure
#: of independence -- there is only one English noun phrase for "account number" -- and
#: it is not what independence buys. What it buys is stated above and is unchanged: a
#: one-line edit to a YAML file cannot blind the gate at the same moment it blinds the
#: detector, because these five patterns live in a different file, in a different regex
#: dialect, and are reached by no code path that reads the registry.
#:
#: **Containment is preserved for every new entry, and it cost registry widenings.**
#: The invariant (``test_detection.py::test_every_egress_gate_pattern_is_contained_by_
#: the_registry`` and its ``_vaultable_not_merely_blockable`` sibling, both parametrized
#: over this tuple) is that every span any entry here would block, the registry claims
#: too, with the same span, at or above ``threshold_obfuscate``. Three widenings in
#: ``entities.yaml`` were needed to keep it, each measured in the note above its entry:
#:
#: * ``MRN`` separator class ``[\s:#.\-/]*+`` -> ``[^0-9A-Za-z]*+``, for the two
#:   self-identifying labels only -- widening all nine bought a false positive on
#:   ``'See the attached file, 20240115 is the export stamp.'`` and the split removes it
#: * ``ACCOUNT_NUMBER`` separator class ``[\s:#.\-]*+`` -> ``[^0-9A-Za-z]*+``
#: * ``TAX_ID`` gains a label-anchored branch for the spellings that are not
#:   ``NN-NNNNNNN``. Its ``TIN`` label is case-sensitive in both copies, because ``tin``
#:   is an English noun and the case-insensitive spelling claimed
#:   ``'The tin, 123456789 units were pressed at the mill.'``
#:
#: The direction is the one this module has fixed twice already: **widen the registry,
#: never narrow the gate.** Every string in each gap was a document the gate would have
#: refused (422, ``demo.py --file`` exit 1) and the detector could have vaulted.
#:
#: **What each entry deliberately does NOT claim.**
#:
#: * ``MRN`` is the one refusal. The registry's own note calls out the residual -- "a
#:   chart number in an unlabelled table or CSV column, where no noun introduces it at
#:   all" -- and nothing short of a bare ``\b[0-9]{6,10}\b`` rule reaches it. Measured
#:   on the 37-document adversarial set: a bare 6-10 digit rule claims **20 of 37**,
#:   including every invoice number, order number, part number, ZIP+4, timestamp and
#:   epoch in it. As a *gate* pattern each of those is a 422 on an ordinary document,
#:   so the unlabelled MRN stays refused and is declared rather than half-fixed. The
#:   labelled MRN is claimed, with the two self-identifying labels only (``mrn``,
#:   ``medical record``) rather than the registry's nine -- ``record``, ``chart``,
#:   ``patient``, ``subject``, ``file`` are ordinary nouns, and a *denial* wants a
#:   tighter grip on the label than a *detection* does.
#: * ``ACCOUNT_NUMBER`` claims ``account``/``acct``/``a/c`` and not ``routing``/``aba``.
#:   A routing number is published by the Federal Reserve; blocking on one is a denial
#:   with no privacy benefit.
#: * ``TAX_ID`` carries the unlabelled ``NN-NNNNNNN`` grouping because the registry has
#:   always claimed exactly that shape unconditionally, so the copy adds no denial the
#:   pipeline did not already make -- it only makes the claim survive an edit to the
#:   config. The bare nine-digit run with no label anywhere near it is refused here for
#:   the same reason it is refused for ``SSN``.
_INDEPENDENT_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("SSN", re.compile(r"\b(?P<v>[0-9]{3}[-. ][0-9]{2}[-. ][0-9]{4})\b")),
    (
        "SSN",
        re.compile(
            r"\b(?:ssns?|s\.s\.n\.?|social\s+security|soc\.?\s*sec\.?|ss\s*#|itins?)"
            r"[^0-9A-Za-z]{0,24}(?:(?:number|num|nbr|no|id|#)\.?[^0-9A-Za-z]{0,24})?"
            r"(?:(?:is|was)[^0-9A-Za-z]{0,24})?"
            r"(?P<v>[0-9]{3}[-. ]?[0-9]{2}[-. ]?[0-9]{4})(?![0-9])",
            re.IGNORECASE,
        ),
    ),
    # MRN -- labelled only, and only the two labels that name a medical record and
    # nothing else. The copula is nested inside the number-word group on purpose: it
    # mirrors the registry, whose note measured that a free-standing "is" turns
    # "Records show 8814027 encounters" into an identifier.
    (
        "MRN",
        re.compile(
            r"\b(?:mrn|medical\s+record)s?\.?[^0-9A-Za-z]{0,24}"
            r"(?:(?:number|num|no|ident|id|ref|#)\.?[^0-9A-Za-z]{0,24}"
            r"(?:(?:is|was)[^0-9A-Za-z]{0,24})?)?"
            r"(?P<v>[0-9]{6,10})\b",
            re.IGNORECASE,
        ),
    ),
    # ACCOUNT_NUMBER -- the 8-17 digit run and the four-group card/IBAN-style spelling,
    # both introduced by an account noun phrase. Copula nested, as for MRN.
    (
        "ACCOUNT_NUMBER",
        re.compile(
            r"\b(?:acct|account|a/c)s?\.?[^0-9A-Za-z]{0,24}"
            r"(?:(?:number|num|no|ident|id|ref|#)\.?[^0-9A-Za-z]{0,24}"
            r"(?:(?:is|was)[^0-9A-Za-z]{0,24})?)?"
            r"(?P<v>[0-9]{8,17}|[0-9]{4}(?:[ -][0-9]{4}){2,3})\b",
            re.IGNORECASE,
        ),
    ),
    # TAX_ID -- the canonical IRS grouping standing alone, ...
    ("TAX_ID", re.compile(r"\b(?P<v>[0-9]{2}-[0-9]{7})\b")),
    # ... and any nine-digit spelling a taxpayer-identification noun phrase introduces.
    # Free-standing copula, as for SSN and unlike MRN: every label here is
    # self-identifying, so there is no reading of "EIN is 123456789" in which the
    # digits are a quantity.
    (
        "TAX_ID",
        re.compile(
            r"\b(?:eins?|e\.i\.n\.?|feins?|(?-i:TIN)s?|employer\s+id(?:entification)?"
            r"|(?:federal\s+)?tax(?:payer)?\s*(?:id(?:entification)?|i\.d\.))"
            r"[^0-9A-Za-z]{0,24}"
            r"(?:(?:number|num|nbr|no|ident|id|ref|#)\.?[^0-9A-Za-z]{0,24})?"
            r"(?:(?:is|was)[^0-9A-Za-z]{0,24})?"
            r"(?P<v>[0-9]{2}[- .]?[0-9]{7})\b",
            re.IGNORECASE,
        ),
    ),
)


def _independent_hits(payload: str, protected: list[tuple[int, int]]) -> list[str]:
    """Entity types found by :data:`_INDEPENDENT_PATTERNS` outside our own spans.

    Runs on the raw payload rather than a normalised form because the protected
    spans are raw offsets, and a pass that could not tell our own output apart would
    block every pseudonymization run. The cost is that an SSN split by a zero-width
    character is not seen here; pass 1 sees that one for any value that was vaulted,
    and a value that was neither vaulted nor plainly written is the residual this
    pass narrows rather than closes.

    **The span compared against ``protected`` is group ``v``, not the whole match**,
    and every pattern in the constant is required to carry that group. A pattern that
    matches a label as well as a value would otherwise offer the union of the two to
    :func:`_overlaps`, and ``_overlaps`` excuses on *any* overlap -- so a label that
    happened to abut one of our tokens would excuse a leak sitting beside it. Group
    ``v`` is the value and nothing else, which is the only span our own output can
    honestly account for.
    """
    hits: list[str] = []
    for entity_type, pattern in _INDEPENDENT_PATTERNS:
        for match in pattern.finditer(payload):
            start, end = match.span("v")
            if not _overlaps(start, end, protected):
                hits.append(entity_type)
    return hits


#: The word-boundary occurrence test, owned by
#: :mod:`secure_context_pipeline.textrules` and re-exported here under the name pass 1
#: has always called it. The rule itself -- why the assertions are per-side, why
#: underscore is a boundary, why the ``in`` pre-filter is exact -- is documented at the
#: definition; this module is one of four consumers and deliberately not the owner.
#:
#: **This is not the only occurrence test pass 1 applies**, and the difference matters
#: to anyone reading it as *the* definition of a leak. It is the right rule for a name
#: and the wrong one for an identifier, because the false-positive argument behind it
#: is a word-list argument: ``Browning`` is a real word containing ``Brown``, while
#: ``batch47-1234567Alpha`` is not a real anything containing a taxpayer ID.
#: :func:`_identifier_needles` scans digit-carrying values without this rule for that
#: reason; the engine's residual sweep still applies it, so the two disagree on purpose
#: -- the gate blocks a shape the sweep leaves behind, which is the safe direction for
#: them to differ in.
_occurs_as_a_unit = occurs_as_a_unit
