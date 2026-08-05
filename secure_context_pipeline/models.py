"""Shared Pydantic v2 models (build doc section 7).

Three schema-level guarantees live here, and all three are load-bearing for the
zero-PII-in-logs requirement:

1. ``AuditEvent`` has no field capable of holding an original value: ``detail``
   rejects string values over 64 characters, and every remaining string column is
   length-capped, so the claim is enforced by the schema rather than by convention.
   The check quantifies over ``model_fields`` rather than over a list of column
   names, because a list only ever covers the columns its author remembered.
2. **Every model in this module is classified for both exits, and the
   classification is quantified over ``model_fields`` for the same reason point 1
   is.** The two exits are ``repr()``/``str()`` -- what an accidental
   ``f"{result}"`` in a log line emits -- and ``model_dump_json()`` -- what
   reaches an HTTP response or a JSON log line. They need *different* rules,
   because a field can be forbidden on one and mandatory on the other::

       repr   masks originals AND surrogates: a log reader cannot tell a
              pseudonymized fake from a real value, so both are '***'.
       dump   masks originals on the PROVIDER-ward path only: the user-ward
              product (``PipelineResult.restored_text``) has to serialize -- it
              is the answer the caller asked for.

   The masked-in-``repr`` set is declared per class as
   :attr:`_MaskedRepr.REPR_MASKED` and rendered by one shared ``__repr__`` that
   walks ``model_fields``, so a newly added field is *printed* by default and a
   newly added **sensitive** field fails ``tests/test_models.py`` until someone
   classifies it. Hand-written ``__repr__`` bodies had the opposite failure mode:
   they silently dropped new fields, which hid the leak the test was looking for.
   This was not a hypothetical -- ``SpanOut.surrogate`` (the same field
   ``TokenRecord`` masks, in the object the API returns) and
   ``PipelineResult.restored_text`` (originals by construction) both rendered in
   full before the quantified test existed.
3. ``Detection.text`` is *also* masked on serialization. ``repr`` masking alone is
   a leak waiting to happen: ``model_dump_json()`` bypasses ``__repr__`` entirely,
   and it is the form that reaches HTTP responses and JSON log lines. ``text`` is
   for in-memory splicing only; read it as an attribute, never by serializing.

   ``Detection.text`` is the only original value on the *provider-ward* path --
   the models that flow toward obfuscation and egress. It is not the only original
   value in the package: :class:`PipelineResult` carries ``restored_text``, which
   is originals by construction. That one is user-ward and is the documented
   response body (``api/schemas.py`` rule 1), which is why it still *serializes* --
   but it is masked in ``repr`` like every other original, because a log line is
   not a response body. The distinction is the point, so the two must not be
   conflated.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, ClassVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

# One ceiling, one definition. `errors.py` owns it because it is the leaf module
# of the two and because the rule originates there (build doc section 16: no
# exception may carry content); `AuditEvent.detail` applies the same number for
# the same reason. Re-exported so `models.MAX_DETAIL_VALUE_LEN` keeps working.
from secure_context_pipeline.errors import MAX_DETAIL_VALUE_LEN

__all__ = [
    "MASK",
    "MAX_AUDIT_LABEL_LEN",
    "MAX_DETAIL_VALUE_LEN",
    "AuditEvent",
    "DetailMap",
    "Detection",
    "EgressReport",
    "EntityAction",
    "EntityCategory",
    "ObfuscationResult",
    "Offset",
    "PipelineResult",
    "RedactionRecord",
    "Score",
    "SpanOut",
    "TokenRecord",
]

MASK = "***"
#: Ceiling for the audit event's free-text columns. Generous next to real values
#: (a uuid4 hex is 32, an entity type is <= 20, a token ID is 8) and small enough
#: that no original value can hide in one.
MAX_AUDIT_LABEL_LEN = 128

#: Confidence score. Bounded to [0, 1] because the threshold policy (obfuscate /
#: redact / ignore) is meaningless if a detector can report a score outside it.
Score = Annotated[float, Field(ge=0.0, le=1.0)]
#: A character offset into the original document. Never negative.
Offset = Annotated[int, Field(ge=0)]
#: The audit ``detail`` map. Declared as a read-only ``Mapping`` on purpose: the
#: stored value is a ``MappingProxyType``, so ``event.detail[k] = v`` is both a
#: mypy error and a runtime ``AttributeError``. See :class:`AuditEvent`.
DetailMap = Mapping[str, int | float | str]


class EntityCategory(StrEnum):
    PII = "PII"
    PHI = "PHI"
    LEGAL = "LEGAL"
    FIN = "FIN"


class EntityAction(StrEnum):
    """What the engine did with a span."""

    OBFUSCATED = "obfuscated"
    REDACTED = "redacted"
    STRIPPED = "stripped"


def _check_span_order(start: int, end: int) -> None:
    """A span may not run backwards. Offsets index into the original document, and
    a reversed pair silently slices the wrong text (or nothing) downstream."""
    if end < start:
        raise ValueError(f"span end {end} precedes start {start}")


class _MaskedRepr(BaseModel):
    """Base for models with a field that must never render into a log line.

    Subclasses name the fields in :attr:`REPR_MASKED`; ``__repr__`` walks
    ``model_fields`` and substitutes :data:`MASK` for those, printing every other
    field normally. Declaring the *masked* set rather than writing the whole
    ``repr`` by hand is the load-bearing part: a hand-written body omits any field
    added after it was written, so the field never appears in ``repr()`` and the
    leak test that greps ``repr()`` for a canary can never see it. Here a new field
    prints by default, so ``tests/test_models.py`` sees the canary and fails until
    the field is classified as printable or masked.

    This class declares no fields of its own, so it contributes nothing to any
    subclass's schema or serialization -- it changes ``repr``/``str`` only.
    """

    #: Field names replaced with :data:`MASK` in ``repr()`` and ``str()``.
    REPR_MASKED: ClassVar[frozenset[str]] = frozenset()

    def __repr__(self) -> str:
        cls = type(self)
        rendered = ", ".join(
            f"{name}={(MASK if name in cls.REPR_MASKED else getattr(self, name))!r}"
            for name in cls.model_fields
        )
        return f"{cls.__name__}({rendered})"

    __str__ = __repr__


class Detection(_MaskedRepr):
    """A detected span. ``text`` is an ORIGINAL VALUE -- memory only, never logged.

    ``text`` is masked in ``repr``/``str`` *and* on serialization; see the module
    docstring for why ``repr`` masking alone is not enough.
    """

    model_config = ConfigDict(frozen=True)

    REPR_MASKED: ClassVar[frozenset[str]] = frozenset({"text"})

    entity_type: str
    category: EntityCategory
    start: Offset
    end: Offset
    text: str
    score: Score

    @model_validator(mode="after")
    def _ordered(self) -> Detection:
        _check_span_order(self.start, self.end)
        return self

    @field_serializer("text", when_used="always")
    @staticmethod
    def _mask_text(value: str) -> str:
        return MASK


class TokenRecord(_MaskedRepr):
    """Vault-side record for one obfuscated entity.

    ``surrogate`` is masked in repr: under pseudonymization it is a realistic
    fake that a reader could mistake for a real value, and masking uniformly is
    cheaper to reason about than masking conditionally.

    ``token_id`` is deliberately an unconstrained ``str`` here rather than a
    pattern-checked 8-hex field. The shape is enforced where it is *created* and
    where it is *emitted* -- :func:`~secure_context_pipeline.crypto.keys.derive_token_id`
    can only return ``hexdigest()[:8]``, and
    :func:`~secure_context_pipeline.surrogates.format_surrogate` rejects anything
    else before it can reach a payload. Duplicating the check on the transport
    model would give a second place for the definition of "a token ID" to live.
    """

    model_config = ConfigDict(frozen=True)

    REPR_MASKED: ClassVar[frozenset[str]] = frozenset({"surrogate"})

    session_id: str
    token_id: str
    entity_type: str
    category: EntityCategory
    surrogate: str
    created_at: float


class RedactionRecord(BaseModel):
    """A span replaced with ``[REDACTED_<TYPE>]``. No ``text`` field, by design."""

    model_config = ConfigDict(frozen=True)

    entity_type: str
    start: Offset
    end: Offset
    score: Score

    @model_validator(mode="after")
    def _ordered(self) -> RedactionRecord:
        _check_span_order(self.start, self.end)
        return self


class SpanOut(_MaskedRepr):
    """UI/API-safe span: offsets into the original document, no original-value field.

    ``surrogate`` is the *same value* :class:`TokenRecord` carries, so it is masked
    in ``repr`` for the same reason: under pseudonymization it is a realistic fake
    a log reader could not distinguish from a real value. It was unmasked here
    while ``TokenRecord`` masked it -- and this is the object the API returns and
    the UI renders, so it is the copy far more likely to reach a log line.

    Masked in ``repr`` only. ``surrogate`` still **serializes**: the UI's highlight
    panel needs it to show which fake stands for which span, and it is a value the
    provider already saw.
    """

    REPR_MASKED: ClassVar[frozenset[str]] = frozenset({"surrogate"})

    entity_type: str
    category: EntityCategory
    start: Offset
    end: Offset
    score: Score
    action: EntityAction
    surrogate: str | None = None

    @model_validator(mode="after")
    def _ordered(self) -> SpanOut:
        _check_span_order(self.start, self.end)
        return self


class ObfuscationResult(BaseModel):
    obfuscated_text: str
    tokens: list[TokenRecord] = Field(default_factory=list)
    redactions: list[RedactionRecord] = Field(default_factory=list)
    stripped: list[RedactionRecord] = Field(default_factory=list)
    # One entry per ORIGINAL span, carrying what the engine did to it. The engine
    # is the only component that knows this; reconstructing it downstream from
    # `tokens` would be lossy (tokens are deduped, spans are not). Powers
    # PipelineResult.detections and the UI highlight panels.
    spans: list[SpanOut] = Field(default_factory=list)


class AuditEvent(BaseModel):
    """Hash-chained audit record.

    This schema *cannot hold* an original value: ``detail`` accepts only counts,
    latencies, hashes, and short machine codes, and every remaining string column
    is length-capped at :data:`MAX_AUDIT_LABEL_LEN`. Without those caps the
    "no field capable of holding an original value" claim was untrue --
    ``entity_type`` and ``token_id`` accepted a 5 000-character string, and both
    are written from values parsed out of untrusted LLM output.

    That claim is quantified over *every* field, so the test that checks it
    (``test_no_audit_event_field_can_hold_a_content_sized_string``) enumerates
    ``model_fields`` rather than a hand-written list of column names. The list it
    replaced named five columns and silently omitted ``prev_hash`` and
    ``entry_hash``, which were uncapped for exactly as long as nothing looked.

    **The ceilings are enforced, not merely declared.** A validator that runs once
    at construction guards nothing on a mutable model, and both escapes were real::

        event.detail["value"] = original   # in-place: the validator never re-runs
        event.entity_type = original       # assignment: pydantic does not re-validate

    So the model is ``frozen`` (assignment raises) and ``detail`` is stored as a
    read-only :class:`~types.MappingProxyType` over a *copy* of the caller's dict
    (in-place mutation raises, and a caller who keeps a reference to the dict it
    passed in cannot reach through it afterwards). ``model_dump`` still emits a
    plain dict, so the persisted and serialized forms are unchanged.

    ``model_construct()`` skips validation by design and remains a way around this;
    the audit writer re-checks at the INSERT boundary for exactly that reason.
    """

    model_config = ConfigDict(frozen=True)

    seq: int | None = None
    ts: float
    session_id: str = Field(max_length=MAX_AUDIT_LABEL_LEN)
    run_id: str | None = Field(default=None, max_length=MAX_AUDIT_LABEL_LEN)
    event_type: str = Field(max_length=MAX_AUDIT_LABEL_LEN)
    entity_type: str | None = Field(default=None, max_length=MAX_AUDIT_LABEL_LEN)
    token_id: str | None = Field(default=None, max_length=MAX_AUDIT_LABEL_LEN)
    detail: DetailMap = Field(default_factory=dict)
    # Capped like every other string column. These hold a 64-char sha256 hexdigest
    # (or "" at genesis), so the ceiling is slack in practice -- but "no field can
    # hold an original value" has to be true of *every* field, and these two were
    # the ones a hand-written list of columns kept missing.
    prev_hash: str | None = Field(default=None, max_length=MAX_AUDIT_LABEL_LEN)
    entry_hash: str | None = Field(default=None, max_length=MAX_AUDIT_LABEL_LEN)

    @field_validator("detail")
    @classmethod
    def _reject_long_values(cls, v: DetailMap) -> DetailMap:
        for key, value in v.items():
            if isinstance(value, str) and len(value) > MAX_DETAIL_VALUE_LEN:
                raise ValueError(
                    f"audit detail {key!r} exceeds {MAX_DETAIL_VALUE_LEN} chars; "
                    "audit records must not carry content"
                )
        # `dict(v)` is belt-and-braces, and honestly so: pydantic already builds a
        # new dict when it coerces the `Mapping` annotation, so replacing this with
        # `MappingProxyType(v)` keeps every test green. The copy is kept because it
        # makes "the caller cannot reach through the reference it passed in" a
        # property of this line rather than of pydantic's coercion behaviour, which
        # is not something this module should have to re-verify on each upgrade.
        # The read-only wrapper, by contrast, is load-bearing and is sabotage-tested.
        return MappingProxyType(dict(v))

    @field_serializer("detail", when_used="always")
    @staticmethod
    def _plain_detail(value: DetailMap) -> dict[str, int | float | str]:
        """Serialize as an ordinary dict -- the read-only wrapper is an in-memory
        guard, not part of the persisted or wire format."""
        return dict(value)


class EgressReport(BaseModel):
    """Result of a passing egress check. Emitted into the audit trail."""

    payload_sha256: str
    payload_chars: int
    originals_scanned: int
    rescan_warnings: int = 0
    elapsed_ms: float = 0.0


class PipelineResult(_MaskedRepr):
    """One end-to-end run. Every field here is user-ward: nothing on this model is
    ever sent to a provider.

    ``obfuscated_payload`` and ``raw_llm_response`` are not in the build doc's
    section 7 schema; they exist because section 9.10's demo shows all four stages
    side by side, and showing the payload the provider actually received is the
    inspectable form of the zero-PII claim. ``obfuscated_payload`` is exactly the
    string the egress gate cleared. ``raw_llm_response`` is untrusted provider
    output and is treated as such everywhere -- it is displayed, and it is scanned
    for token IDs by the restorer; it is never parsed for control flow.

    ``restored_text`` is **originals by construction** -- restoration is the step
    that puts them back -- so it is masked in ``repr``/``str``. User-ward is an
    argument about the *response body*, not about ``f"{result}"`` in a log line,
    and section 16 forbids the latter for any original regardless of direction.
    :class:`~secure_context_pipeline.deobfuscation.restorer.RestoreResult` already
    masks the same text one stage earlier; this model was the copy that did not,
    which made the final object the weakest link in the chain.

    It still **serializes** in full: it is the documented response body
    (``api/schemas.py`` rule 1) and the answer the caller asked for. ``repr`` and
    ``model_dump_json`` are classified separately for exactly this case; see the
    module docstring.

    The other two text fields are deliberately *not* masked in ``repr``:
    ``obfuscated_payload`` is byte-for-byte what the egress gate cleared for the
    provider and ``raw_llm_response`` is what the provider sent back, so both are
    provider-visible by construction. Masking them would suggest a log line is a
    worse exposure than the network call that already happened.
    """

    REPR_MASKED: ClassVar[frozenset[str]] = frozenset({"restored_text"})

    run_id: str
    restored_text: str
    obfuscated_payload: str
    raw_llm_response: str
    strategy: str
    detections: list[SpanOut] = Field(default_factory=list)
    stats: dict[str, float] = Field(default_factory=dict)
    audit_seq: list[int] = Field(default_factory=list)
