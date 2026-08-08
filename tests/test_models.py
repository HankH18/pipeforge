"""Content-exposure tests for :mod:`secure_context_pipeline.models` and ``config``.

Build doc section 16 is the requirement: no original entity value may ever be
logged, printed, ``repr``-ed, or embedded anywhere. A model has **four** ways to
emit its fields, and until this module existed only one field (``Detection.text``)
was checked on any of them:

* ``repr()`` / ``str()`` / ``f"{model}"`` -- what an accidental interpolation in a
  log line produces. Masked.
* ``model_dump()`` / ``model_dump(mode="json")`` / ``model_dump_json()`` *at
  default settings* -- what reaches an HTTP response body or a JSON log line, and
  which bypasses ``__repr__`` entirely. Masked on the provider-ward path.
* **attribute access and its aliases** -- ``getattr``, ``model.__dict__``,
  ``vars()``, ``dict(model)``, ``list(model)``, ``pickle``, ``copy.deepcopy``,
  ``model_copy().__dict__``, and ``model_dump(serialize_as_any=True)``, which asks
  pydantic to serialize by runtime type and so skips every ``field_serializer``.
  **Not masked**, and not maskable while the value must stay readable.
* **``pydantic.ValidationError``** -- raised *instead of* a model when construction
  is refused, so nothing declared on the class has run yet and no mask on it can
  apply. It carries the whole input mapping in ``errors()[0]["input"]`` and an
  elided excerpt of it in ``str(exc)``. **Not masked**, and named here because a
  taxonomy that stops at three exits reads as complete and is not; see
  ``test_a_refused_construction_is_the_fourth_exit_and_carries_the_input_dict``.

This module's docstring used to say there were exactly two, and ``models.py`` and
``config.py`` said so too. That was measurably false in the worse direction:
``Detection.model_dump()`` returned ``'***'`` while ``dict(detection)['text']``
returned the original, and ``Settings.model_dump()`` returned ``'***'`` while
``Settings.model_dump(serialize_as_any=True)`` returned the base64 master key. No
test looked at any of it. So the third exit is now measured field by field and
vector by vector in :data:`THIRD_EXIT_LEAKS` below -- pinned in **both**
directions, so neither a new leak nor a silently-fixed one can leave the prose
stale. A limitation stated exactly is worth more than a guarantee that is not one.

**Why this is quantified rather than a list of assertions.** ``models.py``'s own
docstring states the lesson -- "a list only ever covers the columns its author
remembered" -- and the repository then proved it: ``SpanOut.surrogate`` was
unmasked while ``TokenRecord.surrogate``, the *same value*, was masked, and
``PipelineResult.restored_text`` (originals by construction) printed in full.
Three hand-written ``repr`` tests existed and none of them looked at those fields.

So the tests below discover the models, discover every field that can carry a
string, plant a canary in it, and require an explicit **named** entry in
:data:`REPR_PRINTABLE` / :data:`DUMP_SERIALIZABLE` for every field allowed to
render it. A field that is neither masked nor named fails. That inverts the
default: a new field is a test failure until someone classifies it, instead of
silently joining the set nobody checks.

**The allow-lists are checked in both directions.** An entry naming a field that
does not exist fails (so a rename cannot leave a stale exemption behind), and a
field the allow-list says is printable must *actually* print the canary -- because
a builder that quietly failed to set a field would make every masking assertion in
this module vacuously true. That positive check is the one that keeps the harness
from sharing a blind spot with the thing it checks.
"""

from __future__ import annotations

import base64
import copy
import inspect
import pickle
import secrets
import types
import typing
from collections.abc import Callable, Mapping
from enum import Enum

import pytest
from pydantic import BaseModel, ValidationError

from secure_context_pipeline import config as config_module
from secure_context_pipeline import models
from secure_context_pipeline.api import schemas as api_schemas
from secure_context_pipeline.api.schemas import AuditQueryResponse
from secure_context_pipeline.config import Settings
from secure_context_pipeline.errors import (
    MAX_DETAIL_VALUE_LEN,
    PipelineError,
    VaultMissError,
)
from secure_context_pipeline.models import (
    MASK,
    AuditEvent,
    EntityCategory,
    SpanOut,
    TokenRecord,
)

#: Distinctive enough that a substring match cannot be a coincidence, and short
#: enough to satisfy every length cap in the module (``AuditEvent`` string columns
#: cap at 128 chars, ``detail`` values at 64).
CANARY = "Zelphinia-Quarrowmont-4471902"

# ---------------------------------------------------------------------------
# Classification: which fields are ALLOWED to render a string, and why.
#
# Anything not named here must be masked (i.e. must appear in its model's
# `REPR_MASKED`). The reason strings are part of the test: an entry without one
# fails, so "add it to the allow-list" cannot be done without saying why.
# ---------------------------------------------------------------------------

_LABEL = "an entity-type label from entities.yaml -- config-supplied, never document content"
_TOKEN_ID = "an 8-hex token ID; it is printed in the outbound payload by design"
_HASH = "a sha256 hexdigest -- a hash of content, not content"
_RUN_ID = "a uuid4 hex run identifier, generated by the pipeline"
_STRATEGY = "a strategy name from a closed Literal set"
_PROVIDER_VISIBLE = (
    "provider-visible by construction: this is what was sent to / returned by the LLM"
)
_STRUCTURED = "counts, latencies, hashes and short machine codes; string values capped at 64 chars"
_METRIC_KEYS = "metric names fixed by the emitting code, mapped to floats"
# Session IDs are credential-grade for DELETE /sessions/{id} and are deliberately
# NOT masked here: the audit response and the audit DB carry them by design, and
# masking them in a model repr would not close the exposure that matters (the
# application's own INFO log stream, tracked separately against
# vault/session_registry.py). Naming the reason keeps that trade visible.
_SESSION_ID = "a session identifier; carried by the audit record and response by design"

#: ``(model, field) -> reason`` for fields that may render in ``repr()``/``str()``.
REPR_PRINTABLE: dict[tuple[str, str], str] = {
    ("Detection", "entity_type"): _LABEL,
    ("TokenRecord", "session_id"): _SESSION_ID,
    ("TokenRecord", "token_id"): _TOKEN_ID,
    ("TokenRecord", "entity_type"): _LABEL,
    ("RedactionRecord", "entity_type"): _LABEL,
    ("SpanOut", "entity_type"): _LABEL,
    ("ObfuscationResult", "obfuscated_text"): _PROVIDER_VISIBLE,
    ("AuditEvent", "session_id"): _SESSION_ID,
    ("AuditEvent", "run_id"): _RUN_ID,
    ("AuditEvent", "event_type"): "a machine event code from a fixed vocabulary",
    ("AuditEvent", "entity_type"): _LABEL,
    ("AuditEvent", "token_id"): _TOKEN_ID,
    ("AuditEvent", "detail"): _STRUCTURED,
    ("AuditEvent", "prev_hash"): _HASH,
    ("AuditEvent", "entry_hash"): _HASH,
    ("EgressReport", "payload_sha256"): _HASH,
    ("PipelineResult", "run_id"): _RUN_ID,
    ("PipelineResult", "obfuscated_payload"): _PROVIDER_VISIBLE,
    ("PipelineResult", "raw_llm_response"): _PROVIDER_VISIBLE,
    ("PipelineResult", "strategy"): _STRATEGY,
    ("PipelineResult", "stats"): _METRIC_KEYS,
}

#: ``(model, field) -> reason`` for fields that may render in ``model_dump_json()``.
#:
#: This list is longer than :data:`REPR_PRINTABLE` on purpose, and the difference
#: is the whole design: serialization is the *product* (an HTTP response body),
#: ``repr`` is an accident (a log line). ``PipelineResult.restored_text`` is the
#: answer the caller asked for and must serialize; it must never be logged. A
#: surrogate is a value the provider already saw, so it serializes to the UI --
#: but a log reader cannot tell it from a real value, so it does not print.
DUMP_SERIALIZABLE: dict[tuple[str, str], str] = {
    **REPR_PRINTABLE,
    (
        "TokenRecord",
        "surrogate",
    ): "the fake the provider already saw; the UI maps it back to a span",
    ("SpanOut", "surrogate"): "the fake the provider already saw; the UI maps it back to a span",
    ("PipelineResult", "restored_text"): (
        "the documented response body (api/schemas.py rule 1) -- the answer the caller asked for"
    ),
}

#: ``(model, field) -> reason`` for fields that must NOT survive serialization.
#: Every entry is cross-checked against the model's registered ``field_serializer``
#: decorators, so the mask has to exist in ``models.py`` -- claiming it here is not
#: enough. Together with :data:`DUMP_SERIALIZABLE` this partitions every
#: string-bearing field, which is what makes "no field is unclassified" checkable.
DUMP_MASKED: dict[tuple[str, str], str] = {
    ("Detection", "text"): (
        "the original value on the provider-ward path; in-memory splicing only, never a wire form"
    ),
}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _model_classes() -> list[type[BaseModel]]:
    """Every pydantic model *defined in* ``models.py``.

    Discovered from the module namespace rather than from ``__all__``: a model
    someone forgot to export is still a model that can leak, and it is exactly the
    one a curated list would miss.
    """
    found = [
        obj
        for obj in vars(models).values()
        if inspect.isclass(obj) and issubclass(obj, BaseModel) and obj.__module__ == models.__name__
    ]
    assert found, "no models discovered -- the discovery predicate is broken, not the module"
    return sorted(set(found), key=lambda cls: cls.__name__)


def _is_str(annotation: object) -> bool:
    """``str`` itself, never a ``str`` subclass.

    ``StrEnum`` members are ``str`` subclasses but cannot hold arbitrary text --
    ``EntityCategory("canary")`` raises -- so identity is the right test.
    """
    return annotation is str


def _canary_for(annotation: object) -> object | None:
    """A value carrying :data:`CANARY`, or ``None`` if this annotation cannot hold text.

    Containers count: ``AuditEvent.detail`` is a ``Mapping[str, int | float | str]``
    whose *keys and values* are both caller-supplied, so both get a canary.
    """
    if _is_str(annotation):
        return CANARY

    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)

    if origin in (types.UnionType, typing.Union):
        return CANARY if any(_is_str(arg) for arg in args) else None

    if origin is not None and inspect.isclass(origin) and issubclass(origin, Mapping):
        key_t, value_t = (*args, object, object)[:2]
        if not (_is_str(key_t) or _admits_str(value_t)):
            return None
        return {CANARY if _is_str(key_t) else "k": CANARY if _admits_str(value_t) else 1.0}

    if origin in (list, tuple, set, frozenset):
        return [CANARY] if args and _admits_str(args[0]) else None

    return None


def _admits_str(annotation: object) -> bool:
    if _is_str(annotation):
        return True
    if typing.get_origin(annotation) in (types.UnionType, typing.Union):
        return any(_is_str(arg) for arg in typing.get_args(annotation))
    return False


def _string_bearing_fields() -> list[tuple[type[BaseModel], str]]:
    pairs: list[tuple[type[BaseModel], str]] = []
    for cls in _model_classes():
        for name, info in cls.model_fields.items():
            if _canary_for(info.annotation) is not None:
                pairs.append((cls, name))
    return pairs


def _filler(cls: type[BaseModel], name: str, annotation: object) -> object:
    """A benign, schema-valid value for a field that is not the canary's target.

    Raises on an annotation it does not recognise. That is deliberate: a silently
    skipped field would build a model missing a required value, the constructor
    would raise, and the test would look like it exercised something it did not.
    """
    if _is_str(annotation):
        return "x"
    if annotation is float:
        return 0.5  # inside Score's [0, 1]
    if annotation is int:
        return 0  # inside Offset's [0, inf), and start == end is an ordered span
    if annotation is bool:
        return False
    if inspect.isclass(annotation) and issubclass(annotation, Enum):
        return next(iter(annotation))

    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin in (types.UnionType, typing.Union):
        return _filler(cls, name, args[0])
    if origin is not None and inspect.isclass(origin) and issubclass(origin, Mapping):
        return {}
    if origin in (list, tuple, set, frozenset):
        return []

    raise AssertionError(
        f"tests/test_models.py cannot construct {cls.__name__}.{name}: "
        f"unhandled annotation {annotation!r}. Teach _filler about it -- do not skip it."
    )


def _instance_with(cls: type[BaseModel], field: str, value: object) -> BaseModel:
    kwargs: dict[str, object] = {
        name: _filler(cls, name, info.annotation) for name, info in cls.model_fields.items()
    }
    kwargs[field] = value
    return cls(**kwargs)


def _renderings(model: BaseModel) -> dict[str, str]:
    """Every way this model can turn into text."""
    return {
        "repr()": repr(model),
        "str()": str(model),
        'f"{model}"': f"{model}",
    }


_PAIRS = _string_bearing_fields()
_IDS = [f"{cls.__name__}.{field}" for cls, field in _PAIRS]


# ---------------------------------------------------------------------------
# The allow-lists must describe the module exactly
# ---------------------------------------------------------------------------


def test_every_string_bearing_field_is_classified_for_both_exits() -> None:
    """No field may be unclassified, and no entry may name a field that is gone.

    Both directions matter. Unclassified fields are the leak this module exists to
    catch. Stale entries are the quieter failure: rename ``restored_text`` and an
    allow-list keyed on the old name silently stops constraining anything, while
    the suite stays green.
    """
    discovered = {(cls.__name__, field) for cls, field in _PAIRS}
    assert discovered, "no string-bearing fields discovered -- discovery is broken"

    masked_repr = {
        (cls.__name__, field)
        for cls, field in _PAIRS
        if field in getattr(cls, "REPR_MASKED", frozenset())
    }

    unclassified_repr = discovered - set(REPR_PRINTABLE) - masked_repr
    assert not unclassified_repr, (
        f"string field(s) neither masked in repr nor named in REPR_PRINTABLE: "
        f"{sorted(unclassified_repr)}"
    )
    unclassified_dump = discovered - set(DUMP_SERIALIZABLE) - set(DUMP_MASKED)
    assert not unclassified_dump, (
        f"string field(s) named in neither DUMP_SERIALIZABLE nor DUMP_MASKED: "
        f"{sorted(unclassified_dump)}"
    )
    assert not (set(DUMP_SERIALIZABLE) & set(DUMP_MASKED)), (
        f"contradictory classification -- serializable AND dump-masked: "
        f"{sorted(set(DUMP_SERIALIZABLE) & set(DUMP_MASKED))}"
    )
    assert not (set(DUMP_MASKED) - discovered), (
        f"stale DUMP_MASKED entries naming fields that no longer exist: "
        f"{sorted(set(DUMP_MASKED) - discovered)}"
    )

    assert not (set(REPR_PRINTABLE) & masked_repr), (
        f"contradictory classification -- printable AND masked: "
        f"{sorted(set(REPR_PRINTABLE) & masked_repr)}"
    )
    assert not (set(REPR_PRINTABLE) - discovered), (
        f"stale REPR_PRINTABLE entries naming fields that no longer exist: "
        f"{sorted(set(REPR_PRINTABLE) - discovered)}"
    )
    assert not (set(DUMP_SERIALIZABLE) - discovered), (
        f"stale DUMP_SERIALIZABLE entries naming fields that no longer exist: "
        f"{sorted(set(DUMP_SERIALIZABLE) - discovered)}"
    )

    for table_name, table in (
        ("REPR_PRINTABLE", REPR_PRINTABLE),
        ("DUMP_SERIALIZABLE", DUMP_SERIALIZABLE),
        ("DUMP_MASKED", DUMP_MASKED),
    ):
        for key, reason in table.items():
            assert reason.strip(), f"{table_name}{key} was classified without a stated reason"


def test_dump_masked_fields_have_a_real_field_serializer_in_models_py() -> None:
    """The mask must be declared in the module, not merely asserted in this file.

    Without this, deleting ``Detection._mask_text`` would leave
    :data:`DUMP_MASKED` claiming a guarantee that no code provides -- and the
    canary sweep would fail with a message about a leak rather than about a
    deleted serializer.
    """
    by_name = {cls.__name__: cls for cls in _model_classes()}
    for (model_name, field), _reason in DUMP_MASKED.items():
        cls = by_name[model_name]
        serialized_fields = {
            name
            for decorator in cls.__pydantic_decorators__.field_serializers.values()
            for name in decorator.info.fields
        }
        assert field in serialized_fields, (
            f"{model_name}.{field} is listed as dump-masked but {model_name} registers no "
            f"field_serializer for it -- the mask does not exist in models.py"
        )


def test_repr_masked_names_only_real_string_bearing_fields() -> None:
    """A typo in ``REPR_MASKED`` masks nothing and raises nothing. Catch it here."""
    for cls in _model_classes():
        masked = getattr(cls, "REPR_MASKED", frozenset())
        for field in masked:
            assert field in cls.model_fields, f"{cls.__name__}.REPR_MASKED names absent {field!r}"
            annotation = cls.model_fields[field].annotation
            assert _canary_for(annotation) is not None, (
                f"{cls.__name__}.REPR_MASKED names {field!r}, which cannot hold a string "
                f"({annotation!r}) -- the mask is doing nothing"
            )


# ---------------------------------------------------------------------------
# The canary sweeps
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("cls", "field"), _PAIRS, ids=_IDS)
def test_no_unclassified_string_field_survives_repr(cls: type[BaseModel], field: str) -> None:
    """Plant a canary; require it masked unless :data:`REPR_PRINTABLE` names the field.

    The ``else`` branch is not filler. It asserts the canary *does* appear for
    every allow-listed field, which proves the constructor actually stored the
    canary. Without it a builder bug would make every masked-field assertion in
    this module pass for the wrong reason -- the exact "checker shares a blind spot
    with the thing it checks" failure this suite keeps rediscovering.
    """
    model = _instance_with(cls, field, _canary_for(cls.model_fields[field].annotation))
    key = (cls.__name__, field)

    if key in REPR_PRINTABLE:
        assert CANARY in repr(model), (
            f"{cls.__name__}.{field} is allow-listed as printable but the canary never "
            "reached repr() -- the test builder is not exercising this field"
        )
        return

    for how, rendered in _renderings(model).items():
        assert CANARY not in rendered, f"{cls.__name__}.{field} leaked through {how}"
    assert MASK in repr(model), f"{cls.__name__}.{field} is masked but no {MASK!r} was rendered"


@pytest.mark.parametrize(("cls", "field"), _PAIRS, ids=_IDS)
def test_no_unclassified_string_field_survives_serialization(
    cls: type[BaseModel], field: str
) -> None:
    """The same sweep for ``model_dump()`` / ``model_dump_json()``.

    ``repr`` masking alone is a leak waiting to happen: serialization bypasses
    ``__repr__`` entirely and is the form that reaches an HTTP response.
    """
    model = _instance_with(cls, field, _canary_for(cls.model_fields[field].annotation))
    key = (cls.__name__, field)
    as_json = model.model_dump_json()
    as_dict = str(model.model_dump())

    if key in DUMP_SERIALIZABLE:
        assert CANARY in as_json, (
            f"{cls.__name__}.{field} is allow-listed as serializable but the canary never "
            "reached model_dump_json() -- the test builder is not exercising this field"
        )
        return

    assert CANARY not in as_json, f"{cls.__name__}.{field} leaked through model_dump_json()"
    assert CANARY not in as_dict, f"{cls.__name__}.{field} leaked through model_dump()"


def test_masked_repr_prints_every_other_field_so_a_new_one_cannot_hide() -> None:
    """The masked models must print every field they do not mask.

    This is what makes the canary sweep above meaningful. A hand-written
    ``__repr__`` -- which is what ``Detection`` and ``TokenRecord`` used to have --
    omits any field added after it was written, so a new sensitive field never
    appears in ``repr()``, the canary sweep sees nothing, and the suite reports
    green over a field nobody classified. Rendering from ``model_fields`` makes a
    new field visible by default, so it must be classified before it can ship.
    """
    for cls in _model_classes():
        masked = getattr(cls, "REPR_MASKED", frozenset())
        if not masked:
            continue
        model = _instance_with(cls, next(iter(cls.model_fields)), "x")
        rendered = repr(model)
        assert rendered.startswith(f"{cls.__name__}("), rendered
        for name in cls.model_fields:
            assert f"{name}=" in rendered, (
                f"{cls.__name__}.__repr__ omits {name!r}; a field that never renders can "
                "never be caught leaking by a repr test"
            )


def test_repr_masking_survives_nesting() -> None:
    """A masked child inside a parent must stay masked.

    ``ObfuscationResult.tokens`` and ``PipelineResult.detections`` are lists of
    models that mask a field. Pydantic's default parent ``repr`` calls ``repr()``
    on each element today; if that ever changed to walk ``__repr_args__`` instead,
    every child mask would be bypassed by one interpolation of the parent -- and
    the parent is the object a caller actually holds.
    """
    token = TokenRecord(
        session_id="s",
        token_id="1a2b3c4d",
        entity_type="NAME",
        category=EntityCategory.PII,
        surrogate=CANARY,
        created_at=0.0,
    )
    span = SpanOut(
        entity_type="NAME",
        category=EntityCategory.PII,
        start=0,
        end=1,
        score=0.9,
        action=models.EntityAction.OBFUSCATED,
        surrogate=CANARY,
    )
    parents: list[BaseModel] = [
        models.ObfuscationResult(obfuscated_text="x", tokens=[token], spans=[span]),
        models.PipelineResult(
            run_id="r",
            restored_text=CANARY,
            obfuscated_payload="p",
            raw_llm_response="l",
            strategy="tokenization",
            detections=[span],
        ),
    ]
    for parent in parents:
        for how, rendered in _renderings(parent).items():
            assert CANARY not in rendered, (
                f"{type(parent).__name__} leaked a masked child field through {how}"
            )


# ---------------------------------------------------------------------------
# Settings (config.py) -- the same discipline for secret-shaped fields
# ---------------------------------------------------------------------------

#: Settings fields whose *name* looks secret-shaped but are not secrets. Named,
#: with a reason, for the same purpose as the tables above: adding
#: ``SCP_SIGNING_KEY`` to ``Settings`` must fail this test until someone decides
#: whether it is a secret, rather than shipping unmasked because ``repr=False``
#: was not copied onto it.
NON_SECRET_KEY_SHAPED_SETTINGS: dict[str, str] = {
    "key_provider": "a provider name from a closed Literal set, not key material",
    "llm_max_tokens": "an integer output-token ceiling",
}

_SECRET_SHAPED = ("key", "secret", "token", "password", "credential")


def test_every_secret_shaped_settings_field_is_masked_on_both_exits() -> None:
    """``master_key`` and ``anthropic_api_key`` are the secrets. Prove it stays true.

    ``config.py`` masks them twice over -- ``repr=False``, a hand-written
    ``__repr__``, and a field serializer -- but all three name the two fields
    explicitly. A third secret added later inherits none of it, and the
    hand-written ``__repr__`` would not even print it, so nothing would look wrong.
    """
    secret_shaped = {
        name
        for name in Settings.model_fields
        if any(marker in name for marker in _SECRET_SHAPED)
        and name not in NON_SECRET_KEY_SHAPED_SETTINGS
    }
    assert secret_shaped == {"master_key", "anthropic_api_key"}, (
        f"secret-shaped Settings fields changed: {sorted(secret_shaped)}. Mask any new one "
        "(repr=False + the _mask_secret serializer) or name it in "
        "NON_SECRET_KEY_SHAPED_SETTINGS with a reason."
    )
    for name, reason in NON_SECRET_KEY_SHAPED_SETTINGS.items():
        assert name in Settings.model_fields, f"stale exemption for absent Settings.{name}"
        assert reason.strip(), f"Settings.{name} was exempted without a stated reason"

    for name in secret_shaped:
        assert Settings.model_fields[name].repr is False, (
            f"Settings.{name} is secret-shaped but not repr=False"
        )


# ---------------------------------------------------------------------------
# The THIRD exit: attribute access and every alias of it
#
# `repr` and `model_dump` are the two exits this file was originally written
# against, and both are masked. They are not the only ways a value leaves a model.
# Pydantic keeps field values in the instance `__dict__`, so every spelling of
# "read the attribute" -- including two `model_dump` calls that opt out of the
# schema -- returns the value in full. That is not a bug to fix here; it is a
# boundary to state exactly, because the alternative is a docstring that promises
# more than the code delivers, which is the failure mode this suite exists for.
#
# The tables below are the statement, and the tests make it a measurement.
# ---------------------------------------------------------------------------


def _pickled(model: BaseModel, field: str) -> str:
    """``pickle.dumps`` output as text.

    ``latin-1`` maps every byte to exactly one character, so an ASCII substring
    search over the decoded form is exact -- no byte can be lost or merged the way
    a lossy decode or a ``repr()`` escape could hide a match.
    """
    return pickle.dumps(model).decode("latin-1")


#: Exit 1. What an accidental ``f"{model}"`` in a log line produces.
REPR_VECTORS: dict[str, Callable[[BaseModel, str], str]] = {
    "repr()": lambda m, _f: repr(m),
    "str()": lambda m, _f: str(m),
    'f"{model}"': lambda m, _f: f"{m}",
}

#: Exit 2. Serialization at its default settings -- HTTP bodies and JSON logs.
DUMP_VECTORS: dict[str, Callable[[BaseModel, str], str]] = {
    "model_dump()": lambda m, _f: repr(m.model_dump()),
    'model_dump(mode="json")': lambda m, _f: repr(m.model_dump(mode="json")),
    "model_dump_json()": lambda m, _f: m.model_dump_json(),
}

#: Exit 3. Attribute access, spelled ten ways. Each entry maps a vector to the
#: reason it cannot be masked -- the reason is a property of the *vector*, not of
#: any field, which is why it is stated once here instead of 60 times below.
UNMASKABLE_VECTORS: dict[str, str] = {
    "getattr()": (
        "the supported read path itself: Detection.text is spliced into the outbound "
        "payload and Settings.master_key is decoded by master_key_bytes(). A model that "
        "hid this value from its own attribute would not be able to do its job."
    ),
    "__dict__": "pydantic stores field values here; this IS the attribute, spelled differently",
    "vars()": "vars(obj) returns obj.__dict__ -- the same object as the row above",
    "dict()": (
        "dict(model) consumes BaseModel.__iter__, which yields __dict__ items directly; "
        "no serializer is involved, so no field_serializer can intercept it"
    ),
    "list()": "the same __iter__ protocol as dict(model), materialised as pairs",
    "model_dump(serialize_as_any=True)": (
        "duck-typed serialization: the caller explicitly asks pydantic to serialize by each "
        "value's RUNTIME type, which bypasses the declared schema and every field_serializer "
        "on it. Documented pydantic behaviour, not a defect in this package."
    ),
    "model_dump_json(serialize_as_any=True)": "the JSON twin of the row above, same mechanism",
    "pickle.dumps()": (
        "pickle serialises __dict__ and must preserve it byte-for-byte to round-trip; "
        "a masking pickle would produce an object that silently is not the original"
    ),
    "copy.deepcopy().__dict__": "a copy carries the same __dict__ by definition",
    "model_copy().__dict__": (
        "model_copy copies field values rather than serialising them -- deliberately, and "
        "config.py recommends it for exactly that reason"
    ),
}

ATTRIBUTE_VECTORS: dict[str, Callable[[BaseModel, str], str]] = {
    "getattr()": lambda m, f: repr(getattr(m, f)),
    "__dict__": lambda m, _f: repr(m.__dict__),
    "vars()": lambda m, _f: repr(vars(m)),
    "dict()": lambda m, _f: repr(dict(m)),
    "list()": lambda m, _f: repr(list(m)),
    "model_dump(serialize_as_any=True)": lambda m, _f: repr(m.model_dump(serialize_as_any=True)),
    "model_dump_json(serialize_as_any=True)": lambda m, _f: m.model_dump_json(
        serialize_as_any=True
    ),
    "pickle.dumps()": _pickled,
    "copy.deepcopy().__dict__": lambda m, _f: repr(copy.deepcopy(m).__dict__),
    "model_copy().__dict__": lambda m, _f: repr(m.model_copy().__dict__),
}

_ALL_ATTRIBUTE_VECTORS = frozenset(ATTRIBUTE_VECTORS)

#: ``(model, field) -> the exact set of exit-3 vectors the value survives.``
#:
#: This is the allow-list, and it is an equality, not a ceiling: the measured set
#: must match it exactly. That direction matters twice over. A value that starts
#: surviving a *new* vector fails, which is the leak case. A value that stops
#: surviving one also fails -- because either somebody hardened the model and the
#: prose in ``models.py``/``config.py`` is now stale, or the test builder quietly
#: failed to plant the value at all, which would make every masking assertion in
#: this file vacuously true. That second case is the one this suite has had to
#: rediscover repeatedly, so it is checked structurally rather than trusted.
#:
#: Every field here is a key or an original. The set is *derived* from the
#: declarations (``REPR_MASKED``, :data:`DUMP_MASKED`, ``repr=False``) by
#: :func:`_sensitive_fields`, and the test below asserts the derivation and this
#: table name the same fields -- so a new secret cannot ship unclassified.
THIRD_EXIT_LEAKS: dict[tuple[str, str], frozenset[str]] = {
    ("Detection", "text"): _ALL_ATTRIBUTE_VECTORS,
    ("PipelineResult", "restored_text"): _ALL_ATTRIBUTE_VECTORS,
    ("SpanOut", "surrogate"): _ALL_ATTRIBUTE_VECTORS,
    ("Settings", "anthropic_api_key"): _ALL_ATTRIBUTE_VECTORS,
    ("Settings", "master_key"): _ALL_ATTRIBUTE_VECTORS,
    ("TokenRecord", "surrogate"): _ALL_ATTRIBUTE_VECTORS,
}


def _sensitive_fields() -> list[tuple[type[BaseModel], str]]:
    """Every field the package *declares* to be a key or an original value.

    Derived from the declarations themselves -- each model's ``REPR_MASKED``,
    :data:`DUMP_MASKED`, and ``Settings``' ``repr=False`` -- rather than from a
    hand-written list, for the reason ``models.py`` states and this repository has
    proved more than once: a list only covers what its author remembered.
    """
    by_name = {cls.__name__: cls for cls in _model_classes()}
    pairs: set[tuple[type[BaseModel], str]] = set()
    for cls in _model_classes():
        pairs.update((cls, name) for name in getattr(cls, "REPR_MASKED", frozenset()))
    pairs.update((by_name[model_name], name) for model_name, name in DUMP_MASKED)
    pairs.update(
        (Settings, name) for name, info in Settings.model_fields.items() if info.repr is False
    )
    assert pairs, "no sensitive fields discovered -- the derivation is broken, not the package"
    return sorted(pairs, key=lambda pair: (pair[0].__name__, pair[1]))


def _sensitive_instance(cls: type[BaseModel], field: str) -> tuple[BaseModel, str]:
    """An instance of ``cls`` carrying a distinctive value in ``field``, and that value.

    The value is computed here and returned *independently* of the instance -- it is
    never read back off the model with ``getattr``. If it were, a builder that
    dropped the value would still agree with itself and every leak check would pass
    over an empty field. The ``getattr()`` vector then serves as the anchor: it must
    always report a leak, which is only possible if the plant actually landed.
    """
    if cls is Settings:
        # `master_key` has to survive Settings' own base64-and-length validation,
        # so the planted value is a real 32-byte key: 44 distinctive base64
        # characters, which is exactly what escapes in production if one of these
        # vectors is taken. Both secrets are always set, so the instance is valid
        # whichever one is under test.
        #
        # `anthropic_api_key` MUST be passed under its alias. It declares
        # `validation_alias=AliasChoices("ANTHROPIC_API_KEY")`, which *replaces* the
        # field name as an accepted input key, and `extra="ignore"` then silently
        # discards the field-name spelling -- `Settings(anthropic_api_key=...)`
        # leaves the field at None with no error. The `getattr()` anchor below is
        # what caught that; without it this builder would have been measuring an
        # empty field and reporting the absence of a value as the absence of a leak.
        key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        api_key = f"sk-ant-{CANARY}"
        settings = Settings(**{"master_key": key, "ANTHROPIC_API_KEY": api_key})  # type: ignore[arg-type]
        return settings, key if field == "master_key" else api_key
    return _instance_with(cls, field, CANARY), CANARY


def _measure(cls: type[BaseModel], field: str) -> dict[str, frozenset[str]]:
    """Which vectors, in each of the three exits, emit the planted value."""
    model, planted = _sensitive_instance(cls, field)
    groups = {"repr": REPR_VECTORS, "dump": DUMP_VECTORS, "attribute": ATTRIBUTE_VECTORS}
    return {
        group: frozenset(
            name for name, render in vectors.items() if planted in render(model, field)
        )
        for group, vectors in groups.items()
    }


_SENSITIVE = _sensitive_fields()
_SENSITIVE_IDS = [f"{cls.__name__}.{field}" for cls, field in _SENSITIVE]


def test_the_three_exit_vector_tables_are_well_formed_and_disjoint() -> None:
    """The tables are the specification; check the specification before using it.

    A vector listed in two exits, or an ``UNMASKABLE_VECTORS`` reason with no
    matching renderer, would make the sweeps below quietly measure something other
    than what they claim to.
    """
    groups = {"repr": REPR_VECTORS, "dump": DUMP_VECTORS, "attribute": ATTRIBUTE_VECTORS}
    seen: set[str] = set()
    for name, vectors in groups.items():
        assert vectors, f"the {name} exit has no vectors"
        overlap = seen & set(vectors)
        assert not overlap, f"vector(s) claimed by two exits: {sorted(overlap)}"
        seen |= set(vectors)

    assert set(UNMASKABLE_VECTORS) == set(ATTRIBUTE_VECTORS), (
        "every attribute-access vector needs a stated reason it cannot be masked, and every "
        "stated reason needs a vector that exercises it; symmetric difference: "
        f"{sorted(set(UNMASKABLE_VECTORS) ^ set(ATTRIBUTE_VECTORS))}"
    )
    for name, reason in UNMASKABLE_VECTORS.items():
        assert reason.strip(), f"{name} was exempted without a stated reason"


def test_every_declared_key_and_original_is_named_in_the_third_exit_table() -> None:
    """The derived sensitive set and :data:`THIRD_EXIT_LEAKS` must name the same fields.

    Both directions, for the usual two reasons. A new secret that nobody classified
    is the leak this table exists to catch; a stale entry naming a renamed field is
    the quieter failure, where the table stops constraining anything while the suite
    stays green.
    """
    derived = {(cls.__name__, field) for cls, field in _SENSITIVE}
    declared = set(THIRD_EXIT_LEAKS)
    assert derived == declared, (
        "THIRD_EXIT_LEAKS does not describe the package. Unclassified key/original field(s): "
        f"{sorted(derived - declared)}. Stale entries naming fields that are no longer "
        f"declared sensitive: {sorted(declared - derived)}."
    )
    for key, vectors in THIRD_EXIT_LEAKS.items():
        unknown = set(vectors) - set(ATTRIBUTE_VECTORS)
        assert not unknown, (
            f"{key} expects a leak on {sorted(unknown)}, which is not an attribute-access "
            "vector. Only exit 3 may be allow-listed -- a leak through repr or through "
            "default serialization is a defect, not an exemption."
        )


@pytest.mark.parametrize(("cls", "field"), _SENSITIVE, ids=_SENSITIVE_IDS)
def test_no_key_or_original_survives_repr_or_default_serialization(
    cls: type[BaseModel], field: str
) -> None:
    """Exits 1 and 2 are the ones that are masked. Prove it for every sensitive field.

    ``repr`` must never carry a key or an original -- that is section 16, and it
    holds regardless of direction, because a log line is not a response body.
    ``dump`` is allowed to carry one only where :data:`DUMP_SERIALIZABLE` says the
    value is the product the caller asked for, and there it is required to, since a
    field that silently stopped serializing would break the API rather than the
    security claim.
    """
    measured = _measure(cls, field)
    assert measured["repr"] == frozenset(), (
        f"{cls.__name__}.{field} is a key or an original and it reached "
        f"{sorted(measured['repr'])} -- section 16 forbids this on every path"
    )

    serializes = (cls.__name__, field) in DUMP_SERIALIZABLE
    expected = frozenset(DUMP_VECTORS) if serializes else frozenset()
    assert measured["dump"] == expected, (
        f"{cls.__name__}.{field} is "
        + ("allow-listed as serializable" if serializes else "not allow-listed as serializable")
        + f" but reached exactly {sorted(measured['dump'])} of the default-serialization "
        f"vectors; expected {sorted(expected)}"
    )


@pytest.mark.parametrize(("cls", "field"), _SENSITIVE, ids=_SENSITIVE_IDS)
def test_the_third_exit_leaks_exactly_what_the_docstrings_claim_it_leaks(
    cls: type[BaseModel], field: str
) -> None:
    """Attribute access is unmasked, and this pins *precisely* how unmasked.

    This test is unusual in asserting that a value **does** escape. It is not
    endorsing the escape -- it is refusing to let ``models.py`` and ``config.py``
    describe a boundary that nobody measures. Those two module docstrings each
    claimed there were two exits and that serialization could not route around the
    repr mask; both statements were false, and no test in the repository could have
    noticed, because none of these vectors appeared anywhere in ``tests/``.

    If a future change closes one of these vectors -- a ``SecretStr`` field, an
    overridden ``__iter__`` -- this test goes red on purpose. Deleting the entry is
    then the correct fix, together with the prose that promised it.
    """
    measured = _measure(cls, field)["attribute"]
    expected = THIRD_EXIT_LEAKS[(cls.__name__, field)]

    assert "getattr()" in measured, (
        f"{cls.__name__}.{field} did not survive plain attribute access. Exactly two things "
        f"cause that, and they need opposite responses. Either the builder never planted the "
        f"value -- in which case every other assertion about this field is vacuous and the "
        f"builder is the bug -- or the field became self-masking (a SecretStr-style wrapper, "
        f"whose repr is '**********'), in which case this is good news and the fix is to "
        f"update THIRD_EXIT_LEAKS and the models.py/config.py docstrings. Vectors that still "
        f"carried it: {sorted(measured)}."
    )
    assert measured == expected, (
        f"{cls.__name__}.{field}: the third exit moved. Newly leaking: "
        f"{sorted(measured - expected)}. No longer leaking: {sorted(expected - measured)}. "
        "Update THIRD_EXIT_LEAKS *and* the module docstrings in models.py / config.py -- "
        "they cite this table by name."
    )


def test_models_and_config_docstrings_describe_the_third_exit() -> None:
    """The prose has to name the unmasked exit, not just the two masked ones.

    Both module docstrings previously described a two-exit world, which read as a
    complete guarantee and was not one. Checking for *mentions of the mechanism*
    rather than for exact sentences is deliberate: an exact-sentence check breaks on
    harmless rewording, while rewriting back to a two-exit story means deleting
    every one of these tokens, which is precisely the regression worth catching.

    What it cannot do is judge whether the prose is *accurate* -- only that it
    engages with the third exit at all. The accuracy check is the measurement test
    above; this one keeps the two from drifting apart.
    """
    tokens = ("__dict__", "serialize_as_any", "pickle", "dict(", "vars(")
    for module in (models, config_module):
        doc = module.__doc__ or ""
        present = [token for token in tokens if token in doc]
        assert len(present) >= 3, (
            f"{module.__name__}'s module docstring mentions only {present} of the "
            f"attribute-access exit's mechanisms {list(tokens)}. A docstring that describes "
            "only repr() and model_dump() overstates the guarantee; see THIRD_EXIT_LEAKS."
        )


# ---------------------------------------------------------------------------
# The exception detail ceiling, which claimed parity with AuditEvent.detail
# ---------------------------------------------------------------------------

#: 408 characters of clinical note, encoded as a single 983-digit integer. This is
#: the shape that walked past `errors.py`: the check was `isinstance(value, str)`
#: and `DetailValue` is `int | float | str | None`, so an integer had no length to
#: measure. `models.py` had already closed the same hole on `AuditEvent.detail`
#: (with a 1,540-char note and a 3,709-digit int) while `errors.py`'s docstring
#: still called itself "the identical guard".
_NOTE = (
    "Patient John Smith, MRN 4823910, DOB 1978-03-02, dx metastatic "
    "pancreatic carcinoma, SSN 123-45-6789. " * 4
)
_NOTE_AS_INT = int.from_bytes(_NOTE.encode("utf-8"), "big")


def test_a_document_encoded_as_an_integer_is_refused_by_a_pipeline_error() -> None:
    """The exception ceiling must measure the RENDERED width, in every type.

    The counterpart of ``test_audit.py::test_a_document_encoded_as_an_integer_is_
    refused_by_the_model``. The audit side had that test; the exception side had
    none, which is exactly why the two guards drifted apart under a docstring
    asserting they were identical.

    This is not a theoretical surface. ``api/errors.py`` writes
    ``dict(exc.detail)`` straight into the HTTP response body, and
    ``PipelineError.__init__`` renders every detail value into ``str(exc)`` -- so a
    document that clears the ceiling is both in the body and in any log line that
    interpolates the exception. Measured before the fix: the 408-character note
    below was accepted as a 983-digit int and produced a 1,004-character
    ``str(exc)`` from which the full text came back with one ``to_bytes``.

    Asserted over three payloads, because a fix that special-cased ``int`` would
    satisfy the interesting half and still be type-conditional. ``float`` is
    deliberately *not* one of them: ``str()`` of any Python float is at most 24
    characters (``str(-sys.float_info.max)`` is 24; the unsigned
    ``sys.float_info.max`` is 23), so no float can breach a
    64-char ceiling and a float case would be a test that cannot fail. The third
    payload is a ``list`` -- ``**detail: DetailValue`` is a type hint and nothing
    enforces it at runtime, so a future call site that passes ``entity_types=[...]``
    where the shipped one passes a joined string renders its whole contents into
    the body. That is the "future call site cannot do so silently" case the module
    docstring says this guard exists for.
    """
    with pytest.raises(ValueError, match="must not carry content"):
        PipelineError(note=_NOTE)
    with pytest.raises(ValueError, match="must not carry content"):
        PipelineError(note=_NOTE_AS_INT)
    with pytest.raises(ValueError, match="must not carry content"):
        PipelineError(entity_types=[_NOTE])  # type: ignore[arg-type]

    # The recovery that makes it a disclosure rather than a curiosity: the premise
    # is that the integer really is the document, not merely a large number.
    recovered = _NOTE_AS_INT.to_bytes((_NOTE_AS_INT.bit_length() + 7) // 8, "big").decode()
    assert recovered.startswith("Patient John Smith"), "premise: the int really is the note"


def test_a_pipeline_error_bounds_the_detail_KEY_as_well_as_the_value() -> None:
    """Both halves of a detail entry reach the response body, so both are bounded.

    ``AuditEvent`` bounds its detail keys for this reason and ``PipelineError`` did
    not, so a 500-character key was accepted here and refused there. No shipped
    call site builds a dynamic key -- they all arrive as kwargs literals -- so this
    closes a hardening gap rather than a live leak, which is the kind that survives
    precisely because nothing exercises it.
    """
    with pytest.raises(ValueError, match="must not carry content"):
        PipelineError(**{"k" * (MAX_DETAIL_VALUE_LEN + 1): 1})


def test_the_tightened_exception_ceiling_still_admits_real_structured_detail() -> None:
    """The positive control: bounding every type must not break the actual callers.

    A ceiling measured on ``str(value)`` now applies to ``None``, ints and floats,
    which no previous version of this guard touched. Every shipped detail value is
    one of these shapes -- ``str(None)`` is 4 characters, a latency renders to ~20 --
    so this pins that the fix costs the real call sites nothing. Without it, a
    later over-tightening (say, rejecting ``None``) would look like a passing test
    run for the two tests above.
    """
    error = PipelineError(
        session_id="a" * MAX_DETAIL_VALUE_LEN,
        token_id=None,
        reason="egress_vault_original",
        hit_count=3,
        elapsed_ms=12.345678901234567,
    )
    assert error.detail["token_id"] is None
    assert error.detail["hit_count"] == 3
    assert VaultMissError(session_id="s", token_id=None).detail["token_id"] is None


def test_the_two_detail_ceilings_are_the_same_guard_and_not_merely_documented_so() -> None:
    """``errors.py`` claims parity with ``AuditEvent.detail``; check the parity.

    The docstring said "mirroring the identical guard" for as long as the two were
    *not* identical, and nothing compared them -- each side had its own tests and
    each passed. So the claim itself is the assertion here: the same payload, in
    every renderable type and on both halves of the entry, must be refused by both
    or accepted by both.

    Quantified over the payloads rather than written as four hand-paired cases for
    the usual reason: the string case is the one an author remembers, and it was
    the only one that agreed.
    """
    payloads: tuple[object, ...] = (
        "x" * (MAX_DETAIL_VALUE_LEN + 1),
        _NOTE_AS_INT,
        [_NOTE],
    )
    for payload in payloads:
        audit_refused = True
        try:
            AuditEvent(ts=0.0, session_id="s", event_type="X", detail={"n": payload})  # type: ignore[dict-item]
        except ValidationError:
            pass
        else:
            audit_refused = False

        error_refused = True
        try:
            PipelineError(n=payload)  # type: ignore[arg-type]
        except ValueError:
            pass
        else:
            error_refused = False

        assert audit_refused == error_refused, (
            f"{type(payload).__name__} payload: AuditEvent.detail "
            f"{'refused' if audit_refused else 'ACCEPTED'} it and PipelineError "
            f"{'refused' if error_refused else 'ACCEPTED'} it. errors.py's docstring "
            "calls these the identical guard; make them identical or stop saying so."
        )

    long_key = "k" * (MAX_DETAIL_VALUE_LEN + 1)
    with pytest.raises(ValidationError):
        AuditEvent(ts=0.0, session_id="s", event_type="X", detail={long_key: 1})
    with pytest.raises(ValueError, match="must not carry content"):
        PipelineError(**{long_key: 1})


# ---------------------------------------------------------------------------
# The retracted "cannot hold an original value" claim, on the response model
# that hands audit rows to an outside reader
# ---------------------------------------------------------------------------


def test_the_audit_response_model_does_serialize_a_short_original() -> None:
    """The measurement behind the retraction, pinned so the overclaim cannot return.

    ``api/schemas.py`` used "``AuditEvent`` cannot hold an original value by
    construction" as the stated reason ``GET /audit`` needs no further filtering.
    ``audit/logger.py`` and the README both retract that claim, and this is the one
    line that disproves it: a name, an MRN, an SSN and an e-mail all fit inside the
    64-character detail ceiling and the 128-character label ceiling, and the real
    response model serialises every one of them.

    Like ``test_the_third_exit_leaks_exactly_what_the_docstrings_claim_it_leaks``,
    this asserts that something **does** come out. It is not endorsing it -- no call
    site writes these values, and the leakage harness measures that on every run.
    It refuses to let the boundary schema justify itself with a guarantee the rest
    of the repository has already withdrawn.
    """
    event = AuditEvent(
        ts=1.0,
        session_id="s",
        event_type="DETECT",
        entity_type="MRN 4823910",
        token_id="john.smith@example.com",
        detail={"v": "John Smith", "ssn": "123-45-6789"},
    )
    body = AuditQueryResponse(events=[event], returned=1, limit=10, offset=0).model_dump_json()
    for original in ("MRN 4823910", "john.smith@example.com", "John Smith", "123-45-6789"):
        assert original in body, (
            f"{original!r} did not survive into the GET /audit body. If a real ceiling now "
            "stops it, that is good news and the fix is to update this test AND the honest "
            "prose in api/schemas.py, audit/logger.py and the README together."
        )

    # What the ceilings *do* buy, and the half of the claim that is true.
    with pytest.raises(ValidationError):
        AuditEvent(ts=1.0, session_id="s", event_type="X", detail={"note": _NOTE})


def test_the_boundary_schema_docstrings_state_the_retracted_claim_honestly() -> None:
    """``api/schemas.py`` must not re-derive its safety from the withdrawn guarantee.

    The overclaim was retracted in three places (README, ``audit/logger.py``,
    ``test_audit.py``) and left standing in the boundary schema, where it was
    load-bearing rather than decorative -- it was the stated reason the audit body
    is returned unfiltered. Prose that contradicts the prose one module away is how
    a retraction gets quietly un-retracted.

    Checked as "the false sentence is gone AND the honest mechanism is named",
    because deleting the claim without replacing it would leave the response model
    with no stated argument at all. The token check follows
    ``test_models_and_config_docstrings_describe_the_third_exit``: mechanisms, not
    exact sentences, so a rewording survives and a rewrite back to "by
    construction" does not.
    """
    module_doc = api_schemas.__doc__ or ""
    class_doc = AuditQueryResponse.__doc__ or ""

    for name, doc in (("module", module_doc), ("AuditQueryResponse", class_doc)):
        assert "structurally incapable of holding one" not in doc, (
            f"api/schemas.py's {name} docstring still asserts the retracted "
            "'incapable of holding an original' guarantee; audit/logger.py retracts it."
        )

    assert "cannot hold an original value by construction" not in class_doc, (
        "AuditQueryResponse still justifies the unfiltered audit body with the claim "
        "the README calls disprovable in one line."
    )
    for token in ("content", "correlation", "leakage harness", "call site"):
        assert token in class_doc.lower(), (
            f"AuditQueryResponse's docstring no longer mentions {token!r}. The honest "
            "argument has three parts -- content cannot get in, a short identifier is "
            "kept out by call site and measured, and the correlation risk is handled by "
            "the proved scope in routes/audit.py -- and dropping one turns the remaining "
            "two back into an overclaim."
        )


def test_the_prompt_cap_comment_names_the_pass_that_rewrites_the_prompt() -> None:
    """``MAX_PROMPT_CHARS`` must not be justified by "the prompt goes out unmodified".

    The comment on the cap said the prompt was spliced into the outbound payload
    verbatim, and said it as the *reason* the cap exists -- in the module whose rule 1
    is declared to govern the whole file. It is false, and it is false in the
    direction that matters: a reader concludes that a name typed into ``prompt`` and
    absent from the document reaches the provider. It does not. The orchestrator runs
    the prompt through the same detector and the same engine as the document before
    the injector builds the payload.

    This test guards the *prose*. The behaviour behind it is measured elsewhere and
    with the real detector, by
    ``test_egress_gate.py::test_pii_typed_into_the_prompt_never_reaches_the_provider``,
    which parametrises eight values that appear nowhere in the document and asserts
    each is absent from what the provider was handed -- six of which used to come back
    ``SENT 200`` with the value on the wire.

    A ``#:`` comment is not reachable through ``__doc__``, so this reads the module
    source. Checked like
    ``test_the_boundary_schema_docstrings_state_the_retracted_claim_honestly``: the
    false sentence is gone AND the honest mechanism is named, so a rewording survives
    and a rewrite back to the old reason does not. The last limb is what keeps this
    from decaying into a spelling test -- the stat keys the comment cites are read
    back off ``PipelineOrchestrator.run``'s own code object, so renaming a stat
    reddens this instead of quietly orphaning the prose that names it.
    """
    # Imported here rather than at module scope: the orchestrator's import graph
    # pulls in spaCy (~1.8 s measured), and this module is otherwise pure-model.
    from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator

    source = inspect.getsource(api_schemas)
    start = source.index("#: Ceiling on the user's question")
    block = source[start : source.index("MAX_PROMPT_CHARS = ", start)]
    # Unwrapped before matching. The retracted sentence wrapped across two ``#:``
    # lines, so a search against the raw block found none of it and the "false
    # sentence is gone" limb could not fire on the very text it was written for.
    comment = " ".join(line.lstrip("#:").strip() for line in block.splitlines())

    assert "spliced into the outbound payload verbatim" not in comment, (
        "the MAX_PROMPT_CHARS comment still gives verbatim splicing as the reason for "
        "the cap. What the injector splices in is the *obfuscated* prompt."
    )
    for token in ("obfuscat", "prompt_entities_detected", "prompt_tokens_issued", "OBFUSCATE"):
        assert token in comment, (
            f"the MAX_PROMPT_CHARS comment no longer mentions {token!r}. The honest "
            "reason for the cap is that the prompt drives its own detect pass, its own "
            "obfuscate pass, a vault write per value and the gate's re-scan -- naming "
            "the pass is what stops the cap being read as 'the prompt goes out as typed'."
        )

    run_consts = {c for c in PipelineOrchestrator.run.__code__.co_consts if isinstance(c, str)}
    for key in ("prompt_entities_detected", "prompt_tokens_issued"):
        assert key in run_consts, (
            f"the comment cites stats[{key!r}], which PipelineOrchestrator.run no longer "
            "writes. Prose that names a key nothing emits is how a retraction rots back "
            "into the original overclaim."
        )
    assert "prompt_entities_detected_XXX" not in run_consts, (
        "premise: the code-object check can tell present from absent, so the two "
        "assertions above are not passing for free."
    )


# ---------------------------------------------------------------------------
# The FOURTH exit: the model that was never built
# ---------------------------------------------------------------------------
def test_a_refused_construction_is_the_fourth_exit_and_carries_the_input_dict() -> None:
    """``models.py`` said "there are *three* exits". There are four.

    The first three are all reads of a model that exists, which is what hid this
    one: a ``ValidationError`` is raised *instead of* the model, so no
    ``__repr__`` and no ``field_serializer`` declared on the class has run, and
    none of them could apply if they had. Pydantic attaches the caller's whole
    input mapping to the error -- ``errors()[0]["input"]`` verbatim, plus a
    middle-elided excerpt inside ``str(exc)`` -- so a ``Detection`` that is
    refused emits the very ``text`` the accepted ``Detection`` masks on two exits.

    Two things are asserted, and the second is the reason this is a test rather
    than a paragraph. That the channel exists, measured on the exact model whose
    ``text`` field is the package's only provider-ward original. And that it is
    **not specific to the span-order check** that exposed it: a plain missing-field
    rejection carries the same dict, so "move that one validator to field level"
    would narrow the channel and leave the taxonomy just as wrong.

    Deliberately not asserting that the leak is closed. It cannot be closed at this
    layer, and the containment is elsewhere and already tested: ``api/errors.py``
    rewrites every ``RequestValidationError`` to field names and counts, and
    ``errors.py``'s hierarchy caps structured detail at
    :data:`MAX_DETAIL_VALUE_LEN`. What this pins is that the boundary is *stated*.
    """
    with pytest.raises(ValidationError) as excinfo:
        models.Detection(
            entity_type="NAME",
            category=EntityCategory.PII,
            start=5,
            end=0,
            text=CANARY,
            score=0.5,
        )
    reported = excinfo.value.errors()[0]["input"]
    assert isinstance(reported, Mapping), (
        "premise: pydantic attaches the input as a mapping for an after-validator; "
        f"got {type(reported).__name__}, so the assertion below would be vacuous"
    )
    assert reported.get("text") == CANARY, (
        "the fourth exit closed. That is good news and this test is now the stale "
        "half: delete the entry and the 'four exits' prose in models.py with it."
    )

    # The same channel, reached without the span-order validator, so nobody can
    # read this as one validator's problem.
    with pytest.raises(ValidationError) as missing:
        models.Detection(  # type: ignore[call-arg]
            entity_type="NAME",
            category=EntityCategory.PII,
            start=0,
            end=len(CANARY),
            text=CANARY,
        )
    assert any(
        isinstance(err["input"], Mapping) and err["input"].get("text") == CANARY
        for err in missing.value.errors()
    ), "a missing-field rejection no longer carries the input dict"

    # And the prose has to name it. Checking for the mechanism rather than an exact
    # sentence, for the reason
    # `test_models_and_config_docstrings_describe_the_third_exit` states.
    doc = models.__doc__ or ""
    counted = doc.lower().replace("*", "")
    assert "four exits" in counted, "models.py still counts three exits"
    assert "three exits" not in counted, (
        "models.py claims both counts. The taxonomy is the guarantee, so it has to "
        "have one number in it."
    )
    for token in ("ValidationError", "input"):
        assert token in doc, (
            f"models.py's exit taxonomy does not mention {token!r}. A three-exit story "
            "reads as complete and is not: a refused construction emits what an "
            "accepted one masks."
        )


def test_no_docstring_in_models_still_claims_an_audit_row_cannot_hold_an_original() -> None:
    """The retracted claim, hunted in the module that declares the ceilings.

    ``AuditEvent``'s length caps make a row incapable of holding *content* -- a
    paragraph, a note, a document. They were also, for a while, described as making
    it "incapable of holding an original value", which is a different and false
    statement: ``"John Smith"``, ``"MRN 4823910"``, an SSN and an e-mail all fit
    inside 64 characters, and no length check can recognise a name.
    ``audit/logger.py``, ``api/schemas.py`` and the README each retract it in so
    many words; two copies survived here, in the module docstring and on
    ``AuditEvent`` itself -- the two places a reader checking the guarantee lands
    first.

    Scanned as source text rather than as ``__doc__`` so class and field docstrings
    are covered together, and phrased as a ban on the *claim* rather than a
    requirement for particular replacement wording, which would break on any honest
    rewrite. The positive half of the statement is asserted too: deleting the
    sentence and saying nothing would also pass a pure ban.
    """
    source = inspect.getsource(models)
    lowered = " ".join(source.lower().split())
    for retracted in (
        "no field capable of holding an original",
        "cannot hold an original",
        "cannot *hold* an original",
    ):
        assert retracted not in lowered, (
            f"models.py still asserts {retracted!r}. The ceilings bound content, not "
            "identifiers; the no-originals property belongs to the call sites and is "
            "measured by the leakage harness."
        )
    assert "cannot hold content" in lowered or "cannot hold *content*" in lowered, (
        "the claim was deleted rather than corrected. The true, narrower statement -- "
        "the ceilings make a row incapable of holding content -- is load-bearing for "
        "the audit design and has to survive the retraction."
    )
    assert "leakage harness" in lowered, (
        "models.py retracts the schema-level claim without naming what replaced it. "
        "The no-originals property is measured, not asserted, and prose that drops "
        "the measurement leaves a reader with nothing."
    )


# ---------------------------------------------------------------------------
# Settings' pluggable seams: open by config string, or closed by a Literal
# ---------------------------------------------------------------------------
def test_every_pluggable_seam_is_selectable_by_config_string() -> None:
    """Build doc sections 8, 9.3 and 9.6 all say "one class + one registry entry".

    Three seams make that promise -- the LLM provider, the key provider, and the
    obfuscation strategy -- and only the first kept it. The other two declared
    ``Settings`` fields as closed ``Literal``s, so a class registered through the
    documented seam could be written, registered, and never *named*: pydantic
    refused the string before the registry that knows about it was consulted, and
    both ``build_key_provider``'s ``unknown_key_provider`` branch and
    ``build_strategy``'s ``unknown_strategy`` branch were unreachable from a
    validated ``Settings``. Measured: ``key_provider="aws_kms"`` and
    ``strategy="redaction"`` each raised ``literal_error`` while
    ``llm_provider="openai"`` was accepted.

    This lives in the file that already cross-checks ``models.py`` against
    ``config.py`` because it is a statement about ``Settings``' field declarations,
    and it is quantified over the three seams rather than written three times, so a
    fourth pluggable field that ships as a ``Literal`` fails here.

    Fail-closed is asserted alongside, because widening a field without it would
    trade an unreachable branch for a silent acceptance -- and for ``strategy``
    the check has to be at *construction*: ``build_strategy`` runs per span inside
    the engine, so leaving it there would turn a config typo into an HTTP 500 on
    every run instead of a refusal at startup.
    """
    key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    for field in ("llm_provider", "key_provider", "strategy"):
        annotation = Settings.model_fields[field].annotation
        assert typing.get_origin(annotation) is not typing.Literal, (
            f"Settings.{field} is a closed Literal, so a class registered through the "
            "documented plug-in seam cannot be selected by config string and the "
            "registry's own unknown-name branch is dead code"
        )
        assert annotation is str, f"Settings.{field} should be a plain str; got {annotation}"

    # `strategy` is the one validated here rather than downstream, so it is the one
    # whose refusal this file can and must observe.
    with pytest.raises(PipelineError) as excinfo:
        Settings(master_key=key, strategy="no-such-strategy")
    assert excinfo.value.detail["reason"] == "unknown_strategy"
    assert Settings(master_key=key, strategy="pseudonymization").strategy == "pseudonymization"
