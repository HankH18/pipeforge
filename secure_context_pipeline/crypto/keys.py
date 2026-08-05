"""Key hierarchy and HMAC derivations (build doc section 8).

    env master key  --HKDF-->  per-user document key      (derived on demand, never stored)
    session key     --HKDF-->  per-session vault key      (session key is in-memory only)
    session key     --HMAC-->  token IDs, date shift, faker seeds

Two properties follow from the construction rather than from policy:

* **Reversible within a session, irreversible across sessions.** Token IDs are
  ``HMAC(session_key, ...)``. The session key is ephemeral and never persisted, so
  destroying it is cryptographic erasure -- surviving vault ciphertext becomes
  undecryptable garbage and tokens become unlinkable to their originals.
* **Per-user and per-session isolation is cryptographic.** Different ``user_id``
  or ``session_id`` produces an independent key via HKDF ``info``, so the wrong
  key fails AES-GCM authentication instead of returning someone else's plaintext.

**Domain separation.** Two keys are each used for more than one purpose, so the
separation has to be argued, not assumed.

*HKDF (master key, session key).* Each ``info`` string carries a purpose prefix
(``doc:``, ``vault:``, ``kms-wrap``) before the variable part, and the variable
part is a single identifier with no further structure, so no two purposes can
produce the same ``info``. The master key and the session key are different input
keying material besides, so ``doc:`` and ``vault:`` derivations could not collide
even if the strings did.

*HMAC (session key).* One session key backs three unrelated derivations, and their
message spaces are provably disjoint rather than merely different::

    token ID    HMAC(sk, entity_type || 0x00 || normalize(value))   always has a NUL
    date shift  HMAC(sk, b"date-shift")                             never has a NUL
    Faker seed  HMAC(sk, b"faker:" || entity_type)                  never has a NUL

:func:`_label_bytes` rejects an ``entity_type`` that is empty or contains NUL,
which is what makes the right-hand column true: every token-ID message contains at
least one NUL and neither of the others can contain any. The two NUL-free spaces
are separated from each other by their fixed prefixes (``b"faker:"`` cannot begin
``b"date-shift"``). So no value plantable in a document and no entity type
addable to ``entities.yaml`` can steer one derivation into another's input.
``test_session_key_hmac_domains_are_disjoint`` pins all three formulas to the
build doc and asserts the invariant.

A greenfield design would give every derivation an explicit, unique domain tag
rather than deriving separation from a framing byte. The build doc fixes these
three message formats verbatim, so the property is proved and tested here instead
of the formats being changed.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import unicodedata
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.aead import KEY_LEN, decrypt, encrypt
from secure_context_pipeline.errors import ConfigError

__all__ = [
    "HKDF_SALT",
    "MAX_TOKEN_COUNTER",
    "EnvKeyProvider",
    "KeyProvider",
    "MockKMSKeyProvider",
    "build_key_provider",
    "derive_date_shift_days",
    "derive_faker_seed",
    "derive_token_id",
    "derive_vault_key",
    "new_session_key",
    "normalize",
]

HKDF_SALT = b"scp-v1"
MAX_TOKEN_COUNTER = 0xFFFFFFFF
_WHITESPACE = re.compile(r"\s+")


def _hkdf(ikm: bytes, info: bytes) -> bytes:
    """One 32-byte key from ``ikm``, separated from every other key by ``info``."""
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=HKDF_SALT, info=info).derive(ikm)


def _check_session_key(session_key: bytes) -> None:
    """Reject any key that is not a full 32-byte session key.

    Every HMAC derivation below goes through this. ``hmac.new`` happily accepts a
    zero-length key, and a zero-length key turns every "irreversible across
    sessions" guarantee into a *publicly computable* function: anyone could
    recompute ``HMAC(b"", "NAME\\x00john smith")[:8]`` and link tokens across
    sessions, deployments, and users. The guarantee has to be enforced, not
    assumed, at the point the key is used.
    """
    if len(session_key) != KEY_LEN:
        raise ConfigError(reason="session_key_wrong_length", length=len(session_key))


def _label_bytes(label: str, *, reason: str) -> bytes:
    """UTF-8 bytes of an HMAC label, rejecting the two shapes that break framing.

    ``derive_token_id`` frames its message as ``label || 0x00 || value``. That is
    only injective while the label is non-empty and contains no NUL of its own --
    otherwise ``("A\\x00B", "C")`` and ``("A", "B\\x00C")`` hash the same message.
    Entity types are an *opaque, config-supplied string* (build doc section 6.2),
    so this is validated rather than assumed.
    """
    raw = label.encode("utf-8")
    if not raw or b"\x00" in raw:
        raise ConfigError(reason=reason, length=len(raw))
    return raw


# ---------------------------------------------------------------------------
# Key providers
# ---------------------------------------------------------------------------


@runtime_checkable
class KeyProvider(Protocol):
    """The seam a real KMS drops into.

    ``EnvKeyProvider`` is the shipped default; ``MockKMSKeyProvider`` demonstrates
    envelope semantics. A production AWS/GCP KMS implementation satisfies this
    same protocol, which is the whole cloud-compatibility claim.
    """

    name: str

    def doc_key(self, user_id: str) -> bytes:
        """32-byte AES key for this user's documents. Derived on demand, never stored."""
        ...


class EnvKeyProvider:
    """Master key from ``SCP_MASTER_KEY``; per-user keys by HKDF. Never logged."""

    name = "env"

    def __init__(self, settings: Settings) -> None:
        master = settings.master_key_bytes()
        if len(master) != KEY_LEN:
            raise ConfigError(reason="master_key_wrong_length", length=len(master))
        self._master = master

    def doc_key(self, user_id: str) -> bytes:
        if not user_id:
            raise ConfigError(reason="empty_user_id")
        return _hkdf(self._master, b"doc:" + user_id.encode("utf-8"))

    def __repr__(self) -> str:
        return "EnvKeyProvider(master_key='***')"

    __str__ = __repr__


class MockKMSKeyProvider:
    """Local mock of a KMS envelope workflow (build doc section 8, flagged stretch).

    Mirrors ``generate_data_key`` / ``decrypt``: a data key is generated at random
    and returned *both* in plaintext and wrapped under the customer master key, and
    only the wrapped copy is ever meant to be persisted. That is the shape an
    S3+KMS deployment stores alongside each object.

    ``doc_key`` stays HKDF-deterministic so ``DocumentStore`` behaves identically
    under either provider -- the envelope methods are the demonstrated seam, not a
    behavioural change. A real deployment would persist ``wrapped`` per document
    and call :meth:`decrypt_data_key` on read.

    The customer master key is never used directly as a cipher key: the wrapping
    key is its own HKDF derivation (``info=b"kms-wrap"``), so the CMK feeds
    HKDF-Extract and nothing else. Using one key as both HKDF input and an AES-GCM
    key has no known interaction, but "the master key is only ever an HKDF input"
    is a property worth being able to state without qualification -- and a real KMS
    keeps its CMK inside the HSM for the same reason.
    """

    name = "mock_kms"

    #: HKDF ``info`` for the key that wraps data keys. Distinct from ``doc:`` and
    #: ``vault:``, so the wrapping key is independent of every document key.
    WRAP_INFO = b"kms-wrap"

    def __init__(self, settings: Settings) -> None:
        self._cmk = settings.master_key_bytes()
        if len(self._cmk) != KEY_LEN:
            raise ConfigError(reason="master_key_wrong_length", length=len(self._cmk))
        self._wrapping_key = _hkdf(self._cmk, self.WRAP_INFO)

    def generate_data_key(self, context: str) -> tuple[bytes, bytes]:
        """Return ``(plaintext_data_key, wrapped_data_key)``. Persist only the wrapped one."""
        data_key = secrets.token_bytes(KEY_LEN)
        wrapped = encrypt(self._wrapping_key, data_key, context.encode("utf-8"))
        return data_key, wrapped

    def decrypt_data_key(self, wrapped: bytes, context: str) -> bytes:
        """Unwrap a data key. Wrong ``context`` fails AES-GCM authentication.

        ``context`` is the KMS encryption-context analogue and is bound as AAD, so
        a wrapped key lifted from one object cannot be unwrapped for another.
        """
        return decrypt(self._wrapping_key, wrapped, context.encode("utf-8"), scope="kms_data_key")

    def doc_key(self, user_id: str) -> bytes:
        if not user_id:
            raise ConfigError(reason="empty_user_id")
        return _hkdf(self._cmk, b"doc:" + user_id.encode("utf-8"))

    def __repr__(self) -> str:
        return "MockKMSKeyProvider(cmk='***')"

    __str__ = __repr__


_PROVIDERS: dict[str, type[EnvKeyProvider] | type[MockKMSKeyProvider]] = {
    EnvKeyProvider.name: EnvKeyProvider,
    MockKMSKeyProvider.name: MockKMSKeyProvider,
}


def build_key_provider(settings: Settings) -> KeyProvider:
    """Select a provider by config string. Adding a real KMS = one class + one entry."""
    try:
        cls = _PROVIDERS[settings.key_provider]
    except KeyError as exc:
        raise ConfigError(reason="unknown_key_provider", value=settings.key_provider[:64]) from exc
    return cls(settings)


# ---------------------------------------------------------------------------
# Session / vault keys
# ---------------------------------------------------------------------------


def new_session_key() -> bytes:
    """A fresh 32-byte session key. In-memory only; a process restart kills all sessions."""
    return secrets.token_bytes(KEY_LEN)


def derive_vault_key(session_key: bytes, session_id: str) -> bytes:
    """``HKDF(session_key, info="vault:" + session_id)``. Derived on demand, never stored."""
    _check_session_key(session_key)
    if not session_id:
        raise ConfigError(reason="empty_session_id")
    return _hkdf(session_key, b"vault:" + session_id.encode("utf-8"))


# ---------------------------------------------------------------------------
# HMAC derivations
# ---------------------------------------------------------------------------


def normalize(value: str) -> str:
    """NFKC, collapse (and trim) whitespace, casefold -- build doc section 8.

    Dedupe and token derivation both key on this, so ``"John  SMITH"`` and
    ``"john smith"`` map to one vault row and one token.

    The consequence to know about: values that differ *only* below normalization
    share a vault entry, so restoration returns the surface form that was vaulted
    first. A document with ``JOHN SMITH`` in a header and ``John Smith`` in prose
    restores both as whichever appeared first. That is the intended trade -- one
    token per entity is what makes the payload's co-occurrence structure honest and
    the vault small -- but it is a fidelity loss, not a free lunch.
    """
    return _WHITESPACE.sub(" ", unicodedata.normalize("NFKC", value)).strip().casefold()


def derive_token_id(session_key: bytes, entity_type: str, value: str, *, counter: int = 0) -> str:
    """Truncated ``HMAC-SHA256(session_key, entity_type || 0x00 || normalize(value))``.

    Deterministic within a session, independent across sessions, and irreversible
    once the session key is gone -- all as properties of the construction.

    **On the 4-byte truncation** (build doc section 8; not this module's choice).
    32 bits is a *namespace*, not a security parameter: nothing about secrecy rests
    on the token's width, because the preimage is protected by the session key, not
    by digest length. What it costs is uniqueness -- a birthday collision is around
    0.1% at 3 000 entities in one session and near-certain around 200 000 -- which
    is why the ``counter`` path below exists and is exercised by a test rather than
    argued away. Short tokens are also the readable choice: they survive an LLM
    copying them by hand, which a 64-hex digest would not.

    ``counter`` re-derives on that collision; the caller increments until the
    resulting ID is unused (``SessionVault``/``ObfuscationEngine`` do, and log the
    count).

    **Why the counter is a prefix, not a suffix** -- a deliberate deviation from
    section 8's "appended counter byte". Appending the counter bytes is *not*
    injective: the message for
    ``("NAME", "john smith", counter=1)`` is byte-identical to the message for
    ``("NAME", "john smith\\x00\\x00\\x00\\x01", counter=0)``, so an attacker who can
    plant a value containing those four bytes can steer a second, distinct value
    onto a token ID the collision path is about to hand out. Framing the counter as
    a leading ``0x00 || counter`` block makes the two message spaces provably
    disjoint, because a ``counter == 0`` message can never begin with NUL (the
    entity type is validated non-empty and NUL-free). The ``counter == 0`` message
    -- the only one the pipeline emits in the normal path -- is byte-for-byte the
    formula in section 8, so no token ID changes.
    """
    _check_session_key(session_key)
    label = _label_bytes(entity_type, reason="invalid_entity_type")
    if not 0 <= counter <= MAX_TOKEN_COUNTER:
        raise ConfigError(reason="token_counter_out_of_range", counter=counter)
    message = label + b"\x00" + normalize(value).encode("utf-8")
    if counter:
        message = b"\x00" + counter.to_bytes(4, "big") + message
    return hmac.new(session_key, message, hashlib.sha256).hexdigest()[:8]


def derive_date_shift_days(session_key: bytes) -> int:
    """One consistent per-session shift in [-300, -30] u [30, 299] days.

    Intervals between dates survive the shift (they are reasoning-relevant);
    absolute dates do not (they are identifiers). The +/-30 floor stops the shift
    from landing close enough to the true date to be useful to an attacker.

    Two things a reader should not have to derive:

    * The upper bound is 299, not 300. ``% 600`` yields ``[0, 599]``, so the raw
      shift lands in ``[-300, 299]`` and the floor correction only pushes
      ``[-29, 29]`` outwards.
    * The result is **not uniform**: the correction folds the 60 raw values in
      ``[-29, 29]`` onto ``[30, 59]`` and ``[-59, -30]``, giving those two bands
      roughly double weight. That costs a fraction of a bit of entropy in a value
      that is already secret (it is HMAC output under the session key), so it does
      not weaken the shift -- but it is a real, visible property of the build
      doc's formula rather than an accident of this implementation. The build doc
      writes the correction as ``sign(delta) * 30``, which is undefined at
      ``delta == 0``; a zero shift would be no shift at all, so it is treated as
      positive here.

    Modulo bias from ``% 600`` over a 256-bit HMAC digest is on the order of
    2**-247 and is not worth correcting.
    """
    _check_session_key(session_key)
    raw = hmac.new(session_key, b"date-shift", hashlib.sha256).digest()
    delta = (int.from_bytes(raw, "big") % 600) - 300
    if abs(delta) < 30:
        delta += 30 if delta >= 0 else -30
    return delta


def derive_faker_seed(session_key: bytes, entity_type: str) -> int:
    """Per-session, per-entity-type Faker seed, so fakes are stable within a session."""
    _check_session_key(session_key)
    label = _label_bytes(entity_type, reason="invalid_faker_label")
    return int.from_bytes(
        hmac.new(session_key, b"faker:" + label, hashlib.sha256).digest()[:8], "big"
    )
