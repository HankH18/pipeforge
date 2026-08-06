"""In-memory session key registry (build doc sections 8 and 9.4).

This module holds the only copy of every live session key. Three properties are
load-bearing and each one is a property of *where the key lives*, not of policy:

1. **Never persisted.** A session key is ``secrets.token_bytes(32)`` created here
   and stored in a plain dict. It is never written to disk, never sent over the
   wire, never logged, and never rendered by ``__repr__``. A process restart
   therefore kills every session -- which is the documented, accepted cost of the
   irreversibility guarantee.
2. **Destruction is cryptographic erasure.** :meth:`SessionRegistry.destroy`
   *pops* the key. Every vault ciphertext for that session is AES-GCM under a key
   HKDF-derived from it, so once the last reference is dropped those rows are
   undecryptable garbage. Deleting the rows afterwards is hygiene, not the
   control.
3. **Expiry is indistinguishable from absence.** :meth:`SessionRegistry.key`
   sweeps the TTL on every access and raises :class:`SessionExpiredError` for an
   expired *or* unknown session ID. Callers cannot use the error to learn whether
   a session ever existed.

Concurrency: the dict is guarded by an :class:`asyncio.Lock`, so a sweep racing a
create or a destroy cannot observe a half-updated map.

The clock is injectable (``clock=``) purely so TTL behaviour is testable without
sleeping; production callers use the default :func:`time.time`.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import new_session_key
from secure_context_pipeline.errors import MAX_DETAIL_VALUE_LEN, SessionExpiredError

logger = logging.getLogger(__name__)

__all__ = ["SessionRegistry"]


@dataclass(frozen=True, slots=True, repr=False)
class _Session:
    """One live session. ``key`` is the only copy and never leaves this module.

    **This was a ``NamedTuple`` and that was the one gap in an otherwise uniform
    pattern.** Every other key- or original-bearing object here masks its
    ``__repr__`` on purpose -- :class:`SessionRegistry` renders ``active=N``,
    ``_SessionCache`` renders ``entries=N``, ``StrategyContext`` declares
    ``session_key`` as ``field(repr=False)``, ``Settings`` renders ``'***'``.
    ``_Session`` did not, because it never had to be written: ``NamedTuple``
    *generates* a ``__repr__`` that renders every field, so ``repr(entry)``
    printed the raw 32-byte session key as a ``bytes`` literal.

    The asymmetry is worth stating, because it is the opposite of the intuition
    that makes the rest of the codebase safe by accident: a plain class's default
    repr is ``<_Session object at 0x...>``, which hides its attributes, so
    :class:`~secure_context_pipeline.store.document_store.EncryptedDocumentStore`
    leaks nothing despite defining no ``__repr__`` at all. ``NamedTuple`` and
    ``@dataclass`` do the reverse and expose them. Opting out is therefore not
    belt-and-braces here, it is required.

    No call site reprs a ``_Session`` today, so this closed a latent gap rather
    than an active leak -- but "one accidental ``logger.debug("%r", entry)``
    away" is exactly how a key reaches a log file, and the registry's own
    docstring commits to the key never being rendered.

    The dataclass form is also structurally tighter than a masked ``NamedTuple``
    would have been: a ``NamedTuple`` *is* a ``tuple``, so ``tuple(entry)``,
    ``entry[0]`` and iterable-unpacking all keep handing the key to a default
    ``repr`` no matter what ``__repr__`` says. ``slots=True`` leaves no
    ``__dict__`` for a generic object-dumper to walk either. Nothing relied on
    the tuple protocol: the key is read as ``entry.key`` at every call site.
    """

    key: bytes = field(repr=False)
    expires_at: float
    user_id: str

    def __repr__(self) -> str:
        """Mask the key; the other two fields are already logged in the clear."""
        return f"_Session(key='***', expires_at={self.expires_at!r}, user_id={self.user_id!r})"

    __str__ = __repr__


def _short(session_id: str) -> str:
    """Clamp an identifier to the error/audit detail ceiling.

    Session IDs we mint are 32-char uuid4 hex, but a caller-supplied ID arrives
    from an HTTP path parameter and may be arbitrarily long. Clamping keeps a
    hostile ID from turning a :class:`SessionExpiredError` into a ``ValueError``
    from the base class's 64-character guard.
    """
    return session_id[:MAX_DETAIL_VALUE_LEN]


def _handle(session_id: str) -> str:
    """A stable, non-reversible correlation tag for a session ID. **Not the ID.**

    A session ID is a *credential*: ``DELETE /sessions/{id}?user_id=...`` needs only
    the pair, and that deletion is irreversible by construction -- popping the key is
    cryptographic erasure, so every vault row for the session becomes undecryptable
    garbage. There is no undo and no recovery path. Writing a live session ID and its
    owning ``user_id`` onto one INFO record therefore put both halves of that pair in
    the application's log stream, where they reach whatever ships logs off the host.

    Note what the fix is *not*. :func:`_short` clamps to
    :data:`~secure_context_pipeline.errors.MAX_DETAIL_VALUE_LEN` (64), and every ID
    this module mints is a 32-char uuid4 hex, so ``_short`` is the identity function
    on exactly the IDs that matter. ``destroy`` applied it and ``create`` did not,
    which read like an inconsistency worth closing by copying ``_short`` into
    ``create`` -- and that would have changed nothing at all while looking like a fix.
    ``_short`` exists to stop a hostile *caller-supplied* ID from overflowing an
    error's detail ceiling. It was never a mask, and this is not the same problem.

    A truncated SHA-256 is: it is stable, so an operator can still follow one session
    from creation through destruction and expiry in the logs, and it is not the
    credential, so a log reader cannot use it to destroy anything. uuid4 carries 122
    bits of entropy, so the digest is not invertible by search -- no salt is needed,
    and a per-process salt would only break the correlation this exists to preserve.

    The audit trail is deliberately unchanged: it records full session IDs by design
    (they are the join key for a session's events, and the audit DB is access-
    controlled). This is about the INFO log stream, which is not.
    """
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:12]


class SessionRegistry:
    """``{session_id: _Session(key, expires_at, user_id)}`` guarded by an ``asyncio.Lock``.

    Typical lifecycle::

        registry = SessionRegistry(settings)
        session_id, expires_at = await registry.create("alice")
        key = await registry.key(session_id)      # SessionExpiredError once TTL passes
        await registry.destroy(session_id)        # cryptographic erasure

    **A session belongs to the user who created it.** ``user_id`` is recorded at
    :meth:`create` and read back by :meth:`owner`, so a caller presenting a
    session ID can be checked against the ``user_id`` it claims. Without that
    binding, a session ID was a credential for *any* user's documents and the
    only thing standing between an attacker and another user's data was the
    ``doc_id`` being unguessable -- obscurity, not authorization, sitting
    directly underneath the per-user-key isolation the design claims.
    """

    def __init__(self, settings: Settings, *, clock: Callable[[], float] = time.time) -> None:
        self._settings = settings
        self._clock = clock
        # The single copy of every live session key. Never persisted, never logged.
        self._sessions: dict[str, _Session] = {}
        #: Sessions whose key has been dropped but whose vault rows, cache and
        #: VAULT_DESTROY event are still outstanding. Populated by every sweep,
        #: whoever triggered it; drained by :meth:`sweep`. See `_sweep_locked`.
        self._unreaped: set[str] = set()
        self._lock = asyncio.Lock()

    # -- mutation ----------------------------------------------------------

    async def create(self, user_id: str, *, ttl_seconds: int | None = None) -> tuple[str, float]:
        """Mint a session for ``user_id``: fresh uuid4 hex ID and a fresh 32-byte key.

        ``user_id`` is mandatory, and deliberately positional: an unbound session
        is exactly the vulnerability this parameter exists to close, so there is
        no default that could quietly recreate one.

        ``ttl_seconds`` overrides :attr:`Settings.session_ttl_seconds` (a TTL of
        ``0`` yields a session that is already expired on first access -- the
        expiry test case). Returns ``(session_id, expires_at)``; the key itself
        is never returned to the creator, only via :meth:`key`.
        """
        ttl = self._settings.session_ttl_seconds if ttl_seconds is None else ttl_seconds
        ttl = max(ttl, 0)
        session_id = uuid.uuid4().hex
        expires_at = self._clock() + ttl
        key = new_session_key()
        async with self._lock:
            self._sweep_locked()
            self._sessions[session_id] = _Session(key, expires_at, user_id)
        logger.info(
            "session created",
            extra={
                # A correlation handle, never the live ID -- see `_handle`. This
                # record also carries `user_id`, so logging the ID here would have
                # put both halves of the DELETE /sessions credential pair on one line.
                "session": _handle(session_id),
                "user_id": _short(user_id),
                "ttl_seconds": ttl,
                "active": len(self._sessions),
            },
        )
        return session_id, expires_at

    async def destroy(self, session_id: str) -> bool:
        """Pop the key. **This alone is cryptographic erasure.**

        Returns whether the session existed. Python cannot zeroise an immutable
        ``bytes`` object, so the guarantee is "the last reference is dropped and
        the object becomes unreachable", not "the page is overwritten" -- a
        memory-scraping adversary on the app host is explicitly out of scope for
        this tier (build doc section 9.4).
        """
        async with self._lock:
            existed = self._sessions.pop(session_id, None) is not None
        logger.info(
            "session key destroyed",
            extra={
                # Same handle as the creation record, so the two still join on one
                # session. `_short` was a no-op here too: a minted ID is 32 chars
                # against a 64-char ceiling.
                "session": _handle(session_id),
                "existed": existed,
                "active": len(self._sessions),
            },
        )
        return existed

    async def sweep(self) -> list[str]:
        """Drop every expired session; return the IDs that were removed.

        The caller is responsible for the rest of the destruction path (vault
        rows, ``VAULT_DESTROY`` audit event) -- the registry owns keys only.
        """
        async with self._lock:
            self._sweep_locked()
            # Returns everything awaiting destruction, not merely what THIS call
            # observed. Any of the six other accessors may have swept the session
            # first; the caller of this method is the only one that finishes the job.
            return self._drain_unreaped_locked()

    # -- read --------------------------------------------------------------

    async def key(self, session_id: str) -> bytes:
        """The session key, sweeping the TTL first.

        Raises :class:`SessionExpiredError` for an expired *or* unknown session;
        the two are deliberately indistinguishable (no existence oracle).
        """
        async with self._lock:
            self._sweep_locked()
            entry = self._sessions.get(session_id)
            if entry is None:
                raise SessionExpiredError(session_id=_short(session_id))
            return entry.key

    async def owner(self, session_id: str) -> str:
        """The ``user_id`` this session was created for; same error contract as :meth:`key`.

        Callers compare the result against the ``user_id`` a request claims. They
        must answer a mismatch with the *same* ``SessionExpiredError`` this raises
        for an unknown session: a distinct "wrong user" reply would tell an
        attacker that the session ID is real and merely belongs to someone else,
        which is the enumeration oracle the uniform 401 exists to prevent.
        """
        async with self._lock:
            self._sweep_locked()
            entry = self._sessions.get(session_id)
            if entry is None:
                raise SessionExpiredError(session_id=_short(session_id))
            return entry.user_id

    async def belongs_to(self, session_id: str, user_id: str) -> bool:
        """Whether ``session_id`` is live *and* owned by ``user_id``.

        Never raises -- not for an unknown session, and not for any ``str`` on
        either side. That is the whole contract: a caller that must stay
        oracle-free (logout answers 204 whatever the outcome) cannot leak
        existence through an exception it forgot to catch.

        The API layer does not currently route through here -- it compares
        inline, having worked around the ``TypeError`` described below while this
        copy still had it. With that gone the two are equivalent again, and this
        is the one that belongs to the component that owns the ``user_id``.

        **The comparison is over UTF-8 bytes, and that is not cosmetic.**
        ``secrets.compare_digest`` accepts ``str`` only when *both* sides are
        pure ASCII and raises ``TypeError`` otherwise. Nothing upstream rejects a
        non-ASCII identifier -- ``create`` takes any string and the API bounds
        ``user_id`` by length alone -- so the ``str`` form crashed on the very
        input this check exists to reject, and it did so *asymmetrically*: an
        unknown session returned ``False`` while a live session owned by
        ``"josé"`` raised, which is exactly the existence oracle the uniform
        answer is for. Encoding first is total over every ``str`` and keeps the
        constant-time property: ``user_id`` is attacker-supplied, and a
        byte-by-byte early exit would leak the owner's identity one character at
        a time. Length stays observable, as it is for the ``str`` form, and is
        bounded to 1..64 by the API's ``MAX_ID_LEN``.
        """
        try:
            owner = await self.owner(session_id)
        except SessionExpiredError:
            return False
        return secrets.compare_digest(owner.encode("utf-8"), user_id.encode("utf-8"))

    async def active_ids(self) -> frozenset[str]:
        """IDs of sessions that are still live, after sweeping."""
        async with self._lock:
            self._sweep_locked()
            return frozenset(self._sessions)

    # -- internals ---------------------------------------------------------

    def _sweep_locked(self) -> list[str]:
        """Remove expired entries. Caller must hold ``self._lock``.

        Every ID dropped here is also recorded in :attr:`_unreaped`, and that is what
        makes the rest of the destruction path reachable. **Six accessors call this
        and throw the return value away** -- ``create``, ``key``, ``expires_at``,
        ``owner``, ``active_ids`` and ``belongs_to`` -- so whichever of them happened
        to observe an expiry first removed the ID permanently, and
        ``deps.reap_expired_sessions`` (the one caller that *uses* the list) could
        never see it again. The vault rows and the decrypted cache then survived to
        process exit, which is exactly the state the reaper was added to prevent.

        It is not a rare race. The shipped ``Dockerfile`` polls ``GET /health`` every
        30 seconds, and that route calls ``active_ids`` -- so in the container the
        reaper was disarmed for essentially every session.

        Recording rather than reaping here is deliberate: this runs under the lock
        and must stay synchronous, while destruction needs to await SQLite and the
        audit log. So the knowledge is kept and ``sweep()`` hands it to a caller that
        can act on it.
        """
        now = self._clock()
        expired = [sid for sid, entry in self._sessions.items() if entry.expires_at <= now]
        for session_id in expired:
            self._sessions.pop(session_id, None)
            self._unreaped.add(session_id)
        if expired:
            logger.info(
                "expired sessions swept",
                extra={"expired_count": len(expired), "active": len(self._sessions)},
            )
        return expired

    def _drain_unreaped_locked(self) -> list[str]:
        """Take the IDs awaiting destruction. Caller must hold ``self._lock``."""
        drained = sorted(self._unreaped)
        self._unreaped.clear()
        return drained

    def __repr__(self) -> str:
        """Counts only -- a key must never reach a log line, a traceback, or a REPL."""
        return f"SessionRegistry(active={len(self._sessions)})"

    __str__ = __repr__
