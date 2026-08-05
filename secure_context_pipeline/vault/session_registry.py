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
import logging
import secrets
import time
import uuid
from collections.abc import Callable
from typing import NamedTuple

from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import new_session_key
from secure_context_pipeline.errors import MAX_DETAIL_VALUE_LEN, SessionExpiredError

logger = logging.getLogger(__name__)

__all__ = ["SessionRegistry"]


class _Session(NamedTuple):
    """One live session. ``key`` is the only copy and never leaves this module."""

    key: bytes
    expires_at: float
    user_id: str


def _short(session_id: str) -> str:
    """Clamp an identifier to the error/audit detail ceiling.

    Session IDs we mint are 32-char uuid4 hex, but a caller-supplied ID arrives
    from an HTTP path parameter and may be arbitrarily long. Clamping keeps a
    hostile ID from turning a :class:`SessionExpiredError` into a ``ValueError``
    from the base class's 64-character guard.
    """
    return session_id[:MAX_DETAIL_VALUE_LEN]


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
                "session_id": session_id,
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
                "session_id": _short(session_id),
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
            return self._sweep_locked()

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

    async def expires_at(self, session_id: str) -> float:
        """Wall-clock expiry for a live session; same error contract as :meth:`key`."""
        async with self._lock:
            self._sweep_locked()
            entry = self._sessions.get(session_id)
            if entry is None:
                raise SessionExpiredError(session_id=_short(session_id))
            return entry.expires_at

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
        """Remove expired entries. Caller must hold ``self._lock``."""
        now = self._clock()
        expired = [sid for sid, entry in self._sessions.items() if entry.expires_at <= now]
        for session_id in expired:
            self._sessions.pop(session_id, None)
        if expired:
            logger.info(
                "expired sessions swept",
                extra={"expired_count": len(expired), "active": len(self._sessions)},
            )
        return expired

    def __repr__(self) -> str:
        """Counts only -- a key must never reach a log line, a traceback, or a REPL."""
        return f"SessionRegistry(active={len(self._sessions)})"

    __str__ = __repr__
