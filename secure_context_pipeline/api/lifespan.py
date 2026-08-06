"""Process startup and shutdown: everything expensive, built exactly once.

The spaCy pipeline behind Presidio costs tens of seconds to load and the three
aiosqlite connections are process-scoped, so all of it happens here rather than
per request -- and unwinds in reverse on any failure, because a half-built
startup leaks a connection whose non-daemon worker thread stops the interpreter
from exiting at all.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path

from secure_context_pipeline.api.deps import Services
from secure_context_pipeline.audit.logger import (
    DEFAULT_DB_FILENAME as AUDIT_DB_FILENAME,
)
from secure_context_pipeline.audit.logger import (
    AuditLogger,
)
from secure_context_pipeline.config import Settings
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection.detector import Detector, warm_up
from secure_context_pipeline.detection.registry import load_registry
from secure_context_pipeline.llm.base import build_provider
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import EgressGate
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import EncryptedDocumentStore
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import (
    DEFAULT_DB_FILENAME as VAULT_DB_FILENAME,
)
from secure_context_pipeline.vault.session_vault import SessionVault

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
async def _close_quietly(closers: Iterable[Callable[[], Awaitable[None]]]) -> None:
    """Await every closer, letting none of them stop the others.

    Shutdown is best-effort by nature: a connection that is already gone must not
    prevent the next one from being released.
    """
    for closer in closers:
        try:
            await closer()
        except Exception:
            logger.exception("error closing a resource")


async def _build_services(settings: Settings) -> Services:
    """Construct the whole pipeline. Called once per process, from the lifespan.

    Startup is **transactional**: three aiosqlite connections are opened in
    sequence, and if a later step raises, every earlier one is closed before the
    error propagates. Without that, a half-built startup leaks a connection --
    and, because aiosqlite's worker threads are not daemons, the interpreter can
    no longer exit at all, so the process hangs instead of reporting the failure.
    The realistic trigger is not exotic: ``docker-compose`` bind-mounts ``./data``
    from the host, the container runs as uid 10001, and a root-owned host directory
    makes the opens fail. Which one fails is worth stating correctly, because this
    docstring said "the *second*" and that is wrong in the direction that matters --
    it implies a partially-built startup is the common case, when in fact the
    **first** open (``AuditLogger``, below) is what dies, before any connection
    exists to leak. The unwind path is still load-bearing for every other partial
    failure; it is simply not what this particular trigger exercises. See
    ``docker-compose.yml``'s ``user:`` mapping for the fix.
    """
    started = time.perf_counter()
    data_dir = Path(settings.data_dir)
    await asyncio.to_thread(data_dir.mkdir, parents=True, exist_ok=True)

    registry = load_registry(settings.registry_path)

    # spaCy + Presidio: seconds of CPU, and blocking. Never on the event loop,
    # and never per request (build doc section 12). A failure here is reported
    # through /health rather than refusing to boot -- a container that will not
    # start tells an operator nothing about why.
    model_loaded = True
    try:
        await asyncio.to_thread(warm_up, settings)
    except Exception:
        model_loaded = False
        logger.exception(
            "spacy model failed to load; /health will report degraded",
            extra={"spacy_model": settings.spacy_model},
        )

    # Unwound in reverse on any failure below, including cancellation.
    opened: list[Callable[[], Awaitable[None]]] = []
    try:
        audit = await AuditLogger.open(data_dir / AUDIT_DB_FILENAME)
        opened.append(audit.close)
        store = await EncryptedDocumentStore.open(settings)
        opened.append(store.close)
        sessions = SessionRegistry(settings)
        vault = await SessionVault.open(data_dir / VAULT_DB_FILENAME, sessions)
        opened.append(vault.close)

        # Session keys never survive a restart, so every row left by the previous
        # process is undecryptable garbage. Drop it rather than let a stale
        # session_id look live.
        orphans = await vault.sweep_orphans(await sessions.active_ids())
        # The store's counterpart. `put` writes both blobs and then commits the
        # metadata row, unwinding itself on any exception -- but not on SIGKILL,
        # OOM or power loss, which strand blobs with no row pointing at them.
        # Since `doc_id` only ever comes from a row, those files are unreachable
        # AND uncollectable: permanent disk, bounded only by replacing the volume.
        stranded_blobs = await store.sweep_orphans()

        detector = Detector(registry, settings)
        engine = ObfuscationEngine(
            registry=registry,
            vault=vault,
            session_registry=sessions,
            settings=settings,
            audit=audit,
        )
        gate = EgressGate(vault=vault, detector=detector, settings=settings, audit=audit)
        orchestrator = PipelineOrchestrator(
            store=store,
            detector=detector,
            engine=engine,
            injector=ContextInjector(),
            gate=gate,
            provider=build_provider(settings),
            restorer=Restorer(vault=vault, settings=settings, audit=audit),
            vault=vault,
            settings=settings,
            audit=audit,
        )
    except BaseException:
        # Reverse order, and BaseException rather than Exception: a cancelled
        # startup must unwind too, or the aiosqlite worker threads it already
        # started keep the interpreter alive and the process hangs instead of
        # reporting why it failed.
        await _close_quietly(reversed(opened))
        raise

    logger.info(
        "pipeline ready",
        extra={
            "model_loaded": model_loaded,
            "llm_provider": settings.llm_provider,
            "strategy": settings.strategy,
            "orphan_rows_swept": orphans,
            "orphan_blobs_swept": stranded_blobs,
            "startup_ms": round((time.perf_counter() - started) * 1000.0, 1),
        },
    )
    return Services(
        settings=settings,
        registry=registry,
        audit=audit,
        store=store,
        sessions=sessions,
        vault=vault,
        detector=detector,
        engine=engine,
        gate=gate,
        orchestrator=orchestrator,
        model_loaded=model_loaded,
        ui_mounted=False,
    )


async def _shutdown(services: Services) -> None:
    """Close every connection. Session keys die with the process, by design."""
    await _close_quietly((services.store.close, services.vault.close, services.audit.close))
