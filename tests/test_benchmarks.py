"""Performance benchmarks (build doc section 12). Marker: ``bench``.

Budgets, all with generous margins against the spec, all measured against the real
components rather than a microbenchmark of a hot loop:

=====================================  ==========================  =========
Measurement                            What it bounds              Budget
=====================================  ==========================  =========
Obfuscation of 2,000 words             detect + obfuscate, no LLM  < 2 s
Vault lookup p99 (1,000 lookups)       the egress/restore hot path < 5 ms
De-obfuscation of a 500-token reply    the answer-assembly stage   < 500 ms
  -- warm vault (the request path)     cache hits, no SQLite       < 500 ms
  -- cold vault (worst case)           500 SQLite + AES-GCM reads  < 500 ms
  -- pseudonymization surrogate pass   regex compile + rewrite     < 500 ms
Full pipeline, 12k-word brief          every stage we control      < 15 s
=====================================  ==========================  =========

``pytest -m bench`` selects *only* these; it is not an opt-in gate, and the
docstring used to call the marker "opt-in", which was wrong in the direction that
matters. There is no ``addopts`` in ``pyproject.toml`` and no
``collection_modifyitems`` hook, so a bare ``pytest`` collects and runs every one
of them -- which is also what README section 4 counts ("2280 collected: 134
leakage + 5 bench + rest unit + integration").

**They stay in the default run, deliberately.** These measurements are the only
evidence behind the section 12 table in the README, and a number nobody re-measures
is a number that quietly stops being true; deselecting them by default would leave
the README's headline latencies unbacked on every run that matters. The known cost
is that a wall-clock assertion measures the machine as well as the code, and on a
loaded box it can go red for reasons unrelated to the pipeline. The answer to that
is :data:`BENCH_REPEATS` -- best-of-N on the budgets with the least headroom, which
keeps the achievability claim intact -- and **not** a skip marker, a retry, or a
widened budget. A skip would delete the evidence; the other two would weaken the
claim. If one of these is red, the first move is to read the printed table: it
gives the measured number and the headroom, which is usually enough to tell
contention from a regression, and a genuine regression slows every repetition.

The measured numbers are printed as a table at the end of the module so they can be
quoted directly in the README -- an assertion that something is "under budget" is
worth much less to a reviewer than the number it actually came in at.

**What is deliberately excluded.** Loading ``en_core_web_lg`` costs seconds and
happens exactly once per process (``detection.detector.get_analyzer``, wired into
the FastAPI lifespan and ``demo.py``). Charging that to a per-request budget would
measure the wrong system, so the analyzer is warmed before timing starts.

The full-pipeline budget runs here on the **mock** provider, which covers every
stage this system is responsible for and none of the network. The variant that
includes a real provider round trip stays in ``demo.py --real``, since it needs an
API key to mean anything. Neither number substitutes for the other: this one is
reproducible by anyone who runs the suite, and that one is the end-to-end truth.
"""

from __future__ import annotations

import base64
import secrets
import statistics
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import pytest_asyncio

from secure_context_pipeline.audit.logger import AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import derive_token_id
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection.detector import Detector
from secure_context_pipeline.detection.registry import EntityRegistry, load_registry
from secure_context_pipeline.llm.mock_provider import MockProvider
from secure_context_pipeline.models import Detection, EntityCategory, TokenRecord
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import EgressGate
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import EncryptedDocumentStore
from secure_context_pipeline.surrogates import format_surrogate
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault

pytestmark = pytest.mark.bench

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = REPO_ROOT / "entities.yaml"
LARGE_BRIEF = REPO_ROOT / "fixtures" / "legal_brief_large.txt"

#: Section 12 budgets. Generous against the spec on purpose: a benchmark that
#: fails on a loaded laptop is a benchmark people learn to ignore.
BUDGET_OBFUSCATE_S = 2.0
BUDGET_VAULT_P99_MS = 5.0
BUDGET_RESTORE_MS = 500.0
BUDGET_PIPELINE_S = 15.0

WORDS = 2_000
VAULT_ENTRIES = 500
VAULT_LOOKUPS = 1_000
RESPONSE_TOKENS = 500

#: Repetitions for the two budgets with the least headroom, scored **best-of-N**.
#:
#: A wall-clock assertion measures the machine as much as the code. These two run at
#: 4.8x and 2.3x headroom, and a reviewer's laptop mid-Spotlight-index, a CI box with
#: noisy neighbours, or -- as happened during this build -- three other test suites
#: running concurrently, can plausibly eat that. A benchmark that goes red for
#: reasons unrelated to the code is a benchmark people learn to re-run until it is
#: green, which is strictly worse than not having it.
#:
#: Best-of-N is the right correction here rather than a wider budget, because the
#: property being asserted is "this pipeline **can** do the work inside the budget"
#: -- an achievability claim, for which the fastest clean observation is the correct
#: estimator and a contended one is simply a worse measurement of the same thing.
#: Widening the budget instead would weaken the claim itself, which is the one thing
#: not on the table. A genuine regression slows down *every* iteration, so the
#: minimum moves with it and the test still fails; that is verified by sabotage
#: rather than argued.
#:
#: Applied to every budget whose headroom is in single digits. Best-of-3 as scored,
#: across three consecutive quiet runs on this machine::
#:
#:     full pipeline, 12k-word brief          6.93 - 7.05 s / 15 s     2.1x   repeated
#:     restore 500 surrogates (pseudonym.)     120 - 123 ms / 500 ms   4.2x   repeated
#:     obfuscate 2,000 words (pseudonym.)    0.401 - 0.419 s / 2 s     4.9x   repeated
#:     obfuscate 2,000 words (tokenization)  0.382 - 0.399 s / 2 s     5.1x   repeated
#:     restore 500 tokens, cold vault          188 ms / 500 ms          2.7x   repeated
#:     restore 500 tokens, warm vault          138 ms / 500 ms          3.6x   single
#:     vault lookup p99                          ~0.001 ms / 5 ms     ~4500x  single
#:
#: **The two token-restore rows were 73 ms (7.4x) and 5.4 ms (96x) until the restore
#: stage began itemising what it restored.** Core requirement 7 wants a
#: de-obfuscation event to name an entity type and a token, so the restorer now
#: writes one ``DEOBFUSCATE`` row per distinct restored token ID -- the same
#: one-row-per-entity shape the obfuscation engine already pays for on the way out.
#: A hash-chained write costs ~0.55 ms, so a 500-token response spends 240 ms in the
#: audit log and lands at 345 ms (1.4x) if the itemisation is uncapped; that is what
#: ``restorer._MAX_RESTORE_ROWS`` (256) bounds, and the numbers above are with it.
#: The added cost is now a constant, whatever the model sends back. The two rows are
#: still the fastest way to see an ``AuditLogger.emit`` regression: they are almost
#: entirely audit writes.
#:
#: The repetition earns its place on the two newest rows rather than being copied onto
#: them out of symmetry: single-shot, the surrogate restore came in at 283.5 ms (1.8x,
#: the tightest budget in the module) and the cold-vault restore at 107.3 ms (4.7x).
#: Best-of-3 more than halves both. The first iteration is paying for a cold SQLite
#: page cache and first-call overhead in the regex engine, which is a property of the
#: measurement rather than of the pipeline -- precisely the case best-of-N is for.
#:
#: The surrogate restore is worth calling out because it had no budget test at all
#: until recently: the section 12 restore row was asserted for the token pass only,
#: and on the warm path the token pass used to be the cheap half by a factor of 23.
#: It is not any more -- 138 ms against 124 ms -- and the reason is the itemisation
#: above, not the matching: a pseudonym has no token ID, so the surrogate pass writes
#: no per-entity rows and its number did not move.
#:
#: The last two are single-shot. That was written when the warm restore sat at 96x,
#: where no realistic contention reaches; at 3.6x it is now the second-tightest row
#: in the module and single-shot is no longer justified by headroom -- it is left
#: that way only because the same 500-token restore *is* repeated one test below,
#: cold, so a regression in the shared path already has a best-of-3 witness.
BENCH_REPEATS = 3


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Measurement:
    name: str
    measured: float
    budget: float
    unit: str
    note: str = ""

    @property
    def headroom(self) -> float:
        return self.budget / self.measured if self.measured else float("inf")

    def render(self) -> str:
        return (
            f"  {self.name:<44} {self.measured:>10.3f} {self.unit:<3} "
            f"(budget {self.budget:g} {self.unit}, {self.headroom:>6.1f}x headroom)"
            + (f"  {self.note}" if self.note else "")
        )


@dataclass(slots=True)
class Report:
    rows: list[Measurement] = field(default_factory=list)

    def record(
        self, name: str, measured: float, budget: float, unit: str, note: str = ""
    ) -> Measurement:
        row = Measurement(name=name, measured=measured, budget=budget, unit=unit, note=note)
        self.rows.append(row)
        return row

    def render(self) -> str:
        header = "[bench] measured numbers (build doc section 12)"
        return "\n".join([header, *(row.render() for row in self.rows)])


@pytest.fixture(scope="module")
def report(request: pytest.FixtureRequest) -> Iterator[Report]:
    """Collects every measurement and prints the table once, for the README."""
    book = Report()
    yield book
    if not book.rows:
        return
    table = book.render()
    capture = request.config.pluginmanager.getplugin("capturemanager")
    if capture is not None:
        with capture.global_and_fixture_disabled():
            print("\n" + table)
    else:  # pragma: no cover -- capture plugin is always present under pytest
        print("\n" + table)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def registry() -> EntityRegistry:
    return load_registry(REGISTRY_PATH)


@pytest.fixture(scope="module")
def bench_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    return Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path_factory.mktemp("bench-data"),
        registry_path=REGISTRY_PATH,
        llm_provider="mock",
    )


@pytest.fixture(scope="module")
def detector(registry: EntityRegistry, bench_settings: Settings) -> Detector:
    """Built once, then warmed: model load is a startup cost, not a request cost."""
    built = Detector(registry, bench_settings)
    built.analyzer  # noqa: B018 -- forces the spaCy load outside the timed region
    return built


@pytest.fixture(scope="module")
def brief_slab() -> str:
    """The first 2,000 words of the large legal brief -- the section 12 input."""
    text = LARGE_BRIEF.read_text(encoding="utf-8")
    return " ".join(text.split()[:WORDS])


@pytest_asyncio.fixture
async def vault_stack(
    bench_settings: Settings, tmp_path: Path
) -> AsyncIterator[tuple[SessionRegistry, SessionVault, AuditLogger]]:
    audit = await AuditLogger.open(tmp_path / "audit.db")
    sessions = SessionRegistry(bench_settings)
    vault = await SessionVault.open(tmp_path / "vault.db", sessions)
    try:
        yield sessions, vault, audit
    finally:
        await vault.close()
        await audit.close()


# ---------------------------------------------------------------------------
# 1. Obfuscation throughput
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("strategy", ["tokenization", "pseudonymization"])
async def test_obfuscation_of_2000_words_is_under_two_seconds(
    registry: EntityRegistry,
    bench_settings: Settings,
    detector: Detector,
    brief_slab: str,
    vault_stack: tuple[SessionRegistry, SessionVault, AuditLogger],
    report: Report,
    strategy: str,
) -> None:
    """Detect + obfuscate 2,000 words of the large brief, LLM excluded.

    This is the whole pre-egress stage: everything that has to happen between a
    request arriving and a payload being safe to send. Timing only the splice
    would flatter the number by hiding the part that actually costs -- spaCy NER
    is the bottleneck, and the README's Q1 answer depends on that being visible.
    """
    sessions, vault, audit = vault_stack
    engine = ObfuscationEngine(
        registry=registry,
        vault=vault,
        session_registry=sessions,
        settings=bench_settings,
        audit=audit,
    )
    assert len(brief_slab.split()) == WORDS

    # Best-of-N: see BENCH_REPEATS. Each repetition gets its own session, so no
    # repetition is measuring another's warm vault.
    total_s = float("inf")
    detect_s = obfuscate_s = 0.0
    detections: list[Detection] = []
    obfuscated = None
    for _ in range(BENCH_REPEATS):
        session_id, _expires_at = await sessions.create("test-user")
        started = time.perf_counter()
        run_detections = await detector.detect(brief_slab, "legal")
        run_detect_s = time.perf_counter() - started

        mark = time.perf_counter()
        run_obfuscated = await engine.obfuscate(
            session_id, brief_slab, run_detections, strategy=strategy, doc_category="legal"
        )
        run_obfuscate_s = time.perf_counter() - mark

        if run_detect_s + run_obfuscate_s < total_s:
            total_s = run_detect_s + run_obfuscate_s
            detect_s, obfuscate_s = run_detect_s, run_obfuscate_s
        detections, obfuscated = list(run_detections), run_obfuscated

    # The measurement must be of real work, not of an empty document.
    assert detections, "the brief slab produced no detections; the benchmark is meaningless"
    assert obfuscated is not None
    assert obfuscated.tokens
    assert obfuscated.obfuscated_text != brief_slab

    report.record(
        f"obfuscate {WORDS} words ({strategy})",
        total_s,
        BUDGET_OBFUSCATE_S,
        "s",
        note=(
            f"detect {detect_s * 1000:.0f} ms + engine {obfuscate_s * 1000:.0f} ms, "
            f"{len(detections)} entities, {len(obfuscated.tokens)} tokens"
        ),
    )
    assert total_s < BUDGET_OBFUSCATE_S, (
        f"{strategy}: detect+obfuscate of {WORDS} words took {total_s:.3f} s "
        f"(detect {detect_s:.3f} s, engine {obfuscate_s:.3f} s), budget {BUDGET_OBFUSCATE_S} s"
    )


# ---------------------------------------------------------------------------
# 2. Vault lookup latency
# ---------------------------------------------------------------------------


async def _populate(
    sessions: SessionRegistry, vault: SessionVault, session_id: str, count: int
) -> list[str]:
    """Vault ``count`` distinct values; return the token IDs actually issued."""
    session_key = await sessions.key(session_id)
    token_ids: list[str] = []
    for index in range(count):
        value = f"Benchmark Subject Number {index:04d}"
        token_id = derive_token_id(session_key, "NAME", value)
        record = TokenRecord(
            session_id=session_id,
            token_id=token_id,
            entity_type="NAME",
            category=EntityCategory.PII,
            surrogate=format_surrogate("PII", "NAME", token_id),
            created_at=time.time(),
        )
        await vault.put(session_id, record, value)
        # A collision would have re-derived the ID, so read back what was stored.
        stored = await vault.get_by_original(session_id, "NAME", value)
        assert stored is not None
        token_ids.append(stored.token_id)
    return token_ids


async def test_vault_lookup_p99_is_under_five_milliseconds(
    vault_stack: tuple[SessionRegistry, SessionVault, AuditLogger],
    report: Report,
) -> None:
    """1,000 cached lookups, p99 under 5 ms (build doc sections 9.4 and 10.1).

    This is the number the EgressGate and the restorer live on: the gate consults
    the vault for every outbound payload and the restorer once per distinct token
    in a response, so a slow vault read shows up as latency on every request.
    """
    sessions, vault, _audit = vault_stack
    session_id, _expires_at = await sessions.create("test-user")
    token_ids = await _populate(sessions, vault, session_id, VAULT_ENTRIES)
    assert len(token_ids) == VAULT_ENTRIES

    samples: list[float] = []
    for index in range(VAULT_LOOKUPS):
        token_id = token_ids[index % len(token_ids)]
        started = time.perf_counter()
        value = await vault.get_by_token(session_id, token_id)
        samples.append((time.perf_counter() - started) * 1000.0)
        assert value.startswith("Benchmark Subject Number")

    samples.sort()
    p50 = samples[len(samples) // 2]
    p99 = samples[int(len(samples) * 0.99) - 1]
    report.record(
        f"vault lookup p99 ({VAULT_LOOKUPS} cached reads)",
        p99,
        BUDGET_VAULT_P99_MS,
        "ms",
        note=f"p50 {p50:.4f} ms, mean {statistics.mean(samples):.4f} ms, {VAULT_ENTRIES} entries",
    )
    assert p99 < BUDGET_VAULT_P99_MS, (
        f"vault lookup p99 was {p99:.4f} ms over {VAULT_LOOKUPS} lookups, "
        f"budget {BUDGET_VAULT_P99_MS} ms"
    )


# ---------------------------------------------------------------------------
# 3. De-obfuscation latency
# ---------------------------------------------------------------------------


async def test_deobfuscation_of_a_500_token_response_is_under_500ms(
    bench_settings: Settings,
    vault_stack: tuple[SessionRegistry, SessionVault, AuditLogger],
    report: Report,
) -> None:
    """Restore a response carrying 500 distinct tokens (build doc sections 10.7 and 12).

    Every token is distinct, so the restorer's per-call resolution cache cannot
    absorb the work: 500 separate resolutions plus the string rebuild.

    **What this measures is the warm path, and that is now said rather than implied.**
    This docstring used to claim "500 real vault reads", which was false and measurably
    so -- counting ``SessionVault._fetch_one`` across this benchmark's own inputs gives
    **zero** SQLite reads and therefore zero AES-GCM decryptions. ``_populate`` vaults
    the values through ``vault.put``, which fills the vault's own ``_SessionCache``, so
    every resolution here is a dict hit on already-decrypted plaintext. The cache doing
    the absorbing was never the restorer's per-call one; it was the vault's.

    That is not a worthless measurement -- it is exactly the production request path,
    where obfuscation has just populated the cache in the same process moments earlier
    -- but it is the *best* case, not the worst one the old wording claimed. The worst
    case is measured immediately below by
    :func:`test_deobfuscation_of_a_500_token_response_is_under_500ms_with_a_cold_vault`,
    which drops the cache first and does pay for 500 SQLite reads and 500 AES-GCM
    decryptions. Both are held to the same budget, so the claim survives either way.
    """
    sessions, vault, audit = vault_stack
    restorer = Restorer(vault=vault, settings=bench_settings, audit=audit)
    session_id, _expires_at = await sessions.create("test-user")
    token_ids = await _populate(sessions, vault, session_id, RESPONSE_TOKENS)

    lines = [
        f"Paragraph {index}: the record identifies "
        f"{format_surrogate('PII', 'NAME', token_id)} as a party to the matter."
        for index, token_id in enumerate(token_ids)
    ]
    response = "\n".join(lines)

    started = time.perf_counter()
    restored = await restorer.restore(session_id, response, strategy="tokenization")
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    assert restored.tokens_seen == RESPONSE_TOKENS
    assert restored.restored_count == RESPONSE_TOKENS
    assert restored.vault_misses == 0

    report.record(
        f"restore a {RESPONSE_TOKENS}-token response (warm vault)",
        elapsed_ms,
        BUDGET_RESTORE_MS,
        "ms",
        note=f"{len(response):,} chars, {restored.restored_count} values restored, 0 SQLite reads",
    )
    assert elapsed_ms < BUDGET_RESTORE_MS, (
        f"restoring {RESPONSE_TOKENS} tokens took {elapsed_ms:.1f} ms, "
        f"budget {BUDGET_RESTORE_MS} ms"
    )


async def test_deobfuscation_of_a_500_token_response_is_under_500ms_with_a_cold_vault(
    bench_settings: Settings,
    vault_stack: tuple[SessionRegistry, SessionVault, AuditLogger],
    report: Report,
) -> None:
    """The same 500-token restore, but paying for real SQLite reads and real AES-GCM.

    The warm benchmark above is the request path; this is the worst case its docstring
    used to claim to be. Dropping ``_caches[session_id]`` after ``_populate`` forces
    every resolution through ``SessionVault._fetch_one`` and the decrypt that follows
    it. Measured with a counting wrapper on ``_fetch_one``: **0** calls warm, **500**
    calls cold, which is what makes the two rows different measurements rather than
    the same one run twice.

    The cold path is reachable in production, which is why it gets a budget rather
    than a comment: a restore whose session was vaulted by a *different* worker
    process, or before a restart, or after the cache was evicted, starts cold. Held to
    the same ``BUDGET_RESTORE_MS`` as the warm path -- if the cold path ever needs a
    looser budget than the warm one, that is a finding about the vault, not a reason
    to move the line.

    ``vault._caches`` is private and is reached into on purpose. The alternative is
    reopening a second ``SessionVault`` on the same database file, which measures
    connection setup as well and makes the number harder to attribute; the assertion
    below on the ``_fetch_one`` count is what keeps this honest either way.
    """
    sessions, vault, audit = vault_stack
    restorer = Restorer(vault=vault, settings=bench_settings, audit=audit)
    session_id, _expires_at = await sessions.create("test-user")
    token_ids = await _populate(sessions, vault, session_id, RESPONSE_TOKENS)

    response = "\n".join(
        f"Paragraph {index}: the record identifies "
        f"{format_surrogate('PII', 'NAME', token_id)} as a party to the matter."
        for index, token_id in enumerate(token_ids)
    )

    # Count the reads, so "cold" is verified rather than assumed. A future cache that
    # survives this pop would silently turn this back into a copy of the warm test.
    reads = 0
    original_fetch_one = SessionVault._fetch_one

    async def counting_fetch_one(
        self: SessionVault, sql: str, params: tuple[object, ...]
    ) -> object:
        nonlocal reads
        reads += 1
        return await original_fetch_one(self, sql, params)

    # Best-of-N: see BENCH_REPEATS. At 4.7x this sits in the same band as the
    # obfuscation budgets, which are repeated for the same reason. The cache is
    # dropped again before every repetition, so each one is genuinely cold -- and
    # `reads` is therefore counted per repetition, not cumulatively.
    elapsed_ms = float("inf")
    restored = None
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(SessionVault, "_fetch_one", counting_fetch_one)
        for _ in range(BENCH_REPEATS):
            vault._caches.pop(session_id, None)
            reads = 0
            started = time.perf_counter()
            run_restored = await restorer.restore(session_id, response, strategy="tokenization")
            elapsed_ms = min(elapsed_ms, (time.perf_counter() - started) * 1000.0)
            restored = run_restored

    assert restored is not None
    assert restored.restored_count == RESPONSE_TOKENS
    assert restored.vault_misses == 0
    assert reads == RESPONSE_TOKENS, (
        f"premise: a cold vault must do one SQLite read per distinct token -- got "
        f"{reads} for {RESPONSE_TOKENS} tokens; if this is 0 the cache was not dropped "
        "and this benchmark is a duplicate of the warm one"
    )

    report.record(
        f"restore a {RESPONSE_TOKENS}-token response (cold vault)",
        elapsed_ms,
        BUDGET_RESTORE_MS,
        "ms",
        note=f"{reads} SQLite reads + {reads} AES-GCM decryptions",
    )
    assert elapsed_ms < BUDGET_RESTORE_MS, (
        f"restoring {RESPONSE_TOKENS} tokens from a cold vault took {elapsed_ms:.1f} ms "
        f"({reads} SQLite reads), budget {BUDGET_RESTORE_MS} ms"
    )


async def test_deobfuscation_of_a_500_surrogate_response_is_under_500ms(
    bench_settings: Settings,
    vault_stack: tuple[SessionRegistry, SessionVault, AuditLogger],
    report: Report,
) -> None:
    """The pseudonymization half of the restore budget, which had none (build doc 12).

    The section 12 restore row was asserted for the **token** pass only: the shipped
    benchmark calls ``restore(..., strategy="tokenization")`` with no ``surrogates``
    and no ``issued``, so ``_compile_surrogate_pattern`` and ``_restore_surrogates``
    never ran and the README's unqualified "restore a 500-token response" number
    covered one of the two strategies. The obfuscate row is already split into a
    tokenization and a pseudonymization measurement; this is the restore side of the
    same split.

    It is the more expensive half, and for a different reason than the token pass:
    tokens are found by a fixed regex and resolved one by one, while surrogates are
    matched by a single alternation compiled *from the surrogate map itself*, so the
    cost scales with the number of distinct fakes rather than with the number of
    occurrences. 500 distinct surrogates is therefore a 500-branch pattern, which is
    the shape worth bounding.

    Mixed full-name and surname fakes on purpose: the restorer's longest-first
    ordering is what stops ``Vandenberg`` rewriting the tail of ``Marguerite
    Vandenberg``, and a map of only full names would never exercise it.
    """
    sessions, vault, audit = vault_stack
    restorer = Restorer(vault=vault, settings=bench_settings, audit=audit)
    session_id, _expires_at = await sessions.create("test-user")

    surrogates: dict[str, str] = {}
    lines: list[str] = []
    for index in range(RESPONSE_TOKENS):
        surname = f"Vandenberg{index:04d}"
        full_name = f"Marguerite {surname}"
        surrogates[full_name] = f"Real Person Number {index:04d}"
        surrogates[surname] = f"Person{index:04d}"
        # Both spellings occur, so the longest-first ordering is actually exercised.
        lines.append(
            f"Paragraph {index}: the record identifies {full_name} as a party; "
            f"{surname} is named again in the schedule."
        )
    response = "\n".join(lines)

    # Best-of-N: see BENCH_REPEATS. At 1.8x this is now the tightest budget in the
    # module -- tighter than the full pipeline -- so it gets the same treatment the
    # other tight budgets get, for the same reason and by the same policy. The pass is
    # read-only with respect to the vault, so repeating it measures the same work.
    elapsed_ms = float("inf")
    restored = None
    for _ in range(BENCH_REPEATS):
        started = time.perf_counter()
        run_restored = await restorer.restore(
            session_id, response, strategy="pseudonymization", surrogates=surrogates, issued=()
        )
        elapsed_ms = min(elapsed_ms, (time.perf_counter() - started) * 1000.0)
        restored = run_restored
    assert restored is not None

    # The pass must actually have done the work, or the timing bounds nothing.
    assert restored.surrogates_seen > 0, (
        "premise: the surrogate pass must have run -- if this is 0 the benchmark is "
        "timing an empty pattern and the budget is vacuous"
    )
    assert restored.surrogate_misses == 0, "every surrogate in the map must resolve"
    for fake, original in list(surrogates.items())[:5]:
        assert fake not in restored.text, f"surrogate {fake} survived the pass"
        assert original in restored.text

    report.record(
        f"restore a {RESPONSE_TOKENS}-surrogate response (pseudonymization)",
        elapsed_ms,
        BUDGET_RESTORE_MS,
        "ms",
        note=f"{len(response):,} chars, {len(surrogates)} distinct surrogates in the pattern",
    )
    assert elapsed_ms < BUDGET_RESTORE_MS, (
        f"restoring {len(surrogates)} surrogates took {elapsed_ms:.1f} ms, "
        f"budget {BUDGET_RESTORE_MS} ms"
    )


# ---------------------------------------------------------------------------
# 4. Whole-pipeline latency
# ---------------------------------------------------------------------------


async def test_full_pipeline_on_the_large_brief_is_under_fifteen_seconds(
    registry: EntityRegistry,
    bench_settings: Settings,
    detector: Detector,
    vault_stack: tuple[SessionRegistry, SessionVault, AuditLogger],
    tmp_path: Path,
    report: Report,
) -> None:
    """Fetch, detect, obfuscate, gate, model, restore -- the section 12 budget.

    This is the fourth performance budget the specification names, and it was the
    only one with no automated check: the build doc puts it in ``demo.py --real``,
    which needs an API key and a network, so nothing verified it in CI and the
    number quoted in the README was a measurement nobody could reproduce by
    running the suite.

    Running it on the mock provider closes that gap for **everything this system
    controls**. What it deliberately does not cover is the provider round trip,
    which on a real call dominates the total and is not ours to optimise. So the
    honest reading of this budget is "the pipeline's own work fits inside 15 s
    with room for a model call", and ``demo.py --real`` remains the check that
    includes the network. Both numbers are worth having; neither replaces the
    other.

    The largest fixture is the input on purpose -- 12,000 words and 200+ distinct
    entities is the Q1 discussion artifact, so the benchmark and the README's
    scaling answer are measuring the same document.
    """
    sessions, vault, audit = vault_stack
    store = await EncryptedDocumentStore.open(bench_settings)
    orchestrator = PipelineOrchestrator(
        store=store,
        detector=detector,
        engine=ObfuscationEngine(
            registry=registry,
            vault=vault,
            session_registry=sessions,
            settings=bench_settings,
            audit=audit,
        ),
        injector=ContextInjector(),
        gate=EgressGate(
            vault=vault, detector=detector, settings=bench_settings, audit=audit
        ),
        provider=MockProvider(),
        restorer=Restorer(vault=vault, settings=bench_settings, audit=audit),
        vault=vault,
        settings=bench_settings,
        audit=audit,
    )

    try:
        document = LARGE_BRIEF.read_text(encoding="utf-8")
        doc_id = await store.put(
            "bench-user", "legal_brief_large.txt", document.encode("utf-8"), "legal"
        )
        # Best-of-N: see BENCH_REPEATS. This is the tightest budget in the table
        # (2.3x) and therefore the one a contended machine can turn red on its own.
        elapsed_s = float("inf")
        result = None
        for _ in range(BENCH_REPEATS):
            session_id, _expires_at = await sessions.create("bench-user")
            started = time.perf_counter()
            run_result = await orchestrator.run(
                session_id, "bench-user", doc_id, "Summarise the disputed issues.", "tokenization"
            )
            elapsed_s = min(elapsed_s, time.perf_counter() - started)
            result = run_result
        assert result is not None
    finally:
        await store.close()

    # The measurement has to be of a run that actually did the work.
    assert result.stats["entities_detected"] > 0
    assert result.stats["tokens_issued"] > 0
    assert result.restored_text
    assert result.stats["vault_misses"] == 0

    stats = result.stats
    report.record(
        "full pipeline, 12k-word brief (mock provider)",
        elapsed_s,
        BUDGET_PIPELINE_S,
        "s",
        note=(
            f"detect {stats['detect_ms']:.0f} ms + engine {stats['obfuscate_ms']:.0f} ms "
            f"+ gate {stats['egress_ms']:.0f} ms + restore {stats['restore_ms']:.0f} ms, "
            f"{int(stats['entities_detected'])} spans, {int(stats['tokens_issued'])} tokens"
        ),
    )
    assert elapsed_s < BUDGET_PIPELINE_S, (
        f"the full pipeline took {elapsed_s:.2f} s on {len(document.split()):,} words "
        f"(detect {stats['detect_ms']:.0f} ms, engine {stats['obfuscate_ms']:.0f} ms, "
        f"gate {stats['egress_ms']:.0f} ms, restore {stats['restore_ms']:.0f} ms), "
        f"budget {BUDGET_PIPELINE_S} s"
    )
