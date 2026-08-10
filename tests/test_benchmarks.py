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
matters. There is no ``addopts`` in ``pyproject.toml`` deselecting them, and the
one ``pytest_collection_modifyitems`` hook in ``tests/conftest.py`` touches
``real_llm`` items and nothing else, so a bare ``pytest`` collects and runs every
one of these -- which is what the collected-test split in README section 1 counts.
(That sentence used to read "there is no ``collection_modifyitems`` hook" and to
paste the split as a literal; the first half stopped being true when ``--real-llm``
was added, and the second was a copy of a number that lives in section 1 and is
re-derived by ``tests/test_readme_claims.py`` from a real collection.)

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
#: A wall-clock assertion measures the machine as much as the code. The repeated
#: rows are the ones whose headroom is in single digits -- which rows those are is a
#: property of the current tree and is printed by every run rather than pasted here
#: -- and a reviewer's laptop mid-Spotlight-index, a CI box with noisy neighbours,
#: or -- as happened during this build -- three other test suites running
#: concurrently, can plausibly eat single-digit headroom. A benchmark that goes red for
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
#: **This comment used to paste a seven-row table of measured timings, and that
#: table was the third different set of numbers for the same benchmarks in this
#: repository** -- the README published one set, an audit measured another, and this
#: docstring carried a third, none of them current. It is deleted rather than
#: refreshed. A pasted number that nothing re-derives is a claim with a half-life,
#: and three copies of it is three half-lives; the measurements this module makes
#: are printed by :class:`Report` on every run and bound to the README's published
#: table by :func:`test_the_readme_benchmark_table_is_the_one_this_run_measured`,
#: which is the only copy that cannot go stale silently.
#:
#: What is *not* a measurement and therefore stays written down here is the
#: reasoning:
#:
#: * Best-of-N is applied to every budget whose headroom is in single digits, and to
#:   nothing else. Which rows those are moves with the code, so the module does not
#:   name them; the printed table does, on every run.
#: * The token-restore rows are almost entirely audit writes. Core requirement 7
#:   wants a de-obfuscation event to name an entity type and a token, so the restorer
#:   writes one ``DEOBFUSCATE`` row per distinct restored token ID -- the same
#:   one-row-per-entity shape the obfuscation engine already pays for outbound. That
#:   cost is bounded by ``restorer._MAX_RESTORE_ROWS`` (512) rather than left to
#:   scale with whatever the model sends back, and these two rows are the fastest way
#:   to see an ``AuditLogger.emit`` regression.
#: * The first iteration of a cold-vault restore pays for a cold SQLite page cache
#:   and first-call overhead in the regex engine. Both are properties of the
#:   measurement rather than of the pipeline, which is precisely the case best-of-N
#:   exists for -- and precisely why widening a budget instead would be the wrong
#:   correction.
#: * The surrogate restore is worth calling out because it had no budget test at all
#:   until recently: the section 12 restore row was asserted for the token pass only,
#:   so the README's unqualified "restore a 500-token response" figure covered one of
#:   the two strategies.
BENCH_REPEATS = 3

REPO_ROOT_README = REPO_ROOT / "README.md"

#: How far this run's headroom may sit outside the range the README publishes for
#: the same row before the published figure is called stale, as a multiplicative
#: factor. NOT a fraction of the guarded quantity and not a fixed millisecond
#: allowance: a wall-clock figure moves with the machine, so the only stable thing
#: to bound is a ratio.
#:
#: Chosen from measurement rather than taste, and widened once after measuring:
#:
#: * Three consecutive runs of this module on an idle box moved each row's headroom
#:   by at most **1.15x**.
#: * The widest *legitimate* gap between a row measured here and the range the README
#:   publishes for it was **1.48x** on that idle box -- the cold-vault restore, whose
#:   two published samples were taken on a quieter machine than the rows above them.
#: * The same row on a **contended** box, with three other suites running, went to
#:   **2.4x**. That is the number this bound has to survive, and 3.0 did not leave
#:   enough room above it.
#: * The defect this bound exists to catch -- a warm-restore row published at
#:   93.3x while this module measures it in single digits -- is **6.8x** idle and
#:   **10.4x** contended.
#:
#: So 4.0: 1.7x of margin above the worst honest reading and 1.7x below the defect.
#: A bound placed by measuring both populations rather than by picking a round
#: number and hoping.
#:
#: **What that buys and what it does not.** It catches an order-of-magnitude stale
#: figure -- the 50x and 7x cases this table has now produced twice -- and it does
#: not catch a 2x drift. It is a *staleness* detector, not a regression detector:
#: the regression detector is the budget assertion in each test, which is exact and
#: is what the README says is the only number it asserts. A reviewer on hardware
#: more than 3x away from the published range will see this go red, and the correct
#: response is to add their observation to the published range, which is the
#: behaviour section 1 already asks for.
README_HEADROOM_FACTOR = 4.0


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

    # Best-of-N: see BENCH_REPEATS. This sits in the same single-digit-headroom
    # band as the obfuscation budgets, which are repeated for the same reason.
    # (A headroom figure used to be quoted here; it was one of the three stale
    # copies BENCH_REPEATS' comment now records deleting. The run prints it.) The cache is
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

    # Best-of-N: see BENCH_REPEATS. This row is repeated because its headroom is in
    # single digits, by the same policy as the others; which row is *tightest* moves
    # with the code, is printed by the run, and is checked against the README's
    # published table by test_the_readme_benchmark_table_is_the_one_this_run_measured
    # rather than asserted in a comment here. The pass is
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
        # Best-of-N: see BENCH_REPEATS. Single-digit headroom, and therefore one a
        # contended machine can turn red on its own.
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


# ---------------------------------------------------------------------------
# 5. The README's published table, bound to what this run measured
# ---------------------------------------------------------------------------
#
# Nothing bound it before. `tests/test_readme_claims.py` said so out loud -- "the
# bench figures are a pasted measurement, not a re-derivation, so nothing here
# drifts under a later commit" -- and the consequence was exactly what that sentence
# predicts: the README published a 500-token warm restore at 5.359 ms / 93.3x while
# this module measured 36.5 ms / 13.7x on a quiet box, and a separate audit had
# earlier measured the same row near 285 ms. Three numbers, one row, none of them
# derivable from anything.
#
# The correction is not to paste today's numbers, which would rot on the same
# schedule. It is to bind the things that do not move with the machine:
#
#   * the BUDGET, which is a constant in this file;
#   * the RELATIONSHIP between each published sample and its budget (the headroom
#     column must be arithmetic on the row's own numbers, at the precision printed);
#   * the ROW SET, which is whatever this module measures;
#   * the IDENTITY of the tightest row, which is a property of the code rather than
#     of the box -- a slower machine moves every row together;
#   * and, as a staleness detector only, the ratio between published and measured
#     headroom, bounded by README_HEADROOM_FACTOR.

import math  # noqa: E402 -- kept beside the section that uses it
import re  # noqa: E402


@dataclass(frozen=True, slots=True)
class ReadmeBenchRow:
    """One row of the README's section 1 benchmark table, as published."""

    label: str
    #: Every measurement column, in seconds, in the order printed.
    samples: tuple[float, ...]
    #: The same columns as ``(low, high)`` intervals implied by the printed
    #: precision: ``0.001 ms`` means "somewhere in [0.0005, 0.0015] ms", which is the
    #: difference between the vault row being checkable and being nonsense.
    sample_bounds: tuple[tuple[float, float], ...]
    budget_s: float
    budget_text: str
    headroom: float
    #: The headroom cell as its own printed precision implies: ``1.75x`` stands for
    #: anything in [1.745, 1.755). Without this the arithmetic check below rejects
    #: correct rows -- ``2 s / 1.142 s`` is 1.75055, which is not 1.75.
    headroom_bounds: tuple[float, float]
    raw: str

    @property
    def worst_headroom(self) -> float:
        return self.budget_s / max(self.samples)

    @property
    def published_headroom_range(self) -> tuple[float, float]:
        """Every headroom the row's MEASUREMENT columns support, widest reading.

        Derived from the samples alone, and the headroom cell is deliberately not
        one of the inputs. The first version of this property included it, which
        made ``low <= headroom <= high`` an assertion that a number lies inside a
        range built from itself -- vacuous, and caught by sabotage rather than by
        reading: editing the headroom cell alone left the check green. It is
        exactly the failure this whole file is here to remove, produced while
        removing it.
        """
        candidates = [self.budget_s / value for _, value in self.sample_bounds]
        candidates += [self.budget_s / value for value, _ in self.sample_bounds]
        return min(candidates), max(candidates)


_DURATION = re.compile(r"^([\d,]+(?:\.\d+)?)\s*(s|ms)$")
# The multiplication sign is written as an escape: RUF001 flags the literal as an
# ambiguous character, and this file is otherwise plain ASCII.
_HEADROOM = re.compile(r"^([\d,]+(?:\.\d+)?)\s*[x\u00d7]$", re.IGNORECASE)


def _number(text: str) -> float:
    return float(text.replace(",", ""))


def _printed_bounds(text: str, scale: float) -> tuple[float, float]:
    """``"0.001"`` -> the half-open interval its last printed digit stands for."""
    digits = len(text.partition(".")[2])
    half = 0.5 * 10.0**-digits
    value = _number(text)
    return (value - half) * scale, (value + half) * scale


def parse_readme_bench_table(text: str) -> list[ReadmeBenchRow]:
    """The benchmark table, located by its column headings rather than by position.

    Located rather than counted from the top of the file: section numbering moves,
    and a table found by index is a table that silently becomes a different table.
    The header must be unique, which is itself a check -- two benchmark tables on
    one page is the shape that let the boundary counts disagree six ways.
    """
    lines = text.splitlines()
    headers = [
        index
        for index, line in enumerate(lines)
        if line.startswith("|")
        and "budget" in line.lower()
        and "headroom" in line.lower()
        and "measurement" in line.lower()
    ]
    assert len(headers) == 1, (
        f"expected exactly one benchmark table (a header row naming Measurement, "
        f"Budget and Headroom); found {len(headers)}"
    )
    columns = [cell.strip().lower() for cell in lines[headers[0]].strip().strip("|").split("|")]
    budget_at = columns.index(next(c for c in columns if "budget" in c))
    headroom_at = columns.index(next(c for c in columns if "headroom" in c))

    rows: list[ReadmeBenchRow] = []
    for line in lines[headers[0] + 2 :]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        assert len(cells) == len(columns), f"ragged benchmark row: {line[:80]!r}"

        samples: list[float] = []
        bounds: list[tuple[float, float]] = []
        for index, cell in enumerate(cells):
            if index in (0, budget_at, headroom_at):
                continue
            match = _DURATION.match(cell)
            if match is None:
                continue
            scale = 1.0 if match.group(2) == "s" else 1e-3
            samples.append(_number(match.group(1)) * scale)
            bounds.append(_printed_bounds(match.group(1), scale))
        assert samples, f"no measurement column in benchmark row: {line[:80]!r}"

        budget = _DURATION.match(cells[budget_at])
        assert budget is not None, f"unparsable budget {cells[budget_at]!r} in {line[:80]!r}"
        headroom = _HEADROOM.match(cells[headroom_at])
        assert headroom is not None, f"unparsable headroom {cells[headroom_at]!r}"

        rows.append(
            ReadmeBenchRow(
                label=cells[0],
                samples=tuple(samples),
                sample_bounds=tuple(bounds),
                budget_s=_number(budget.group(1)) * (1.0 if budget.group(2) == "s" else 1e-3),
                budget_text=cells[budget_at],
                headroom=_number(headroom.group(1)),
                headroom_bounds=_printed_bounds(headroom.group(1), 1.0),
                raw=line,
            )
        )
    assert rows, "the benchmark table has a header and no rows"
    return rows


def normalise_bench_label(label: str) -> str:
    """``"Obfuscate 2,000 words (tokenization)"`` -> ``"obfuscate 2000 words (tokenization)"``.

    Thousands separators only: the labels are otherwise expected to match, because
    the README's are copied from this module's :class:`Report` and that is the
    coupling worth having. A rename here is meant to force a rename there.
    """
    return " ".join(re.sub(r"(?<=\d),(?=\d)", "", label).lower().split())


def _tightest_claim_sentences(text: str) -> list[str]:
    """Every sentence claiming some row has the least headroom.

    Blocks first, then sentences: a markdown table row ends in ``|`` rather than a
    full stop, so a naive sentence split glues the whole table onto the sentence
    that follows it and the word count then matches every row at once. Also
    measured rather than supposed -- a synthetic claim sentence sitting directly
    under a table passed the first version of this check for that reason.

    Scoped to the SENTENCE and not to the paragraph, and that is not a detail: the
    paragraph carrying this claim in section 1 also discusses the warm and cold
    restore rows at length, so a paragraph-scoped word count ties between three
    rows, identifies none, and the check silently passes on the one case it exists
    for. Measured, not supposed -- the first version of this test did exactly that.
    """
    units: list[str] = []
    for block in re.split(r"\n\s*\n", text):
        if block.lstrip().startswith("|"):
            units.extend(" ".join(row.split()) for row in block.splitlines())
        else:
            units.append(" ".join(block.split()))
    sentences: list[str] = []
    for unit in units:
        sentences.extend(re.split(r"(?<=[.!?])\s+(?=[A-Z*`])", unit))
    return [
        sentence
        for sentence in sentences
        if re.search(r"\btightest\b|\bleast headroom\b", sentence, re.IGNORECASE)
    ]


#: Words that appear in so many row labels that they identify nothing.
_LABEL_STOPWORDS = frozenset({"a", "the", "of", "and", "response", "words", "per"})


def _row_named_by(rows: list[Measurement], sentence: str) -> str | None:
    """Which measured row a sentence is about, or ``None`` if it does not say.

    Word overlap against each row's label rather than a pattern per sentence: the
    lesson of every stale claim in this repository is that the next wrong sentence
    is worded differently, so a matcher keyed on wording is a matcher for the
    sentence that has already been fixed. Returns ``None`` on a tie, which is the
    honest answer and the reason the table check beside this one is the binding
    half.
    """
    lowered = sentence.lower()
    scores = {
        row.name: sum(
            1
            for word in set(re.findall(r"[a-z]+", normalise_bench_label(row.name)))
            if word not in _LABEL_STOPWORDS and word in lowered
        )
        for row in rows
    }
    best = max(scores.values())
    if best == 0:
        return None
    named = sorted(name for name, score in scores.items() if score == best)
    return named[0] if len(named) == 1 else None


def _seconds(row: Measurement) -> float:
    return row.measured if row.unit == "s" else row.measured / 1000.0


def _budget_seconds(row: Measurement) -> float:
    return row.budget if row.unit == "s" else row.budget / 1000.0


def check_readme_bench_table(rows: list[Measurement], text: str) -> None:
    """The published benchmark table, checked against the run that just happened.

    Defined last in the module on purpose: pytest runs a file in definition order,
    so by the time this executes every other benchmark has recorded its row into the
    module-scoped :class:`Report`. It therefore costs no extra measurement -- it
    reads the numbers the run already produced.

    **What this binds.**

    * *The budget column.* ``BUDGET_RESTORE_MS`` and friends are constants in this
      file, and the README publishes them as a column. Exact, both ways.
    * *The row set.* Every row this module measures has a published row and every
      published row is measured. This is the check that catches a benchmark added
      with no table row -- the shape that let the surrogate-restore pass ship with
      no budget assertion at all.
    * *The headroom column.* It must be arithmetic on the row's own published
      numbers, at the precision they are printed to. ``0.001 ms`` against a 5 ms
      budget supports any headroom from 3,333x to 10,000x, and pretending it means
      exactly 5,000x would make the vault row unfalsifiable in one direction and
      absurd in the other.
    * *Every published sample is under its own budget.* A table that publishes a
      measurement its own test would fail is a table describing a red suite.
    * *The identity of the tightest row.* A slower machine moves every row together,
      so which row has the least headroom is a property of the code. This is the
      part of the table that survives being run somewhere else.

    **What this does not bind, stated because the alternative is implying it does.**
    It does not verify the published numbers were ever observed -- they are one
    sample of seven taken on someone's laptop, and no test can re-derive a past
    observation. It does not detect a 2x drift; see :data:`README_HEADROOM_FACTOR`
    for the measurement behind that number and for why a tighter bound would fail on
    honest hardware differences. And it is a *staleness* detector, not a performance
    gate: the gate is the budget assertion in each test above, which is exact.
    """
    assert rows, (
        "no benchmark recorded a row, so this check has nothing to compare. It reads the "
        "module-scoped Report, so run the whole module rather than this test alone"
    )
    measured = {normalise_bench_label(row.name): row for row in rows}
    published = {
        normalise_bench_label(row.label): row for row in parse_readme_bench_table(text)
    }

    assert len(measured) == len(rows), "two benchmarks recorded the same row name"
    replacement = "\n  ".join(
        f"| {row.name} | {row.measured:.3f} {row.unit} | {row.budget:g} {row.unit} "
        f"| {row.headroom:.1f}x |"
        for row in rows
    )
    assert measured.keys() == published.keys(), (
        f"the README's benchmark table lists {sorted(published)} and this run measured "
        f"{sorted(measured)}. The table's labels come from this module's Report, so a "
        f"benchmark added or renamed here has to be added or renamed there.\n"
        f"This run measured:\n  {replacement}"
    )

    stale: list[str] = []
    for key, row in sorted(published.items()):
        run = measured[key]
        run_budget = _budget_seconds(run)
        assert math.isclose(row.budget_s, run_budget, rel_tol=1e-9), (
            f"{row.label!r} is published against a budget of {row.budget_text} and this "
            f"module asserts {run.budget:g} {run.unit}; the budget is a constant in "
            "tests/test_benchmarks.py and the README publishes it, so they cannot differ"
        )

        low, high = row.published_headroom_range
        # Interval overlap, not point containment: both sides are rounded for print,
        # so `2 s / 1.142 s = 1.75055` and a published `1.75x` are the same claim.
        stated_low, stated_high = row.headroom_bounds
        assert stated_low < high and stated_high > low, (
            f"{row.label!r} publishes {row.headroom}x headroom, which its own numbers do "
            f"not support: {row.budget_text} against {[f'{s:g}' for s in row.samples]} "
            f"gives {low:.2f}x to {high:.2f}x. One cell of this row was edited alone"
        )
        for sample, cell in zip(row.samples, row.sample_bounds, strict=True):
            assert sample < row.budget_s, (
                f"{row.label!r} publishes {sample:g} s against a {row.budget_text} budget, "
                "so the table is quoting a measurement that fails its own assertion"
            )
            assert cell[0] > 0, f"{row.label!r} publishes a non-positive measurement"

        run_headroom = run.headroom
        drift = 1.0
        if run_headroom < low:
            drift = low / run_headroom
        elif run_headroom > high:
            drift = run_headroom / high
        if drift > README_HEADROOM_FACTOR:
            stale.append(
                f"{row.label}: published {low:.1f}x-{high:.1f}x, this run {run_headroom:.1f}x "
                f"({run.measured:.3f} {run.unit}) -- {drift:.1f}x outside"
            )

    assert not stale, (
        "the README's benchmark table is stale by more than "
        f"{README_HEADROOM_FACTOR:g}x on:\n  " + "\n  ".join(stale) + "\n\n"
        "This is a staleness bound, not a budget: every one of these still passed its "
        "own budget assertion. Re-run `pytest -m bench -q -s` and republish the table "
        "with the observation the page is missing. This run measured:\n  " + replacement
    )

    tightest_published = min(published.values(), key=lambda row: row.worst_headroom).label
    tightest_measured = min(rows, key=lambda row: row.headroom).name
    assert normalise_bench_label(tightest_published) == normalise_bench_label(
        tightest_measured
    ), (
        f"the README's table gives {tightest_published!r} the least headroom and this run "
        f"gives it to {tightest_measured!r}. Row *values* move with the machine; which row "
        "is tightest does not, so this is a real disagreement rather than a slow laptop"
    )


def check_tightest_benchmark_prose(rows: list[Measurement], text: str) -> None:
    """A sentence naming the tightest benchmark is a claim about the code, so check it.

    Section 1's prose says, in so many words, that one particular row "is now the
    tightest-scoring benchmark in the module". That sentence outlives its
    measurement the same way every other pasted figure on the page does -- and
    unlike the figures it reads as an architectural statement, so nobody re-checks
    it. It is checkable: the tightest row is whichever this run measured with the
    least headroom.

    Matched by scoring each measured row's label against the words of the claim,
    rather than by pattern-matching a sentence: the point of the whole
    stale-disclosure exercise in this repository is that the next wrong sentence
    uses different words. A row wins if more of its label's words appear in the
    claim than any other row's, and a claim that identifies no row at all is
    ignored -- which is the honest limit of this check and is why the assertion
    above, on the table itself, is the one that binds.
    """
    assert rows, "no benchmark recorded a row; run the whole module"

    # Tripwire on the instrument. Every escape hatch below -- no claim sentence, no
    # row identified, a tie -- exits green, which is right on a page that makes no
    # such claim and indistinguishable from a matcher that has stopped working. So
    # the matcher is put to a claim built from this run's own first row before it is
    # trusted on the README's.
    probe_row = rows[0]
    probe = f"The {probe_row.name} is the tightest benchmark in the module."
    assert _tightest_claim_sentences(probe) == [probe], (
        f"the tightest-claim sentence finder no longer recognises {probe!r}, so this "
        "check now passes on every README"
    )
    assert _row_named_by(rows, probe) == probe_row.name, (
        f"the row matcher can no longer identify {probe_row.name!r} from a sentence that "
        "names it in full, so this check now passes on every README"
    )

    claims = _tightest_claim_sentences(text)
    if not claims:
        return

    tightest = min(rows, key=lambda row: row.headroom).name
    for claim in claims:
        named = _row_named_by(rows, claim)
        if named is None:
            continue
        assert named == tightest, (
            f"section 1 says {named!r} is the tightest benchmark in the module; this run "
            f"measures {tightest!r} as the tightest. The sentence is: {claim[:240]!r}"
        )


def test_the_readme_benchmark_table_is_the_one_this_run_measured(report: Report) -> None:
    """Thin wrapper: :func:`check_readme_bench_table` against the live README.

    Split so the rig can be exercised on a synthetic table without editing the real
    ``README.md`` -- which other agents are writing to, and which is the document
    under audit rather than a fixture. A guard that can only be observed failing on
    the one document it is pointed at has never been shown to *pass* for the right
    reason.
    """
    check_readme_bench_table(report.rows, REPO_ROOT_README.read_text(encoding="utf-8"))


def test_the_prose_that_names_a_tightest_benchmark_names_the_one_that_is(
    report: Report,
) -> None:
    """Thin wrapper: :func:`check_tightest_benchmark_prose` against the live README."""
    check_tightest_benchmark_prose(report.rows, REPO_ROOT_README.read_text(encoding="utf-8"))
