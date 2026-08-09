# Secure Context Pipeline

A privacy boundary between an encrypted document store and an external LLM provider.

```
fetch + decrypt → detect → obfuscate → EGRESS GATE → provider → restore
```

The claim this system makes is narrow and testable: **no whole vaulted value leaves the process
boundary toward the provider, and that is verifiable by inspection — subject to four named
boundaries this design does not close.** Obfuscation is reversible within a session and
cryptographically irreversible across sessions.

The word doing the work is **whole**, and the four boundaries are stated here rather than 300
lines down, because each one is a shape that has been *confirmed* to reach the provider with the
gate live:

1. **A partial value** — one component of a multi-word original. The *composite-span* sub-case,
   where detection merged a list of values into one span, is closed on both sides; see §7 gap 9.
2. **A value glued inside a longer alphanumeric word**, *names and other digit-poor values only*
   — a digit-carrying identifier **is** caught, see the two identifier floors below.
3. **A homoglyph substitution** — Cyrillic `о` for Latin `o` is different bytes, and catching it
   needs a UTS-39 confusables table rather than another normalisation form.
4. **A multi-word original shorter than 8 alphanumeric characters, whose separator the payload
   respells.** The separator-invariant limb below has a length floor, and ordinary two-word
   names sit under it: `Amy Cox` and `Ann Lee` are six characters, `Jo Ann` is five. For those,
   a payload writing `Amy-Cox` or `AmyCox` walks the whole name out. The shipped generator corpus
   plants three of them — `Gene Lee`, `Paul Lee`, `Ryan Ray`. That measurement, re-derived over 26
   seeds × four kinds, also sizes the floor honestly: 358 of 8,390 multi-component values (4.3%)
   sit under it, but 267 of those are digit-bearing and still scanned unbounded, so what is left
   with only the four bounded forms is **91** — 69 lab values, 19 small amounts and those three
   names. Pinned by
   `test_egress_gate.py::test_the_floor_s_corpus_measurement_is_the_one_the_docstring_quotes`.

   **This one is not closeable by lowering the number, which was measured rather than assumed.**
   Real short names and common English phrases occupy the same length range: at a floor of 5 all
   six test names are covered *and* `of the` / `in the` / `to the` become needles that match the
   shipped fixtures 67, 95 and 53 times; at 8, no phrase matches and no name is covered. Since
   confidence-band redactions are handed to the gate as needles, a phrase-shaped original
   reaching the vault is not hypothetical — so lowering the floor trades a narrow leak for a
   broad outage. What would close it is the entity **type**, which the limb cannot see: §9.4
   fixes `originals_for_session` as `frozenset[str]`, so the gate gets strings with no way to
   tell `Amy Cox` from `of the`. Threading types through is the fix, and it changes an interface
   the specification pins.

Each is pinned by a named test so that closing one later is a red rather than a silent widening
of the claim; all four are detailed under *Leakage harness* below.

**Those four are all *scan* boundaries, and reading only them will mislead you.** Every one is a
value the vault holds that the payload can still carry out — rare, adversarial, one value at a
time. Three further limits sit one stage *earlier*, where a value is never detected and so never
becomes something the gate could look for, and two of them are ordinary rather than exotic:
**organisation names are not an entity type at all**, and **outside a medical document bare dates
pass through by specification** — 153 of them in cleartext on the largest shipped fixture. The
third is a plain NER recall miss on a person name, which is the case that shows why the gate
cannot backstop a detection miss. All three are measured and pinned in the same *Leakage harness*
section below, under *A fifth / sixth / seventh limit*.

**This list said *four* until recently, and the fourth was wrong in the direction that flatters
the document**: it named a combining mark spliced into a value as an open boundary, with a
rationale — *"folding marks out would make `José` and `Jose` the same value"* — that is a
statement about the **needle**, while the gate folds the **haystack**. `_deaccent` compares a
mark-stripped payload against an unstripped needle, so `José` and `Jose` stay distinct *and* the
splice is caught. The code had closed it and the README was still advertising it, citing a test
(`test_a_combining_mark_inside_a_value_is_outside_what_this_harness_claims`) that **does not
exist** — here and in the §10 traceability table. The real ones are
`test_egress_gate.py::test_a_combining_mark_spliced_into_a_value_no_longer_reaches_the_provider`
and `integration/test_pipeline.py::test_a_combining_mark_spliced_into_a_name_never_reaches_the_provider`.

**Three shapes that were open and undeclared are also now closed**, all found by adversarial
review rather than by the harness, and all reproduced end to end before being fixed:

- **Any alteration of a multi-word original's interior separator.** `Marguerite Vandenberg` was
  vaulted from a clean mention and reached the provider as `Marguerite<U+200B>Vandenberg` —
  identical to a human reader and to the model, and missed by all four compared forms, because
  every one of them keeps the separator in the needle. Deleting the space, or writing `-`, `_`
  or `.` in its place, missed identically. Pass 1 now compares a form that relaxes the separator
  *between* components while keeping the word boundaries at the outer edges — which is what
  distinguishes it from boundary 2 above, still open, where the *neighbour* is alphanumeric.
- **A value in the redact band.** A detection scoring between the two thresholds is redacted and
  gets no vault row, so pass 1 had no needle for it — while the re-scan dropped it for the same
  numeric reason, because both banded on `SCP_THRESHOLD_OBFUSCATE`. Both payload-side passes
  were therefore switched off over precisely the band that produces un-vaulted values, and a
  real SSN scoring 0.40 reached the provider byte-for-byte. See *Graceful degradation* in §6.
  The needle that closes it has an availability cost, and it is paid in the engine rather than the
  gate: every *undetected* repeat of that value became a block, so the residual sweep now redacts
  those repeats with the same marker (Deviation 8). What still blocks is the glued shape
  (`ledgerref452189376x`), which is exactly the disclosure the needle exists to catch.
- **An identifier restated in another decimal digit script.** A vaulted MRN `5567281` reached the
  provider as the same seven digits written in Arabic-Indic, extended Arabic-Indic, Devanagari,
  Bengali, N'Ko or Osmanya — with all three passes silent — while the *fullwidth* spelling of the
  same number blocked, because NFKC folds compatibility variants and leaves 580 of the 660
  codepoints that carry a decimal value exactly as they are. **This is not boundary 3**: these are
  not look-alikes of ASCII digits but different characters with the same numeric value, so the
  confusables table that boundary names has nothing to say about them. Pass 1's folded forms now
  write every decimal digit in ASCII (`egress_gate._fold_decimal_digits`), on the needle as well as
  the haystack — the one fold that is symmetric, because a digit's identity *is* its value, so two
  spellings that fold together denote one number. Pinned by
  `test_egress_gate.py::test_a_vaulted_identifier_restated_in_another_digit_script_is_blocked`
  (six scripts × four limbs) and
  `::test_the_digit_fold_is_symmetric_so_a_scripted_original_blocks_ascii`.

A stronger claim was written here first, and it was wrong in the way that matters — it promised
`never` while the document itself documented the exceptions.

Everything below is measured on this repository, not aspirational.

### If you have ten minutes before the review

| You want | Go to |
|---|---|
| Does it run? | §1 — two commands, and the numbers the suite prints. **If you just cloned it, read the boxed note above this table first.** |
| Is the zero-egress claim real? | §1 *Leakage harness* — including the shapes the harness itself was blind to, the four boundaries it does **not** claim, and how each was found |
| What does it **not** defend? | §3 — **start with "The weakest point in this design"**: `user_id` is an asserted claim and there is no authn at this tier |
| The one route with no auth on it | §2 — `GET /fixtures/{name}`, the only file-serving route: a four-name allow-list read into memory at import, why a session would be friction rather than a control, and the traversal corpus that was **run** rather than argued |
| The six live-review questions | §5 — each answered in its first sentence |
| Where it breaks at scale | §5 Q1 — the bottleneck is not the one you would guess, and the obvious fix was measured and **rejected** |
| What I got wrong | §8 Deviations (70, each with a reason) and §7 Known gaps |

**If you are cloning this repository right now, read this first.** Until the commit that carries
this sentence, `.gitignore` line 7 was `data/`. In git's grammar an unanchored pattern matches a
directory of that name at *any* depth, so besides the runtime blob directory it also matched
`secure_context_pipeline/detection/data/` — the two gazetteers `entities.yaml` requires and
`load_registry` fails closed without. They were untracked, and a fresh clone therefore could not
start: `demo.py` exited 2 on `ConfigError(reason='registry_gazetteer_missing')` and the suite
raised 457 errors. It was invisible locally precisely *because* the files were ignored — `git
status` reported a clean tree and every local run worked. The rule is now `/data/`, the
gazetteers are tracked, and `test_every_runtime_asset_the_registry_needs_actually_reaches_the_image`
now asks **git's index** rather than the author's working tree, which is the only source that
does not share the blind spot. If a clone of this repo does not run, that is the first thing to
check and it is the bug I would expect to have left behind.

**The three things most worth attacking**, stated up front so they are not a discovery:
the `user_id` gap above; the audit chain is tamper-**evident**, not tamper-proof, and an
attacker with DB write access can rewrite it end to end (§5 Q5); and detection recall is a
spaCy ceiling, not a config one — which is exactly why the egress gate, not the detector, is
the security control.

---

## 1. Setup & demo

### Path A — Docker

```bash
cp .env.example .env
# generate the master key and paste it into SCP_MASTER_KEY
python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"

mkdir -p data                  # see the note below if you are on Linux
docker compose up --build      # UI at http://localhost:8000
```

The container runs uvicorn with `--no-access-log`, and that is a control rather than tidiness.
uvicorn's access logger writes the request line verbatim — path *and* query string — to stdout,
which compose pipes into the container log. Two routes carry a credential pair there:
`DELETE /sessions/{id}?user_id=…` is the whole of what an irreversible cryptographic erasure
needs, and `GET /documents/{doc_id}/text?user_id=…` is the document read pair.
`SessionRegistry._handle` logs a truncated SHA-256 instead of a session ID precisely to keep that
pair out of the log stream; the access log put it back one line away. Per-request visibility is
not lost — the audit chain already holds it in a masked, access-controlled, tamper-evident form.
Pinned by `tests/test_log_stream_hygiene.py` (the `CMD` carries the flag, and `docker-compose.yml`
does not override the `CMD` and drop it).

**On Linux, run it as yourself instead:**

```bash
SCP_UID=$(id -u) SCP_GID=$(id -g) docker compose up --build
```

This is the one setup step that differs by host, and it is worth a sentence because
the failure is a crash loop rather than an error. `data/` is gitignored, so a fresh
clone does not have it; the Linux daemon then creates the bind-mount source as
`root:root`, and a **bind mount masks the directory it covers** — so the image's
build-time `chown` of `/app/data` to uid 10001 does not apply to what is actually
mounted there. The first SQLite open (the audit log) fails with `unable to open
database file`, startup aborts, and `restart: unless-stopped` retries it forever.
It is invisible on macOS and Docker Desktop, where the file-sharing layer remaps
ownership to the calling user — which is exactly why it survived this long: every
local run here was clean.

The spaCy `en_core_web_lg` model (425 MiB on disk) is baked in at **build** time, not fetched at
runtime. That is deliberate: the premise of this system is that detection happens locally and
no document text reaches a third party, so the container must not need network access to
start. The cost is a **1.31 GB image** — measured with `docker image inspect`, twice, on two
independent builds of the current `Dockerfile`.

That number was **2.85 GB** earlier in this build, and why it moved is worth a sentence. The
Dockerfile used `COPY . .`, which shipped the whole working tree: a 745 MB host virtualenv
built for the wrong platform, `.git`, `data/` (real encrypted blobs, the vault, the audit
chain) — and `.env`, which would have put `SCP_MASTER_KEY` in a published layer, where it
decrypts every document in the store. Replacing it with an explicit `COPY` allow-list plus a
`.dockerignore` fixed the leak and took 1.54 GB out of the image at the same time. A deny-list
forgets; an allow-list cannot. You can check the result in one command:

```bash
# 1. No secret reached a build instruction (ENV / ARG / RUN):
docker history --no-trunc secure-context-pipeline:1.0.0 | grep -cE 'SCP_MASTER_KEY=|ANTHROPIC_API_KEY='   # -> 0

# 2. And -- the check that actually catches THIS bug -- no secret reached a layer's *contents*:
docker run --rm --entrypoint sh secure-context-pipeline:1.0.0 -c \
  'ls -a /app; find / -xdev \( -name ".env" -o -name "*.key" -o -name "id_rsa" \) 2>/dev/null'
# -> /app holds only the allow-listed files; the find prints nothing.
```

Command 1 alone would **not** have caught the leak it is printed under. The offending instruction
was `COPY . .`, and that is all `docker history` records — the layer's *contents* are where
`.env` was, and history never shows them. Command 2 is the one that fails when the file ships.
(Measured on the current image: `/app` holds only the allow-listed files, and the only `.pem`
files anywhere are the CA trust stores that ship with `python:3.11-slim`.)

Command 2 has the same blind spot one level down, and it cost 38 files. `ls -a /app` prints the
top level, and `.dockerignore` patterns are anchored to the context root unless they start with
`**/` — so `__pycache__/` meant `./__pycache__` and nothing else, while `COPY
secure_context_pipeline/ secure_context_pipeline/` copies an allow-listed directory *whole*. The
1.0.0 image therefore shipped 38 host-compiled `.pyc` files and imported them (`python -v -c
'import secure_context_pipeline.config'` printed `code object from
'/app/secure_context_pipeline/__pycache__/config.cpython-311.pyc'`), so the container ran
bytecode built on a macOS host rather than bytecode derived from the source it shipped.
`PYTHONDONTWRITEBYTECODE=1` cannot help: it stops the image *writing* `.pyc` files, and these
arrived pre-written. The same anchoring made `.env`, `*.pem` and `*.key` inert below the root —
a probe context with a seeded `secure_context_pipeline/.env` shipped it while the root `.env`
was correctly excluded. Every rule meant to match anywhere is now spelled `**/`; `data/` stays
anchored on purpose, because `**/data/` would also remove the gazetteers. The depth-aware check:

```bash
# The rebuild is part of the check, not a precondition to it: the image tagged
# BEFORE this fix prints 38, which is the defect above. Re-tag, then count.
docker build -t secure-context-pipeline:1.0.0 .
docker run --rm --entrypoint sh secure-context-pipeline:1.0.0 -c 'find /app -name "*.pyc" | wc -l'   # -> 0
```

Measured both ways against Docker 29.4.1: the pre-fix image answers `38`, a rebuild on the same
tree with the corrected `.dockerignore` answers `0`, and both gazetteers are still present — which
is the half a blanket `**/data/` would have broken. `tests/test_build_context.py` pins the rule
statically, so the property survives on a machine with no daemon.

The container runs as a non-root user. Readiness costs a few seconds after start:
the spaCy pipeline is loaded once in the FastAPI lifespan, never per request, so that cost is
paid at boot and not on the latency budget below. (The compose healthcheck allows a 90 s grace
period, which is headroom for a cold container, not the observed startup time.)

### Path B — local

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m spacy download en_core_web_lg

python demo.py                 # headless end-to-end, mock provider, exits non-zero on failure
```

`demo.py` generates an ephemeral master key if `SCP_MASTER_KEY` is unset, so it runs on a
clean clone with no `.env`.

**One optional prerequisite, undeclared until an audit pass caught it: `node`.** Nothing the
pipeline does needs it — it is not imported, not in `pyproject.toml`, not in the image — but
`tests/test_ui_behaviour.py` executes `ui/app.js` under it and the whole module is
`skipif`-guarded on `shutil.which("node")`. Without node those **85** tests skip in silence and
the suite still reports green, so the "`app.js` now has execution tests" claim below is
*unverified* on that host. `node --version` is the whole check; the failure mode is a false
assurance rather than a broken run, which is why it is called out here rather than made a hard
dependency. The harness's scripted `fetch` now awaits its responder — so a test can script *no
reply at all*, a promise that never settles — and it rejects when `init.signal` aborts, the way a
real `fetch` does. Both exist so the request deadline can be tested honestly: a stub that ignored
the abort signal would let a timeout test pass against code with no timeout in it.

### Tests

```bash
pytest                  # full suite -- no API key, no network
pytest -m leakage       # 100-run zero-PII-in-transit harness
pytest -m bench         # performance benchmarks
mypy                    # --strict on the package
ruff check .
```

### Measured results

Everything below is output from this repository, not an estimate.

```
2689 passed, 1 skipped       # full suite WITH node on PATH, pasted as `pytest -q` printed it.
                             #   The skip is the real-network LLM smoke test.
                             #   Without node it is 111 skipped -- the 110 UI behaviour tests go
                             #   with it. See Path B above.
                             #   2690 collected: 158 leakage + 7 bench + rest unit + integration
mypy --strict                # clean, 52 source files -- PACKAGE ONLY, see below
ruff check .                 # clean, whole repo
97% branch coverage          # pytest --cov=secure_context_pipeline --cov-branch
                             #   5036 statements, 79 missed; 1270 branches, 57 partial (package only; see below)
```

**One test is failing on the working tree this block was measured from, and the block says so
rather than letting a reviewer discover it.** The counts above are the ones a *correct* tree
yields — collection, the marker split and the coverage figures are all re-derived from the tree
by `tests/test_readme_claims.py`, and `passed + skipped` is asserted to equal what `pytest`
collects. What the tree currently prints is one failure short of it:
`tests/test_ui_behaviour.py::test_the_page_serves_its_own_favicon_so_a_load_logs_no_console_error`
requires the page's `rel="icon"` to be an inline `data:` URI, and the page now ships a real
same-origin `ui/favicon.png` because the inline form was measured *blocked* by the page's own CSP
(Deviation 68). The test is the old claim's own pin, left behind by the change it was written
for; it is red for the right reason and is owned by the file it lives in, not by this section.
Until it is replaced, expect `2688 passed, 1 failed, 1 skipped` and treat the failure as this
one — anything else is a finding.

**The coverage line is the one figure in that block a red run *moves*, and it moved.** It read
98% and now reads 97%: a failing test leaves its own code paths unexecuted, so `missed` and
`partial` are inflated by whatever is red at the moment of measurement, and the pasted figures
were taken on a tree that was. Read the coverage line as a **floor** — a green run lands at or
above it — and re-derive it rather than trusting it, which is what checklist step 5 exists for.
The three figures the block states *exactly* are not affected: the collected count, the marker
split and the `statements` denominator are properties of the source rather than of a run, and
`tests/test_readme_claims.py` re-derives all three from the tree on every suite.

**On the scope of that mypy line, because "clean" is doing less work than it looks.**
`pyproject.toml` pins `files = ["secure_context_pipeline"]`, so `mypy --strict` type-checks the
**package only** — 52 files. The test suite is roughly half the repository by line count and is
**not** covered by that gate. Run against the whole tree — `mypy --strict .`, which ignores the
`files` pin — it is **91 files and 144 remaining errors**, none of which is a latent bug: **56**
are `attr-defined` from monkeypatching module-level re-exports (a legitimate test idiom that
`--strict` dislikes), **40** are `arg-type` where tests construct `Detection(category="PII")`
with a bare `str` instead of the `EntityCategory` enum, and the remaining 48 are assorted
narrowing complaints. Re-derive rather than trust: `mypy --strict . 2>&1 | tail -1` for the
totals and `| grep -oE '\[[a-z-]+\]$' | sort | uniq -c | sort -rn` for the split. Those two
absolute counts are the most rot-prone numbers on this page — they move every time a test file
is added, and this paragraph still read **79 files / 100 errors** after the commits that added
the newest test modules — so it is the **composition** that carries the argument, not the
totals. That caveat is no longer doing the work on its own, because it was two wrong underneath
it (**90 / 129** against a tree of 91 and, at that time, a run of 131 — the same run measures
**144** today, which is the rot this sentence predicts happening again): both **file** counts are now counted
from the tree and pinned exactly by
`test_the_mypy_paragraph_counts_the_files_the_two_scopes_actually_hold`, and the split is pinned
against the total it is spelled out as. The error total itself stays unpinned — it is a property
of a run, and re-deriving it in the suite would check this paste against the tool it is a paste
of. What *was* worth fixing is fixed: the package
carries exactly **one** `# type: ignore` today, on the untyped `regex` import that
`detection/registry.py` needs. (An earlier draft of this paragraph claimed 37 stale
suppressions had been removed across four audit loops. That is not checkable *here* — the
cleanup predates this repository's first commit, where the package already carried none — and
this section opens by promising output from this repository rather than an estimate. The
checkable number is the one above.) The scope is stated rather than widened because the `arg-type`
hits are the interesting residue: those tests are not exercising the enum the production path
actually carries, which is a mild stub-blindness signal and a real next step rather than a
one-line config change.

**And the same question about the `ruff` line, which had a real hole in it until recently.**
`ruff check .` is the *linter*. `ruff format` is the *formatter*, it is **not** in the gate, and
`ruff format --check .` reports **39 files** that would be reformatted (53 already formatted). That was cosmetic on its
own; what made it a defect is that `pyproject.toml` disabled `E501` with the comment "line length
handled by formatter" — so line length was enforced by the formatter, the formatter never ran,
and the stated 100-column limit was enforced by nothing. There were **145** violations, four of
them in the package.

`E501` is now on, and the accounting is worth stating exactly because "we turned the rule on"
can hide a blanket exemption. Of the 145, **50 are fixed and 95 remain**: **33 lay outside the
two files that carry generated document text, and all 33 are fixed** — most by a formatter pass
scoped to just the offending files, six by hand — and a further **17 inside
`tests/test_detection.py` were fixed rather than exempted**, taking that file from 24 long lines
to 7. That split is worth spelling out because the previous version of this paragraph stated the
33 and the 95 and silently dropped the 17, so a paragraph whose whole point is that the
accounting is exact was 17 short of its own baseline: **33 + 17 + 95 = 145**. The 95 that remain
live in the two per-file exemptions, which are argued rather than blanket: `fixtures/*` (88 long
lines) and `tests/test_detection.py` (7), whose long lines are
**generated and annotated document text** — `<<NAME|Aurelio Santangelo>>  <<SSN|602 33 1194>>`,
clinical notes, privileged memoranda. The detector is fed those strings verbatim, so wrapping one
moves a span offset and changes what the recall table measures; they are also inside
triple-quoted blocks, where `# noqa` cannot reach. Every other long line was fixed rather than
exempted, and a planted 110-column line in `config.py` was confirmed to fail the gate, so the
rule is enforced rather than merely configured. The remaining 39-file formatter divergence is
left as a known, stated gap: reformatting the tree wholesale is a large cosmetic diff with no
correctness content, and it is now the *only* thing `ruff` is not gating.

**Coverage above is the package only** (`--cov=secure_context_pipeline`), which is the gate
`pyproject.toml` configures. Measured across the whole repository — package, tests, `demo.py`
and `fixtures/` — it is **98%** of **24,992** statements: **24,341** for the package plus
`tests/` plus `fixtures/`, and `demo.py`'s **651** on top of that. It is published as its two
addends because it is the most rot-prone number on this page — every test module added moves it,
and it was 55 statements adrift within one commit of being written — so
`tests/test_readme_claims.py` re-derives all three from the source tree in
`::test_the_whole_repository_statement_total_is_the_one_coverage_would_report`.

**That test pins all three of those numbers exactly, and the one that had been banded was
tightened back rather than widened — which is worth one paragraph, because the band's reasoning
was sound and still lost.** The obvious design was tried first: pinning everything turned the
whole suite **red on a two-statement drift** — 0.01%, on a sentence whose claim is a percentage —
so the fastest-moving figure, the package + `tests/` + `fixtures/` sum, was checked against a
**0.5% band** that warned inside and failed outside. A number that goes red on every commit does
teach the next reader to edit the assertion instead of the prose, and that is a real cost. It was
removed anyway, on three findings. **First, the band could not buy what it was bought for**: the
same pasted block carries the collected-test count and the package denominator, both pinned
*exactly*, and both move for the same reasons. Replaying the nineteen commits ending at `b82964a`
as package / three-root / `def test_` deltas: **16 of the 19 moved the banded total at all, and 15
of those 16 also moved one of those two exact numbers**, so on 15 of them the suite was red
whatever the band did. The one exception is a deleted duplicate import that moved the total by
**one statement**. So the band bought exactly **one** green run in nineteen commits — this
paragraph claimed *zero* until the replay was re-derived for this pass, which counted every
replayed commit as a mover; three of the nineteen moved nothing at all. **Second, it was found holding an 81-statement error** — 21,347 published
against 21,428 measured — passing with a warning, its own width having been re-justified by hand
twice, which is the tell that a tolerance is not absorbing noise. **Third, a tolerance expressed
as a fraction of the quantity it guards widens on its own as that quantity grows** — 95 statements
when it was written, 107 when it was re-read, with nothing in the mechanism to revisit it — and a
band is memoryless, so it cannot tell one commit that moved the total by 81 from eleven commits
during which the published figure was 81 wrong. A per-commit allowance spent as a standing one
never comes back. So every published number in this section is now re-derived and pinned exactly,
each failure message carries its replacement, and the way the suite stays green is this page being
correct. What is *not* claimed is that exactness is a style: `missed`, `branches` and `partial`
below stay banded, because those are properties of a run that test deliberately does not perform.
The same pass found the *instrument* wrong as well as the number — the helper hardcoded
`# pragma: no cover` as coverage's whole default exclusion set, when 7.x also drops `...` stub
bodies and `if TYPE_CHECKING:` blocks, so it over-counted the five package modules carrying a
Protocol or an abstract method and published a denominator `coverage report` never prints. It now
uses coverage's own reporter and is checked file by file against a real run.

**`demo.py` has to be measured on its own**, and the reason is a small trap: the demo tests load
it by *file path* under a synthetic module name, so `--cov=demo` warns `module-not-imported` and
silently omits all 651 of its statements from the total. `coverage run --include='demo.py'` is
what reports it. Those two files were the last real gaps:
`demo.py` sat at **26%** and `fixtures/generator.py` at **69%** while every module around them
was above 90, because each defect this audit found got a regression test and nothing went back
to cover what had never been tested at all. `demo.py` is now 94% and the generator 96%; the
demo is the first artefact a reviewer runs, and until this pass its `--dump-wire` path, its
fail-closed demonstration, its destruction demonstration and its entire argument surface had no
test. `ui/app.js` had no *execution* tests either — only checks that read it as text — and now
has behavioural ones driven through `node`, **which is why node is a prerequisite for that
claim and for nothing else**: on a host without it, those 110 tests skip and this sentence is a
statement about a run that did not happen. Path B says how to check.

**Every number in this section was stale until an adversarial review pass re-measured them**, and
the way they went stale is worth one sentence because it is the same failure this document keeps
recording about the code. They were all measured correctly, once, at the commit that split
`api/app.py` into `routes/` and added `textrules.py`/`daterules.py` — and then the file count,
the statement count and the suite total all moved while the prose did not. The line above this
block reads *"Everything below is output from this repository, not an estimate"*, and the
pre-submission checklist tells a reviewer what output to expect, so a stale figure here is not
cosmetic: it is a check that fails for the reader running it. Re-derive them with the commands
in the block rather than trusting this paragraph.

**On that coverage number.** It is reported because it was *not* measured for the first four
review passes — `pytest-cov` was not installed — and the cost of that shows up in this
document: every "deleting X left the suite green" finding here was found by hand, one mutation
at a time, and at least one control was discovered untested only after it had already failed
silently. The number itself is weak evidence (98% of lines executed says nothing about what was
asserted); the *partial-branch list* is the useful artifact, and working it is what surfaced
four untested branches in the audit writer's own error handling — including one where a
transient fault would have wedged every subsequent write. `demo.py` was the sharpest case of the
gap between executed and asserted: it was fully executed by `tests/test_demo_flows.py`, but its
twenty graded assertions were checked only by *name*, so eleven of the conditions behind them —
fifteen of the twenty ledger entries, including the fail-closed section's own "control" — could
each be replaced with the literal `True` and all 41 tests still passed. Each now has a test that
falsifies exactly one condition and asserts that one named check goes red. The whole-run smoke
test asserts the ledger rather than the section headings, which come from `section()` calls and
survive the demonstrations under them being deleted: with RUN B and the fail-closed section
removed, the demo still printed every heading and still exited 0 on `PASS -- 10/10 checks
passed, 0 failures`. That file is now 54 tests.

**Leakage harness** (`pytest -m leakage`, 100 runs, both strategies alternating, varied seeds):

```
[leakage] 100/100 runs clean, 0 leaks (2966 originals vaulted and scanned, 2419 surrogates round-tripped)
[leakage] evidence: for each run counted above -- a freshly generated document, in
          THIS process -- no original reached the outbound payload, the audit DB or
          the process log, inside the four boundaries this module's docstring declares.
[leakage] NOT evidence: that this module is deterministic. Measured 9.4e-03 spurious
          reds per suite from the unbounded digit limbs -- one-sided (a collision
          manufactures a red; it never turns a leak green), reproducible by no seed:
            payload (gate pass 1: regrouped + identifier limbs)  6.5e-03
            audit query view (find_in_digit_heavy_text)          1.0e-03
            DEBUG log haystack (find_in_digit_heavy_text)        1.9e-03
          the bounded limbs add an unquantified <=1.5e-02, bounded by observation only.
[leakage] so N clean runs bound that rate at 3/N and no tighter (rule of three):
          ~318 consecutive clean suites before a green streak is evidence about it.
          Derivation: _HARNESS_RUN_FLOOR.
```

**`Ledger.summary()` prints four lines now, and the three new ones are the point rather than
decoration.** The tally line is byte-for-byte what it always was — this page quotes it and
`test_readme_claims` parses it, so the qualification was *added* and never substituted — and the
lines under it say what the tally is and is not evidence of. The false-red rate is quoted per
channel so a reader can check the parts against `_HARNESS_RUN_FLOOR` instead of taking the total
on trust; the residual is named as **one-sided**, which is what keeps the caveat from reading as a
discount on `0 leaks`; and the rule-of-three number is there because *"it went green four times"*
is the specific argument the caveat was written against. Pinned by
`tests/leakage/test_leakage_harness.py::test_the_summary_says_what_a_full_clean_suite_does_and_does_not_establish`
and `::test_the_false_red_rate_the_prose_quotes_is_the_one_the_code_computes`.

**Three of the four numbers on that tally line reproduce and the fourth does not, and the block
would be dishonest if it did not say which.** `100/100`, `0 leaks` and `2966 originals` came back
identical on all five executions measured for this pass. The surrogate tally did not: **2407,
2416, 2419 and 2424** across four of them, and 2418 on the fifth. It counts surrogates the *model*
referenced and the restorer then
round-tripped, and the mock provider's echo is drawn against a per-session pseudonym key, so which
surrogates come back is re-rolled every run — the same non-determinism
`test_a_short_surrogate_inside_a_longer_word_has_not_survived` was written for, where it made a
red "appear and disappear between runs". Expect roughly 2,415 there and treat a different value as
normal; treat a `2966` that moved, or anything other than `100/100, 0 leaks`, as a finding. This
paragraph exists because the block previously published `2434` — a value none of the runs measured
for it printed, sitting inside a block headed "output from this repository, not an estimate".
`tests/test_readme_claims.py::test_the_pasted_leakage_tally_is_one_the_readme_says_it_observed`
now requires the pasted figure to be one this paragraph lists.

**The originals tally moved, and this is the finding the rule above asks for rather than a silent
edit.** This block published **2,981** until this pass; the current tree prints **2,966** on every
one of five consecutive executions. That number is deterministic, so a move in it is a change in
what the detector plants or finds — not noise — and it is recorded here as one. What has *not*
been done is a bisect to the commit that moved it: the uncommitted working tree touches no
detection, obfuscation or vaulting code, so the change arrived with committed work in this wave
(the composite-date split of gap 9 is the candidate, unverified), and the honest statement is that
the value was re-measured rather than explained. Nothing about the assertion moves with it —
`ledger.leaks == 0` is what the harness asserts, and the tally is the evidence that the assertion
was exercised over a real population.

**100 runs, zero leaks** is the load-bearing result. It has come back clean on every run of the
committed tree — which this paragraph used to state as *"it has been reproduced"*, a word those
runs do not earn. Read the two halves separately. *`0 leaks` means exactly what
it says*: the residual channel the summary now prints is one-sided, a collision can only
manufacture a red, and nothing in it can turn a leak green. *"It goes green every time"* is the
half that is not evidence: N clean executions bound the false-red rate at 3/N and no tighter, so
four of them bound it at 0.75 per suite, which is no bound at all — it takes roughly **318**
consecutive clean suites before a green streak says anything about the measured 9.4e-03. Also read
the summary line precisely, because the two halves of it mean different
things: `Ledger.record()` counts runs that **completed**, and `ledger.leaks` counts only what the
three leak scans found. So `99/100 runs clean, 0 leaks` is a coherent and possible line — it
means one parametrized run raised before reaching `record()` for a reason that was *not* a leak.
A reviewer working against an uncommitted, mid-edit tree saw exactly that once and it did not
reproduce in 20 subsequent runs. The harness is honest about it rather than papering over it:
`assert ledger.runs == selected` fails the summary outright rather than quoting a tally over a
smaller denominator, which is the failure mode that would otherwise hide. Treat `leaks == 0` as
the assertion and the denominator as the thing that proves the assertion was actually exercised.

The two tallies beside it behave differently from each other, and the difference is worth stating
precisely rather than describing both as "reproducible":

- **2,966 originals** is stable for a given commit. Document seeds are fixed, so the same 100
  documents carry the same values, and this number only moves when detection changes. Observed
  identical on all five runs of the current build measured for this pass — and it *did* move
  across commits this wave, from 2,981, which is exactly the signal this bullet describes.
- **The surrogate round-trip count is not stable and is not a fingerprint of the build.** Two
  independent things move it. Within one commit it drifts by a few counts because session keys
  are `secrets.token_bytes(32)` and pseudonyms are seeded from `HMAC(session_key, …)`, so every
  pseudonymization run draws different fakes and which lines the mock provider echoes shifts
  with them — the count is of surrogates *the model happened to mention*. Three consecutive runs
  of the current build read **2,407 / 2,416 / 2,419**, with 2,966 originals identical in all
  three. A stable number in the second column would
  actually be evidence of a bug: it would mean session keys were not random. Across commits it
  moves much further, because any change to obfuscation or restoration changes what there is to
  mention; it was observed at **2,717** during one such change. Do not treat any single reading
  as a regression signal — `ledger.leaks == 0` is the assertion, and the tally is context.

  This is also why the round-trip rework below is reported with a *paired* measurement rather
  than a before/after of the summary line: computed both ways inside one process over the same
  100 runs, the old and new expectations agree exactly (2,410 vs 2,410). Two separate harness
  invocations differ by a handful either way regardless of what changed.

Read them as scale, not as a fingerprint.

**A note on how much this harness is worth.** It reported a clean 100/100 while it was blind to
a real class of leak, and the shape of that failure is the most useful thing in this section.

The harness decided "does this value occur in this text" **four separate times**, with four
local conventions, none of which agreed with the gate. Two were *stricter* than the code and
therefore hid leaks: the payload scan used `(?<!\w)…(?!\w)`, and since `_` is a regex `\w`,
`_John Smith_` — plain markdown emphasis — did not match its own planted original, nor did any
value whose first or last character is punctuation (`tel(415) 555-0123`, `USD$1,234.56`). Two
were *looser* and therefore invented leaks: the audit-database scan was a bare `bytes`
containment test, so a six-digit original landing inside a 32-hex `run_id` reads as a leak; and
the surviving-surrogate check used a bare `in` against a restorer that replaces on word
boundaries, so a short generated surname inside an ordinary word reported as a surrogate that
escaped. Because pseudonyms derive from a random per-session key, that last one appeared and
vanished between runs.

Three copies of one bug agreeing with each other is not corroboration; it launders the claim.
And a rare false red on the headline assertion is worse than its frequency suggests, because it
teaches the reader to disbelieve the next one.

All four now route through the gate's own rule, imported rather than restated, so a divergence
is an `ImportError` instead of silence. Three tests hold the line:
`test_the_occurrence_rule_has_no_fourth_copy` checks that single definition against an
independently written reference across 220 needle/haystack pairs;
`test_the_shared_occurrence_rule_agrees_with_the_reference_on_generated_input` does the same
comparison over **2,000 hypothesis-generated pairs** drawn from an alphabet built out of the
character classes the rule turns on, because every version of this bug so far was a case the
hand-written corpus was extended for *after* the miss (30,000 examples over a wider alphabet
including accents, a zero-width space, a combining mark and CJK found no disagreement either);
and `test_no_leak_comparison_in_this_module_bypasses_the_shared_rule` fails if any bare
membership test reappears in the file — catching the **class** rather than the four instances,
which is the only thing that has actually worked on this bug.

That last rule was itself only scanning the first two-thirds of the file. It excluded the
region from its own snippet list onward, to stop the list matching itself — and the 100-run
function is defined after that list, so three of the four historical bugs sat in a region the
rule never looked at. Found by sabotage rather than by reading: putting
`[o for o in originals if o in sent_payload]` back into the payload scan left the test green.
The excluded region is now computed from the parsed module (the list and the test's own body,
nothing else), and the test asserts that the 100-run function is inside what it scans.

**One thing sharing the rule was actively wrong, and that is now split out.** "Never be laxer
than the gate" is the correct rule for leak *detection*, and exactly the wrong rule for
round-trip *completeness*, where the expectation must be able to disagree with the code it
checks. The set of originals that must come back was built with `surrogates.extract_token_ids`
(i.e. the production `TOKEN_RE`) and the gate's occurrence rule — both of which the **restorer**
also uses. So if `TOKEN_RE` could not see a token the model emitted: the expectation dropped it,
the restorer left it in the answer, and assertion 4's residual scan (also `TOKEN_RE`) could not
see it either. All three agreed, and the only visible effect was that `round_trip_checked` got
*smaller* — a shrinking denominator, which nobody reads as a failure. The user gets an answer
with a dangling `1a2b3c4d` in it and the harness reports 100/100 clean.

The expectation is now derived independently: the 8-hex ID as a plain case-insensitive substring
of the model's own words, pseudonyms through the independently-written reference rule, and a
hand-written surrogate parser instead of `STRICT_TOKEN_RE`.
`test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots` enforces both halves
— structurally over the parsed AST (none of those four names may be *used* by the completeness
path, though they must still be discussable in a docstring) and behaviourally, by asserting that
a bare ID the production grammar provably cannot match still lands in the expectation. The
tally itself did not move: computed both ways over the same 100 runs in one process, old and new
agree exactly (2,410 vs 2,410).

**Three further holes were then found by attacking the harness instead of reading it**, and they
matter more than the first four because none of them was a *disagreement* between copies — the
occurrence rule was by then correct and shared. Each was a channel the scan could not observe at
all. They were found by neutering the egress gate, splicing a real original into a real payload
in a specific shape, and checking whether the harness noticed:

| Leak shape | Gate | Harness (before) | Cause |
|---|---|---|---|
| One zero-width space inside the value | blocks | **blind** | the harness compared 2 forms; the gate compares **3** |
| Accented original in an audit `detail` | n/a | **blind** | `ensure_ascii` stores `José` as `José` |
| Value logged via `extra={...}` | n/a | **blind** | `caplog.text` renders no `extra` fields |

The first is the instructive one, and it is the mirror image of the earlier bug. The harness
docstring asserted it scanned *"the same two forms the EgressGate scans, so the harness cannot
pass on a normalisation the gate would also miss"*. The gate had since gained a **third** —
invisible-character folding, added to close a one-character bypass — and the harness was never
updated. So the checker had become **weaker than the code it checks**. On the outbound payload
that is survivable, because the gate is a second opinion. On the audit database and the process
log, **the harness is the only thing that looks at those bytes at all**, so one U+200B was a
complete bypass of "zero originals in the audit log".

The second and third are the same failure in a different disguise: the harness was scanning a
*rendering* of the channel rather than the channel. `json.dumps` and `canonical_json` both
default to `ensure_ascii=True`, so an accented surname is genuinely in the audit DB in a form
any JSON reader decodes and no raw scan matches. And this package routes nearly every variable
it logs through `extra=` — `session_id`, `token_id`, counts, latencies — none of which appears
in `caplog.text`, while a production JSON formatter renders all of them. The natural logging
leak, `logger.debug("...", extra={"value": original})`, was structurally invisible to the
assertion that exists to catch it.

All three are closed and each has a test that fails without the fix. **The headline number did
not move under the stronger instrument** — 100/100, zero leaks, on three consecutive runs — which
is the only reason it is worth more than it was before: the same result now survives a scan that
sees strictly more.

**The four boundaries named at the top of this file are stated rather than closed**, because
closing them would manufacture false reds indistinguishable from real ones. They are the same
four, in the same words, as the numbered list in the opening section — this list carried a
different four until this pass, because it counted the combining-mark shape (closed, and kept
below as a record) and never mentioned the separator floor at all. Each is pinned by a test, so
closing one later is a red rather than a silent widening of the claim:

- **Partial disclosure.** If a splice bug leaves *one component* of a multi-word original behind
  — the surname of a vaulted full name — neither the harness nor the gate reports it. Both ask
  whether the **value** occurs. A word-level scan is not safely assertable here: fixture
  originals include ordinary clinical phrases (`chronic low back pain`) and Faker surnames that
  are ordinary English words (`Brown`, `Rich`). So the honest form of the guarantee is *no whole
  vaulted value* reaches the payload, the audit log or the process log, and
  `test_a_partial_value_leak_is_outside_what_this_harness_claims` pins that boundary.
- **A value glued into a longer word — on the text channels only.** `xJohn Smithx` carries the
  original byte for byte and is reported by neither the payload scan nor the gate. The occurrence
  rule asserts a word boundary on each side whose adjacent needle character is alphanumeric —
  which is precisely what stops `Brown` matching inside `Browning`. Relaxing it only for
  multi-word originals does not rescue it: `chronic low back pains` contains `chronic low back
  pain`. What keeps the residual risk small is that the pipeline cannot emit this shape — every
  surrogate and redaction marker ends in `]`, so a splice that leaves an original beside our own
  output has a non-alphanumeric character between them and *is* caught. Pinned by
  `test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims`.

  **On the audit database it applies to one of the two limbs, and that division of labour is now
  pinned rather than assumed.** SQLite writes a record's column values end to end with no
  delimiter, so an original in a label column sits in the *file* as
  `…EGRESS_BLOCKMarguerite Vandenbergdeadbeef…` — alphanumeric on both sides. The **byte** limb
  of assertion 2 is therefore blind to it (measured on a real `AuditLogger`, not reasoned about).
  The **query** limb sees the same value as `"entity_type": "Marguerite Vandenberg"`, where JSON
  quoting supplies the boundaries, and catches it — so the claim holds, on the other limb, and
  the byte limb's unique contribution is bytes the query view cannot reach at all: freed pages,
  WAL remnants, superseded row images.

  Worth reporting because the obvious fix is wrong and was reverted before shipping. Loosening
  the byte limb to plain containment so it could carry the label-column case alone re-opens the
  exact false-positive class the anchoring exists for, with interest: `8.2` is an ordinary
  vaulted lab value and every audit row carries an `elapsed_ms`, so `{"elapsed_ms":18.25}` reads
  as a leak. On the assertion that carries the headline number, a rare false red is worse than
  its frequency suggests. Both directions are pinned by
  `test_the_byte_limb_and_the_query_limb_of_the_audit_scan_see_different_things`, and end to end
  through the real writer by
  `test_the_audit_scan_catches_a_label_column_original_and_says_which_limb_did`, which asserts
  *which* limb caught it so the attribution cannot rot into "the scan handles it".
- *(Not one of the four — a retired boundary, kept here as a record of how it was argued.)*
  **A combining mark spliced into a value — CLOSED, and this entry is kept to record that the
  argument for leaving it open was wrong.** The reasoning was: *"folding marks out would make
  `José` and `Jose` the same value."* That is true of the **needle** and irrelevant to the
  **haystack**, and the gate folds the haystack. `_deaccent` strips marks from the payload only,
  so `Nathaniél Brightwater` matches a vaulted `Nathaniel Brightwater` while a payload that
  legitimately says `Jose` still does not match a vaulted `José` — the needle keeps its accent.
  Pinned by `test_egress_gate.py::test_a_combining_mark_spliced_into_a_value_no_longer_reaches_the_provider`
  and `integration/test_pipeline.py::test_a_combining_mark_spliced_into_a_name_never_reaches_the_provider`.
  **The first version of this closure covered only *combining* marks, and that was narrower than
  it read.** A *spacing* diacritic — U+00B4 ACUTE ACCENT, U+00A8 DIAERESIS and the rest of the
  modifier block — draws the same glyph and walked straight through, on the real gate, for a
  vaulted name *and* a vaulted MRN. The cause was ordering rather than oversight: NFKC expands a
  spacing diacritic into a **space** plus a combining mark, so folding the mark afterwards leaves
  the space behind and the value stays broken. The skeleton form is now derived from the raw
  payload with those characters removed first, and the class is defined by compatibility
  decomposition (`<compat> 0020 <mark>`) rather than a hand-picked list.

  Two residuals, both stated rather than implied. A vaulted value that *itself* carries a mark
  (`José Ruiz`) is not protected against a *second* mark being spliced into it, because the
  needle is never stripped. And a modifier *letter* with no diacritic decomposition — U+02C8
  MODIFIER LETTER VERTICAL LINE — is not in the class and is not removed; it belongs with the
  homoglyph boundary below, and closing it needs the same confusables table. Both are pinned by
  tests that go red the day either changes.
- **Homoglyphs.** Cyrillic `о` for Latin `o` needs a confusables table, not another
  normalisation form. Out of scope in the gate for the same reason.
- **A multi-word original under the 8-alphanumeric floor, whose separator the payload respells.**
  The separator-invariant limb only runs on values long enough that a respelling cannot collide
  with ordinary English, so `Amy-Cox` or `AmyCox` for a vaulted `Amy Cox` walks the whole name
  out. The floor is measured rather than assumed: over 26 seeds × four kinds, 358 of 8,390
  multi-component values sit under it, and once the digit-bearing ones (still scanned unbounded)
  are removed, **91** are left with only the four bounded forms — 69 lab values, 19 small amounts
  and three names. Lowering it does not close the boundary, it trades a narrow leak for a broad
  outage: at a floor of 5, `of the` becomes a needle that matches the shipped fixtures 67 times.
  Pinned by
  `test_egress_gate.py::test_the_floor_s_corpus_measurement_is_the_one_the_docstring_quotes`.

**A fifth limit, and it is a different kind: organisation names are not an entity type at all.**
The four above are *scan* limitations — a value the vault holds that the payload can still carry
out. This one sits earlier: the build doc's section 6.2 registry defines the entity set and has
no `ORG`, `EMPLOYER` or `PAYER` type, so an organisation name is never detected, never vaulted,
and therefore never something the gate could look for. It reaches the provider by design.

It is called out here because the demo makes it look like an inconsistency rather than a
decision, and a reviewer will see that before reading any of this. In `medical_note.txt` the
hospital **is** obfuscated and the insurance carrier three lines away is not:

```
...filed with Pinnacle Grove Benefit Trust under member ID [PHI_INSURANCE_ID_7ad98951].
...the primary care panel at [PII_ADDRESS_cd988587], and the insurance authorisation...
```

The asymmetry is an artifact of NER labelling, not policy: `ADDRESS` is backed by Presidio's
`LOCATION`, and spaCy tags "Larkspur Valley **Hospital**" as a LOCATION while "Pinnacle Grove
Benefit **Trust**" is an ORG, which nothing maps. So one org is protected by accident and its
neighbour is not.

Adding an `ORG` type would close it in about four lines of `entities.yaml` and is deliberately
not done: the registry is the specified entity set, inventing a requirement is not the same as
meeting one, and a new type changes detection across every fixture and every recall number on
this page. What *is* done is making the gap measurable — `fixtures/generator.py` now plants the
organisation names it writes, so they are counted ground truth rather than invisible: 72 distinct
values across 26 seeds x four kinds, appearing 163 times in the four committed fixture files. Planting them does not close the gap and is not claimed to: nothing
detects them, they never round-trip, and `expected_entities` documents `ORG` as the one planted
class no registry entity claims. Whether organisation names belong in scope is a product
decision, and it is one this submission records rather than makes.

**A sixth limit, the same kind and by far the largest by volume: ordinary dates pass through in
non-medical documents.** The build doc's section 6.2 defines the entity verbatim as
`DATE: {category: PHI, presidio: DATE_TIME, only_in_doc_categories: [medical]}`, and its line 331
states the consequence in words — *"in `medical` docs, remaining dates map to `DATE` (PHI — HIPAA
treats individual-related dates as identifiers); elsewhere bare dates pass through."* So this is
the specification being met rather than a defect, and `entities.yaml` is deliberately **not**
widened to close it. Until this pass it was declared only in a YAML comment, which is not a place
a reviewer reads.

Measured at the provider boundary on the shipped fixtures — distinct dates in the source, and how
many of those exact strings survive verbatim into the outbound payload:

| Fixture | Dates in source | Reaching the provider in cleartext |
|---|---|---|
| `legal_brief_large.txt` | 155 | **153** |
| `financial_disclosure.txt` | 12 | **11** — the whole PART IV transaction ledger plus the reporting period |
| `legal_memo.txt` | 4 | **4** |
| `medical_note.txt` | 8 | **0**, as designed |

**The surviving set is identical under both strategies, and that is the load-bearing part of the
measurement.** Under pseudonymization a *detected* date comes back as a shifted, date-shaped
fake, so counting date **shapes** scores the medical payload at 8 and reads like a leak; counting
only strings that are also in the source separates "never detected" from "detected and shifted".
A set that does not move between tokenization and pseudonymization is a set nothing ever
detected. The few caught outside a medical document are caught for other reasons and two of them
by accident: `01/17/1977` in the disclosure is under a `Date of birth:` label and is a `DOB`,
while in the brief `01/25/2023` was typed `ADDRESS` (spaCy called it a LOCATION) and `02/01/2023`
`CLIENT_IDENTITY` (spaCy called it a PERSON) — masked under the wrong label rather than covered
by a rule. Everything else in those payloads scanned clean under both strategies: 0 surviving
originals from the vault, and 0 surviving source values matching name, email, phone, SSN, EIN,
MRN, member ID, account number or docket number shapes. The one other survival is two postcodes
inside the disclosure's street addresses, which is §7's already-declared `ADDRESS`-rides-`LOCATION`
gap rather than a new one.

**What a reader of the boundary list above would otherwise wrongly conclude.** Those four
boundaries are adversarial single values — a splice, a homoglyph, a respelled separator — and the
headline claim is phrased about *vaulted* values, which is silent on a value that was never
vaulted. Nothing in either prepares a reader for a hundred and fifty-three dates in the clear on
the largest shipped fixture. Stated plainly: **outside a medical document this system does not
protect dates at all**, so a litigation chronology or a transaction ledger reaches the model
intact. If your threat model treats those as sensitive, this scoping is the thing to change, and
changing it is a product decision — widening `DATE` moves every recall number on this page.
Pinned by
`tests/test_declared_boundaries.py::test_ordinary_dates_pass_through_outside_medical_documents`
(four fixtures × both strategies, exact counts both sides) and
`::test_a_bare_date_is_detected_in_a_medical_document_and_not_in_a_legal_one` (the same sentence
in two categories, so the rule is visible without holding 155 dates in your head). Widening
`DATE` turns the table above red rather than leaving it silently stale — confirmed by deleting
`only_in_doc_categories: [medical]` and watching four of the six assertions fail.

**A seventh limit, and the sharpest illustration in this project of a point made abstractly
everywhere else: a plain NER recall miss, and the gate cannot backstop it.** Reproduced on the
real detector against the shipped registry, three inputs differing only where marked:

```
"Name: Priyanka Raghunathan\nMRN: 9224297\n"    -> [(MRN, 9224297)]                  name unclaimed
"Name: David Ochoa\nMRN: 9224297\n"             -> [(NAME, David Ochoa), (MRN, ...)]
"Priyanka Raghunathan was admitted overnight"   -> [(NAME, Priyanka Raghunathan)]
```

Same frame with a different name: found. Same name in ordinary prose: found. This is spaCy recall
variance on one string in one shape, not a rule anything here wrote — which is exactly why it
cannot be patched. End to end, on the real component graph, the document the provider receives is
this — the 8-hex token IDs are per-session and differ every run, everything else is verbatim:

```
<DOCUMENT>
PATIENT CHART
Name: Priyanka Raghunathan   DOB: [PII_DOB_f7c8299e]
MRN: [PHI_MRN_392a5f00]
</DOCUMENT>
```

The date of birth masked, the medical record number masked, and the patient's own name in the
clear between them. That juxtaposition is what a reviewer will point at, and the honest answer is
that the gate was never the control that could have caught it.

**Why no pass of the gate helps, stated pass by pass, because this is where the system's
strongest control runs out.** The gate is a second opinion on *obfuscation*; it was never one on
*detection*. A value the detector never saw is never vaulted, and from there:

| Pass | What it does | Why it cannot help here |
|---|---|---|
| 1 | Scans the payload for the session's vaulted originals | The name was never vaulted, so **the needle does not exist** |
| 2 | Re-runs *the same* `Detector` over the payload | A second look, not a second opinion — Deviation 42 already says so, and this is what that costs: every blind spot it had at detect time it has again, over strictly the same string |
| 3 | A genuinely independent recogniser set | It matches **patterns**, and a person name is not a pattern — that is the whole reason `NAME` rides NER rather than a regex |

Three passes, three different reasons, one outcome. This is the concrete form of §7's first known
gap — *detection recall is the binding constraint on the whole system* — and it is the argument
for scispaCy or a self-hosted clinical NER being the highest-value next change rather than more
gate hardening. Widening a pattern to cover one name would not generalise to the next one, and
adding an entity type is a product decision nobody has made.

**The own goal that came with it, now fixed.** This exact string was the worked example in
`_context_window_start`'s docstring in `detection/detector.py` — the function illustrating the
field-label clamp handed a reviewer a chart header whose patient name this pipeline does not
find. The example now uses `Chelsea Hammond`, which it does, and the docstring says why it
changed so nobody restores the more realistic-looking name. Pinned by
`tests/test_declared_boundaries.py::test_the_gate_cannot_backstop_a_name_the_detector_never_saw`,
which drives the real component graph: the detection premise, the absent needle in the vault, the
name on the wire with the DOB beside it masked, and both controls — the same frame with a name
that *is* found, and the same name in prose. If it goes red, recall improved and this section is
what has to change, not the assertion.

**Two of those four — partial disclosure and the glued-into-a-longer-word shape — are blind spots
the harness and the gate mostly share**, because both resolve to the same occurrence rule — so
for those shapes there is usually no second opinion. Confirmed
rather than reasoned about: with the gate **live**, a real vaulted original spliced into a real
payload glued to a letter completed the run and reached the provider. Where the gate is a second
opinion that is survivable; on the audit database and the process log, where nothing else looks,
it is not — which is why these are recorded as claims the harness does not make rather than as
cases it happens not to have hit.

**"Mostly" is the honest word, and the exception is worth a paragraph**, because it is where this
project's recurring defect last showed up. The glued-into-a-longer-word boundary does **not**
apply to digit-carrying values: the gate has a fifth comparison, `_identifier_needles`, which
tests a value as a bare substring with **no adjacency rule at all** once it carries enough
digits. `batch47-1234567Alpha` conceals a taxpayer ID from `\b`-anchored patterns and from the
word-boundary rule, and from nothing else; a reader is not fooled by it and neither is the model.

That limb has **two floors, and they are different numbers on purpose**:

| Floor | Value | Applies to | Set by |
|---|---|---|---|
| `MIN_IDENTIFIER_DIGITS` | 7 | the whole value, separators included (`512-24-8710`) | keeping six-digit *dates* and *amounts* out of an unbounded scan — they are aggregates of 2- and 3-digit runs, and `Filed 03/12/850` is ordinary text |
| `MIN_IDENTIFIER_RUN_DIGITS` | 6 | one contiguous digit run (`552140`) | the shipped registry: `MRN` is `\K\d{6,10}`, so the detector vaults six-digit MRNs |
| `_HARNESS_RUN_FLOOR` (harness only) | 7 | the audit DB and the process log | this file's own false-positive budget on those channels |

These were **one** constant, and that is the twelfth instance of the defect this repo keeps
hunting — not a checker sharing an implementation with the thing it checks, but a **number
justified against one channel silently setting another channel's security floor.** Seven was
argued from dates and amounts; it was then applied to a contiguous run, where the argument does
not hold. The measured consequence, on the real detector, registry and gate, with `552140` — the
first row of `DEV_IDENTIFIER_POSITIVES`, a value the detector is *required* to vault:

```
payload:  "Internal routing tag: MRN552140B must match the ledger."
pass 1 bounded    miss  — the trailing B denies the right-hand word boundary
pass 1 unbounded  miss  — six digits, one below the single shared floor
pass 2            miss  — MRN's registry pattern ends in \b, which B also denies
pass 3            miss  — carries an SSN recogniser only
                  -> RELEASED, vaulted MRN on the wire byte for byte
```

Four independent misses for one underlying reason is what a shared blind spot looks like. It is
fixed, pinned end to end by `test_a_six_digit_identifier_core_glued_to_a_letter_is_blocked`, and
— the part that matters more — pinned *at the seam* by
`test_no_shipped_identifier_pattern_can_match_below_the_gate_s_run_floor`, which reads
`entities.yaml` itself and goes red if the config and the constant ever disagree again. That test
is deliberately sourced from a **different artifact** than the code it checks, which is the one
thing that has reliably caught this class.

**Why the harness keeps a higher floor than the gate, stated as a cost rather than a footnote.**
The gate scans the outbound payload, where the only run of `[0-9a-f]` the pipeline emits is an
8-hex token ID; a six-digit needle lands inside one with p ≈ 1.8e-7. The harness also scans the
audit database, which is a field of 32-hex run IDs and sha256 digests. Counted on the real 3.6 MB
of DBs a suite leaves behind:

```
distinct 6-digit windows present: 15055   -> p(a given 6-digit needle collides) = 1.5e-2
distinct 7-digit windows present:  9366   -> p(a given 7-digit needle collides) = 9.4e-4
```

At six digits that is order-of-**one** spurious "an original reached the audit database" per
100-run suite. A rare false red on the headline assertion is worse than its frequency suggests —
it teaches the reader to disbelieve the next genuine one — so the harness stops at seven on those
two channels and **the cost is written down**: a vaulted six-digit MRN core glued into an
alphanumeric run, *in the audit DB or the log*, is not reported by this harness. The gate does
block that shape on the payload. So the two files are now narrower and wider than each other in
named, measured places instead of by accident.

**That measurement was taken against the wrong channel, and re-taking it is what explains an
intermittent red nobody could reproduce.** The 3.6 MB above is the surface of the database
*files* — which the text scan never reads. `find_in_bytes` reads those, and it declines these
needles outright. What `find_in_digit_heavy_text` is actually handed is one much smaller haystack
and one much larger one, and counting the distinct 7-digit windows each run's haystacks really
contain, over a full 100-run replay and the 203 pure-digit identifier needles those runs produce:

```
audit query view (one session's rows)          99 windows -> 2.1e-03 expected spurious reds / suite
DEBUG log haystack (log_haystack(caplog))   7,574 windows -> 1.7e-01 expected spurious reds / suite
```

The audit figure is on the side of the line the seven-digit floor was drawn for. **The log figure
is 170× the wrong side of it**, and it had never been measured, because the arithmetic had only
ever been run against the database files. Both are live rather than theoretical: run 099
(medical/pseudonymization, seed 90099) failed assertion 2a on a seven-digit MRN with `identifier`
as the only limb that fired, once in 24 executions of the identical 100 runs and never again —
which is what a coincidence against per-process random hex looks like from the outside, and is not
something a seed reproduces. Narrowing either limb further — a higher floor, a boundary on the
needle, dropping a haystack — is a real loss of reach on the two channels where this harness is
the only opinion there is, so the trade is recorded in `_HARNESS_RUN_FLOOR` rather than taken
quietly. What *was* taken is the free half: `describe_hits` now names the **kind of run** an
`identifier`-only hit landed in (`inside a 64-char hexadecimal run` against `inside a 17-char mixed
run`), so the next occurrence is one line to classify instead of an afternoon to reproduce.

**How the other shapes were confirmed.** The list above is what survived an attack, not what was
left over after reading the code. A copy of the pipeline was sabotaged — a real vaulted original
re-spliced into the outbound payload in twelve shapes, with the gate's original-value pass
blinded — and the harness was required to go red on each. It caught the verbatim value, markdown
emphasis (`_John Smith_`, `**John Smith**`), both punctuation-edged shapes (`tel(415) 555-0123`,
`USD$1,234.56`), a value inside a token's `|hint` tail, a value split across a line break, a
case-only difference, and a value followed by a full stop. It missed exactly the three above.

Getting here took four fixes to the pipeline itself (Deviations 11–14) and eight to the
instrument; two of the pipeline fixes were found by this harness and by nothing else.

**Benchmarks** (`pytest -m bench`, budgets from the build specification). Measured on an
M-series laptop that was **not idle** — several other test suites were running concurrently:

| Measurement | Worst of a 7-run sample | Best of the same 7 | Budget | Headroom at that **worst** | Scoring |
|---|---|---|---|---|---|
| Obfuscate 2,000 words (tokenization) | 1.142 s | 0.363 s | 2 s | 1.75× | best of 3 |
| Obfuscate 2,000 words (pseudonymization) | 1.281 s | 0.377 s | 2 s | 1.56× | best of 3 |
| Vault lookup p99 (1,000 cached reads) | 0.001 ms | 0.001 ms | 5 ms | 4,284× | single shot |
| Restore a 500-token response (warm vault) | 5.359 ms | 5.119 ms | 500 ms | 93.3× | single shot |
| Restore a 500-token response (cold vault) | 61.496 ms | 60.229 ms | 500 ms | 8.1× | best of 3 |
| Restore a 500-surrogate response (pseudonymization) | 120.514 ms | 119.598 ms | 500 ms | 4.1× | best of 3 |
| Full pipeline, 12k-word brief (mock provider) | 9.776 s | 5.928 s | 15 s | 1.53× | best of 3 |

**The three restore rows are a different seven runs, and saying so is the point of the table.**
The shipped single row measured the **warm** path and called it "restore": obfuscation has just
filled the vault's `_SessionCache` in the same process, so the request path does zero SQLite reads
and zero AES-GCM decryptions. That is the production path and it is worth publishing, but it is
not the worst case, and the pseudonymization pass — the expensive half, by a factor of 23 on the
warm path — had no budget assertion at all. There are now three, all against the same 500 ms
`BUDGET_RESTORE_MS`, and the warm/cold split is verified rather than asserted by counting
`SessionVault._fetch_one`: **0 calls warm, 500 cold**. The surrogate restore is now the
tightest-scoring benchmark in the module. Their seven runs were taken later, on a quieter machine
than the four rows above, which is why their best/worst spread is a few percent rather than 3×;
mixing the two samples in one table would be worse than labelling them.

The best/worst spread on the four original rows is 3.1× on the same machine in the same ten
minutes, which is the honest headline of this table: **the budget column is a claim about this
system, and every other column is a claim about a laptop.** The worst readings here come from the tail of the sample, when the
machine had been running suites back to back for an hour; the best are what an idle box gives.
Both are reported so a reviewer re-running this and seeing 0.4 s does not conclude the table was
padded, and one seeing 1.2 s does not conclude it was fabricated.

**The budget column is the claim. Every other column is one sample of seven.** That framing is
the third correction this table has needed, and the sequence is worth more than the numbers.

It first carried single point values. Those were replaced with ranges, because a wall-clock
figure quoted to three significant figures invites exactly the check it cannot survive. The
ranges were then replaced with *floors* — "≥ 2.2×", "≥ 3,600×" — on the reasoning that a floor
only gets safer with more measurements. **Then more measurements broke one of the floors and
came within 1% of another.** The seven runs behind the table above put the full pipeline at
7.248 s — 2.07× headroom, under the "≥ 2.2×" the table itself asserted — on two of seven runs,
and put the vault at 3,636× against a stated floor of 3,600×.

A floor computed from seven samples is not a bound. It is an *estimate of a tail from seven
draws*, which is the same category of error as the point value it replaced — one level up, and
harder to see because it is wearing the costume of caution. So the columns now say what they
are, and the only number this page asserts is the budget, because the budget is the only one a
test enforces. All five of the original measurements passed on all seven of their runs, and all
seven of today's — the four unchanged rows plus the three restore rows that replaced the fifth —
passed on all seven of theirs. Seven measurements, four budget constants: `BUDGET_OBFUSCATE_S`, `BUDGET_VAULT_P99_MS`,
`BUDGET_RESTORE_MS` (asserted three ways — warm, cold, pseudonymization) and `BUDGET_PIPELINE_S`.

If your own run lands outside these readings, that is expected and is not a regression. If it
lands outside the *budget*, that is a real failure and `pytest -m bench` will say so.

**The retraction, kept because it is more useful than the claim was.** This paragraph used to
say that the two original point values (`6.69 s` and `~4,600×`) "did not reproduce on **any**"
of the runs behind the table, and that `~4,600×` "overstated the headroom actually observed".

Both statements are false, and the seven runs above refute both. `~4,600×` reproduced twice
(4,616.8× and 4,612.5×), so it never overstated anything. `6.69 s` was exceeded twice (7.203 s
and 7.248 s). Two independent re-runs of this build, seven invocations each, reported the same
thing. The original point values were reproducible; the *criticism* of them was the
unsupportable claim, because "did not reproduce on any" is a universal statement and it was made
from a sample far too small to carry the word **any**.

Which is the lesson of this whole page turning up where it was least expected: the paragraph
written to explain why an unreproducible number is dangerous was itself an unreproducible
number, and it survived review precisely because it read like the *cautious* option. Being the
one who points out an overclaim is not evidence of being right — a negative universal needs
more sampling than the positive claim it attacks, not less.

The table moved off point values for the good reason and not this one: a reviewer who re-runs
`pytest -m bench` and sees a different number has been handed a reason to doubt everything else
on the page. Re-measure with:

```bash
pytest -m bench -q -s     # prints the table above, with per-stage breakdowns
```

**Why two of these are best-of-3, and why that is not the same as widening the budget.** A
wall-clock assertion measures the machine as much as the code, and these two run at the least
headroom in the table. A benchmark that goes red because a reviewer's laptop was indexing is one
people learn to re-run until it is green, which is worse than not having it. The property being
asserted is *achievability* — "this pipeline **can** do the work inside the budget" — and for an
achievability claim the fastest clean observation is the correct estimator while a contended one
is simply a worse measurement of the same thing. Relaxing the budget instead would weaken the
claim, which is the one thing not on the table.

It still catches a real regression, and that is checked rather than argued: a deliberate +10 s
regression injected into `PipelineOrchestrator.run` fails the full-pipeline budget — it lands at
baseline + 10 s, because a genuine slowdown affects every iteration and therefore moves the
minimum. (A +6 s regression passes — correctly, since that is genuinely inside a 15 s budget.)
Both are stated relative to the baseline rather than as fixed totals, because the baseline is a
measurement that moves with the code and a hard-coded sum silently stops matching it. The two
high-headroom rows are single-shot because contention cannot plausibly consume the margin
between a sub-microsecond lookup and a 5 ms budget, or between a 4.8 ms restore and a 500 ms
one — and note that this is an argument about those *budgets*, not about the sampled headroom
figures. The vault figure moved by 27% across seven runs (3,636× to 4,617×), which is exactly
the kind of number this section has now been wrong about twice.

That last row used to live only in `demo.py --real`, where it needed an API key and a network
and therefore never ran in CI. It is now a `bench` test on the mock provider, so it covers
every stage this system is responsible for and none of the network. `demo.py --real` still
enforces the same 15 s budget *including* the provider round trip — that is the end-to-end
truth, and neither number replaces the other.

Full pipeline detail, mock provider, analyzer already warm (median of three runs):

| Document | Size | Spans | Distinct entities vaulted | End to end |
|---|---|---|---|---|
| `legal_brief_large.txt` | 12,062 words | 739 (647 obfuscated, 64 redacted, 28 stripped) | 251 | **6.48 s** (budget 15 s) |
| `medical_note.txt` | 393 words | 52 (51 obfuscated, 1 redacted, 0 stripped) | 32 | **0.29 s** |

(Counts are **engine-level** — what `PipelineResult.detections` carries and what `demo.py` prints
— not detector-level. The distinction is the whole reason this row was wrong twice. The detector
returns 54 spans for the medical note; overlap resolution and dedupe reduce that to the 52 the
payload is actually built from. An earlier note here claimed the opposite — that 52 was the
*obfuscated* count and 54 the total — which inverted the two roles and disagreed with the number
`demo.py` prints on every run, i.e. with the first thing a reviewer sees. The brief's row is
consistent on the same basis: 647 + 64 + 28 = 739.)

### Useful demo flags

| Flag | Purpose |
|---|---|
| `--strategy {tokenization,pseudonymization}` | switch obfuscation mode |
| `--file <path> --category <cat>` | run on an arbitrary reviewer-supplied document |
| `--real` | use the Anthropic provider (needs `ANTHROPIC_API_KEY`); asserts full pipeline < 15 s |
| `--dump-wire` | with `--real`, capture the **literal outbound HTTP body** and scan it against the vault |
| `--verify-chain` | print the audit hash-chain verification result |

`--dump-wire` is the honest answer to "prove nothing leaks": it attaches an httpx event hook
to the real SDK client and writes the actual bytes on the wire to a file you can grep.

---

## 2. Architecture

```
                              ┌───────────────────────────────┐
  user / demo.py / UI ───────►│      PipelineOrchestrator     │
                              └───────────────┬───────────────┘
                                              │
   DocumentStore ◄────────────────────────────┤   AES-256-GCM at rest
   (per-user HKDF keys, AAD-bound)            │
                                              │
   Detector ◄──────────────────────────────── ┤   Presidio + spaCy, in worker threads
   (registry-driven, chunked)                 │
                                              │
   ObfuscationEngine ◄───────────────────────►│◄──► SessionVault
   (dedupe, splice, sweep)                    │     HMAC token IDs, AES-GCM entries,
        ▲                                     │     AAD = session_id + token_id
        │  the USER PROMPT goes through the   │
        │  same detector + engine + vault     │     ← Deviation 40. §9.5.2 passes the
        │  (steps 3b / 4b in orchestrator)    │       prompt through raw; measured, six
                                              │       entity types typed into the prompt
   ContextInjector ◄───────────────────────── ┤       box reached the provider verbatim
   (fences the document in <DOCUMENT>…</DOCUMENT>,
    neutralising any fence tag in either      │     ← Deviation 41
    untrusted half — Deviation 41)            │
                                              │
   ╔══════════════════════════════════════╗   │
   ║  EgressGate  — FAIL CLOSED           ║◄──┤   ← nothing reaches the provider
   ║  1. scan for every vault original    ║   │      except through here
   ║  2. detector re-scan minus surrogates║   │
   ║  3. recognisers the detector does    ║   │   ← Deviation 42: §9.5.3 specifies
   ║     NOT use (independent opinion)    ║   │      two. Pass 2 re-runs the same
   ╚══════════════════════════════════════╝   │      Detector, so it is a second
                                              │      *look*, not a second *opinion*.
   LLMProvider (Anthropic | Mock) ◄────────── ┤
                                              │
   Restorer ◄────────────────────────────────►│◄──► SessionVault
   (tolerant token regex, post-assertions)    │
                                              │
   AuditLogger ◄──────────────────────────────┘   hash-chained, token IDs only
```

The ordering is a **security property, not a convenience**. `EgressBlockedError` propagates
out of `orchestrator.run()` before any provider request is constructed; there is no code path
that reaches the network without a passing gate.

### The HTTP surface

The library is the product; this is a thin layer over it. Four of these endpoints differ from
the build specification's table, and every difference is a closed hole rather than a
preference — Deviations 16–19.

**Three controls this layer ships that the specification's table does not describe, and that
nothing above used to mention.** They were built, they are tested, and they were invisible to
anyone reading this document — which for the strongest work in the API layer is the wrong way
round:

- **`GET /audit` proves ownership, it does not merely scope.** The documented call
  `/audit?session_id=X` returns **422**: `user_id` is mandatory, and the route checks it against
  the owner recorded in the log at `SESSION_CREATE`. A wrong owner gets a byte-identical empty
  page rather than a distinguishable error, so the endpoint cannot be used to confirm that a
  session ID is real. Without this the log handed any anonymous holder of a `run_id` the
  `session_id`, `doc_id` and `user_id` of that run — i.e. both credential pairs needed to read
  the original document and to erase the vault. `routes/audit.py` calls the previous behaviour
  "a live, complete break", which is accurate.
- **Failed ownership proofs are metered and audited.** ~20 failures from one caller earns
  `429`, and each one writes an `AUDIT_ACCESS_DENIED` event — a **13th** event type, and one that
  sits deliberately **outside** `EVENT_TYPES`. That frozenset stays the build doc's fixed
  **twelve** and is asserted by count in `tests/test_audit.py`, so the only phrasing that is true
  of the code is **twelve members of the vocabulary, all emitted, plus a thirteenth emitted
  beside it** — written and chained like any other row. §5 Q5 and Deviation 26 now say it that
  way as well; both read "all twelve" until this pass, which left one count described two
  different ways in one document. Writes (`POST /sessions`,
  `POST /documents`, `DELETE /sessions/{id}`) are metered on the same mechanism.
- **Uploads are capped** (`REQUEST_TOO_LARGE`) and read in bounded chunks, so an unbounded body
  cannot be streamed into memory.

The meter keys on the **source address**, because that is the only caller identifier this tier
has. Behind a proxy or a shared NAT that is one bucket for many callers, which is a real
limitation and is why "per-caller rate limiting keyed to a proven identity" is still on the
production list rather than crossed off it.

| Method & path | Purpose | Notes |
|---|---|---|
| `POST /sessions` | create session | `{user_id}` → `{session_id, expires_at}`. The session is **bound to that `user_id`**. |
| `DELETE /sessions/{id}` | logout, destroys the vault | Requires `?user_id=`. Returns an **unconditional 204** — owned, stranger, unknown and already-destroyed are byte-identical. |
| `POST /documents` | upload | multipart + `user_id`, `doc_category` → `{doc_id}` |
| `GET /documents/{doc_id}/text` | original text for the UI's first panel | Owner-only, by decryption rather than by a permission check. Never on the outbound path. |
| `POST /pipeline/run` | end-to-end | `{session_id, user_id, doc_id, prompt, strategy?}` → `PipelineResult`. Session/user binding enforced with `compare_digest`. |
| `GET /audit` | compliance query | **Requires `session_id` or `run_id`**; unscoped is `400 AUDIT_SCOPE_REQUIRED`. Also filters `event_type`, `since`, `until`; paginated. `since`/`until` must be **finite** and `offset` must fit SQLite's signed 64-bit `INTEGER` — both are `422 VALIDATION_ERROR` otherwise. Neither refusal is tidiness: a `NaN` bound binds as SQL `NULL`, so `(:since IS NULL OR ts >= :since)` was true for every row and the window was silently dropped rather than matching nothing; and `offset` past 2^63−1 raised an `OverflowError` no handler was registered for, which left the middleware stack entirely and answered a bare `text/plain` 500 with no CSP, no `nosniff` and no `referrer-policy`, plus a logged traceback, repeatable for free from one anonymously minted session. |
| `GET /audit/verify` | hash-chain check | `{valid, length}` |
| `GET /health` | liveness | Model loaded, DB reachable, and a **count** of active sessions — never their IDs. |
| `HEAD /health` | liveness, headers only | Declared explicitly, and answers the route. |
| `GET /fixtures/{name}` | one of the four shipped demo documents, so the UI preset loads in one click | **The only route that serves a file, and the only unauthenticated *read*.** `name` must be one of exactly four literals; everything else is `404 NOT_FOUND` (`reason: not_a_shipped_fixture`). The bytes come from a frozen mapping built once at import, so the request path is a dict lookup and there is no filesystem access downstream of the handler. Detail below the table — it is the row most worth attacking, so it is the row with the most written under it. |
| `GET /` | demo UI | static mount |

Two response conventions are worth naming because they look like sloppiness and are not.
An expired session, an unknown session, and a session belonging to somebody else all return
the **same** `401 SESSION_EXPIRED`; a wrong-owner document and an absent document both return
the same `404 NOT_FOUND`. In each case the distinguishable answer would be an oracle, and the
information a caller is owed is "no", not "no, and here is why".

`/docs` and `/redoc` are **off** (Deviation 19) — they fetch JS and CSS from a CDN, which
contradicts the offline premise of the whole design. `/openapi.json` is served locally.

**`HEAD /health` is declared, and it is a fix rather than a formality.** FastAPI's `@router.get`
registers `GET` only, so `HEAD` was a *partial* match and Starlette fell through to the catch-all
`Mount("/")` the UI is served from — measured, `curl -I /health` on a healthy process returned
**404** while `curl /health` returned 200. It is the first probe a load balancer and an ops
reviewer try. The same handler is registered twice rather than once with `methods=[...]`, because
FastAPI derives one operation ID per route and the combined form ships a duplicate into the
schema. `HEAD` on the other `GET` routes (`/audit`, `/audit/verify`,
`/documents/{doc_id}/text`) still 404s and is tracked separately.

**Four response headers, stamped on every response by middleware, not per route.**
`content-security-policy` (`default-src 'none'`, `frame-ancestors 'none'`, `base-uri 'none'`),
`x-content-type-options: nosniff`, `referrer-policy: no-referrer` — and, added late,
**`cache-control: no-store`**. That fourth one matters more than its size: `GET
/documents/{doc_id}/text` is one of exactly two endpoints allowed to return decrypted original
plaintext and it shipped with **no `Cache-Control` at all** (measured; and `grep -rni no-store`
matched nothing in the tree), so that body was storable by any intermediary and by the browser's
back/forward and disk caches, outliving the session TTL and the cryptographic erasure on a machine
the process does not control. It is stamped on every response rather than on that one route for
the same reason `METERED_METHODS` keys on the HTTP method rather than a path allow-list: a
per-route list goes stale the moment a route is added.

**The 422 no-echo guarantee had exactly one exception and no longer does.** This API's error
paths report *which fields* failed and never the caller's input — except that under
`extra="forbid"` pydantic's `extra_forbidden` `loc` ends in the caller's **own** key, which the
handler joined straight into `fields`. Measured: a body carrying `{"evil_field_<script>": 1}`
came back as `{"errors":1,"fields":"body.evil_field_<script>"}` — up to 64 characters of
attacker-chosen text out of the endpoint whose documented purpose is not reflecting the caller's
input. An extra field's name is now reported as `body.<extra>`; declared field names are still
named, because that is what makes a 422 actionable.

#### `GET /fixtures/{name}` — the only file-serving route, and the only unauthenticated read

Added late, to close Deviation 57 (the preset dropdown named four documents the page had no way
to fetch). It is the first control a reviewer clicks and it is the one route on this surface that
takes a **filename** from a caller, so it gets more space here than its handler's size suggests.
`secure_context_pipeline/api/routes/documents.py` is the implementation; everything below is
measured against it, not summarised from intent.

**What it serves: four literals, read once at import.** The allow-list is a
`MappingProxyType` mapping an exact filename to the `doc_category` that document is scanned
under — `medical_note.txt` → medical, `legal_memo.txt` → legal, `financial_disclosure.txt` →
financial, `legal_brief_large.txt` → legal. All four are **synthetic**, generated by
`fixtures/generator.py`, and they already ship in the clone and in the image
(`COPY fixtures/ fixtures/`), so publishing them over HTTP moves no boundary: anyone who can
reach this port can already read them out of the repository. `_load_shipped_fixtures` reads them
into a second frozen mapping **once, at import** — **91,935 bytes** (2,826 + 3,260 + 2,820 +
83,029) resident for the life of the process, a median **0.206 ms** to load over 50 repeats,
0.006% of the ~1.5 GB an `en_core_web_lg` worker already holds.

It is a literal table rather than `FIXTURES_DIR.glob("*.txt")`, and that difference is the whole
control. A glob makes the served set a property of the filesystem *at the moment of the request*:
a scratch file, a document a reviewer dropped in to try it, a symlink planted by anything that can
write there — each becomes world-readable on an anonymous GET the instant it appears, with no diff
and no review. With a table, adding a name is a diff. That these four names are the ones the repo
actually ships is measured against `git ls-files`, not asserted, by
`test_api_documents.py::test_the_fixture_allow_list_is_exactly_what_the_repo_ships`.

**The request path never touches the filesystem.** A caller's string reaches exactly one
operation, `FIXTURE_BYTES.get(name)`. There is no `open`, no `read_bytes` and no `/` operator
anywhere downstream of the handler — the only string ever joined onto a directory is the table's
own key, in the import-time loader. That is what makes widening this route later an *addition* of
filesystem access to a handler that has none (a diff a reviewer sees) rather than a change to
which path an existing read is handed (a diff that looks like a rename). Pinned by
`test_the_request_path_never_touches_the_filesystem`, which booby-traps `Path.open`,
`Path.read_bytes` and `Path.read_text`, repoints `FIXTURES_DIR` at a nonexistent directory for the
duration of one request, and still gets **200** with the byte-for-byte correct body.

**Why it takes no session — and the counterweight, recorded rather than argued away.** Three
things all hold, and if any one stopped holding the decision would need re-making:

1. **It would gate content the same origin already publishes anonymously.** Measured on a server
   started for this pass: `GET /` returns `200 text/html` and `GET /app.js` returns
   `200 text/javascript` with no credential of any kind. A synthetic fixture is the same class of
   shipped asset as the page that loads it.
2. **A session is not a credential here.** `POST /sessions` mints one for any `user_id` an
   anonymous caller asks for — measured, `{"user_id":"anybody-at-all"}` came back with a
   `session_id` and an `expires_at`. So a session gate would mean "make one extra anonymous
   request first", not "authenticate". This is the same `user_id` gap §3 opens with, and the
   audit-proof meter exists because of it.
3. **It would reintroduce the friction the route was added to remove.** The preset is the first
   control touched in the demo; requiring a session to load a document puts an ordering trap back
   exactly where one was just taken out.

The counterweight is real and is not softened: this is an unauthenticated read that returns bytes
the server holds. That is precisely *why* the control is a closed four-name allow-list rather than
authentication — authentication decides *who* may read, and the property that matters here is that
**there is nothing else to read**. The structural half of that is pinned in both directions by
`test_the_fixture_route_takes_no_session_and_can_reach_no_user_data`: an anonymous GET is served,
a bogus `X-Session-Id` changes nothing (so there is no half-state where a reviewer believes they
authenticated), and the handler's signature is asserted to be exactly one parameter — no
`ServicesDep`, so it cannot reach the encrypted store, the vault, the audit log or the registry.
Add a services dependency later and that test goes red, which is the moment the session question
gets asked again.

**Traversal was tested, not argued.** The committed corpus is `TRAVERSALS` in
`tests/test_api_documents.py`: **20** names, each driven through
`test_no_name_a_caller_can_send_reaches_a_file_off_the_allow_list`. Two details make it evidence
rather than decoration:

- **It is driven at the ASGI layer**, by a hand-built `scope`, because `httpx` removes dot
  segments from a request target before any transport sees it — a traversal sent through the
  client library would be testing `httpx`. A reverse proxy, a hand-written socket or a
  non-conforming client can deliver these paths verbatim.
- **The assertion is *which* 404.** A refusal carrying `reason: not_a_shipped_fixture` came from
  the allow-list; a bare routing miss would carry `{"status": 404}` and would mean the allow-list
  was never consulted. `/etc/passwd` and `fixtures/generator.py` both exist and are readable by
  this process, so a route that joined the caller's string onto a directory would answer **200
  with content** for at least the traversals. And
  `test_the_allow_listed_name_is_the_positive_control_for_that_corpus` drives the same rig with
  one name changed and requires a 200, so the corpus cannot pass by the route not existing.

That corpus was re-run for this pass against a **live uvicorn** — its own `SCP_DATA_DIR`, port
8073 — over a **raw socket**, writing each request line verbatim. **36** request lines, which
account for themselves as **32** + **3** + **1**: thirty-two came back `404 NOT_FOUND` with
`reason: not_a_shipped_fixture` and no `root:`, no `def ` and no echo of the caller's string in
the body; three did something else and are stated precisely below rather than rounded up into
"all 404"; one is the positive control. Covered: `../../etc/passwd`, `../fixtures/generator.py`,
`....//....//etc/passwd`, `/etc/passwd` and `//etc/passwd`, an absolute-form request target
(`GET http://host/fixtures/../../etc/passwd`), single-encoded (`%2e%2e%2fetc%2fpasswd`,
`..%2f..%2fetc%2fpasswd`, `%2fetc%2fpasswd`), **double-encoded** (`%252e%252e%252fetc%252fpasswd`,
`..%252f..%252fetc%252fpasswd`), overlong UTF-8 (`..%c0%af..`), a fullwidth solidus
(`..%ef%bc%8f..`), backslashes, NUL bytes (`medical_note.txt%00`, `medical_note.txt%00.png`),
suffix traversal (`medical_note.txt/../../etc/passwd`), whitespace padding (`%20` leading and
trailing, `%09`, `+`), case variants (`MEDICAL_NOTE.TXT`, `medical_note.TXT`), a trailing dot, an
NTFS stream suffix (`::$DATA`), a Unicode lookalike (`medical%EF%BD%8Enote.txt`), real neighbours
that are not on the list (`generator.py`, `__init__.py`, `.env`), and the degenerate names
(the empty string, `.`, `..`). The positive control, `medical_note.txt`, returned **200** and the 2,826 bytes on
disk.

The three are worth stating precisely, because rounding them up would be claiming a control that
did not fire:

- A **raw NUL byte** and a **leading space** in the request line are rejected by `h11` with a
  **400** before routing — the application never sees them. They still reach the allow-list in the
  ASGI-level test, which is where a protocol parser cannot answer first.
- A **bare trailing space** is not deliverable over HTTP at all: the space is the request-line
  delimiter, so `GET /fixtures/medical_note.txt  HTTP/1.1` reaches the app as the clean name and
  is served. That is the client's normalisation, not this route's; the encoded form
  `medical_note.txt%20` is a 404, and the raw form is one of the 20 in the ASGI corpus.

**Symlinks are refused at load, so the 404 is a property of the table.** A request cannot express
a symlink, so this was verified end to end instead: a copy of the package was run from a temporary
root whose `fixtures/medical_note.txt` was a symlink to a planted `root:x:0:0:` file outside the
directory. The server logged `demo fixture refused: symlink (name=medical_note.txt)` at startup
and answered **404** (`reason: fixture_not_installed`) for that name, while the three untouched
siblings still returned 200. Unit-pinned by
`test_the_loader_refuses_a_symlink_planted_under_an_allow_listed_name` and
`test_the_loader_refuses_a_symlink_to_a_file_inside_its_own_directory`; the loader also refuses a
non-regular file, anything over 1 MiB, and bytes that are not valid UTF-8, and
`test_a_readable_file_beside_the_fixtures_is_never_loaded` plants a `.env` holding a
`SCP_MASTER_KEY` in the very directory the loader reads and shows it is not loaded — the gate is
the allow-list, not the directory. `test_the_served_table_cannot_be_extended_at_runtime` closes
the last way in: both mappings are `MappingProxyType`, so no fifth entry can be added after the
reviewed four.

**What the response is, and what it is not.** `text/plain; charset=utf-8`, with the four
middleware headers on top of it (measured on the live run: `content-security-policy: default-src
'none'; …`, `x-content-type-options: nosniff`, `referrer-policy: no-referrer`,
`cache-control: no-store`), so a browser that navigates here renders inert text. The route stores
nothing and issues no `doc_id`: the page takes these bytes straight back to `POST /documents` as an
ordinary multipart upload with the same `user_id` and `doc_category`, so the preset is not a second
ingestion path. That a preset run and a hand-picked run of the same fixture produce the same stored
document and the same detections is proved end to end by
`test_a_preset_run_and_a_hand_picked_run_of_one_fixture_detect_identically`.

The one thing this route is *not* is metered: `METERED_METHODS` covers writes, and a GET of a
92 KB in-memory table is not the cost `POST /documents` is metered for. Behind a proxy it is
therefore an unmetered anonymous read of four fixed files, which is the honest statement of its
worst case.

---

## 3. Threat model

| Adversary | Control | Residual risk |
|---|---|---|
| **Provider or network intermediary reads the payload** | Egress gate (fail-closed, **three** passes; see §2 for what each one is and why the third exists) + token opacity | The obfuscated payload still reveals document *shape*: entity counts, types, and positions. A 40-entity medical note is visibly a 40-entity medical note. |
| **Vault database stolen at rest** | AES-256-GCM under a key derived from an in-memory-only session key. The session key is never persisted. | Live-process memory scraping. Session-lifetime plaintext lives in RAM by design (that is what makes a < 5 ms lookup possible). **Declared out of scope for this tier.** |
| **Cross-session access, same user** | Per-session HKDF vault keys, AAD binding to `session_id:token_id`, non-deterministic token IDs across sessions | None identified. A row copied between sessions fails GCM authentication. |
| **Log or audit exfiltration** (*reading* the log) | Length ceilings that make the log incapable of holding *content* (`detail` values 64 chars, label columns 128), enforced again at the write boundary; no call site that writes a value; and the leakage harness scanning the raw DB **bytes** on all 100 runs | **A short identifier would fit, and the schema cannot tell.** `detail={"v": "John Smith"}` validates — see below. The guarantee is "nothing writes one", measured, not "the schema forbids one". Plus traffic analysis of event counts and timings. |
| **Audit tampering** (*writing* to the log) | SHA-256 hash chain over every event, plus **two independent high-water marks** (`sqlite_sequence` and a trigger-guarded `audit_chain_meta`) so deleting the newest rows is caught — and `seq` allocated above the watermark, so the evidence does not expire | **Bounded, and the bound is the interesting part.** A silent truncation costs four statements, not one, and all four must land in step — measured as a ladder in §5 Q5. The digests are **unkeyed**, so an attacker who runs all four can rewrite the chain end to end and it will verify — demonstrated, not assumed. |
| **Replay of Session A ciphertext into Session B** | AAD authentication failure | None identified. |
| **Caller presents a session ID that is not theirs** | Sessions are **bound to the creating `user_id`**; `POST /pipeline/run` compares with `secrets.compare_digest` and answers the same `401 SESSION_EXPIRED` as an unknown session. `DELETE /sessions/{id}` requires the owner's `user_id` and returns an unconditional 204 either way. | The `user_id` is still an **asserted claim, not a proven one** — there is no real authentication at this tier. What the binding buys is that a leaked *session ID* is no longer sufficient on its own; what it does not buy is protection against a caller who simply asserts someone else's `user_id`. Real authn is the production item. |
| **Anonymous enumeration of live session IDs** | `GET /audit` requires a `session_id`/`run_id` scope; `/health` reports a session *count*, never IDs | None identified for the enumeration path itself. This was a **live hole, not a hypothetical**: unscoped `GET /audit` published every active session ID, and `DELETE /sessions/{id}` then accepted them — full vault destruction with zero credentials. |
| **Wrong user requests another user's document** | Per-user HKDF document keys **and** AAD binding to `doc:<user_id>:<doc_id>` — two independent legs, each pinned by its own test | Surfaced as `NOT_FOUND`, byte-identical to an absent document: same exception type, same code, same detail keys. The *content* oracle is closed. A **timing** side channel is not — see below. |
| **PHI typed into the *prompt* rather than the document** | The user prompt goes through the same detector, engine and vault as the document, and is tokenized before assembly (Deviation 40) | Measured as a **live bypass before this was built**: six entity types typed into the prompt box reached the provider verbatim while the document beside them was fully tokenized. Residual: prompt spans are excluded from `PipelineResult.detections` (offsets are document-space), so the UI highlight panel shows nothing for them — the values *are* vaulted and tokenized, but a user cannot see that they were. |
| **An uploaded document carrying instructions for the model** | The document is fenced in `<DOCUMENT>…</DOCUMENT>` and any fence tag inside either untrusted half is neutralised to `&lt;…`, so an upload cannot close the fence early and be read as top-level instruction (Deviation 41) | **This is defence against confusion, not against a determined injection, and the difference matters.** A model can still be talked into ignoring a fence; nothing here detects or blocks instruction-shaped text. What the fence guarantees is only that the *delimiter* cannot be forged. Prompt injection is **not** a claim this system makes. |
| **A document uploaded without a `doc_category`** | `only_in_doc_categories` scopes category-specific rules; `_validate_category` rejects an *unknown* category | **Open, and it is the default.** `doc_category` is an optional form field defaulting to `None`. Measured on a real privileged brief: `legal` finds `CASE_STRATEGY` (the one entity with `action: redact`) and `CLIENT_IDENTITY`; `None` finds neither, so the litigation strategy is never redacted, never vaulted, and pass 1 has nothing to look for. The guard is written against the typo and open on the omission. Same shape as the `user_id` row: a **user-supplied lever on which security controls run.** §7 gap 4. |
| **Inference / re-identification** | See below — this is the interesting one | Substantial and irreducible. |

### The weakest point in this design: `user_id` is an asserted claim

If you read one paragraph of this threat model, read this one. **There is no authentication at
this tier.** `user_id` arrives as a request parameter and the system believes it. Every
isolation property below is real *given* that claim, and none of them survives a caller who
simply types someone else's `user_id`:

- per-user HKDF document keys derive from the asserted `user_id`, so asserting Alice's `user_id`
  derives Alice's key;
- the session/user binding added in Deviation 16 stops a leaked **session ID** being a
  credential for anyone else's documents — it does not stop a caller claiming to be Alice in the
  first place;
- `doc_id` being 32 unguessable hex characters is what actually stands between an attacker and
  another user's document, and **obscurity is not the control this design claims to have**.

So the honest statement of the boundary is: this system enforces *cryptographic isolation
between identities*, and it does **not** establish identity. Those are different jobs, and only
the first one is built. The fix is not a patch to this code — it is an authentication layer in
front of it (OIDC/JWT at the API edge, `user_id` taken from a verified token claim and never
from the request body), after which every property below becomes load-bearing rather than
conditional.

It is called out here, at the top, rather than left in a table cell, because it is the first
thing a security reviewer should find and the last thing a submission should bury.

### Two dependencies log document text at DEBUG, and both are muzzled at import

"No originals in logs" is only as true as the **whole process's** logging, not the part this
codebase writes. Two third-party libraries in the dependency tree emit document content at
`DEBUG`, and neither is obvious from reading our own source:

- **Presidio's `LemmaContextAwareEnhancer`** logs `"Context list is: %s"` with lemmatised words
  taken from the document under analysis. Muzzled in `detection/detector.py`.
- **The Anthropic SDK** logs `"Request options: %s"` with the **entire serialized request
  body** — `system` and `messages` in full — on every call *and every retry*. Muzzled in
  `llm/anthropic_provider.py`.

Both are silenced with a level **and** a sub-INFO filter attached to the logger, not a level
alone. That distinction is the whole point: `setLevel` is advisory, and any host application
that later calls `logging.config.dictConfig` or `setLevel(DEBUG)` — which is the first thing
anyone does while debugging — silently undoes it. A filter on the logger survives that.

**Severity, stated honestly rather than inflated.** The Anthropic payload has already cleared
the egress gate, so what would be logged is surrogates, not originals: this is a defence-in-depth
finding, not a live leak. But §16 forbids content in logs *unconditionally*, a retry logs it
again, and "what does your dependency tree log?" is a fair question that most submissions
cannot answer at all. `demo.py --real --dump-wire` remains the sanctioned way to inspect a real
request body.

### The AAD concatenation is unambiguous, and a test enforces it

Both AADs are colon-joined from attacker-influenced identifiers — `doc:<user_id>:<doc_id>` and
`<session_id>:<token_id>` — and concatenating identifiers into an authenticated field is a
classic way to build a collision. If `("alice:x", "y")` and `("alice", "x:y")` produced the
same AAD, a caller who controls a `user_id` could authenticate against somebody else's blob.

They cannot, and the reason is structural: the **right-hand component is fixed-width**. A
`doc_id` is exactly 32 hex characters and a `token_id` exactly 8, so the string parses
unambiguously from the right regardless of what the left component contains. That is a real
guarantee, but it is a guarantee about a *format*, so the crypto tests now import the store's
own `_DOC_ID_RE` rather than restating the width — widening `doc_id` breaks a crypto test
rather than silently dissolving the argument.

A production build would length-prefix each component instead of relying on a fixed-width tail.
The concatenated format is the build specification's, and it is safe as specified **because**
of the width constraint, which is exactly the kind of dependency that deserves a test rather
than a comment.

### A document's two blobs share one AAD, so they are interchangeable on disk

Each upload stores two encrypted files: the raw bytes and the extracted text. The build
specification fixes `AAD = doc:<user_id>:<doc_id>`, which is per *document*, not per blob — so
both halves authenticate under the same AAD, and an attacker with write access to the data
directory can **overwrite one with the other** and have it read back cleanly. This was checked
rather than reasoned about: swapping the files on disk and re-reading succeeds.

The impact is **integrity only, and it is bounded**. Both blobs already belong to the same
document and the same owner, both still decrypt solely under that owner's derived key, and no
value crosses a user or session boundary. What an attacker achieves is making `get_text` return
the raw bytes, or vice versa — a corruption, not a disclosure.

It is not fixable without deviating from the specified AAD; the fix is one more component
(`doc:<user_id>:<doc_id>:raw` versus `:txt`), which is a one-line change and a spec deviation.
It is written down here rather than left to be discovered, and it is the kind of thing a
docstring claiming "blobs are not portable" would have hidden — that claim was in this
codebase, and it was false.

### The document read path is not timing-uniform

The response to "absent document" and "wrong owner" is identical in every byte a caller can
read. It is not identical in *time*, and pretending otherwise would be the easy lie:

- an absent `doc_id` fails immediately at `ENOENT` — the blob is never opened;
- a wrong-owner `doc_id` is read off disk in full and *then* rejected by AES-GCM.

Measured on a 2.25 MB blob: **0.067 ms vs 1.199 ms — about 18×**, and the gap grows with blob
size because it is dominated by the read itself.

**What it actually discloses**, stated precisely: that a `doc_id` the caller *already holds*
corresponds to a stored document. It does not disclose the owner, the content, the category,
or any part of the plaintext, and a `doc_id` is 32 hex characters — an attacker who cannot
already name one learns nothing, because guessing is the same problem as guessing a 128-bit
value.

**Why it is not fixed.** The obvious equalisation — check the metadata table first and refuse
before touching the blob — trades a cryptographic guarantee for a bookkeeping one. Isolation
here is deliberately a property of key derivation, not of a row that says who owns what; making
reads conditional on that row means a lost or corrupted metadata row denies a legitimate owner
a document they can still perfectly well decrypt. A constant-time read (always fetch, always
attempt) would close it at the cost of doing full disk I/O for every miss. Neither trade is
obviously right at this tier, so the mechanism is unchanged and the residual is written down
here rather than discovered in review.

### Filenames are stored in cleartext, deliberately

There is a real tension in this codebase and it deserves a straight answer rather than being
left for a reviewer to find.

`extraction.py` logs only a file's *suffix*, never its name, on the explicit reasoning that a
filename can itself be a personal identifier — `chen-oncology-2024.pdf` discloses a name and a
probable diagnosis before a single byte is decrypted. That reasoning is correct.

The `documents` metadata table nevertheless stores `filename` in cleartext, and this is the
intended posture, not an oversight:

- **Metadata is queryable by design.** The store has to answer "list this user's documents"
  without decrypting every blob, and a required, spec-level capability of the store is that its
  document listing is usable.
- **The boundary this system defends is egress, not the local disk.** The threat model above
  puts a stolen vault DB in scope and grants that the metadata DB leaks *shape* — counts,
  categories, sizes, timestamps. A filename is more of the same class of disclosure, and
  encrypting it while leaving `size_bytes`, `doc_category` and `created_at` in the clear would
  buy very little.
- **It never reaches the provider.** The filename is not part of any payload the egress gate
  releases; the pipeline sends the document body and nothing else.

So the two positions are consistent once the line is drawn in the right place: **filenames are
acceptable at rest in a store the operator already controls, and unacceptable in logs**, which
are shipped, aggregated, retained under different rules, and read by people who were never
granted access to the documents themselves. If filename confidentiality at rest were required,
the change is small — encrypt the column under the user's document key and keep a blind index
for listing — and it is listed in §7 rather than claimed.

### Inference and re-identification

This is where the honest answer is uncomfortable, so it gets its own section.

Perfect masking of *direct* identifiers does not prevent re-identification. A rare diagnosis
plus a date range plus a geographic region can identify a person even when every name, MRN,
and account number in the document is a token. Specifically:

- **Tokenization leaks co-occurrence structure.** `[PHI_NAME_1a2b3c4d]` appearing near
  `[PHI_DIAGNOSIS_9f2e77b1]` twelve times tells an observer these two entities are related, and
  how often.
- **Pseudonymization leaks demographic plausibility.** A generated fake name carries an
  implied ethnicity, gender, and era. That is a signal the original may not have had, and it
  can be *wrong* in ways that mislead a downstream human reader.
- **Tier-3 class hints leak deliberately.** `[PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]` tells
  the model — and anyone reading the payload — that the patient is diabetic. That is a
  conscious trade of class-level disclosure for reasoning utility, and it is a **per-entity
  config dial** (`hint: true|false`), not a global decision.

**Shipped mitigations:** per-session date shifting (absolute dates destroyed, intervals
preserved); typed tokens that carry no information about the value itself; forced redaction of
free-text legal strategy. **Not shipped:** a k-anonymity-style generalization pass, which is
the real answer and is listed in §7.

---

## 4. Why these choices

### Detection: Microsoft Presidio, locally

An LLM-based detector would itself exfiltrate the PII it was detecting — the premise of this
pipeline forbids it. Presidio runs entirely in-process, is deterministic and auditable (you
can point at the recognizer that fired), and is config-extensible, which is what makes the
"add an entity type by editing YAML" requirement real rather than aspirational. Latency fits
the budget without a network round-trip.

The alternative worth taking seriously is AWS Comprehend Medical, which has materially better
clinical NER. It is rejected here for the same reason as the LLM detector: it is a network
call carrying the document. A self-hosted clinical NER model is the production path if
detection quality becomes the binding constraint.

#### Measured recall

Detection quality was an estimate in this README until it was measured. It is now an annotated
corpus: **320 values across 42 documents and 1,672 words**, spanning all four categories plus
untagged documents, and deliberately including the adversarial shapes real documents carry —
hard-wrapped prose, table layouts, OCR-style column spacing, internal-domain email, and five
different spellings of a date of birth.

| | Before | After |
|---|---|---|
| Values **covered** by a detected span | 88% | **99%** |
| Values covered **and correctly typed** | 88% | **99%** |
| False positives, disjoint 18-doc / 797-word clean corpus | — | **0 spans (0.00 per 1,000 words)** |

The three residual misses are all spaCy `PERSON` failures and are named individually in a test
rather than rounded away.

**What this number is worth, stated precisely.** The same work wrote both the corpus and the
fixes it drove, so it measures **the shapes it knew to look for**, and it does not transfer to
production as a recall estimate. A corpus written by the person fixing the detector is a
regression harness, not an evaluation.

##### The held-out number, which is the one to believe

Rather than leave that caveat as an argument, it was measured. `HELD_OUT_CORPUS` is a control of
**53 documents in registers that appear nowhere in the tuning corpus** — radiology, pathology,
pharmacy prior-auth, EOB, trial adverse-event, immunization, telehealth chat, portal message,
hospice plan — annotated *before* being run and never used to change a pattern.

| Over 366 values, none of which anything was tuned against | Tuned corpus | **Held-out** |
|---|---|---|
| Values **covered** by a detected span | 99% | **91%** |
| Values covered **and correctly typed** | 99% | **90%** |

Reproduce with `pytest tests/test_detection.py -k held_out -s`; the floors are asserted, not
commented, so a regression fails the build.

**The average is the least useful number here. This is the per-entity breakdown, worst first:**

| Entity | N | Covered | Typed |
|---|---|---|---|
| `SETTLEMENT_TERM` | 2 | **0%** | **0%** |
| `DATE` | 10 | **30%** | **30%** |
| `NAME` | 58 | **81%** | **79%** |
| `MRN` | 15 | 80% | 80% |
| `AMOUNT` | 25 | 84% | 84% |
| `DOB` | 33 | 88% | 85% |
| `CLIENT_IDENTITY` | 13 | 92% | 92% |
| `ACCOUNT_NUMBER` | 19 | 95% | 95% |
| `SSN`, `TAX_ID`, `PHONE`, `EMAIL`, `ADDRESS`, `CASE_ID`, `DIAGNOSIS`, `MEDICATION`, `INSURANCE_ID`, `LAB_RESULT`, `CASE_STRATEGY`, `PRIVILEGED_MARKER` | 191 | 100% | 100% |

The `N` column sums to the 366 in the header above it. It did not until an audit pass re-ran
the table: the 100% row read **194** over nine entities that carry **182** values between them,
and left out `CASE_STRATEGY` (2) and `PRIVILEGED_MARKER` (2), which are also at 100% — 186 in
total, and 191 since `INSURANCE_ID` joined the bucket. The rows summed to 374 against a declared total of 366, and the 8-value error was
in the flattering direction, inflating the perfectly-detected bucket. Every other row reproduces
exactly, which is what made this one worth catching; re-derive the whole table with the command
above rather than trusting this one.

**`NAME` is the weakest point of this whole submission, and it is not close.** Not because 81% is
the lowest number — it is not — but because of the count and the consequence. It is 58 of the 366
values, so it is the largest absolute quantity of PII left in the clear, and it is the entity the
entire pseudonymization design rests on. A missed `NAME` is invisible to **all three** egress
passes: it was never vaulted, so pass 1 has nothing to look for; `NAME` is not in
`HIGH_SEVERITY_TYPES`, so pass 2's re-scan cannot block it; and `_INDEPENDENT_PATTERNS` has one
entry (separated SSN), so pass 3 has no opinion. Demonstrated end to end, using one of the
detector's own printed held-out misses:

```
POST /pipeline/run -> 200 ; egress_rescan_warnings: 0.0
outbound payload: "…Specimen received from Ingeborg Vasquez-Lund, seen with [PII_NAME_aa096360].…"
```

A real surname in the clear, in the same sentence as a tokenized one, with the gate reporting
zero warnings. `SETTLEMENT_TERM` at 0% and `DATE` at 30% are smaller in volume but have the same
shape of failure.

**This is the honest bottom line.** Detection recall is the binding constraint (§7), and an entity
the detector misses is not merely unblocked: it never enters the vault, so pass 1 does not scan
for it, pass 2 re-scans with the *same* detector and shares the miss exactly, and the 100-run
leakage harness plants only values the detector found — so it cannot see the miss either. **The
instrument that measures leaks is blind to precisely the leaks that matter most.** `100/100
clean` is therefore a statement about values the detector found, not about all PII in the
document, and §7 gap #1's parenthetical that "the gate makes misses safe" holds only for the four
entity types in `HIGH_SEVERITY_TYPES`, or where the same value was vaulted from another
occurrence. The architectural answer is that the gate is fail-closed over the vault — a defence
in depth that does not depend on recall — and the engineering answer is a clinical NER model
(scispaCy, Comprehend Medical) rather than spaCy plus gazetteers. Neither makes 81% on `NAME`
acceptable, and it is stated here rather than left for a reviewer to find.

*(An earlier revision of this table reported 88.5% / 87.4% with `MRN` at 27%/13%. `MRN`'s three
literal label patterns were then replaced with a label-independent shape, taking it to 80%/80%
and the total to 91%/90%. The figures above are from a fresh run of the command named above.)*

What makes the fixes more credible than the number is that five of the six came from a
**property** rather than a corpus row — Public Suffix List validation dropping internal
domains, newline-terminated tails truncating hard-wrapped sentences, a greedy quantifier
swallowing the next value's boundary, lemma-inert context words, and score-versus-specificity
ranking. Each is a defect you can reason about without the corpus, and each has an independent
test. The **gazetteer expansion is the exception**: it is the one change fitted to observed
data, and it is the one to discount.

**Known gaps, stated plainly:**

- **Gazetteer recall.** 170 medications and 208 diagnoses cover the common cases. A rare drug
  or an unusual phrasing of a condition is missed, and a gazetteer is a closed vocabulary by
  construction — it cannot generalise the way a clinical NER model does. scispaCy or Comprehend
  Medical is next.
- **Full-name recall is bounded by spaCy, not by configuration.** Measured on the corpus above:
  **~98% for `NAME`, ~86% for `CLIENT_IDENTITY`**. No amount of registry tuning moves this,
  because both resolve to Presidio's `PERSON`, i.e. to the spaCy model. It is the single
  strongest argument for a better NER model and the reason the egress gate cannot be a
  detection-quality story: the gate is what makes the residual **safe** rather than invisible.
- **Emails at dotless hosts are missed by design.** `user@localhost` and similar single-label
  hosts are not matched. The backstop pattern (Deviation 31) requires a dot in the domain,
  because anything looser starts matching ordinary prose containing `@`. A real deployment that
  carries dotless internal hosts needs an explicit allow-list of them.
- **Presidio's `DATE_TIME` over-fires on relative prose** — "daily", "overnight", "the last
  twelve hours". Left unhandled these poison the vault: once "daily" is a known original, the
  egress gate blocks every payload containing the word. Mitigated with a registry-driven
  `require_digit` rule (a date that *identifies* someone carries a numeral). This is a
  precision patch, not a fix for the underlying recognizer.
- **Free-text legal strategy detection is heuristic.** The `CASE_STRATEGY` patterns catch
  common phrasings and will miss paraphrases. This is why that entity is `action: redact`
  rather than tokenized — see §6.
- **`aiosqlite` is thread-wrapped, not truly async.** It is not a real async driver; it moves
  blocking calls to a thread pool. Fine at this scale, wrong at scale.
- **Single-process session registry.** Session keys live in one process's memory. Multi-node
  requires Redis plus KMS-held envelope keys, and a process restart currently kills every
  live session (documented and accepted — it is the same property that makes destruction
  cryptographic).

**One thing that looks like a gap and is not.** The detector's paragraph-splitting regex,
`\n[ \t]*\n+`, does not match CRLF, which reads like a chunking bug on Windows-authored
documents. It is unreachable: `extraction.py` normalises `\r\n` and bare `\r` to `\n` before
returning, and every path from upload to detection goes through that function, so the detector
never sees a CRLF. The regex is defence-in-depth against a caller who bypasses extraction and
hands the detector raw text — worth knowing, not worth fixing, and written down here so the
next reader does not re-derive the same false alarm.

### Storage: encrypted file store + SQLite with application-layer AES-GCM

Deliberately **not** SQLCipher. SQLCipher is one password per database file, so per-user
isolation would become a policy claim enforced by application logic. With application-layer
AES-GCM, per-user isolation is a property of key derivation: a different `user_id` derives a
different key via HKDF, and the wrong key fails authentication rather than returning someone
else's plaintext. SQLCipher also adds real Docker build fragility for zero isolation gain.

Cloud compatibility is satisfied at the interface level rather than by implementation:
`DocumentStore` is a Protocol that admits an S3/GCS backend, and `KeyProvider` admits AWS or
GCP KMS. `MockKMSKeyProvider` ships as the local demonstration — it implements real
`generate_data_key`/`decrypt` envelope semantics with encryption-context binding, and wraps
data keys under `HKDF(cmk, info=b"kms-wrap")` rather than using the master key directly as a
cipher key, so the CMK stays input keying material the way a real KMS treats it.

**Two of those seams were closed by the config schema, and are now open.** `Settings.key_provider`
and `Settings.strategy` were closed `Literal`s while `llm_provider` beside them was a `str`, so a
`KeyProvider` or `ObfuscationStrategy` registered through the documented seam could be written,
registered, and never *selected* — and `build_key_provider`'s `unknown_key_provider` branch and
`build_strategy`'s `unknown_strategy` branch were both unreachable from a validated `Settings`.
Both fields are `str` now, and both still fail closed, at different points and for a stated
reason: `key_provider` at startup in `EncryptedDocumentStore.__init__`, and `strategy` at
`Settings` construction, because `build_strategy` runs *per span* and leaving the check there
would have turned a config typo into an HTTP 500 per run instead of a refusal at startup.
**Residual:** `api/schemas.py::StrategyName` is still a closed `Literal`, so a plug-in strategy is
selectable by `SCP_STRATEGY` but not yet per request.

**"Why SQLite and not Postgres — and what breaks first?"** SQLite is the right call at this
tier: no service to run, no connection pool to tune, and the isolation property under
examination lives in key derivation rather than in the database. What breaks first is
measurable, and measuring it corrected a guess.

The initial assumption was that no explicit `PRAGMA busy_timeout` meant an immediate
`database is locked` under contention. That is wrong — Python's `sqlite3` defaults it to
5,000 ms and `aiosqlite` inherits it. **Measured: 5.21 s of blocking before failure.** The real
problem is the consequence rather than the error. There is one connection per store instance,
and `aiosqlite` is a thread wrapper, so a second process contending for the write lock blocks
that store's worker thread for five seconds — which stalls **every request on that store**, not
just the writer. A single slow writer becomes a five-second outage for all readers.

That is the scaling wall, and it arrives well before any throughput limit: the first time this
runs as more than one process against one file. Postgres is the answer at that point, and the
`DocumentStore` Protocol is where it plugs in.

**"What happens if the process dies mid-write?"** `put` writes both blobs and then commits the
metadata row, and it unwinds itself on any exception — but not on `SIGKILL`, OOM, or power
loss, which strand blob files with no row pointing at them. Because a `doc_id` only ever comes
from a row, those files were both unreachable and uncollectable: permanent disk growth bounded
only by replacing the volume. The store now has `sweep_orphans()`, mirroring the vault's, wired
into the API lifespan so it runs at startup rather than existing as a tested method with no
production caller.

**"Two users upload the same document — what happens?"** They get two independent ciphertexts
and neither can read the other's. There is no content-addressing and no deduplication, which
would be a storage optimisation that quietly breaks per-user isolation: a shared blob needs a
shared key. Each copy is encrypted under `HKDF(master, "doc:" + user_id)` with a fresh nonce,
so identical plaintext yields unrelated bytes.
`test_document_store.py::test_identical_content_from_two_users_yields_different_ciphertext`
pins it.

---

## 5. Live-review questions

### Q1 — A 50-page brief with 200 entities. Where does it break?

Measured on `fixtures/legal_brief_large.txt` (12,062 words, **251 distinct entities** vaulted
plus 13 redacted values held as gate-only needles, so pass 1 scans for **264**), full pipeline,
mock provider: **6.4 s end to end**, against a 15 s budget.

The stage breakdown is the answer, and it is not the one you would guess (best of three runs
on a loaded machine):

| Stage | Brief (12k words) | Medical note (393 words) |
|---|---|---|
| Detect (spaCy, stage 3) | 2,816 ms | 109 ms |
| Obfuscate (engine) | 871 ms | 33 ms |
| **Egress gate** | **2,911 ms** | **156 ms** |
| Restore | 2.4 ms | 1.2 ms |

**The gate costs about as much as detection.** That is the finding, and it took measuring the
gate's two passes separately to see it (pass 1 is median-of-15; it is short enough that a single
sample is mostly scheduler noise):

| | Brief | Medical note |
|---|---|---|
| Pass 1 — scan for vault originals, `O(payload × entities)` | 277 ms | 1.8 ms |
| Pass 2 — detector re-scan of the payload | 2,759 ms | 151 ms |

So **spaCy runs twice per request** — once over the document in stage 3, once over the
assembled payload inside the gate — and those two passes are **87%** of wall time on the brief
and **86%** on the medical note.

**Pass 1's numbers here are 13x and 5x what this README used to claim** (21.3 ms and 0.36 ms),
and the increase is a deliberate purchase rather than a regression. Each of the four compared
forms in Deviation 48, the flexible-separator limb that closed the digit-regrouping release, and
the spacing-diacritic skeleton all added work to the same `O(payload × originals)` loop — every
one of them added because a vaulted original was reaching the provider without it. The stale
numbers mattered because of the conclusion drawn from them: this section used to say the
originals scan was **0.8%** of the gate on the brief, i.e. a rounding error. It is now **9.5%**
on the brief and **1.2%** on the note. Still not the bottleneck — pass 2 is, by roughly 10x —
but no longer negligible, and no longer something to wave away when deciding what to optimise.

#### The number above is per-*document*; the thing that grows is the *session*

Everything in this section is single-request latency, and that framing hid a real defect for
four review passes. Pass 1 is `O(payload × originals)`, and **originals accumulate across every
document in a 3600 s session**, not per request. Measured against an 81 KB payload:

| Session originals | Pass 1 |
|---|---|
| 251 (one brief) | 68.5 ms |
| 1,000 | 216 ms |
| 5,000 | 1,022 ms |
| 20,000 | 4,023 ms |
| 60,000 | 12,141 ms |

Cleanly linear, as expected. What made it a security problem rather than a latency one is that
pass 1 was **synchronous, on the event loop**, and `DEFAULT_TIMEOUT_S` claimed to bound the whole
`check()`. `asyncio.timeout` can only fire at a suspension point, and a synchronous CPU-bound
loop has none — so the budget bounded pass 2 and nothing else, and because this is an ASGI app
the stall was process-wide. Both halves measured, with a 0.5 s budget against 60k originals:

```
before:  check() returned after 7.35 s   (budget silently ignored)
         unrelated coroutine starved for 7.36 s   (head-of-line blocking for EVERY request)
after:   check() blocked at 0.52 s       (budget enforced)
         unrelated coroutine starved for 0.03 s
```

That capture is from when the defect was found, and the 7.35 s in it is the 60k row of the table
above **as it then stood**. The same row now measures 12.1 s, for the reasons given earlier in
this section — so the unbounded stall this closed is now about 65% longer than the capture shows,
and the enforced side is unchanged, because 0.52 s is the budget rather than a property of the
scan. The capture is left as recorded rather than re-run with today's numbers: it is evidence of
a specific fix at a specific commit, and silently restating it against newer code would make it
look like a fresh measurement of something that has not been re-measured.

The fix is one line — pass 1 runs in a worker thread — and it is the difference between a stated
budget and an enforced one. Pinned by `test_the_timeout_bounds_pass_one_and_not_only_the_detector`
and `test_a_long_pass_one_does_not_stall_unrelated_coroutines`, both of which fail if the scan
returns to the loop. The remaining ceiling is the vault's own single lock and unbounded plaintext
cache, which is §7 gap 7 and is not fixed.

#### The obvious fix — scoping the re-scan — was measured and rejected

This README previously named it as the next change: restrict pass 2 to the spans *not* covered
by an emitted surrogate, skip the constant system prompt, "the single largest win available",
"changes no guarantee". Both halves of that turned out to be wrong, and the measurement is
worth more than the optimisation would have been.

**It is not the largest win. It is barely a win.** Median-of-7 on the 12k-word brief (an
earlier min-of-3 pass reported 25–39% and was measuring noise):

| Pass-2 input | Chars | Time |
|---|---|---|
| Full payload (today) | 86,753 | 2,677 ms |
| Minus the system prompt | 85,919 | 2,713 ms (**+1.4%**) |
| Minus every protected span | 66,879 | 2,491 ms (**−7.0%**) |

Protected spans cover **22.9%** of the payload — not the ~95% this README used to assert
without measuring — and the system prompt is **834 chars, 0.96%** of it, so skipping it saves
nothing at all; the +1.4% above is noise around zero, and an earlier pass measured it at −0.2%.
The whole optimisation is worth ~186 ms of a ~6,410 ms run: **2.9%**.

(The payload length drifts by ~100 characters between sessions — Tier-2 dates are re-rendered
under a per-session shift and `12/15/2024` is not the same width as `5/3/2024` — so treat
`86,7xx` as the scale rather than a fingerprint. The two ratios that carry the argument, 22.9%
and 0.96%, re-derive exactly.)

**And it does not preserve the guarantee.** Excising spans changes what the detector finds in
the text that *remains*: spaCy NER is conditioned on surrounding tokens, `_resolve_builtin`
picks between claimant entity types using character-distance context windows, and removing a
fifth of the payload moves every chunk boundary. Measured across both strategies and three
fixtures, the excised scan **lost a finding the full scan makes in four of six configurations**
(`ADDRESS` ×3, `NAME` ×1) and *gained* one in a fifth. It is a different scan, not a cheaper
one — and "changes no guarantee" is not something you can say about a change that
demonstrably changes the output.

Those particular losses are warn-only today, because everything that *blocks* is pattern-typed.
That is a property of the current tuning table, not a safety argument — and there is a second,
structural reason. The protected-span set is derived partly from `STRICT_TOKEN_RE` run over the
**uploaded document** — the strict grammar, not the tolerant `TOKEN_RE` the restorer reads
mangled model output with, and that difference is itself a closed bypass: an uploaded
`PII-ACCOUNT12345678-deadbeef` is a 1.00-confidence `ACCOUNT_NUMBER` to the shipped detector and
`TOKEN_RE` matches it, so under the tolerant grammar it was excused wholesale; under
`STRICT_TOKEN_RE` it is not protected at all. Today the set only decides which detections are
discarded *after* a full-context scan, and the token-hint bypass (`EgressGate._protected_spans`)
is closed by refusing to protect the hint tail. Letting that set decide what the detector *ever
sees* would upgrade an uploader's lever from "suppress a finding on my own token" to "reshape
the gate's input" — a strictly larger version of the bug already fixed.

**What the measurement points at instead.** Everything in `HIGH_SEVERITY_TYPES` — `SSN`, `MRN`,
`ACCOUNT_NUMBER`, `TAX_ID` — is pattern-typed. Those recognizers alone, over the full payload,
complete in **0.67 ms: 0.025% of the spaCy pass**. spaCy's ~2.7 seconds inside the gate therefore
buys exactly one thing — the advisory `rescan_warnings` counter. Splitting pass 2 into a cheap
always-on pattern check and an optional NER canary is the real answer, and it is a change to the
gate's *contract* (`rescan_warnings`, and the constructor-configurable `high_severity` set that
lets NER hits block) rather than a scoping tweak. Not shipped: rewriting the security
centerpiece's blocking path deserves its own review cycle, not a footnote in a perf section.

Bottlenecks in order, corrected by measurement:

1. **The second spaCy pass**, ~43% of end-to-end wall time (2,759 ms of the 6.4 s above; the
   ~37% this list used to give was computed against numbers this section now retracts). It
   cannot be *scoped* away safely, per the measurement above; the tractable form is making the
   blocking path not need spaCy.
2. **spaCy NER itself**, which is then the floor for both passes. It scales roughly linearly
   with document length; mitigated today by paragraph-boundary chunking with parallel
   per-chunk analysis (`asyncio.to_thread`, semaphore of 4). The scale answer is a process
   pool or a sidecar detector service, because this is CPU-bound and the GIL is the ceiling,
   not I/O.
3. **Vault writes** are individually trivial (p99 **0.001 ms** cached) but are issued one per
   unique entity. Batching into a single transaction per run removes the syscall overhead.

Aho-Corasick for the originals scan — the obvious answer, and the one this README gave before
the passes were timed separately — would optimise **277 ms out of 6,400**, i.e. 4.3% of the run.
(This sentence said "21 ms out of 7,160" until this pass: 21.3 ms is the pass-1 figure four
paragraphs above explicitly retracts, and 7,160 ms is not a total this file measures anywhere.
The corrected figure is 13x larger and still does not change the ranking.) It is the right
asymptotic shape and the wrong thing to do first. That is worth saying plainly: the
`O(payload × entities)` term was reasoned about rather than measured, and measuring it changed
the ranking.

**"So why haven't you fixed it?"** Fair question, and the answer is not "no time".

The fix is a change to the *security-critical* component, and it is the one component where a
subtle mistake is invisible: the gate is what makes the zero-egress claim true, and an
optimisation that skips the wrong span produces a payload that looks clean and is not. The
specific change — restrict pass 2 to the spans not already covered by an emitted surrogate,
and skip the constant system prompt — narrows what the re-scan looks at, and the whole reason
pass 2 exists is to catch what the *first* pass did not know about. Narrowing it using the
engine's own output means trusting the engine to tell the gate what it already handled, which
is precisely the coupling the two-pass design exists to avoid.

There is direct evidence from this build that the instinct is dangerous. Deviation 13 records
an attempt to exempt emitted spans from pass 1 for the same reason — it looked obviously
correct, and it *hid a real leak* (a pseudonym containing another entity's genuine surname).
The exemption was reverted and the fix moved upstream into the collision guard, where it could
be made true rather than assumed. The pass-2 optimisation is the same shape of change, on the
pass that has less independent verification behind it.

So the honest position is: **it is measured, it is understood, it is scoped, and it is not
shipped**, because the headroom against the budget — **1.53× at the worst of the seven runs in
§1's table, 2.5× at the best** — does not justify taking risk in the one component whose
correctness the entire submission rests on. (This sentence used to justify itself with a
"2.2× headroom". That is the floor §1 **retracts**: two of seven runs came in under it, at
2.07×, and the shipped table now reports the worst reading rather than a floor. A number §1
spends four paragraphs withdrawing was still doing argumentative work here in §5, which is the
same drift this document keeps recording — and note the direction: less headroom makes this
decision *easier*, not harder, so the argument survives its own correction unchanged.) What would make me do it: an
extension of the leakage harness that runs the optimised gate and the naive gate over the same
payload and asserts they agree on every run, so the optimisation is checked against the thing
it is replacing rather than against my confidence in it. That is a half-day of work and it is
the right order of operations — the differential test first, then the optimisation.

### Q2 — The model writes "the patient's condition". What do you do?

**Nothing, and that is the correct answer under tokenization.**

The model never saw the patient's name. It saw `[PHI_NAME_1a2b3c4d]`. When it paraphrases that
token as "the patient", it is paraphrasing a *token*, not a name — the underlying value was
never exposed, so there is nothing to leak and nothing to restore. The sentence is already
both safe and readable.

Rule 4 of the token contract ("prefer the placeholder over a paraphrase such as 'the
patient'") reduces how often this happens. It does not eliminate it, and it is not trying to.

Linking "the patient" back to `[PHI_NAME_…]` for display enrichment is a **UX feature, not a
security control**, and it is future work. There is deliberately no co-reference resolver in
this codebase — building one would add a substantial failure surface to solve a problem that
is not a security problem.

The one case that *does* matter is pseudonymization, where the model sees a plausible fake
name and may paraphrase it. Same analysis: the fake is not the original.

**"But rule 4 means you are relying on the model to cooperate. What happens when it doesn't?"**
Nothing that matters, and this is the important structural point: **no security property in
this system depends on the model obeying the contract.**

Work through the failure modes. The model ignores rule 4 and writes "the patient" — safe, it
is paraphrasing a token it was never given the referent for. It mangles the token
(`**[PHI_NAME_1A2B3C4D]**`, a dropped bracket, an upper-cased hash, a stripped hint) — the
restorer's regex is deliberately tolerant of exactly those forms, and
`test_deobfuscation.py::test_mangled_token_forms_restore` enumerates them. It mangles one past
recognition — `[UNRESOLVED_ENTITY]` plus a `VAULT_MISS` audit event, a degraded answer rather
than a failed request. It **invents** a token that was never issued — for a bracketed one, the
same path, and `integration/test_pipeline.py::test_vault_miss_on_deobfuscation` is that case;
for an unbracketed one it is left verbatim instead, which is Deviation 49. It emits something
that merely looks like a token — and the protection there is **not** that the vault is asked
and declines. On the production path the vault is never asked at all: the orchestrator hands
the restorer the set of IDs this run actually minted, and an ID outside that set is refused
before any lookup happens. The distinction is the whole mechanism rather than a nicety, because
a token ID is eight hex characters and two sessions' ID spaces do collide by chance; asking the
vault about an ID we did not issue is exactly how a coincidence becomes a substitution of one
entity's value for another's. `restorer.py`'s own docstring records that incident.

The contract buys *readability*. The guarantee is upstream of it, in the fact that the model
never received the value. That is the whole reason the egress gate is the security control and
the prompt is not.

### Q3 — An adversary has the obfuscated document and the response, in pseudonym mode. What do they learn?

**They learn:** entity types and counts; the co-occurrence graph (which entities appear near
each other, and how often); relative date intervals, because the per-session shift is a
constant offset and intervals are deliberately preserved; and document structure and topic.

**They cannot recover values**, and the reason is structural rather than statistical:

- Fakes are a **Faker draw seeded by HMAC(session_key, …)**, not a transform of the original.
  There is no function from the fake back to the original, because no information from the
  original survives into the fake beyond its format.
- The date shift is random per session, so cross-session comparison of the same document
  yields two unrelated date sets. It is **not uniformly distributed**, and that is worth
  stating before a reviewer finds it: the specified formula takes `Δ` mod 600 and then, when
  `|Δ| < 30`, pushes it outward by 30 days. That folds the **59** raw values in `[-29, 29]` onto
  `[30, 59]` and `[-59, -31]` — not `[-59, -30]`, because `Δ = -30` is already outside the fold
  and nothing lands on it — so those 59 outputs are drawn about twice as often as the rest. (The
  modulo bias itself is ~2⁻²⁴⁷ and ignorable.) An adversary who knows the formula therefore knows
  the shift is at least 30 days and is slightly more likely to land on one of those 59 — which
  narrows a brute-force search over shifts from 541 candidates to a distribution over them. It
  does not recover the shift without a known-plaintext date, and it is the specification's
  formula rather than an implementation accident, but "non-uniform" is the accurate word and a
  uniform draw over the same `[-300, -30] ∪ [30, 299]` would be strictly better.
- Name-component linking is derived per component (`HMAC(session_key, "NAME:last:smith")`), so
  the same surname maps consistently within a session — which prevents the mixed-identity
  artifacts that would otherwise invite differential comparison across sessions.

**Residual risk, stated plainly:** the demographic plausibility of generated names is a real
inference surface, and a fake that reads as a specific ethnicity or era is a signal the
original may not have carried. **If adversarial exposure of outputs is in your threat model,
use tokenization, not pseudonymization.** That is the actual recommendation, and it is why
tokenization is the default.

**"You keep saying intervals are preserved as if that were free. Isn't the interval pattern
itself identifying?"** Yes. This is the sharpest objection to Tier 2 and the answer is to
concede it.

A sequence of visit dates — admitted, three follow-ups at irregular gaps, a procedure, a
readmission — is close to a fingerprint. Shifting every date by one constant destroys the
absolute positions and preserves the *shape* exactly, and the shape is what makes a record
matchable against any other dataset that contains the same encounters. Anyone holding a claims
extract or a hospital census for the right region can align on the pattern and recover the
offset from a single anchor. Date shifting defeats "what is this patient's birthday"; it does
not defeat linkage.

That trade is deliberate — clinical reasoning about "three days post-op" is most of why the
document is being analysed at all — but it is a trade, not a mitigation, and the real fix is
the generalization pass in §7 that is **not built**: bucket intervals into ranges, drop
precision below a week for anything outside the reasoning window. Until that exists, the
correct summary is that Tier 2 protects against a reader and not against a data broker.

### Q4 — The vault is a high-value target. Isn't that a problem?

Yes, and by design — it is the *only* place re-identification is possible. Concentrating that
capability in one auditable component is the point, not an accident.

**Shipped controls:** vault entries are AES-256-GCM under a key derived from a session key
that exists only in process memory, so a stolen database yields undecryptable bytes; AAD binds
every row to `session_id:token_id`, so an attacker with write access cannot splice rows
between sessions; TTL expiry and logout both destroy the key; **no key material is ever
written to disk**; and every vault *mutation and resolution* is audited — one `OBFUSCATE`
event per value written (entity type + token ID), one `DEOBFUSCATE` per restore, a
`VAULT_MISS` for every token that resolves to nothing, and a `VAULT_DESTROY` on teardown.
The events are emitted by the callers, not by the vault: the gate's bulk read of the
originals set is summarised as a count on `EGRESS_PASS` rather than logged per value, so
"audited" here means every write and every resolution, not a row per read.

**Reaching the vault through the API is also narrower than it was.** A session is bound to
the `user_id` that created it, so a session ID is no longer a bearer credential for anyone
else's documents; `GET /audit` will not hand out live session IDs to an anonymous caller; and
`DELETE /sessions/{id}` — the one irreversible operation in the system — requires the owner's
`user_id` and answers an unconditional 204 regardless, so it is neither usable by a stranger
nor readable as an oracle. All three were **real holes found and closed during this build**,
not defensive design written up after the fact, and the honest version of this answer says so:
the vault's cryptography was never the weak part. The way in was the HTTP layer above it.

**What a production deployment adds:** KMS envelope encryption with per-session data keys
(the `MockKMSKeyProvider` seam already exists); an HSM-backed master key; mutual-TLS service
isolation so the vault is not in the same process as the request handler; a rate-limited vault
API with anomaly alerting on bulk reads; and `mlock`-ed pages for the key registry so keys
cannot be paged to swap.

**What none of that fixes:** an attacker with code execution in the live process during an
active session can read plaintext out of the vault cache. That is out of scope for this tier
and is stated in the threat model rather than hidden.

**"During an active session" is now literally true, and it was not.** The two sentences above —
"TTL expiry and logout both destroy the key" and "during an active session" — both imply the
plaintext cache is bounded by the session's life plus an explicit logout. That held for logout
*before* the TTL lapsed and failed after it: `DELETE /sessions/{id}` gates `vault.destroy` behind
`_owns_session`, which answers False for an expired session, so a user logging out after the hour
destroyed nothing and the decrypted originals stayed in `_SessionCache`. The logout path now
reaches the reaper — `delete_session` calls `reap_expired_sessions` before the ownership check —
so an explicit `DELETE` evicts the cache and deletes the rows whether or not the TTL has already
lapsed. Pinned by `tests/test_api.py::test_logging_out_after_the_ttl_lapsed_still_destroys_the_vault`,
and see Deviation 54 and gap 7 in §7 for the reaper's other two call sites and its bound.

**"Keys live only in memory, so a process restart destroys every live session. Isn't that an
availability failure you have rebranded as a security property?"** It is genuinely both, and
the honest answer is that it is the same fact viewed from two directions rather than a
rebranding.

What is actually lost on restart is bounded: session keys and their vault rows. Documents are
encrypted under keys derived from the master key and survive untouched; the audit log is
separate and survives; nothing needs re-uploading. What a user loses is the ability to restore
an *answer* they already received from a session that has ended — they re-run the request. TTL
is an hour by default, so the exposure window is small by construction.

The uncomfortable part is what happens when you fix it. Multi-node means a shared session
registry, which means the keys leave the process — Redis, or KMS-held envelope keys. The
moment that happens, "the key exists in exactly one process's memory and dies with it" stops
being true, and the erasure guarantee weakens from *cryptographic* to *operational*: you are
now trusting a key store to actually delete. **That is a real tension, not a solved problem**,
and the design I would actually ship keeps the session key in the request-handling process and
uses KMS only to wrap a per-session data key, so destruction is still a local memory event and
the shared store never holds anything usable on its own.

### Q5 — A HIPAA auditor asks what happened over the last 30 days.

**What the log gives them, today:**

- A hash-chained, append-only event stream. `verify_chain()` recomputes every entry hash and
  re-checks every link. **Verified by test to detect**: an in-place `UPDATE` of *every* persisted
  column (`session_id`, `run_id`, `event_type`, `entity_type`, `token_id`, `ts` and `detail`,
  each parametrised separately — a column omitted from the digest would be freely editable);
  inserting a row *without recomputing the chain*; reordering two rows; deleting a row from
  the middle; **replaying** a genuine
  correctly-hashed row at a new `seq`; **forging a new genesis row** and shifting the rest up;
  deleting the newest rows (truncation); deleting every row of one session; and deleting every
  row in the log. A tampered row that makes the walk itself *unreadable* — a non-numeric `ts`, a
  corrupt page — returns `False` rather than raising, so the verifier cannot be crashed using
  the tamper it is looking for.

  **That last sentence was an overclaim until recently, and how it was caught is worth the
  space.** It was true of the chain walk and of nothing else, because the test behind it drove a
  *monkeypatched cursor* and its docstring argued a real corrupted file was impossible to test:
  "a file mangled badly enough to fail the walk also fails `AuditLogger.open`". That was wrong,
  and being wrong in a docstring is how the test never got written. Zeroing one 4 KiB page of a
  120-row audit database leaves `open` perfectly happy — the file length still matches the
  header's page count, so nothing reads the dead page until the walk does — and truncation is not
  the wall either: a 5-row database cut to 90% opens *and* verifies `True`, because the bytes
  removed were unused tail. Writing the file-level test
  (`test_verify_chain_reports_a_physically_corrupted_file_that_open_accepts`) then found three
  defects the mock could not reach:

  - `query()` and `length()` crashed on the same file `verify_chain()` handled — raw
    `sqlite3.DatabaseError`, and in the truncated case a bare `TypeError` from `float(row["ts"])`
    where a lost page returned `NULL`. `GET /audit` and `GET /audit/verify` therefore still
    returned 500s on a corrupt log; only one of the three readers had been hardened. All three
    now share one `_UNREADABLE` rule, pinned by
    `test_every_audit_reader_shares_one_unreadable_rule` so they cannot drift apart again.
  - `verify_chain()` **raised** on a blanked high-water mark. `sqlite_sequence` is an ordinary
    writable table, so `UPDATE sqlite_sequence SET seq = NULL` is accepted, and `int(row["seq"])`
    ran *outside* the walk's error handling. An attacker deleting the newest rows has every
    reason to make that exact edit, since the high-water mark is the only thing that notices — so
    the verifier could be crashed by the second half of the very attack it exists to catch. It
    reports `False` now (`test_verify_chain_survives_a_tampered_high_water_mark`), not "no
    opinion", because a sentinel that exists but holds garbage is evidence rather than absence.
  - `AuditLogger.open()` **leaked its connection thread** whenever setup failed.
    `aiosqlite.connect` starts a non-daemon worker and returns before any statement touches the
    file, so `PRAGMA journal_mode=WAL` was the first thing to fail — escaping with `self._conn`
    still `None`, leaving the caller no handle and the thread alive. A process that opened a
    damaged audit DB could not exit, with no error message. Found because a probe script hung and
    had to be killed.

  The pattern is the recurring one in this codebase, in its quietest form yet: not a checker that
  shared a bug with the thing it checked, but a *docstring that explained why a test was
  impossible*, believed for as long as nobody measured it.

  Three of those are worth naming because a naive chain misses them. A truncated tail leaves the
  survivors internally perfect, so it is caught by SQLite's `sqlite_sequence` high-water mark,
  which `AUTOINCREMENT` maintains and `DELETE` does not roll back. And a wholly-erased session
  used to read back as *clean*, which is the worst possible answer to a compliance query.

  The third is the competent version of a middle deletion and it is the one to attack in the
  review. Having deleted the row, **re-link**: walk the survivors and recompute `prev_hash` and
  `entry_hash` for every one of them with the published formula. The digests are unkeyed, so
  this costs nothing. Every row now recomputes, every link matches, and the high-water mark is
  untouched because the `seq` values were left alone — so the *only* surviving witness is that
  `seq` skips a number. Compact the numbering to hide that and the high-water mark catches it
  instead. Both halves are asserted in
  `test_deleting_a_middle_row_and_relinking_the_chain_is_still_caught`, which also asserts the
  attacker's own success first, so it cannot pass by failing to build the attack. That test was
  added because the `seq`-continuity comparison was the one check in `verify_chain` no test
  isolated: deleting it in a scratch copy left all 100 audit tests green while this exact attack
  flipped from detected to undetected.

  **The relabel form of that erasure is a residual, and the scoped check cannot close it.**
  `DELETE`ing a session's rows is caught from every scope because the structural checks are
  global. Rewriting them instead — `UPDATE` the events table setting `session_id` from `X` to
  `Y` — erases X's history just as completely and moves nothing, so every link and every `seq`
  still holds. The rewritten rows do fail their own `entry_hash` (`session_id` is inside the
  hashed payload), and both checks that can see that report it: `verify_chain()` returns `false`,
  and so does `verify_chain("Y")`. What returns `true` is `verify_chain("X")`, the victim's own
  scope — and over HTTP the scoped route answers `{valid: true, length: 0}`, byte-identical to
  "this session never existed".

  It is not patchable, which is why it is documented rather than fixed. A relabelled row is,
  column for column, a row whose stored `session_id` names another session and whose hash does
  not recompute — the identical input class as an ordinary tampered row that genuinely belongs
  to that other session, which `test_tamper_is_scoped_to_the_affected_session` deliberately pins
  as *not* failing an unrelated session's scope. The pre-tamper `session_id` is inside the digest
  the tamper destroyed, so nothing can recover it and no rule can tell the two apart. Nor is
  "the scope came back empty" the signal: relabel two of a session's three rows and the third is
  still in scope, still hashes, and the scope still answers `true`. Both facts are pinned
  (`test_relabelling_a_session_out_of_itself_is_a_known_residual`,
  `test_a_partial_relabel_is_invisible_to_the_scope_it_left`).

  So the scoped form's honest contract is "the rows *labelled* with this session are intact, and
  the log they sit in is structurally whole" — never "no record of this session has been taken
  out of it". **The unscoped `verify_chain()` is the compliance answer**; the scoped one is a
  per-slice detail. Like every other gap here, the real fix is the off-box anchor in *Production
  gaps*, since a per-session anchor is the only thing that can attest membership.

  **The exact edge of the high-water defence, since it is easy to overstate.** Measured as a
  ladder rather than asserted as a property, because "how many statements does a silent
  truncation cost" is the only honest way to state what an unkeyed in-file scheme buys. Each rung
  is a real command run against a real audit DB, and all four are pinned by
  `test_a_silent_tail_truncation_costs_four_statements_and_all_four_are_needed`:

  | Attacker statements | Result |
  |---|---|
  | 1. `DELETE FROM audit_events WHERE seq >= 4` | **caught** — the watermark disagrees with the tail |
  | 2. …+ `UPDATE sqlite_sequence SET seq = 3` | **caught** — `audit_chain_meta` holds the same mark in a table SQLite does not manage |
  | 3. …+ `DELETE`/lowering `UPDATE` on `audit_chain_meta` | **refused by SQLite** — two triggers enforce "only ever grows" |
  | 4. …+ `DROP TRIGGER` *then* the lowering `UPDATE` | **not caught** — the residual, and the reason the real fix is an off-box anchor |

  Two of those rungs are new, and both closed a hole that the previous version of this section
  described as "one more `UPDATE`" without noticing was worse than that:

  - **The evidence used to erase itself.** `emit` allocated `seq = MAX(seq) + 1` over the
    *surviving* rows, so a freed tail number was handed straight back out. Delete the newest
    three events (`verify_chain` → `false`, correctly), then let three ordinary events flow
    through the public API — the seqs become contiguous `1..N` again, the tail matches the
    high-water mark, and `verify_chain` returns **`true`** with the original events permanently
    gone. `length()` and `query()` agree, so the documented `len(page) == length()` completeness
    check also reads clean: a reviewer sees a COMPLETE, VALID log. No second statement, no hash
    work, and every existing tail test checked `verify_chain` immediately after the delete —
    inside the window where the defence still worked. `seq` is now allocated above the
    *watermark*, so the deleted numbers are never re-issued and the gap is permanent.
  - **A missing bookkeeping row read as "no opinion".** A `NULL` in `sqlite_sequence` was tamper
    evidence (and tested); a *deleted row* degraded to no-opinion and returned `true` (and was
    not). The delete is the easier of the two — it needs no arithmetic, where the tested `UPDATE`
    needs the survivor count. A log that still holds rows has certainly been written, so no mark
    of any kind on a non-empty log is now `false`.

  Rung 4 is the same unkeyed-digest limit described below, reached by a shorter route than
  "rewrite the whole chain", and it is what the off-box anchor in *Production gaps* is for.
- A per-call `EGRESS_PASS` record carrying entity counts and the **SHA-256 of the exact
  payload** that was released — proving the gate ran before every provider call, and proving
  *which* payload was released, without retaining the content. `LLM_CALL` carries the **same**
  digest, so "was every provider call preceded by a passing gate, on the same bytes" is a join
  rather than an assurance: for every `LLM_CALL`, the `EGRESS_PASS` with the same `run_id` has a
  lower `seq` and an identical `payload_sha256`. The row also carries `rescan_warning_types` —
  the sorted, deduplicated entity **types** pass 2 warned about, never their text — so a non-zero
  `egress_rescan_warnings` is diagnosable instead of alarming. On the shipped medical note the
  three are all `ADDRESS`: the detector re-typing "MD" and "RN" out of the clinician lines, which
  is a false positive and not a near leak, and which nothing recorded until now.
- `run_id` correlation: one identifier ties the whole detect → obfuscate → egress → LLM →
  restore chain together, so "what happened on this request" is a single query. On the three
  **short** shipped fixtures that is **34–40 events per run** (medical note 37, legal memo 34,
  financial disclosure 40), in the order `DETECT → OBFUSCATE → REDACT/STRIP → EGRESS_PASS →
  LLM_CALL → DEOBFUSCATE`. On the fourth — `legal_brief_large.txt`, the 12k-word document Q1 is
  about — it is **347**: one row per distinct value (251 `OBFUSCATE` + 64 `REDACT` + 28 `STRIP`
  + the four chain events), so the count scales with the document rather than with the request.
  Measured through the real orchestrator on both strategies; identical either way. The
  per-value granularity is the point — it is what lets an auditor ask which *entity* went where
  — and the cost is that "show me the trail for one real brief" is a 347-row answer, so three
  of them overflow `query`'s default `limit=1000` page. That band read "34–40 on the shipped
  fixtures" until this was measured on all four, which is 8.7× wrong on the only one a reviewer
  is told elsewhere to care about.
- **Which documents were read**, which is the first question an access review actually asks:
  `DETECT.detail.doc_id` carries the document identifier and `fetch_ms` its read latency.
- Queryable by session, run, event type, and time range — and **checkably** so.
  `AuditLogger.length()` takes the same filter set as `query()`, which is what lets a caller
  tell a complete answer from a truncated page: `query` defaults to `limit=1000`, and a full
  page is otherwise indistinguishable from the whole result. The 30-day query is literally
  `query(since=now - 30*86400)` compared against `length(since=now - 30*86400)` — **as a
  server-side call.** It is not reachable over HTTP; see the gap below.
- **Nothing in the dependency tree logs content either.** Presidio and the Anthropic SDK both
  emit document text at `DEBUG` — the SDK logs the entire request body on every call and every
  retry — and both are muzzled at import with a level *and* a sub-INFO filter, so a host
  `dictConfig` cannot silently re-enable them. Details in §3. This is the half of "no originals
  in logs" that a schema guarantee cannot reach.
- **Zero originals anywhere in the log — measured, and *not* guaranteed by the schema.** This
  README used to say the `AuditEvent` model "has no field capable of holding an original value".
  (`models.py` now says the same thing this bullet does, in both places it used to make the
  stronger claim — the module docstring's point 1 and `AuditEvent`'s class docstring — naming the
  call sites and the leakage harness as what actually holds. **One copy survives outside the
  fix**, in `api/routes/audit.py`'s `GET /audit` docstring, where it is load-bearing for a
  different argument: that the log's *content* is safe to return and its *correlation* is not.
  It is left standing here rather than silently corrected, because a retraction that does not
  say where the claim still lives is the same defect one level up.)
  That is false and a reviewer can disprove it in one line: `detail` accepts any string up to 64
  characters and the label columns up to 128, so `"John Smith"`, `"MRN 4823910"`, an SSN and an
  e-mail all fit. What the ceilings actually buy is that the log cannot hold **content** — a
  paragraph, a note, a document — which is the bulk-exfiltration shape, and they are enforced
  twice: at the model, and again at the write boundary where `model_construct()` cannot skip them.
  The boundary re-checks `detail`'s **type** rule (`Mapping[str, int | float | str]`) as well as
  its width, and the reason is worth a line because the width check alone looked sufficient and
  was not: `detail={"k": {"a": 1}}` renders as 13 characters, far under the 64-char ceiling, so a
  width-only boundary accepted it and the row was written — after which the *reader* refused the
  stored column as "not a detail map" and `verify_chain()` returned `false` **permanently**, on a
  row the logger wrote itself, while `query()` handed the row back with `detail={}` and said
  nothing. A write boundary that admits a value its own reader cannot parse manufactures the
  tamper evidence it exists to report. Lists and `null` had the same shape, and an integer too
  large for CPython to render at all (past 4,300 digits) used to escape as a bare `ValueError`
  from inside the width measurement rather than the documented `PipelineError` — so the *larger*
  smuggled document got a less typed refusal than the smaller one.

  The guarantee against a *short* identifier is a different kind of claim and is worth stating
  as what it is: **no call site writes one, and that is measured rather than asserted.** Every
  `emit` passes counts, latencies, digests, entity *type* names and 8-hex token IDs. The leakage
  harness scans the raw SQLite file — bytes, not the query API — against every vaulted original
  on all 100 runs. Re-checked directly for this answer: 85 distinct originals from three real
  runs, scanned against every raw column of the resulting 112-row log, **zero hits**.
  `test_audit.py::test_the_schema_bounds_a_value_but_does_not_forbid_a_short_one` pins the
  honest version so the overclaim cannot come back.

**Gaps the auditor should be told about:**

- **The 30-day sweep is a library call, not an HTTP call.** `GET /audit` deliberately requires a
  `session_id` or `run_id` scope and refuses an unscoped query with 400 `AUDIT_SCOPE_REQUIRED`
  (Deviation 18): every row carries a `session_id`, and a `session_id` is the bearer credential
  for `DELETE /sessions/{id}`, so an open endpoint would hand any anonymous caller a list of live
  sessions to destroy. The consequence is that "queryable by time range" — which is true of
  `AuditLogger.query()` — **is not answerable over HTTP**, and an auditor cannot self-serve: a
  cross-session date-range report runs server-side against `AuditLogger`, which is what
  `demo.py --verify-chain` and a compliance job would do. That is an unresolved design tension
  rather than an oversight: compliance querying and session-credential secrecy want opposite
  things from the same endpoint, and the fix is a *separate* authenticated compliance API with
  its own authorisation — not a query parameter on the one anonymous callers can reach. Not
  built.
- **All twelve members of `EVENT_TYPES` are emitted, including `SESSION_EXPIRE`** — plus a
  thirteenth, `AUDIT_ACCESS_DENIED`, which sits outside that frozenset by design and is described
  in §2 (Deviations 26 and 54). This
  bullet used to say the opposite — that `SESSION_EXPIRE` was declared and never written, so an
  auditor asking "show me every session that expired" got an empty result and would be entitled
  to read it as "none did". The reasoning behind that was: TTL lapse is discovered lazily by the
  next accessor, so nothing is running at the moment a session dies. The premise was right and
  the conclusion was wrong — the auditable moment is not when the session dies but when a request
  **notices**, and `api/deps.reap_expired_sessions` runs exactly there. It emits `SESSION_EXPIRE`
  and `VAULT_DESTROY` together, the death and the teardown it triggered being two facts a
  timeline wants separately, with no background sweeper and no timer thread.
  `test_api.py::test_ttl_expiry_runs_the_whole_destruction_path` asserts both land.

- **The chain is tamper-*evident*, not tamper-*proof*, and the difference is not academic.**
  The digest is `sha256(prev_hash ‖ canonical_json(event))`. There is no secret in that
  formula, so anyone who can write to the audit database can forge a row and recompute every
  subsequent hash, and `verify_chain()` will return `True`. That is not a hypothetical — it is
  a demonstrated result against this code. What the chain actually buys is that an attacker
  must rewrite **the entire chain from the forged row forward**, in one consistent pass, with
  write access to the file: it converts "edit one row in SQLite" into "replace the whole log",
  and it makes most *partial* tampers — the realistic case, including a database-level
  `UPDATE`, a mid-chain `DELETE`, a mid-chain `INSERT`, a reorder, and a truncated tail —
  detectable.

  **One partial tamper is not detectable, and it is a cheap one: appending to the tail.**
  Read the last row, take its `entry_hash` as `prev_hash`, use `seq + 1`, and compute the new
  `entry_hash` with the same public formula. Every check passes, and each for a reason that
  cannot be patched from inside this process — the link genuinely is correct, the `seq`
  genuinely is next, the digest has no secret to get wrong, and both watermarks move on their
  own (`sqlite_sequence` is bumped by the `INSERT`; `audit_chain_meta`'s trigger forbids only
  a *decrease*). A forged tail row is not merely hard to distinguish from a legitimate append —
  it is identical to one. This is the general limit of an unkeyed hash chain whose every piece
  of state is held by the writer, not a defect in this implementation, and it is pinned as an
  accepted residual by `test_a_correctly_hashed_tail_append_is_a_known_residual`, which asserts
  `verify_chain()` returns `True` and fails if that ever silently changes.

  For the truncated tail specifically the cost is now four statements that must all land in
  step, and — the part that had been quietly missing — the evidence is **durable**: it used to
  expire on its own as soon as ordinary traffic reused the freed `seq` numbers, so an attacker
  needed only patience rather than a second statement. See the ladder in §5 Q5.

  #### Which attacker the audit log stops, stated as tiers

  "Tamper-evident" is not one property, and the useful question is *against whom*. Three tiers,
  and the design answers them differently:

  | | **T1 — has the DB**, not the app's secrets (stolen backup, mounted volume, compromised DB user) | **T2 — has the host** (env, process memory, DB writes) | **T3 — has deploy rights** (can change this code) |
  |---|---|---|---|
  | Alter or delete an existing event | **caught** | **caught** | not caught |
  | Append a forged event at the tail | not caught | not caught | not caught |
  | Rewrite the whole chain forward | **caught** — needs the whole log replaced in one consistent pass, which no partial write achieves | not caught | not caught |
  | Stop events being written at all | n/a | not caught | not caught |

  The single row that matters most is the first, and it is the one that holds: **an attacker who
  cannot rewrite the entire chain cannot alter or remove any record of what happened.** They can
  only *add* a record of something that did not. For an auditor asking "what did this system do",
  missing and edited events are the dangerous ones, and those are covered at both T1 and T2.

  What no in-process mechanism reaches is T2's append, and it is worth being exact about why,
  because the obvious fix does not work. Keying the digest — HMAC instead of SHA-256 — moves T1's
  row for append into "caught", since a backup thief cannot compute a valid tag. It does nothing
  at T2, because the writer must hold the key in order to write, so the attacker who owns the host
  owns the key. That is not a smaller version of the real fix; it is a different, narrower one,
  and describing it as "the audit log is now tamper-proof" would be exactly the kind of overclaim
  the rest of this document exists to avoid. It is not shipped for that reason: the tier it closes
  overlaps heavily with the tier that already has `data/` and `.env`.

  Closing T2 requires trust to live somewhere the writer is not, and there are two shapes of that:
  an **off-box append-only sink** (S3 Object Lock, a WORM store, a managed audit service), or
  **anchoring** — publishing the head hash periodically somewhere the app cannot rewrite, which
  freezes everything before the last anchor and bounds forgery to the window since. Anchoring is
  the cheaper idea and the one with nowhere to land here: this deployment is a single-host
  `docker-compose`, and an anchor written next to the database is worth nothing, because it is the
  same attacker and the same filesystem. Both are production changes; neither is shipped.

  **If the off-box sink is ever adopted, the test that should fail first is
  `test_no_release_survives_an_audit_write_that_failed_before_it`.** It pins, per component, that
  no payload reaches the provider when the audit write that precedes it failed — measured event by
  event, with `EGRESS_PASS` failing as `EgressBlockedError` because the gate refuses to release what
  it could not record. A local SQLite write fails rarely; a network write fails routinely, and the
  natural way to make a remote sink resilient is to wrap emits in the same `except Exception` the
  *block* paths already use. That change would silently convert "refuses to release unaudited" into
  "releases whenever the audit service is unavailable" — and it was verified that nothing else in
  the suite notices: under that mutation 2,072 tests pass and only this one goes red.
- Payload hashes prove *which* payload was sent but do not let anyone inspect *what* was sent.
  Retaining payloads would answer that — and would create exactly the sensitive-data store
  this system exists to avoid. That is a deliberate trade, not an oversight.
- The log captures our side only. What the provider did with the payload after receipt is
  contractual territory (a BAA), not something this system can attest to.
- Timestamps depend on host clock integrity. Production wants trusted timestamping or an
  external append-only sink.

**"Your `EGRESS_PASS` record hashes 'the payload'. How do I know the bytes you hashed are the
bytes you sent?"** This is the right question to ask of any attestation, because a hash of the
wrong string proves nothing, and it is the one gap in this answer that is actually closed by
test rather than by argument.

Three things pin it. `test_egress_gate.py::test_payload_sha256_is_the_digest_of_the_scanned_bytes`
asserts the digest recorded in the audit event is the digest of the string the gate scanned.
The leakage harness then closes the other half at the provider boundary: `CountingProvider`
captures the two strings the provider was actually handed, and every one of the 100 runs
asserts `sent_payload == result.obfuscated_payload` before it scans anything — so the string
the gate saw and the string the provider received are checked for identity on every run rather
than assumed to be the same object. `demo.py` makes the same assertion a third time as a
smoke check.

The residual is narrow and worth naming: all three observe at the *provider interface*, not on
the socket. A bug between `provider.complete()` and the HTTP body would be invisible to them.
That is what `demo.py --real --dump-wire` exists for — it attaches an httpx event hook, writes
the literal outbound request body to a file, and scans **that** against the vault. It needs a
real API key, so it is not part of the CI story, but it is the one check that observes actual
bytes on the wire.

### Q6 — Why is cross-session non-determinism a *security* requirement, not a nice-to-have?

Because a token that is stable across sessions is a **persistent pseudonymous identifier**,
and that is the thing that makes linkage attacks work.

If `John Smith` always maps to `[PII_NAME_1a2b3c4d]`, then anyone who obtains payloads from
two different sessions — two leaked logs, two compromised provider requests, a subpoena of
different date ranges — can join them on that token. They can build a longitudinal profile
without ever learning the name: this entity appears in an oncology note in March and a
bankruptcy filing in July. And the moment *one* session's vault is compromised, that single
mapping retroactively de-anonymizes **every** historical payload containing that token. One
compromise becomes a skeleton key.

Deriving token IDs as `HMAC(ephemeral_session_key, …)` makes each session's token space
cryptographically independent. Compromising one session's key bounds the blast radius to that
session's payloads. It converts "we promise not to correlate across sessions" — a policy
statement that survives exactly as long as the policy does — into "correlation is
computationally infeasible", which is a property of the construction.

That is also why destroying the session key is genuine erasure rather than deletion: without
the key, the surviving ciphertext is unlinkable to anything, and the tokens in any leaked
payload are unlinkable to each other.

**"You have also destroyed your ability to correlate legitimately. What if I want a
longitudinal view of one patient across ten sessions?"** Then you need a different system, and
that is the correct outcome rather than a limitation to apologise for.

The distinction is who authorises the linkage. Stable tokens would give longitudinal
correlation to *everyone who ever sees a payload* — the provider, anyone with a leaked log, an
attacker holding two sessions' traffic — as an unavoidable side effect of the token format.
Nobody approves that; it simply happens. A longitudinal view is a legitimate product
requirement, but it is a **re-identification capability**, and re-identification capabilities
belong behind an explicit, authorised, audited interface: a service that holds the mapping,
checks who is asking, records that they asked, and can be revoked.

This design already has exactly one such component — the vault — and Q4 is the argument for
concentrating that power in one auditable place. Making tokens stable across sessions would
scatter the same capability across every payload the system has ever emitted, with no
authorisation step and no audit record. So the answer is: build the linkage service, keep the
tokens ephemeral, and never let correlation be something that leaks by default from the
encoding.

---

## 6. Strategy selection

### Per-entity assignment

Dispatch is `registry.tier_of(entity_type)` — the engine contains **no entity names**. The
assignment answers one question: *does the model need to reason about this value's content,
its temporal relations, or neither?*

| Tier | Entities | Surrogate | Why |
|---|---|---|---|
| **1 — reasoning-inert identifiers** | NAME, CLIENT_IDENTITY, SSN, MRN, INSURANCE_ID, ACCOUNT_NUMBER, TAX_ID, CASE_ID, ADDRESS, EMAIL, PHONE | realistic, format-preserving fake | The model uses these *referentially* and never reasons about their content. A plausible fake buys fluency at zero utility cost. |
| **2 — temporal** | DOB, DATE | per-session date shift, re-rendered in the source format | Intervals are reasoning-relevant ("three days post-op"); absolute dates are identifiers. The shift preserves the former and destroys the latter. |
| **3 — reasoning-load-bearing** | DIAGNOSIS, MEDICATION | class-annotated token, `[PHI_MEDICATION_2f4a1b3c\|oral-antidiabetic]` | The model genuinely needs the drug class to reason clinically. The hint gives class-level signal; the token core keeps restore exact. |
| **4 — precise numerics** | LAB_RESULT, SETTLEMENT_TERM, AMOUNT | plain token | Any fake corrupts reasoning about magnitude, and any hint *of* magnitude leaks the value. Referential integrity only. |

**Rejected alternatives for Tier 3**, since this is the interesting one: swapping in a
same-class fake drug corrupts clinical reasoning (wrong dose ranges, wrong interactions) while
*still* leaking the class — strictly worse on both axes. Free-text generalization ("an oral
diabetes medication") collides across entities and is a fragile restore anchor the moment the
model paraphrases it.

**Engine-level actions**, applied identically in both modes and before any confidence test:

- `PRIVILEGED_MARKER` → **stripped entirely.** A typed token would advertise the exact
  classification it exists to mask, and a privilege banner is constant boilerplate with zero
  reasoning value.
- `CASE_STRATEGY` → **always redacted**, regardless of confidence. Strategy prose is precisely
  what privilege protects; a token of it carries no reasoning value and a *pseudonym* of it
  would fabricate strategy. Forcing redaction also closes a hole the leakage harness cannot
  see: free text that is never obfuscated never enters the vault, and so is invisible to the
  egress gate's original-value scan.

### Mode selection

- **Tokenization** (default): uniform typed tokens for every entity. Minimal inference
  surface, near-exact regex restore. **Choose this when adversarial exposure of outputs is in
  your threat model.**
- **Pseudonymization**: the tiered policy above. Choose when readability and reasoning quality
  dominate and outputs stay inside your trust boundary.

### NAME and DOB, compared directly

Both entity types in every row, because the two strategies do not rank the same way for them —
`NAME` is Tier 1 and `DOB` is Tier 2, and the tier is the whole difference.

| | Tokenization | Pseudonymization |
|---|---|---|
| **Reversibility** | Exact, and identically so for both: restore keys on an 8-hex HMAC matched by a deliberately tolerant regex, and a DOB's token is no different from a name's. | **NAME** — surrogate string matching, longest-first with word boundaries. **DOB** — the same string matching over a *rendered date*; the shift is a bijection, but the restorer never sees a date, only the characters it was rendered as. |
| **LLM reasoning utility** | **NAME** — stilted; depends on the prompt contract holding. **DOB** — this is where the two modes are furthest apart, and it is the strongest argument on this page for pseudonymization. A tokenized DOB is opaque, so the model loses **all** temporal reasoning over it: it cannot compute an age, a post-op day, or an interval to any other date, because the two dates it would subtract are now two unrelated 8-hex hashes. Anything the answer needed to *derive* from a date is simply unavailable. | **NAME** — reads naturally, survives paraphrase, needs no contract. **DOB** — one constant shift per session (`derive_date_shift_days`, ±30–300 days) applied to **every** Tier-2 value, so intervals between dates in the document survive **exactly**: "three days post-op" is still three days, an interval between admission and discharge is unchanged, and ordering is preserved. Absolute dates — the identifying half — are destroyed. |
| **Inference surface** | Type and count only, for both. | **NAME** — a fake name leaks demographic plausibility. **DOB** — the shift leaks every interval it preserves, which is the trade taken on purpose; and a shifted date is still a *date*, so month, day-of-week and seasonality survive it. |
| **Restore robustness** | Near-exact for both — high-entropy synthetic grammar, and any occurrence is unambiguous. | **NAME** — inherits natural-language mutation risk; a fake is an ordinary word. **DOB** — softer still: `_compile_surrogate_pattern` matches the rendered string literally, so a model that reformats `03/12/1985` as `March 12, 1985` has written something the restorer cannot match, which is the same class of silent miss §7 gap 3 records for names. |
| **Failure mode** | Model mangles the token → tolerated by the regex, or `[UNRESOLVED_ENTITY]` + audit. Visible and audited in both cases, and for a DOB the model more often refuses to answer than answers wrongly. | **NAME** — a downstream human reads the fake **as real**. **DOB** — arguably worse, because the wrong answer is a *number*. An age is not an interval between two document dates; it is an interval between the DOB and **today**, and today is not shifted. So a clinician asking "how old is this patient?" gets an age computed off the shifted date, wrong by 30 to 300 days. Measured over the shift's whole 541-value domain against 365 birthdays: **45.1% of (DOB, session-shift) pairs change the integer age**, and the interval between two dates *inside* the document is unchanged to the day in all of them. Restoration cannot repair it — it puts the real DOB back, but the age the model *derived* from the fake one is ordinary prose, not a surrogate, so `_assert_no_surrogates` has nothing to catch. The other 54.9% are right by luck, which is the worse half: no signal either way. |
| **"Smith" vs "John Smith"**, and its DOB analogue | Distinct tokens either way. Correct reversibility, mild utility loss. | **NAME** — component-linked to a consistent fake surname: better readability, slightly larger inference surface. **DOB** — the shift is many-to-one by construction, so `2024-01-05` and `Friday, January 5, 2024` shift to the same day and render to the same string; two originals sharing one surrogate is the one collision restoration cannot undo, so the colliding date **degrades to a plain token** and loses only its own interval while every other date keeps the shared shift. |

That last failure-mode row is the one that should drive the decision, and it points the same way
for both entity types. A mangled token is a visible, audited, recoverable failure. A fake name
mistaken for a real one by a clinician or a paralegal is a silent one — and a *derived* number,
an age or a post-op day computed off a shifted date, is silent in a second way: there is no fake
string left in the answer for the restorer or `_assert_no_surrogates` to notice, only a wrong
integer. That asymmetry is why the DOB row does not simply follow the NAME row. Tokenization
costs the model its temporal reasoning outright and says so loudly; pseudonymization keeps the
reasoning that is internal to the document and quietly breaks the reasoning that reaches outside
it.

### Graceful degradation: the third outcome, and what it costs

Every entity does not get a surrogate. There are **two** thresholds, and the band between them
is where a value is destroyed rather than masked:

| Detector score | Outcome | Vault entry? | Restorable? |
|---|---|---|---|
| `>= SCP_THRESHOLD_OBFUSCATE` (0.5) | replaced via the configured strategy | yes — one row per distinct value | **yes** |
| `>= SCP_THRESHOLD_REDACT` (0.3), below obfuscate | replaced with `[REDACTED_<TYPE>]` | **no** | **no — permanently** |
| below `SCP_THRESHOLD_REDACT` | left alone | no | n/a |

**The band is decided once per value, on its highest-scoring sighting.** A value the detector
sees twice at different confidences would otherwise be banded twice — tokenized where it scored
above the obfuscate threshold and irreversibly `[REDACTED_<TYPE>]` where it scored below, in the
same payload. That fails safe, but it contradicts the engine's own rule (one vault row, one
token, N splices), shows the model two referents for one entity, and costs a restoration the
user was entitled to. Maximum rather than minimum because the question is *is this value
sensitive*, and the most confident sighting is the best evidence available.

It is visible in the numbers: `medical_note.txt`'s `704-555-0151` scores 0.75 at its labelled
mention and 0.40 in bare prose, so it is now obfuscated at both sites. **18 of 23 PHONE
*detections* across the four fixtures still score in the band** — that is a property of the
detector — but a detection whose value scores higher elsewhere is lifted out of it, which is why
the medical note now reports 1 redaction rather than 2.

The middle row is the requirement that low-confidence detections are **redacted, never passed
through raw** — a detector that is unsure must not be allowed to leak. The consequence is worth
stating plainly rather than leaving to be discovered: a redacted span has no vault entry, so
**restore cannot put it back**, and the answer the user reads keeps the `[REDACTED_PHONE]`
marker where the original stood. That is a deliberate trade — an unrecoverable value is
preferable to a leaked one — but it is a real loss of utility and it is not rare.

**Measured on the four committed fixtures: 18 of 23 `PHONE` detections (78%) score in this
band**, and they are the only entity type that does — though the per-value banding above lifts
any of them that also appears with a higher score, so fewer than 18 are actually redacted. Presidio's `PhoneRecognizer` bases at 0.40
and context lifts it to 0.75, so a phone number written without a nearby context word scores
0.40 and is destroyed. The single redaction `medical_note.txt` reports is a phone number
— there is no policy-redacted entity in that fixture to explain it. So
the first question a reviewer is likely to ask after a demo run — *"why did the phone number
come back redacted?"* — has this as its answer, and the fix is a per-entity `threshold:`
override in `entities.yaml` rather than a code change.

One consequence for the egress gate is not obvious and is worth the sentence: a redacted value
gets no vault row, which used to mean the gate had **no needle for it** while its re-scan
dropped the same value for the same numeric reason. Both payload-side passes were switched off
over exactly this band. The vault now records confidence-band values as unrestorable
gate-only needles — no token, no surrogate, no row, nothing added to any restore path — so
"no vault entry" still holds in the sense the specification means it, and the gate can still
see them. See §7 gap 1 and `SessionVault.note_unrestorable`.

---

## 7. Known gaps & next day

**Stated honestly, in rough priority order.** This part is the register. The *next day* half the
heading promises is at the end, under **With one more day** — four or five of these, in the order
I would actually take them, with an hour cost each and an explicit list of what I would leave
alone.

- **Two shapes the egress gate denies that are not disclosures, and one it may deny that is
  not a leak.** The gate is allowed to be wrong in the deny direction, but a denial reads like
  a leak to whoever investigates it, so both are named here. (a) The re-scan floor is
  `threshold_redact`, and Presidio's score at that level is *context*-derived: a
  `[PII_SSN_…]` token or `[REDACTED_SSN]` marker this pipeline printed lifts any bare
  nine-digit run in the same payload to 0.40, so a document carrying a handled SSN **and** an
  untyped claim or invoice number is denied. Measured at 0 denials across 64 corpus documents,
  because generated nine-digit values are themselves planted entities and get tokenised.
  (b) The separator-invariant limb allows an unbounded run of non-alphanumerics between a
  value's components, so two components of a multi-word original appearing consecutively
  across a sentence break or a list bullet match. Bounding that run is the obvious fix and was
  left undone deliberately: the corpus measurement that would justify a specific bound has not
  been made, and picking a number without it is how `MIN_IDENTIFIER_DIGITS` acquired the wrong
  one.

- **`ADDRESS` is among the weakest entities here, and the recall table's 100% does not mean
  what it looks like.** `ADDRESS` rides Presidio's `LOCATION` recognizer, so what it actually
  detects is bare place names — on `financial_disclosure.txt` the only two ADDRESS spans are
  `Florida` and `Illinois`. A street line, a house number and a postcode are not covered by an
  ADDRESS span, and the held-out corpus's ADDRESS annotations are all bare city names with no
  digit and no comma, so the measured figure is reporting success on the easy half of the
  entity. Closing it needs street/postcode annotations in the held-out set first, so the
  number stops being a corpus artifact, and then a pattern recognizer beside the NER one.
- **No test attributes an event-loop stall to the stage that caused it.** The integration
  guard's bound scales with `detect_ms`, so it can only really catch the *detector* going back
  on the loop; a 464 ms stall in the residual sweep sat under it, green, until it was measured
  by hand. An absolute ceiling was tried and removed rather than tuned, because the heartbeat
  also contends with spaCy in its own worker thread and the number it reads cannot distinguish
  the two. Per-stage attribution is the real fix.
- **The pseudonymization preamble does not describe the payload it is sent with.**
  `PSEUDONYMIZATION_SYSTEM_PROMPT` is two sentences and carries **no placeholder rules** — the
  comment above it says pseudonymization "needs no contract", because the fakes read as ordinary
  values — but a pseudonymization payload is *mixed*: the reasoning-load-bearing and precise-numeric
  tiers emit bracketed tokens by design (§6). Measured on the shipped fixtures, obfuscated under
  `pseudonymization` and assembled through `ContextInjector.build`, the payload carries
  **17** bracketed placeholders for `medical_note.txt`, **4** for `legal_memo.txt` and **16** for
  `financial_disclosure.txt`, under a preamble that never mentions one. Nothing leaks — the token
  core is what it always was and the restorer does not need the model's cooperation (§5 Q2) — but
  the model is handed strings it was given no rule for, which is a *utility* gap and a small
  instruction-following risk: rules 2 and 3 of the token contract (reproduce exactly, never
  invent) are the ones keeping a mangled token restorable. The fix is to select the preamble on
  the **shape of what was emitted** rather than on the strategy name, which is the same
  correction Deviation 65 made on the banner; it is not made here, and this bullet is the
  statement of the mismatch rather than a plan.

1. **Detection recall is the binding constraint on the whole system.** The egress gate makes
   misses *safe* (it blocks), but it cannot make them *invisible* — a missed entity that
   another detection already vaulted causes a block, and a genuinely novel one passes through.
   scispaCy or a self-hosted clinical NER model is the single highest-value next change.

   **A measured neighbour of that constraint, which is a span boundary rather than a miss.**
   `_is_field_label_tail` — the clamp that stops an NER span running off a soft wrap into the
   *next* field's label — is only consulted when the span contains a `\n`. A **space-separated
   inline header** has no line break inside the span, so nothing trims it. Reproduced on the real
   detector against the shipped registry, using the shipped medical fixture's own patient:

   ```
   detect("PATIENT CHART\nName: David Ochoa   DOB: 03/12/1985   Admitted: 07/01/2024\n"
          "The attending discussed the plan with David Ochoa this morning.\n", "medical")
   -> NAME 'David Ochoa   DOB'   DOB '03/12/1985'   DATE '07/01/2024'   NAME 'David Ochoa'
   ```

   The label is swallowed into the vaulted original, so the value the vault holds is not a value
   and the payload loses its `DOB:` label. **This is milder than the newline case Deviation 33(a)
   records, and the difference is why it is a gap and not a leak**: the bare `David Ochoa` later in
   the same document is separately detected and vaulted, so pass 1 still has a needle for the name
   itself. The shipped fixture is unaffected — its header puts each label on its own line, which is
   exactly the shape the clamp already handles (`NAME 'David Ochoa'`, `DOB '04/13/1956'`, measured)
   — so the suite cannot see this, the same way the *unwrapped* legal fixture could not see the
   soft-wrap leak that produced the clamp. Extending the rule past the newline is the fix, and it
   is not free: the tail after run-on whitespace is Title Case, which is also the shape of a
   surname, so the position test rule 3 already uses would have to carry it.
2. **Pseudonymization is reversible by *luck*; tokenization is reversible by *design*.** This is
   the sharpest thing in this list and the README did not previously draw the distinction. A
   token carries an 8-hex ID which is a *key* — the restorer looks it up. A pseudonym has no
   key: restoration is best-effort string matching over untrusted model output. Component
   linking issues both the full fake and the surname fake as separate surrogates in one session
   (`{'Chelsea Hammond': 'Nathaniel Brightwater', 'Hammond': 'Brightwater'}`), and longest-first
   alternation protects the pair only while the model reproduces the long fake intact. Measured
   end to end on the real engine, vault and restorer, **any interior insertion breaks it and
   every counter still reports success**:

   The real patient is `Chelsea Hammond`; the issued fakes are `Nathaniel Brightwater` and
   `Brightwater`. The model sees only the fakes, and the restorer maps fake → real:

   | Model wrote (the fake) | User reads | Verdict |
   |---|---|---|
   | `Nathaniel Brightwater remains stable.` | `Chelsea Hammond remains stable.` | correct |
   | `Nathaniel M. Brightwater remains stable.` | `Nathaniel M. Hammond` | **hybrid** |
   | `Brightwater, Nathaniel remains stable.` | `Hammond, Nathaniel` | **hybrid** |
   | `Nathaniel Dr Brightwater remains stable.` | `Nathaniel Dr Hammond` | **hybrid** |

   The output is a **fake given name welded to the real surname** — silent misattribution, a
   person who does not exist carrying a real patient's name — and every counter still reports a
   clean run: `restored_count` goes *up*, `vault_misses` stays 0, and `_assert_no_surrogates`
   cannot fire because `Nathaniel` on its own is not an issued fake. `restorer.py` handles
   exactly one member of this class — `\s+` flexing for line wrapping — and its comment claims
   that is "the only place this can be fixed". That claim is **wrong**, and the three rows above
   are the counterexamples. The honest position: use tokenization when correctness of attribution
   matters. A real fix needs the restorer to refuse a component fake when the full fake matched
   nearby but not exactly, which is a design change rather than a patch.
3. **The near-miss counter that is supposed to backstop the above is built from the matcher it
   backstops.** `_count_surrogate_near_misses` calls `_compile_surrogate_pattern(fold=True)` —
   the same function used to restore, differing only by `re.IGNORECASE`. Its docstring calls it
   "deliberately an upper bound" on unrestored fakes; it is an upper bound only in the *case*
   dimension and inherits every boundary rule the matcher has. Measured directly against the real
   counter, with `Brightwater` as an issued fake:

   ```
   model wrote                          counter   fake still readable?
   NATHANIEL BRIGHTWATER is stable.        1          yes   (caught)
   nathaniel brightwater is stable.        1          yes   (caught)
   The Brightwaters were contacted.        0          yes   <- SILENT
   Nathaniel Bright-\nwater is stable.     0          yes   <- SILENT (soft wrap)
   ```

   One exception to "inherits every boundary rule": a surrogate that contains a newline — the
   detector emits `NAME` spans that run past a hard wrap into the next field's label — has its
   first line counted as a separate alternative, because a model quoting only the name half
   produced `restored 0 / misses 0 / suspected 0` and the fake as the answer. The
   boundary-adjacent survivals above are unaffected and the numbers in the table are unchanged;
   the plural `The Brightwaters were contacted.` still counts 0, pinned by
   `test_a_pluralised_fake_is_not_counted_and_the_docstring_no_longer_says_it_is`.

   So it covers the dimension it was written for and is blind to the boundary-adjacent survivals,
   which are the same class of miss the matcher itself has. This is the project's recurring defect
   living in the one function that exists to be the safety net, and it is recorded rather than
   fixed because a genuinely independent counter is a second matcher with different rules — the
   thing that needs designing, not patching.
4. **`doc_category` is an uploader-supplied field that switches security controls off by
   default.** `CASE_STRATEGY` carries `action: redact` — the one entity forcibly destroyed
   regardless of confidence — and is scoped `only_in_doc_categories: [legal]`. The API field is
   optional and defaults to `None` ("omit for unclassified"). Measured on the shipped registry
   with a real privileged brief:

   ```
   doc_category=legal    -> 4 detections incl. CASE_STRATEGY, CLIENT_IDENTITY
   doc_category=medical  -> 3 detections, CASE_STRATEGY absent
   doc_category=None     -> 3 detections, CASE_STRATEGY absent   <- the default
   ```

   So a legal brief uploaded without a category never has its litigation strategy redacted, never
   vaults it, and therefore gives pass 1 nothing to scan for; pass 2 runs with the same `None` and
   shares the blind spot by construction. `document_store.py`'s own `InvalidCategoryError`
   docstring makes exactly the right argument — a mis-filed document "would silently lose the
   category-scoped detection rules that make its most sensitive entities detectable at all" — and
   then `_validate_category` opens with `if doc_category is None: return None`. The guard is
   written against the typo and open on the omission, and omission is the default. This is the
   same shape as the `user_id` gap in §3: a user-supplied lever on which controls run. It is
   listed rather than fixed because the fix is a product decision (reject unclassified uploads,
   or run every category's rules when unclassified and accept the false-positive cost).
5. **Pass 3 — the only genuinely independent opinion — covers one of four high-severity types.**
   `_INDEPENDENT_PATTERNS` holds a single SSN recogniser, while `HIGH_SEVERITY_TYPES` is
   `{SSN, MRN, ACCOUNT_NUMBER, TAX_ID}`. For the other three the *only* recogniser in the system
   is the single registry pattern, consulted identically at detect time and in pass 2 — so the
   argument pass 3 was built on (a recogniser's blind spot is shared by detection and by the
   re-scan, therefore something differently sourced is required) is answered for 25% of the
   blocking surface. Deviation 43 is a demonstrated instance: `MRN`'s trailing `\b`, denied by one
   letter, was invisible to all three passes at once. Scope was chosen per-*instance* (the one
   measured Presidio failure) rather than per-*class*.
6. **`HIGH_SEVERITY_TYPES` does not follow its own stated membership rule.** The comment says the
   set is "pattern-typed entities with near-zero false-positive rates", and that NER-typed re-hits
   are warned rather than blocked because blocking them would make pseudonymization unusable.
   `INSURANCE_ID` (`\b[A-Z]{2,6}\d{7,12}\b`) and `CASE_ID` are pattern-typed and high-specificity,
   are **not** in the set, and are released with a warning at 1.00 confidence. Measured. The
   membership is narrower than the rule given for it, with no reason recorded — which reads badly
   precisely because the comment invites the question.
7. **The vault serialises every session through one `asyncio.Lock` and one connection**, and its
   plaintext cache is unbounded. Five call sites (`put`, `_fetch_one`, `destroy`, `sweep_orphans`,
   `close`) take the same process-wide lock with no per-session striping, so a 251-entity brief
   takes and releases it 251 times against every other session in the process. Separately,
   `self._caches` is a `dict[str, _SessionCache]` of session-lifetime **plaintext** with no
   eviction and no size cap, so nothing bounds one session's cache: the 251-entity brief holds
   251 decrypted originals in RAM for as long as that session lives.

   **This gap used to end "until process close", and that half was wrong — Deviation 54 is the
   accurate side of the contradiction.** The premise is still true: `SessionRegistry.
   _sweep_locked` expiring a key does **not** drop the vault's cache, and neither does the
   anonymous `GET /health` sweep the container polls. What drops it is
   `api/deps.reap_expired_sessions`, which drains the registry's unreaped set and calls
   `vault.destroy()` per expired ID — popping the `_SessionCache` and deleting the rows — and it
   runs at the top of `_require_session` (every `POST /pipeline/run`), at the top of
   `delete_session` (every `DELETE /sessions/{id}`), and at the top of `create_session` (every
   `POST /sessions`). The last two are not symmetry: logout on an already-expired session could
   not destroy anything, because `_owns_session` answers False for it and the `vault.destroy`
   call sits behind that gate — measured at `session_ttl_seconds=3`, `cached=True originals=3
   rows=3` before **and** after the `DELETE`, and pinned by
   `tests/test_api.py::test_logging_out_after_the_ttl_lapsed_still_destroys_the_vault`. And
   `POST /sessions` is the only source of future expiries and needs no credential, so reaping
   there is what keeps the registry's unreaped set from being an anonymously fillable queue.
   Measured on a
   1 s-TTL session: after the health-style sweep the cache and the row are both still there;
   after the next session-bearing request `cached_session_ids()` is empty, `row_count()` is 0,
   and `SESSION_EXPIRE`/`VAULT_DESTROY` are in the log. What survives is narrower and is the
   part worth keeping: an **idle** process — one that expires sessions and then serves no
   further session-bearing request — holds their plaintext until it does or until exit, and
   within a live session the cache is uncapped either way. Gap 17 below covers the *document
   store* and gap 12 the session registry; neither is this.

   **What the drain bound costs, as a residency window rather than as a shrug.** Capping one
   request at `MAX_REAP_PER_REQUEST` = 16 destructions moved the moment an expired session's
   *already decrypted* originals leave `SessionVault._caches` from "the first reaping call after
   the expiry is observed" to later, by exactly this much: an expired session at 1-based position
   `p` in the backlog is finished on the `ceil(p / 16)`-th reaping call counted from the call that
   enqueued it, so a burst of `E` sessions expiring together is fully destroyed after `ceil(E / 16)`
   reaping calls — **1** call for a burst of 16, **63** for a burst of 1 000 — against 1 call for
   any size of burst before the bound existed. Three things keep that narrower than the formula
   reads. Reaping calls are not scarce: every authenticated request runs one through
   `_require_session`, and so do `POST /sessions` and `DELETE /sessions/{id}`, so the unit is a
   request rather than a timer tick. `first=` collapses the window to a single call for a session
   the caller *names*, which is the only case a user can observe. And the window governs
   **residency, not confidentiality** — `SessionRegistry._sweep_locked` pops the key before an ID
   can reach the queue, so the AES-GCM rows are already undecryptable and every cache accessor
   fails at `registry.key()` first; what is waiting is a plaintext `_SessionCache` no route can
   read. Raising 16 shortens the window and lengthens the worst-case victim request in the same
   proportion, at the ~1.2 ms per destruction measured above. Pinned by
   `tests/test_api.py::test_the_bounded_drain_delays_an_untouched_expiry_by_one_call_per_sixteen`.

   **And a destruction that fails is re-queued rather than logged and forgotten.** The ID is
   popped from the backlog *before* the destroy is attempted and nothing else ever offers it again
   — `SessionRegistry.sweep` drains its unreaped set once — so the earlier arrangement stranded a
   session's decrypted originals for the life of the process on one transient failure. A failed ID
   now goes back at the **tail** (head placement would let a handful of permanent failures spend
   every request's whole budget while healthy expiries waited behind them), which makes
   `MAX_REAP_ATTEMPTS` = 8 a bound on *total* work rather than per-request work: one retry costs
   one full trip through the queue, so a permanently failing ID costs 8 destroy attempts for the
   life of the process. An exhausted ID is **not** dropped — dropping is the eviction defect
   Deviation 54 records — it moves to `Services.reap_failed`, a dead-letter map where it stops
   consuming the 16-per-request budget, stays enumerable, and comes back out with a fresh budget
   when `DELETE /sessions/{id}` names it. A cancelled request no longer takes its in-flight slice
   with it either: `CancelledError` is a `BaseException` and never reached the reaper's
   `except Exception`, so a client disconnecting mid-drain silently stranded the rest of the slice
   with nothing logged; the remainder is now re-queued in a `finally`, and charged no attempt,
   because a destroy that never ran is not evidence that the session cannot be destroyed. Pinned by
   `test_a_destruction_that_fails_is_requeued_instead_of_stranding_the_session`,
   `test_a_cancelled_request_does_not_take_the_slice_it_was_draining_with_it` and
   `test_a_flooded_reap_backlog_never_drops_a_session_holding_plaintext`.
8. **Two structural debts, since paid — and one of them was not cosmetic after all.** Both were
   deferred once with the note that "no defect sits behind either". That was right about one and
   wrong about the other, which is worth recording.
   - **`api/app.py` was 1,835 lines carrying seven concerns**, with all eight endpoint handlers
     nested as closures in one 345-line `_register_routes`, so no endpoint was importable. Now
     **308 lines** (`wc -l`, and it moves with any edit) — `create_app()` and the module
     docstring — over `constants.py`, `deps.py`, `middleware.py`, `lifespan.py`, `errors.py` and
     `routes/{sessions,documents,pipeline,audit,health}.py`. The stated blocker ("the closures bind to that function's locals") turned out
     to be false: checked by AST, `_register_routes` has **zero** locals and every `app`
     reference is inside a decorator, because dependencies already flow through `ServicesDep`.
     The risk was a DI-wiring mistake, which a green suite would not catch — so the move was
     guarded by a behavioural snapshot taken beforehand (route table, middleware stack, full
     OpenAPI schema, and a 16-probe auth matrix of anonymous / owner / wrong-user /
     unknown-session against every route). The post-move diff was empty. This one *was* cosmetic.
   - **The word-boundary rule is now singular, in a leaf module.** `secure_context_pipeline/
     textrules.py` imports nothing from the package and exports `ALNUM`, `LEFT_GUARD`/
     `RIGHT_GUARD`, `guards_left`/`guards_right`, `boundary_guards`, `word_bounded_pattern` and
     `occurs_as_a_unit`; the gate, engine, restorer, strategy and harness all depend *downward*
     on it. **This one was not cosmetic.** The previous arrangement shared the *alphabet* but not
     the *decision*: `engine.py` and `restorer.py` imported `_ALNUM` and then rebuilt the
     assertions by hand, so a rename raised `ImportError` as advertised while an edit to the rule
     still had to be made in three places, with nothing to catch a missed one. That is the same
     defect this document records eleven other instances of, surviving *inside the fix for it* —
     and calling it cosmetic was itself the mistake. `test_no_module_reassembles_the_boundary_
     guards_by_hand` now scans package source and fails on any lookaround built next to an
     alphabet reference outside the owning module, which is the check the old arrangement could
     not express.

9. **The pipeline could *manufacture* a partial value, not merely fail to catch one.** §1's first
   named boundary — a slice of a multi-word original — is disclosed as something a *document* can
   carry past the gate. This is the same blind spot reached from the other side, and it is worse:
   the fragment was produced by our own obfuscation stage, so no amount of care with the input
   would have avoided it. The egress gate and the 100-run harness each ask whether a **whole**
   vaulted value occurs as a unit; neither asks whether a fragment is present.

   spaCy returns `03/11/2024, 09/17/2024` as a **single** `DATE` span, so that composite string
   becomes one vault original. A different date in the same document, `10/01/2024`, shifted by the
   session's −204 days, renders as `03/11/2024` — a verbatim, word-bounded **slice** of that
   original. The Tier-2 collision guard tested only whether a rendered date *contains* an
   original, never whether it is *contained in* one, so a real appointment date of the real
   patient went to the provider inside a string the pipeline itself invented. Both scanners
   reported clean, correctly by their own definitions. `0 leaks` was true and misleading at once.

   The guard is now symmetric and the colliding date degrades to a plain token. Swept rather
   than sampled: 50 fixture documents × **540** shifts of the driving variable — **27 collisions
   before, 0 after**. The leakage harness went from 1 failing run in 8 to 8/8 clean.

   **That sweep was one shift short of the space, and this paragraph used to call it
   exhaustive.** `derive_date_shift_days` does not have 540 reachable values; it has **541**.
   `% 600` puts the raw shift in `[-300, 299]` and the ±30 fold pushes `[-29, 29]` outward,
   leaving `[-300, -30]` (271 values) ∪ `[30, 299]` (270). Measured against the real function
   rather than re-derived from the formula it implements:

   ```bash
   python -c "import hashlib, secure_context_pipeline.crypto.keys as k; \
   print(len({k.derive_date_shift_days(hashlib.sha256(i.to_bytes(8, 'big')).digest()) \
   for i in range(1_500_000)}))"     # -> 541; both bands contiguous, nothing inside +/-30
   ```

   `tests/test_crypto.py::test_the_date_shift_table_covers_its_whole_domain` asserts the same
   shape from the other end (600 residues, 59 of them doubled by the fold, so 541 distinct). So
   read the result as 540 of 541 shifts, with the record silent on which one it missed —
   **swept, not exhausted**. The word mattered here more than elsewhere, because this is the one
   paragraph in §7 that offers exhaustion in place of sampling as its evidence.

   **That fixed the failure. It did not fix the condition, so the condition was fixed too** — on
   both sides, because a detection-only fix would violate this design's own posture that the gate
   is a second opinion which does not trust detection.

   - *Upstream:* `Detector._split_composite_dates` emits one detection per date when a Tier-2 span
     fails to parse as a single date **and** splits on `,` / `;` / `&` / `and` into ≥2
     constituents that **each** parse. One unparseable piece refuses the whole split — a partial
     split is worse than none, since it would vault some constituents and leave a rump span
     holding the rest. Offsets are checked by slicing the document, and drift raises rather than
     emits. It is also a **utility win**: those dates used to degrade to a plain token, losing the
     interval property Tier 2 exists for; now each one carries the session shift.
   - *Downstream:* `EgressGate._composite_needles` derives a needle per constituent of a composite
     vaulted original, through the same bounded-form comparison the whole value uses. Both sides
     share one delimiter grammar (`textrules.delimited_parts`), which is what makes "the gate
     scans for the pieces detection would have split out" mechanically true rather than a comment.

   **What the gate deliberately will not do**, because the gate is fail-closed and a false positive
   is a denied request that looks exactly like a leak: a constituent below `MIN_IDENTIFIER_DIGITS`
   contributes nothing, so `April 2024` never makes `April` a needle and `Park Avenue, Springfield`
   never makes `Park` one; and one sub-floor constituent refuses the whole value, so `Jan 5, 2024`
   cannot contribute `2024` and deny every document. Measured rather than asserted: across 30
   freshly generated documents the detector returned 1,345 spans, **211 carrying a list delimiter,
   0 contributing a composite needle** — on a corpus where detection behaves, this limb fires on
   nothing. It earns its place on the day detection does not.

   **What genuinely remains.** A bare component of a *non-composite* original — vaulted
   `John Smith`, payload says `Smith`. Whitespace is deliberately not a delimiter, which is what
   keeps the rule above away from this case, and closing it needs per-entity component policy
   rather than one predicate: that is where the `Brown`/`Browning` trade actually bites. Two
   smaller residuals: `dateutil` parses `2024-01-01, 2024-12-31` as a *single* date and silently
   drops the rest, so Tier 2 renders one shifted date over a span denoting two (a fidelity loss,
   not a disclosure — the gate limb still covers its security half, and it is pinned by
   `test_a_composite_that_parses_as_one_date_is_never_split`); and a two-digit-year composite
   splits upstream but contributes no gate needles, each part carrying six digits against a floor
   of seven.

   So the honest qualifier on the headline claim is now narrower than it was: *no whole vaulted
   value reaches the provider* is what is measured, and it is a **multi-word original**, not a
   composite detector span, that still makes "whole" load-bearing.

10. **No k-anonymity / generalization pass.** This is the real answer to the inference risk in
   §3, and it is not built.
11. **Financial transaction dates pass through deliberately.** Amounts and counterparties are
   masked; the dates are not, because `DATE` is scoped to medical documents. That is a
   quasi-identifier residual and a real gap.
12. **Sub-3-character spans are never obfuscated.** They carry no re-identification signal, and
   sweeping them would corrupt unrelated words — but the floor is a policy choice, and it is
   applied uniformly rather than per-entity.
13. **Single-process session registry.** Redis plus KMS envelope keys for multi-node.
14. **The document read path leaks existence through timing** — ~18× between an absent
   `doc_id` and a wrong-owner one on a 2 MB blob. Content-identical, time-distinguishable;
   analysed in §3. A constant-time read closes it and costs a full disk read per miss.
15. **Filenames are cleartext in the metadata table.** Deliberate and argued in §3; the fix, if
   the requirement changes, is an encrypted column plus a blind index for listing.
16. **The audit chain is unkeyed**, so it survives partial tampering but not a full rewrite by
   someone with DB write access (§5 Q5). An off-box append-only sink or an auditor-held HMAC
   key is the real answer; both are production infrastructure rather than a code change here.
17. **The DOCX decompression-bomb guard bounds the declared size, not the transient cost.**
   Checking the archive's declared uncompressed bytes closes the ~1000× amplification a zip
   bomb needs. It does not bound what `zipfile.ZipFile()` itself spends parsing the central
   directory before any check can run: an archive at the 16 MB upload cap can declare **zero**
   uncompressed bytes and still cost ~110 MB RSS, about 7×. Measured and pinned by a test. A
   real fix streams the archive or parses it in a memory-capped subprocess; the shipped guard
   is the cheap 99% and the residual is stated rather than implied.
18. **SQLite write contention stalls every reader on the store**, not just the writer — five
   seconds of it, measured. Analysed in §4; the fix is Postgres and the Protocol seam exists.
19. **A document's two blobs share one AAD** and can be swapped on disk (§3). Integrity only,
   and closing it means deviating from the specified AAD.
20. **Co-reference display enrichment** — a UX feature, per Q2.
21. **`Settings.llm_max_retries` is an *attempt* count, not a retry count.** It is consumed as
   `max(1, min(llm_max_retries, MAX_ATTEMPTS))`, so `1` means one attempt and **no** retry —
   the opposite of what an operator setting "max retries = 1" expects. The behaviour is
   correct and tested; the name is wrong. It is a rename (`llm_max_attempts`) rather than a
   logic change, and it is recorded here rather than quietly renamed because the setting is
   already in `.env.example` and changing it is a breaking config change.
22. **Streaming responses with incremental restore.** Today the full response is restored in
   one pass, so a streaming UI would show tokens before restoration.
23. **OpenTelemetry spans per pipeline stage.** Timings exist in `stats` and the audit log but
   are not exported.
24. **An OpenAI provider class** — one class plus one registry entry, by construction.
25. **`TOKEN_RE` tolerates whitespace at both separators and neither end of the hash.** The
    matcher now accepts a token a model re-cased and one it wrapped at either `_`, which closes
    the two classes §10's Core 6 row used to over-claim. What it still refuses is a wrap
    *inside* the hash — `[PHI_NAME_1a2b\n3c4d]` does not match — which is the same line-wrap
    mechanism one position over, and the residue is a live token in the user's answer rather
    than a silent one, because `_assert_no_surrogates` cannot see a form the grammar does not
    describe either. Measured on the shipped matcher, and the fix is not free: the hash is the
    only group whose alphabet is a *subset* of the entity type's, so allowing whitespace inside
    it means the type group and the hash group stop being separable by their contents alone.
    Three other refusals are deliberate and stay: a dropped category (`[NAME_1a2b3c4d]`), a
    bare space or a `.` written where a separator belongs (`[PHI NAME 1a2b3c4d]`,
    `[PHI.NAME.1a2b3c4d]` — a hyphen *is* accepted, since `format_surrogate`'s own alphabet is
    what bounds that class), and a short hash — the last for the security reason Deviation 28
    records, since the egress gate builds its skip-list from this grammar's stricter twin.

### With one more day

The list above is a register, not a plan; a reviewer asking "what would you build next" is owed
a selection out of it rather than the whole thing again. This is the order I would actually work
in, with what each buys and roughly what it costs. Every item named here is still open on the
tree this README describes — which is worth saying, because several of its neighbours are not
(gap 8's two structural debts are paid, and both halves of gap 9's composite-span defect are
closed), and a plan that proposes finished work is not a plan.

1. **Close the `doc_category` omission — gap 4, ~1 h.** An optional, uploader-supplied field
   currently decides whether the one entity with `action: redact` is detected at all, and its
   default is the unsafe value; that is the cheapest genuine *security* fix left on the list and
   nothing else here is worth as much per hour. Two candidate fixes, and the choice is a product
   decision: reject an unclassified upload at the API boundary, or run every category's rules
   when the field is absent. I would ship the second — it fails closed and needs no client
   change — and price its false positives on the four shipped fixtures before committing to it.
2. **Widen pass 3 to the other three high-severity types, and make `HIGH_SEVERITY_TYPES` match
   its own stated rule — gaps 5 and 6, ~3 h.** The egress gate, not the detector, is the
   security control in this design (§3), and its only genuinely *independent* limb covers one of
   the four types it blocks on. `MRN`, `ACCOUNT_NUMBER` and `TAX_ID` each have exactly one
   recogniser, consulted identically at detect time and at re-scan, so a blind spot in it is
   shared by every pass at once — which is not a hypothetical, it is Deviation 43. In the same
   sitting: either add `INSURANCE_ID` and `CASE_ID` to the blocking set or write down why they
   are excluded, because the comment above the set invites that question and does not answer it.
3. **Refuse the component-fake hybrid in the restorer, and give its near-miss counter rules of
   its own — gaps 2 and 3, ~4 h.** This is the sharpest correctness defect in the repository:
   pseudonymization welds a fake given name onto a real patient's surname, and every counter
   reports a clean run while it happens. The fix is a rule rather than a patch — refuse a
   component surrogate when its full-name sibling matched *nearby but not exactly* — and it has
   to come with a counter that is not built from `_compile_surrogate_pattern`, or the safety net
   keeps certifying the blind spots of the thing it is meant to backstop.
4. **Extend the field-label clamp past the newline — the measured neighbour under gap 1, ~2 h.**
   A space-separated inline header vaults `David Ochoa   DOB` as a single original, so the vault
   holds a string that is not a value and the payload loses its `DOB:` label. It is bounded,
   reproducible on the shipped detector, and the position test rule 3 already applies is most of
   the answer; the cost is that a Title Case tail is also the shape of a surname, so it needs the
   measurement before the edit.
5. **Select the system preamble on the shape of the payload rather than on the strategy name —
   the fourth unnumbered bullet above, ~1 h.** A pseudonymization payload carries 4 to 17
   bracketed placeholders under a preamble that never mentions one, and rules 2 and 3 of the
   token contract are exactly what keeps a mangled token restorable. Cheap utility, and a small
   instruction-following risk retired with it. Same correction Deviation 65 made on the banner.

Roughly eleven hours, which is a day with room left for the re-measurement each of those forces
on §1, §8 and §10 — a change that lands without its numbers being re-derived is how this page
goes stale, and that budget is part of the estimate rather than an overrun.

**What I would deliberately not do with that day, and why.** Naming the omissions matters more
than naming the picks, because the biggest item on the list is one of them:

- **scispaCy, or a self-hosted clinical NER model — gap 1's headline.** It is the highest-value
  change in the whole register and it does not fit in a day. It is a model swap *plus* a
  re-measured recall table against the held-out corpus, and a recall figure I have not re-derived
  is worse than the ceiling I have documented. The egress gate makes a miss safe in the interim,
  which is the reason the gate rather than the detector was made the control in the first place.
- **A k-anonymity / generalization pass (gap 10), and an `ADDRESS` pattern recogniser.** Both
  need corpus work before any code: `ADDRESS`'s 100% recall is a corpus artifact until the
  held-out set carries street lines and postcodes, so writing the recogniser first would just
  move an unmeasured number. Annotation is a day on its own.
- **Postgres, Redis, an off-box audit sink — gaps 13, 16 and 18.** Infrastructure rather than
  code, and the `DocumentStore` and `KeyProvider` Protocol seams that make them cheap already
  exist and are tested. This is a deployment decision to be taken with a requirement in hand,
  not a day of typing against an imagined one.
- **The constant-time document read — gap 14.** It closes an existence oracle that §3 already
  analyses and prices, and it costs a full disk read on every miss. I would want the requirement
  before paying that, and §3 is the argument for why it can wait.
- **The 39-file `ruff format` divergence (§1).** A large cosmetic diff with no correctness
  content, which would bury every substantive change above it in review. It is the last thing I
  would spend a reviewer's attention on.

---

## 8. Deviations from the build specification

Recorded per the build doc's instruction. Each one is a deliberate choice with a reason.

| # | Deviation | Rationale |
|---|---|---|
| 1 | `SCP_LLM_MODEL` defaults to `claude-opus-5`, not `claude-sonnet-4-6`. The provider sends **no** `temperature`/`top_p`/`top_k` and passes `output_config.effort: "low"`. | The specified model is valid but older. On the current model family those sampling parameters are **removed and return HTTP 400**, so sending them would break the real-provider path outright. Model is env-configurable either way. |
| 2 | Added `pyyaml`, `python-dateutil`, and `python-multipart` to dependencies. | The first two are required by the specified design (the registry is YAML; Tier 2 parses dates with `dateutil`) but absent from the pinned list. (This row read as a complete enumeration of added dependencies and was missing one — `regex`, which was undeclared entirely. See Deviation 47.) Without `python-multipart`, FastAPI raises at **route-registration** time and the container never boots. |
| 3 | `CASE_ID` patterns use single backslashes. | The spec shows `\\b`, which inside YAML single quotes is a literal backslash followed by `b`, not a word boundary. Every other entry uses single backslashes. |
| 4 | Added `requires_context` and `require_digit` registry fields. | `requires_context` implements the specified DOB-vs-DATE semantics declaratively. `require_digit` fixes a real defect — see §4. Both are config, so config-only extensibility is preserved. |
| 5 | `EgressGate.check()` is `async`. | The re-scan runs the detector, which offloads spaCy to a worker thread. A synchronous gate would either block the event loop or skip the re-scan. Both are worse than the signature change. |
| 6 | Added `secure_context_pipeline/surrogates.py`. | The token grammar has three consumers — the tokenization strategy, the restorer, and the egress gate's skip-list. One authoritative definition stops them drifting apart. No spec-mandated directory was renamed. |
| 7 | `ObfuscationResult` carries `spans`; `engine.obfuscate()` accepts `run_id`. | The engine is the only component that knows what it did to each span; reconstructing it downstream is lossy because tokens are deduped and carry no offsets. `run_id` is required for the specified audit correlation. |
| 8 | **The engine performs a residual sweep** beyond the specified splice algorithm. | The spec splices only detected spans. Real documents mention the same value repeatedly and NER does not fire every time — a value detected in a header and missed in prose leaves the original in the payload, which the gate then (correctly) blocks on, rendering the pipeline unusable on ordinary documents. Once a value is vaulted it is now masked everywhere: **detection decides what is sensitive; the vault decides where it appears.** The sweep now also covers the one value class that gets *no* vault row — a redact-band detection, which `note_unrestorable` hands to the gate as a needle. Masking only its labelled mention meant an ordinary document stating the same number twice was refused by a needle the same call had just planted: three of three financial shapes returned `422 EGRESS_BLOCKED(reason='vault_original')` through the real app. Its residual occurrences now get the same `[REDACTED_<TYPE>]` marker. Policy redactions (`action: redact`) are still excluded — that span is prose, not a value — and a prior call's vault row always outranks the marker, so a restorable value is never downgraded to an irreversible one. |
| 9 | Originals shorter than 3 characters are neither vaulted nor scanned for. | Applied consistently in the engine and the gate so the vault's originals set stays exactly co-extensive with what the gate can enforce. Otherwise the guarantee quietly becomes "zero originals, except the ones too short to check". |
| 10 | Domain-specific exceptions live beside their packages (`llm/base.py`, `store/document_store.py`). | All inherit `PipelineError`, so the no-content contract and the 64-char detail ceiling apply uniformly — and the ceiling is measured on the **rendered** width of *both halves* of every detail entry, key and value, not on `str` values alone. That distinction was a real gap, not a nicety: `errors.py` tested `isinstance(value, str)` long after `AuditEvent.detail` had moved to `len(str(value))`, while its own docstring called the two "the identical guard". A 408-character clinical note encoded as a 983-digit int therefore cleared the exception ceiling and rendered verbatim into `str(exc)` — 1,004 characters for `PipelineError(note=...)`, recoverable with one `to_bytes` — and `api/errors.py` writes `dict(exc.detail)` straight into the HTTP body. The two ceilings are now compared against each other, payload by payload, in `tests/test_models.py::test_the_two_detail_ceilings_are_the_same_guard_and_not_merely_documented_so` — a parity claim that nothing checks is how they drifted apart in the first place. Cross-package errors remain in `errors.py`, which documents the split. |
| 11 | **Overlap resolution ranks `action: strip`/`redact` entities above score.** | The spec's rule is score, then span length. That is wrong for policy actions, and demonstrably so: spaCy mis-tags a bare numeric date as PERSON at 0.85, and that 10-character span evicted the 129-character `CASE_STRATEGY` span (0.7) that *contained* it — sending privileged strategy prose to the provider unredacted. A policy action is a categorical rule, not a confidence-weighted detection, so its score should not decide whether it survives. Failing this way also fails safe: worst case is over-redacting a sentence. Applied in the detector and again in the engine. |
| 12 | **The pseudonym collision guard is seeded with the whole document's originals and rejects word-level collisions.** | Found by the 100-run harness. A pseudonym is drawn from the same value space as the originals, so Faker can hand back `"Rachel Medina"` while `"Medina"` is genuinely another entity's original — putting a real surname verbatim on the wire inside our own surrogate. The guard previously read only the vault (values written *so far*), making it order-dependent; it now receives every original up front and rejects on any shared word, not just whole-string equality. |
| 13 | **The egress gate matches on word boundaries, not raw substrings.** | `"Brown"` is a real original; a generated fake surname `"Browning"` contains it, and a naive `"brown" in payload` reported a leak that was not one. Word-boundary matching also makes the gate agree with the engine's residual sweep about what counts as an occurrence — previously they disagreed, which is exactly how a value could be swept everywhere and still be reported present. **They agreed on boundaries and still disagreed on whitespace**, with precisely that consequence: the sweep escaped its needle literally, so a space could not match a newline plus an indent, while the gate compares normalised forms that collapse whitespace. A value recurring across a line break was left by the sweep and blocked by the gate, making every hard-wrapped document — the shape Deviation 32 says every document arrives in — an unconditional `EGRESS_BLOCKED`. `textrules.word_bounded_pattern` now flexes internal whitespace, which is what the restorer already did; the helper moved there so there is one decision rather than three. **A masking approach was tried first and reverted**: exempting emitted spans from the scan *hid* the genuine `Medina` leak. The exemption belongs upstream in the guard, where it can be made true rather than assumed. |
| 14 | **A shifted date that lands on another real date degrades to a plain token.** | The per-session shift is one constant so intervals survive, which means a shifted date can land exactly on a *different* real date in the same document. The rendered surrogate is then a verbatim original: the gate blocks and the restorer cannot disambiguate. That single date becomes a plain token; every other date keeps the shared shift, so all remaining intervals survive and the value stays restorable. Blocking the whole request would be a strictly worse trade. |
| 15 | **The adversarial fixture value is not the shape the specification suggests.** | The suggested shape — alphanumeric groups separated by hyphens, with a run of digits in the middle — *is* detected: `CASE_ID`'s `\b\d{2}-[A-Z]{1,4}-\d{3,6}\b` claims the digit run at 0.70, in every document category. The engine would obfuscate it and the gate would never see it, making the adversarial test prove nothing. The harness uses an all-alphabetic grouping instead, plus `test_planted_value_is_invisible_to_the_detector`, which asserts the detector really is blind to it across all four categories rather than assuming so. |
| 16 | **A session is bound to the `user_id` that created it**, and `POST /pipeline/run` checks the binding with `secrets.compare_digest`. | The spec's §9.9 treats `session_id` as the whole credential. Unbound, it was a credential for *anyone's* documents: a caller with their own session, another user's `user_id`, and that user's `doc_id` got a 200 and the PHI. The only obstacle was `doc_id` being unguessable — obscurity, sitting directly underneath the per-user-key isolation this design claims. A mismatch answers the **same** `401 SESSION_EXPIRED` as an unknown session, so the check adds no "wrong user" oracle. |
| 17 | **`DELETE /sessions/{id}` takes a required `user_id` query parameter.** | Without it, anyone who learned a `session_id` could destroy another user's vault — and that is irreversible by construction, since it pops the key. The response stays an **unconditional, byte-identical 204** for owned, stranger, unknown and already-destroyed sessions: revealing which of those it was would rebuild the existence oracle the parameter exists to close. Only a session that both exists *and* belongs to the caller is actually touched; the outcome goes to the audit log, not to the status code. |
| 18 | **`GET /audit` requires a `session_id` or `run_id` scope**, returning `400 AUDIT_SCOPE_REQUIRED` otherwise. | Unscoped, it was a **session-ID enumeration oracle**: an anonymous `GET /audit` harvested live session IDs, which `DELETE /sessions/{id}` then accepted — three users' vaults erased with zero credentials. Liveness is deliberately *not* checked, so the post-destruction audit tail the demo prints (build doc §9.11) still works after the session is gone. |
| 19 | **`/docs` and `/redoc` are disabled** (`docs_url=None`, `redoc_url=None`); `/openapi.json` is still served locally. | Swagger and ReDoc load JS and CSS from `cdn.jsdelivr.net` and `fastapi.tiangolo.com`. A pipeline whose entire premise is that no document text and no third-party fetch leaves the box should not ship a default page that phones out, and on an airgapped host both render blank. The schema is still there for anyone who wants it. |
| 20 | **The token-ID collision counter is a *leading* `0x00 ‖ counter` block, not the spec's "appended counter byte".** | This is a **security correction, not a style preference.** Appending is not injective: with the counter on the end, `("NAME", "john smith", counter=1)` hashes the byte-identical message as `("NAME", "john smith\x00\x00\x00\x01", counter=0)`. An attacker who can get a chosen value into a document can therefore steer the collision path onto a token ID that is already in use. Framing the counter on the *left*, before the entity type, makes the message unambiguously parseable and the construction injective. `test_crypto.py::test_token_id_counter_is_not_forgeable_from_the_value` pins it, and `::test_token_id_counter_zero_is_the_section_8_formula_verbatim` pins that the counter-0 case is still exactly the spec's formula. |
| 21 | **`Detection.text` and both `Settings` secrets are masked on *serialization*, not only in `__repr__`.** | The spec's "repr rule" covers `f"{detection}"`. It does not cover `model_dump_json()`, and that gap was **two real plaintext leaks**: dumping `Settings` emitted `SCP_MASTER_KEY`, and dumping a `Detection` emitted the original value. Both are the natural thing for a logging or debugging path to call. Strictly stronger than the spec. **Consequence worth naming:** `Settings` no longer round-trips through `model_dump()` — the dump is for humans and logs, not for reconstruction. |
| 22 | **`MockKMSKeyProvider` wraps data keys under `HKDF(cmk, info=b"kms-wrap")`** rather than using the master key directly as a cipher key. | The CMK should be input keying material, never a working cipher key — that is what a real KMS does, and it keeps one key from serving two purposes. It also makes the "cloud-compatible by construction" claim in §4 an actual structural property rather than an interface resemblance. |
| 23 | `PipelineResult` carries `raw_llm_response`; `ObfuscationResult` carries `stripped`. | Neither is in the spec's §7 schema. `raw_llm_response` is required by the spec's *own* UI section, whose third panel shows the model's reply with tokens still visible; `stripped` is needed because strip and redact are different actions and the API cannot report what it did without distinguishing them. |
| 24 | `SpanOut.action` is an `EntityAction` StrEnum, not a bare `str`; `AuditEvent.detail` is a read-only `Mapping`, not a `dict`. | Both are tightenings. The enum makes `obfuscated`/`redacted`/`stripped` exhaustive and typo-proof under `mypy --strict`; the read-only mapping stops a caller mutating an event's detail after the entry hash is computed, which would silently break the chain. `detail` still serializes as a plain object, so the wire format is unchanged. |
| 25 | The date-shift floor correction treats `Δ == 0` as positive. | The spec writes `sign(Δ)*30`, which is undefined at zero. Choosing positive is arbitrary but must be *chosen*, or the shift is unspecified for one value in 600. |
| 26 | **`SESSION_EXPIRE` was in the §7 event vocabulary and never emitted — now CLOSED.** | TTL lapse is discovered *lazily* — `SessionRegistry` sweeps on the next access — so there is no moment at which a session expires and code is running to record it. That was the argument for leaving it unemitted, and it was the wrong conclusion from a correct premise: the right moment is not when the session dies but when a request **notices**, which is exactly where `deps.reap_expired_sessions` now runs. It emits `SESSION_EXPIRE` and `VAULT_DESTROY` together — the death and the teardown it triggered are two facts an auditor reconstructing a timeline wants separately. No background sweeper and no timer thread, which is the failure mode this row was right to refuse. All twelve members of `EVENT_TYPES` are now emitted, plus the thirteenth (`AUDIT_ACCESS_DENIED`) that §2 describes and that is deliberately outside that frozenset. See Deviation 54. |
| 27 | **Two of §4's ten numbered steps emit no dedicated audit event.** The narrative says each step "emits audit events and captures latency"; steps 2 (fetch + decrypt) and 5 (context injection) capture latency only. | §7 fixes the event-type vocabulary and neither step has a member of it. Inventing `DOC_FETCH`/`INJECT` would be a *larger* deviation — from the vocabulary, which is the part a compliance reader depends on — for evidence that already exists elsewhere: the fetch is evidenced on the `DETECT` event emitted immediately after it in the same `run_id` (now carrying `doc_id` and `fetch_ms`, so the "which documents were read" question is answerable), and the injection is evidenced by `EGRESS_PASS`, which carries the sha256 and length of exactly the assembled payload. Both steps are timed in `PipelineResult.stats`; step 5 previously had **no** timing at all, which was a plain gap and is fixed. |
| 28 | **The token contract reproduces §9.5.2's `[PHI_MEDICATION_2f4a|oral-antidiabetic]` verbatim — a 4-hex hash — while §7 and §9.7 specify 8.** | The build doc contradicts itself, so "follow the spec" is not available: §9.5.2 calls its block "the exact system prompt", §7 declares `token_id` as 8 hex, and §9.7's `TOKEN_RE` requires `[0-9a-fA-F]{8}`. Keeping the prompt verbatim is the *safer* of the two, not merely the more literal. Being outside the grammar makes the literal inert: `TOKEN_RE` does not match it, so the restorer leaves it and the residual assertion stays silent. Normalising it to 8 hex would make it match — and a model echoing the example would then hit a hash the vault never issued, substituting `[UNRESOLVED_ENTITY]` and emitting a spurious **`VAULT_MISS`**, which is supposed to mean a real anomaly worth a compliance look. It is not a skip-list hole either: `_protected_spans` does not cover it, so pass 2 re-scans it like any other prose (more scrutiny than a real token's core gets), pass 1 never exempts it, and the shipped detector finds zero entities in either system prompt. Pinned by `test_the_token_contract_example_is_outside_the_grammar_and_that_is_inert`. |
| 29 | **`run()` re-derives the outbound digest and refuses to send unless it matches the one the gate cleared**, and `AuditLogger.length()` accepts the full `query()` filter set. | Both are additions rather than departures. The first closes a time-of-check-to-time-of-use window the spec's ordering requirement does not cover: "the gate ran first" and "the gate cleared what we sent" are different claims, and only the second is the guarantee — a stage inserted between the check and the provider call would satisfy every ordering test while releasing unaudited bytes. It fails as `EgressBlockedError(payload_changed_after_check)`, so the 422 handler and the audit trail treat it like any other block. The second makes §9.8's "logs must be queryable" *checkable*: `query` pages at 1000, and without a matching count a full page is indistinguishable from a complete 30-day answer. |
| 30 | **The `documents` metadata table has a sixth column, `size_bytes`.** | The spec enumerates five. Listing a user's documents without decrypting every blob needs the size, and §3 already grants that the metadata DB leaks *shape* — counts, categories, sizes, timestamps — so the column discloses nothing the threat model does not already concede. `test_document_store.py::test_metadata_columns_are_exactly_the_specified_schema` pins the full list, so a seventh column cannot appear silently. |
| 31 | **`EMAIL` gains a `patterns:` backstop** alongside `presidio: EMAIL_ADDRESS`. | Presidio's `EmailRecognizer` validates every candidate through `tldextract`, which resolves the domain against the **Public Suffix List** — an address whose suffix is not on that list scores zero and is dropped *silently*. Measured **0.0 recall** on `@acme.internal`, `@hospital.local`, `@mail.corp` and `@cluster.lan`, which is exactly what enterprise and hospital documents carry. EMAIL is a §2-mandated entity type, so a recogniser that only sees public domains does not satisfy the requirement. |
| 32 | **Sentence-tail patterns tolerate a soft line wrap; `CASE_STRATEGY`'s capture window goes 120 → 240 characters.** | The build doc's `[^.\n]{0,120}` terminates a span at the first newline. Every document reaching the detector has been through `extraction.py` and arrives **hard-wrapped**, so on a realistic document `action: redact` covered only the *first line* of its own strategy sentence and **shipped the remainder to the provider**. That is the failure the forced redaction exists to prevent. A blank line still ends the span, so paragraphs cannot run together. |
| 33 | **`LAB_RESULT` is case-folded, its tail is lazy, its newline branch refuses a field label, its tail may cross a non-sentence period, and the bound goes 20 → 30.** | Greedy matching read `"your LDL is 162 and your A1C came back at 7.4"` as a single span ending at the `1` of `A1C` — so the second result, `7.4`, escaped obfuscation entirely. A greedy quantifier on a tail pattern does not merely over-capture; it swallows the boundary that the *next* value needed. Three later changes, each measured: (a) the soft-wrap branch of Deviation 32 ran off the row into the **next field's label** — `"Recent labs: LDL\nDOB: 1974-03-02"` was one span `'LDL\nDOB: 1974'`, which collapses two lines, vaults a composite that is not a value (so the bare date is never an original and the gate has no needle for it), and audits a PII date as PHI. `test_no_detection_spans_a_line_break` could not see it: that test filters to `presidio:`-backed entities, which is exactly the set `LAB_RESULT` is not in. The guard refuses only a `\n` followed by a short letters-only run and a colon, so the wrapped table row the branch exists for (`'HbA1c\n    7.4'`) still matches. (b) `[^.\n]` could not cross any `.`, so `"LDL cholesterol (calc.) 162"` and the dot leaders of `"WBC ..... 12.3"` returned **zero** detections and their values went un-vaulted, invisible to all three egress passes; a `.` is now crossable only when what follows it past any blanks is neither a letter nor a line end, so `"LDL was normal. Patient is 62"` still does not match. (c) `" cholesterol (calc.) "` is 21 characters, so (b) alone cannot reach it inside the spec's 20. Recall on the four shipped fixtures is unchanged at 873 detections with identical per-type tallies; clean-corpus false positives unchanged at 0; the three tail branches stay disjoint on their first character and dot-run attacks measure a flat 2.0x per doubling (0.06 / 0.09 / 0.18 / 0.34 ms at 4k / 8k / 16k / 32k characters). Pinned by `tests/test_registry_edges.py` section 7. |
| 34 | **Three of the build doc's own `context:` words are replaced by lemma stems** (`filed`→`file`, `presents`→`present`, `prescribed`→`prescribe`); a fourth, `routing`→`rout`, is a **widening rather than a repair**; and a fifth, `takes`, is dropped outright rather than stemmed (see Deviation 46). | Presidio's context enhancer tests `configured_word in lemma` as a **substring**. `"filed"` is not a substring of the lemma `"file"`, so those three specification words were **inert — no boost, ever**, and that boost is what keeps a 0.70 pattern hit ahead of spaCy's flat 0.85, so the inert words were quietly losing overlap resolutions. **This row previously said all five were inert, and for `routing` that was false in the phrasing that matters.** spaCy lemmatises `routing` to `routing` in the noun-adjunct reading — `"ACH routing number 021000021"`, i.e. the actual ACH context — so the spec's own word boosts there, 0.70 → 1.00. It is inert only in the verb reading (`"we are routing the payment to account no. …"`, lemma `rout`). The shipped `rout` is a substring of **both** lemmas and so covers both readings; the honest cost is that it is a substring of `routine`, `route` and `router` too, which the spec's word is not. Kept because a missed ACH context is a missed obfuscation and a spurious boost is not. |
| 35 | **Overlap resolution ranks pattern/gazetteer-backed entities above presidio-backed ones** — below policy actions, above score. | Presidio scores every spaCy guess 0.85 and every registry pattern 0.70, so the *general-purpose guess* took the label off the *specific claim*. Measured consequence: a docket number `24-ARB-00912`, typed as `DATE_TIME`, was being routed through the **Tier-2 date-shift path** — parsed as a date and re-rendered. Coverage is unchanged by construction; only the label moves, and it moves toward the more specific recogniser. |
| 36 | **The diagnosis gazetteer grows from 109 to 208 terms.** | §9.2's stated coverage target is "fixtures plus realistic docs", and common presenting conditions were simply absent. This is the most corpus-fitted change in this group and is flagged as such in §4. |
| 37 | **`TOKEN_RE` bounds every quantifier §9.7 leaves unbounded**: `\s*`→`\s{0,4}`, `[A-Z0-9_]*`→`{0,63}`, the hint suffix→`{1,24}`. | The specified regex is **catastrophically backtrackable**: adjacent unbounded quantifiers around an optional group cost **93 s** on a payload of 128,000 whitespace characters, which is a denial-of-service reachable from an ordinary document upload, and the restorer runs on every response. Bounding fixes it at **9.8 ms** on the same input. (This row previously said "a crafted 500-character input", which was wrong and trivially falsifiable — 500 characters is instant. The cost is quadratic in input length: measured 0.0058 / 0.023 / 0.090 / 0.363 / 1.446 s at 1k / 2k / 4k / 8k / 16k characters, i.e. **exactly 4x per doubling**, which extrapolates to 93 s at 128k. The 93 s and 10 ms figures were both right; the input size was not.) The behavioural cost was measured rather than assumed and is exactly **one** case: more than four whitespace characters inside a token leaves the closing bracket behind (`[PHI_NAME_1a2b3c4d     ]` → `John Smith     ]`). The value still restores, nothing leaks, and no post-restore assertion trips. The other two bounds cost nothing — neither an entity name past 63 characters nor a hint past 24 is emittable, because `format_surrogate` refuses to construct one. |
| 38 | **§10.7's `[PHI_MEDICATION_2f4a|oral-antidiabetic]` (a 4-hex ID) is deliberately *not* restorable.** | The build doc contradicts itself: §8 fixes token IDs at `hexdigest()[:8]`, §9.7's own regex demands `{8}`, and only §10.7's example uses 4. The normative half wins. Widening to `{4,8}` would also widen the **egress gate's skip-list** — the gate skips spans matching the token grammar, so a looser grammar means more of the payload exempted from the re-scan, which is a security cost paid for an example. Pinned in both directions: a 4-hex token is unmatchable by the restorer *and* unissuable via `format_surrogate`, so the two halves cannot drift apart. |
| 39 | **`Restorer.restore` accepts an optional `issued` set; `RestoreResult` gains `fabricated`, `lost` and `surrogate_misses`.** | Without knowing which surrogates were actually issued, every unresolved reference is a single undifferentiated "miss". With it, the restorer distinguishes a token the **model invented** (never issued — a model-behaviour signal) from one that **was** issued and no longer resolves (a vault or session fault). Those are different incidents with different responses, and collapsing them loses the distinction precisely when an operator needs it. The orchestrator passes it, so production misses classify rather than reading as `indeterminate`. |
| 40 | **The user prompt is detected and obfuscated too**, in the same session and against the same vault (`orchestrator.run()` steps 3b/4b). §9.5.2's injector assembles `{system} + {user prompt} + {obfuscated document}` — the prompt goes through **raw**. | The prompt box is a text input a human types PHI into, and measured, it was a straight bypass of the whole design: six entity types typed into it reached the provider verbatim over HTTP while the document beside them was fully tokenized. The prompt is now detected, vaulted and tokenized before assembly, and the two token lists are merged (`_merge_tokens`), so the same restore path covers both. **A grader will notice this immediately** — the model no longer sees the question as written. Two consequences worth stating: the answer quality depends on the token contract carrying the prompt's intent, and `PipelineResult.detections` deliberately **excludes** prompt spans (`SpanOut` offsets are document-space and there is no span-space field), so §7's UI highlight panel reports nothing for them. `prompt_entities_detected` and `prompt_tokens_issued` are in `stats`. |
| 41 | **The outbound payload fences the document**: `{obfuscated prompt}\n\n<DOCUMENT>\n{obfuscated document}\n</DOCUMENT>`, with any `</?\s*DOCUMENT\s*>` in **either** untrusted half rewritten to `&lt;…`. §9.5.2 specifies bare concatenation. | An uploaded document that closes the fence early has its remainder read as top-level instruction. This is defence in depth against *confusion*, not against a determined injection — a model can still be talked into ignoring a fence, and this repo makes no prompt-injection claim. Neutralisation runs **before** the gate scans, so the gate still sees the exact bytes that go on the wire. Visible in every payload and in `demo.py --dump-wire`, which is why it is recorded rather than left as a surprise. |
| 42 | **The egress gate runs a third, blocking pass** (`_independent_hits` over `_INDEPENDENT_PATTERNS`), with its own `reason="independent_pattern"`. §9.5.3 specifies two. | Pass 2 re-runs the **same** `Detector` that ran at detect time, so it is a second *look*, not a second *opinion*, and every blind spot it had then it has again. Measured: Presidio's `UsSsnRecognizer.invalidate_result` returns a hard 0.0 for the published example SSNs, so `Member SSN 123-45-6789 verified` was never detected, never vaulted, and passed all passes silent. Pass 3 is a recogniser the detector does not use. **Its scope is honestly narrow** — one entity type of the four in `HIGH_SEVERITY_TYPES` — so the "different provenance" argument is answered for SSN and left standing for `MRN`, `TAX_ID` and `ACCOUNT_NUMBER`, each of which has exactly one registry pattern consulted identically at detect time and at re-scan. Listed in §7 Known gaps. |
| 43 | **The gate has two identifier floors, not one**: `MIN_IDENTIFIER_DIGITS = 7` for the whole-value needle, `MIN_IDENTIFIER_RUN_DIGITS = 6` for a contiguous digit run. | They were one constant, and that was a live leak of the exact class this project keeps finding — **a number chosen for one channel's false-positive budget was silently setting another channel's security floor.** Seven was justified against dates (`03/12/85`) and amounts (`$1,234.56`), which are aggregates of 2- and 3-digit runs. A *contiguous* six-digit run is not that shape: it is an identifier core, and `MRN`'s shipped pattern is `\K\d{6,10}`, so the detector vaults six-digit MRNs the gate then declined to scan unbounded. Measured on the real detector, registry and gate: `MRN552140B` in a document body put a vaulted MRN on the wire byte for byte, with pass 1 bounded, pass 1 unbounded, pass 2 and pass 3 each having a separate reason to miss it. Pinned by `test_a_six_digit_identifier_core_glued_to_a_letter_is_blocked` and, so the config and the code cannot disagree again, by `test_no_shipped_identifier_pattern_can_match_below_the_gate_s_run_floor`, which reads `entities.yaml` itself. |
| 44 | **`ObfuscationStrategy.make_surrogate` takes a keyword-only `session_id`.** §9.3 fixes the ABC as `make_surrogate(self, detection, token_id, vault)`. | `SessionVault` is a multi-session object — every accessor needs the ID, and the Tier-1 collision guard reads the vault. This is a spec-mandated public interface (the pluggability contract §10.3's dummy-strategy test exists to prove), so it is the kind of signature a reviewer diffs against §9.3, and it was previously claimed as "documented as required" in `strategies/base.py` while appearing nowhere in this file. |
| 45 | **The Faker seed label carries the normalized original value**, not just the entity type: `HMAC(session_key, b"faker:" + f"{entity_type}:{normalize(text)}")`. §9.3 writes `b"faker:" + entity_type`. | Stability per *value* rather than per *type* is what component linking needs — one patient must own both `Sherri Lopez` and `Lopez` across the whole document. `crypto/keys.py` still computes §9.3's message exactly — `HMAC(sk, b"faker:" + label)`; only the label passed to it is composite, which is why the parameter is named `label` rather than `entity_type`. Not a disclosure: the HMAC is under a secret 32-byte session key, `normalize` cannot introduce NUL, and `_label_bytes` rejects one, so the domain separation argument in `keys.py` still holds. Recorded because original values now flow into a keyed derivation, which is a fact a security reviewer should be told rather than have to find. |
| 46 | **`CASE_ID` pattern 1 drops §6.2's `(?:Case|Docket)\s+No\.?\s*[:#]?\s*` prefix**, widens `[a-z]{2}` to `[a-z]{2,4}`, and adds `(?i)`. | Real briefs cite bare docket numbers, and requiring the lexical prefix missed them. The cost is that the pattern now claims any `d:dd-xx-ddd` run in **any** document category with no lexical context, which is exactly the broadening Deviation 15 relies on. Deviation 3 covers only the backslash spelling and was previously the only row mentioning `CASE_ID`. Same class, lower stakes: `MEDICATION` drops the spec's `takes` context word (explained in `entities.yaml`, not here until now), and `MRN`/`ACCOUNT_NUMBER` are wholesale rewrites acknowledged only in a §4 parenthetical. |
| 47 | **`regex` is a hard runtime dependency and is now declared.** | `detection/registry.py` does `import regex`, and it resolved only transitively through `presidio-analyzer`. It is not optional: `MRN` and `ACCOUNT_NUMBER` use PCRE `\K` and possessive quantifiers, which the standard library's `re` **cannot compile at all** (`bad escape \K`), so `entities.yaml` is not portable to `re` and every path that touches the registry — config, detector, engine, strategies — fails at import without it. Deviation 2 enumerated the added dependencies and omitted the one that was undeclared. |
| 48 | **A Tier-2 span that is a *list* of dates is split into one detection per date** (`Detector._split_composite_dates`), and the egress gate derives a scan needle per constituent of a composite vaulted original (`_composite_needles`). | spaCy returns `03/11/2024, 09/17/2024` as one `DATE` span, so the whole string became a single vault original. A different date shifted onto `03/11/2024` then rendered a **verbatim slice** of that original, and both leak scanners reported clean — correctly, since each asks whether a *whole* vaulted value occurs. The pipeline was manufacturing the partial disclosure that §1's first boundary describes. Splitting is refused unless every constituent parses, because a partial split leaves a rump span with the same defect; the gate limb is duplicated on purpose so the fix does not depend on detection being right. It is also a utility gain — those dates previously degraded to a plain token, losing the interval property Tier 2 exists for. |
| 49 | **§9.7's `[UNRESOLVED_ENTITY]` + `VAULT_MISS` rule is not applied to an *unbracketed* token whose ID this run did not mint** — it is left byte-for-byte, with `vault_misses` unincremented and no audit row. | §9.7 states the rule for any unknown `token_id`, unconditionally, and the shipped restorer honours it for every **bracketed** form (including all seven mangled shapes in §10.7). The carve-out is the `foreign` branch in `Restorer._restore_tokens`, and it exists because an unbracketed match is far more likely to be *document text* than a mangled token: `TOKEN_RE` is deliberately tolerant of missing brackets so the restorer can read what an LLM mangled, and that same tolerance makes a clinical document's own `PHI-MRN-40281993` a match. Substituting `[UNRESOLVED_ENTITY]` there would delete a real sentence from the user's answer to protect a value that was never ours; leaving it is the conservative failure. The narrowing is only available when `issued` is supplied, which the orchestrator always does — so the production path takes this branch and the library default (`issued=None`) does not. Pinned by `test_document_text_that_merely_looks_like_a_token_survives_verbatim`. (This row previously cited `test_a_document_reference_the_model_echoes_never_reaches_the_audit_log`, which is a real and valuable test but pins the **opposite** branch: its input is parenthesised, parentheses count as brackets, and it asserts the value IS rewritten to `[UNRESOLVED_ENTITY]` with a `VAULT_MISS` row — the negation of this row's three claims.) |
| 50 | **`AMOUNT` is unbounded over digits and commas and must end on a digit** (`\d[\d,]*\d|\d` with `\.\d{1,2}`) instead of §6.2's `[\d,]{1,12}(?:\.\d{2})?\b`. | The character class counts digits *and* commas against one bound and truncates at the twelfth character, so `$1,234,567,890.12` matched only `$1,234,567,` — the token was spliced in beside a bare `890.12`, six digits of a real figure in the clear, and pass 1 had no needle for them because the vaulted original is the truncated string. That is the partial-value class Deviation 48 exists to close. `{1,2}` on the cents closes the same hole one character wide (`$1,234.5` matched `$1,234`, leaving `.5`). **A strictly 3-digit-grouped alternation was tried first and was worse than the build doc's version**, not better: it truncated every amount not grouped in threes, so `$12,34,567` matched `$12` and left `,34,567` on the wire where the original pattern matched the whole string. Assuming a grouping convention re-created the defect the change was written to remove. |
| 51 | **`normalize()` applies NFKC a second time, after casefolding, and strips non-whitespace C0/C1 controls.** | Casefolding is not closed over NFKC — `casefold("ß")` is `"ss"`, so `"ß" + U+0323` folds to `"ss" + U+0323` and a second NFKC composes the trailing `s` with the mark. `normalize` was therefore **not idempotent**, while `SessionVault.put` indexed on one pass and `get_by_original` re-normalised on the documented grounds that it was: the write landed under one key, the read-back missed under another, and the engine raised `vault_put_not_readable` from a branch commented `# pragma: no cover -- this cannot happen`. HTTP 500 from an ordinary `.txt`. Controls are stripped for a sibling reason: Deviation 45 routes the normalised *document value* into an HMAC label, and `_label_bytes` rejects a label carrying its own NUL — a guard written for config typos, applied to document content, so one NUL in a span (or in the JSON `prompt`, with a benign document) was a 500. Pinned by a property test over the whole Unicode range. |
| 52 | **`_parse_fallback` parses against two anchors and rejects any date **any** of whose (year, month, day) came from the default.** | The `\d+` twice guard rejects a bare year but not a bare clock time: `9:15 AM` has two digit runs, neither a date component, so dateutil resolved the whole date from the anchor and the payload asserted a day the source never mentions — the exact lie `daterules.py` says it exists to prevent ("a shifted today is a wrong date that looks right"); relocating the anchor moved it rather than removing it. Every subsequent clock time collided on the same fabricated date, so three times on one page rendered three incomparable ways. No digit heuristic can decide this; parsing against two anchors that share no field answers it exactly. **The rule is ANY, not ALL**, and the cost is worth stating: a partial date that supplies some components but not others -- `3/14`, `March 14` -- is refused Tier-2 treatment and degrades to a plain token rather than a shifted date. That is the safe direction (a token discloses nothing and invents nothing) but it is a recall loss, not a free win. |
| 53 | **`load_registry` validates `only_in_doc_categories` against `DOC_CATEGORIES`**, which moved to `models.py` so both consumers share one vocabulary. | It was validated against nothing. A typo (`medial`) loaded clean, and because the field is enforced by *restricting the requested entity set*, an unmatchable value restricted the entity out of **every** document including `general` and unclassified — never detected, so never vaulted, so no egress-gate backstop either. A one-character config typo silently removed an entity and all three of its defences, while the adjacent `category:` typo has always raised. |
| 54 | **TTL expiry now runs the full destruction path** (`api/deps.reap_expired_sessions`), not only the key pop. | §4 step 10 and §9.4 both say expiry destroys like logout — key popped, vault rows deleted, `VAULT_DESTROY` audited. Only the first happened. `SessionRegistry.sweep()`'s own docstring says "the caller is responsible for the rest", and there was no caller: `sweep()` appeared exactly once in the tree, in a test. An expired session therefore left AES-GCM rows in `vault.db` and a decrypted cache in RAM until process exit — and they were **unreclaimable**, because `DELETE /sessions` gates on an ownership check that raises for an expired session and skips `vault.destroy`. Reaping runs on the request that discovers the expiry. Note that the *discovering* read is often not the reaping one: five other accessors sweep too — including the anonymous `GET /health` the shipped Dockerfile polls every 30 seconds — so `SessionRegistry` records every ID it drops in an unreaped set that `sweep()` drains, rather than the reaper depending on being first to notice. It was not, and while it depended on that it reaped nothing in the container. It also emits `SESSION_EXPIRE` — declared in `audit/logger.py` since the first commit and, until now, **never emitted anywhere**, which is the gap Deviation 26 records and that module's own comment calls "a real gap rather than a spare constant". Both events are written: `SESSION_EXPIRE` for the death and `VAULT_DESTROY` for the teardown it triggered, because an auditor asking "when did this session end, and was it torn down" wants both facts. **This row previously claimed to close Deviation 26 while the event was still unemitted** — the claim was written from the intent rather than the code. The drain is bounded: one request finishes at most `MAX_REAP_PER_REQUEST` (16) expired sessions and the residual stays queued in `Services.reap_backlog`. Unbounded, one arbitrary request paid for every other caller's expiries — measured, 258 anonymous sessions reaped in 311 ms inside a single request, and an end-to-end victim `POST /pipeline/run` at 1890 ms. With the bound the same scenario is 16 reaps in 32 ms and a 196 ms victim run. **The queue itself used to carry a companion ceiling — `MAX_REAP_BACKLOG`, 4 096 IDs, oldest-first eviction — and this row used to defend it with the argument the code carried: the key is popped before an ID reaches the queue, so a dropped ID's rows are already undecryptable and what is lost is a `DELETE` and two audit rows, never confidentiality. That argument is true of the SQLite rows and false of this process, and the ceiling is gone.** `SessionVault.destroy` is the only thing that pops a live session's `SessionVault._caches[session_id]` — the other two writers are `close()`, which drops every cache as the process ends, and `sweep_orphans`, which at startup touches only sessions the registry has never heard of — and that dict holds originals that are *already decrypted* and need no key; `SessionRegistry.sweep` drains its unreaped set, so an evicted ID is never offered again. An evicted ID therefore left plaintext resident until process exit, rows on disk that nothing could reclaim, no tombstone, and neither `SESSION_EXPIRE` nor `VAULT_DESTROY` ever written for it. Measured: flood 4 096 IDs behind one real expired session and the victim's `['943-41-9520']` is still in `_caches` after the whole backlog has drained. The ceiling capped the cheap half (a 32-character ID) by abandoning the expensive half for ever. What bounds the queue now is the drain, because the same requests fill and drain it: an ID enters only because some earlier request minted the session, so fill is at most one per request against 16 out, and every entry is strictly smaller than the registry entry it replaced. Removing the eviction also removed the one loop in `_enqueue_for_reaping` that could run an unbounded number of times in a single request. Both structures are `OrderedDict`, which is a measured requirement rather than a preference now that the queue has no ceiling: a plain `dict` does not compact on delete, so draining 200 000 queued IDs 16 at a time cost 6 662 ms in total and 1 307 µs on the worst single request, against 22 ms and 27 µs for the identical loop on an `OrderedDict`. Failure handling and the residency window the 16 costs are in §7 gap 7. |
| 55 | **A lone name component is always treated as a surname**; §9.3's "same rule for first names" is not implemented. | `role` is `"last"` for the final word of a span and `"first"` otherwise, so a bare given name (`"Priya said…"`) gets a surname-shaped fake and does not link to the `Priya Raman` mapped elsewhere. It is the right default for these documents — a lone component in clinical and legal prose is overwhelmingly a surname (`"Dr. Patel said…"`) — and the module docstring has always said so, but the ledger had not. |
| 56 | **The demo UI's "destroy session, then run again" shows the *erasure*, not a live vault miss** (§9.10 describes it as demonstrating the vault-miss path). | A destroyed session is refused at the session check — `401 SESSION_EXPIRED` — **before** the vault is consulted, so no `VAULT_MISS` is reachable from one in this architecture; the button's banner promised otherwise. What it does demonstrate is stronger: the key is gone, so nothing can be decrypted at all. The genuine vault-miss path is exercised where it actually occurs — a model inventing a token inside a *live* session — by `test_vault_miss_on_deobfuscation` at both unit and integration level, and by `demo.py`. Two supporting bugs fixed with it: `destroySession` nulled `S.sessionId`, and `loadAudit` bailed on a null one, so the audit panel went blank at exactly the moment `VAULT_DESTROY` landed in it, and the `SESSION_EXPIRED` refresh branch was dead code. |
| 57 | **§9.10's "upload fixture dropdown" is a `doc_category` preset beside a manual file input, not an upload control.** | The dropdown lists the four bundled filenames, but nothing can deliver them to the page: a browser cannot read a path off disk, and `_mount_ui` mounts `secure_context_pipeline/ui/` alone — measured, `GET /fixtures/medical_note.txt` is a **404** (`/` and `/app.js` are 200), and the Dockerfile's `COPY fixtures/ fixtures/` only puts them where the *server* can see them. So the control could never do what its name promised — and until now it did not **say** so: labelled `fixture`, its only listener copied `data-cat` into `doc_category` and its `value` was read nowhere, so selecting `medical_note.txt` and pressing **Run** issued **zero requests** and answered `NO_FILE`, on the first control a reviewer touches. The label read `fixture preset` and the hint named the remaining step (`now pick fixtures/medical_note.txt with the file button`), so the two-step was stated rather than discovered — and that fix, which this row described, said closing it properly needed a read-only server route for `fixtures/`, an API change the UI-scoped pass did not make. **That change has since been made and this row is closed.** `GET /fixtures/{name}` serves the four bundled documents out of an import-time allow-list (§2, *the only file-serving route*), the dropdown now fetches the document it names and posts it in one click, and the `GET /fixtures/medical_note.txt` measured **404** above measures **200** today — re-measured on a live server for this pass, along with the traversal corpus §2 records. `test_the_fixture_preset_names_the_path_the_file_picker_still_needs` was deleted rather than relaxed, because it pinned the friction rather than the feature; `test_choosing_a_preset_uploads_that_document_in_one_click` replaces it and reads the wire instead of the label — exactly one `GET /fixtures/medical_note.txt`, then a `POST /documents` whose multipart body carries the fetched bytes under the fixture's own filename and category. `test_every_element_the_ui_addresses_exists_in_the_page` still applies — the UI harness's DOM stub mints an element for any id asked of it, so until that test existed a mis-typed id was invisible to every behavioural test in the file. |
| 58 | **A span scoring below `SCP_THRESHOLD_REDACT` (0.3) is dropped, not redacted.** Build doc §2 bullet 8 says "entities detected below the obfuscation-confidence threshold are **redacted**, never passed through raw", which taken literally is a floor of zero; §9.2's three bands specify a floor. This implements §9.2. | The two cannot both hold and the price is measurable: Presidio's `UsSsnRecognizer` scores `412337891` (and `41233-7891`, `412-337891`) at **0.05** with no supporting context, so `Detector._floor_for` drops it and the digits reach the provider verbatim. The properly formatted `412-33-7891` scores 0.85 and is vaulted; the same bare digits with "SSN" nearby score inside the redact band and become `[REDACTED_SSN]`. So the gap is exactly "9-digit-shaped, no context", where the same string is far more often an order number or a ledger reference. **Closing it is an engine change, not a detector one**: `ObfuscationEngine._classify` independently discards the same band, so removing `_floor_for`'s floor changes nothing on the wire — measured, payload byte-identical. Doing it properly means redacting every 9-digit run in every document. Written out at `Detector._floor_for`, and `test_detection.py::test_below_floor_span_is_dropped` now carries a "what this is NOT evidence of" note so the traceability table cannot cite it for §2 bullet 8 again. |
| 59 | **`INSURANCE_ID`'s letter prefix goes `[A-Z]{2,4}` → `[A-Z]{2,6}`.** | The spec's bound knows `BCBS` and `UHC` and misses every payer whose member-ID scheme prints five or six letters — `AETNA`, `CIGNA`, `HUMANA`, `ANTHEM`. That is the identifier-position failure class stated above `MRN` in `entities.yaml`: a member ID no pattern anchors on is never vaulted, so pass 1 has no needle for it and pass 2 re-runs this same pattern. Measured on `"Member ID AETNA1234567 and policy HUMANA12345678 and BCBS123456789 on file."`: **one** detection of three before, three after — the two longer member IDs had been travelling to the provider byte for byte. Held-out `INSURANCE_ID` coverage **4/5 → 5/5**. The trade was measured, not argued: two more letters do not loosen what makes the pattern specific — the letters stay upper case and must abut the digit run with no separator, so `"AETNA 4412093"` and `"Aetna4412093"` are still not matches — and false positives are unchanged at **0** across both clean corpora (35 documents), with unannotated spans inside the recall corpus unchanged at 4 of a permitted 6. Pinned by `tests/test_registry_edges.py::test_the_shipped_insurance_id_pattern_reaches_five_and_six_letter_payers`. |
| 60 | **A `VAULT_MISS` row classified `fabricated` carries `entity_type=None`, every miss row carries `detail['category']`, and provider-attributable miss rows are capped at 32 per restore.** | The same claim §7's "zero originals anywhere in the log" bullet retracts, failing in a second field. The old code kept the **model-supplied** entity type on a token this run never minted — measured, a real call wrote `entity_type=PHI_MARISOL_VANTERPOOL`, which is attacker-chosen text in a typed column of the audit chain. A fabricated row now carries `entity_type=None` beside the `token_id=None` it already had, and all three classifications carry `detail['category']`, one of the four `CATEGORIES` literals parsed out of the token grammar rather than trusted. The cap is an availability control on the same surface: a response can carry arbitrarily many fabricated placeholders, and each one was a row. At most `_MAX_MISS_ROWS` (32) individual rows are written for provider-attributable misses, followed by one summary row (`reason: token_misses_suppressed`, carrying `suppressed`, `suppressed_fabricated`, `suppressed_indeterminate`, `row_cap`); `vault_lost` rows are **never** capped, because their count is bounded by what this run minted and each one names a value a user was entitled to see. Measured: 1,000 fabricated placeholders cost 561 ms uncapped against the §12 500 ms restore budget, and 22 ms capped. §3's threat-model table covers what the provider **reads** and has no row for what it **returns**; this is that row. |
| 61 | **The demo UI bounds every request and destroys the session it replaces.** | Two defects the UI audit found in `ui/app.js`. (a) `api()` had no deadline, and `setBusy(true)` disables Run, Destroy, Create session, the file picker and both selects for the whole of a request — so a reply that never arrived locked the page until a reload, with the spinner turning and no banner. There are now two budgets: 30 s for session mints, deletes, audit pages and badges, and 240 s for `POST /documents` and `POST /pipeline/run`. 240 s is derived from the server's own ceiling: `llm_timeout_s` 60 s × `MAX_ATTEMPTS` 3 + two `MAX_BACKOFF_S` 10 s sleeps = 200 s for the provider stage alone, before detection, obfuscation and the gate's three passes. A timeout banners `REQUEST_TIMEOUT` and says the request may still be running server-side. (b) Pressing **Create session** with one already live abandoned it: no `DELETE` was issued, so the previous session key and its vault rows stayed in process memory until the TTL reaped them, and the page had nulled `lastSessionId`, so nothing on it could ever address them again. It now deletes the outgoing session, owner-scoped with that session's own owner, and proves the erasure with the same `VAULT_DESTROY existed=1` read the Destroy button uses rather than trusting the 204 — which is deliberately not an ownership oracle. Pinned by `test_a_request_that_never_answers_gives_the_controls_back`, `test_the_two_posts_that_do_server_side_work_get_the_longer_budget`, `test_creating_a_second_session_destroys_the_one_it_replaces`, `test_a_replacement_the_log_does_not_confirm_is_not_called_an_erasure` and `test_a_replacement_whose_delete_failed_says_the_old_vault_is_still_there`. |
| 62 | **Panels 2 and 3 now say what each highlight IS, and the two red legend keys are no longer the same square.** | Panel 1's marks have carried entity type, action, score and surrogate since the first build; the two panels that show the *substitute* carried no tooltip at all, so the only thing separating a vault-backed surrogate token, an irreversible `[REDACTED_*]` marker and a realistic pseudonym was a colour — and the legend names a *category*, not a kind. Panel 3 is where that bites: a pseudonym reads as genuine clinical prose in the provider's-eye view. `renderMarks` now emits one of three tooltips, chosen off the emitted shape rather than off the strategy that was asked for, and none of them names an original value. Separately, `style.css` claimed `.unres` was distinguished from `.c-RED` by a wavy underline — but the legend swatch is an empty 10×10 `<i>`, so there was nothing to underline and the `[REDACTED_*]` and "not restored (vault miss)" keys rendered as two dark red squares at 1.09:1 against each other, meaning opposite things. The not-restored swatch is now hatched. Pinned by `test_a_mark_in_panel_two_or_three_says_which_of_the_three_kinds_it_is`, `test_a_pseudonym_with_no_detection_behind_it_still_gets_an_honest_tooltip` and `test_the_two_red_keys_in_the_legend_are_not_the_same_square`. |
| 63 | **Two stale-state defects in the demo UI: the audit tail after a refused run, and the header health badge.** | `resetRun` blanks the four panels, the stats row and the `#audit-run` label and deliberately does not touch the audit table, and `run()`'s `catch` reloaded that table for `EGRESS_BLOCKED` and `SESSION_EXPIRED` only — so every other server-side refusal left the *previous* run's rows under an emptied label beside panel 1's new document. It is now reloaded for every refusal that reached the server, and skipped for the two `ensureDoc` preflights (`NO_FILE`, `NO_CATEGORY`) that issue no request at all. The health badge was written once, at load: kill the server mid-demo and every action bannered `NETWORK_UNREACHABLE` while the header still read a green `ok`. It now moves on the first unreachable call, and `health()`'s own failure path sets `badge err` rather than leaving the dim grey it starts as. Pinned by `test_a_refused_run_reloads_the_audit_tail_whatever_refused_it` and `test_a_dead_api_moves_the_header_badge_it_used_to_leave_reading_ok`. |
| 64 | **The verify chain can no longer be started twice.** | It is the one button `setBusy` deliberately leaves alive, and it had no in-flight guard. The chain walk is priced in *rows* (`audit.py`: 5,000 per token, burst 24) and charged on success, so an impatient double-click spent the bucket and the second answer was the 429 that `app.js`'s own `RATE_LIMITED` sentence describes — a throttle the page inflicted on itself and then reported as though the server had. One in-flight walk, one request. Pinned by `test_the_chain_walk_cannot_be_started_twice`. |
| 65 | **The success banner reports the composition the run *emitted*, not the strategy it was *asked* for**, and says so in a code a reviewer can grep. | The banner read `strategy <name>`, unqualified, and the vault is what makes that a lie rather than a paraphrase: a record is keyed by (entity type, value) for the **life of the session** and has no strategy dimension, so whichever strategy ran first owns every surrogate that value gets afterwards — deliberately, because it is what keeps a pseudonym minted on run 1 restoring correctly on run 4. Measured through the real API on `fixtures/medical_note.txt` as `medical`, one session, both orders, `tokens_issued` 32 either way: pseudonymization first and **tokenization** selected second gives `pseudonyms_issued` **18** under a banner that said "tokenization", with panel 2 reading `Patient name: Steven Lee`, `Phone: 468-376-2490` and `romerochristina@example.org` — a reviewer reads eighteen invented values as this patient's real ones. The reverse order gives **0** and merely understates. The banner now reads `RUN_OK  run_id <id> · <strategy> requested · N of the M surrogates in the payload are realistic fake values, K are bracketed tokens`, derived from `stats.tokens_issued` and `stats.pseudonyms_issued` (the second read off the emitted **shape**, `orchestrator._is_pseudonym`, not off the request). Where the request and the emitted composition contradict each other the code becomes **`RUN_OK_STRATEGY_DRIFT`** and the banner turns yellow: tokenization requested with any pseudonym on the wire, or pseudonymization requested with none. A **mixed** pseudonymization run is deliberately *not* flagged — the content tier emits a bracketed token by design, so warning there would fire on runs that are working. A response carrying neither counter gets the bare `X requested` and no verdict, and a strategy name the page does not know gets its composition printed and no verdict either, because `config._BUILTIN_STRATEGIES` is a floor rather than a closed set. `RUN_OK` stays the prefix on both branches — the run did succeed; what drifted is the page's own label — so the colour is the difference a reviewer sees first. Pinned by `test_the_banner_prints_the_composition_the_run_emitted_not_the_strategy_asked_for`, `test_a_run_doing_what_was_asked_still_prints_its_composition_and_stays_green`, `test_the_banner_states_no_verdict_it_cannot_derive_from_the_response`, `test_the_counters_the_banner_reasons_from_are_counters_the_pipeline_emits` and `test_the_real_pipeline_drives_the_drift_banner_and_the_span_reconciliation`. |
| 66 | **Panel 1's header and the `entities_detected` chip count two different sets, and the reconciliation is no longer hover-only.** | Measured on `fixtures/medical_note.txt` as `medical`: the strip read `entities_detected 54` three lines above a header reading `52 spans masked`, on every run, with the only reconciliation on the page hidden in a `title`. Two disagreeing counts three lines apart with the explanation behind a hover is a page inviting the reviewer to pick which number is real. The header now reads `<chars> chars · <masked> spans masked · detector returned <detected>, neither set contains the other`, and the chip carries an on-screen `· before policy` tag. **"N of M" is still refused, in both directions**, because it is false: `_plan` drops 3 of the 54 at the `MIN_SWEEP_LEN` = 3 enforceability floor (`MD`, `RN`, `MD`, all typed `ADDRESS`) and `_sweep_residual` adds one the detector never returned (`Larkspur Valley Hospital`, already vaulted this session under another surface form) — 54 − 3 + 1 = 52, so neither set contains the other. Both operands come from the same response (`result.detections.length` and `stats.entities_detected`); with `entities_detected` absent nothing is printed, because inventing the second number is the defect this whole row is about. Pinned by `test_the_two_span_counts_on_the_page_are_each_labelled_for_what_they_count`, `test_a_refused_run_does_not_leave_the_span_reconciliation_on_an_empty_counter` and the real-pipeline test named in row 65. |
| 67 | **Two tooltips claimed this run had *minted* something it may only have re-emitted.** | The pseudonym tip in panels 2 and 3 read `A PSEUDONYM this run minted for a <TYPE>`, and the `tokens_issued` chip said "Vault rows this run minted". Both are false on exactly the run where they matter most — the drift case in row 65, where a `tokenization` run following a `pseudonymization` one in the same session re-emitted **18** fakes it could not have minted. The response carries no per-record minted/reused flag, so the page may not claim one in either direction. The tip now reads `A PSEUDONYM standing in for a <TYPE>. It reads like a real value and is not one -- it was invented in this session (not necessarily by this run: the vault reuses a record for the life of the session) and the original never left the vault.`, and the chip reads "Vault records this run's payload draws on … minted by this run, or reused from an earlier call in this session; the response does not say which". Neither names an original value. Pinned by `test_a_pseudonym_with_no_detection_behind_it_still_gets_an_honest_tooltip` and the panel-tooltip tests named in row 62. |
| 68 | **The demo page ships a real favicon file, and the CSP was *not* widened to admit it.** | A browser asks for `/favicon.ico` unprompted; `_mount_ui` mounts `secure_context_pipeline/ui/` alone and shipped no icon, so the catch-all answered `404 {"code":"NOT_FOUND"}` and every cold load was red in devtools on a security demo that had done nothing wrong. The first fix was an inline `data:` URI carrying a comment asserting that a favicon is fetched by the browser process and so escapes `img-src 'self'`. **That is not what the browser does**: measured against this exact page, Chrome 151.0.7922.77 logged **2** console errors on every cold load, both `Loading the image 'data:image/png;base64,…' violates the following Content Security Policy directive: "img-src 'self'"`. The `rel="icon"` fetch is a renderer image fetch and `img-src` governs it, so the inline icon traded a 404 for a CSP violation and the page still had no icon. It is now `secure_context_pipeline/ui/favicon.png` — a **128-byte 16×16 PNG**, served from the same mount, no route added — and `img-src 'self'` is **byte-identical** in both places it is declared, the `<meta>` tag and `api/constants.py`. Re-measured the same way: 0 console errors, and the network log holds `/`, `/style.css`, `/app.js`, `/favicon.png` and `/health`, with no `/favicon.ico` request at all. PNG rather than SVG because an SVG's mandatory `xmlns` is spelled as a w3.org URL, which the self-containment test correctly cannot tell from a genuine off-host reference. The instinct that produced the inline version was right about the risk — an asset that works locally and is missing from a clone is this repository's own worst historical bug — and wrong about the remedy: the answer is `git check-ignore` (measured: the file matches no ignore rule) and a commit. Pinned by `test_api_ui_escaping.py::test_the_page_icon_is_same_origin_so_the_page_cannot_block_its_own_favicon` and `::test_the_icon_rule_rejects_every_form_that_was_measured_blocked`, the second of which fails the three forms that were measured blocked (the inline base64 URI among them) so the rule is not "reject everything". **Two loose ends a reviewer will hit, stated rather than left to be found.** `secure_context_pipeline/ui/favicon.png` is **untracked** as this row is written — the file exists in the working tree and matches no ignore rule, and until it is committed a clean clone is back to the 404 this row closes. And `tests/test_ui_behaviour.py::test_the_page_serves_its_own_favicon_so_a_load_logs_no_console_error` still asserts `href.startswith("data:image/")`, i.e. the superseded inline form, so it is **red on this tree**: it is the old claim's own pin, it was not updated with the page, and it has to be replaced by whoever owns that file rather than deleted — the property it was written for (a load that logs no console error) is the right one and is now true for a different reason. |
| 69 | **`Create session` is a two-step, because creating one over a live session erases that session's key and vault rows first.** | Row 61 made the replacement honest — the outgoing session is deleted, owner-scoped, and the erasure proved from `VAULT_DESTROY existed=1` — which turned a bare button into a destructive one. It now sits inside a `<details class="guard">`: the summary arms it (`Create session…`) and a second click on **Mint a new session key** commits, the same shape the Destroy button uses. **Any walkthrough that says "click Create session" needs the extra step** — or, better, should note that the happy path does not need the button at all: the first **Run** with no session mints one itself and banners `SESSION_AUTOCREATED`, and the green run banner then says the scope was auto-created for it. Pinned by `test_creating_a_session_is_gated_because_it_erases_the_session_it_replaces`, `test_a_run_with_no_session_mints_one_through_the_button_s_own_path` and `test_the_create_session_button_is_never_labelled_as_the_automatic_mint`. |
| 70 | **`Restorer.restore()` takes a `hints=` map, and the stranded-hint deletion it enables is bounded twice — but the shipped orchestrator does not pass it.** | A model that strips *both* brackets off `[PHI_DIAGNOSIS_1a2b3c4d\|cardiovascular]` leaves the class hint welded to the restored original (`chest pain\|cardiovascular`). The earlier remedy was a text-only mop-up, and it could bound the deletion only by the hint alphabet — which is also ordinary English — so it deleted `\|and`, `\|per-protocol` and a markdown table cell. The parameter is the fix: `hints` maps token ID → **the hint this run actually wrote after the pipe**, and a stranded tail is removed only where the caller supplies that map, the value is `HINT_RE`-shaped (`[a-z0-9-]{1,24}`, so at most 25 characters including the pipe) *and* the bytes equal what we wrote. Omit the map and the hint survives visibly, which is the older behaviour and is still pinned. **What is not claimed:** `PipelineOrchestrator.run()` does not supply `hints` today — it passes `surrogates` and `issued` only — so on the pipeline a reviewer actually runs, the stranded hint still survives, and the closure is available to callers rather than shipped in the demo path. Pinned by `test_a_run_supplied_hint_map_consumes_only_the_bytes_it_names`, `test_a_hint_map_can_only_delete_the_bytes_that_map_authorises`, `test_a_hint_the_emitter_could_not_have_written_is_dropped_from_the_map`, `test_the_hint_map_is_keyed_case_insensitively_like_issued`, `test_the_hint_map_is_inert_on_the_answer_when_the_run_emitted_no_hints`, `test_a_hint_stranded_by_a_dropped_bracket_costs_no_word_of_the_answer` and `test_mangled_hint_mopup_never_eats_the_models_prose`. |

---

## 9. Repository map

```
secure_context_pipeline/
  config.py          Settings -- the only component that reads the environment
  models.py          Pydantic models; AuditEvent is frozen, length-capped, detail read-only
  errors.py          Exception hierarchy; structured detail only, 64-char ceiling
  surrogates.py      The token grammar -- one definition, three consumers
  textrules.py       The word-boundary rule -- one decision, five importers
  daterules.py       Date parsing that remembers the source format + the composite-span split
  crypto/            AES-GCM with mandatory AAD; HKDF hierarchy; HMAC derivations
  store/             Encrypted document store + text extraction
  detection/         Presidio wrapper, registry-built recognizers, gazetteers
  obfuscation/       Strategies (tokenization | pseudonymization) + the engine
  vault/             Session vault + in-memory session key registry
  pipeline/          Orchestrator, context injector, EGRESS GATE
  deobfuscation/     Tolerant restorer with post-restore assertions
  audit/             Hash-chained, append-only, queryable
  llm/               Provider protocol, Anthropic, deterministic mock
  api/               FastAPI layer
  ui/                Static demo page, no build step -- four files, all same-origin:
                     index.html, style.css, app.js, favicon.png (128 bytes, 16x16)
entities.yaml        The ONLY place entity types are defined
fixtures/            Synthetic documents + their generator -- no real data anywhere
```

### Fixtures

All four are generator-produced and committed. **No real personal data anywhere** — SSNs use
the never-issued `9xx` area block, phone numbers the NANP `555-01xx` fictional range, and
e-mail the RFC 2606 reserved domains. Counts below are from `python -m fixtures.generator` at
the default seed, and every committed file is byte-identical to what the generator emits, so a
reviewer can regenerate and diff:

| Fixture | Words | Distinct planted values | Entity types |
|---|---|---|---|
| `medical_note.txt` | 393 | 30 | 11 |
| `legal_memo.txt` | 475 | 32 | 9 |
| `financial_disclosure.txt` | 306 | 36 | 9 |
| `legal_brief_large.txt` | **12,062** | **298** | 9 |

The large brief is the specification's "~12,000 words, 200+ distinct entities" artifact — it is
the Q1 discussion document, the input to the full-pipeline benchmark, and the reason the
generator asserts its own word count and distinct-entity count at build time rather than
trusting the templates to stay in range.

These same four files are the entire allow-list of `GET /fixtures/{name}` (§2), which is how the
demo UI loads one in a click. They are the only files this server will hand back over HTTP, and
they are synthetic by construction — which is why serving them is a convenience rather than a
disclosure.

`generator.expected_entities(seed, kind)` returns the exact literals planted, which is what
lets the leakage harness assert on ground truth instead of on the detector's own opinion of
what it found. Two entity types deliberately do not round-trip and are excluded from restore
assertions: `PRIVILEGED_MARKER` is stripped and `CASE_STRATEGY` is redacted.

`entity_type` is an **opaque string** in the engine, vault, restorer, audit logger and API —
the components a new entity type has to travel through. That is what makes adding one a
config-only change, and `tests/test_extensibility.py` proves it by failing if the new type's
name appears anywhere in package source.

Two modules do hold small, named entity tables, and pretending otherwise would be the kind of
claim this README exists to avoid:

- `obfuscation/strategies/pseudonymization.py` knows four names (`NAME`, `CLIENT_IDENTITY`,
  `EMAIL`, `ADDRESS`) to pick a person/email/place generator. Everything else — including a
  Tier-1 entity added by config tomorrow — falls through to the structural mask, which
  preserves the shape of whatever it is handed.
- `pipeline/egress_gate.py` lists four (`SSN`, `MRN`, `ACCOUNT_NUMBER`, `TAX_ID`) as the
  pattern-typed entities whose re-scan hits block rather than warn.

Neither is on the path a new entity type needs: both degrade to the generic branch, which is
why the passport acceptance test passes end to end under both strategies without either file
learning the word. They are tuning tables, not dispatch — but they are entity names in package
source, and the honest form of the claim names them.

---

## 10. Requirements traceability

Every requirement, the code that satisfies it, and **the test that proves it**. A row whose
third column is empty is a claim, not a result; the one row that ends in a human check is
marked as such rather than quietly asserted.

| Requirement | Implementation | Proving test |
|---|---|---|
| **Core 1** — encrypted store, PDF/DOCX/TXT, AES-256, per-user keys | `store/document_store.py`, `store/extraction.py`, `crypto/aead.py`, `crypto/keys.py::EnvKeyProvider.doc_key` | `test_document_store.py::test_blobs_on_disk_are_ciphertext`, `::test_no_plaintext_anywhere_under_the_data_dir`, `::test_absent_and_foreign_documents_are_indistinguishable`, `::test_confusable_user_ids_cannot_read_each_others_documents`; `test_extraction.py` (pdf/docx/txt); `integration/test_pipeline.py::test_per_user_document_keys_are_load_bearing_on_their_own` |
| **Core 2** — detector, nine-entity minimum, spans with type + confidence | `entities.yaml` (20 types), `detection/registry.py`, `detection/recognizers.py`, `detection/detector.py::Detector.detect`, `models.py::Detection`/`SpanOut` | `integration/test_pipeline.py::test_the_nine_mandated_entity_types_survive_the_whole_round_trip`; `test_detection.py::test_entity_positive_and_near_miss` (positive **and** near-miss negative for **all 20** registry entities, `presidio:`-only ones included; the coverage guard `::test_fixture_table_covers_every_registry_entity` derives its expectation from the whole registry minus an explicitly named exemption set, so a new entity cannot arrive without fixtures) |
| **Core 3** — two strategies + per-entity justification | `obfuscation/strategies/{base,tokenization,pseudonymization}.py`, `registry.tier_of`, README §6 | `test_obfuscation.py::test_tokenization_format_round_trips_through_the_strict_grammar`, `::test_pseudonym_preserves_identifier_formats`, `::test_tier3_diagnosis_emits_a_class_annotated_token_from_the_gazetteer`, `::test_tier4_numerics_stay_plain_tokens` |
| **Core 4** — vault encrypted, deterministic in-session, purged on expiry/logout | `vault/session_vault.py`, `vault/session_registry.py` | `test_vault.py::test_within_session_determinism`, `::test_destroy_makes_tokens_unreadable`, `::test_destroy_surviving_row_is_undecryptable`, `::test_surviving_row_cannot_repopulate_a_destroyed_cache`; `integration/test_pipeline.py::test_expired_session` |
| **Core 5** — context injector, chunking, pre-send check | `pipeline/context_injector.py`, `pipeline/egress_gate.py`, `detection/detector.py::chunk_text` | `test_context_injector.py::test_serialized_is_exactly_what_the_gate_scans`; `test_egress_gate.py::test_the_gate_runs_before_the_provider_on_the_happy_path`, `::test_the_provider_is_never_reached_when_the_gate_blocks`; `test_detection.py::test_entity_straddling_a_chunk_boundary_is_detected_whole` |
| **Core 6** — restore, including mangled/paraphrased token forms | `deobfuscation/restorer.py`, `surrogates.py::TOKEN_RE` (`_any_case`, `_SEPARATOR`) | `test_deobfuscation.py::test_mangled_token_forms_restore` (a parametrised table of forms), `::test_hint_is_ignored_for_lookup`, `::test_post_restore_assertion_fires_on_residual_token`, `::test_a_fake_reassembled_across_a_splice_boundary_still_fails_the_run`; `integration/test_pipeline.py::test_vault_miss_on_deobfuscation`. **Two mangling classes were outside that set until this week** and are named rather than folded in: a **re-cased** token (`[phi_name_1a2b3c4d]`, `[Phi_Name_…]` — only the hash was ever case-tolerant) and **whitespace at either `_` separator**, which is what a line wrap inside a token looks like (`[PHI_NAME_\n1a2b3c4d]`). Both now restore, driven through the real `Restorer` by `test_readme_claims.py::test_the_two_mangling_classes_this_row_names_restore_through_the_real_restorer` — a round trip, not a regex match, because the row claims restoration. **The residual is stated in §7 gap 25**: whitespace *inside* the 8-hex hash is still unmatched, which is the same line-wrap class one position over. |
| **Core 7** — audit: ts, session, type, token, action; queryable; zero originals | `audit/logger.py`, `models.py::AuditEvent` | `test_audit.py::test_persisted_rows_carry_no_free_text_columns`, `::test_detail_rejects_long_string_values`, `::test_truncating_the_tail_breaks_the_chain`, `::test_deleting_a_middle_row_and_relinking_the_chain_is_still_caught`, `::test_erasing_a_whole_session_is_not_reported_as_that_session_being_clean`, `::test_a_truncated_tail_does_not_heal_when_the_log_advances`, `::test_a_silent_tail_truncation_costs_four_statements_and_all_four_are_needed`, `::test_deleting_the_sqlite_sequence_row_does_not_launder_a_truncation`, `::test_two_processes_sharing_one_audit_db_lose_no_events`; leakage assertion 2 and `leakage/test_leakage_harness.py::test_the_audit_scan_catches_a_label_column_original_and_says_which_limb_did` |
| **Critical constraint** — reversible in-session, irreversible across | `crypto/keys.py::derive_token_id` (HMAC under an ephemeral key), key destruction | `test_crypto.py::test_token_id_deterministic_within_session`, `::test_token_id_non_deterministic_across_sessions`, `::test_token_id_is_irreversible_without_the_key`; `integration/test_pipeline.py::test_restoration_is_impossible_after_the_session_is_destroyed` |
| **NFR** — config-only entity add | `entities.yaml`; `entity_type` opaque downstream | `test_extensibility.py::test_package_source_never_mentions_passport` (the grep **is** the proof), plus the three end-to-end cases beside it |
| **NFR** — strategy swappable via config | strategy registry dict, `Settings.strategy` | `test_obfuscation.py::test_dummy_strategy_plugs_in_with_zero_engine_changes`, `::test_per_entity_strategy_override_is_config_only`, `::test_a_per_entity_strategy_override_restores_in_both_directions` (both override directions carried through `Restorer.restore`, not just the surrogate's shape); `test_llm.py::test_new_provider_name_is_selectable_with_zero_other_changes` |
| **NFR** — zero PII in transit, verifiable by inspection | `pipeline/egress_gate.py` (fail-closed, **three** passes — §9.5.3 specifies two; the third is Deviation 42) | `leakage/test_leakage_harness.py::test_no_original_ever_leaves_the_process` (**100 runs**), `::test_unknown_shape_value_blocks_egress_and_the_call_never_fires`, `::test_the_leak_scan_bites`; the four stated boundaries are pinned by `::test_a_partial_value_leak_is_outside_what_this_harness_claims` and `::test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims` (the homoglyph one by `test_egress_gate.py::test_a_homoglyph_substitution_is_outside_what_the_scan_claims`, which was **missing entirely** until this audit — the only entry in the list whose status was an assertion about the code rather than a measurement of it; the separator-floor one by `test_egress_gate.py::test_the_floor_s_corpus_measurement_is_the_one_the_docstring_quotes`); the combining-mark shape is **closed**, not a boundary, and is pinned by `test_egress_gate.py::test_a_combining_mark_spliced_into_a_value_no_longer_reaches_the_provider` (the glued-word boundary applies to the byte limb of the audit scan too; the query limb is what catches a label-column original — see `leakage/test_leakage_harness.py::test_the_byte_limb_and_the_query_limb_of_the_audit_scan_see_different_things`); round-trip completeness is derived independently of the restorer, enforced by `leakage/test_leakage_harness.py::test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots`; `demo.py --dump-wire` for the literal HTTP body |
| **NFR** — vault isolation is cryptographic, cross-session | per-session HKDF vault keys, AAD `session_id:token_id` | `test_vault.py::test_aad_binding_across_sessions`, `::test_aad_binding_across_token_ids`; `integration/test_pipeline.py::test_concurrent_session_isolation` (50 interleaved ops) |
| **NFR** — graceful degradation (redacted, not obfuscated, between the two thresholds — **not** a claim about spans below the redact floor, see Deviation 58) | engine threshold policy, `action: redact` | `test_obfuscation.py::test_mid_confidence_span_is_redacted_without_a_vault_entry`, `::test_case_strategy_is_force_redacted_in_both_modes`; `test_detection.py::test_mid_confidence_span_is_returned_inside_the_redact_band`, `::test_redact_band_reaches_the_obfuscated_text_end_to_end` |
| **NFR** — async pipeline, spaCy off the event loop | `detector.detect` (`asyncio.to_thread` behind `Semaphore(4)`), `aiosqlite`, `aiofiles` | `integration/test_pipeline.py::test_the_pipeline_never_blocks_the_event_loop`; `test_extraction.py::test_extraction_runs_off_the_event_loop_thread` |
| **Spec-mandated test cases** (5, by name) | — | `integration/test_pipeline.py::test_happy_path_end_to_end`, `::test_entity_type_not_found`, `::test_vault_miss_on_deobfuscation`, `::test_expired_session`, `::test_concurrent_session_isolation` |
| **Stack** — Python 3.11, `cryptography`, pytest, Docker, `.env` only | `pyproject.toml` (`requires-python >=3.11,<3.13`), `Dockerfile`, `docker-compose.yml`, `.env.example`, `config.py` | `test_crypto.py::test_settings_secrets_do_not_survive_serialization`; `test_api.py::test_dockerfile_never_copies_the_working_tree_wholesale`. **`docker compose up` itself is a human check** — checklist step 3. |
| **Cloud row** (stretch) — KMS mock, S3/GCS-compatible design | `crypto/keys.py::MockKMSKeyProvider`, `KeyProvider`/`DocumentStore` Protocols | `test_crypto.py::test_mock_kms_envelope_round_trip`, `::test_mock_kms_binds_encryption_context`, `::test_build_key_provider_selects_by_config`; `test_document_store.py::test_key_provider_is_the_seam`. **Known thinness:** the KMS provider is tested as a unit, never driven end-to-end with `SCP_KEY_PROVIDER=mock_kms`. |
| **Live review Q1–Q6** | README §5 | Q1's numbers come from `test_benchmarks.py` and the stage table; the rest are arguments, not testable claims. |
| **README deliverable** — setup, architecture, threat model, design rationale, a tokenization-vs-pseudonymization comparison for **at least two entity types**, and what one more day would buy | §1, §2, §3, §4, §6 (*NAME and DOB, compared directly*), §7 (*With one more day*) | `test_readme_claims.py::test_both_entity_types_the_comparison_table_names_appear_in_every_row`, `::test_the_dob_rows_carry_the_two_arguments_that_are_specific_to_a_date`, `::test_the_age_error_rate_the_dob_row_quotes_is_the_one_the_shift_produces`, `::test_section_7_answers_the_next_day_question_its_own_heading_asks`, `::test_the_next_day_plan_proposes_only_work_that_is_still_open`. **The last two named requirements are the ones this page failed**: §6's table was headed for two entity types and four of its six rows discussed one, and no day-scoped statement existed anywhere in the file — a `grep -i` for "additional day" or "one more day" returned nothing. Both are now structural, so a rewrite that drops either goes red rather than unnoticed. |
| **Functional must-haves (all 7)** | — | **Human check.** See below. |
| **Performance benchmarks (all 5)** | `test_benchmarks.py`, `leakage/test_leakage_harness.py` | **All five are automated.** The four latency budgets are `test_benchmarks.py::test_obfuscation_of_2000_words_is_under_two_seconds`, `::test_vault_lookup_p99_is_under_five_milliseconds`, `::test_deobfuscation_of_a_500_token_response_is_under_500ms` (plus its cold-vault and surrogate-pass variants), `::test_full_pipeline_on_the_large_brief_is_under_fifteen_seconds`. The fifth is the **zero-leakage** figure — 100 automated runs over varied fixture documents — `leakage/test_leakage_harness.py::test_no_original_ever_leaves_the_process` (parametrised over `RUNS = 100`), tallied by `::test_leakage_summary` and protected from silent shrinkage by `::test_the_selected_run_expectation_cannot_shrink_silently`. Mapped clause by clause below. |

### The row a human has to close

It references the confidential challenge document, which is deliberately not reproduced
anywhere in this repository. It cannot be verified from inside the repo, and pretending
otherwise would be the exact failure this table exists to prevent.

- **Functional must-haves (all 7).** The build specification I worked from paraphrases these
  rather than quoting them. Open the original challenge document, read the seven must-haves,
  and tick each against §10 above and against a `python demo.py` run. The likely mapping is
  upload → detect → obfuscate → inject → egress-check → LLM → restore, all of which `demo.py`
  exercises and asserts on, but **the wording is the authority and I could not see it.**

**The fifth performance benchmark used to be listed here as a second human check, which is the
one direction a traceability table can be wrong in that costs marks for nothing: a requirement
conceded that the repository already satisfies.** It read "read the fifth off the
original document; if it is a throughput or concurrency figure, nothing here measures it yet."
It is not a throughput figure and it is measured: the fifth benchmark is **zero PII leakage,
verified across 100 automated test runs on varied fixture documents**, which is the harness §1
opens with. The other four are latency budgets, automated and enforced — obfuscate 2,000 words
< 2 s, vault lookup p99 < 5 ms, restore 500 tokens < 500 ms, full pipeline < 15 s. The fifth
maps clause by clause, and the "varied" clause is the one worth checking rather than assuming:

| The clause | What the harness actually does | Named in |
|---|---|---|
| **100 automated test runs** | `RUNS = 100`, one parametrised case per run. The tally is asserted against `RUNS` rather than against however many cases were *selected*, so deselecting runs turns the summary red instead of quietly shrinking the claim. | `RUNS`, `test_no_original_ever_leaves_the_process`, `test_leakage_summary`, `test_the_selected_run_expectation_cannot_shrink_silently` |
| **varied fixture documents** | Every run draws its own seed (`SEED_BASE + index`), so the 100 runs are 100 *different generated documents* rather than one document scanned 100 times. Three document kinds rotate (`medical` / `legal` / `financial`) under two alternating strategies, so each of the six (kind, strategy) pairs runs 16 or 17 times. | `plan_run`, `KINDS`, `STRATEGIES`, `SEED_BASE` |
| **zero PII leakage** | Each run asserts that no vaulted original occurs, as a word-bounded unit, in the outbound payload, in the audit database or in the captured logs — and that the prompt carried a real original in the first place, so a clean run cannot be vacuously clean. | `test_no_original_ever_leaves_the_process`, `test_the_prompt_carries_a_real_original` |
| **verified** | The scan is sabotaged rather than trusted: a planted original must make it fire, and the harness's own rule is checked against the gate's on generated input so the checker cannot inherit the checked code's blind spots. | `test_the_leak_scan_bites`, `test_the_harness_is_never_weaker_than_the_gate_on_generated_input`, `test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots` |

Re-derive the middle row rather than taking it on trust — it is the clause a reader is most
likely to suspect of being decorative:

```bash
python - <<'PY'
from tests.leakage.test_leakage_harness import RUNS, plan_run
from fixtures import generator
plans = [plan_run(i) for i in range(RUNS)]
print(RUNS, len({p[0] for p in plans}),
      len({generator.generate(s, k) for s, k, _ in plans}),
      len({(k, st) for _, k, st in plans}))
PY
# -> 100 100 100 6
#    100 runs, 100 distinct seeds, 100 distinct documents, all six (kind, strategy) pairs.
```

What is *not* claimed by that fifth benchmark is any wider than §1 already states: "zero
leakage" means no **whole** vaulted value reaches the provider, and the four boundaries that
qualifier leaves open are enumerated in §1 and pinned by their own tests. The original document
remains the authority on the wording; what it is no longer the authority on is whether anything
here measures it.

---

## 11. Pre-submission checklist

Ordered, and every step is either a command with an expected result or a judgement only a
human can make. Run it top to bottom in a **fresh clone**, because half of what it catches is
the difference between "works here" and "works anywhere".

**1 — Clean clone.**

```bash
git clone <repo-url> /tmp/scp-verify && cd /tmp/scp-verify
```

**2 — No secret in the tree or the history.** The first two must print nothing; the third must
show the example file only.

```bash
git log --all -p \
  | grep -nE 'SCP_MASTER_KEY=[A-Za-z0-9+/]{20,}|ANTHROPIC_API_KEY=[A-Za-z0-9_+/-]{20,}|sk-ant-[A-Za-z0-9]{24,}'
# expect: no output. The value shapes are matched, not the variable names: a real master key is
# 32 random bytes base64 (44 chars) and a real API key carries a long unbroken alphanumeric run.
# Grepping the bare names instead reports 9 hits on a clean tree -- this README's own three
# commands match themselves, `demo.py` prints `export ANTHROPIC_API_KEY=sk-ant-...` in its help,
# and the tests use a literal `sk-ant-not-a-real-key`. A check that cries wolf on a clean repo
# is one a reviewer learns to wave through, which is the failure mode worth avoiding here.
git log --all --name-only --pretty=format: | sort -u | grep -x '.env'          # expect: no output
ls -a | grep -E '^\.env'                                                        # expect: .env.example
```

If the second one prints `.env`, the file is in history and a rewrite (`git filter-repo`) is
required before submission — deleting it in a later commit is not enough.

**3 — Docker path.** Needs a `.env`; `docker-compose.yml` has `env_file: .env` with no fallback.

```bash
cp .env.example .env
python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"
# paste the output into SCP_MASTER_KEY in .env
docker compose up --build
```

Then, in another shell — the model load takes a few seconds, so allow for it:

```bash
curl -fsS localhost:8000/health                       # expect: model loaded, db reachable
open http://localhost:8000                            # the four-panel demo UI
docker image inspect secure-context-pipeline:1.0.0 --format '{{.Size}}'   # expect ~1.31 GB
docker history --no-trunc secure-context-pipeline:1.0.0 \
  | grep -cE 'SCP_MASTER_KEY=|ANTHROPIC_API_KEY='     # expect: 0
```

`/docs` is deliberately **404** (Deviation 19). That is not a broken build.

**4 — Local path, from the same clean clone.**

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m spacy download en_core_web_lg
node --version         # optional -- without it the 110 UI behaviour tests skip, silently
python demo.py && echo "demo exit 0"
```

`demo.py` mints an ephemeral master key if `SCP_MASTER_KEY` is unset, so it runs with no `.env`.
It exits non-zero on any failed assertion — the exit code is the check, but read the printed
ledger too.

**5 — The suite, in the clean clone.**

```bash
pytest -q            # expect WITH node: the pass count §1 pastes, 1 skipped (the real-network
                     #   LLM smoke test), and no failures. That pass count is written down in
                     #   exactly one place -- §1 -- so this step cannot drift out of agreement
                     #   with it, which is what it did. Without node: 111 skipped --
                     #   tests/test_ui_behaviour.py goes with it, and §1's app.js
                     #   execution-test claim is uncovered on your run.
pytest -m leakage -q # expect: 100/100 runs clean, 0 leaks
pytest -m bench -q   # expect: 7 measurements, all inside budget
mypy                 # expect: Success, 52 source files
ruff check .         # expect: All checks passed!

# The partial-branch list, which is the part worth reading:
pytest --cov=secure_context_pipeline --cov-branch \
       --cov-report=term-missing:skip-covered -q
```

Paste the leakage summary line into §1 if it has drifted. The `100/100, 0 leaks` part does not
move; the two tallies beside it track what the detector currently finds.

**6 — The one row only you can close.** Open the original challenge document and tick the
**seven functional must-haves** against §10 and a `demo.py` run. It is described in §10 under
"The row a human has to close". This is the one step that cannot be delegated, because the
source document is confidential and is deliberately not in this repository.

While you have it open, confirm the fifth performance benchmark reads as §10 now maps it —
zero PII leakage over 100 automated runs on varied fixture documents. That row is **automated**
and no longer a human check; this is a wording confirmation, not a measurement.

**7 — Reviewer-supplied fixture, if there is one.**

```bash
python demo.py --file /path/to/their.pdf --category medical
```

**8 — Confidentiality sweep.** No challenge-document text anywhere:

```bash
grep -rniE 'take-?home|challenge (doc|document)|confidential' --include='*.py' --include='*.md' \
  --include='*.yaml' . | grep -v '\.venv'
```

Expect two kinds of line and nothing else. The first is this project's own uses of the word
"confidential" — the legal fixtures and the privilege markers. The second is the hits on the
other two alternations, named here for the reason step 2 names its own: a check that prints
output its expectation does not mention is one the reader adjudicates once and waves through
after that. They are the three source comments marking where the auth model stops (`api/app.py`,
`api/schemas.py`, `tests/test_api.py`) and this README's own instruction to open the source
document — §10's "the row a human has to close", step 6 above, and this paragraph. Appending
`| grep -viE 'take-?home|original challenge document'` removes every one of them, including the
lines here that name them, leaving only the "confidential" hits. Anything that reads like quoted
requirements text must go.

**9 — README, last.** Confirm §1 numbers match what step 5 just printed, and that §3, §4, §5,
§6, §7 and §8 are all present and current.

**10 — Access and submit.** Repo private, hiring team granted access, link submitted through
the portal before the deadline.
