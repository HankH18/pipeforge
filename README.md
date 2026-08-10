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

**Detector-side Unicode respelling belongs on that earlier list too, and it is named separately
because calling it "recall" undersells how ordinary it is.** A value written in a spelling the
patterns do not match is never detected, so it is never vaulted and the gate is never given it —
measured on the shipped registry, where `Member SSN 123-45-6789` scores `SSN@0.70` while the same
number carrying one zero-width space, respelled in fullwidth digits (`ＳＳＮ：１２３－４５－６７８９`), or
in Arabic-Indic digits (`٥٥٥-٥٥-٥٥٥٥`) each score **nothing**, in every document category. The
asymmetry is the point: `EgressGate._scan_originals` already folds all three — it strips
default-ignorables and rewrites every Unicode decimal digit in its ASCII spelling — so the gate
would catch these *if a vault row existed*. Fullwidth digits in particular are ordinary output
from a CJK word processor rather than an attack, which is what separates this from an NER miss on
an unusual name. Closing it is a detection-side normalisation pass, not a gate change.

**Three shapes that were open and undeclared are now closed**, all found by adversarial review
rather than by the harness, and all reproduced end to end before being fixed: any alteration of a
multi-word original's interior separator (`Marguerite<U+200B>Vandenberg` reached the provider,
because every compared form kept the separator in the needle); a value in the **redact band**,
which gets no vault row, so pass 1 had no needle for it while the re-scan dropped it for the same
numeric reason — a real SSN scoring 0.40 reached the provider byte-for-byte; and an identifier
restated in another **decimal digit script** (Arabic-Indic, Devanagari, N'Ko and three more),
which NFKC does not fold because those are not look-alikes of ASCII digits but different
characters carrying the same numeric value. Each has a named test and each is detailed below.

A fifth shape — a **combining mark** spliced into a value — was carried on this list as an open
boundary long after the code had closed it, on a rationale (*"folding marks out would make `José`
and `Jose` the same value"*) that is a statement about the **needle** while the gate folds the
**haystack**, and citing a test that did not exist. It is closed, and the record of how it was
argued is kept below rather than deleted. A stronger claim than the one at the top of this file
was written here first, and it was wrong in the way that matters — it promised `never` while the
document itself documented the exceptions.

Everything below is measured on this repository, not aspirational.

## Contents

| | Section | What is in it |
|---|---|---|
| **1** | [Setup & demo](#1-setup--demo) | Two commands, then every number this repository measures: [suite, types, lint, coverage](#the-numbers-this-repository-prints) · [leakage harness](#leakage-harness--100-runs-zero-leaks) · [benchmarks](#benchmarks) |
| **2** | [Architecture](#2-architecture) | Component graph, [the HTTP surface](#the-http-surface), and [the one unauthenticated read](#get-fixturesname--the-only-file-serving-route-and-the-only-unauthenticated-read) |
| **3** | [Threat model](#3-threat-model) | Adversary/control/residual table, and [the weakest point in the design](#the-weakest-point-in-this-design-user_id-is-an-asserted-claim) |
| **4** | [Why these choices](#4-why-these-choices) | Detection and storage rationale, [measured recall](#measured-recall) including the held-out corpus |
| **5** | [Live-review questions](#5-live-review-questions) | [Q1](#q1--a-50-page-brief-with-200-entities-where-does-it-break) scale · [Q2](#q2--the-model-writes-the-patients-condition-what-do-you-do) paraphrase · [Q3](#q3--an-adversary-has-the-obfuscated-document-and-the-response-in-pseudonym-mode-what-do-they-learn) inference · [Q4](#q4--the-vault-is-a-high-value-target-isnt-that-a-problem) the vault · [Q5](#q5--a-hipaa-auditor-asks-what-happened-over-the-last-30-days) audit · [Q6](#q6--why-is-cross-session-non-determinism-a-security-requirement-not-a-nice-to-have) non-determinism |
| **6** | [Strategy selection](#6-strategy-selection) | [Per-entity assignment](#per-entity-assignment), [NAME and DOB compared](#name-and-dob-compared-directly), [graceful degradation](#graceful-degradation-the-third-outcome-and-what-it-costs) |
| **7** | [Known gaps & next day](#7-known-gaps--next-day) | The register, then [what one more day buys](#with-one-more-day) |
| **8** | [Deviations](#8-deviations-from-the-build-specification) | 72 rows, indexed here, reasoned in full in [`DEVIATIONS.md`](DEVIATIONS.md) |
| **9** | [Repository map](#9-repository-map) | Layout, [where the specification's directory names live](#where-the-specifications-directory-names-live), fixtures |
| **10** | [Requirements traceability](#10-requirements-traceability) | Every requirement, its code, and the test that proves it |
| **11** | [Pre-submission checklist](#11-pre-submission-checklist) | Ten ordered steps, each a command or a human judgement |

### If you have ten minutes before the review

| You want | Go to |
|---|---|
| Does it run? | §1 — two commands, and the numbers the suite prints. **If you just cloned it, read the boxed note above this table first.** |
| Is the zero-egress claim real? | §1 *Leakage harness* — including the shapes the harness itself was blind to, the four boundaries it does **not** claim, and how each was found |
| What does it **not** defend? | §3 — **start with "The weakest point in this design"**: `user_id` is an asserted claim and there is no authn at this tier |
| The one route with no auth on it | §2 — `GET /fixtures/{name}`, the only file-serving route: a four-name allow-list read into memory at import, why a session would be friction rather than a control, and the traversal corpus that was **run** rather than argued |
| The six live-review questions | §5 — each answered in its first sentence |
| Where it breaks at scale | §5 Q1 — the bottleneck is not the one you would guess, and the obvious fix was measured and **rejected** |
| What I got wrong | §8 Deviations (75, each with a reason) and §7 Known gaps |

> **If a clone of this repository does not run, check this first.** `.gitignore` line 7 used to be
> an unanchored `data/`, which in git's grammar matches a directory of that name at *any* depth —
> so besides the runtime blob directory it also matched `secure_context_pipeline/detection/data/`,
> the two gazetteers `entities.yaml` requires and `load_registry` fails closed without. They were
> untracked, a fresh clone could not start (`demo.py` exited 2 on
> `ConfigError(reason='registry_gazetteer_missing')`, the suite raised 457 errors), and it was
> invisible locally *because* the files were ignored: `git status` reported a clean tree and every
> local run worked. The rule is `/data/` now, the gazetteers are tracked, and
> `test_every_runtime_asset_the_registry_needs_actually_reaches_the_image` asks **git's index**
> rather than the author's working tree — the only source that does not share the blind spot.

**The three things most worth attacking**, stated up front so they are not a discovery:
`user_id` is an asserted claim and there is no authentication at this tier (§3); the audit chain
is tamper-**evident**, not tamper-proof, and an attacker with DB write access can rewrite it end
to end (§5 Q5); and detection recall is a spaCy ceiling, not a config one — which is exactly why
the egress gate, not the detector, is the security control.

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

**On Linux, run it as yourself instead:**

```bash
SCP_UID=$(id -u) SCP_GID=$(id -g) docker compose up --build
```

This is the one setup step that differs by host, and it is worth a sentence because
the failure is a permission error rather than an obvious one. `data/` is gitignored,
so a fresh clone does not have it; the Linux daemon then creates the bind-mount
source as `root:root`, and a **bind mount masks the directory it covers** — so the
image's build-time `chown` of `/app/data` to uid 10001 does not apply to what is
actually mounted there. The first SQLite open (the audit log) fails with `unable to
open database file` and startup aborts. It is invisible on macOS and Docker Desktop,
where the file-sharing layer remaps ownership to the calling user — which is exactly
why it survived this long: every local run here was clean. The restart policy is
`on-failure:3` rather than `unless-stopped` so that a startup failure retries three
times and then **stops**, instead of replaying its own logs until the reviewer
scrolls away.

The spaCy `en_core_web_lg` model (425 MB on disk, `du -sh` on the installed package) is baked in
at **build** time, not fetched at runtime. That is deliberate: the premise of this system is that
detection happens locally and no document text reaches a third party, so the container must not
need network access to start. The cost is a **1.31 GB image**. The container runs as a non-root
user, and readiness costs a few seconds after start — the spaCy pipeline is loaded once in the
FastAPI lifespan, never per request, so that cost is paid at boot and not on the latency budget
below. (The compose healthcheck allows a 90 s grace period: headroom for a cold container, not
the observed startup time.)

`docker-compose.yml` declares `env_file` with `required: false`, and that is a fix rather than a
preference. The bare `env_file: .env` form makes the file mandatory at **parse** time, so on a
fresh clone — which has no `.env`, because `.env` is gitignored — `docker compose up --build`
died before building anything, with an error naming a missing file rather than the missing key
behind it. Measured both ways in a fresh clone: `docker compose config` exits **1** with the old
form and **0** with the shipped one, and still resolves the file when it is present.

**What a reviewer who forgets the key actually saw.** Fixing the parse error only moved the
failure: compose started the container, `Settings` refused on its own terms — correctly — and the
reason arrived at the *bottom* of a 45-line traceback (starlette → `contextlib` → six repeated
`fastapi/routing.py merged_lifespan` frames → pydantic-settings), ending in `ConfigError:
CONFIG_ERROR(reason='master_key_missing', hint='set_SCP_MASTER_KEY_see_env_example')` — after
which `restart: unless-stopped` replayed the whole thing. Measured in a fresh clone with no
`.env`: **RestartCount 12** in four minutes, still climbing. The information was there; it was 44
lines below where a reader stops.

The check now runs *in front of* the application, as the first statement of the service's
`command`, and the whole of what a fresh clone with no `.env` prints is nine lines that say what
to do:

```
app-1  | === NOT STARTED: SCP_MASTER_KEY is missing ========================
app-1  |   It is the base64 32-byte key every document, vault row and audit
app-1  |   entry is encrypted under. No default, no fallback -- starting
app-1  |   without one would mean writing plaintext. From the repo root:
app-1  |     cp .env.example .env
app-1  |     python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
...
app-1  | exited with code 78
```

No traceback, `docker compose up` exits **1** (`--exit-code-from app` gives **78**, `EX_CONFIG`),
and `RestartCount` stops at **3** instead of climbing — 36 log lines in total, against an
unbounded scroll. With a `.env` present the check `exec`s straight through, so there is no wrapper
process left behind: PID 1 in the running container is `uvicorn … --no-access-log` itself,
`app-1` reports `Up (healthy)`, and `/health` returns `model_loaded: true`.

**Restating the `uvicorn` argv in compose is the cost of that, and it is bounded by a test rather
than by care.** A compose `command:` replaces the image's `CMD` outright, and that `CMD` carries
`--no-access-log`, which is a disclosure control rather than tidiness (see *Log-stream hygiene*).
`test_log_stream_hygiene.py::test_compose_does_not_override_the_command_and_drop_the_flag`
already asserted that any override at that indent must carry the flag — it went red on the first
version of this change, which is exactly what it is for. None of this weakens the fail-closed
rule: `Settings` still raises and the API still cannot boot without a key, pinned by the config
tests rather than by compose. The check only decides which line the reviewer reads first.

**How the image was checked for secrets and for host artefacts is in
[Docker image, verified](#docker-image-verified) below** — after the demo flags, because it is
forensics rather than setup and it sat between `docker compose up` and a reviewer's first
successful run.

### Path B — local

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m spacy download en_core_web_lg     # 425 MB; do this before going offline

python demo.py                 # headless end-to-end, mock provider, exits non-zero on failure
```

`demo.py` generates an ephemeral master key if `SCP_MASTER_KEY` is unset, so it runs on a
clean clone with no `.env`.

**Do not skip the `spacy download` line, and here is the failure it prevents.** Presidio's
`SpacyNlpEngine.load` calls `_download_spacy_model_if_needed`, which calls `spacy.cli.download`
the first time an analyzer is constructed with the model absent
(`presidio_analyzer/nlp_engine/spacy_nlp_engine.py`). So the pip path does not fail fast on a
missing model — it silently fetches several hundred megabytes over the network at first use, and
on an offline host it fails inside detector construction rather than at install. The Docker path
does not have this behaviour at all, because the model is in the image. Downloading it
explicitly is what makes the local path as offline-capable as the container.

**One optional prerequisite, undeclared until an audit pass caught it: `node`.** Nothing the
pipeline does needs it — it is not imported, not in `pyproject.toml`, not in the image — but
`tests/test_ui_behaviour.py` executes `ui/app.js` under it and the whole module is
`skipif`-guarded on `shutil.which("node")`. Without it those tests skip in silence and the suite
still reports green, so the "`app.js` has execution tests" claim below is *unverified* on that
host. `node --version` is the whole check; the failure mode is a false assurance rather than a
broken run. The harness's scripted `fetch` awaits its responder — so a test can script *no reply
at all*, a promise that never settles — and rejects when `init.signal` aborts, the way a real
`fetch` does, so the request deadline can be tested against code that might have no timeout in it.

### Tests

```bash
pytest                  # full suite -- no API key, no network
pytest -m leakage       # 100-run zero-PII-in-transit harness
pytest -m bench         # performance benchmarks
mypy                    # --strict on the package
ruff check .
```

### Measured results

Everything below is output from this repository, not an estimate. Every figure names the command
that produces it — re-derive rather than trust, which is what checklist step 5 exists for.

#### The numbers this repository prints

```
2980 passed, 1 skipped       # full suite WITH node on PATH, as `pytest -q` printed it.
                             #   The skip is the real-network LLM smoke test.
                             #   2981 collected: 169 leakage + 9 bench + rest unit + integration
mypy                         # clean, 52 source files -- PACKAGE ONLY, see below
ruff check .                 # clean, whole repo
98% branch coverage          # pytest --cov=secure_context_pipeline --cov-branch
                             #   5,291 statements, 82 missed; 1,366 branches, 60 partial (package only)
```

**That block is checked rather than pasted, and this is the one place it appears.** Collection,
the marker split, both statement denominators, the two `mypy` file counts and the formatter
divergence are re-derived from the tree by `tests/test_readme_claims.py`, and `passed + skipped`
is asserted to equal what `pytest` collects, so a stale number reddens the suite instead of
misleading a reviewer; each failure message carries its replacement. The honest limit: no test can
run the suite from inside the suite, so what is bound is that this arithmetic is self-consistent
with what `pytest` *collects*. "Green" is the reviewer's own run. The coverage line is also the
one figure a red run moves — a failing test leaves its own paths unexecuted, inflating `missed`
and `partial` — so read it as a **floor**.

**On the scope of that `mypy` line, because "clean" is doing less work than it looks.**
`pyproject.toml` pins `files = ["secure_context_pipeline"]`, so the gate type-checks the
**package only** — 52 files. The test suite is roughly half the repository by line count and is
**not** covered by it. Run against the whole tree — `mypy --strict .`, which ignores that pin — it
is **92 files and 153 remaining errors**, none of which is a latent bug: **57** are `attr-defined`
from monkeypatching module-level re-exports (a legitimate test idiom `--strict` dislikes), **44**
are `arg-type` where tests construct `Detection(category="PII")` with a bare `str` instead of the
`EntityCategory` enum, and the remaining 52 are assorted narrowing complaints. Re-derive with
`mypy --strict . 2>&1 | tail -1` and `| grep -oE '\[[a-z-]+\]$' | sort | uniq -c | sort -rn`. Both
file counts are counted from the tree and pinned exactly and the split is pinned against its own
total; the error total stays unpinned, because it is a property of a run and re-deriving it in the
suite would check this paste against the tool it is a paste of. The package carries exactly
**one** `# type: ignore`, on the untyped `regex` import. The `arg-type` hits are the interesting
residue: those tests are not exercising the enum the production path carries, which is a mild
stub-blindness signal and a real next step rather than a config change.

**And the same question about the `ruff` line, which had a real hole in it.** `ruff check .` is
the *linter*. `ruff format` is the *formatter*, it is **not** in the gate, and `ruff format
--check .` reports **42 files** that would be reformatted (52 already formatted). That was
cosmetic on its own; what made it a defect is that `pyproject.toml` disabled `E501` with the
comment "line length handled by formatter" — so line length was enforced by the formatter, the
formatter never ran, and the stated 100-column limit was enforced by nothing. There were **145**
violations, four of them in the package.

`E501` is on now, and the accounting is stated exactly because "we turned the rule on" can hide a
blanket exemption. Of the 145, **49 are fixed and 96 remain**: **33 lay outside** the two files
that carry generated document text and all 33 are fixed, and a further **16 inside**
`tests/test_detection.py` were fixed rather than exempted, taking that file from 24 long lines to
8. **33 + 16 + 96 = 145**. The 96 that remain live in two per-file exemptions, argued rather than
blanket: `fixtures/*` (88 long lines) and `tests/test_detection.py` (8), whose long lines are
**generated and annotated document text** — `<<NAME|Aurelio Santangelo>>  <<SSN|602 33 1194>>`,
clinical notes, privileged memoranda. The detector is fed those strings verbatim, so wrapping one
moves a span offset and changes what the recall table measures; they are also inside
triple-quoted blocks, where `# noqa` cannot reach. A planted 110-column line in `config.py` was
confirmed to fail the gate, so the rule is enforced rather than merely configured. The 42-file
`ruff format` divergence is left as a stated gap — a large cosmetic diff with no correctness
content — and it is the only thing `ruff` is not gating.

That accounting was itself wrong twice, and both corrections cost something. It read "50 fixed
and 95 remain … from 24 long lines to 7" until this pass, from counting with `awk 'length>100'`,
which counts **bytes**: four exempted lines carry an em dash at three bytes each, so the byte count
says 9 where the character count — the one `ruff` uses — says **8**. And one of those eight is not
corpus text at all: `tests/test_detection.py:6941` is an ordinary list comprehension two columns
over, so the exemption's stated rule is true of seven of the eight. Wrapping the eighth is the
honest repair rather than widening the rule, and it is not made here only because this pass owns
this document and not that file.

**Coverage above is the package only** (`--cov=secure_context_pipeline`), which is the gate
`pyproject.toml` configures. Measured across the whole repository — package, tests, `demo.py` and
`fixtures/` — it is **98%** of **26,971** statements: **26,281** for the package plus `tests/`
plus `fixtures/`, and `demo.py`'s **690** on top of that. It is published as its two addends
because `demo.py` has to be measured separately: the demo tests load it by *file path* under a
synthetic module name, so `--cov=demo` warns `module-not-imported` and silently drops all 690 of
its statements. Every published number here is pinned **exactly** rather than banded, which is an
argued position: a band on the fastest-moving figure was found holding an 81-statement error, and
a replay of nineteen commits showed it bought exactly one green run, because the collected-test
count and the package denominator beside it are pinned exactly and move on the same commits.
`missed`, `branches` and `partial` stay unpinned — properties of a run this suite deliberately
does not perform.

**What the coverage number is worth.** It was not measured for the first four review passes, and
the cost shows up throughout this document: every "deleting X left the suite green" finding here
was found by hand, one mutation at a time. 98% of lines executed says nothing about what was
*asserted* — the **partial-branch list** is the useful artifact, and working it surfaced four
untested branches in the audit writer's own error handling, one of which would have wedged every
subsequent write on a transient fault. `demo.py` was the sharpest case of executed-versus-asserted:
fully executed by `tests/test_demo_flows.py`, but its twenty graded assertions were checked only by
*name*, so fifteen of the twenty ledger entries — including the fail-closed section's own control —
could each be replaced with the literal `True` and every test still passed. Each has a test that
falsifies exactly one condition now. That file is now 56 tests.

#### Leakage harness — 100 runs, zero leaks

`pytest -m leakage`: 100 runs, both strategies alternating, one freshly generated document per
run.

```
[leakage] 100/100 runs clean, 0 leaks (3066 originals vaulted and scanned, 2411 surrogates round-tripped)
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

The three lines under the tally were **added** rather than substituted — the tally is
byte-for-byte what it always was — and they say what it is and is not evidence of. The false-red
rate is quoted per channel so a reader can check the parts rather than take the total on trust;
the residual is named as **one-sided**, which is what keeps the caveat from reading as a discount
on `0 leaks`; and the rule-of-three number is there because *"it went green four times"* is the
argument the caveat was written against.

**Three of the four numbers on that tally line reproduce and the fourth does not, and the block
would be dishonest if it did not say which.** `100/100`, `0 leaks` and `3066 originals` came back
identical on all four consecutive executions measured for this pass. The surrogate tally did not:
**2411, 2422, 2421 and 2439** across those four runs. It counts surrogates the *model* referenced
and the restorer then round-tripped, and the mock provider's echo is drawn against a per-session
pseudonym key, so which surrogates come back is re-rolled every run. Treat a different value there
as normal; treat a `3066` that moved, or anything other than `100/100, 0 leaks`, as a finding.
`test_the_pasted_leakage_tally_is_one_the_readme_says_it_observed` requires the pasted figure to be
one this paragraph lists, because the block once published a value no run had printed.

**The originals tally moved, and that is the finding the rule above asks for rather than a silent
edit.** This block published **2,966** until this pass; the tree prints **3,066** on every one of
four consecutive executions. Document seeds are fixed, so the same 100 documents carry the same
values and this number is deterministic — a move in it is a change in what the detector plants or
finds, not noise. The candidate cause is this wave's detection work, of which the largest item is
the `SSN` registry backstop (Deviation 71), which turns nine-digit runs in identifier position
into vaulted originals that previously were not detected at all; that is an attribution rather
than a bisected result, and the honest statement is that the value was re-measured rather than
explained. Nothing about the *assertion* moves with it — `ledger.leaks == 0` is what the harness
asserts, and the tally is the evidence that the assertion was exercised over a real population.

**100 runs, zero leaks** is the load-bearing result, and its two halves are worth different
amounts. *`0 leaks` means exactly what it says*: the residual channel is one-sided, a collision
can only manufacture a red, and nothing in it can turn a leak green. *"It goes green every time"*
is the half that is not evidence — N clean executions bound the false-red rate at 3/N and no
tighter, so four of them bound it at 0.75 per suite, which is no bound at all. Read the summary
line precisely too: `Ledger.record()` counts runs that **completed** while `ledger.leaks` counts
what the scans found, so `99/100 runs clean, 0 leaks` is a coherent line. The harness refuses to
quote a tally over a smaller denominator (`assert ledger.runs == selected`), which is the failure
mode that would otherwise hide.

##### What this harness is worth: it reported 100/100 while blind to a real class of leak

That failure is the most useful thing in this section, and it happened in three distinct shapes.

**Four local copies of one rule.** The harness decided "does this value occur in this text" four
separate times, none agreeing with the gate. Two were *stricter* than the code and therefore hid
leaks — the payload scan used `(?<!\w)…(?!\w)`, and since `_` is a regex `\w`, `_John Smith_`
did not match its own planted original, nor did any value edged with punctuation (`tel(415)
555-0123`, `USD$1,234.56`). Two were *looser* and invented leaks: a bare `bytes` containment test
over the audit DB reads a six-digit original inside a 32-hex `run_id` as a leak. Three copies of
one bug agreeing with each other is not corroboration, it launders the claim — and a rare false
red on the headline assertion is worse than its frequency suggests, because it teaches the reader
to disbelieve the next one. All four route through the gate's own rule now, imported rather than
restated, so a divergence is an `ImportError` instead of silence. Three tests hold it: one
comparing that single definition against an independently written reference over 220 pairs, one
doing the same over **2,000 hypothesis-generated pairs** drawn from the character classes the rule
turns on, and `test_no_leak_comparison_in_this_module_bypasses_the_shared_rule`, which fails if
any bare membership test reappears — catching the **class** rather than the four instances. That
last rule was itself only scanning the first two-thirds of the file, found by sabotage rather than
by reading.

**Sharing the rule was actively wrong in one place.** "Never be laxer than the gate" is right for
leak *detection* and exactly wrong for round-trip *completeness*, where the expectation must be
able to disagree with the code it checks. The set of originals that must come back was built with
the production `TOKEN_RE` and the gate's occurrence rule — both of which the **restorer** also
uses — so a token the grammar could not see was dropped by the expectation, left in the answer by
the restorer, and missed by the residual scan. All three agreed, and the only visible effect was a
*shrinking denominator*, which nobody reads as a failure. The expectation is derived independently
now, enforced structurally over the parsed AST and behaviourally by
`test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots`. Computed both ways
over the same 100 runs in one process, old and new agree exactly (2,410 vs 2,410).

**Three channels the scan could not observe at all**, found by neutering the gate, splicing a real
original into a real payload, and checking whether the harness noticed:

| Leak shape | Gate | Harness (before) | Cause |
|---|---|---|---|
| One zero-width space inside the value | blocks | **blind** | the harness compared 2 forms; the gate compares **3** |
| Accented original in an audit `detail` | n/a | **blind** | `ensure_ascii` stores `José` as `Jos\u00e9` |
| Value logged via `extra={...}` | n/a | **blind** | `caplog.text` renders no `extra` fields |

The first is the mirror image of the earlier bug: the harness docstring asserted it scanned "the
same two forms the EgressGate scans", the gate had since gained a **third** — invisible-character
folding — and the harness was never updated, so the checker had become **weaker than the code it
checks**. On the payload that is survivable, because the gate is a second opinion; on the audit
database and the process log, where the harness is the only thing that looks at those bytes, one
U+200B was a complete bypass. The second and third are the same failure in a different disguise —
scanning a *rendering* of the channel rather than the channel. All three are closed, each with a
test that fails without the fix, and **the headline number did not move under the stronger
instrument**, which is the only reason it is worth more than it was.

##### The wire-level test: the same claim, on the bytes the SDK actually sends

Everything above observes at the *provider interface* — the string handed to `provider.complete()`
— and a bug between that call and the HTTP body would be invisible to it. That residual is closed
in CI now rather than only by `demo.py --real --dump-wire`.
`tests/leakage/test_wire_leakage.py` drives the real Anthropic SDK against a transport that
captures the **serialized request body** and scans those bytes against the vault. Measured: **178
vaulted originals across 6 real SDK requests, 23,334 bytes of captured body, 0 hits**. It needs no
API key and no network, because the transport is what is replaced, not the client.

**Those six cases were evidence of the obfuscator, not of the gate, and that was measured rather
than suspected.** On an ordinary document the engine replaces every detected value, so the body is
already clean when the gate is consulted and the gate's verdict is not load-bearing for any of
them. Forcing `EgressGate._scan_originals` — the whole of pass 1 — to `return 0` reddened
`tests/test_egress_gate.py` (**178 failed, 160 passed**) and nine tests in the harness, and left
this file **entirely green, 4 passed**. A file carrying the network-inspection requirement that
cannot see the last line of defence die is a green whose name overstates its evidence — the same
defect class as the harness's own blind spot above.

It is closed by running one document **twice**, differing only in what the vault knows.
`ZXQQ-KLM-RSTV-WYNP` is a value the shipped registry does not recognise, so the engine leaves it
in the payload and the detector-driven passes 2 and 3 cannot see it either. In the **control** run
the vault has never heard of it and the request goes out carrying it *byte-for-byte* — the
counterfactual made real rather than argued. In the **gate-bound** run the identical `doc_id` is
sent with the value seeded through `SessionVault.note_unrestorable`, the shipped path the engine
uses for a redact-band detection that gets no token, and pass 1 stops the request before it
reaches the transport at all. The delta between the two runs, read at `request.content`, *is* the
gate: `::test_the_gate_bound_case_is_a_real_counterfactual` holds the control,
`::test_the_vaulted_plant_never_reaches_the_wire` scans any body that escapes, and
`::test_the_gate_is_what_kept_it_off_the_wire` pins the block reason as `vault_original`. Re-run
with the same `return 0` sabotage the two named last go **red**, reporting the planted value in
the raw bytes of an outbound request.

This does not contradict the "three passes had to be silenced" measurement below: that one is
about a *detected* value, which passes 2 and 3 also catch. The plant is the case where only pass 1
can act, which is what makes it the probe that binds this file to the gate.

The other half of the same question — *are the bytes you hashed the bytes you sent?* — is pinned
three ways: `test_egress_gate.py::test_payload_sha256_is_the_digest_of_the_scanned_bytes` asserts
the digest in the audit event is the digest of the string the gate scanned; the harness's
`CountingProvider` asserts `sent_payload == result.obfuscated_payload` on every one of the 100
runs before it scans anything; and `demo.py` makes the same assertion a third time.

**Defence in depth, measured rather than asserted.** Producing a genuine wire leak required
silencing **three** independent gate passes: with pass 1 blinded the re-scan still blocked, with
passes 1 and 2 blinded the independent recogniser set still blocked, and only with all three
neutered did a vaulted value reach the captured body. That is the concrete content of
"fail-closed, three passes" — a count of how many things have to be wrong at once, not a
description of a diagram.

##### The four boundaries this harness does not claim

**The four boundaries named at the top of this file are stated rather than closed**, because
closing them would manufacture false reds indistinguishable from real ones. Each is pinned by a
test, so closing one later is a red rather than a silent widening of the claim:

- **Partial disclosure.** If a splice bug leaves *one component* of a multi-word original behind —
  the surname of a vaulted full name — neither the harness nor the gate reports it. Both ask
  whether the **value** occurs. A word-level scan is not safely assertable here: fixture originals
  include ordinary clinical phrases (`chronic low back pain`) and Faker surnames that are ordinary
  English words (`Brown`, `Rich`). So the honest form of the guarantee is *no whole vaulted value*
  reaches the payload, the audit log or the process log, and
  `test_a_partial_value_leak_is_outside_what_this_harness_claims` pins that boundary.
- **A value glued into a longer word — on the text channels only.** `xJohn Smithx` carries the
  original byte for byte and is reported by neither the payload scan nor the gate. The occurrence
  rule asserts a word boundary on each side whose adjacent needle character is alphanumeric, which
  is what stops `Brown` matching inside `Browning`; relaxing it only for multi-word originals does
  not rescue it, because `chronic low back pains` contains `chronic low back pain`. What keeps the
  residual risk small is that the pipeline cannot emit this shape — every surrogate and redaction
  marker ends in `]`, so a splice that leaves an original beside our own output has a
  non-alphanumeric character between them and *is* caught. Pinned by
  `test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims`.

  On the audit database it applies to one of the two limbs, and that division of labour is pinned
  rather than assumed. SQLite writes column values end to end with no delimiter, so an original in
  a label column sits in the *file* as `…EGRESS_BLOCKMarguerite Vandenbergdeadbeef…` — alphanumeric
  on both sides, and the **byte** limb is blind to it. The **query** limb sees the same value as
  `"entity_type": "Marguerite Vandenberg"`, where JSON quoting supplies the boundaries, and catches
  it. The obvious fix is wrong and was reverted before shipping: loosening the byte limb to plain
  containment re-opens the false-positive class the anchoring exists for, since `8.2` is an
  ordinary vaulted lab value and every audit row carries an `elapsed_ms`. Both directions are
  pinned end to end through the real writer by
  `test_the_audit_scan_catches_a_label_column_original_and_says_which_limb_did`, which asserts
  *which* limb caught it so the attribution cannot rot into "the scan handles it".
- *(Not one of the four — a retired boundary, kept as a record of how it was argued.)* **A
  combining mark spliced into a value — CLOSED.** The reasoning for leaving it open was *"folding
  marks out would make `José` and `Jose` the same value"*, which is true of the **needle** and
  irrelevant to the **haystack**: `_deaccent` strips marks from the payload only. The first
  version of the closure covered only *combining* marks, and a *spacing* diacritic walked straight
  through on the real gate, because NFKC expands one into a **space** plus a combining mark and
  folding the mark afterwards leaves the space behind. The skeleton form is derived with those
  characters removed first now, and the class is defined by compatibility decomposition rather
  than a hand-picked list. Two residuals, both pinned: a vaulted value that itself carries a mark
  is not protected against a *second* mark spliced into it, and a modifier *letter* with no
  diacritic decomposition belongs with the homoglyph boundary below.
- **Homoglyphs.** Cyrillic `о` for Latin `o` is different bytes, and catching it needs a UTS-39
  confusables table rather than another normalisation form. Out of scope in the gate for the same
  reason. Pinned by
  `test_egress_gate.py::test_a_homoglyph_substitution_is_outside_what_the_scan_claims`.
- **A multi-word original under the 8-alphanumeric floor, whose separator the payload respells.**
  The separator-invariant limb only runs on values long enough that a respelling cannot collide
  with ordinary English, so `Amy-Cox` or `AmyCox` for a vaulted `Amy Cox` walks the whole name out.
  The floor is measured rather than assumed: over 26 seeds × four kinds, 358 of 8,390
  multi-component values sit under it, and once the digit-bearing ones (still scanned unbounded)
  are removed, **91** are left with only the four bounded forms — 69 lab values, 19 small amounts
  and three names. Lowering it trades a narrow leak for a broad outage: at a floor of 5, `of the`
  becomes a needle that matches the shipped fixtures 67 times. Pinned by
  `test_egress_gate.py::test_the_floor_s_corpus_measurement_is_the_one_the_docstring_quotes`.

**Two of those four — partial disclosure and the glued-into-a-longer-word shape — are blind spots
the harness and the gate mostly share**, because both resolve to the same occurrence rule.
Confirmed rather than reasoned about: with the gate **live**, a real vaulted original spliced into
a real payload glued to a letter completed the run and reached the provider.

**"Mostly" is the honest word.** The glued-word boundary does **not** apply to digit-carrying
values: the gate has a fifth comparison, `_identifier_needles`, which tests a value as a bare
substring with no adjacency rule at all once it carries enough digits. That limb has **two floors,
and they are different numbers on purpose** — `MIN_IDENTIFIER_DIGITS = 7` over the whole value
(keeping six-digit dates and amounts out of an unbounded scan) and `MIN_IDENTIFIER_RUN_DIGITS = 6`
over one contiguous run (set by the registry, where `MRN` is `\K\d{6,10}`). They were **one**
constant, which is a **number justified against one channel silently setting another channel's
security floor**, and it was a live leak: with `552140` — a value the detector is *required* to
vault — the payload `Internal routing tag: MRN552140B must match the ledger.` missed on all four
limbs at once (the trailing `B` denies both word boundaries, six digits is one below the shared
floor, and pass 3 carries an SSN recogniser only) and released a vaulted MRN byte for byte. Fixed,
and — the part that matters more — pinned *at the seam* by
`test_no_shipped_identifier_pattern_can_match_below_the_gate_s_run_floor`, which reads
`entities.yaml` itself and goes red if config and constant ever disagree again. That test is
deliberately sourced from a **different artifact** than the code it checks, which is the one thing
that has reliably caught this class.

The harness keeps a **higher** floor than the gate on the audit DB and the process log
(`_HARNESS_RUN_FLOOR` = 7), and the cost is written down rather than footnoted: a vaulted six-digit
MRN core glued into an alphanumeric run *in those two channels* is not reported. The reason is a
false-positive budget measured on the real haystacks — 99 distinct 7-digit windows in one session's
audit query view against 7,574 in the DEBUG log haystack, the log figure being 170× the wrong side
of the line the floor was drawn for and never previously measured, because the arithmetic had only
ever been run against the database *files*.

**How the other shapes were confirmed.** The list above is what survived an attack, not what was
left over after reading the code. A copy of the pipeline was sabotaged — a real vaulted original
re-spliced into the outbound payload in twelve shapes, with the gate's original-value pass blinded
— and the harness was required to go red on each. It caught the verbatim value, markdown emphasis,
both punctuation-edged shapes, a value inside a token's `|hint` tail, a value split across a line
break, a case-only difference, and a value followed by a full stop. It missed exactly the three
above.

##### A fifth limit: organisation names are not an entity type at all

The four above are *scan* limitations — a value the vault holds that the payload can still carry
out. This one sits earlier: the specified registry defines the entity set and has no `ORG`,
`EMPLOYER` or `PAYER` type, so an organisation name is never detected, never vaulted, and
therefore never something the gate could look for. It reaches the provider by design.

It is called out because the demo makes it look like an inconsistency rather than a decision. In
`medical_note.txt` the hospital **is** obfuscated and the insurance carrier three lines away is
not — `ADDRESS` rides Presidio's `LOCATION`, and spaCy tags "Larkspur Valley **Hospital**" as a
LOCATION while "Pinnacle Grove Benefit **Trust**" is an ORG, which nothing maps. One org is
protected by accident and its neighbour is not. Adding an `ORG` type would close it in about four
lines of `entities.yaml` and is deliberately not done: the registry is the specified entity set,
inventing a requirement is not the same as meeting one, and a new type moves every recall number
on this page. What *is* done is making the gap measurable — `fixtures/generator.py` plants the
organisation names it writes, so they are counted ground truth rather than invisible: 72 distinct
values across 26 seeds × four kinds, appearing 163 times in the four committed fixtures. Planting
them does not close the gap and is not claimed to.

##### A sixth limit, the largest by volume: dates pass through outside medical documents

The specification defines the entity as `DATE: {category: PHI, presidio: DATE_TIME,
only_in_doc_categories: [medical]}` and spells the consequence out in prose as well: the type is
scoped to clinical documents on the HIPAA reasoning that a date tied to an individual is itself an
identifier, and anywhere else a plain date is left alone. So this is the specification being met
rather than a defect,
and `entities.yaml` is deliberately **not** widened to close it. Measured at the provider boundary
— distinct dates in the source, and how many of those exact strings survive verbatim into the
outbound payload:

| Fixture | Dates in source | Reaching the provider in cleartext |
|---|---|---|
| `legal_brief_large.txt` | 155 | **153** |
| `financial_disclosure.txt` | 12 | **11** — the whole PART IV transaction ledger plus the reporting period |
| `legal_memo.txt` | 4 | **4** |
| `medical_note.txt` | 8 | **0**, as designed |

**The surviving set is identical under both strategies, and that is the load-bearing part of the
measurement.** Under pseudonymization a *detected* date comes back as a shifted, date-shaped fake,
so counting date **shapes** scores the medical payload at 8 and reads like a leak; counting only
strings that are also in the source separates "never detected" from "detected and shifted". A set
that does not move between strategies is a set nothing ever detected. The few caught outside a
medical document are caught for other reasons, two by accident: `01/17/1977` in the disclosure is
under a `Date of birth:` label and is a `DOB`, while in the brief `01/25/2023` was typed `ADDRESS`
and `02/01/2023` `CLIENT_IDENTITY` — masked under the wrong label rather than covered by a rule.
Everything else in those payloads scanned clean under both strategies.

**What a reader of the boundary list would otherwise wrongly conclude.** Those four boundaries are
adversarial single values, and the headline claim is phrased about *vaulted* values, which is
silent on a value that was never vaulted. Nothing in either prepares a reader for a hundred and
fifty-three dates in the clear on the largest shipped fixture. Stated plainly: **outside a medical
document this system does not protect dates at all**, so a litigation chronology or a transaction
ledger reaches the model intact. If your threat model treats those as sensitive, this scoping is
the thing to change, and changing it is a product decision. Pinned by
`tests/test_declared_boundaries.py::test_ordinary_dates_pass_through_outside_medical_documents`
(four fixtures × both strategies, exact counts both sides) and
`::test_a_bare_date_is_detected_in_a_medical_document_and_not_in_a_legal_one`. Widening `DATE`
turns the table above red rather than leaving it silently stale — confirmed by deleting
`only_in_doc_categories: [medical]` and watching four of the six assertions fail.

##### A seventh limit: a plain NER recall miss, which the gate cannot backstop

The sharpest illustration in the project of a point made abstractly everywhere else. Reproduced on
the real detector against the shipped registry, three inputs differing only where marked:

```
"Name: Priyanka Raghunathan\nMRN: 9224297\n"    -> [(MRN, 9224297)]                  name unclaimed
"Name: David Ochoa\nMRN: 9224297\n"             -> [(NAME, David Ochoa), (MRN, ...)]
"Priyanka Raghunathan was admitted overnight"   -> [(NAME, Priyanka Raghunathan)]
```

Same frame with a different name: found. Same name in ordinary prose: found. This is spaCy recall
variance on one string in one shape, not a rule anything here wrote — which is why it cannot be
patched. End to end, the document the provider receives is this:

```
<DOCUMENT>
PATIENT CHART
Name: Priyanka Raghunathan   DOB: [PII_DOB_f7c8299e]
MRN: [PHI_MRN_392a5f00]
</DOCUMENT>
```

The date of birth masked, the medical record number masked, and the patient's own name in the
clear between them. That juxtaposition is what a reviewer will point at, and the honest answer is
that the gate was never the control that could have caught it:

| Pass | What it does | Why it cannot help here |
|---|---|---|
| 1 | Scans the payload for the session's vaulted originals | The name was never vaulted, so **the needle does not exist** |
| 2 | Re-runs *the same* `Detector` over the payload | A second look, not a second opinion — every blind spot it had at detect time it has again, over strictly the same string |
| 3 | A genuinely independent recogniser set | It matches **patterns**, and a person name is not a pattern — that is the whole reason `NAME` rides NER rather than a regex |

Three passes, three different reasons, one outcome. This is the concrete form of §7's first known
gap — *detection recall is the binding constraint on the whole system* — and the argument for
scispaCy or a self-hosted clinical NER being the highest-value next change rather than more gate
hardening. Pinned by
`tests/test_declared_boundaries.py::test_the_gate_cannot_backstop_a_name_the_detector_never_saw`,
which drives the real component graph: the detection premise, the absent needle in the vault, the
name on the wire with the DOB beside it masked, and both controls. If it goes red, recall improved
and this section is what has to change, not the assertion.

#### Benchmarks

`pytest -m bench -q -s`, budgets from the build specification. Measured on an M-series laptop with
nothing else running, one quiet invocation:

| Measurement | This run | Budget | Headroom | Scoring |
|---|---|---|---|---|
| Obfuscate 2,000 words (tokenization) | 0.379 s | 2 s | 5.3× | best of 3 |
| Obfuscate 2,000 words (pseudonymization) | 0.395 s | 2 s | 5.1× | best of 3 |
| Vault lookup p99 (1,000 cached reads) | 0.001 ms | 5 ms | 4,612.8× | single shot |
| Restore a 500-token response (warm vault) | 34.378 ms | 500 ms | 14.5× | single shot |
| Restore a 500-token response (cold vault) | 87.948 ms | 500 ms | 5.7× | best of 3 |
| Restore a 500-surrogate response (pseudonymization) | 121.750 ms | 500 ms | 4.1× | best of 3 |
| Full pipeline, 12k-word brief (mock provider) | 6.652 s | 15 s | 2.3× | best of 3 |

**The budget column is the claim; every other column is one observation on one laptop.** The route
to that framing is worth more than the numbers. The table carried single point values, then
ranges, then *floors* — "≥ 2.2×", "≥ 3,600×" — on the reasoning that a floor only gets safer with
more measurements. Then more measurements broke one floor and came within 1% of another. A floor
computed from seven samples is not a bound; it is an estimate of a tail from seven draws, wearing
the costume of caution. So the columns say what they are, and the only number this page asserts is
the budget, because the budget is the only one a test enforces.

**And the table is bound to the run now rather than pasted from one.**
`test_the_readme_benchmark_table_is_the_one_this_run_measured` compares it against the
measurements the module just took: the budget column against the constants the suite asserts, the
row set against the rows the module records, the headroom column as arithmetic on each row's own
numbers at the precision printed, every published sample against its own budget, and — the part
that survives being run on another machine — **the identity of the tightest row**, since a slower
box moves every row together. It is why the previous table could not survive this pass: it
published a warm restore at 93.3× headroom while the module measured it in single digits, and
nothing on either side noticed. The staleness ratio between published and measured headroom is
bounded at 4×, deliberately loose, because a tighter bound fails on honest hardware differences.

The **full pipeline on the 12k-word brief is the tightest row in the table** at 2.3×, and that is
a property of the code rather than of the box. The three restore rows exist because the shipped
single row measured the **warm** path and called it "restore": obfuscation has just filled the
vault's `_SessionCache` in the same process, so the request path does zero SQLite reads and zero
AES-GCM decryptions. That is the production path and worth publishing, but it is not the worst
case, and the pseudonymization pass — the expensive half — had no budget assertion at all. There
are three now, all against the same 500 ms `BUDGET_RESTORE_MS`, and the warm/cold split is
verified rather than asserted by counting `SessionVault._fetch_one`: **0 calls warm, 500 cold**.

**Why two of these are best-of-3, and why that is not the same as widening the budget.** A
wall-clock assertion measures the machine as much as the code, and a benchmark that goes red
because a reviewer's laptop was indexing is one people learn to re-run until it is green — worse
than not having it. The property asserted is *achievability*: "this pipeline **can** do the work
inside the budget", and for that the fastest clean observation is the correct estimator while a
contended one is simply a worse measurement of the same thing. Relaxing the budget instead would
weaken the claim, which is the one thing not on the table. It still catches a real regression, and
that is checked rather than argued: a deliberate +10 s regression injected into
`PipelineOrchestrator.run` fails the full-pipeline budget, because a genuine slowdown affects
every iteration and therefore moves the minimum. (A +6 s regression passes — correctly, since that
is genuinely inside a 15 s budget.) If your own run lands outside these readings that is expected;
if it lands outside the *budget*, `pytest -m bench` will say so.

Full pipeline detail, mock provider, analyzer already warm (median of three runs):

| Document | Size | Spans | Distinct entities vaulted | End to end |
|---|---|---|---|---|
| `legal_brief_large.txt` | 12,062 words | 739 (647 obfuscated, 64 redacted, 28 stripped) | 251 | **6.48 s** (budget 15 s) |
| `medical_note.txt` | 393 words | 52 (51 obfuscated, 1 redacted, 0 stripped) | 32 | **0.29 s** |

Counts are **engine-level** — what `PipelineResult.detections` carries and what `demo.py` prints —
not detector-level. The detector returns 54 spans for the medical note; overlap resolution and
dedupe reduce that to the 52 the payload is built from. The brief's row is consistent on the same
basis: 647 + 64 + 28 = 739.

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

### Docker image, verified

The image was **2.85 GB** earlier in this build, and why it moved matters more than the size. The
Dockerfile used `COPY . .`, which shipped the whole working tree: a 745 MB host virtualenv built
for the wrong platform, `.git`, `data/` (real encrypted blobs, the vault, the audit chain) — and
`.env`, which would have put `SCP_MASTER_KEY` in a published layer, where it decrypts every
document in the store. An explicit `COPY` allow-list plus a `.dockerignore` fixed the leak and
took 1.54 GB out of the image at the same time. A deny-list forgets; an allow-list cannot.

```bash
# 1. No secret reached a build instruction (ENV / ARG / RUN):
docker history --no-trunc secure-context-pipeline:1.0.0 | grep -cE 'SCP_MASTER_KEY=|ANTHROPIC_API_KEY='   # -> 0

# 2. And -- the check that actually catches THIS bug -- no secret reached a layer's *contents*:
docker run --rm --entrypoint sh secure-context-pipeline:1.0.0 -c \
  'ls -a /app; find / -xdev \( -name ".env" -o -name "*.key" -o -name "id_rsa" \) 2>/dev/null'

# 3. And no host-compiled bytecode, which is the same blind spot one level down:
docker build -t secure-context-pipeline:1.0.0 .
docker run --rm --entrypoint sh secure-context-pipeline:1.0.0 -c 'find /app -name "*.pyc" | wc -l'   # -> 0
```

Command 1 alone would **not** have caught the leak it is printed under: the offending instruction
was `COPY . .`, and that is all `docker history` records — the layer's *contents* are where `.env`
was, and history never shows them. Command 3 exists because command 2 has the same blind spot one
level down, and it cost 38 files: `.dockerignore` patterns are anchored to the context root unless
they start with `**/`, so `__pycache__/` meant `./__pycache__` and nothing else while `COPY
secure_context_pipeline/ secure_context_pipeline/` copies an allow-listed directory *whole*. The
1.0.0 image therefore shipped 38 host-compiled `.pyc` files and imported them, so the container ran
bytecode built on a macOS host rather than bytecode derived from the source it shipped;
`PYTHONDONTWRITEBYTECODE=1` cannot help, because it stops the image *writing* them and these
arrived pre-written. The same anchoring made `.env`, `*.pem` and `*.key` inert below the root — a
probe context with a seeded `secure_context_pipeline/.env` shipped it while the root `.env` was
correctly excluded. Every rule meant to match anywhere is spelled `**/` now; `data/` stays anchored
on purpose, because `**/data/` would also remove the gazetteers. Measured both ways against Docker
29.4.1: the pre-fix image answers `38`, a rebuild on the same tree answers `0`, and both gazetteers
are still present. `tests/test_build_context.py` pins the rule statically, so the property survives
on a machine with no daemon.

The container runs uvicorn with `--no-access-log`, and that is a control rather than tidiness.
uvicorn's access logger writes the request line verbatim — path *and* query string — to stdout,
which compose pipes into the container log, and two routes carry a credential pair there:
`DELETE /sessions/{id}?user_id=…` is the whole of what an irreversible cryptographic erasure needs,
and `GET /documents/{doc_id}/text?user_id=…` is the document read pair. `SessionRegistry._handle`
logs a truncated SHA-256 instead of a session ID precisely to keep that pair out of the log stream;
the access log put it back one line away. Per-request visibility is not lost — the audit chain
holds it in a masked, access-controlled, tamper-evident form. Pinned by
`tests/test_log_stream_hygiene.py`.

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

**Three controls this layer ships that the specification's table does not describe**, and that
nothing above used to mention. They were built, they are tested, and they were invisible to anyone
reading this document — which for the strongest work in the API layer is the wrong way round:

- **`GET /audit` proves ownership, it does not merely scope.** `user_id` is mandatory (the
  documented call without it is a **422**) and the route checks it against the owner recorded in
  the log at `SESSION_CREATE`. A wrong owner gets a byte-identical empty page rather than a
  distinguishable error, so the endpoint cannot be used to confirm that a session ID is real.
  Without this the log handed any anonymous holder of a `run_id` the `session_id`, `doc_id` and
  `user_id` of that run — i.e. both credential pairs needed to read the original document and to
  erase the vault. `routes/audit.py` calls the previous behaviour "a live, complete break", which
  is accurate.
- **Failed ownership proofs are metered and audited.** ~20 failures from one caller earns `429`,
  and each writes an `AUDIT_ACCESS_DENIED` event — a **13th** event type, and one that sits
  deliberately **outside** `EVENT_TYPES`. That frozenset stays the build doc's fixed **twelve** and
  is asserted by count in `tests/test_audit.py`, so the only phrasing true of the code is *twelve
  members of `EVENT_TYPES`, all emitted, plus a thirteenth emitted beside it* — written and chained
  like any other row. Writes (`POST /sessions`, `POST /documents`, `DELETE /sessions/{id}`) are
  metered on the same mechanism.
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
| `GET /audit` | compliance query | **Requires `session_id` or `run_id`**; unscoped is `400 AUDIT_SCOPE_REQUIRED`. Also filters `event_type`, `since`, `until`; paginated. `since`/`until` must be **finite** and `offset` must fit SQLite's signed 64-bit `INTEGER` — both `422` otherwise, and neither refusal is tidiness: a `NaN` bound binds as SQL `NULL`, so the window was silently dropped rather than matching nothing, and an `offset` past 2^63−1 raised an `OverflowError` no handler was registered for, escaping the middleware stack entirely and answering a bare `text/plain` 500 with no CSP and a logged traceback, repeatable for free from one anonymously minted session. |
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
**404** while `curl /health` returned 200. It is the first probe a load balancer tries. The same
handler is registered twice rather than once with `methods=[...]`, because FastAPI derives one
operation ID per route and the combined form ships a duplicate into the schema. `HEAD` on the
other `GET` routes still 404s and is tracked separately.

**Four response headers, stamped on every response by middleware, not per route.**
`content-security-policy` (`default-src 'none'`, `frame-ancestors 'none'`, `base-uri 'none'`),
`x-content-type-options: nosniff`, `referrer-policy: no-referrer` — and, added late,
**`cache-control: no-store`**. That fourth matters more than its size: `GET
/documents/{doc_id}/text` is one of exactly two endpoints allowed to return decrypted original
plaintext and it shipped with **no `Cache-Control` at all** (measured; `grep -rni no-store` matched
nothing in the tree), so that body was storable by any intermediary and by the browser's disk
cache, outliving the session TTL and the cryptographic erasure on a machine the process does not
control. It is stamped on every response rather than on that one route for the same reason
`METERED_METHODS` keys on the HTTP method rather than a path allow-list: a per-route list goes
stale the moment a route is added.

**The 422 no-echo guarantee had exactly one exception and no longer does.** Error paths report
*which fields* failed and never the caller's input — except that under `extra="forbid"` pydantic's
`extra_forbidden` `loc` ends in the caller's **own** key, which the handler joined straight into
`fields`. Measured: a body carrying `{"evil_field_<script>": 1}` came back as
`{"errors":1,"fields":"body.evil_field_<script>"}` — up to 64 characters of attacker-chosen text
out of the endpoint whose documented purpose is not reflecting the caller's input. An extra field's
name is reported as `body.<extra>` now; declared field names are still named, because that is what
makes a 422 actionable.

#### `GET /fixtures/{name}` — the only file-serving route, and the only unauthenticated read

Added late, to close Deviation 57 (the preset dropdown named four documents the page had
no way to fetch). It is the first control a reviewer clicks and the one route on this surface that
takes a **filename** from a caller, so it gets more space than its handler's size suggests.
`secure_context_pipeline/api/routes/documents.py` is the implementation.

**What it serves: four literals, read once at import.** The allow-list is a `MappingProxyType`
mapping an exact filename to the `doc_category` it is scanned under — `medical_note.txt` →
medical, `legal_memo.txt` → legal, `financial_disclosure.txt` → financial,
`legal_brief_large.txt` → legal. All four are **synthetic**, generated by `fixtures/generator.py`,
and they already ship in the clone and in the image, so publishing them over HTTP moves no
boundary: anyone who can reach this port can already read them out of the repository.
`_load_shipped_fixtures` reads them into a second frozen mapping once, at import — **91,935
bytes** (2,826 + 3,260 + 2,820 + 83,029) resident for the life of the process, a median 0.206 ms
to load over 50 repeats.

It is a literal table rather than `FIXTURES_DIR.glob("*.txt")`, and that difference is the whole
control. A glob makes the served set a property of the filesystem *at the moment of the request*:
a scratch file, a document a reviewer dropped in, a symlink planted by anything that can write
there — each becomes world-readable on an anonymous GET the instant it appears, with no diff and
no review. With a table, adding a name is a diff. That these four names are the ones the repo
ships is measured against `git ls-files`, not asserted, by
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
things hold: it would gate content the same origin already publishes anonymously (`GET /` and
`GET /app.js` return 200 with no credential of any kind); a session is not a credential here,
because `POST /sessions` mints one for any `user_id` an anonymous caller asks for, so a session
gate would mean "make one extra anonymous request first" rather than "authenticate"; and it would
reintroduce the friction the route was added to remove. The counterweight is real and is not
softened: this is an unauthenticated read that returns bytes the server holds. That is precisely
*why* the control is a closed four-name allow-list rather than authentication — authentication
decides *who* may read, and the property that matters here is that **there is nothing else to
read**. Pinned in both directions by
`test_the_fixture_route_takes_no_session_and_can_reach_no_user_data`: an anonymous GET is served,
a bogus `X-Session-Id` changes nothing (so there is no half-state where a reviewer believes they
authenticated), and the handler's signature is asserted to be exactly one parameter — no
`ServicesDep`, so it cannot reach the encrypted store, the vault, the audit log or the registry.
Add a services dependency later and that test goes red, which is the moment the session question
gets asked again.

**Traversal was tested, not argued.** The committed corpus is `TRAVERSALS` in
`tests/test_api_documents.py`: **20** names, each driven through
`test_no_name_a_caller_can_send_reaches_a_file_off_the_allow_list`. Two details make it evidence
rather than decoration. It is driven at the **ASGI layer**, by a hand-built `scope`, because
`httpx` removes dot segments from a request target before any transport sees it — a traversal sent
through the client library would be testing `httpx`. And the assertion is *which* 404: a refusal
carrying `reason: not_a_shipped_fixture` came from the allow-list, where a bare routing miss would
mean the allow-list was never consulted; `/etc/passwd` and `fixtures/generator.py` both exist and
are readable by this process, so a route that joined the caller's string onto a directory would
answer **200 with content**.

That corpus was re-run for this pass against a **live uvicorn** over a raw socket, writing each
request line verbatim: **36** request lines, which account for themselves as **32** + **3** +
**1** — thirty-two `404 NOT_FOUND` with `reason: not_a_shipped_fixture` and no echo of the caller's
string, three that did something else, and the positive control, which returned **200** and the
2,826 bytes on disk. The corpus covers dot-segment traversal raw, single-encoded, double-encoded,
overlong-UTF-8 and fullwidth-solidus; absolute-form request targets; backslashes; NUL bytes; suffix
traversal; whitespace padding; case variants; a trailing dot; an NTFS stream suffix; a Unicode
lookalike; real neighbours off the list (`generator.py`, `.env`); and the degenerate names. The
three exceptions are stated rather than rounded up into "all 404": a raw NUL byte and a leading
space are rejected by `h11` with a **400** before routing (they still reach the allow-list in the
ASGI test, which is where a protocol parser cannot answer first), and a bare trailing space is not
deliverable over HTTP at all, since the space is the request-line delimiter — that is the client's
normalisation, not this route's, and the encoded form is a 404.

**Symlinks are refused at load, so the 404 is a property of the table.** A request cannot
express a symlink, so this was verified end to end: a copy of the package was run from a temporary
root whose `fixtures/medical_note.txt` was a symlink to a planted `root:x:0:0:` file outside the
directory. The server logged `demo fixture refused: symlink` at startup and answered **404**
(`reason: fixture_not_installed`) for that name while the three untouched siblings still returned
200. The loader also refuses a non-regular file, anything over 1 MiB, and bytes that are not valid
UTF-8, and `test_a_readable_file_beside_the_fixtures_is_never_loaded` plants a `.env` holding a
`SCP_MASTER_KEY` in the very directory the loader reads and shows it is not loaded — the gate is
the allow-list, not the directory. `test_the_served_table_cannot_be_extended_at_runtime` closes
the last way in: both mappings are `MappingProxyType`, so no fifth entry can be added after the
reviewed four.

**What the response is, and what it is not.** `text/plain; charset=utf-8`, with the four
middleware headers on top of it, so a browser that navigates here renders inert text. The route
stores nothing and issues no `doc_id`: the page takes these bytes straight back to
`POST /documents` as an ordinary multipart upload, so the preset is not a second ingestion path —
proved end to end by `test_a_preset_run_and_a_hand_picked_run_of_one_fixture_detect_identically`.
The one thing this route is *not* is metered: `METERED_METHODS` covers writes. Behind a proxy it
is therefore an unmetered anonymous read of four fixed files, which is the honest statement of its
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

### Four residuals in the storage layer, stated rather than discovered

- **The AAD concatenation is unambiguous, and a test enforces it.** Both AADs are colon-joined
  from attacker-influenced identifiers — `doc:<user_id>:<doc_id>` and `<session_id>:<token_id>` —
  and concatenating identifiers into an authenticated field is a classic way to build a collision:
  if `("alice:x", "y")` and `("alice", "x:y")` produced the same AAD, a caller who controls a
  `user_id` could authenticate against somebody else's blob. They cannot, and the reason is
  structural — the **right-hand component is fixed-width**, a `doc_id` being exactly 32 hex
  characters and a `token_id` exactly 8, so the string parses unambiguously from the right whatever
  the left component contains. That is a guarantee about a *format*, so the crypto tests import the
  store's own `_DOC_ID_RE` rather than restating the width: widening `doc_id` breaks a crypto test
  rather than silently dissolving the argument. A production build would length-prefix each
  component instead.
- **A document's two blobs share one AAD, so they are interchangeable on disk.** Each upload stores
  the raw bytes and the extracted text; the specified `AAD = doc:<user_id>:<doc_id>` is per
  *document*, not per blob, so an attacker with write access to the data directory can overwrite
  one with the other and have it read back cleanly. Checked rather than reasoned about: swapping
  the files on disk and re-reading succeeds. The impact is **integrity only, and bounded** — both
  blobs belong to the same document and the same owner, both decrypt solely under that owner's
  derived key, and no value crosses a user or session boundary. The fix is one more AAD component
  (`:raw` versus `:txt`), which is a one-line change and a spec deviation. It is written down here
  rather than left to be discovered, and it is the kind of thing a docstring claiming "blobs are
  not portable" would have hidden — that claim was in this codebase, and it was false.
- **The document read path is not timing-uniform.** The response to "absent document" and "wrong
  owner" is identical in every byte a caller can read, and not in *time*: an absent `doc_id` fails
  immediately at `ENOENT` while a wrong-owner one is read off disk in full and *then* rejected by
  AES-GCM. Measured on a 2.25 MB blob: **0.067 ms vs 1.199 ms, about 18×**, and the gap grows with
  blob size. What it discloses, precisely: that a `doc_id` the caller *already holds* corresponds
  to a stored document. Not the owner, the content, the category or any plaintext — and a `doc_id`
  is 32 hex characters, so an attacker who cannot already name one learns nothing. It is not fixed
  because the obvious equalisation (check the metadata table first) trades a cryptographic
  guarantee for a bookkeeping one: isolation here is deliberately a property of key derivation, and
  making reads conditional on a row means a lost row denies a legitimate owner a document they can
  still perfectly well decrypt. A constant-time read closes it at the cost of full disk I/O on
  every miss. Neither trade is obviously right at this tier.
- **Filenames are stored in cleartext, deliberately**, and there is a real tension in it.
  `extraction.py` logs only a file's *suffix*, never its name, on the reasoning that a filename can
  itself be a personal identifier — `chen-oncology-2024.pdf` discloses a name and a probable
  diagnosis before a byte is decrypted. That reasoning is correct, and the `documents` metadata
  table nevertheless stores `filename` in cleartext. Three reasons make the two positions
  consistent: metadata is queryable by design and the store has to answer "list this user's
  documents" without decrypting every blob; the boundary this system defends is egress, not the
  local disk, and the threat model already grants that the metadata DB leaks shape (counts,
  categories, sizes, timestamps), of which a filename is more of the same class; and it never
  reaches the provider. So the line is drawn at **acceptable at rest in a store the operator
  already controls, unacceptable in logs**, which are shipped, aggregated, retained under different
  rules and read by people never granted access to the documents. If filename confidentiality at
  rest were required, the change is small — encrypt the column under the user's document key, keep
  a blind index for listing.

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

**What that number is worth, stated precisely.** The same work wrote both the corpus and the
fixes it drove, so it measures **the shapes it knew to look for** and does not transfer to
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

**`NAME` is the weakest point of this whole submission, and it is not close.** Not because 81%
is the lowest number — it is not — but because of the count and the consequence. It is 58 of the
366 values, so it is the largest absolute quantity of PII left in the clear, and it is the entity
the entire pseudonymization design rests on. A missed `NAME` is invisible to **all three** egress
passes: never vaulted, so pass 1 has nothing to look for; not in `HIGH_SEVERITY_TYPES`, so pass 2's
re-scan cannot block it; and `_INDEPENDENT_PATTERNS` holds SSN entries only, so pass 3 has no
opinion. Demonstrated end to end using one of the detector's own printed held-out misses:

```
POST /pipeline/run -> 200 ; egress_rescan_warnings: 0.0
outbound payload: "…Specimen received from Ingeborg Vasquez-Lund, seen with [PII_NAME_aa096360].…"
```

A real surname in the clear, in the same sentence as a tokenized one, with the gate reporting zero
warnings. `SETTLEMENT_TERM` at 0% and `DATE` at 30% are smaller in volume with the same shape of
failure.

**This is the honest bottom line.** Detection recall is the binding constraint (§7), and an entity
the detector misses is not merely unblocked: it never enters the vault, so pass 1 does not scan for
it, pass 2 re-scans with the *same* detector and shares the miss exactly, and the 100-run leakage
harness plants only values the detector found — so it cannot see the miss either. **The instrument
that measures leaks is blind to precisely the leaks that matter most.** `100/100 clean` is
therefore a statement about values the detector found, not about all PII in the document. The
architectural answer is that the gate is fail-closed over the vault — a defence in depth that does
not depend on recall — and the engineering answer is a clinical NER model rather than spaCy plus
gazetteers. Neither makes 81% on `NAME` acceptable, and it is stated here rather than left for a
reviewer to find.

What makes the fixes more credible than the number is that five of the six came from a
**property** rather than a corpus row — Public Suffix List validation dropping internal domains,
newline-terminated tails truncating hard-wrapped sentences, a greedy quantifier swallowing the
next value's boundary, lemma-inert context words, and score-versus-specificity ranking. Each is a
defect you can reason about without the corpus, and each has an independent test. The **gazetteer
expansion is the exception**: it is the one change fitted to observed data, and the one to
discount.

**Known gaps in detection, stated plainly:**

- **Gazetteer recall.** 170 medications and 208 diagnoses cover the common cases. A rare drug or an
  unusual phrasing is missed, and a gazetteer is a closed vocabulary by construction — it cannot
  generalise the way a clinical NER model does. scispaCy or Comprehend Medical is next.
- **Full-name recall is bounded by spaCy, not by configuration**, because `NAME` and
  `CLIENT_IDENTITY` both resolve to Presidio's `PERSON`. No amount of registry tuning moves it. It
  is the single strongest argument for a better NER model and the reason the egress gate cannot be
  a detection-quality story: the gate is what makes the residual **safe** rather than invisible.
- **Emails at dotless hosts are missed by design.** `user@localhost` and similar single-label hosts
  are not matched, because the backstop pattern requires a dot in the domain and anything looser
  starts matching ordinary prose containing `@`. A deployment carrying dotless internal hosts needs
  an explicit allow-list of them.
- **Presidio's `DATE_TIME` over-fires on relative prose** — "daily", "overnight", "the last twelve
  hours". Left unhandled these poison the vault: once "daily" is a known original, the egress gate
  blocks every payload containing the word. Mitigated with a registry-driven `require_digit` rule
  (a date that *identifies* someone carries a numeral). A precision patch, not a fix for the
  underlying recognizer.
- **Free-text legal strategy detection is heuristic.** The `CASE_STRATEGY` patterns catch common
  phrasings and will miss paraphrases, which is why that entity is `action: redact` rather than
  tokenized — see §6.
- **`aiosqlite` is thread-wrapped, not truly async**, and the **session registry is
  single-process**: session keys live in one process's memory, so multi-node requires Redis plus
  KMS-held envelope keys, and a restart kills every live session (the same property that makes
  destruction cryptographic).

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
registered, and never *selected* — and the corresponding `unknown_*` branches were unreachable
from a validated `Settings`. Both fields are `str` now and both still fail closed, at different
points and for a stated reason: `key_provider` at startup in `EncryptedDocumentStore.__init__`,
and `strategy` at `Settings` construction, because `build_strategy` runs *per span* and leaving
the check there would turn a config typo into an HTTP 500 per run instead of a refusal at startup.
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

This README previously named it as the next change: restrict pass 2 to the spans *not* covered by
an emitted surrogate, skip the constant system prompt, "the single largest win available",
"changes no guarantee". Both halves were wrong, and the measurement is worth more than the
optimisation would have been.

**It is not the largest win. It is barely a win.** Median-of-7 on the 12k-word brief (an earlier
min-of-3 pass reported 25–39% and was measuring noise):

| Pass-2 input | Chars | Time |
|---|---|---|
| Full payload (today) | 86,753 | 2,677 ms |
| Minus the system prompt | 85,919 | 2,713 ms (**+1.4%**) |
| Minus every protected span | 66,879 | 2,491 ms (**−7.0%**) |

Protected spans cover **22.9%** of the payload — not the ~95% this README used to assert without
measuring — and the system prompt is **834 chars, 0.96%** of it, so skipping it saves nothing at
all. The whole optimisation is worth ~186 ms of a ~6,410 ms run: **2.9%**. (The payload length
drifts by ~100 characters between sessions, because Tier-2 dates are re-rendered under a
per-session shift and `12/15/2024` is not the width of `5/3/2024`; the two ratios that carry the
argument re-derive exactly.)

**And it does not preserve the guarantee.** Excising spans changes what the detector finds in
the text that *remains*: spaCy NER is conditioned on surrounding tokens, `_resolve_builtin` picks
between claimant entity types using character-distance context windows, and removing a fifth of
the payload moves every chunk boundary. Measured across both strategies and three fixtures, the
excised scan **lost a finding the full scan makes in four of six configurations** (`ADDRESS` ×3,
`NAME` ×1) and *gained* one in a fifth. It is a different scan, not a cheaper one — and "changes
no guarantee" is not something you can say about a change that demonstrably changes the output.
There is a second, structural reason: the protected-span set is derived from `STRICT_TOKEN_RE` run
over the **uploaded document**, so letting it decide what the detector *ever sees* would upgrade an
uploader's lever from "suppress a finding on my own token" to "reshape the gate's input" — a
strictly larger version of a bug already fixed.

**What the measurement points at instead.** Everything in `HIGH_SEVERITY_TYPES` — `SSN`, `MRN`,
`ACCOUNT_NUMBER`, `TAX_ID` — is pattern-typed, and those recognizers alone, over the full payload,
complete in **0.67 ms: 0.025% of the spaCy pass**. spaCy's ~2.7 seconds inside the gate therefore
buys exactly one thing, the advisory `rescan_warnings` counter. Splitting pass 2 into a cheap
always-on pattern check and an optional NER canary is the real answer, and it is a change to the
gate's *contract* rather than a scoping tweak. Not shipped: rewriting the security centrepiece's
blocking path deserves its own review cycle, not a footnote in a perf section.

Bottlenecks in order, corrected by measurement:

1. **The second spaCy pass**, ~43% of end-to-end wall time (2,759 ms of the 6.4 s above). It cannot
   be *scoped* away safely, per the measurement above; the tractable form is making the blocking
   path not need spaCy.
2. **spaCy NER itself**, which is then the floor for both passes. It scales roughly linearly with
   document length; mitigated today by paragraph-boundary chunking with parallel per-chunk analysis
   (`asyncio.to_thread`, semaphore of 4). The scale answer is a process pool or a sidecar detector
   service, because this is CPU-bound and the GIL is the ceiling, not I/O.
3. **Vault writes** are individually trivial (p99 **0.001 ms** cached) but are issued one per
   unique entity. Batching into a single transaction per run removes the syscall overhead.

Aho-Corasick for the originals scan — the obvious answer, and the one this README gave before the
passes were timed separately — would optimise **277 ms out of 6,400**, i.e. 4.3% of the run. It is
the right asymptotic shape and the wrong thing to do first. That is worth saying plainly: the
`O(payload × entities)` term was reasoned about rather than measured, and measuring it changed the
ranking.

**"So why haven't you fixed it?"** Fair question, and the answer is not "no time". The fix is a
change to the *security-critical* component, and it is the one component where a subtle mistake is
invisible: the gate is what makes the zero-egress claim true, and an optimisation that skips the
wrong span produces a payload that looks clean and is not. Narrowing pass 2 using the engine's own
output means trusting the engine to tell the gate what it already handled, which is precisely the
coupling the two-pass design exists to avoid. There is direct evidence from this build that the
instinct is dangerous: an earlier attempt to exempt emitted spans from pass **1**, for the same
reason, looked obviously correct and *hid a real leak* — a pseudonym containing another entity's
genuine surname. It was reverted and the fix moved upstream into the collision guard, where it
could be made true rather than assumed.

So the honest position is: **it is measured, it is understood, it is scoped, and it is not
shipped**, because the headroom against the budget — **2.3× on the run §1 publishes** — does not
justify taking risk in the one component whose correctness the entire submission rests on. What
would change that: an extension of the leakage harness that runs the optimised gate and the naive
gate over the same payload and asserts they agree on every run, so the optimisation is checked
against the thing it is replacing rather than against my confidence in it. Half a day, and it is
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
capability in one auditable component is the point, not an accident: the alternative to one
high-value target is the same capability smeared across every payload the system has ever
emitted, with no authorisation step and no audit record (that is Q6's argument, reached from the
other side).

The useful form of the question is *which attacker*, because the vault answers four of them
differently and only one of the four is a cryptography problem.

| Attacker | What they get | Why |
|---|---|---|
| **Vault DB at rest** (stolen backup, mounted volume) | Nothing usable | Entries are AES-256-GCM under a key derived from a session key that exists only in process memory and is never persisted. There is no key on disk to steal alongside the ciphertext. |
| **Row-splicing with DB write access** | A GCM authentication failure | AAD binds every row to `session_id:token_id`, so a row moved between sessions or between tokens fails to authenticate rather than decrypting to somebody else's value. Pinned by `test_vault.py::test_aad_binding_across_sessions` and `::test_aad_binding_across_token_ids`. |
| **The HTTP layer above it** | **This was the way in, three times** | See below. The vault's cryptography was never the weak part. |
| **Code execution in the live process during an active session** | Plaintext, out of the cache | Out of scope for this tier, stated in the threat model rather than hidden. Session-lifetime plaintext lives in RAM by design — it is what makes a sub-millisecond lookup possible. |

**The way in was the API, and the honest version of this answer says so.** Three real holes,
found and closed during this build rather than designed against afterwards:

- **`GET /audit` published live session IDs to anonymous callers**, and `DELETE /sessions/{id}`
  then accepted them — full vault destruction with zero credentials. The route now requires a
  `session_id` or `run_id` scope and *proves ownership* against the owner recorded at
  `SESSION_CREATE`; a wrong owner gets a byte-identical empty page rather than a distinguishable
  error, so the endpoint cannot be used to confirm that a session ID is real.
- **A session ID was a bearer credential for anyone else's documents.** Sessions are bound to the
  `user_id` that created them now, and `POST /pipeline/run` compares with `secrets.compare_digest`
  and answers the same `401 SESSION_EXPIRED` as an unknown session.
- **`DELETE /sessions/{id}` — the one irreversible operation in the system — took no owner.** It
  requires the owner's `user_id` now and answers an unconditional 204 either way, so it is neither
  usable by a stranger nor readable as an oracle.

Failed ownership proofs are metered (~20 from one caller earns `429`) and each writes an
`AUDIT_ACCESS_DENIED` event. The meter keys on the **source address**, because that is the only
caller identifier this tier has — behind a proxy or a shared NAT that is one bucket for many
callers, which is why "per-caller rate limiting keyed to a proven identity" is still on the
production list rather than crossed off it.

**Destruction is the other half of "high-value target", and it is where the interesting
engineering is.** "TTL expiry and logout both destroy the key" is easy to write and was not
literally true: `DELETE /sessions/{id}` gated `vault.destroy` behind `_owns_session`, which
answers False for an *expired* session — so a user logging out after the hour destroyed nothing
and the decrypted originals stayed in `_SessionCache`. The logout path reaches the reaper now
(`delete_session` calls `reap_expired_sessions` before the ownership check), so an explicit
`DELETE` evicts the cache and deletes the rows whether or not the TTL has already lapsed. Pinned
by `test_api.py::test_logging_out_after_the_ttl_lapsed_still_destroys_the_vault`.

The reaper itself is bounded, and each bound is a stated cost rather than a shrug:

- **`MAX_REAP_PER_REQUEST` = 16** caps one request's destructions, so a burst of `E` sessions
  expiring together is fully destroyed after `ceil(E / 16)` reaping calls — 1 call for a burst of
  16, 63 for a burst of 1,000. Reaping calls are not scarce (every authenticated request runs one,
  and so do `POST /sessions` and `DELETE /sessions/{id}`), `first=` collapses the window to a
  single call for a session the caller *names*, and the window governs **residency, not
  confidentiality**: `SessionRegistry._sweep_locked` pops the key before an ID can reach the
  queue, so the AES-GCM rows are already undecryptable and every cache accessor fails at
  `registry.key()` first. What is waiting is a plaintext `_SessionCache` no route can read.
- **A destruction that fails is re-queued rather than logged and forgotten**, at the *tail* — head
  placement would let a handful of permanent failures spend every request's whole budget while
  healthy expiries waited behind them. `MAX_REAP_ATTEMPTS` = 8 is therefore a bound on total work,
  not per-request work. An exhausted ID is **not dropped**; it moves to a dead-letter map where it
  stops consuming the per-request budget, stays enumerable, and comes back with a fresh budget when
  `DELETE /sessions/{id}` names it.
- **A cancelled request no longer takes its in-flight slice with it.** `CancelledError` is a
  `BaseException` and never reached the reaper's `except Exception`, so a client disconnecting
  mid-drain silently stranded the rest of the slice with nothing logged. The remainder is re-queued
  in a `finally` and charged no attempt, because a destroy that never ran is not evidence that the
  session cannot be destroyed.

**Every vault mutation and resolution is audited** — one `OBFUSCATE` per value written (entity
type + token ID), one `DEOBFUSCATE` per restore, a `VAULT_MISS` for every token that resolves to
nothing, and a `VAULT_DESTROY` on teardown. The events are emitted by the callers rather than by
the vault, and the gate's bulk read of the originals set is summarised as a **count** on
`EGRESS_PASS` rather than logged per value — so "audited" here means every write and every
resolution, not a row per read. That distinction is the kind of thing that reads as a quibble
until an auditor asks what the log actually contains.

**Why the vault is worth concentrating rather than distributing, stated as a count rather than as
a slogan.** The claim "fail-closed, three passes" is only worth what it costs an attacker, so it
was measured: producing a genuine vaulted value on the wire required silencing **three
independent gate passes**. Blinding pass 1 alone left the detector re-scan blocking; blinding
passes 1 and 2 left the independent recogniser set blocking; only with all three neutered did the
value reach the captured HTTP body (§1, *the wire-level test*). One component holding the
re-identification capability is what makes three separate opinions about the same payload
affordable at all.

**What a production deployment adds:** KMS envelope encryption with per-session data keys (the
`MockKMSKeyProvider` seam already exists and implements real `generate_data_key`/`decrypt`
semantics with encryption-context binding); an HSM-backed master key; mutual-TLS service isolation
so the vault is not in the same process as the request handler; a rate-limited vault API with
anomaly alerting on bulk reads; and `mlock`-ed pages for the key registry so keys cannot be paged
to swap.

**What none of that fixes:** an attacker with code execution in the live process during an active
session can read plaintext out of the vault cache. That is out of scope for this tier.

**"Keys live only in memory, so a process restart destroys every live session. Isn't that an
availability failure you have rebranded as a security property?"** It is genuinely both, and the
honest answer is that it is one fact viewed from two directions. What is lost on restart is
bounded: session keys and their vault rows. Documents are encrypted under keys derived from the
master key and survive untouched; the audit log is separate and survives; nothing needs
re-uploading. What a user loses is the ability to restore an *answer* from a session that has
ended — they re-run the request — and the TTL is an hour by default, so the exposure window is
small by construction.

The uncomfortable part is what happens when you fix it. Multi-node means a shared session
registry, which means the keys leave the process — Redis, or KMS-held envelope keys. The moment
that happens, "the key exists in exactly one process's memory and dies with it" stops being true,
and the erasure guarantee weakens from *cryptographic* to *operational*: you are now trusting a
key store to actually delete. **That is a real tension, not a solved problem**, and the design I
would actually ship keeps the session key in the request-handling process and uses KMS only to
wrap a per-session data key, so destruction is still a local memory event and the shared store
never holds anything usable on its own.

### Q5 — A HIPAA auditor asks what happened over the last 30 days.

**Four guarantees, three gaps, and one ladder that prices the residual.** The query itself is
`query(since=now - 30*86400)` compared against `length(since=…)` — the same filter set on both,
which is what lets a caller tell a complete answer from a truncated page, since `query` defaults to
`limit=1000` and a full page is otherwise indistinguishable from the whole result.

*The guarantees:*

1. **Every event is hash-chained and append-only.** `verify_chain()` recomputes every entry hash
   and re-checks every link, and is verified *by test* to detect an in-place `UPDATE` of every
   persisted column (each parametrised separately — a column omitted from the digest would be
   freely editable), an insert without recomputing the chain, a reorder, a middle deletion, a
   **replay** of a genuine correctly-hashed row at a new `seq`, a **forged genesis row**, a
   truncated tail, the erasure of one whole session, and the erasure of every row. A tamper that
   makes the walk *unreadable* returns `False` rather than raising, so the verifier cannot be
   crashed with the tamper it is looking for — a claim that was an overclaim until the test behind
   it stopped driving a monkeypatched cursor. Zeroing one 4 KiB page of a 120-row audit database
   leaves `open` perfectly happy, and the real file-level test then found three defects the mock
   could not reach: `query()` and `length()` still crashed where `verify_chain()` coped (all three
   share one `_UNREADABLE` rule now), `verify_chain()` *raised* on a blanked high-water mark — the
   second half of the very attack it exists to catch — and `AuditLogger.open()` leaked its
   connection thread whenever setup failed, so a process that opened a damaged audit DB could not
   exit. A docstring explaining why a test is impossible is how the test never gets written.
2. **A middle deletion survives re-linking.** Delete a row, walk the survivors, recompute
   `prev_hash`/`entry_hash` with the published formula — the digests are unkeyed, so this costs
   nothing. Every row recomputes and every link matches; the only surviving witness is that `seq`
   skips a number, and compacting the numbering to hide *that* is caught by the high-water mark
   instead. `test_deleting_a_middle_row_and_relinking_the_chain_is_still_caught` asserts both
   halves, and asserts the attacker's own success first so it cannot pass by failing to build the
   attack.
3. **The gate provably ran before every provider call, on the same bytes.** `EGRESS_PASS` carries
   the SHA-256 of the exact released payload and `LLM_CALL` carries the same digest, so "was every
   provider call preceded by a passing gate" is a join rather than an assurance. The row also
   carries `rescan_warning_types` — the entity *types* pass 2 warned about, never their text.
4. **`run_id` correlation** ties detect → obfuscate → egress → LLM → restore together: **34–40
   events per run** on the three short fixtures, **347** on `legal_brief_large.txt` (one row per
   distinct value — 251 `OBFUSCATE` + 64 `REDACT` + 28 `STRIP` + four chain events), so the count
   scales with the document rather than the request. Per-value granularity is the point: it is what
   lets an auditor ask which *entity* went where.

*The gaps:*

- **The 30-day sweep is a library call, not an HTTP call.** `GET /audit` requires a `session_id` or
  `run_id` scope, because every row carries a `session_id` and a `session_id` is the bearer
  credential for `DELETE /sessions/{id}` — an open endpoint would hand any anonymous caller a list
  of live sessions to destroy. So "queryable by time range" is true of `AuditLogger.query()` and
  **not answerable over HTTP**, and an auditor cannot self-serve. Compliance querying and
  session-credential secrecy want opposite things from one endpoint; the fix is a *separate*
  authenticated compliance API, not a query parameter on the one anonymous callers can reach. Not
  built.
- **The chain is tamper-*evident*, not tamper-*proof*, and one partial tamper is undetectable.**
  The digest is `sha256(prev_hash ‖ canonical_json(event))` with no secret in it, so anyone who can
  write to the database can forge a row and recompute every subsequent hash — demonstrated against
  this code, not hypothesised. What the chain buys is that a partial tamper (`UPDATE`, mid-chain
  `DELETE` or `INSERT`, reorder, truncated tail) is detectable and a full rewrite means replacing
  the whole log in one consistent pass. The exception is **appending to the tail**: read the last
  row, take its `entry_hash` as `prev_hash`, use `seq + 1`, recompute. Every check passes, each for
  a reason that cannot be patched from inside this process — the link genuinely is correct, the
  `seq` genuinely is next, the digest has no secret to get wrong, and both watermarks move on their
  own. A forged tail row is not hard to distinguish from a legitimate append, it *is* one. Pinned
  as an accepted residual by `test_a_correctly_hashed_tail_append_is_a_known_residual`.
- **A *relabelled* session is invisible to its own scope, and it is not patchable.** `DELETE`ing a
  session's rows is caught from every scope, because the structural checks are global. `UPDATE`ing
  `session_id` from `X` to `Y` erases X's history just as completely and moves nothing, so every
  link and every `seq` still holds. The rewritten rows fail their own `entry_hash`, and both checks
  that can see it report it — `verify_chain()` returns `false` and so does `verify_chain("Y")`.
  What returns `true` is `verify_chain("X")`, the victim's own scope, which over HTTP is
  `{valid: true, length: 0}`: byte-identical to "this session never existed". Unpatchable because a
  relabelled row is, column for column, the same input class as an ordinary tampered row that
  genuinely belongs to that other session, and the pre-tamper `session_id` is inside the digest the
  tamper destroyed. **The unscoped `verify_chain()` is the compliance answer**; the scoped one is a
  per-slice detail.

**The exact edge of the truncation defence, as a ladder rather than a property**, because "how many
statements does a silent truncation cost" is the only honest way to state what an unkeyed in-file
scheme buys. Every rung is a real command against a real audit DB, and all four are pinned by
`test_a_silent_tail_truncation_costs_four_statements_and_all_four_are_needed`:

| Attacker statements | Result |
|---|---|
| 1. `DELETE FROM audit_events WHERE seq >= 4` | **caught** — the watermark disagrees with the tail |
| 2. …+ `UPDATE sqlite_sequence SET seq = 3` | **caught** — `audit_chain_meta` holds the same mark in a table SQLite does not manage |
| 3. …+ `DELETE`/lowering `UPDATE` on `audit_chain_meta` | **refused by SQLite** — two triggers enforce "only ever grows" |
| 4. …+ `DROP TRIGGER` *then* the lowering `UPDATE` | **not caught** — the residual, and the reason the real fix is an off-box anchor |

Two of those rungs are new and both closed holes reading would not have found. **The evidence used
to expire on its own**: `emit` allocated `seq = MAX(seq) + 1` over the *surviving* rows, so a freed
tail number was handed straight back out — delete the newest three events, let three ordinary
events flow through the public API, and the seqs become contiguous again, the tail matches the
watermark, and `verify_chain` returns **`true`** with the original events permanently gone. No
second statement, no hash work, and every existing tail test checked `verify_chain` immediately
after the delete, inside the window where the defence still worked. `seq` is allocated above the
*watermark* now. And **a missing bookkeeping row read as "no opinion"**: a `NULL` in
`sqlite_sequence` was tamper evidence and tested, a *deleted row* degraded to `true` and was not.

**Which attacker the log stops**, since "tamper-evident" is not one property:

| | **T1 — has the DB**, not the app's secrets | **T2 — has the host** (env, memory, DB writes) | **T3 — has deploy rights** |
|---|---|---|---|
| Alter or delete an existing event | **caught** | **caught** | not caught |
| Append a forged event at the tail | not caught | not caught | not caught |
| Rewrite the whole chain forward | **caught** — needs the whole log replaced in one consistent pass | not caught | not caught |
| Stop events being written at all | n/a | not caught | not caught |

The first row is the one that matters and it holds: **an attacker who cannot rewrite the entire
chain cannot alter or remove any record of what happened.** They can only *add* a record of
something that did not, and for an auditor asking "what did this system do", missing and edited
events are the dangerous ones. Keying the digest moves T1's append row into "caught" and does
nothing at T2, because the writer must hold the key in order to write — a different, narrower fix
rather than a smaller version of the real one. Closing T2 requires trust to live where the writer
is not: an off-box append-only sink, or anchoring the head hash somewhere the app cannot rewrite.
Anchoring is cheaper and has nowhere to land on a single-host `docker-compose`, where an anchor
beside the database is the same attacker and the same filesystem. Neither is shipped. **If the
off-box sink is ever adopted, the test that should fail first is
`test_no_release_survives_an_audit_write_that_failed_before_it`** — it pins, per component, that no
payload reaches the provider when the audit write preceding it failed, with `EGRESS_PASS` failing
as `EgressBlockedError` because the gate refuses to release what it could not record. A local
SQLite write fails rarely; a network write fails routinely, and the natural way to make a remote
sink resilient is to wrap emits in the same `except Exception` the block paths already use — which
would silently convert "refuses to release unaudited" into "releases whenever the audit service is
unavailable". Verified that nothing else notices: under that mutation 2,072 tests pass and only
this one goes red.

**Zero originals anywhere in the log — measured, and *not* guaranteed by the schema.** This README
used to say the `AuditEvent` model "has no field capable of holding an original value". That is
false and a reviewer can disprove it in one line: `detail` accepts any string up to 64 characters
and the label columns up to 128, so `"John Smith"`, an SSN and an e-mail all fit. What the ceilings
buy is that the log cannot hold **content** — the bulk-exfiltration shape — and they are enforced
twice, at the model and again at the write boundary where `model_construct()` cannot skip them. The
boundary re-checks `detail`'s **type** rule as well as its width, and that is not belt-and-braces:
`detail={"k": {"a": 1}}` renders as 13 characters, so a width-only boundary accepted it, the
*reader* then refused the stored column, and `verify_chain()` returned `false` **permanently** on a
row the logger wrote itself. A write boundary that admits a value its own reader cannot parse
manufactures the tamper evidence it exists to report. The guarantee against a *short* identifier is
a different kind of claim: **no call site writes one, and that is measured rather than asserted** —
every `emit` passes counts, latencies, digests, entity *type* names and 8-hex token IDs, and the
leakage harness scans the raw SQLite **bytes** against every vaulted original on all 100 runs.
Re-checked for this answer: 85 distinct originals from three real runs against every raw column of
the resulting 112-row log, **zero hits**.

**All twelve members of `EVENT_TYPES` are emitted, including `SESSION_EXPIRE`** — plus a
thirteenth, `AUDIT_ACCESS_DENIED`, which sits outside that frozenset by design (§2). This bullet
used to say the opposite: that `SESSION_EXPIRE` was declared and never written, so an auditor
asking "show me every session that expired" got an empty result and would be entitled to read it as
"none did". The reasoning was that TTL lapse is discovered lazily, so nothing is running at the
moment a session dies — the premise was right and the conclusion wrong. The auditable moment is
when a request **notices**, and `api/deps.reap_expired_sessions` runs exactly there, emitting
`SESSION_EXPIRE` and `VAULT_DESTROY` together.

Three smaller limits: payload hashes prove *which* payload was sent but do not let anyone inspect
*what* was sent (retaining payloads would create exactly the sensitive-data store this system
exists to avoid); the log captures our side only, and what the provider did after receipt is
contractual territory; and timestamps depend on host clock integrity, so production wants trusted
timestamping.

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
same payload. That fails safe, but it contradicts the engine's own rule (one vault row, one token,
N splices), shows the model two referents for one entity, and costs a restoration the user was
entitled to. Maximum rather than minimum, because the question is *is this value sensitive* and the
most confident sighting is the best evidence available.

The middle row is the requirement that low-confidence detections are **redacted, never passed
through raw** — a detector that is unsure must not be allowed to leak. The consequence is worth
stating plainly rather than leaving to be discovered: a redacted span has no vault entry, so
**restore cannot put it back**, and the answer the user reads keeps the `[REDACTED_PHONE]` marker
where the original stood. A deliberate trade — an unrecoverable value is preferable to a leaked one
— but a real loss of utility, and not rare. **Measured on the four committed fixtures: 18 of 23
`PHONE` detections (78%) score in this band**, and they are the only entity type that does.
Presidio's `PhoneRecognizer` bases at 0.40 and context lifts it to 0.75, so a phone number written
without a nearby context word scores 0.40 and is destroyed — though the per-value banding above
lifts any of them that also appears with a higher score, which is why `medical_note.txt`'s
`704-555-0151` (0.75 labelled, 0.40 in bare prose) is now obfuscated at both sites and the note
reports 1 redaction rather than 2. So the first question a reviewer is likely to ask after a demo
run — *"why did the phone number come back redacted?"* — has this as its answer, and the fix is a
per-entity `threshold:` override in `entities.yaml` rather than a code change.

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

- **Two shapes the egress gate denies that are not disclosures.** The gate is allowed to be wrong
  in the deny direction, but a denial reads like a leak to whoever investigates it. (a) The re-scan
  floor is `threshold_redact`, and Presidio's score at that level is *context*-derived, so a
  `[PII_SSN_…]` token this pipeline printed lifts any bare nine-digit run in the same payload to
  0.40 and a document carrying a handled SSN **and** an untyped invoice number is denied. Measured
  at 0 denials across 64 corpus documents, because generated nine-digit values are themselves
  planted entities and get tokenised. (b) The separator-invariant limb allows an unbounded run of
  non-alphanumerics between a value's components, so two components appearing consecutively across
  a sentence break match. Bounding that run is the obvious fix and was left undone deliberately:
  the corpus measurement that would justify a specific bound has not been made, and picking a
  number without it is how `MIN_IDENTIFIER_DIGITS` acquired the wrong one.
- **`ADDRESS` is among the weakest entities here, and the recall table's 100% does not mean what it
  looks like.** `ADDRESS` rides Presidio's `LOCATION` recognizer, so what it detects is bare place
  names — on `financial_disclosure.txt` the only two ADDRESS spans are `Florida` and `Illinois`. A
  street line, a house number and a postcode are not covered, and the held-out corpus's ADDRESS
  annotations are all bare city names with no digit and no comma, so the measured figure reports
  success on the easy half of the entity. Closing it needs street/postcode annotations in the
  held-out set first, so the number stops being a corpus artifact, then a pattern recognizer beside
  the NER one.
- **No test attributes an event-loop stall to the stage that caused it.** The integration guard's
  bound scales with `detect_ms`, so it can only really catch the *detector* going back on the loop;
  a 464 ms stall in the residual sweep sat under it, green, until it was measured by hand. An
  absolute ceiling was tried and removed rather than tuned, because the heartbeat also contends
  with spaCy in its own worker thread. Per-stage attribution is the real fix.
- **The pseudonymization preamble does not describe the payload it is sent with.**
  `PSEUDONYMIZATION_SYSTEM_PROMPT` is two sentences and carries **no placeholder rules** — the
  comment above it says pseudonymization "needs no contract", because the fakes read as ordinary
  values — but a pseudonymization payload is *mixed*: the reasoning-load-bearing and
  precise-numeric tiers emit bracketed tokens by design (§6). Measured on the shipped fixtures,
  the payload carries **17** bracketed placeholders for `medical_note.txt`, **4** for
  `legal_memo.txt` and **16** for `financial_disclosure.txt`, under a preamble that never mentions
  one. Nothing leaks — the restorer does not need the model's cooperation (§5 Q2) — but the model
  is handed strings it was given no rule for, which is a *utility* gap and a small
  instruction-following risk. The fix is to select the preamble on the **shape of what was
  emitted** rather than on the strategy name.

1. **Detection recall is the binding constraint on the whole system.** The egress gate makes
   misses *safe* (it blocks), but it cannot make them *invisible* — a missed entity that another
   detection already vaulted causes a block, and a genuinely novel one passes through. scispaCy or
   a self-hosted clinical NER model is the single highest-value next change.

   **A measured neighbour of that constraint, which is a span boundary rather than a miss.**
   `_is_field_label_tail` — the clamp that stops an NER span running off a soft wrap into the
   *next* field's label — is only consulted when the span contains a `\n`, so a **space-separated
   inline header** has no line break inside the span and nothing trims it. Reproduced on the real
   detector: `Name: David Ochoa   DOB: 03/12/1985` yields `NAME 'David Ochoa   DOB'`, so the label
   is swallowed into the vaulted original — the vault holds a string that is not a value, and the
   payload loses its `DOB:` label. It is a gap rather than a leak because the bare `David Ochoa`
   later in the same document is separately detected and vaulted, so pass 1 still has a needle for
   the name. The shipped fixture is unaffected (its header puts each label on its own line), which
   is why the suite cannot see it — the same way the unwrapped legal fixture could not see the
   soft-wrap leak that produced the clamp in the first place. Extending the rule past the newline
   is the fix and it is not free: the tail after run-on whitespace is Title Case, which is also
   the shape of a surname.
2. **Pseudonymization is reversible by *luck*; tokenization is reversible by *design*.** A token
   carries an 8-hex ID which is a *key* — the restorer looks it up. A pseudonym has no key:
   restoration is best-effort string matching over untrusted model output. Component linking issues
   both the full fake and the surname fake as separate surrogates in one session, and longest-first
   alternation protects the pair only while the model reproduces the long fake intact. Measured end
   to end on the real engine, vault and restorer — the real patient is `Chelsea Hammond`, the
   issued fakes are `Nathaniel Brightwater` and `Brightwater` — **any interior insertion breaks it
   and every counter still reports success**: `Nathaniel M. Brightwater`, `Brightwater, Nathaniel`
   and `Nathaniel Dr Brightwater` restore to `Nathaniel M. Hammond`, `Hammond, Nathaniel` and
   `Nathaniel Dr Hammond`. The output is a **fake given name welded to the real surname** — silent
   misattribution, a person who does not exist carrying a real patient's name — while
   `restored_count` goes *up*, `vault_misses` stays 0, and `_assert_no_surrogates` cannot fire
   because `Nathaniel` on its own is not an issued fake. `restorer.py` handles exactly one member
   of this class (`\s+` flexing for line wrapping) and its comment claims that is "the only place
   this can be fixed"; those three are the counterexamples. The honest position: use tokenization
   when correctness of attribution matters. A real fix needs the restorer to refuse a component
   fake when the full fake matched nearby but not exactly.
3. **The near-miss counter that is supposed to backstop the above is built from the matcher it
   backstops.** `_count_surrogate_near_misses` calls `_compile_surrogate_pattern(fold=True)` — the
   same function used to restore, differing only by `re.IGNORECASE`. Its docstring calls it
   "deliberately an upper bound" on unrestored fakes; it is an upper bound only in the *case*
   dimension and inherits every boundary rule the matcher has. Measured against the real counter,
   with `Brightwater` as an issued fake: `NATHANIEL BRIGHTWATER` and `nathaniel brightwater` both
   count 1 and are caught, while `The Brightwaters were contacted.` and a soft-wrapped
   `Bright-\nwater` both count **0** with the fake still readable. This is the project's recurring
   defect living in the one function that exists to be the safety net, and it is recorded rather
   than fixed because a genuinely independent counter is a second matcher with different rules —
   the thing that needs designing, not patching.
4. **`doc_category` is an uploader-supplied field that switches security controls off by default.**
   `CASE_STRATEGY` carries `action: redact` — the one entity forcibly destroyed regardless of
   confidence — and is scoped `only_in_doc_categories: [legal]`. The API field is optional and
   defaults to `None`. Measured on the shipped registry with a real privileged brief:

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
   written against the typo and open on the omission, and omission is the default. Same shape as
   the `user_id` gap in §3: a user-supplied lever on which controls run. Listed rather than fixed
   because the fix is a product decision.
5. **Pass 3 — the only genuinely independent opinion — covers one of four high-severity types.**
   `_INDEPENDENT_PATTERNS` holds two SSN recognisers (the separated spelling, and any nine-digit
   spelling introduced by an SSN/ITIN label) while `HIGH_SEVERITY_TYPES` is `{SSN, MRN,
   ACCOUNT_NUMBER, TAX_ID}`. For the other three the *only* recogniser in the system is the single
   registry pattern, consulted identically at detect time and in pass 2 — so the argument pass 3
   was built on is answered for 25% of the blocking surface. Deviation 43 is a demonstrated
   instance: `MRN`'s trailing `\b`, denied by one letter, was invisible to all three passes at
   once. Scope was chosen per-*instance* rather than per-*class*.
6. **`HIGH_SEVERITY_TYPES` does not follow its own stated membership rule.** The comment says the
   set is "pattern-typed entities with near-zero false-positive rates". `INSURANCE_ID`
   (`\b[A-Z]{2,6}\d{7,12}\b`) and `CASE_ID` are pattern-typed and high-specificity, are **not** in
   the set, and are released with a warning at 1.00 confidence. Measured. The membership is
   narrower than the rule given for it, with no reason recorded — which reads badly precisely
   because the comment invites the question.
7. **The vault serialises every session through one `asyncio.Lock` and one connection**, and its
   plaintext cache is unbounded. Five call sites (`put`, `_fetch_one`, `destroy`, `sweep_orphans`,
   `close`) take the same process-wide lock with no per-session striping, so a 251-entity brief
   takes and releases it 251 times against every other session in the process. Separately,
   `self._caches` is a `dict[str, _SessionCache]` of session-lifetime **plaintext** with no
   eviction and no size cap, so the 251-entity brief holds 251 decrypted originals in RAM for as
   long as that session lives. This gap used to end "until process close", and that half was
   wrong: `api/deps.reap_expired_sessions` drains the registry's unreaped set and calls
   `vault.destroy()` per expired ID at the top of `_require_session`, `delete_session` and
   `create_session` — measured on a 1 s-TTL session, the cache and row survive a health-style
   sweep and are both gone after the next session-bearing request. What survives is narrower and
   is the part worth keeping: an **idle** process holds expired sessions' plaintext until it
   serves another session-bearing request or exits, and within a live session the cache is uncapped
   either way. The reaper's own bounds — the 16-per-request drain window, the tail re-queue, the
   dead-letter map — are described in §5 Q4, where they belong with the destruction argument. Gap
   17 covers the *document store* and gap 13 the session registry; neither is this.
8. **Two structural debts, since paid — and one of them was not cosmetic after all.** Both were
   deferred once with the note that "no defect sits behind either", which was right about one and
   wrong about the other. **`api/app.py` was 1,835 lines carrying seven concerns**, with all eight
   endpoint handlers nested as closures in one 345-line `_register_routes`, so no endpoint was
   importable; it is **308 lines** (`wc -l`) now, over `constants.py`, `deps.py`, `middleware.py`,
   `lifespan.py`, `errors.py` and `routes/`. The stated blocker ("the closures bind to that
   function's locals") turned out to be false — checked by AST, `_register_routes` had **zero**
   locals — and the move was guarded by a behavioural snapshot taken beforehand (route table,
   middleware stack, full OpenAPI schema, and a 16-probe auth matrix), whose post-move diff was
   empty. That one *was* cosmetic. **The word-boundary rule is now singular**, in
   `secure_context_pipeline/textrules.py`, which imports nothing from the package; the gate,
   engine, restorer, strategy and harness all depend downward on it. **This one was not cosmetic.**
   The previous arrangement shared the *alphabet* but not the *decision*: `engine.py` and
   `restorer.py` imported `_ALNUM` and rebuilt the assertions by hand, so a rename raised
   `ImportError` as advertised while an edit to the rule still had to be made in three places with
   nothing to catch a missed one — the same defect this document records eleven other instances of,
   surviving *inside the fix for it*.
9. **The pipeline could *manufacture* a partial value, not merely fail to catch one.** §1's
   first named boundary is disclosed as something a *document* can carry past the gate; this is the
   same blind spot reached from the other side, and it is worse, because the fragment was produced
   by our own obfuscation stage. spaCy returns `03/11/2024, 09/17/2024` as a **single** `DATE`
   span, so that composite string became one vault original; a different date in the same document,
   shifted by the session's −204 days, rendered as `03/11/2024` — a verbatim, word-bounded **slice**
   of that original. The Tier-2 collision guard tested only whether a rendered date *contains* an
   original, never whether it is *contained in* one, so a real appointment date of the real patient
   went to the provider inside a string the pipeline itself invented. Both scanners reported clean,
   correctly by their own definitions: `0 leaks` was true and misleading at once.

   The guard is symmetric now and the colliding date degrades to a plain token — 50 fixture
   documents × **540** shifts, **27 collisions before, 0 after**, and the leakage harness went from
   1 failing run in 8 to 8/8 clean. **That sweep was one shift short of the space, and this
   paragraph used to call it exhaustive**: `derive_date_shift_days` has **541** reachable values,
   because `% 600` puts the raw shift in `[-300, 299]` and the ±30 fold pushes `[-29, 29]` outward,
   leaving 271 ∪ 270. So read it as 540 of 541, with the record silent on which one it missed —
   **swept, not exhausted**. The word mattered more here than elsewhere, because this is the one
   paragraph in §7 that offers exhaustion in place of sampling as its evidence.

   That fixed the failure but not the condition, so the condition was fixed on **both** sides — a
   detection-only fix would violate this design's own posture that the gate does not trust
   detection. *Upstream*, `Detector._split_composite_dates` emits one detection per date when a
   Tier-2 span fails to parse as one date and splits into ≥2 constituents that **each** parse (one
   unparseable piece refuses the whole split, since a partial split would vault some constituents
   and leave a rump span holding the rest). *Downstream*, `EgressGate._composite_needles` derives a
   needle per constituent through the same bounded-form comparison, and both sides share one
   delimiter grammar (`textrules.delimited_parts`) — which is what makes "the gate scans for the
   pieces detection would have split out" mechanically true rather than a comment. What the gate
   deliberately will **not** do: a constituent below `MIN_IDENTIFIER_DIGITS` contributes nothing,
   so `April 2024` never makes `April` a needle, and one sub-floor constituent refuses the whole
   value, so `Jan 5, 2024` cannot contribute `2024` and deny every document. Measured across 30
   freshly generated documents: 1,345 spans, **211 carrying a list delimiter, 0 contributing a
   composite needle**. **What genuinely remains** is a bare component of a *non-composite* original
   — vaulted `John Smith`, payload says `Smith` — which needs per-entity component policy rather
   than one predicate. So the honest qualifier is narrower than it was: it is a **multi-word
   original**, not a composite detector span, that still makes "whole" load-bearing.
10. **No k-anonymity / generalization pass.** This is the real answer to the inference risk in §3,
   and it is not built. Bucket intervals into ranges, drop precision below a week outside the
   reasoning window — it is what turns Tier 2 from "protects against a reader" into "protects
   against a data broker" (§5 Q3), and it needs a design pass of its own rather than a patch.
11. **Financial transaction dates pass through deliberately.** Amounts and counterparties are
   masked; the dates are not, because `DATE` is scoped to medical documents. A quasi-identifier
   residual and a real gap — see the sixth limit in §1 for the measured volume.
12. **Sub-3-character spans are never obfuscated.** They carry no re-identification signal, and
   sweeping them would corrupt unrelated words — but the floor is a policy choice, applied
   uniformly rather than per-entity.
13. **Single-process session registry.** Redis plus KMS envelope keys for multi-node.
14. **The document read path leaks existence through timing** — ~18× between an absent `doc_id`
   and a wrong-owner one on a 2 MB blob. Content-identical, time-distinguishable; analysed in §3.
   A constant-time read closes it and costs a full disk read per miss.
15. **Filenames are cleartext in the metadata table.** Deliberate and argued in §3; the fix, if the
   requirement changes, is an encrypted column plus a blind index for listing.
16. **The audit chain is unkeyed**, so it survives partial tampering but not a full rewrite by
   someone with DB write access (§5 Q5). An off-box append-only sink or an auditor-held HMAC key is
   the real answer; both are production infrastructure rather than a code change here.
17. **The DOCX decompression-bomb guard bounds the declared size, not the transient cost.**
   Checking the archive's declared uncompressed bytes closes the ~1000× amplification a zip bomb
   needs. It does not bound what `zipfile.ZipFile()` spends parsing the central directory before
   any check can run: an archive at the 16 MB upload cap can declare **zero** uncompressed bytes
   and still cost ~110 MB RSS, about 7×. Measured and pinned by a test. A real fix streams the
   archive or parses it in a memory-capped subprocess.
18. **SQLite write contention stalls every reader on the store**, not just the writer — five
   seconds of it, measured. Analysed in §4; the fix is Postgres and the Protocol seam exists.
19. **A document's two blobs share one AAD** and can be swapped on disk (§3). Integrity only, and
   closing it means deviating from the specified AAD.
20. **Co-reference display enrichment** — a UX feature, per Q2.
21. **`Settings.llm_max_retries` is an *attempt* count, not a retry count.** Consumed as
   `max(1, min(llm_max_retries, MAX_ATTEMPTS))`, so `1` means one attempt and **no** retry — the
   opposite of what an operator setting "max retries = 1" expects. The behaviour is correct and
   tested; the name is wrong. A rename rather than a logic change, recorded here rather than
   quietly renamed because the setting is already in `.env.example`.
22. **Streaming responses with incremental restore.** Today the full response is restored in one
   pass, so a streaming UI would show tokens before restoration.
23. **OpenTelemetry spans per pipeline stage.** Timings exist in `stats` and the audit log but are
   not exported.
24. **An OpenAI provider class** — one class plus one registry entry, by construction.
25. **`TOKEN_RE` tolerates whitespace at both separators and neither end of the hash.** The matcher
   accepts a token a model re-cased and one it wrapped at either `_`, which closes the two classes
   §10's Core 6 row used to over-claim. What it still refuses is a wrap *inside* the hash —
   `[PHI_NAME_1a2b\n3c4d]` does not match — which is the same line-wrap mechanism one position
   over, and the residue is a live token in the user's answer rather than a silent one, because
   `_assert_no_surrogates` cannot see a form the grammar does not describe either. The fix is not
   free: the hash is the only group whose alphabet is a *subset* of the entity type's, so allowing
   whitespace inside it means the type group and the hash group stop being separable by their
   contents alone. Three other refusals are deliberate and stay: a dropped category
   (`[NAME_1a2b3c4d]`), a bare space or a `.` where a separator belongs, and a short hash — the
   last for the security reason Deviation 28 records, since the egress gate builds its skip-list
   from this grammar's stricter twin.

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
- **The 42-file `ruff format` divergence (§1).** A large cosmetic diff with no correctness
  content, which would bury every substantive change above it in review. It is the last thing I
  would spend a reviewer's attention on.

---

## 8. Deviations from the build specification

Recorded per the build document's instruction. Each one is a deliberate choice with a reason.
**The reasons live in [`DEVIATIONS.md`](DEVIATIONS.md); the index below is the map.** That split
is itself a decision worth one sentence: the register was 80 KB of rationale sitting between the
threat model and the repository map, it carries no rubric weight, and a reviewer with an hour
should not have to walk through it to reach §9. Nothing was dropped in the move.

Numbers are **stable and never reused** — they are cited from `entities.yaml`, from package
source, from tests and from elsewhere in this document, so renumbering would silently invalidate
about forty cross-references. A row that is closed, merged into another or superseded keeps its
number and says which. Rows **73–75** are new: three deviations that were undisclosed until this
pass, one of them a defect *inside* the fix row 63 takes credit for. Nine rows were corrected
against the tree rather than left as written, and each correction is stated inside its row —
`DEVIATIONS.md` opens with the list.

| # | Deviation | Rationale |
|---|---|---|
| 1 | `SCP_LLM_MODEL` defaults to `claude-opus-5`, not `claude-sonnet-4-6`. The provider sends **no** `temperat… | The specified model is valid but older. |
| 2 | Added `pyyaml`, `python-dateutil`, and `python-multipart` to dependencies. | The first two are required by the specified design (the registry is YAML; Tier 2 parses dates… |
| 3 | `CASE_ID` patterns use single backslashes. *(→#46)* | **Merged into #46**, which is the substantive `CASE_ID` row. |
| 4 | Added `requires_context` and `require_digit` registry fields. | `requires_context` implements the specified DOB-vs-DATE semantics declaratively. |
| 5 | `EgressGate.check()` is `async`. | The re-scan runs the detector, which offloads spaCy to a worker thread. |
| 6 | Added `secure_context_pipeline/surrogates.py`. | The token grammar has **seven** importing consumers in package source — the orchestrator, the… |
| 7 | `ObfuscationResult` carries `spans`; `engine.obfuscate()` accepts `run_id`. | The engine is the only component that knows what it did to each span; reconstructing it downs… |
| 8 | **The engine performs a residual sweep** beyond the specified splice algorithm. | The spec splices only detected spans. |
| 9 | Originals shorter than 3 characters are neither vaulted nor scanned for. | Applied consistently in the engine and the gate so the vault's originals set stays exactly co… |
| 10 | Domain-specific exceptions live beside their packages (`llm/base.py`, `store/document_store.py`). | All inherit `PipelineError`, so the no-content contract and the 64-char detail ceiling apply… |
| 11 | **Overlap resolution ranks `action: strip`/`redact` entities above score.** | The spec's rule is score, then span length. |
| 12 | **The pseudonym collision guard is seeded with the whole document's originals and rejects word-level coll… | Found by the 100-run harness. |
| 13 | **The egress gate matches on word boundaries, not raw substrings.** | `"Brown"` is a real original; a generated fake surname `"Browning"` contains it, and a naive… |
| 14 | **A shifted date that lands on another real date degrades to a plain token.** | The per-session shift is one constant so intervals survive, which means a shifted date can la… |
| 15 | **The adversarial fixture value is not the shape the specification suggests.** | The suggested shape — alphanumeric groups separated by hyphens, with a run of digits in the m… |
| 16 | **A session is bound to the `user_id` that created it**, and `POST /pipeline/run` checks the binding with… | The spec's §9.9 treats `session_id` as the whole credential. |
| 17 | **`DELETE /sessions/{id}` takes a required `user_id` query parameter.** | Without it, anyone who learned a `session_id` could destroy another user's vault — and that i… |
| 18 | **`GET /audit` requires a `session_id` or `run_id` scope**, returning `400 AUDIT_SCOPE_REQUIRED` otherwise. | Unscoped, it was a **session-ID enumeration oracle**: an anonymous `GET /audit` harvested liv… |
| 19 | **`/docs` and `/redoc` are disabled** (`docs_url=None`, `redoc_url=None`); `/openapi.json` is still serve… | Swagger and ReDoc load JS and CSS from `cdn.jsdelivr.net` and `fastapi.tiangolo.com`. |
| 20 | **The token-ID collision counter is a *leading* `0x00 ‖ counter` block, not the spec's "appended counter… | This is a **security correction, not a style preference.** Appending is not injective: with t… |
| 21 | **`Detection.text` and both `Settings` secrets are masked on *serialization*, not only in `__repr__`.** | The spec's "repr rule" covers `f"{detection}"`. |
| 22 | **`MockKMSKeyProvider` wraps data keys under `HKDF(cmk, info=b"kms-wrap")`** rather than using the master… | The CMK should be input keying material, never a working cipher key — that is what a real KMS… |
| 23 | `PipelineResult` carries `raw_llm_response`; `ObfuscationResult` carries `stripped`. | Neither is in the spec's §7 schema. |
| 24 | `SpanOut.action` is an `EntityAction` StrEnum, not a bare `str`; `AuditEvent.detail` is a read-only `Mapp… | Both are tightenings. |
| 25 | The date-shift floor correction treats `Δ == 0` as positive. | The spec writes `sign(Δ)*30`, which is undefined at zero. |
| 26 | **`SESSION_EXPIRE` was in the §7 event vocabulary and never emitted — now CLOSED.** **[CLOSED]** *(→#54)* | **CLOSED, and merged into #54**, which carries the mechanism and its bounds. |
| 27 | **Two of §4's ten numbered steps emit no dedicated audit event.** The narrative says each step "emits aud… | §7 fixes the event-type vocabulary and neither step has a member of it. |
| 28 | **The token contract reproduces §9.5.2's `[PHI_MEDICATION_2f4a\|oral-antidiabetic]` verbatim — a 4-hex ha… | The build doc contradicts itself, so "follow the spec" is not available: §9.5.2 presents its… |
| 29 | **`run()` re-derives the outbound digest and refuses to send unless it matches the one the gate cleared**… | Both are additions rather than departures. |
| 30 | **The `documents` metadata table has a sixth column, `size_bytes`.** | The spec enumerates five. |
| 31 | **`EMAIL` gains a `patterns:` backstop** alongside `presidio: EMAIL_ADDRESS`. | Presidio's `EmailRecognizer` validates every candidate through `tldextract`, which resolves t… |
| 32 | **Sentence-tail patterns tolerate a soft line wrap; `CASE_STRATEGY`'s capture window goes 120 → 240 chara… | The build doc's `[^.\n]{0,120}` terminates a span at the first newline. |
| 33 | **`LAB_RESULT` is case-folded, its tail is lazy, its newline branch refuses a field label, its tail may c… | Greedy matching read `"your LDL is 162 and your A1C came back at 7.4"` as a single span endin… |
| 34 | **Three of the build doc's own `context:` words are replaced by lemma stems** (`filed`→`file`, `presents`… | Presidio's context enhancer tests `configured_word in lemma` as a **substring**. |
| 35 | **Overlap resolution ranks pattern/gazetteer-backed entities above presidio-backed ones** — below policy… *(→#11)* | **Merged into #11**: the two are one change to one function, overlap resolution's ranking, an… |
| 36 | **The diagnosis gazetteer grows from 109 to 208 terms.** | §9.2's stated coverage target is "fixtures plus realistic docs", and common presenting condit… |
| 37 | **`TOKEN_RE` bounds every quantifier §9.7 leaves unbounded**: `\s*`→`\s{0,4}`, `[A-Z0-9_]*`→`{0,63}`, the… | The specified regex is **catastrophically backtrackable**: adjacent unbounded quantifiers aro… |
| 38 | **§10.7's `[PHI_MEDICATION_2f4a\|oral-antidiabetic]` (a 4-hex ID) is deliberately *not* restorable.** *(→#28)* | **Merged into #28**, which is the same decision about the same self-contradiction in the buil… |
| 39 | **`Restorer.restore` accepts an optional `issued` set; `RestoreResult` gains `fabricated`, `lost` and `su… | Without knowing which surrogates were actually issued, every unresolved reference is a single… |
| 40 | **The user prompt is detected and obfuscated too**, in the same session and against the same vault (`orch… | The prompt box is a text input a human types PHI into, and measured, it was a straight bypass… |
| 41 | **The outbound payload fences the document**: `{obfuscated prompt}\n\n<DOCUMENT>\n{obfuscated document}\n… | An uploaded document that closes the fence early has its remainder read as top-level instruct… |
| 42 | **The egress gate runs a third, blocking pass** (`_independent_hits` over `_INDEPENDENT_PATTERNS`), with… **[CLOSED]** | *Scope claim superseded by #71.* Pass 2 re-runs the **same** `Detector` that ran at detect ti… |
| 43 | **The gate has two identifier floors, not one**: `MIN_IDENTIFIER_DIGITS = 7` for the whole-value needle,… | They were one constant, and that was a live leak of the exact class this project keeps findin… |
| 44 | **`ObfuscationStrategy.make_surrogate` takes a keyword-only `session_id`.** §9.3 fixes the ABC as `make_s… | `SessionVault` is a multi-session object — every accessor needs the ID, and the Tier-1 collis… |
| 45 | **The Faker seed label carries the normalized original value**, not just the entity type: `HMAC(session_k… | Stability per *value* rather than per *type* is what component linking needs — one patient mu… |
| 46 | **`CASE_ID` pattern 1 drops §6.2's `(?:Case\|Docket)\s+No\.?\s*[:#]?\s*` prefix**, widens `[a-z]{2}` to `… | Real briefs cite bare docket numbers, and requiring the lexical prefix missed them. |
| 47 | **`regex` is a hard runtime dependency and is now declared.** *(→#2)* | **Merged into #2**, the added-dependency row, which omitted this one and was corrected for it. |
| 48 | **A Tier-2 span that is a *list* of dates is split into one detection per date** (`Detector._split_compos… | spaCy returns `03/11/2024, 09/17/2024` as one `DATE` span, so the whole string became a singl… |
| 49 | **§9.7's `[UNRESOLVED_ENTITY]` + `VAULT_MISS` rule is not applied to an *unbracketed* token whose ID this… | §9.7 states the rule for any unknown `token_id`, unconditionally, and the shipped restorer ho… |
| 50 | **`AMOUNT` is unbounded over digits and commas and must end on a digit** (`\d[\d,]*\d\|\d` with `\.\d{1,2… | The character class counts digits *and* commas against one bound and truncates at the twelfth… |
| 51 | **`normalize()` applies NFKC a second time, after casefolding, and strips non-whitespace C0/C1 controls.** | Casefolding is not closed over NFKC — `casefold("ß")` is `"ss"`, so `"ß" + U+0323` folds to `… |
| 52 | **`_parse_fallback` parses against two anchors and rejects any date **any** of whose (year, month, day) c… | The `\d+` twice guard rejects a bare year but not a bare clock time: `9:15 AM` has two digit… |
| 53 | **`load_registry` validates `only_in_doc_categories` against `DOC_CATEGORIES`**, which moved to `models.p… | It was validated against nothing. |
| 54 | **TTL expiry now runs the full destruction path** (`api/deps.reap_expired_sessions`), not only the key pop. | §4 step 10 and §9.4 both say expiry destroys like logout — key popped, vault rows deleted, `V… |
| 55 | **A lone name component is always treated as a surname**; §9.3's "same rule for first names" is not imple… | `role` is `"last"` for the final word of a span and `"first"` otherwise, so a bare given name… |
| 56 | **The demo UI's "destroy session, then run again" shows the *erasure*, not a live vault miss** (§9.10 des… | A destroyed session is refused at the session check — `401 SESSION_EXPIRED` — **before** the… |
| 57 | **CLOSED — §9.10's "upload fixture dropdown" is now a real one-click upload control.** (Recorded as a dev… **[CLOSED]** | The dropdown listed the four bundled filenames and nothing could deliver them to the page: a… |
| 58 | **A span scoring below `SCP_THRESHOLD_REDACT` (0.3) is dropped, not redacted.** The build doc's summary b… | *Narrowed by #71.* The two cannot both hold and the price is measurable: Presidio's `UsSsnRec… |
| 59 | **`INSURANCE_ID`'s letter prefix goes `[A-Z]{2,4}` → `[A-Z]{2,6}`.** | The spec's bound knows `BCBS` and `UHC` and misses every payer whose member-ID scheme prints… |
| 60 | **A `VAULT_MISS` row classified `fabricated` carries `entity_type=None`, every miss row carries `detail['… | The same claim §7's "zero originals anywhere in the log" bullet retracts, failing in a second… |
| 61 | **The demo UI bounds every request and destroys the session it replaces.** | *Extended by #69.* Two defects the UI audit found in `ui/app.js`. |
| 62 | **Panels 2 and 3 now say what each highlight IS, and the two red legend keys are no longer the same squar… | Panel 1's marks have carried entity type, action, score and surrogate since the first build;… |
| 63 | **Two stale-state defects in the demo UI: the audit tail after a refused run, and the header health badge.** | `resetRun` blanks the four panels, the stats row and the `#audit-run` label and deliberately… |
| 64 | **The verify chain can no longer be started twice.** | It is the one button `setBusy` deliberately leaves alive, and it had no in-flight guard. |
| 65 | **The success banner reports the composition the run *emitted*, not the strategy it was *asked* for**, an… | *Followed by #66 and #67.* The banner read `strategy <name>`, unqualified, and the vault is w… |
| 66 | **Panel 1's header and the `entities_detected` chip count two different sets, and the reconciliation is n… | *Follows #65; see also #67.* Measured on `fixtures/medical_note.txt` as `medical`: the strip… |
| 67 | **Two tooltips claimed this run had *minted* something it may only have re-emitted.** *(→#62)* | **Merged into #62**, the panel-tooltip row, and superseded in framing by #65 and #66. |
| 68 | **The demo page ships a real favicon file, and the CSP was *not* widened to admit it.** | A browser asks for `/favicon.ico` unprompted; `_mount_ui` mounts `secure_context_pipeline/ui/… |
| 69 | **`Create session` is a two-step, because creating one over a live session erases that session's key and… | Row 61 made the replacement honest — the outgoing session is deleted, owner-scoped, and the e… |
| 70 | **`Restorer.restore()` takes a `hints=` map, and the stranded-hint deletion it enables is bounded twice —… | A model that strips *both* brackets off `[PHI_DIAGNOSIS_1a2b3c4d\|cardiovascular]` leaves the… |
| 71 | **`SSN` in `entities.yaml` carries a `patterns:` backstop as well as `presidio: US_SSN`, and pass 3 carri… | Deviation 42 above says pass 3 closes the invalidated-SSN hole and cites `Member SSN 123-45-6… |
| 72 | **`entities.yaml` is checked against the *installed* Presidio for validator blind spots, not against a li… | The SSN leak above and the EMAIL one before it (`EmailRecognizer.validate_result` resolves th… |
| 73 | **The header health badge was a one-way latch: the fix in #63 overshot, and the recovery direction did no… | #63 records the badge being written exactly once at load, so killing the server mid-demo left… |
| 74 | **`CASE_ID` ships three patterns, and only the first was disclosed.** | #46 explains pattern 1 — the dropped `(?:Case\|Docket)\s+No\.?` prefix, `[a-z]{2}` widened to… |
| 75 | **`SETTLEMENT_TERM` is case-folded; the specified pattern is case-sensitive.** | Both shipped patterns carry a leading `(?i)`, so `Settle`, `SETTLEMENT` and `settle` are clai… |

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

### Where the specification's directory names live

**A reviewer diffing the required tree against the repository root finds none of the eight
directories the build document names, and until this pass nothing said why** — `grep` for any
disclosure of it returned zero hits, which makes it the one structural difference from the
specification that was undeclared.

They all exist, one level down. The specification names its components as top-level directories;
this repository is an installable Python distribution, so they are **subpackages of the
`secure_context_pipeline` package** rather than directories beside it. `store/`, `detection/`,
`obfuscation/`, `vault/`, `pipeline/`, `deobfuscation/`, `audit/` and `llm/` are all present with
the specified names and the specified responsibilities; the prefix is what makes
`pip install -e .` produce one importable namespace instead of eight top-level modules called
`audit`, `store` and `pipeline`, each of which would collide with something on PyPI.

One further difference, inside that: **`obfuscation/engine` is a module, not a directory.** The
specification names an `engine` component under `obfuscation/`; here it is
`secure_context_pipeline/obfuscation/engine.py`, one file, with the strategies in a sibling
`strategies/` package. The reason is that the engine is a single class with one public method and
no internal seam worth a package boundary — the seam that *does* exist is the strategy protocol,
and that is where the directory went. `import secure_context_pipeline.obfuscation.engine` resolves
either way, so nothing downstream can tell the difference; this is disclosed because a structural
difference a reviewer can see and the document does not mention is exactly the shape that reads as
an oversight.

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

The large brief is the artifact the specification asks for — roughly twelve thousand words and
comfortably over two hundred distinct entities. It is
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
| **Core 2** — detector, nine-entity minimum, spans with type + confidence | `entities.yaml` (20 types), `detection/registry.py`, `detection/recognizers.py`, `detection/detector.py::Detector.detect`, `models.py::Detection`/`SpanOut` | `integration/test_pipeline.py::test_the_nine_mandated_entity_types_survive_the_whole_round_trip`; `test_detection.py::test_entity_positive_and_near_miss` (positive **and** near-miss negative for **all 20** registry entities; the coverage guard `::test_fixture_table_covers_every_registry_entity` derives its expectation from the whole registry minus a named exemption set, so a new entity cannot arrive without fixtures) |
| **Core 3** — two strategies + per-entity justification | `obfuscation/strategies/{base,tokenization,pseudonymization}.py`, `registry.tier_of`, README §6 | `test_obfuscation.py::test_tokenization_format_round_trips_through_the_strict_grammar`, `::test_pseudonym_preserves_identifier_formats`, `::test_tier3_diagnosis_emits_a_class_annotated_token_from_the_gazetteer`, `::test_tier4_numerics_stay_plain_tokens` |
| **Core 4** — vault encrypted, deterministic in-session, purged on expiry/logout | `vault/session_vault.py`, `vault/session_registry.py` | `test_vault.py::test_within_session_determinism`, `::test_destroy_makes_tokens_unreadable`, `::test_destroy_surviving_row_is_undecryptable`, `::test_surviving_row_cannot_repopulate_a_destroyed_cache`; `integration/test_pipeline.py::test_expired_session` |
| **Core 5** — context injector, chunking, pre-send check | `pipeline/context_injector.py`, `pipeline/egress_gate.py`, `detection/detector.py::chunk_text` | `test_context_injector.py::test_serialized_is_exactly_what_the_gate_scans`; `test_egress_gate.py::test_the_gate_runs_before_the_provider_on_the_happy_path`, `::test_the_provider_is_never_reached_when_the_gate_blocks`; `test_detection.py::test_entity_straddling_a_chunk_boundary_is_detected_whole` |
| **Core 6** — restore, including mangled/paraphrased token forms | `deobfuscation/restorer.py`, `surrogates.py::TOKEN_RE` | `test_deobfuscation.py::test_mangled_token_forms_restore`, `::test_hint_is_ignored_for_lookup`, `::test_post_restore_assertion_fires_on_residual_token`, `::test_a_fake_reassembled_across_a_splice_boundary_still_fails_the_run`; `integration/test_pipeline.py::test_vault_miss_on_deobfuscation`. **Two mangling classes were outside that set until this week** and are named rather than folded in: a **re-cased** token and **whitespace at either `_` separator**, which is what a line wrap inside a token looks like. Both restore now, driven through the real `Restorer` by `test_readme_claims.py::test_the_two_mangling_classes_this_row_names_restore_through_the_real_restorer` — a round trip, not a regex match, because the row claims restoration. **The residual is stated in §7 gap 25**: whitespace *inside* the 8-hex hash is still unmatched. |
| **Core 7** — audit: ts, session, type, token, action; queryable; zero originals | `audit/logger.py`, `models.py::AuditEvent` | `test_audit.py::test_persisted_rows_carry_no_free_text_columns`, `::test_detail_rejects_long_string_values`, `::test_truncating_the_tail_breaks_the_chain`, `::test_deleting_a_middle_row_and_relinking_the_chain_is_still_caught`, `::test_erasing_a_whole_session_is_not_reported_as_that_session_being_clean`, `::test_a_truncated_tail_does_not_heal_when_the_log_advances`, `::test_a_silent_tail_truncation_costs_four_statements_and_all_four_are_needed`, `::test_deleting_the_sqlite_sequence_row_does_not_launder_a_truncation`, `::test_two_processes_sharing_one_audit_db_lose_no_events`; leakage assertion 2 and `leakage/test_leakage_harness.py::test_the_audit_scan_catches_a_label_column_original_and_says_which_limb_did` |
| **Critical constraint** — reversible in-session, irreversible across | `crypto/keys.py::derive_token_id` (HMAC under an ephemeral key), key destruction | `test_crypto.py::test_token_id_deterministic_within_session`, `::test_token_id_non_deterministic_across_sessions`, `::test_token_id_is_irreversible_without_the_key`; `integration/test_pipeline.py::test_restoration_is_impossible_after_the_session_is_destroyed` |
| **NFR** — config-only entity add | `entities.yaml`; `entity_type` opaque downstream | `test_extensibility.py::test_package_source_never_mentions_passport` (the grep **is** the proof), plus the three end-to-end cases beside it |
| **NFR** — strategy swappable via config | strategy registry dict, `Settings.strategy` | `test_obfuscation.py::test_dummy_strategy_plugs_in_with_zero_engine_changes`, `::test_per_entity_strategy_override_is_config_only`, `::test_a_per_entity_strategy_override_restores_in_both_directions` (both override directions carried through `Restorer.restore`, not just the surrogate's shape); `test_llm.py::test_new_provider_name_is_selectable_with_zero_other_changes` |
| **NFR** — zero PII in transit, verifiable by inspection | `pipeline/egress_gate.py` (fail-closed, **three** passes — §9.5.3 specifies two; the third is Deviation 42) | `leakage/test_leakage_harness.py::test_no_original_ever_leaves_the_process` (**100 runs**), `::test_unknown_shape_value_blocks_egress_and_the_call_never_fires`, `::test_the_leak_scan_bites`; the four stated boundaries are pinned by `::test_a_partial_value_leak_is_outside_what_this_harness_claims` and `::test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims`, plus `test_egress_gate.py::test_a_homoglyph_substitution_is_outside_what_the_scan_claims` (**missing entirely** until this audit — the only entry whose status was an assertion about the code rather than a measurement of it) and `test_egress_gate.py::test_the_floor_s_corpus_measurement_is_the_one_the_docstring_quotes`; the combining-mark shape is **closed**, not a boundary, and is pinned by `test_egress_gate.py::test_a_combining_mark_spliced_into_a_value_no_longer_reaches_the_provider`; the audit scan's two limbs by `leakage/test_leakage_harness.py::test_the_byte_limb_and_the_query_limb_of_the_audit_scan_see_different_things`; round-trip completeness, derived independently of the restorer, by `::test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots`; and the serialized HTTP body by `leakage/test_wire_leakage.py::test_the_request_body_is_the_obfuscated_document_not_the_original`. |
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
conceded that the repository already satisfies.** It read "read the fifth off the original
document; if it is a throughput or concurrency figure, nothing here measures it yet." It is not a
throughput figure and it is measured: the fifth benchmark asks for zero PII leakage established
over a hundred automated runs against documents that differ from each other, which is the harness
§1 opens with. The other four
are latency budgets, automated and enforced. The fifth maps clause by clause, and the "varied"
clause is the one worth checking rather than assuming:

| The clause | What the harness actually does | Named in |
|---|---|---|
| **100 automated test runs** | `RUNS = 100`, one parametrised case per run. The tally is asserted against `RUNS` rather than against however many cases were *selected*, so deselecting runs turns the summary red instead of quietly shrinking the claim. | `RUNS`, `test_no_original_ever_leaves_the_process`, `test_leakage_summary`, `test_the_selected_run_expectation_cannot_shrink_silently` |
| **varied fixture documents** | Every run draws its own seed (`SEED_BASE + index`), so the 100 runs are 100 *different generated documents*. Three kinds rotate (`medical` / `legal` / `financial`) under two alternating strategies, so each of the six (kind, strategy) pairs runs 16 or 17 times. | `plan_run`, `KINDS`, `STRATEGIES`, `SEED_BASE` |
| **zero PII leakage** | Each run asserts that no vaulted original occurs, as a word-bounded unit, in the outbound payload, the audit database or the captured logs — and that the prompt carried a real original, so a clean run cannot be vacuously clean. | `test_no_original_ever_leaves_the_process`, `test_the_prompt_carries_a_real_original` |
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

Ordered, and every step is either a command with an expected result or a judgement only a human
can make. Run it top to bottom in a **fresh clone**, because half of what it catches is the
difference between "works here" and "works anywhere".

**1 — Clean clone.**

```bash
git clone <repo-url> /tmp/scp-verify && cd /tmp/scp-verify
```

**2 — No secret in the tree or the history.** The first two must print nothing; the third must
show the example file only.

```bash
git log --all -p \
  | grep -nE 'SCP_MASTER_KEY=[A-Za-z0-9+/]{20,}|ANTHROPIC_API_KEY=[A-Za-z0-9_+/-]{20,}|sk-ant-[A-Za-z0-9]{24,}'
# expect: no output. The value SHAPES are matched, not the variable names: a real master key is
# 32 random bytes base64 (44 chars) and a real API key carries a long unbroken alphanumeric run.
# Grepping the bare names instead reports 9 hits on a clean tree -- this README's own commands
# match themselves, `demo.py` prints `export ANTHROPIC_API_KEY=sk-ant-...` in its help, and the
# tests use a literal `sk-ant-not-a-real-key`. A check that cries wolf on a clean repo is one a
# reviewer learns to wave through, which is the failure mode worth avoiding here.
git log --all --name-only --pretty=format: | sort -u | grep -x '.env'          # expect: no output
ls -a | grep -E '^\.env'                                                        # expect: .env.example
```

If the second one prints `.env`, the file is in history and a rewrite (`git filter-repo`) is
required before submission — deleting it in a later commit is not enough.

**3 — Docker path.** `docker-compose.yml` declares `env_file` as optional, so compose starts
without a `.env`; the container then refuses with a `NOT STARTED: SCP_MASTER_KEY is missing`
message, exits 78 and stops after three attempts. Give it a key:

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
python -m spacy download en_core_web_lg   # do this now: presidio otherwise fetches it at first
                                          # detector construction, and fails offline
node --version                            # optional -- without it the UI behaviour tests skip
python demo.py && echo "demo exit 0"
```

`demo.py` mints an ephemeral master key if `SCP_MASTER_KEY` is unset, so it runs with no `.env`.
It exits non-zero on any failed assertion — the exit code is the check, but read the printed
ledger too.

**5 — The suite, in the clean clone.**

```bash
pytest -q            # expect WITH node: the pass count §1 pastes, and 1 skipped (the real-network
                     #   LLM smoke test). That pass count is written down in exactly one place --
                     #   §1 -- so this step cannot drift out of agreement with it, which is what
                     #   it did. Without node: 120 skipped -- tests/test_ui_behaviour.py goes
                     #   with it, and §1's app.js execution-test claim is uncovered on your run.
pytest -m leakage -q # expect: 100/100 runs clean, 0 leaks
pytest -m bench -q   # expect: the seven measurements §1 tabulates, all inside budget
mypy                 # expect: Success, 52 source files
ruff check .         # expect: All checks passed!

# The partial-branch list, which is the part worth reading. `-m "not bench"` is not tidiness:
# coverage instruments the package, which multiplies a sub-microsecond vault lookup by enough
# that the benchmark table's staleness check compares an instrumented run against an
# uninstrumented table and reports a disagreement that is real and uninteresting. The
# uninstrumented `pytest -m bench` above is the gate; this command is for the branch list.
pytest -m "not bench" --cov=secure_context_pipeline --cov-branch \
       --cov-report=term-missing:skip-covered -q
```

The `--cov` totals §1 pastes are from a run of the **whole** suite, benchmarks included, so a
`not bench` run reports a slightly smaller denominator. §1's `statements` figure is the one that
is re-derived and pinned; `missed`, `branches` and `partial` are properties of a run and move with
what you deselected and with whatever was red at the time.

Paste the leakage summary line into §1 if it has drifted. The `100/100, 0 leaks` part does not
move; the two tallies beside it track what the detector currently finds, and §1 says which of them
is deterministic.

**6 — The one row only you can close.** Open the original challenge document and tick the **seven
functional must-haves** against §10 and a `demo.py` run. It is described in §10 under "The row a
human has to close". This is the one step that cannot be delegated, because the source document is
confidential and is deliberately not in this repository.

While you have it open, confirm the fifth performance benchmark reads as §10 now maps it — a
leakage figure established over a hundred automated runs on documents that differ, rather than a
throughput or concurrency number. That row is **automated** and no longer a human check; this is a
wording confirmation, not a measurement.

**7 — Reviewer-supplied fixture, if there is one.**

```bash
python demo.py --file /path/to/their.pdf --category medical
```

**8 — Confidentiality sweep.** No challenge-document text anywhere:

```bash
grep -rniE 'take-?home|challenge (doc|document)|confidential' --include='*.py' --include='*.md' \
  --include='*.yaml' . | grep -v '\.venv'
```

Expect two kinds of line and nothing else, named here for the reason step 2 names its own: a check
that prints output its expectation does not mention is one the reader adjudicates once and waves
through after that.

The **first** kind is this project's own vocabulary — the word "confidential" in the legal
fixtures and privilege markers (`fixtures/generator.py`, `tests/test_detection.py`,
`tests/test_obfuscation.py`, `entities.yaml`) and the word "confidentiality" used as a security
term in source comments (`surrogates.py`, `context_injector.py`, `api/deps.py`,
`store/document_store.py`, `vault/session_vault.py`, and several tests). Those are the bulk and
none of them is document text.

The **second** kind is this repository saying, in its own words, that the source document is
confidential and is not reproduced: §10's "the row a human has to close", step 6 above, this
paragraph, and `DEVIATIONS.md`'s opening statement — plus the three source comments marking where
the auth model stops. That is a handful of lines and each one is a *reference* to the document
rather than a quotation of it.

Adjudicate them by reading, not by filtering: an earlier version of this paragraph promised that
appending `| grep -viE 'take-?home|original challenge document'` removed every hit, and it does
not — the sentences that say "the **confidential** challenge document" survive it, which is the
same class of unchecked claim this page keeps recording about itself. What must not appear is
anything that reads like *quoted requirements text*; if it does, paraphrase it.

**9 — README and register, last.** Confirm §1's numbers match what step 5 printed, and that §3,
§4, §5, §6, §7 and §8 (with `DEVIATIONS.md` behind it) are all present and current.

**10 — Access and submit.** Repo private, hiring team granted access, link submitted through
the portal before the deadline.
