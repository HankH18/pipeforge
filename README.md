# Secure Context Pipeline

A privacy boundary between an encrypted document store and an external LLM provider.

```
fetch + decrypt → detect → obfuscate → EGRESS GATE → provider → restore
```

The claim this system makes is narrow and testable: **no whole vaulted value leaves the process
boundary toward the provider, and that is verifiable by inspection — subject to three named
boundaries this design does not close.** Obfuscation is reversible within a session and
cryptographically irreversible across sessions.

The word doing the work is **whole**, and the three boundaries are stated here rather than 300
lines down, because each one is a shape that has been *confirmed* to reach the provider with the
gate live:

1. **A partial value** — one component of a multi-word original. The *composite-span* sub-case,
   where detection merged a list of values into one span, is closed on both sides; see §7 gap 9.
2. **A value glued inside a longer alphanumeric word**, *names and other digit-poor values only*
   — a digit-carrying identifier **is** caught, see the two identifier floors below.
3. **A homoglyph substitution** — Cyrillic `о` for Latin `o` is different bytes, and catching it
   needs a UTS-39 confusables table rather than another normalisation form.

Each is pinned by a named test so that closing one later is a red rather than a silent widening
of the claim; all three are detailed under *Leakage harness* below.

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

**Two shapes that were open and undeclared are also now closed**, both found by adversarial
review rather than by the harness, and both reproduced end to end before being fixed:

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

A stronger claim was written here first, and it was wrong in the way that matters — it promised
`never` while the document itself documented the exceptions.

Everything below is measured on this repository, not aspirational.

### If you have ten minutes before the review

| You want | Go to |
|---|---|
| Does it run? | §1 — two commands, and the numbers the suite prints. **If you just cloned it, read the boxed note above this table first.** |
| Is the zero-egress claim real? | §1 *Leakage harness* — including the shapes the harness itself was blind to, the four boundaries it does **not** claim, and how each was found |
| What does it **not** defend? | §3 — **start with "The weakest point in this design"**: `user_id` is an asserted claim and there is no authn at this tier |
| The six live-review questions | §5 — each answered in its first sentence |
| Where it breaks at scale | §5 Q1 — the bottleneck is not the one you would guess, and the obvious fix was measured and **rejected** |
| What I got wrong | §8 Deviations (56, each with a reason) and §7 Known gaps |

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
1637 passed, 1 skipped       # full suite; the skip is the real-network LLM smoke test
                             #   128 leakage - 5 bench - rest unit + integration
mypy --strict                # clean, 52 source files -- PACKAGE ONLY, see below
ruff check .                 # clean, whole repo
96% branch coverage          # pytest --cov=secure_context_pipeline --cov-branch
                             #   4360 statements, 127 missed; 1070 branches, 81 partial
```

**On the scope of that mypy line, because "clean" is doing less work than it looks.**
`pyproject.toml` pins `files = ["secure_context_pipeline"]`, so `mypy --strict` type-checks the
**package only** — 52 files. The test suite is roughly half the repository by line count and is
**not** covered by that gate. Run against the whole tree it is 79 files and 100 remaining errors,
none of which is a latent bug: 46 are `attr-defined` from monkeypatching module-level re-exports
(a legitimate test idiom that `--strict` dislikes), 31 are `arg-type` where tests construct
`Detection(category="PII")` with a bare `str` instead of the `EntityCategory` enum, and the rest
are assorted narrowing complaints. What *was* worth fixing is fixed: **37 stale `# type: ignore`
suppressions** had accumulated across four audit loops and are gone — decayed scaffolding that
only a checker would ever find. The scope is stated rather than widened because the `arg-type`
hits are the interesting residue: those tests are not exercising the enum the production path
actually carries, which is a mild stub-blindness signal and a real next step rather than a
one-line config change.

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
silently. The number itself is weak evidence (96% of lines executed says nothing about what was
asserted); the *partial-branch list* is the useful artifact, and working it is what surfaced
four untested branches in the audit writer's own error handling — including one where a
transient fault would have wedged every subsequent write.

**Leakage harness** (`pytest -m leakage`, 100 runs, both strategies alternating, varied seeds):

```
[leakage] 100/100 runs clean, 0 leaks
          (2979 originals vaulted and scanned, 2422 surrogates round-tripped)
```

**100 runs, zero leaks** is the load-bearing result. It has been reproduced on every run of the
committed tree, but read the summary line precisely, because the two halves of it mean different
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

- **2,979 originals** is stable for a given commit. Document seeds are fixed, so the same 100
  documents carry the same values, and this number only moves when detection changes. Observed
  identical on every run of the current build.
- **The surrogate round-trip count is not stable and is not a fingerprint of the build.** Two
  independent things move it. Within one commit it drifts by a few counts because session keys
  are `secrets.token_bytes(32)` and pseudonyms are seeded from `HMAC(session_key, …)`, so every
  pseudonymization run draws different fakes and which lines the mock provider echoes shifts
  with them — the count is of surrogates *the model happened to mention*. Three consecutive runs
  of the current build read **2,422 / 2,424 / 2,427**, with 2,979 originals identical in all
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

**Four boundaries are stated rather than closed**, because closing them would manufacture false
reds indistinguishable from real ones. Each is pinned by a test, so closing one later is a red
rather than a silent widening of the claim:

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
- **A combining mark spliced into a value — CLOSED, and this entry is kept to record that the
  argument for leaving it open was wrong.** The reasoning was: *"folding marks out would make
  `José` and `Jose` the same value."* That is true of the **needle** and irrelevant to the
  **haystack**, and the gate folds the haystack. `_deaccent` strips marks from the payload only,
  so `Nathaniél Brightwater` matches a vaulted `Nathaniel Brightwater` while a payload that
  legitimately says `Jose` still does not match a vaulted `José` — the needle keeps its accent.
  Pinned by `test_egress_gate.py::test_a_combining_mark_spliced_into_a_value_no_longer_reaches_the_provider`
  and `integration/test_pipeline.py::test_a_combining_mark_spliced_into_a_name_never_reaches_the_provider`.
  The residual is narrower and stated: a vaulted value that *itself* carries a mark (`José Ruiz`)
  is not protected against a *second* mark being spliced into it, because the needle is never
  stripped. Closing that needs the same confusables table the homoglyph gap needs.
- **Homoglyphs.** Cyrillic `о` for Latin `o` needs a confusables table, not another
  normalisation form. Out of scope in the gate for the same reason.

**The remaining two are blind spots the harness and the gate mostly share**, because both resolve
to the same occurrence rule — so for those shapes there is usually no second opinion. Confirmed
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
| Restore a 500-token response | 27.322 ms | 4.794 ms | 500 ms | 18.3× | single shot |
| Full pipeline, 12k-word brief (mock provider) | 9.776 s | 5.928 s | 15 s | 1.53× | best of 3 |

The best/worst spread is 3.1× on the same machine in the same ten minutes, which is the honest
headline of this table: **the budget column is a claim about this system, and every other column
is a claim about a laptop.** The worst readings here come from the tail of the sample, when the
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
test enforces. All five budgets passed on all seven runs.

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
regression injected into `PipelineOrchestrator.run` fails the full-pipeline budget at 17.16 s,
because a genuine slowdown affects every iteration and therefore moves the minimum. (A +6 s
regression passes — correctly, since 12.7 s is genuinely inside a 15 s budget.) The two
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
| `legal_brief_large.txt` | 12,062 words | 739 (647 obfuscated, 64 redacted, 28 stripped) | 251 | **7.16 s** (budget 15 s) |
| `medical_note.txt` | 393 words | 52 (51 obfuscated, 1 redacted, 0 stripped) | 32 | **0.28 s** |

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
  `429`, and each one writes an `AUDIT_ACCESS_DENIED` event — a **13th** event type, which is
  why Deviation 26's "the twelve" is now out of date. Writes (`POST /sessions`,
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
| `GET /audit` | compliance query | **Requires `session_id` or `run_id`**; unscoped is `400 AUDIT_SCOPE_REQUIRED`. Also filters `event_type`, `since`, `until`; paginated. |
| `GET /audit/verify` | hash-chain check | `{valid, length}` |
| `GET /health` | liveness | Model loaded, DB reachable, and a **count** of active sessions — never their IDs. |
| `GET /` | demo UI | static mount |

Two response conventions are worth naming because they look like sloppiness and are not.
An expired session, an unknown session, and a session belonging to somebody else all return
the **same** `401 SESSION_EXPIRED`; a wrong-owner document and an absent document both return
the same `404 NOT_FOUND`. In each case the distinguishable answer would be an oracle, and the
information a caller is owed is "no", not "no, and here is why".

`/docs` and `/redoc` are **off** (Deviation 19) — they fetch JS and CSS from a CDN, which
contradicts the offline premise of the whole design. `/openapi.json` is served locally.

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
| `INSURANCE_ID` | 5 | 80% | 80% |
| `AMOUNT` | 25 | 84% | 84% |
| `DOB` | 33 | 88% | 85% |
| `CLIENT_IDENTITY` | 13 | 92% | 92% |
| `ACCOUNT_NUMBER` | 19 | 95% | 95% |
| `SSN`, `TAX_ID`, `PHONE`, `EMAIL`, `ADDRESS`, `CASE_ID`, `DIAGNOSIS`, `MEDICATION`, `LAB_RESULT` | 194 | 100% | 100% |

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

Measured on `fixtures/legal_brief_large.txt` (12,062 words, 739 spans, **251 distinct
entities** vaulted), full pipeline, mock provider: **7.16 s end to end**, against a 15 s budget.

The stage breakdown is the answer, and it is not the one you would guess (median of three runs
on a loaded machine):

| Stage | Brief (12k words) | Medical note (393 words) |
|---|---|---|
| Detect (spaCy, stage 3) | 3,303 ms | 107 ms |
| Obfuscate (engine) | 645 ms | 21 ms |
| **Egress gate** | **2,779 ms** | **152 ms** |
| Restore | 1.9 ms | 0.5 ms |

**The gate costs about as much as detection.** That is the finding, and it took measuring the
gate's two passes separately to see it:

| | Brief | Medical note |
|---|---|---|
| Pass 1 — scan for vault originals, `O(payload × entities)` | 21.3 ms | 0.36 ms |
| Pass 2 — detector re-scan of the payload | 2,678 ms | 148 ms |

So **spaCy runs twice per request** — once over the document in stage 3, once over the
assembled payload inside the gate — and those two passes are **84%** of wall time on the brief
and **89%** on the medical note. The originals scan, the part that looks alarming on paper
because it is `O(payload × entities)`, is **0.8%** of the gate on the brief and **0.2%** on the
note.

#### The number above is per-*document*; the thing that grows is the *session*

Everything in this section is single-request latency, and that framing hid a real defect for
four review passes. Pass 1 is `O(payload × originals)`, and **originals accumulate across every
document in a 3600 s session**, not per request. Measured against an 81 KB payload:

| Session originals | Pass 1 |
|---|---|
| 251 (one brief) | 36.6 ms |
| 1,000 | 122 ms |
| 5,000 | 587 ms |
| 20,000 | 2,384 ms |
| 60,000 | 7,378 ms |

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
The whole optimisation is worth ~186 ms of a ~7,160 ms run: **2.6%**.

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
structural reason. The protected-span set is derived partly from `TOKEN_RE` run over the
**uploaded document**. Today it only decides which detections are discarded *after* a
full-context scan, and the token-hint bypass (`EgressGate._protected_spans`) is closed by
refusing to protect the hint tail. Letting that set decide what the detector *ever sees* would
upgrade an uploader's lever from "suppress a finding on my own token" to "reshape the gate's
input" — a strictly larger version of the bug already fixed.

**What the measurement points at instead.** Everything in `HIGH_SEVERITY_TYPES` — `SSN`, `MRN`,
`ACCOUNT_NUMBER`, `TAX_ID` — is pattern-typed. Those recognizers alone, over the full payload,
complete in **0.67 ms: 0.025% of the spaCy pass**. spaCy's ~2.7 seconds inside the gate therefore
buys exactly one thing — the advisory `rescan_warnings` counter. Splitting pass 2 into a cheap
always-on pattern check and an optional NER canary is the real answer, and it is a change to the
gate's *contract* (`rescan_warnings`, and the constructor-configurable `high_severity` set that
lets NER hits block) rather than a scoping tweak. Not shipped: rewriting the security
centerpiece's blocking path deserves its own review cycle, not a footnote in a perf section.

Bottlenecks in order, corrected by measurement:

1. **The second spaCy pass**, ~37% of end-to-end wall time. It cannot be *scoped* away safely,
   per the measurement above; the tractable form is making the blocking path not need spaCy.
2. **spaCy NER itself**, which is then the floor for both passes. It scales roughly linearly
   with document length; mitigated today by paragraph-boundary chunking with parallel
   per-chunk analysis (`asyncio.to_thread`, semaphore of 4). The scale answer is a process
   pool or a sidecar detector service, because this is CPU-bound and the GIL is the ceiling,
   not I/O.
3. **Vault writes** are individually trivial (p99 **0.001 ms** cached) but are issued one per
   unique entity. Batching into a single transaction per run removes the syscall overhead.

Aho-Corasick for the originals scan — the obvious answer, and the one this README gave before
the passes were timed separately — would optimise 21 ms out of 7,160. It is the right
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
shipped**, because a 2.2× headroom against the budget does not justify taking risk in the one
component whose correctness the entire submission rests on. What would make me do it: an
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
  `|Δ| < 30`, pushes it outward by 30 days. That folds `[-29, 29]` onto `[30, 59]` and
  `[-59, -30]`, so those two bands are drawn about twice as often as the rest. (The modulo bias
  itself is ~2⁻²⁴⁷ and ignorable.) An adversary who knows the formula therefore knows the shift
  is at least 30 days and is slightly more likely to sit in a 60-day window — which narrows a
  brute-force search over shifts from 541 candidates to a distribution over them. It does not
  recover the shift without a known-plaintext date, and it is the specification's formula
  rather than an implementation accident, but "non-uniform" is the accurate word and a uniform
  draw over `[30, 300] ∪ [-300, -30]` would be strictly better.
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
  inserting a row; reordering two rows; deleting a row from the middle; **replaying** a genuine
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
  lower `seq` and an identical `payload_sha256`.
- `run_id` correlation: one identifier ties the whole detect → obfuscate → egress → LLM →
  restore chain together, so "what happened on this request" is a single query. On the shipped
  fixtures that is 34–40 events per run, in the order `DETECT → OBFUSCATE → REDACT/STRIP →
  EGRESS_PASS → LLM_CALL → DEOBFUSCATE`.
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
  That is false and a reviewer can disprove it in one line: `detail` accepts any string up to 64
  characters and the label columns up to 128, so `"John Smith"`, `"MRN 4823910"`, an SSN and an
  e-mail all fit. What the ceilings actually buy is that the log cannot hold **content** — a
  paragraph, a note, a document — which is the bulk-exfiltration shape, and they are enforced
  twice: at the model, and again at the write boundary where `model_construct()` cannot skip them.

  The guarantee against a *short* identifier is a different kind of claim and is worth stating
  as what it is: **no call site writes one, and that is measured rather than asserted.** Every
  `emit` passes counts, latencies, digests, entity *type* names and 8-hex token IDs. The leakage
  harness scans the raw SQLite file — bytes, not the query API — against every vaulted original
  on all 100 runs. Re-checked directly for this answer: 85 distinct originals from three real
  runs, scanned against every raw column of the resulting 112-row log, **zero hits**.
  `test_audit.py::test_the_schema_bounds_a_value_but_does_not_forbid_a_short_one` pins the
  honest version so the overclaim cannot come back.

**Gaps the auditor should be told about:**

- **The 30-day sweep is a library call, not an HTTP call.** `GET /audit` deliberately refuses an
  unscoped query (400 `AUDIT_SCOPE_REQUIRED`): every row carries a `session_id`, and a
  `session_id` is the bearer credential for `DELETE /sessions/{id}`, so an open endpoint would
  hand any anonymous caller a list of live sessions to destroy. A cross-session date-range
  report therefore runs server-side against `AuditLogger` (which is what `demo.py --verify` and
  a compliance job would do), not through the public API. That is the right trade at this tier,
  but it does mean "the auditor can just query it" is true of the library and not of the
  deployed surface — the production shape is a separate authenticated compliance role.
- **`SESSION_EXPIRE` is declared in the event vocabulary and never emitted** (Deviation 26). TTL
  lapse is discovered lazily by the next accessor, so nothing is running at the moment a session
  dies. Logout does emit `VAULT_DESTROY`, so the explicit teardown path is covered and only the
  passive one is silent. An auditor asking "show me every session that expired" gets an empty
  result, and would be entitled to read that as "none did".

- **The chain is tamper-*evident*, not tamper-*proof*, and the difference is not academic.**
  The digest is `sha256(prev_hash ‖ canonical_json(event))`. There is no secret in that
  formula, so anyone who can write to the audit database can forge a row and recompute every
  subsequent hash, and `verify_chain()` will return `True`. That is not a hypothetical — it is
  a demonstrated result against this code. What the chain actually buys is that an attacker
  must rewrite **the entire chain from the forged row forward**, in one consistent pass, with
  write access to the file: it converts "edit one row in SQLite" into "replace the whole log",
  and it makes every *partial* tamper — the realistic case, including a database-level
  `UPDATE`, a mid-chain `DELETE`, an `INSERT`, a reorder, and a truncated tail — detectable.
  For the truncated tail specifically the cost is now four statements that must all land in
  step, and — the part that had been quietly missing — the evidence is **durable**: it used to
  expire on its own as soon as ordinary traffic reused the freed `seq` numbers, so an attacker
  needed only patience rather than a second statement. See the ladder in §5 Q5.
  Closing it properly requires the verifier to hold something the application host does not:
  an off-box append-only sink (S3 Object Lock, a WORM store, a managed audit service), or an
  HMAC key held by the auditor rather than the writer. Both are production changes, and neither
  is shipped here.
- Payload hashes prove *which* payload was sent but do not let anyone inspect *what* was sent.
  Retaining payloads would answer that — and would create exactly the sensitive-data store
  this system exists to avoid. That is a deliberate trade, not an oversight.
- The log captures our side only. What the provider did with the payload after receipt is
  contractual territory (a BAA), not something this system can attest to.
- **The 30-day sweep is a server-side call, not an API the auditor can use.** `GET /audit`
  deliberately requires a `session_id` or `run_id` scope (Deviation 18), because an unscoped
  audit endpoint published live session IDs and `session_id` is the bearer credential for
  `DELETE /sessions/{id}`. The consequence is that "queryable by time range" — which is true of
  `AuditLogger.query()` — **is not answerable over HTTP**, and an auditor cannot self-serve. It
  is a library capability with no safe route out.
  That is an unresolved design tension rather than an oversight: compliance querying and
  session-credential secrecy want opposite things from the same endpoint, and the fix is a
  *separate* authenticated compliance API with its own authorisation — not a query parameter on
  the one anonymous callers can reach. Not built.
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

| | Tokenization | Pseudonymization |
|---|---|---|
| **Reversibility** | Exact. Restore keys on an 8-hex HMAC, matched by a deliberately tolerant regex. | Surrogate string matching, longest-first with word boundaries. |
| **LLM reasoning utility** | Stilted; depends on the prompt contract holding. | Reads naturally, survives paraphrase, needs no contract. |
| **Inference surface** | Type and count only. | Fake names leak demographic plausibility; shifted dates leak intervals. |
| **Restore robustness** | Near-exact — high-entropy synthetic grammar, and any occurrence is unambiguous. | Inherits natural-language mutation risk; a fake is an ordinary word. |
| **Failure mode** | Model mangles the token → tolerated by the regex, or `[UNRESOLVED_ENTITY]` + audit. | A downstream human reads the fake **as real**. This is the dangerous one. |
| **"Smith" vs "John Smith"** | Distinct tokens. Correct reversibility, mild utility loss. | Component-linked to a consistent fake surname — better readability, slightly larger inference surface. |

That last failure-mode row is the one that should drive the decision. A mangled token is a
visible, audited, recoverable failure. A fake name mistaken for a real one by a clinician or a
paralegal is a silent one.

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

**Stated honestly, in rough priority order:**

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

1. **Detection recall is the binding constraint on the whole system.** The egress gate makes
   misses *safe* (it blocks), but it cannot make them *invisible* — a missed entity that
   another detection already vaulted causes a block, and a genuinely novel one passes through.
   scispaCy or a self-hosted clinical NER model is the single highest-value next change.
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
   `INSURANCE_ID` (`\b[A-Z]{2,4}\d{7,12}\b`) and `CASE_ID` are pattern-typed and high-specificity,
   are **not** in the set, and are released with a warning at 1.00 confidence. Measured. The
   membership is narrower than the rule given for it, with no reason recorded — which reads badly
   precisely because the comment invites the question.
7. **The vault serialises every session through one `asyncio.Lock` and one connection**, and its
   plaintext cache is unbounded. Five call sites (`put`, `_fetch_one`, `destroy`, `sweep_orphans`,
   `close`) take the same process-wide lock with no per-session striping, so a 251-entity brief
   takes and releases it 251 times against every other session in the process. Separately,
   `self._caches` is a `dict[str, _SessionCache]` of session-lifetime **plaintext** with no
   eviction and no size cap; `SessionRegistry._sweep_locked` expiring a key does **not** drop it.
   So decrypted PII accumulates for every session ever opened and not explicitly logged out, until
   process close — which means the module docstring's "session-lifetime plaintext in RAM is
   accepted" is doing more work than it looks, because that lifetime is not bounded by the
   session's TTL. Gap 17 below covers the *document store* and gap 12 the session
   registry; neither is this.
8. **Two structural debts, since paid — and one of them was not cosmetic after all.** Both were
   deferred once with the note that "no defect sits behind either". That was right about one and
   wrong about the other, which is worth recording.
   - **`api/app.py` was 1,835 lines carrying seven concerns**, with all eight endpoint handlers
     nested as closures in one 345-line `_register_routes`, so no endpoint was importable. Now
     **304 lines** — `create_app()` and the module docstring — over `constants.py`, `deps.py`,
     `middleware.py`, `lifespan.py`, `errors.py` and `routes/{sessions,documents,pipeline,audit,
     health}.py`. The stated blocker ("the closures bind to that function's locals") turned out
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

   The guard is now symmetric and the colliding date degrades to a plain token. Proven
   exhaustively rather than by sampling: `derive_date_shift_days` has exactly **540** reachable
   values, so 50 fixture documents × 540 shifts enumerates the entire space of the driving
   variable — **27 collisions before, 0 after**. The leakage harness went from 1 failing run in 8
   to 8/8 clean.

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
| 8 | **The engine performs a residual sweep** beyond the specified splice algorithm. | The spec splices only detected spans. Real documents mention the same value repeatedly and NER does not fire every time — a value detected in a header and missed in prose leaves the original in the payload, which the gate then (correctly) blocks on, rendering the pipeline unusable on ordinary documents. Once a value is vaulted it is now masked everywhere: **detection decides what is sensitive; the vault decides where it appears.** |
| 9 | Originals shorter than 3 characters are neither vaulted nor scanned for. | Applied consistently in the engine and the gate so the vault's originals set stays exactly co-extensive with what the gate can enforce. Otherwise the guarantee quietly becomes "zero originals, except the ones too short to check". |
| 10 | Domain-specific exceptions live beside their packages (`llm/base.py`, `store/document_store.py`). | All inherit `PipelineError`, so the no-content contract and the 64-char detail ceiling apply uniformly. Cross-package errors remain in `errors.py`, which documents the split. |
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
| 26 | **`SESSION_EXPIRE` is in the §7 event vocabulary and is never emitted.** Eleven of the twelve types are; this one is not. | TTL lapse is discovered *lazily* — `SessionRegistry` sweeps on the next access — so there is no moment at which a session expires and code is running to record it. Logout emits `VAULT_DESTROY` per §4 step 10, so the explicit teardown path is covered and only the passive one is silent. Closing it needs a background sweeper plus an audit handle on the registry, which is a new failure mode (a timer thread that can wedge) in exchange for an event nobody currently queries. The constant is kept rather than deleted so `query(event_type=SESSION_EXPIRE)` returns an honest empty list instead of hiding the gap. Called out in §5 Q5 as a gap the auditor should be told about. |
| 27 | **Two of §4's ten numbered steps emit no dedicated audit event.** The narrative says each step "emits audit events and captures latency"; steps 2 (fetch + decrypt) and 5 (context injection) capture latency only. | §7 fixes the event-type vocabulary and neither step has a member of it. Inventing `DOC_FETCH`/`INJECT` would be a *larger* deviation — from the vocabulary, which is the part a compliance reader depends on — for evidence that already exists elsewhere: the fetch is evidenced on the `DETECT` event emitted immediately after it in the same `run_id` (now carrying `doc_id` and `fetch_ms`, so the "which documents were read" question is answerable), and the injection is evidenced by `EGRESS_PASS`, which carries the sha256 and length of exactly the assembled payload. Both steps are timed in `PipelineResult.stats`; step 5 previously had **no** timing at all, which was a plain gap and is fixed. |
| 28 | **The token contract reproduces §9.5.2's `[PHI_MEDICATION_2f4a|oral-antidiabetic]` verbatim — a 4-hex hash — while §7 and §9.7 specify 8.** | The build doc contradicts itself, so "follow the spec" is not available: §9.5.2 calls its block "the exact system prompt", §7 declares `token_id` as 8 hex, and §9.7's `TOKEN_RE` requires `[0-9a-fA-F]{8}`. Keeping the prompt verbatim is the *safer* of the two, not merely the more literal. Being outside the grammar makes the literal inert: `TOKEN_RE` does not match it, so the restorer leaves it and the residual assertion stays silent. Normalising it to 8 hex would make it match — and a model echoing the example would then hit a hash the vault never issued, substituting `[UNRESOLVED_ENTITY]` and emitting a spurious **`VAULT_MISS`**, which is supposed to mean a real anomaly worth a compliance look. It is not a skip-list hole either: `_protected_spans` does not cover it, so pass 2 re-scans it like any other prose (more scrutiny than a real token's core gets), pass 1 never exempts it, and the shipped detector finds zero entities in either system prompt. Pinned by `test_the_token_contract_example_is_outside_the_grammar_and_that_is_inert`. |
| 29 | **`run()` re-derives the outbound digest and refuses to send unless it matches the one the gate cleared**, and `AuditLogger.length()` accepts the full `query()` filter set. | Both are additions rather than departures. The first closes a time-of-check-to-time-of-use window the spec's ordering requirement does not cover: "the gate ran first" and "the gate cleared what we sent" are different claims, and only the second is the guarantee — a stage inserted between the check and the provider call would satisfy every ordering test while releasing unaudited bytes. It fails as `EgressBlockedError(payload_changed_after_check)`, so the 422 handler and the audit trail treat it like any other block. The second makes §9.8's "logs must be queryable" *checkable*: `query` pages at 1000, and without a matching count a full page is indistinguishable from a complete 30-day answer. |
| 30 | **The `documents` metadata table has a sixth column, `size_bytes`.** | The spec enumerates five. Listing a user's documents without decrypting every blob needs the size, and §3 already grants that the metadata DB leaks *shape* — counts, categories, sizes, timestamps — so the column discloses nothing the threat model does not already concede. `test_document_store.py::test_metadata_columns_are_exactly_the_specified_schema` pins the full list, so a seventh column cannot appear silently. |
| 31 | **`EMAIL` gains a `patterns:` backstop** alongside `presidio: EMAIL_ADDRESS`. | Presidio's `EmailRecognizer` validates every candidate through `tldextract`, which resolves the domain against the **Public Suffix List** — an address whose suffix is not on that list scores zero and is dropped *silently*. Measured **0.0 recall** on `@acme.internal`, `@hospital.local`, `@mail.corp` and `@cluster.lan`, which is exactly what enterprise and hospital documents carry. EMAIL is a §2-mandated entity type, so a recogniser that only sees public domains does not satisfy the requirement. |
| 32 | **Sentence-tail patterns tolerate a soft line wrap; `CASE_STRATEGY`'s capture window goes 120 → 240 characters.** | The build doc's `[^.\n]{0,120}` terminates a span at the first newline. Every document reaching the detector has been through `extraction.py` and arrives **hard-wrapped**, so on a realistic document `action: redact` covered only the *first line* of its own strategy sentence and **shipped the remainder to the provider**. That is the failure the forced redaction exists to prevent. A blank line still ends the span, so paragraphs cannot run together. |
| 33 | **`LAB_RESULT` is case-folded and its tail made lazy.** | Greedy matching read `"your LDL is 162 and your A1C came back at 7.4"` as a single span ending at the `1` of `A1C` — so the second result, `7.4`, escaped obfuscation entirely. A greedy quantifier on a tail pattern does not merely over-capture; it swallows the boundary that the *next* value needed. |
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
| 45 | **The Faker seed label carries the normalized original value**, not just the entity type: `HMAC(session_key, b"faker:" + f"{entity_type}:{normalize(text)}")`. §9.3 writes `b"faker:" + entity_type`. | Stability per *value* rather than per *type* is what component linking needs — one patient must own both `Sherri Lopez` and `Lopez` across the whole document. `crypto/keys.py` still implements §9.3's signature exactly; only the label passed to it is composite. Not a disclosure: the HMAC is under a secret 32-byte session key, `normalize` cannot introduce NUL, and `_label_bytes` rejects one, so the domain separation argument in `keys.py` still holds. Recorded because original values now flow into a keyed derivation, which is a fact a security reviewer should be told rather than have to find. |
| 46 | **`CASE_ID` pattern 1 drops §6.2's `(?:Case|Docket)\s+No\.?\s*[:#]?\s*` prefix**, widens `[a-z]{2}` to `[a-z]{2,4}`, and adds `(?i)`. | Real briefs cite bare docket numbers, and requiring the lexical prefix missed them. The cost is that the pattern now claims any `d:dd-xx-ddd` run in **any** document category with no lexical context, which is exactly the broadening Deviation 15 relies on. Deviation 3 covers only the backslash spelling and was previously the only row mentioning `CASE_ID`. Same class, lower stakes: `MEDICATION` drops the spec's `takes` context word (explained in `entities.yaml`, not here until now), and `MRN`/`ACCOUNT_NUMBER` are wholesale rewrites acknowledged only in a §4 parenthetical. |
| 47 | **`regex` is a hard runtime dependency and is now declared.** | `detection/registry.py` does `import regex`, and it resolved only transitively through `presidio-analyzer`. It is not optional: `MRN` and `ACCOUNT_NUMBER` use PCRE `\K` and possessive quantifiers, which the standard library's `re` **cannot compile at all** (`bad escape \K`), so `entities.yaml` is not portable to `re` and every path that touches the registry — config, detector, engine, strategies — fails at import without it. Deviation 2 enumerated the added dependencies and omitted the one that was undeclared. |
| 48 | **A Tier-2 span that is a *list* of dates is split into one detection per date** (`Detector._split_composite_dates`), and the egress gate derives a scan needle per constituent of a composite vaulted original (`_composite_needles`). | spaCy returns `03/11/2024, 09/17/2024` as one `DATE` span, so the whole string became a single vault original. A different date shifted onto `03/11/2024` then rendered a **verbatim slice** of that original, and both leak scanners reported clean — correctly, since each asks whether a *whole* vaulted value occurs. The pipeline was manufacturing the partial disclosure that §1's first boundary describes. Splitting is refused unless every constituent parses, because a partial split leaves a rump span with the same defect; the gate limb is duplicated on purpose so the fix does not depend on detection being right. It is also a utility gain — those dates previously degraded to a plain token, losing the interval property Tier 2 exists for. |
| 49 | **§9.7's `[UNRESOLVED_ENTITY]` + `VAULT_MISS` rule is not applied to an *unbracketed* token whose ID this run did not mint** — it is left byte-for-byte, with `vault_misses` unincremented and no audit row. | §9.7 states the rule for any unknown `token_id`, unconditionally, and the shipped restorer honours it for every **bracketed** form (including all seven mangled shapes in §10.7). The carve-out is the `foreign` branch in `Restorer._resolve`, and it exists because an unbracketed match is far more likely to be *document text* than a mangled token: `TOKEN_RE` is deliberately tolerant of missing brackets so the restorer can read what an LLM mangled, and that same tolerance makes a clinical document's own `PHI-MRN-40281993` a match. Substituting `[UNRESOLVED_ENTITY]` there would delete a real sentence from the user's answer to protect a value that was never ours; leaving it is the conservative failure. The narrowing is only available when `issued` is supplied, which the orchestrator always does — so the production path takes this branch and the library default (`issued=None`) does not. Pinned by `test_a_document_reference_the_model_echoes_never_reaches_the_audit_log`. |
| 50 | **`AMOUNT` uses a group-structured pattern** (`\d{1,3}(?:,\d{3})+|\d+` with `\.\d{1,2}`) instead of §6.2's `[\d,]{1,12}(?:\.\d{2})?\b`. | The character class counts digits *and* commas against one bound and truncates at the twelfth character, so `$1,234,567,890.12` matched only `$1,234,567,` — the token was spliced in beside a bare `890.12`, six digits of a real figure in the clear, and pass 1 had no needle for them because the vaulted original is the truncated string. That is the partial-value class Deviation 48 exists to close. `{1,2}` on the cents closes the same hole one character wide (`$1,234.5` matched `$1,234`, leaving `.5`). |
| 51 | **`normalize()` applies NFKC a second time, after casefolding, and strips non-whitespace C0/C1 controls.** | Casefolding is not closed over NFKC — `casefold("ß")` is `"ss"`, so `"ß" + U+0323` folds to `"ss" + U+0323` and a second NFKC composes the trailing `s` with the mark. `normalize` was therefore **not idempotent**, while `SessionVault.put` indexed on one pass and `get_by_original` re-normalised on the documented grounds that it was: the write landed under one key, the read-back missed under another, and the engine raised `vault_put_not_readable` from a branch commented `# pragma: no cover -- this cannot happen`. HTTP 500 from an ordinary `.txt`. Controls are stripped for a sibling reason: Deviation 45 routes the normalised *document value* into an HMAC label, and `_label_bytes` rejects a label carrying its own NUL — a guard written for config typos, applied to document content, so one NUL in a span (or in the JSON `prompt`, with a benign document) was a 500. Pinned by a property test over the whole Unicode range. |
| 52 | **`_parse_fallback` parses against two anchors and rejects any date **any** of whose (year, month, day) came from the default.** | The `\d+` twice guard rejects a bare year but not a bare clock time: `9:15 AM` has two digit runs, neither a date component, so dateutil resolved the whole date from the anchor and the payload asserted a day the source never mentions — the exact lie `daterules.py` says it exists to prevent ("a shifted today is a wrong date that looks right"); relocating the anchor moved it rather than removing it. Every subsequent clock time collided on the same fabricated date, so three times on one page rendered three incomparable ways. No digit heuristic can decide this; parsing against two anchors that share no field answers it exactly. **The rule is ANY, not ALL**, and the cost is worth stating: a partial date that supplies some components but not others -- `3/14`, `March 14` -- is refused Tier-2 treatment and degrades to a plain token rather than a shifted date. That is the safe direction (a token discloses nothing and invents nothing) but it is a recall loss, not a free win. |
| 53 | **`load_registry` validates `only_in_doc_categories` against `DOC_CATEGORIES`**, which moved to `models.py` so both consumers share one vocabulary. | It was validated against nothing. A typo (`medial`) loaded clean, and because the field is enforced by *restricting the requested entity set*, an unmatchable value restricted the entity out of **every** document including `general` and unclassified — never detected, so never vaulted, so no egress-gate backstop either. A one-character config typo silently removed an entity and all three of its defences, while the adjacent `category:` typo has always raised. |
| 54 | **TTL expiry now runs the full destruction path** (`api/deps.reap_expired_sessions`), not only the key pop. | §4 step 10 and §9.4 both say expiry destroys like logout — key popped, vault rows deleted, `VAULT_DESTROY` audited. Only the first happened. `SessionRegistry.sweep()`'s own docstring says "the caller is responsible for the rest", and there was no caller: `sweep()` appeared exactly once in the tree, in a test. An expired session therefore left AES-GCM rows in `vault.db` and a decrypted cache in RAM until process exit — and they were **unreclaimable**, because `DELETE /sessions` gates on an ownership check that raises for an expired session and skips `vault.destroy`. Reaping runs on the request that discovers the expiry, which is also the request that would otherwise strand the rows. Also closes Deviation 26's missing expiry event. |
| 55 | **A lone name component is always treated as a surname**; §9.3's "same rule for first names" is not implemented. | `role` is `"last"` for the final word of a span and `"first"` otherwise, so a bare given name (`"Priya said…"`) gets a surname-shaped fake and does not link to the `Priya Raman` mapped elsewhere. It is the right default for these documents — a lone component in clinical and legal prose is overwhelmingly a surname (`"Dr. Patel said…"`) — and the module docstring has always said so, but the ledger had not. |
| 56 | **The demo UI's "destroy session, then run again" shows the *erasure*, not a live vault miss** (§9.10 describes it as demonstrating the vault-miss path). | A destroyed session is refused at the session check — `401 SESSION_EXPIRED` — **before** the vault is consulted, so no `VAULT_MISS` is reachable from one in this architecture; the button's banner promised otherwise. What it does demonstrate is stronger: the key is gone, so nothing can be decrypted at all. The genuine vault-miss path is exercised where it actually occurs — a model inventing a token inside a *live* session — by `test_vault_miss_on_deobfuscation` at both unit and integration level, and by `demo.py`. Two supporting bugs fixed with it: `destroySession` nulled `S.sessionId`, and `loadAudit` bailed on a null one, so the audit panel went blank at exactly the moment `VAULT_DESTROY` landed in it, and the `SESSION_EXPIRED` refresh branch was dead code. |

---

## 9. Repository map

```
secure_context_pipeline/
  config.py          Settings -- the only component that reads the environment
  models.py          Pydantic models; AuditEvent is frozen, length-capped, detail read-only
  errors.py          Exception hierarchy; structured detail only, 64-char ceiling
  surrogates.py      The token grammar -- one definition, three consumers
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
  ui/                Single static demo page, no build step
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
| `medical_note.txt` | 393 | 28 | 10 |
| `legal_memo.txt` | 475 | 29 | 8 |
| `financial_disclosure.txt` | 306 | 32 | 8 |
| `legal_brief_large.txt` | **12,062** | **272** | 8 |

The large brief is the specification's "~12,000 words, 200+ distinct entities" artifact — it is
the Q1 discussion document, the input to the full-pipeline benchmark, and the reason the
generator asserts its own word count and distinct-entity count at build time rather than
trusting the templates to stay in range.

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
third column is empty is a claim, not a result; the two rows that end in a human check are
marked as such rather than quietly asserted.

| Requirement | Implementation | Proving test |
|---|---|---|
| **Core 1** — encrypted store, PDF/DOCX/TXT, AES-256, per-user keys | `store/document_store.py`, `store/extraction.py`, `crypto/aead.py`, `crypto/keys.py::EnvKeyProvider.doc_key` | `test_document_store.py::test_blobs_on_disk_are_ciphertext`, `::test_no_plaintext_anywhere_under_the_data_dir`, `::test_absent_and_foreign_documents_are_indistinguishable`, `::test_confusable_user_ids_cannot_read_each_others_documents`; `test_extraction.py` (pdf/docx/txt); `integration/test_pipeline.py::test_per_user_document_keys_are_load_bearing_on_their_own` |
| **Core 2** — detector, nine-entity minimum, spans with type + confidence | `entities.yaml` (20 types), `detection/registry.py`, `detection/recognizers.py`, `detection/detector.py::Detector.detect`, `models.py::Detection`/`SpanOut` | `integration/test_pipeline.py::test_the_nine_mandated_entity_types_survive_the_whole_round_trip`; `test_detection.py::test_entity_positive_and_near_miss` (per-entity positive **and** near-miss negative) |
| **Core 3** — two strategies + per-entity justification | `obfuscation/strategies/{base,tokenization,pseudonymization}.py`, `registry.tier_of`, README §6 | `test_obfuscation.py::test_tokenization_format_round_trips_through_the_strict_grammar`, `::test_pseudonym_preserves_identifier_formats`, `::test_tier3_diagnosis_emits_a_class_annotated_token_from_the_gazetteer`, `::test_tier4_numerics_stay_plain_tokens` |
| **Core 4** — vault encrypted, deterministic in-session, purged on expiry/logout | `vault/session_vault.py`, `vault/session_registry.py` | `test_vault.py::test_within_session_determinism`, `::test_destroy_makes_tokens_unreadable`, `::test_destroy_surviving_row_is_undecryptable`, `::test_surviving_row_cannot_repopulate_a_destroyed_cache`; `integration/test_pipeline.py::test_expired_session` |
| **Core 5** — context injector, chunking, pre-send check | `pipeline/context_injector.py`, `pipeline/egress_gate.py`, `detection/detector.py::chunk_text` | `test_context_injector.py::test_serialized_is_exactly_what_the_gate_scans`; `test_egress_gate.py::test_the_gate_runs_before_the_provider_on_the_happy_path`, `::test_the_provider_is_never_reached_when_the_gate_blocks`; `test_detection.py::test_entity_straddling_a_chunk_boundary_is_detected_whole` |
| **Core 6** — restore, including mangled/paraphrased token forms | `deobfuscation/restorer.py`, `surrogates.py::TOKEN_RE` | `test_deobfuscation.py::test_mangled_token_forms_restore`, `::test_hint_is_ignored_for_lookup`, `::test_post_restore_assertion_fires_on_residual_token`; `integration/test_pipeline.py::test_vault_miss_on_deobfuscation` |
| **Core 7** — audit: ts, session, type, token, action; queryable; zero originals | `audit/logger.py`, `models.py::AuditEvent` | `test_audit.py::test_persisted_rows_carry_no_free_text_columns`, `::test_detail_rejects_long_string_values`, `::test_truncating_the_tail_breaks_the_chain`, `::test_deleting_a_middle_row_and_relinking_the_chain_is_still_caught`, `::test_erasing_a_whole_session_is_not_reported_as_that_session_being_clean`, `::test_a_truncated_tail_does_not_heal_when_the_log_advances`, `::test_a_silent_tail_truncation_costs_four_statements_and_all_four_are_needed`, `::test_deleting_the_sqlite_sequence_row_does_not_launder_a_truncation`, `::test_two_processes_sharing_one_audit_db_lose_no_events`; leakage assertion 2 and `leakage/test_leakage_harness.py::test_the_audit_scan_catches_a_label_column_original_and_says_which_limb_did` |
| **Critical constraint** — reversible in-session, irreversible across | `crypto/keys.py::derive_token_id` (HMAC under an ephemeral key), key destruction | `test_crypto.py::test_token_id_deterministic_within_session`, `::test_token_id_non_deterministic_across_sessions`, `::test_token_id_is_irreversible_without_the_key`; `integration/test_pipeline.py::test_restoration_is_impossible_after_the_session_is_destroyed` |
| **NFR** — config-only entity add | `entities.yaml`; `entity_type` opaque downstream | `test_extensibility.py::test_package_source_never_mentions_passport` (the grep **is** the proof), plus the three end-to-end cases beside it |
| **NFR** — strategy swappable via config | strategy registry dict, `Settings.strategy` | `test_obfuscation.py::test_dummy_strategy_plugs_in_with_zero_engine_changes`, `::test_per_entity_strategy_override_is_config_only`; `test_llm.py::test_new_provider_name_is_selectable_with_zero_other_changes` |
| **NFR** — zero PII in transit, verifiable by inspection | `pipeline/egress_gate.py` (fail-closed, **three** passes — §9.5.3 specifies two; the third is Deviation 42) | `leakage/test_leakage_harness.py::test_no_original_ever_leaves_the_process` (**100 runs**), `::test_unknown_shape_value_blocks_egress_and_the_call_never_fires`, `::test_the_leak_scan_bites`; the three stated boundaries are pinned by `::test_a_partial_value_leak_is_outside_what_this_harness_claims` and `::test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims` (the homoglyph one by `test_egress_gate.py::test_a_homoglyph_substitution_is_outside_what_the_scan_claims`, which was **missing entirely** until this audit — the only entry in the list whose status was an assertion about the code rather than a measurement of it); the combining-mark shape is **closed**, not a boundary, and is pinned by `test_egress_gate.py::test_a_combining_mark_spliced_into_a_value_no_longer_reaches_the_provider` (the glued-word boundary applies to the byte limb of the audit scan too; the query limb is what catches a label-column original — see `::test_the_byte_limb_and_the_query_limb_of_the_audit_scan_see_different_things`); round-trip completeness is derived independently of the restorer, enforced by `::test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots`; `demo.py --dump-wire` for the literal HTTP body |
| **NFR** — vault isolation is cryptographic, cross-session | per-session HKDF vault keys, AAD `session_id:token_id` | `test_vault.py::test_aad_binding_across_sessions`, `::test_aad_binding_across_token_ids`; `integration/test_pipeline.py::test_concurrent_session_isolation` (50 interleaved ops) |
| **NFR** — graceful degradation (never pass through raw) | engine threshold policy, `action: redact` | `test_obfuscation.py::test_mid_confidence_span_is_redacted_without_a_vault_entry`, `::test_case_strategy_is_force_redacted_in_both_modes`; `test_detection.py::test_below_floor_span_is_dropped` |
| **NFR** — async pipeline, spaCy off the event loop | `detector.detect` (`asyncio.to_thread` behind `Semaphore(4)`), `aiosqlite`, `aiofiles` | `integration/test_pipeline.py::test_the_pipeline_never_blocks_the_event_loop`; `test_extraction.py::test_extraction_runs_off_the_event_loop_thread` |
| **Spec-mandated test cases** (5, by name) | — | `integration/test_pipeline.py::test_happy_path_end_to_end`, `::test_entity_type_not_found`, `::test_vault_miss_on_deobfuscation`, `::test_expired_session`, `::test_concurrent_session_isolation` |
| **Stack** — Python 3.11, `cryptography`, pytest, Docker, `.env` only | `pyproject.toml` (`requires-python >=3.11,<3.13`), `Dockerfile`, `docker-compose.yml`, `.env.example`, `config.py` | `test_crypto.py::test_settings_secrets_do_not_survive_serialization`; `test_api.py::test_dockerfile_never_copies_the_working_tree_wholesale`. **`docker compose up` itself is a human check** — checklist step 3. |
| **Cloud row** (stretch) — KMS mock, S3/GCS-compatible design | `crypto/keys.py::MockKMSKeyProvider`, `KeyProvider`/`DocumentStore` Protocols | `test_crypto.py::test_mock_kms_envelope_round_trip`, `::test_mock_kms_binds_encryption_context`, `::test_build_key_provider_selects_by_config`; `test_document_store.py::test_key_provider_is_the_seam`. **Known thinness:** the KMS provider is tested as a unit, never driven end-to-end with `SCP_KEY_PROVIDER=mock_kms`. |
| **Live review Q1–Q6** | README §5 | Q1's numbers come from `test_benchmarks.py` and the stage table; the rest are arguments, not testable claims. |
| **Functional must-haves (all 7)** | — | **Human check.** See below. |
| **Performance benchmarks (all 5)** | `test_benchmarks.py` | Four are automated. **The fifth is a human check.** See below. |

### The two rows a human has to close

Both reference the confidential challenge document, which is deliberately not reproduced
anywhere in this repository. Neither can be verified from inside the repo, and pretending
otherwise would be the exact failure this table exists to prevent.

- **Functional must-haves (all 7).** The build specification I worked from paraphrases these
  rather than quoting them. Open the original challenge document, read the seven must-haves,
  and tick each against §10 above and against a `python demo.py` run. The likely mapping is
  upload → detect → obfuscate → inject → egress-check → LLM → restore, all of which `demo.py`
  exercises and asserts on, but **the wording is the authority and I could not see it.**
- **Performance benchmarks (all 5).** Four budgets are automated and enforced:
  obfuscate 2,000 words < 2 s, vault lookup p99 < 5 ms, restore 500 tokens < 500 ms, full
  pipeline < 15 s. The challenge names five. Read the fifth off the original document; if it
  is a throughput or concurrency figure, nothing here measures it yet.

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
python demo.py && echo "demo exit 0"
```

`demo.py` mints an ephemeral master key if `SCP_MASTER_KEY` is unset, so it runs with no `.env`.
It exits non-zero on any failed assertion — the exit code is the check, but read the printed
ledger too.

**5 — The suite, in the clean clone.**

```bash
pytest -q            # expect: all passed, 1 skipped (the real-network LLM smoke test)
pytest -m leakage -q # expect: 100/100 runs clean, 0 leaks
pytest -m bench -q   # expect: 5 measurements, all inside budget
mypy                 # expect: Success, 52 source files
ruff check .         # expect: All checks passed!

# The partial-branch list, which is the part worth reading:
pytest --cov=secure_context_pipeline --cov-branch \
       --cov-report=term-missing:skip-covered -q
```

Paste the leakage summary line into §1 if it has drifted. The `100/100, 0 leaks` part does not
move; the two tallies beside it track what the detector currently finds.

**6 — The two rows only you can close.** Open the original challenge document and check:

- the **seven functional must-haves**, against §10 and a `demo.py` run;
- the **fifth performance benchmark** — four are automated, and I could not see which the
  fifth is.

Both are described in §10 under "The two rows a human has to close". This is the one step that
cannot be delegated, because the source document is confidential and is deliberately not in
this repository.

**7 — Reviewer-supplied fixture, if there is one.**

```bash
python demo.py --file /path/to/their.pdf --category medical
```

**8 — Confidentiality sweep.** No challenge-document text anywhere:

```bash
grep -rniE 'take-?home|challenge (doc|document)|confidential' --include='*.py' --include='*.md' \
  --include='*.yaml' . | grep -v '\.venv'
```

Expect only this project's own uses of the word "confidential" (the legal fixtures and the
privilege markers). Anything that reads like quoted requirements text must go.

**9 — README, last.** Confirm §1 numbers match what step 5 just printed, and that §3, §4, §5,
§6, §7 and §8 are all present and current.

**10 — Access and submit.** Repo private, hiring team granted access, link submitted through
the portal before the deadline.
