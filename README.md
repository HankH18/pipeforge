# Secure Context Pipeline

A privacy boundary between an encrypted document store and an external LLM provider.

```
fetch + decrypt → detect → obfuscate → EGRESS GATE → provider → restore
```

The claim this system makes is narrow and testable: **raw PII, PHI, and privileged content
never leave the process boundary toward the provider, and that is verifiable by inspection.**
Obfuscation is reversible within a session and cryptographically irreversible across sessions.

Everything below is measured on this repository, not aspirational.

### If you have ten minutes before the review

| You want | Go to |
|---|---|
| Does it run? | §1 — two commands, and the numbers the suite prints |
| Is the zero-egress claim real? | §1 *Leakage harness* — including the shapes the harness itself was blind to, the four boundaries it does **not** claim, and how each was found |
| What does it **not** defend? | §3 — **start with "The weakest point in this design"**: `user_id` is an asserted claim and there is no authn at this tier |
| The six live-review questions | §5 — each answered in its first sentence |
| Where it breaks at scale | §5 Q1 — the bottleneck is not the one you would guess, and the obvious fix was measured and **rejected** |
| What I got wrong | §8 Deviations (39, each with a reason) and §7 Known gaps |

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

docker compose up --build      # UI at http://localhost:8000
```

The spaCy `en_core_web_lg` model (~590 MB) is baked in at **build** time, not fetched at
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
1217 passed, 1 skipped       # full suite; the skip is the real-network LLM smoke test
                             #   115 leakage - 5 bench - rest unit + integration
mypy --strict                # clean, 39 source files
ruff check .                 # clean, whole repo
```

**Leakage harness** (`pytest -m leakage`, 100 runs, both strategies alternating, varied seeds):

```
[leakage] 100/100 runs clean, 0 leaks
          (2840 originals vaulted and scanned, 2410 surrogates round-tripped)
```

**100 runs, zero leaks** is the load-bearing result and it does not move. The two tallies
beside it behave differently from each other, and the difference is worth stating precisely
rather than describing both as "reproducible":

- **2,840 originals** is stable for a given commit. Document seeds are fixed, so the same 100
  documents carry the same values, and this number only moves when detection changes. Observed
  identical on every run of the current build.
- **The surrogate round-trip count is not stable and is not a fingerprint of the build.** Two
  independent things move it. Within one commit it drifts by a few counts because session keys
  are `secrets.token_bytes(32)` and pseudonyms are seeded from `HMAC(session_key, …)`, so every
  pseudonymization run draws different fakes and which lines the mock provider echoes shifts
  with them — the count is of surrogates *the model happened to mention*. A stable number here
  would actually be evidence of a bug: it would mean session keys were not random. Across
  commits it moves much further, because any change to obfuscation or restoration changes what
  there is to mention; it was observed at **2,717** during one such change and back at **2,408**
  after it. Do not treat any single reading as a regression signal — `ledger.leaks == 0` is the
  assertion, and the tally is context.

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
is an `ImportError` instead of silence. Two tests hold the line:
`test_the_occurrence_rule_has_no_fourth_copy` checks that single definition against an
independently written reference across 220 needle/haystack pairs, and
`test_no_comparison_in_this_module_bypasses_the_shared_rule` fails if any bare membership test
reappears in the file — catching the **class** rather than the four instances, which is the only
thing that has actually worked on this bug.

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
- **A value glued into a longer word.** `xJohn Smithx` carries the original byte for byte and is
  reported by neither. The occurrence rule asserts a word boundary on each side whose adjacent
  needle character is alphanumeric — which is precisely what stops `Brown` matching inside
  `Browning`. Relaxing it only for multi-word originals does not rescue it: `chronic low back
  pains` contains `chronic low back pain`. What keeps the residual risk small is that the
  pipeline cannot emit this shape — every surrogate and redaction marker ends in `]`, so a
  splice that leaves an original beside our own output has a non-alphanumeric character between
  them and *is* caught. Pinned by
  `test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims`.
- **A combining mark spliced into a value.** `normalize` is NFKC, which *composes* — so a
  decomposed rendering of `José` is caught, and that half is now asserted. What no
  normalisation form can do is remove a mark that was never in the vaulted value: `J` + U+0301 +
  `ohn Smith` is simply a different string. Folding marks out would make `José` and `Jose` the
  same value, which the gate's `_INVISIBLE_RE` deliberately refuses in a comment naming that
  exact trade. Pinned by
  `test_a_combining_mark_inside_a_value_is_outside_what_this_harness_claims`.
- **Homoglyphs.** Cyrillic `о` for Latin `o` needs a confusables table, not another
  normalisation form. Out of scope in the gate for the same reason.

**The last three are blind spots the harness and the gate share**, because both resolve to the
same occurrence rule — so for those shapes there is no second opinion. Confirmed rather than
reasoned about: with the gate **live**, a real vaulted original spliced into a real payload with
one combining acute inserted, or glued to a letter, completed the run and reached the provider.
Where the gate is a second opinion that is survivable; on the audit database and the process log,
where nothing else looks, it is not — which is why these are recorded as claims the harness does
not make rather than as cases it happens not to have hit.

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

| Measurement | Worst of a 7-run sample | Budget | Headroom at that worst | Scoring |
|---|---|---|---|---|
| Obfuscate 2,000 words (tokenization) | 0.388 s | 2 s | 5.2× | best of 3 |
| Obfuscate 2,000 words (pseudonymization) | 0.389 s | 2 s | 5.1× | best of 3 |
| Vault lookup p99 (1,000 cached reads) | 0.001 ms | 5 ms | 3,636× | single shot |
| Restore a 500-token response | 4.774 ms | 500 ms | 104.7× | single shot |
| Full pipeline, 12k-word brief (mock provider) | 7.248 s | 15 s | 2.07× | best of 3 |

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
| `medical_note.txt` | 393 words | 54 (52 obfuscated, 2 redacted, 0 stripped) | 32 | **0.28 s** |

(The medical note's span count read `52` here until it was re-derived: 52 is the *obfuscated*
count, and 54 is the total. The brief's row was already consistent — 647 + 64 + 28 = 739.)

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
                                              │     AAD = session_id + token_id
   ContextInjector ◄───────────────────────── ┤
                                              │
   ╔══════════════════════════════════════╗   │
   ║  EgressGate  — FAIL CLOSED           ║◄──┤   ← nothing reaches the provider
   ║  1. scan for every vault original    ║   │      except through here
   ║  2. detector re-scan minus surrogates║   │
   ╚══════════════════════════════════════╝   │
                                              │
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
| **Provider or network intermediary reads the payload** | Egress gate (fail-closed, two independent passes) + token opacity | The obfuscated payload still reveals document *shape*: entity counts, types, and positions. A 40-entity medical note is visibly a 40-entity medical note. |
| **Vault database stolen at rest** | AES-256-GCM under a key derived from an in-memory-only session key. The session key is never persisted. | Live-process memory scraping. Session-lifetime plaintext lives in RAM by design (that is what makes a < 5 ms lookup possible). **Declared out of scope for this tier.** |
| **Cross-session access, same user** | Per-session HKDF vault keys, AAD binding to `session_id:token_id`, non-deterministic token IDs across sessions | None identified. A row copied between sessions fails GCM authentication. |
| **Log or audit exfiltration** (*reading* the log) | Length ceilings that make the log incapable of holding *content* (`detail` values 64 chars, label columns 128), enforced again at the write boundary; no call site that writes a value; and the leakage harness scanning the raw DB **bytes** on all 100 runs | **A short identifier would fit, and the schema cannot tell.** `detail={"v": "John Smith"}` validates — see below. The guarantee is "nothing writes one", measured, not "the schema forbids one". Plus traffic analysis of event counts and timings. |
| **Audit tampering** (*writing* to the log) | SHA-256 hash chain over every event, plus a `sqlite_sequence` high-water check so deleting the newest rows is caught | **Bounded, and the bound is the interesting part.** The digests are **unkeyed**, so an attacker with write access to the DB file can rewrite the chain end to end and it will verify — demonstrated, not assumed. See §5 Q5. |
| **Replay of Session A ciphertext into Session B** | AAD authentication failure | None identified. |
| **Caller presents a session ID that is not theirs** | Sessions are **bound to the creating `user_id`**; `POST /pipeline/run` compares with `secrets.compare_digest` and answers the same `401 SESSION_EXPIRED` as an unknown session. `DELETE /sessions/{id}` requires the owner's `user_id` and returns an unconditional 204 either way. | The `user_id` is still an **asserted claim, not a proven one** — there is no real authentication at this tier. What the binding buys is that a leaked *session ID* is no longer sufficient on its own; what it does not buy is protection against a caller who simply asserts someone else's `user_id`. Real authn is the production item. |
| **Anonymous enumeration of live session IDs** | `GET /audit` requires a `session_id`/`run_id` scope; `/health` reports a session *count*, never IDs | None identified for the enumeration path itself. This was a **live hole, not a hypothetical**: unscoped `GET /audit` published every active session ID, and `DELETE /sessions/{id}` then accepted them — full vault destruction with zero credentials. |
| **Wrong user requests another user's document** | Per-user HKDF document keys **and** AAD binding to `doc:<user_id>:<doc_id>` — two independent legs, each pinned by its own test | Surfaced as `NOT_FOUND`, byte-identical to an absent document: same exception type, same code, same detail keys. The *content* oracle is closed. A **timing** side channel is not — see below. |
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
| Values **covered** by a detected span | 99% | **88.5%** |
| Values covered **and correctly typed** | 99% | **87.4%** |
| `MRN` covered | ~100% | **27% (4 of 15)** |
| `MRN` correctly typed | ~100% | **13% (2 of 15)** |

Reproduce with `pytest tests/test_detection.py -k held_out -s`; the floors are asserted, not
commented, so a regression fails the build.

**Read the gap, not the average.** The 10.5-point drop is the ordinary cost of unseen shapes.
`MRN` is not ordinary: it collapses because the registry recognises the field *labels* it was
shown (`MRN:`, `Medical Record No.`) and unseen documents write `Rec #`, `Chart:`, or put the
number in a table cell with no label at all. Two of the fifteen are absorbed by `DATE`, which is
worse than a miss — a seven-digit record number is date-shifted and looks handled.

**This is the honest bottom line of the whole submission.** Detection recall is the binding
constraint (§7), and an entity the detector misses is not merely unblocked: it never enters the
vault, so egress-gate pass 1 does not scan for it, pass 2 re-scans with the *same* detector and
shares the miss exactly, and the 100-run leakage harness cannot see it either — the instrument
that measures leaks is blind to precisely the leaks that matter most. `100/100 clean` is
therefore a statement about values the detector found, not about all PII in the document. The
architectural answer is that the gate is fail-closed over the vault (a defence in depth that
does not depend on recall), and the engineering answer is a clinical NER model rather than a
gazetteer plus label patterns. Neither answer makes 27% acceptable, and it is stated here rather
than left for a reviewer to find.

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
than a failed request. It **invents** a token that was never issued — same path, and
`integration/test_pipeline.py::test_vault_miss_on_deobfuscation` is that case. It emits
something that merely looks like a token — the restorer resolves against the vault, so an
unissued ID cannot resolve to anybody's data.

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

  **The exact edge of the high-water defence, since it is easy to overstate.**
  `sqlite_sequence` is an ordinary table in the same file, so an attacker who can run the
  `DELETE` can run one more `UPDATE` and the truncation becomes invisible — demonstrated, and
  pinned by `test_tail_truncation_is_only_caught_while_sqlite_sequence_is_intact`. It raises the
  cost of a silent truncation from one statement to two; it does not make it impossible. That is
  the same unkeyed-digest limit described below, reached by a shorter route than "rewrite the
  whole chain".
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

---

## 7. Known gaps & next day

**Stated honestly, in rough priority order:**

1. **Detection recall is the binding constraint on the whole system.** The egress gate makes
   misses *safe* (it blocks), but it cannot make them *invisible* — a missed entity that
   another detection already vaulted causes a block, and a genuinely novel one passes through.
   scispaCy or a self-hosted clinical NER model is the single highest-value next change.
2. **No k-anonymity / generalization pass.** This is the real answer to the inference risk in
   §3, and it is not built.
3. **Financial transaction dates pass through deliberately.** Amounts and counterparties are
   masked; the dates are not, because `DATE` is scoped to medical documents. That is a
   quasi-identifier residual and a real gap.
4. **Sub-3-character spans are never obfuscated.** They carry no re-identification signal, and
   sweeping them would corrupt unrelated words — but the floor is a policy choice, and it is
   applied uniformly rather than per-entity.
5. **Single-process session registry.** Redis plus KMS envelope keys for multi-node.
6. **The document read path leaks existence through timing** — ~18× between an absent
   `doc_id` and a wrong-owner one on a 2 MB blob. Content-identical, time-distinguishable;
   analysed in §3. A constant-time read closes it and costs a full disk read per miss.
7. **Filenames are cleartext in the metadata table.** Deliberate and argued in §3; the fix, if
   the requirement changes, is an encrypted column plus a blind index for listing.
8. **The audit chain is unkeyed**, so it survives partial tampering but not a full rewrite by
   someone with DB write access (§5 Q5). An off-box append-only sink or an auditor-held HMAC
   key is the real answer; both are production infrastructure rather than a code change here.
9. **The DOCX decompression-bomb guard bounds the declared size, not the transient cost.**
   Checking the archive's declared uncompressed bytes closes the ~1000× amplification a zip
   bomb needs. It does not bound what `zipfile.ZipFile()` itself spends parsing the central
   directory before any check can run: an archive at the 16 MB upload cap can declare **zero**
   uncompressed bytes and still cost ~110 MB RSS, about 7×. Measured and pinned by a test. A
   real fix streams the archive or parses it in a memory-capped subprocess; the shipped guard
   is the cheap 99% and the residual is stated rather than implied.
10. **SQLite write contention stalls every reader on the store**, not just the writer — five
   seconds of it, measured. Analysed in §4; the fix is Postgres and the Protocol seam exists.
11. **A document's two blobs share one AAD** and can be swapped on disk (§3). Integrity only,
   and closing it means deviating from the specified AAD.
12. **Co-reference display enrichment** — a UX feature, per Q2.
13. **`Settings.llm_max_retries` is an *attempt* count, not a retry count.** It is consumed as
   `max(1, min(llm_max_retries, MAX_ATTEMPTS))`, so `1` means one attempt and **no** retry —
   the opposite of what an operator setting "max retries = 1" expects. The behaviour is
   correct and tested; the name is wrong. It is a rename (`llm_max_attempts`) rather than a
   logic change, and it is recorded here rather than quietly renamed because the setting is
   already in `.env.example` and changing it is a breaking config change.
14. **Streaming responses with incremental restore.** Today the full response is restored in
   one pass, so a streaming UI would show tokens before restoration.
15. **OpenTelemetry spans per pipeline stage.** Timings exist in `stats` and the audit log but
   are not exported.
16. **An OpenAI provider class** — one class plus one registry entry, by construction.

---

## 8. Deviations from the build specification

Recorded per the build doc's instruction. Each one is a deliberate choice with a reason.

| # | Deviation | Rationale |
|---|---|---|
| 1 | `SCP_LLM_MODEL` defaults to `claude-opus-5`, not `claude-sonnet-4-6`. The provider sends **no** `temperature`/`top_p`/`top_k` and passes `output_config.effort: "low"`. | The specified model is valid but older. On the current model family those sampling parameters are **removed and return HTTP 400**, so sending them would break the real-provider path outright. Model is env-configurable either way. |
| 2 | Added `pyyaml`, `python-dateutil`, and `python-multipart` to dependencies. | The first two are required by the specified design (the registry is YAML; Tier 2 parses dates with `dateutil`) but absent from the pinned list. Without `python-multipart`, FastAPI raises at **route-registration** time and the container never boots. |
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
| 13 | **The egress gate matches on word boundaries, not raw substrings.** | `"Brown"` is a real original; a generated fake surname `"Browning"` contains it, and a naive `"brown" in payload` reported a leak that was not one. Word-boundary matching also makes the gate agree with the engine's residual sweep about what counts as an occurrence — previously they disagreed, which is exactly how a value could be swept everywhere and still be reported present. **A masking approach was tried first and reverted**: exempting emitted spans from the scan *hid* the genuine `Medina` leak. The exemption belongs upstream in the guard, where it can be made true rather than assumed. |
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
| 34 | **Five of the build doc's own `context:` words are replaced by lemma stems** (`filed`→`file`, `presents`→`present`, `prescribed`→`prescribe`, `takes`→`take`, `routing`→`rout`). | Presidio's context enhancer tests `configured_word in lemma`. `"filed"` is not a substring of the lemma `"file"`, so five of the specification's context words were **inert — no boost, ever**. That boost is what keeps a 0.70 pattern hit ahead of spaCy's flat 0.85, so the inert words were quietly losing overlap resolutions. |
| 35 | **Overlap resolution ranks pattern/gazetteer-backed entities above presidio-backed ones** — below policy actions, above score. | Presidio scores every spaCy guess 0.85 and every registry pattern 0.70, so the *general-purpose guess* took the label off the *specific claim*. Measured consequence: a docket number `24-ARB-00912`, typed as `DATE_TIME`, was being routed through the **Tier-2 date-shift path** — parsed as a date and re-rendered. Coverage is unchanged by construction; only the label moves, and it moves toward the more specific recogniser. |
| 36 | **The diagnosis gazetteer grows from 109 to 208 terms.** | §9.2's stated coverage target is "fixtures plus realistic docs", and common presenting conditions were simply absent. This is the most corpus-fitted change in this group and is flagged as such in §4. |
| 37 | **`TOKEN_RE` bounds every quantifier §9.7 leaves unbounded**: `\s*`→`\s{0,4}`, `[A-Z0-9_]*`→`{0,63}`, the hint suffix→`{1,24}`. | The specified regex is **catastrophically backtrackable**: adjacent unbounded quantifiers around an optional group cost **93 s** on a payload of 128,000 whitespace characters, which is a denial-of-service reachable from an ordinary document upload, and the restorer runs on every response. Bounding fixes it at **9.8 ms** on the same input. (This row previously said "a crafted 500-character input", which was wrong and trivially falsifiable — 500 characters is instant. The cost is quadratic in input length: measured 0.0058 / 0.023 / 0.090 / 0.363 / 1.446 s at 1k / 2k / 4k / 8k / 16k characters, i.e. **exactly 4x per doubling**, which extrapolates to 93 s at 128k. The 93 s and 10 ms figures were both right; the input size was not.) The behavioural cost was measured rather than assumed and is exactly **one** case: more than four whitespace characters inside a token leaves the closing bracket behind (`[PHI_NAME_1a2b3c4d     ]` → `John Smith     ]`). The value still restores, nothing leaks, and no post-restore assertion trips. The other two bounds cost nothing — neither an entity name past 63 characters nor a hint past 24 is emittable, because `format_surrogate` refuses to construct one. |
| 38 | **§10.7's `[PHI_MEDICATION_2f4a|oral-antidiabetic]` (a 4-hex ID) is deliberately *not* restorable.** | The build doc contradicts itself: §8 fixes token IDs at `hexdigest()[:8]`, §9.7's own regex demands `{8}`, and only §10.7's example uses 4. The normative half wins. Widening to `{4,8}` would also widen the **egress gate's skip-list** — the gate skips spans matching the token grammar, so a looser grammar means more of the payload exempted from the re-scan, which is a security cost paid for an example. Pinned in both directions: a 4-hex token is unmatchable by the restorer *and* unissuable via `format_surrogate`, so the two halves cannot drift apart. |
| 39 | **`Restorer.restore` accepts an optional `issued` set; `RestoreResult` gains `fabricated`, `lost` and `surrogate_misses`.** | Without knowing which surrogates were actually issued, every unresolved reference is a single undifferentiated "miss". With it, the restorer distinguishes a token the **model invented** (never issued — a model-behaviour signal) from one that **was** issued and no longer resolves (a vault or session fault). Those are different incidents with different responses, and collapsing them loses the distinction precisely when an operator needs it. The orchestrator passes it, so production misses classify rather than reading as `indeterminate`. |

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

- `obfuscation/strategies/pseudonymization.py` knows five names (`NAME`, `CLIENT_IDENTITY`,
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
| **Core 7** — audit: ts, session, type, token, action; queryable; zero originals | `audit/logger.py`, `models.py::AuditEvent` | `test_audit.py::test_persisted_rows_carry_no_free_text_columns`, `::test_detail_rejects_long_string_values`, `::test_truncating_the_tail_breaks_the_chain`, `::test_deleting_a_middle_row_and_relinking_the_chain_is_still_caught`, `::test_erasing_a_whole_session_is_not_reported_as_that_session_being_clean`; leakage assertion 2 |
| **Critical constraint** — reversible in-session, irreversible across | `crypto/keys.py::derive_token_id` (HMAC under an ephemeral key), key destruction | `test_crypto.py::test_token_id_deterministic_within_session`, `::test_token_id_non_deterministic_across_sessions`, `::test_token_id_is_irreversible_without_the_key`; `integration/test_pipeline.py::test_restoration_is_impossible_after_the_session_is_destroyed` |
| **NFR** — config-only entity add | `entities.yaml`; `entity_type` opaque downstream | `test_extensibility.py::test_package_source_never_mentions_passport` (the grep **is** the proof), plus the three end-to-end cases beside it |
| **NFR** — strategy swappable via config | strategy registry dict, `Settings.strategy` | `test_obfuscation.py::test_dummy_strategy_plugs_in_with_zero_engine_changes`, `::test_per_entity_strategy_override_is_config_only`; `test_llm.py::test_new_provider_name_is_selectable_with_zero_other_changes` |
| **NFR** — zero PII in transit, verifiable by inspection | `pipeline/egress_gate.py` (fail-closed, two passes) | `leakage/test_leakage_harness.py::test_no_original_ever_leaves_the_process` (**100 runs**), `::test_unknown_shape_value_blocks_egress_and_the_call_never_fires`, `::test_the_leak_scan_bites`; the four stated boundaries are pinned by `::test_a_partial_value_leak_is_outside_what_this_harness_claims`, `::test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims`, `::test_a_combining_mark_inside_a_value_is_outside_what_this_harness_claims`; `demo.py --dump-wire` for the literal HTTP body |
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
mypy                 # expect: Success, 39 source files
ruff check .         # expect: All checks passed!
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
