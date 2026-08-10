/* Secure Context Pipeline — demo UI. Vanilla JS, no build step, no network deps.
   Every string that originates from a document, an LLM, or an error body is
   HTML-escaped before it is inserted. Nothing untrusted is ever interpolated raw. */
'use strict';
(() => {
  // `userId` is the owner the LIVE session was created for, captured at create time.
  // Every owner-scoped call about an existing session reads it instead of the input
  // field, because the field can drift from the session and silently did: change it
  // to a second name mid-demo and Destroy addressed a session that user does not own.
  const S = {
    sessionId: null, lastSessionId: null, userId: null,
    docId: null, uploadKey: null, busy: false, verifying: false,
    // Whether "Destroy session" has been armed and is waiting for its confirm. State
    // rather than a read of the DOM for the same reason `armed` below is: two buttons
    // and a live region have to agree, and inferring the answer from one of them is how
    // they stop agreeing. See `setDestroyArmed`.
    destroyArmed: false,
    // WHICH of the two document controls Run will upload, and the single source of
    // truth for it: `null`, `{ kind: 'preset', name }`, or `{ kind: 'file' }`. The
    // state is explicit rather than inferred from "is there a file in the picker",
    // because with two controls that infers wrong in both directions -- a preset
    // armed after a file was chosen would silently lose to the leftover file, and a
    // file chosen after a preset would fight it. Arming either one disarms the other
    // here, in one place, and `paintArmed` prints whatever this says.
    armed: null,
    // Whether the header badge is currently making the claim "the API is unreachable".
    // `markUnreachable` is the only writer that sets it and `health()` the only one
    // that clears it, so the badge and this flag cannot disagree. It exists because
    // that claim used to be permanent: see `noteReachable`.
    unreachable: false,
    // The previous run's own tokens, kept for the vault-miss demonstration. Filled on
    // every successful run from `result.obfuscated_payload`, which is this page's copy
    // of the string the egress gate cleared, so the ids here are exactly the ones this
    // session minted for the document on screen. Null until a run succeeds, which is
    // what `restoreAgain` refuses on. Nothing secret: a token id is the half of the
    // mapping that is safe to show, and panel 2 is already printing all of them.
    lastTokens: null,
    // The fabricated token the NEXT run is carrying, or null. Set by `restoreAgain`
    // and consumed by `run`, so the verdict banner can name it and report what the
    // run actually measured rather than what it intended. Cleared in `run`'s
    // `finally`, so a refused run cannot leave it armed for an unrelated later press.
    missDemo: null,
    // Index of the first EGRESS_BLOCK/VAULT_MISS row in the audit table as currently
    // rendered, or null. Written by `renderAudit` on every render -- including the
    // empty and failed-lookup branches -- and read by the vault-miss demonstration to
    // scroll that row into view. A position rather than an element id; see the note in
    // `renderAudit` for why the id version was wrong.
    hotRowIndex: null,
  };

  const $ = (id) => document.getElementById(id);
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ESC[c]);
  const userId = () => $('user').value.trim() || 'demo-user';
  //: The owner of the session on screen. Falls back to the field only when no
  //: session has been created through this page, i.e. when there is no owner to
  //: have drifted from.
  const sessionOwner = () => S.userId || userId();

  // Emitted surrogate grammar + redaction markers (mirrors surrogates.py).
  // Bounded for the same reason TOLERANT_SRC below is -- and this one was NOT in
  // the audit that found that one; the test asserting the property caught it.
  // It runs over `result.obfuscated_payload`, which is our own output but is
  // assembled from document text, so the run lengths are still an uploader's to
  // choose.
  const MARKS_SRC = '\\[(PII|PHI|LEGAL|FIN)_[A-Z][A-Z0-9_]{0,63}_[0-9a-f]{8}(?:\\|[a-z0-9-]{1,24})?\\]' +
    '|\\[REDACTED_[A-Z][A-Z0-9_]{0,63}\\]';
  // Tolerant matcher (mirrors TOKEN_RE) — LLM output mangles brackets and case.
  //
  // Every quantifier is BOUNDED, and the bounds are the ones surrogates.py calls
  // "a security property, not style" — 4 for stray whitespace, 63 for the entity
  // type body (MAX_ENTITY_TYPE_LEN - 1), 24 for a hint. This comment said it
  // mirrored TOKEN_RE while using `\s*` and `[A-Z0-9_]*`, i.e. the two unbounded
  // spellings that grammar exists to avoid, and it is applied to
  // `result.raw_llm_response` — model output, uncapped. The shipped MockProvider
  // echoes its input, so a document carrying a long whitespace run comes straight
  // back: measured, a 128k-character run froze the tab for 26 seconds. No shipped
  // fixture triggers it (longest whitespace run: 46 characters), which is exactly
  // why it survived.
  const TOLERANT_SRC = '[[{(]?\\s{0,4}(?:PII|PHI|LEGAL|FIN)[_-][A-Z][A-Z0-9_]{0,63}[_-][0-9a-fA-F]{8}' +
    '(?:\\s{0,4}\\|\\s{0,4}[a-z0-9-]{1,24})?\\s{0,4}[\\]})]?';
  const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // Under pseudonymization the surrogate is a realistic fake ("Christina Palmer"),
  // not a bracketed token, so no grammar can find it — but the run tells us exactly
  // which strings it emitted. Longest-first, so a short fake cannot bite a chunk
  // out of a longer one that contains it (same rule as restorer.py).
  function surAlt(dets) {
    const uniq = Array.from(new Set((dets || []).map((d) => d.surrogate).filter(Boolean)));
    uniq.sort((a, b) => b.length - a.length || (a < b ? -1 : 1));
    return uniq.map(reEsc).join('|');
  }
  // The restorer swallows more than the token itself (restorer.py _span_and_suffix):
  // markdown hugging it, a possessive it re-attaches to the value, and a mangled
  // hint tail. Those live at the edges of the literals around a token, so trim them
  // before using a literal as an alignment anchor in panel 4.
  //
  // Both runs are BOUNDED for the same reason the two grammars above are, and this
  // pair was outside what the test asserting that property enumerates -- its finder
  // matches `const <NAME>_SRC = <string>;`, so it could only ever see MARKS_SRC and
  // TOLERANT_SRC. `EDGE_CLOSE` was `[*_`]+$`, unanchored at the start, so on a run of
  // markdown characters that is NOT at the end of the literal the engine restarts a
  // maximal run match at every position inside the run and fails `$` each time.
  // Measured in node against the shipped literal: 100 ms at 8k characters, 398 ms at
  // 16k, 1,609 ms at 32k -- 4x per doubling, i.e. a frozen tab on a 64k run, and it
  // is applied to alignment literals cut out of `raw_llm_response`. No real markdown
  // edge is longer than a few characters; eight makes the scan linear.
  const EDGE_CLOSE = /[*_`]{1,8}$/;
  const EDGE_OPEN = /^(?:['’]s?)?[*_`]{0,8}(?:['’]s?)?/;
  const HINT_TAIL = /^\|[^\]})\n]{0,48}[\]})]/;
  //: The possessive the restorer re-attaches to a substituted piece. See `renderRestored`.
  const POSSESSIVE = /^['’]s?/;

  // ---------- the stats strip: what each counter counts, and which ones matter ----------
  //
  // The strip prints every key `PipelineResult.stats` carries -- 22 of them on a
  // shipped fixture -- and it used to print them in ONE styling with no key at all,
  // ordered timings-first. Measured on fixtures/medical_note.txt, that put
  // `egress_rescan_warnings 3` in the same grey chip as `detect_ms 412.6 ms`, so the
  // page never said which numbers are the security claim and which are stopwatch
  // readings, and a reviewer had no way to know whether 3 warnings beside a green
  // RUN_OK is fine (it is -- see that entry) or the thing to ask about.
  //
  // Three visual states, all built from classes `style.css` already defines: this
  // page's CSP is `style-src 'self'` with no `unsafe-inline`, so a new rule would
  // have to go in the stylesheet, and the same argument the audit heading makes
  // applies -- the change does not own that file.
  //
  //   dim    `stat muted`                  a stage timing. Anything matching /_ms$/.
  //   bright `stat`                        a count of what the run did to the data.
  //   green  `stat badge ok`  / red        a counter whose CLEAN READING IS 0,
  //          `stat badge err`              showing the value it actually reads.
  //
  // `zero: true` marks that third set, and it is deliberately three entries long: a
  // page that paints eight things red has stopped ranking them. The three are the
  // restoration failures -- every other safety counter has a legitimate non-zero
  // value on an ordinary run. `why` is the plain-English meaning, rendered as the
  // chip's `title`; the raw key stays visible because it is the API field name a
  // reviewer greps for. Insertion order here IS print order: safety first, because
  // the safety counters are the reason the strip exists.
  //
  // A key absent from this table still renders -- bright, untitled, appended after
  // the known ones -- so a counter the API adds later is visible rather than
  // silently dropped. That was already true of the flat list this replaces and is
  // pinned by `test_render_stats_uses_the_pipeline_order_and_formats_durations`.
  const STAT_META = {
    // `entities_detected` and panel 1's header count two DIFFERENT sets, and the
    // sets are not nested. See the `c1` assignment in `run` for the measurement.
    //
    // `tag` is the ON-SCREEN half of that, and it is here because the hover was the
    // whole of it: measured on fixtures/medical_note.txt as `medical`, this chip read
    // `entities_detected 54` three lines above a header reading "52 spans masked" on
    // EVERY run, and the only thing on the page reconciling them was a `title` on the
    // other number. A reviewer who reads the strip first sees two disagreeing counts
    // and no reason, and hover is not a thing a reviewer does to a number that looks
    // fine. Four words beside the value say which set it is; the header now prints
    // this number too and says the sets are not nested (`C1_DETECTED`), so whichever
    // one is read first carries the reconciliation without a pointer.
    entities_detected: { tag: 'before policy', why: 'SAFETY. Spans the detector ' +
      'returned over the document text, before any policy ran. The header of panel 1 ' +
      'counts a different set -- the spans this run actually masked -- and neither is ' +
      'a subset of the other. Hover that header for the arithmetic.' },
    prompt_entities_detected: { why: 'SAFETY. Spans the detector returned over the ' +
      'prompt you typed. The prompt is obfuscated on the same path the document is; ' +
      'its spans are absent from panel 1 because their offsets are prompt-space.' },
    // "minted" was wrong on exactly the run the next chip exists to expose. The vault
    // keys a record by (entity type, value) for the LIFE OF THE SESSION and has no
    // strategy dimension, so a second run over the same document can mint nothing and
    // still report the same count -- measured on fixtures/medical_note.txt, two runs
    // in one session: tokens_issued 32 both times, and the second run's payload
    // carries the FIRST run's surrogates (that is the drift `strategyClause` reports).
    // "Draws on" is true either way; the response carries no per-record minted/reused
    // flag, so neither this chip nor the banner may claim one.
    tokens_issued: { why: 'SAFETY. Vault records this run\'s payload draws on -- one ' +
      'per distinct (entity type, value), document and prompt together. Minted by ' +
      'this run, or reused from an earlier call in this session; the response does ' +
      'not say which. Lower than entities_detected whenever a value occurs more than ' +
      'once.' },
    prompt_tokens_issued: { why: 'SAFETY. How many of tokens_issued came from the ' +
      'prompt rather than from the document.' },
    pseudonyms_issued: { why: 'SAFETY. How many of tokens_issued the payload carries ' +
      'as a realistic fake rather than as a bracketed token. Read off the emitted ' +
      'shape, not off the strategy that was asked for.' },
    redactions: { why: 'SAFETY. Spans replaced with [REDACTED_<TYPE>] instead of a ' +
      'restorable token -- registry policy, or a score too low to be worth vaulting. ' +
      'Irreversible by design: these do not come back in panel 4.' },
    stripped: { why: 'SAFETY. Spans deleted from the payload outright. Also ' +
      'irreversible, and also absent from panel 4.' },
    egress_rescan_warnings: { why: 'SAFETY. Entity hits the gate\'s OWN detector ' +
      'found in the outbound payload, outside the spans this run emitted -- ' +
      'typically a pseudonym that reads like a real name. Logged, never blocked: a ' +
      'HIGH-SEVERITY re-hit raises EGRESS_BLOCKED and the payload never reaches the ' +
      'provider, so a non-zero count beside a green RUN_OK is the designed outcome ' +
      'and not a leak.' },
    restored_count: { why: 'SAFETY. Occurrences the restorer put an original value ' +
      'back into. Panel 4 paints exactly these.' },
    vault_misses: { why: 'SAFETY, and 0 is the clean reading. Occurrences replaced ' +
      'with [UNRESOLVED_ENTITY] because the vault could not resolve the token. ' +
      'Non-zero has a row in the audit tail below saying which token.', zero: true },
    unresolved_fabricated: { why: 'SAFETY, and 0 is the clean reading. Distinct ' +
      'token IDs in the response that this session never issued -- the model invented ' +
      'them. Nothing leaked and nothing was lost, but the answer names an entity that ' +
      'does not exist.', zero: true },
    unresolved_lost: { why: 'SAFETY, and 0 is the clean reading. Distinct token IDs ' +
      'this run DID issue that the vault no longer holds. The one counter here that ' +
      'means a value the user was entitled to could not be given back.', zero: true },
    // Not a timing, and deliberately next to the one that is: this is the number the
    // PAYLOAD_TOO_LARGE ceiling compares against, so a run that came close says so on
    // the strip rather than only in the refusal it did not quite trigger.
    payload_chars: { why: 'SAFETY. Characters in the assembled outbound payload -- ' +
      'system prompt, obfuscated prompt and obfuscated document together, exactly ' +
      'the string the egress gate scanned. Past 250,000 the run is refused with ' +
      'PAYLOAD_TOO_LARGE before any model call, because one payload is one call.' },
    fetch_ms: { why: 'TIMING. Reading and decrypting the stored document.' },
    detect_ms: { why: 'TIMING. Detection over the document.' },
    prompt_detect_ms: { why: 'TIMING. Detection over the prompt.' },
    obfuscate_ms: { why: 'TIMING. Vaulting and splicing the document.' },
    prompt_obfuscate_ms: { why: 'TIMING. Vaulting and splicing the prompt.' },
    inject_ms: { why: 'TIMING. Assembling the outbound payload.' },
    egress_ms: { why: 'TIMING. The egress gate\'s three passes over the payload.' },
    llm_ms: { why: 'TIMING. The provider call.' },
    restore_ms: { why: 'TIMING. Substituting originals back into the response.' },
    total_ms: { why: 'TIMING. The whole run, end to end.' },
  };

  // ---------- panel 1's counter, and the number it is NOT ----------
  //
  // Panel 1's header said "52 spans" while the strip three lines above it said
  // `entities_detected 54`, with nothing on the page reconciling them. Both numbers
  // are correct and they count different sets:
  //
  //   entities_detected  = len(detections) in `pipeline/orchestrator.run` -- what the
  //                        DETECTOR returned over the document text, before the
  //                        engine applied any policy. (The prompt's spans are
  //                        reported separately as `prompt_entities_detected`.)
  //   panel 1's count    = len(result.detections), which the orchestrator fills from
  //                        `obf.spans` -- one entry per span the ENGINE acted on, and
  //                        every one of them is a splice into the outbound payload:
  //                        a surrogate (OBFUSCATED), a [REDACTED_<TYPE>] marker
  //                        (REDACTED) or a deletion (STRIPPED). "Masked" is the one
  //                        word true of all three.
  //
  // The tempting label is "52 of 54", and it is false: the sets are not nested in
  // either direction. `ObfuscationEngine._plan` DROPS detections (below the
  // MIN_SWEEP_LEN=3 enforceability floor, scoped out of the document category, out of
  // range, or classified away), and `_sweep_residual` ADDS spans the detector never
  // returned -- occurrences of a value this SESSION vaulted on an earlier call that
  // this call's detector missed.
  //
  // Measured on fixtures/medical_note.txt as `medical`, tokenization: detector 54 ->
  // 3 dropped at the enforceability floor ("MD", "RN", "MD", all typed ADDRESS) -> 51
  // planned -> +1 from the residual sweep ("Larkspur Valley Hospital") -> 52 masked.
  // So 52 excludes 3 of the 54 and includes 1 that is not among them.
  //
  // Both numbers are therefore labelled for what they count and each points at the
  // other, rather than being joined by an arithmetic that does not hold.
  const C1_MASKED = ' spans masked';
  const C1_TITLE = 'The spans this run masked in the outbound payload -- replaced with a ' +
    'surrogate, with a [REDACTED_<TYPE>] marker, or deleted -- which is the set ' +
    'highlighted below. The stats strip\'s entities_detected counts a DIFFERENT set: ' +
    'the spans the detector returned over this document before any policy ran. Neither ' +
    'is a subset of the other -- spans under 3 characters are dropped, and the vault\'s ' +
    'cross-call sweep adds occurrences the detector missed here. Measured on ' +
    'fixtures/medical_note.txt as medical: 54 detected, 3 dropped, 1 swept in, 52 masked.';
  // The half of that reconciliation that is not hover, and the reason it exists: the
  // paragraph above was written, both numbers were labelled, and the sentence joining
  // them was still only reachable by hovering one of them. Two counts that disagree on
  // 100% of runs, three lines apart, with the explanation hidden, is a page inviting
  // the reviewer to decide for themselves which one is the real number.
  //
  // "N of M" stays refused -- 52 excludes 3 of the 54 and includes 1 that is not among
  // them -- so the on-screen wording states the relationship that IS true of the two
  // sets and nothing more. Both operands come out of the same response: `masked` is
  // `result.detections.length`, `detected` is `stats.entities_detected`. Absent from
  // `stats`, nothing is printed: there is no second number to reconcile against, and
  // inventing one is the defect this whole block is about.
  // AND THE CLAUSE IS NOW DERIVED FROM THE TWO NUMBERS RATHER THAN ASSERTED OVER THEM.
  // This printed ", neither set contains the other" unconditionally, on every run, for
  // every pair of counts. That sentence is a statement about set MEMBERSHIP and the
  // only thing this function is given is two integers, so on most runs it was a claim
  // the page could not support -- and on at least one it was visibly unearned. Measured
  // in Chrome on fixtures/legal_brief_large.txt as `legal`, tokenization: panel 1 read
  // "83029 chars · 739 spans masked · detector returned 739, neither set contains the
  // other". At 739/739 a reviewer reads a flat contradiction, and the honest answer is
  // that equal counts say nothing either way -- the sets can still differ (the measured
  // medical_note run drops 3 detections at the enforceability floor and sweeps 1 in, so
  // 54 and 52 differ by more than the arithmetic shows), and they can also coincide.
  //
  // What IS derivable from two counts is exactly one direction, and only when they
  // differ: more masked spans than the detector returned PROVES at least that many
  // masked spans were not detections here, because the surplus has to have come from
  // somewhere -- that is the residual sweep. Fewer proves the mirror fact about
  // detections that never became masks. Equal proves nothing, so it claims nothing and
  // says why. `C1_TITLE` still carries the full reconciliation with the measured
  // numbers; this is the part that must be true on every run without being hovered.
  const C1_DETECTED = (n, masked) => {
    const detected = ' · detector returned ' + n;
    if (masked > n) {
      return detected + ', so at least ' + (masked - n) + ' masked ' +
        (masked - n === 1 ? 'span was' : 'spans were') + ' not among them';
    }
    if (masked < n) {
      return detected + ', so at least ' + (n - masked) + ' of them ' +
        (n - masked === 1 ? 'was' : 'were') + ' not masked';
    }
    return detected + ' — the same count, which does not make them the same spans';
  };

  //: restorer.py's sentinel, verbatim. See the gap handling in `renderRestored`.
  const UNRESOLVED = '[UNRESOLVED_ENTITY]';
  //: The fence context_injector.build assembles the document inside. Spelled as
  //: brackets + label rather than as one tag-shaped literal on purpose: the escaping
  //: audit in tests/test_api_ui_escaping.py treats any string that opens like a tag as
  //: markup this file builds, and one at module scope makes the whole IIFE a markup
  //: body -- i.e. every `return` in the file a markup return.
  const DOC_OPEN = '<' + 'DOCUMENT' + '>';
  //: Rows per audit page. This asked for 200 of a list the API returns ascending by
  //: seq, so it showed the HEAD of a section headed "Audit tail": one run on
  //: legal_brief_large.txt (a preset in this page's own dropdown) emits 347 events and
  //: 147 of them were dropped in silence, EGRESS_PASS, LLM_CALL and DEOBFUSCATE among
  //: them. 1,000 is `api/constants.MAX_AUDIT_PAGE`, the largest page the endpoint will
  //: serve, and it covers that run whole; `loadAudit` says so on screen if it ever
  //: fills, because beyond it the same silence returns.
  const AUDIT_LIMIT = 1000;
  //: The event `DELETE /sessions` records its outcome in, and this page's only
  //: evidence that the outcome was an erasure. See `destroyConfirmed`.
  const VAULT_DESTROY = 'VAULT_DESTROY';
  //: Rows the destroy probe asks for. A session id is unique and the route is
  //: idempotent, so there is at most one `api_logout` row; a few more are asked for
  //: because a TTL reap can have written its own `ttl_expiry` row first, and that
  //: one is also a true erasure.
  const DESTROY_PROBE_LIMIT = 8;
  //: The idle body of a panel that holds nothing. Panel 1 says more on the paths
  //: that have something to say; the string is index.html's own placeholder.
  const IDLE = '—';
  const NO_TEXT = 'No text could be extracted from this file. It is most likely a scanned ' +
    'image with no text layer -- OCR is out of scope for this build, so panels 2 to 4 ' +
    'below describe an empty document.';
  const CLEARED = 'cleared — the session key and the vault rows for this run are gone. The ' +
    'audit tail below is what remains, and it is not reversible.';
  //: Panel 1's body on a run this page knows is scoped by a destroyed session. See the
  //: `destroyed` branch in `run` for why the text is not fetched at all. The second
  //: sentence is the honest half: the erasure is of the session key and the token->value
  //: mapping, which is exactly what CLEARED and the VAULT_DESTROYED banner claim and
  //: never more, and a reviewer who notices that the document itself survives should
  //: read that here rather than infer that the page was overstating.
  const ERASED = 'not fetched — this run is scoped by the session you destroyed, so the ' +
    'API refuses it at the session check and this page did not ask for the document text. ' +
    'What the destroy erased is the session key and the vault rows that map a token back ' +
    'to an original value; the encrypted document store is a different store and still ' +
    'holds the file you uploaded, which is why a NEW session can read it again. Press ' +
    '"Create session", then Run.';
  const NEXT_STEP = 'Session created. Choose a demo document or your own file, then press Run.';

  //: `only_in_doc_categories`, mirrored out of entities.yaml, so a run can name the
  //: rule sets it did NOT use. It is a mirror rather than a fetch because nothing
  //: serves the registry: `_mount_ui` mounts this directory alone (`GET /entities.yaml`
  //: is 404) and no endpoint returns the mapping. Drift is caught in the test instead
  //: of at load -- tests/test_ui_behaviour.py's registry test loads the real
  //: entities.yaml through `load_registry` and compares it against this object
  //: evaluated in node, so rescoping an entity or adding a scoped one fails there
  //: rather than leaving the note below quietly wrong.
  const SCOPED_RULES = {
    AMOUNT: ['financial'],
    CASE_STRATEGY: ['legal'],
    CLIENT_IDENTITY: ['legal'],
    DATE: ['medical'],
  };

  // ---------- transport ----------
  //
  // How long this page waits for a reply before it gives up and hands the controls
  // back. There was no deadline at all, and `setBusy(true)` disables Run, Destroy,
  // Create session, the file picker and both <select>s for the whole of a request:
  // a reply that never arrives -- the API killed mid-run, a proxy holding the socket
  // open, a laptop suspended between the send and the answer -- therefore locked the
  // page permanently. Reproduced in the node harness against a fetch that never
  // settles: `btn-run`, `btn-destroy`, `btn-session`, `#file`, `#category` and
  // `#strategy` all read disabled, `#spin` is visible, `#banner` is empty, and
  // nothing short of a reload recovers it.
  //
  // Two budgets, because the calls are not the same size:
  //
  //   slow  the two POSTs that do server-side work. `/pipeline/run` may legitimately
  //         spend `llm_timeout_s` (config.py: 60 s) on each of `MAX_ATTEMPTS`
  //         (anthropic_provider.py: 3) provider attempts plus two backoff sleeps
  //         capped at `MAX_BACKOFF_S` (10 s) -- 200 s of ceiling before detection,
  //         obfuscation and the gate's three passes are counted -- and `/documents`
  //         parses a PDF or expands a .docx inside the request. 240 s clears that
  //         ceiling; anything under it would abort runs the server was going to
  //         answer, which is a worse failure than the one being fixed.
  //   fast  everything else: a session mint, a delete, an audit page, two badges.
  //
  // A plain object rather than two `const`s so the node harness can shorten them;
  // nothing on the page writes it.
  const TIMEOUT = { fast: 30000, slow: 240000 };

  //: The error `api` throws when its budget runs out. Its own code rather than the
  //: engine's AbortError, whose message differs per browser and reads as a bug.
  function timedOut(budget) {
    const late = new Error('timeout');
    late.code = 'REQUEST_TIMEOUT';
    late.detail = 'No reply from the API in ' + Math.round(budget / 1000) +
      ' seconds, so this page stopped waiting and gave the controls back. The request ' +
      'may still be running on the server -- reload the audit tail before assuming it ' +
      'did not happen.';
    return late;
  }

  async function api(method, path, opts) {
    const o = opts || {};
    const init = { method, headers: {} };
    if (o.json) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(o.json); }
    if (o.form) { init.body = o.form; }
    // AbortController, and the deadline covers reading the BODY as well as getting
    // the headers: a proxy that sends a 200 and then stalls mid-stream hangs
    // `res.json()` exactly as long as it would have hung `fetch`.
    const budget = o.slow ? TIMEOUT.slow : TIMEOUT.fast;
    const ctrl = new AbortController();
    let expired = false;
    const timer = setTimeout(() => { expired = true; ctrl.abort(); }, budget);
    init.signal = ctrl.signal;
    try {
      return await send(path, init, budget, () => expired);
    } finally {
      clearTimeout(timer);
    }
  }

  //: The request itself. Split out only so the `clearTimeout` above can be a
  //: `finally` over every exit -- the two throws below and the two returns.
  async function send(path, init, budget, isExpired) {
    let res;
    try {
      res = await fetch(path, init);
    } catch (err) {
      // An abort arrives here as the same rejection a dead connection does, so the
      // deadline flag -- not the exception -- is what tells the two apart.
      if (isExpired()) throw timedOut(budget);
      // `fetch` REJECTS -- connection refused, DNS, CORS, abort -- with a native
      // TypeError carrying neither `.code` nor `.detail`, and showError's
      // `JSON.stringify(e.detail || {})` turned that into the banner "ERROR {}", the
      // literal empty object as the entire user-facing message. The same banner
      // appeared for an unparseable body and for any exception thrown inside the
      // render path, so the three were indistinguishable. `health()` already reports
      // this exact failure as "health: unreachable": the two halves of the UI
      // disagreed about how to report the same thing.
      const dead = new Error('network');
      dead.code = 'NETWORK_UNREACHABLE';
      dead.detail = 'Could not reach the API on this origin (' +
        String((err && err.message) || err) + '). Is the server still running?';
      throw dead;
    }
    // A reply arrived, so the process this page has been calling dead is answering.
    // Placed HERE -- above the status checks, not on the `return body` at the bottom --
    // deliberately: the claim the badge makes is about reachability, and a 401, a 422 or
    // a 429 is as complete a refutation of "unreachable" as a 200 is. Hanging the
    // recovery off the success path alone would leave the header asserting the API was
    // down while it was busy correctly refusing something. See `noteReachable`.
    noteReachable();
    if (res.status === 204) return null;
    const ct = res.headers.get('content-type') || '';
    let body;
    try {
      body = ct.indexOf('json') >= 0 ? await res.json() : await res.text();
    } catch (err) {
      if (isExpired()) throw timedOut(budget);
      // A body that declares JSON and does not parse -- a proxy's error page under
      // the wrong content-type, a truncated response -- threw a SyntaxError out of
      // here and landed in the same content-free banner.
      const unreadable = new Error('unreadable body');
      unreadable.status = res.status;
      unreadable.code = 'BAD_RESPONSE';
      unreadable.detail = 'The server answered ' + res.status +
        ' with a body this page could not read.';
      throw unreadable;
    }
    if (!res.ok) {
      const err = new Error('request failed');
      err.status = res.status;
      err.code = (body && body.code) || ('HTTP_' + res.status);
      err.detail = (body && body.detail) || body;
      throw err;
    }
    return body;
  }

  // ---------- rendering ----------
  function banner(kind, code, msg) {
    const el = $('banner');
    el.className = 'banner ' + kind;
    el.innerHTML = '<b>' + esc(code) + '</b> ' + esc(msg);
    el.hidden = false;
  }
  const clearBanner = () => { $('banner').hidden = true; };

  // The header badge is this page's standing answer to "is the API up", and it was
  // written exactly once, by `health()` at load. After that it never moved: kill the
  // server mid-demo and every action banners NETWORK_UNREACHABLE while the header
  // still reads a green "ok · mock/claude-... · en_core_web_lg", describing a process
  // that is gone. That is the same complaint `api`'s network branch was written to
  // fix -- the two halves of the UI reporting one fact differently -- so the branch
  // now moves the badge too. It is also the class fix: `health()`'s own catch set the
  // text and left `class="badge muted"`, so the one badge that says the API is down
  // was dim grey, indistinguishable from the "health: …" it starts as.
  function markUnreachable() {
    const el = $('health');
    el.className = 'badge err';
    el.textContent = 'health: unreachable';
    S.unreachable = true;
  }

  // The other direction, which did not exist. The badge above was a ONE-WAY latch: the
  // fix that made a network failure move it (see `markUnreachable`) had no counterpart
  // for the recovery, so a server that came back left the header permanently asserting
  // that it was down. That is the same defect the original one was -- the two halves of
  // the UI reporting one fact differently -- pointing the other way, and it is the worse
  // half on a demo: the recovery is the moment a reviewer is deciding whether the
  // failure they just watched was the pipeline's or the laptop's. Reproduced in Chrome
  // against 127.0.0.1:8099: stop the container, press Run, badge reads `health:
  // unreachable` / `badge err`; start it again and press Create session, which answers
  // 200 and mints a session the badge is standing beside -- and the badge still reads
  // `health: unreachable`. Only a reload cleared it.
  //
  // Called from the ONE place every reply passes through, so no future call site can
  // forget it, and it costs a boolean test on the happy path. The re-poll is a real
  // `GET /health` rather than a local repaint, because the badge does not say "a
  // request succeeded", it names the provider, the model and the spaCy model, and only
  // the endpoint knows those. The flag is cleared BEFORE the call: `health()` goes
  // through `api()` too, so clearing it afterwards would make its own success re-enter
  // here and poll again, forever. A `health()` that fails re-sets the flag through its
  // own catch, which is the correct answer -- the API went away again between the two
  // requests.
  function noteReachable() {
    if (!S.unreachable) return;
    S.unreachable = false;
    void health();
  }

  // The `detail` half of a banner. Two things it must not do. It must not print the
  // literal "{}" as the whole message: `JSON.stringify(undefined || {})` is exactly
  // what a native error produced, so "ERROR {}" was this UI's report for the API
  // being down. And it must not print `session_id`, which is not diagnostic and is
  // half of the credential pair that reads the original document and erases the
  // vault -- loadAudit's comment below has the other half. Returns '' when there is
  // nothing left worth showing, so the prose branches read as sentences.
  function detailText(e) {
    if (typeof e.detail === 'string') return e.detail;
    const shown = {};
    let n = 0;
    for (const k of Object.keys(e.detail || {})) {
      if (k === 'session_id') continue;
      shown[k] = e.detail[k];
      n += 1;
    }
    if (n) return JSON.stringify(shown);
    // A native error carries a message and nothing else, and that message is then
    // the only diagnostic there is.
    return e.detail ? '' : String(e.message || '');
  }

  //: A byte count from an error detail as MB, one decimal. Used only on the two
  //: ceilings whose detail always carries the number, and never called without
  //: `typeof n === 'number'` first -- "undefined MB" in a banner would be a worse
  //: message than the blob this table replaces.
  const mb = (n) => Math.round((n / 1048576) * 10) / 10 + ' MB';

  //: The parenthetical the two size refusals share: the ceiling that fired and the
  //: size that hit it, whichever of the two the body actually carried. Empty when
  //: it carried neither, so the sentence in front of it still ends in a full stop.
  function sizePhrase(d) {
    const parts = [];
    if (typeof d.max_bytes === 'number') parts.push('the ceiling is ' + mb(d.max_bytes));
    if (typeof d.bytes === 'number') parts.push('this one is ' + mb(d.bytes));
    return parts.length ? ' (' + parts.join(', ') + ')' : '';
  }

  //: The ceiling behind each field a 422 can name, keyed by the dotted location
  //: FastAPI reports in `detail.fields`. The API's VALIDATION_ERROR detail carries
  //: the field names and an error count and NEVER the limit -- see
  //: `api/errors.py::_validation_handler`, which reduces the body to
  //: `{errors, fields}` precisely so no caller input is echoed -- so the number has
  //: to live on this side. It is a mirror, and a mirror can drift: the numbers here
  //: are `MAX_ID_LEN` (64), `MAX_PROMPT_CHARS` (8000) from `api/schemas.py` and
  //: `MAX_AUDIT_PAGE` (1000) from `api/constants.py`, and
  //: `tests/test_ui_behaviour.py` imports those three constants and asserts each
  //: one appears in the banner this map produces -- the same arrangement
  //: SCOPED_RULES has with entities.yaml, so a ceiling moved in Python fails there
  //: rather than leaving this sentence quietly wrong.
  const FIELD_LIMITS = {
    'body.user_id': 'user_id must be 1 to 64 characters.',
    'body.doc_id': 'doc_id must be 1 to 64 characters.',
    'body.session_id': 'session_id must be at most 64 characters.',
    'body.prompt': 'The prompt box must hold 1 to 8000 characters.',
    'query.limit': 'The audit page size must be 1 to 1000 rows.',
    'query.user_id': 'user_id must be 1 to 64 characters.',
  };

  //: `body.prompt` -> `prompt`. The dotted half is FastAPI's location, not a name
  //: a reviewer can look for on the page.
  const shortField = (f) => f.slice(f.lastIndexOf('.') + 1);

  // ---------- the code-to-sentence table ----------
  //
  // Every code this API can emit, mapped to a sentence that names the control or
  // the input and says what to do next. Before this table `showError` fell through
  // to `detailText` for everything but the three below, so a rejected upload read
  //
  //   UNPROCESSABLE_DOCUMENT {"reason":"unsupported_document_type","suffix":".xyz",
  //   "detected":"unknown"}
  //
  // -- accurate, machine-shaped, and silent about which of this page's controls to
  // touch. Where the detail carries a number that IS the answer (a byte ceiling, a
  // page count, a retry delay) the number is folded into the sentence and the map
  // is then dropped: a sentence followed by the blob it paraphrases is still a blob.
  //
  // The keys were read off the API rather than invented -- the `ApiError` sites in
  // `api/deps.py`, `api/routes/documents.py` and `api/routes/audit.py`, the two
  // `_send_*` writers in `api/middleware.py`, the handlers in `api/errors.py`, and
  // the `code` class attribute of every `PipelineError`/`LLMError` subclass.
  // `INTERNAL_ERROR` is deliberately NOT here: nothing raises it. The 500 handler
  // answers with the exception's own code, which for the base class is
  // `PIPELINE_ERROR`, and a sentence for a code the API cannot emit is dead prose
  // that reads like coverage.
  //
  // Each entry takes `(d, detail)`: `d` is the detail map, normalised to `{}` when
  // the body carried a bare string, and `detail` is `detailText`'s rendering for
  // the entries that still want it appended.
  const SENTENCES = {
    // Both of the gate's exits arrive under this one code, and they are not the
    // same claim. A deliberate block (vault_original / detector_rescan /
    // independent_pattern) is the control catching a leak -- the strongest thing
    // this product says about itself. The fail-safe wrapper in EgressGate.check
    // turns any internal exception into reason "gate_exception", hit_count 0: the
    // control fell over and blocked by default, having caught nothing. The UI said
    // the first sentence for both, with the distinguishing field visible only
    // inside the JSON tail. The tail stays on this one code: `reason` and
    // `hit_count` are the demo's evidence that the block happened.
    EGRESS_BLOCKED: (d, detail) => (d.reason === 'gate_exception'
      ? 'The egress gate FAILED INTERNALLY and blocked by default. Nothing was sent -- and ' +
        'nothing was caught either: this is a gate error, not a caught leak. '
      : 'FAIL-CLOSED: the egress gate refused to release the payload. ' +
        'No provider call was made. ') + detail,

    // The other refusal on the run path, and the one that is NOT about a leak. It is
    // kept off the EGRESS_BLOCKED code deliberately: that code's sentence, and the
    // weight the README puts on it, is "the control caught something", and a document
    // that is merely long has been caught at nothing. Both numbers are stated rather
    // than left in the map because "too large" without them is unactionable and
    // "812004 against 250000" tells the reviewer to split the file in four.
    PAYLOAD_TOO_LARGE: (d) => 'That document assembles into an outbound payload larger than ' +
      'one model call can carry' +
      (typeof d.payload_chars === 'number' && typeof d.limit_chars === 'number'
        ? ' (' + d.payload_chars + ' characters against a ceiling of ' + d.limit_chars + ')'
        : '') +
      '. Nothing was sent, and the egress gate did not run: the payload was refused ' +
      'before either. Split the document and upload each part with the file picker, ' +
      'then run them one at a time in the same session.',

    // The middle sentence exists because this one and the cold-start badge read as
    // opposites. The badge says a session is created for you; this says go and press a
    // button. Both describe the same rule and neither stated it: `run` mints only when
    // `!S.sessionId && !S.lastSessionId`, i.e. only when this page has never held a
    // session. Every state that can produce a SESSION_EXPIRED is outside that -- after a
    // proved destroy `lastSessionId` is kept ON PURPOSE so the run goes to the API and
    // the 401 is the API's (that is the whole live-review sequence), and after a TTL
    // lapse `S.sessionId` is still set, so Run re-sends the id that just expired. In
    // both, pressing Run again gets this same banner and nothing else, which is what
    // made "then re-run" read as advice that does not work. Verified against the live
    // API at 127.0.0.1:8073: destroy, then two further presses of Run, and both answered
    // 401 SESSION_EXPIRED with no POST /sessions in between.
    SESSION_EXPIRED: () =>
      'Session key is gone — the vault cannot be read, so nothing can be obfuscated or restored. ' +
      'Run will not mint a replacement from here: it creates a session only when this page has ' +
      'never had one, so that a refusal like this one comes from the API rather than from the ' +
      'page. Press "Create session" for a new one, then re-run.',

    // Every route here is anonymous, so the meters are per source address:
    // a shared address can spend a budget this browser never touched.
    // The third meter is the one this page is most likely to trip: the chain walk
    // behind Verify chain is priced in ROWS (audit.py: 5,000 rows per token, burst
    // 24), and it is charged on success, so five clicks in a row on a large log
    // spend the bucket. The sentence named the two meters that had not fired.
    // The delay is the whole content of this detail, so it is stated rather than
    // dumped: `{"retry_after_seconds":3}` and "wait 3 seconds" are the same fact.
    RATE_LIMITED: (d) => 'Throttled — too many requests from this address. Durable writes, ' +
      'failed audit-scope lookups, and the chain walk behind Verify chain (priced per row ' +
      'of the log) are each metered per caller. ' +
      (typeof d.retry_after_seconds === 'number'
        ? 'Wait ' + d.retry_after_seconds + ' seconds and retry.'
        : 'Wait and retry.'),

    // ---- upload path: the file picker is the control in every one of these ----
    UPLOAD_TOO_LARGE: (d) => 'That document is larger than this server accepts' + sizePhrase(d) +
      '. Choose a smaller file with the file picker — fixtures/ has documents that fit.',

    // Counted by the ASGI middleware before a handler runs, so it bounds the whole
    // multipart body, not the file alone -- a file just under the upload ceiling
    // can still trip it once the framing and the two form fields are added.
    REQUEST_TOO_LARGE: (d) => 'The request was refused before it was read: it is larger than ' +
      'this server accepts' + sizePhrase(d) + '. The ceiling counts the multipart framing ' +
      'and the form fields as well as the file. Choose a smaller file with the file picker.',

    EMPTY_UPLOAD: () => 'The file you chose has no bytes in it. Choose a document with text ' +
      'in it with the file picker (fixtures/ has one of each supported type).',

    UNPROCESSABLE_DOCUMENT: (d) => {
      if (d.reason === 'unsupported_document_type') {
        return 'This server cannot read that file type' +
          (typeof d.suffix === 'string' && d.suffix ? ' (' + d.suffix + ')' : '') +
          '. Choose a .txt, .md, .pdf or .docx with the file picker.';
      }
      // A scanned PDF with no text layer: every page parsed and every page was
      // empty. The page count is the one number that tells a reviewer the file was
      // read at all, so it is stated rather than left in the map.
      if (d.reason === 'pdf_all_pages_failed') {
        return 'The PDF was opened but all ' + (typeof d.pages === 'number' ? d.pages + ' ' : '') +
          'pages came back empty — a scan with no text layer does this, and there is ' +
          'nothing for the detector to run on. Choose a text-bearing document with the ' +
          'file picker.';
      }
      // The zip-bomb guard in store/extraction.py. Both numbers are the answer to
      // "by how much", so both are named.
      if (d.reason === 'docx_expansion_limit') {
        return 'That .docx declares more uncompressed content than this server will expand' +
          (typeof d.uncompressed === 'number' && typeof d.limit === 'number'
            ? ' (' + mb(d.uncompressed) + ' declared, limit ' + mb(d.limit) + ')' : '') +
          '. Choose a smaller document with the file picker.';
      }
      return 'That document could not be parsed' +
        (typeof d.reason === 'string' && d.reason ? ' (' + d.reason + ')' : '') +
        ', so nothing was stored. Choose another file with the file picker.';
    },

    INVALID_DOC_CATEGORY: () => 'The doc_category sent with the upload is not one this build ' +
      'knows. Choose medical, legal, financial or general in the Category dropdown and run ' +
      'again — the category decides which rule sets run.',

    // ---- request shape ----
    VALIDATION_ERROR: (d) => {
      const fields = String(d.fields || '').split(',').filter(Boolean);
      const limits = [];
      for (const f of fields) {
        if (FIELD_LIMITS[f] && limits.indexOf(FIELD_LIMITS[f]) < 0) limits.push(FIELD_LIMITS[f]);
      }
      return 'The API rejected ' +
        (fields.length ? fields.map(shortField).join(', ') : 'a field in this request') +
        '. ' + (limits.length ? limits.join(' ') + ' ' : '') +
        'Correct that input and try again.';
    },

    // Starlette's own HTTPException, re-rendered by `api/errors.py`. On this page
    // the reachable source is python-multipart refusing a malformed or over-long
    // multipart header, which is the upload again.
    BAD_REQUEST: () => 'The server could not parse the request — a malformed or over-long ' +
      'multipart upload is the reachable cause here. Re-choose the file with the file picker ' +
      'and run again.',

    // StoreAuthError and a genuinely absent document answer identically on purpose
    // (build doc section 8), so the sentence has to cover both without guessing.
    NOT_FOUND: () => 'No such document for this user. "Not yours" and "does not exist" answer ' +
      'identically by design, so check the User ID field still matches the session owner, ' +
      'then re-choose the file to upload it again.',

    AUDIT_SCOPE_REQUIRED: () => 'The audit log can only be read for a session or a run, and ' +
      'this page scopes it to the live session. Press "Create session" first.',

    // 503, raised by every AuditLogger entry point that touches a database it cannot
    // read (errors.py::AuditUnavailableError). It arrived with no sentence, so the
    // one code written specifically to replace an unactionable 500 rendered on this
    // page as the bare word AUDIT_UNAVAILABLE followed by its detail map -- which is
    // the shape it exists to remove.
    //
    // The two halves are told apart because they are not the same news, and
    // `operation` is what separates them. Measured against the real API on an
    // audit.db with one 4 KiB page overwritten: POST /sessions and POST /pipeline/run
    // answer `"operation":"emit"` (a WRITE the log refused, which under "no release
    // without a record" refuses the run with it), GET /audit answers `"query"` and
    // GET /audit/verify answers `"length"` (READS, which cost this page its audit
    // tail and its chain badge and no run at all). A reviewer's first question is
    // whether the run happened, and one sentence for both leaves it unanswered.
    //
    // `audit_db` is the file NAME and never the server's path -- audit/logger.py
    // clips it to `.name` on purpose, so the body says "audit.db" and cannot say
    // where -- which is why the "where" is named here as the setting an operator
    // actually turns. `remedy` ("restore it from backup or start a fresh data
    // directory") is folded into the sentence rather than printed after it: a
    // sentence followed by the map it paraphrases is still a blob.
    AUDIT_UNAVAILABLE: (d) => (d.operation === 'emit'
      ? 'The audit log could not be WRITTEN, so the run was refused before anything was ' +
        'released -- no release without a record. '
      : 'The audit log could not be READ, so there is no audit tail to show and the hash ' +
        'chain cannot be walked. No run was affected by this. ') +
      'The database is unreadable' +
      (typeof d.error === 'string' && d.error ? ' (' + d.error + ')' : '') +
      ' and no control on this page can fix it: restore ' +
      (typeof d.audit_db === 'string' && d.audit_db ? d.audit_db : 'audit.db') +
      ' in the API\'s SCP_DATA_DIR from backup, or point SCP_DATA_DIR at a fresh ' +
      'directory, then restart the API.',

    // The audit log's two siblings, and they arrived the same way -- as new
    // `PipelineError` subclasses with no entry here, found by the derived-code test
    // rather than by being remembered. Neither has a handler of its own in
    // api/errors.py, so both fall through to the base `PipelineError` registration
    // and answer 500 CARRYING THEIR OWN CODE, which is what reaches this table.
    //
    // The three remedies are NOT interchangeable and that is the whole reason these
    // are three sentences rather than one shared "a store is unreadable":
    //
    //   audit.db      restore from backup -- the log is append-only and self-checking.
    //   vault.db      do NOT restore. Its rows are bound to session keys that live in
    //                 the API process's SessionRegistry and die with it, so a restored
    //                 file decrypts to nothing (session_vault.py says so at
    //                 UNREADABLE_VAULT_REMEDY). Fresh directory, new session.
    //   documents.db  restore, OR just upload the document again from this page: the
    //                 ciphertext blobs are separate files that a corrupt metadata
    //                 database does not touch.
    //
    // Only the third has an answer a reviewer can act on without leaving the page, so
    // only the third names a control -- the rest say plainly that no control here can
    // fix it, which is the honest form of "what to do next".
    VAULT_UNAVAILABLE: (d) => 'The vault database is unreadable' +
      (typeof d.error === 'string' && d.error ? ' (' + d.error + ')' : '') +
      ', so nothing can be tokenised or restored and the ' +
      (d.operation === 'get_by_token' || d.operation === 'get_by_surrogate'
        ? 'restore was refused' : 'run was refused') +
      '. Restoring ' +
      (typeof d.vault_db === 'string' && d.vault_db ? d.vault_db : 'vault.db') +
      ' from backup will NOT work: its rows are encrypted under session keys that ' +
      'live only in the API process and die with it. Point SCP_DATA_DIR at a fresh ' +
      'directory, restart the API, then press "Create session" and run again.',

    DOCUMENT_STORE_UNAVAILABLE: (d) => 'The document store is unreadable' +
      (typeof d.error === 'string' && d.error ? ' (' + d.error + ')' : '') +
      ', so the document could not be ' +
      (d.operation === 'put' ? 'stored' : 'read') +
      ' and the run was refused. Only the metadata database is affected -- the ' +
      'encrypted document blobs beside it are separate files -- so choose the file ' +
      'again with the file picker to upload it afresh. If that fails too, restore ' +
      (typeof d.store_db === 'string' && d.store_db ? d.store_db : 'documents.db') +
      ' in the API\'s SCP_DATA_DIR from backup.',

    // ---- restore path ----
    VAULT_MISS: () => 'A placeholder in the answer has no vault entry to restore it from, so ' +
      'the response cannot be de-obfuscated. The session was destroyed or expired between the ' +
      'send and the restore. Press "Create session" and run again.',

    CRYPTO_AUTH_FAILED: () => 'A stored blob failed its AES-GCM authentication tag and was ' +
      'refused rather than trusted — that is the tamper check firing, not a decode glitch. ' +
      'Press "Create session" and upload the document again; if it repeats, the store was ' +
      'written under a different master key.',

    // ---- server-side ----
    NOT_READY: () => 'The API is still starting up — the detector and its gazetteers load once ' +
      'at boot. Wait a few seconds and press the button again.',

    CONFIG_ERROR: (d) => 'The server is misconfigured' +
      (typeof d.reason === 'string' && d.reason ? ' (' + d.reason + ')' : '') +
      ' and no control on this page can fix it. Correct the API environment and restart it.',

    DETECTION_ERROR: () => 'Detection failed on this document, so the run stopped before any ' +
      'payload was built — nothing reached the provider. Try another document with the file ' +
      'picker; if every document fails, the server log has the reason.',

    DETECTION_INVARIANT: () => 'The detector broke one of its own invariants (overlapping or ' +
      'out-of-range spans) and refused to continue rather than obfuscate from a span map it ' +
      'does not trust. Nothing reached the provider. Try another document with the file picker.',

    PIPELINE_ERROR: (d) => 'The pipeline stopped on an internal error' +
      (typeof d.reason === 'string' && d.reason ? ' (' + d.reason + ')' : '') +
      '. Run again; if it repeats, the server log carries the traceback.',

    // ---- provider ----
    LLM_ERROR: () => 'The model provider failed. Only the obfuscated payload was ever sent, so ' +
      'nothing original is exposed by this failure. Run again.',

    LLM_REFUSAL: (d) => 'The provider declined the obfuscated prompt' +
      (typeof d.category === 'string' && d.category ? ' (policy category ' + d.category + ')' : '') +
      '. Nothing original left this machine. Reword the prompt and run again.',

    LLM_TRANSPORT_ERROR: (d) => 'The provider call failed' +
      (typeof d.attempts === 'number' ? ' after ' + d.attempts + ' attempts' : '') +
      (typeof d.reason === 'string' && d.reason ? ' (' + d.reason + ')' : '') +
      '. The pipeline is healthy and the upstream is not: check the API key and network, ' +
      'or set the provider to mock, then run again.',

    LLM_RESPONSE_ERROR: (d) => 'The provider answered but the body carried no usable text' +
      (typeof d.reason === 'string' && d.reason ? ' (' + d.reason + ')' : '') +
      '. Run again; if it repeats, set the provider to mock to keep the demo moving.',
  };

  function showError(e) {
    const detail = detailText(e);
    // A string detail is the shape THIS file throws (NO_FILE, NETWORK_UNREACHABLE);
    // the API's is always a map. Normalising means every entry above can read a
    // field without guarding the container, and a string one still renders through
    // `detail`.
    const d = (e.detail && typeof e.detail === 'object') ? e.detail : {};
    const explain = SENTENCES[e.code];
    // Unknown code -> exactly the rendering that was here before, `detailText` and
    // nothing else. A code this table has never heard of must still reach the
    // screen carrying everything the body had: swallowing it -- or answering with a
    // generic "something went wrong" -- would make the newest failure in the API
    // the quietest one on the page.
    const msg = explain ? explain(d, detail) : detail;
    banner('err', e.code || 'ERROR', String(msg).trim());
    if (e.code === 'NETWORK_UNREACHABLE') markUnreachable();
  }

  // Panel 1: splice detections into the raw text, highest offset first, so the
  // earlier offsets stay valid. Every slice is escaped before it becomes markup.
  function renderOriginal(text, dets) {
    const spans = (dets || [])
      .filter((d) => d.start >= 0 && d.end > d.start && d.end <= text.length)
      .slice()
      .sort((a, b) => b.start - a.start);
    let html = '';
    let cursor = text.length;
    for (const d of spans) {
      if (d.end > cursor) continue; // overlapping span already covered
      const title = d.entity_type + ' · ' + d.action + ' · score ' + Number(d.score).toFixed(2) +
        (d.surrogate ? ' · ' + d.surrogate : '');
      html = '<mark class="c-' + esc(d.category) + '" title="' + esc(title) + '">' +
        esc(text.slice(d.start, d.end)) + '</mark>' +
        esc(text.slice(d.end, cursor)) + html;
      cursor = d.start;
    }
    return esc(text.slice(0, cursor)) + html;
  }

  // ---------- what a mark in panel 2 or 3 says when you hover it ----------
  //
  // Nothing, before these. Panel 1's marks have carried entity type, action, score
  // and the surrogate since the first build, and the two panels that show the
  // SUBSTITUTE carried no `title` at all -- so the only thing telling the three kinds
  // of highlight apart was a colour, and the legend beside it names a CATEGORY, not a
  // kind. Under pseudonymization that is the dangerous direction and panel 3 is where
  // it bites: measured on fixtures/medical_note.txt, "Jamie Cain, MD" is painted PHI
  // green in the provider's-eye view with nothing on the page saying it is an invented
  // value rather than a clinician named in the document. A reviewer's only recourse
  // was diffing panel 3 against panel 1 by eye, which is the manual check the
  // highlighting exists to replace.
  //
  // None of the three names an original value: the whole point is that panels 2 and 3
  // do not hold one. The pseudonym tip names the entity TYPE, which the payload's
  // own bracketed tokens print in clear anyway.
  const TOK_TIP = 'A surrogate token. The original it stands for is in the vault for this ' +
    'session and is not anywhere in this payload; panel 4 puts it back.';
  const RED_TIP = 'A redaction marker. The value was removed rather than tokenised -- ' +
    'irreversible by design, so it does not come back in panel 4.';
  // "this run minted" is what this said, and it was false on exactly the run where
  // the tooltip matters most. The vault keys a record by (entity type, value) for the
  // life of the session, so a fake can be re-emitted by a later run that did not mint
  // it and could not have -- measured on fixtures/medical_note.txt, a `tokenization`
  // run following a `pseudonymization` one in the same session re-emitted 18 of them.
  // The response carries no per-record minted/reused flag, so the tip says what IS
  // derivable from the mark itself: it is a fake, and it belongs to this session.
  // Same rule as `strategyClause` and the `tokens_issued` chip.
  //: "a" or "an" for the entity type that follows. The tooltip hard-coded "a" and the
  //: entity types are registry constants, so under pseudonymization the page printed
  //: "a ADDRESS", "a AMOUNT" and "a EMAIL" -- measured verbatim off a live
  //: medical_note.txt run, on the surface whose whole job is to tell a reviewer that a
  //: convincing-looking value is a fake. It is decided on the letter rather than by a
  //: table because the types are ASCII upper-case identifiers from entities.yaml, so a
  //: type added later gets the right article without anyone remembering to list it;
  //: the fallback string is lower-case and takes the same test.
  const article = (t) => ('AEIOU'.indexOf(String(t).charAt(0).toUpperCase()) >= 0 ? 'an ' : 'a ');
  const psTip = (t) => {
    const kind = t || 'detected value';
    return 'A PSEUDONYM standing in for ' + article(kind) + kind +
      '. It reads like a real value and is not one -- it was invented in this session ' +
      '(not necessarily by this run: the vault reuses a record for the life of the ' +
      'session) and the original never left the vault.';
  };

  // Panels 2 and 3: highlight surrogates (coloured per category) and [REDACTED_*]
  // markers. `from` is where the scan starts; everything before it is plain text.
  //
  // Panel 2's payload opens with the injected instructions, and those instructions
  // carry a documentation example -- "placeholders like [PHI_NAME_1a2b3c4d]" -- that
  // this grammar cannot tell from a surrogate the run actually minted. It was the
  // FIRST highlight in the panel on every run: measured on medical_note.txt, 53 marks
  // against 52 spans, and 54 with a token-shaped string typed into the prompt box.
  // Neither is backed by a detection, a vault row or an audit token_id, so a reviewer
  // cross-checking panel 2 against panel 1 or the audit tail -- the check the
  // four-panel layout invites -- starts on a token that does not exist. Scanning from
  // the payload's own <DOCUMENT> fence drops both without weakening the grammar.
  // The cost, stated: a surrogate minted for PII typed into the *prompt* is no longer
  // highlighted either. The prompt sits ahead of the fence, it is not in
  // `detections`, and it is where the second false mark came from.
  function renderMarks(text, dets, from) {
    const start = from > 0 ? from : 0;
    const meta = new Map();
    (dets || []).forEach((d) => { if (d.surrogate) meta.set(d.surrogate, d); });
    const alt = surAlt(dets);
    const re = new RegExp(MARKS_SRC + (alt ? '|' + alt : ''), 'g');
    let out = esc(text.slice(0, start));
    let last = start;
    let m;
    re.lastIndex = start;
    while ((m = re.exec(text)) !== null) {
      const hit = meta.get(m[0]);
      const guess = (hit && hit.category) || 'PII';
      const c = m[1] || (m[0].slice(0, 10) === '[REDACTED_' ? 'RED' : guess);
      // `m[1]` is MARKS_SRC's category capture, so it is set only when the bracketed
      // surrogate-token limb matched -- which is exactly the three-way split the
      // tooltip needs, and it is read off the emitted SHAPE rather than off the
      // strategy that was asked for.
      const tipText = m[1] ? TOK_TIP : (c === 'RED' ? RED_TIP : psTip(hit && hit.entity_type));
      out += esc(text.slice(last, m.index));
      out += '<mark class="tok c-' + esc(c) + '" title="' + esc(tipText) +
        '">' + esc(m[0]) + '</mark>';
      last = m.index + m[0].length;
    }
    return out + esc(text.slice(last));
  }

  // Panel 4: restoration is a substitution of token runs inside the raw response,
  // so the literal text between tokens survives verbatim. Anchor on those literals
  // and everything in between is a restored region. Bail out to plain text if the
  // alignment ever fails (the model rewrote a literal) — never guess.
  function renderRestored(raw, restored, dets) {
    const alt = surAlt(dets);
    const re = new RegExp(TOLERANT_SRC + (alt ? '|' + alt : ''), 'g');
    const lits = [];
    let last = 0;
    let m;
    while ((m = re.exec(raw)) !== null) { lits.push(raw.slice(last, m.index)); last = m.index + m[0].length; }
    if (!lits.length) return esc(restored);
    lits.push(raw.slice(last));
    let pos = 0;
    let out = '';
    for (let i = 0; i < lits.length; i++) {
      let lit = lits[i];
      if (i > 0) lit = lit.replace(HINT_TAIL, '').replace(EDGE_OPEN, '');
      if (i < lits.length - 1) lit = lit.replace(EDGE_CLOSE, '');
      let at = pos;
      if (lit !== '') {
        at = restored.indexOf(lit, pos);
        if (at < 0) return esc(restored);
      }
      const gap = restored.slice(pos, at);
      // A gap is the region a token was substituted back into -- except where the
      // substitution FAILED. restorer.py writes the fixed sentinel
      // [UNRESOLVED_ENTITY] for a token id the vault never issued, and it lands in
      // exactly the position a real original would, so the alignment above cannot
      // tell the two apart. Measured on a live run with vault_misses 1: panel 4
      // painted 33 "restored region" marks against stats.restored_count 32, and the
      // 33rd was the one value the run FAILED to restore -- shown in the legend's
      // colour for a value it restored, on the same screen as the VAULT_MISS row the
      // audit table flags red. The sentinel is a fixed literal, so splitting it back
      // out is exact. It is marked as itself and deliberately NOT coloured: a third
      // legend key and its swatch belong in index.html and style.css, which this
      // change does not own.
      if (gap !== '' && i === 0) out += esc(gap);
      if (gap !== '' && i > 0) {
        const parts = gap.split(UNRESOLVED);
        for (let k = 0; k < parts.length; k++) {
          if (k > 0) {
            // restorer.py builds the piece as `UNRESOLVED_ENTITY + possessive`, so a
            // trailing "'s" belongs to the sentinel and not to a restored value. Left
            // outside the mark it was still painted as a restored region, and panel 4
            // still counted one more of them than `stats.restored_count` did.
            const own = (parts[k].match(POSSESSIVE) || [''])[0];
            parts[k] = parts[k].slice(own.length);
            out += '<mark class="tok unres" title="not restored: the vault could not ' +
              'resolve this token. See the VAULT_MISS row in the audit tail.">' +
              esc(UNRESOLVED + own) + '</mark>';
          }
          if (parts[k] !== '') out += '<mark class="rest">' + esc(parts[k]) + '</mark>';
        }
      }
      out += esc(lit);
      pos = at + lit.length;
    }
    return out + esc(restored.slice(pos));
  }

  // Grouping is decided by the key's own suffix rather than by `STAT_META`, so a
  // timing the API adds later reads as a timing even before anyone writes it a
  // meaning. It is the same test the formatter already made.
  const isTiming = (k) => /_ms$/.test(k);

  function renderStats(stats) {
    const keys = Object.keys(STAT_META).filter((k) => k in stats)
      .concat(Object.keys(stats).filter((k) => !(k in STAT_META)));
    $('stats').innerHTML = keys.map((k) => {
      const meta = STAT_META[k];
      const v = Number(stats[k]);
      // `tag` rides with the VALUE and not inside the `<i>`, so the raw API field
      // name stays the whole of the key -- it is what a reviewer greps for and what
      // the strip's key section in index.html indexes by. Only a counter whose bare
      // name misleads about WHICH set it counted carries one; see `entities_detected`.
      const tag = meta && meta.tag ? ' · ' + meta.tag : '';
      const shown = (isTiming(k) ? v.toFixed(1) + ' ms' : String(Math.round(v))) + tag;
      // Timings recede, safety counts stay at full brightness, and the three whose
      // clean reading is 0 carry the verdict colour of the number they are showing.
      // `stat badge ok`/`err` reuse the badge rules `style.css` already ships. The
      // cascade was checked rather than hoped for: `.stat` is declared AFTER `.badge`
      // and both set `border-radius` and `padding` at the same specificity, so the
      // chip keeps its own 4px shape; what the badge contributes is `border-color` and
      // `color` from `.badge.ok`/`.badge.err`, which are (0,2,0) and win, plus a
      // harmless `white-space: nowrap`. See the block above `STAT_META`.
      let cls = 'stat';
      if (isTiming(k)) cls = 'stat muted';
      else if (meta && meta.zero) cls = Math.round(v) === 0 ? 'stat badge ok' : 'stat badge err';
      // Named `tip` and not `title`: `renderOriginal` already has a `title` holding
      // `d.entity_type` and `d.action`, and the escaping audit in
      // tests/test_api_ui_escaping.py resolves an identifier's safety across the whole
      // file rather than per scope -- so reusing the name would import that one's raw
      // terms into this expression and the audit would (correctly) refuse it.
      const tip = meta ? ' title="' + esc(meta.why) + '"' : '';
      return '<span class="' + cls + '"' + tip + '><i>' + esc(k) + '</i>' + esc(shown) +
        '</span>';
    }).join('');
  }

  // ---------- the banner's strategy clause: the REQUEST vs what was emitted ----------
  //
  // The banner printed `result.strategy`, which is what the caller ASKED FOR --
  // `orchestrator.run`'s `chosen`, i.e. the dropdown's value or the server default --
  // and the page presented it, unqualified, as a description of the run. It is not
  // one, and the gap is not theoretical:
  //
  //   The vault keys a record by (entity type, value) for the LIFE OF THE SESSION and
  //   has no strategy dimension. Whichever strategy ran FIRST therefore owns every
  //   surrogate that value gets afterwards. That reuse is deliberate and must not be
  //   "fixed" -- it is what makes a pseudonym minted on run 1 still RESTORE correctly
  //   on run 4 (orchestrator.py `_surrogate_map` and `_pseudonyms_issued`).
  //
  // Measured through the real API on fixtures/medical_note.txt as `medical`, one
  // session, both orders, tokens_issued 32 on all four runs:
  //
  //   A. tokenization first, then pseudonymization selected: banner said
  //      "strategy pseudonymization", pseudonyms_issued 0, panel 2 100% hash tokens
  //      ("Patient name: [PII_NAME_09453c04]"). Understates: harmless, still a lie.
  //   B. pseudonymization first, then TOKENIZATION selected: banner said
  //      "strategy tokenization", pseudonyms_issued 18, and panel 2 read
  //      "Patient name: Steven Lee", "Phone: 468-376-2490",
  //      "romerochristina@example.org", "Note filed 06/07/2024 by physician
  //      Benjamin Hansen, MD".
  //
  // B is the dangerous one and it is dangerous BECAUSE the label is reassuring: a
  // reviewer inspecting panel 2 under the word "tokenization" reads eighteen invented
  // values as this patient's real ones, and the only contradicting signal on the page
  // was a `pseudonyms_issued` chip whose meaning was hover-only.
  //
  // So the clause prints the EFFECTIVE COMPOSITION, derived from the two counters the
  // response already carries -- `tokens_issued` and `pseudonyms_issued`, the second
  // read off the emitted surrogate SHAPE (`orchestrator._is_pseudonym`) rather than
  // off the strategy -- and the requested name is labelled "requested" rather than
  // stated. No new endpoint, no new response field, nothing about what the pipeline
  // emits changes; only what the page says about it.
  //
  // What it deliberately does NOT say: which individual records were minted here and
  // which were reused. The response has no per-record flag, so "14 reused from this
  // session's vault" would be the same class of over-claim one layer down -- a hash
  // token under pseudonymization is also what the CONTENT tier legitimately emits
  // (`PseudonymizationStrategy.make_surrogate`). "Bracketed tokens" is true of both.

  //: What each strategy NAME promises about the shape of the surrogates it emits:
  //: `false` = never a realistic fake (TokenizationStrategy has no tier dispatch and
  //: returns `plain_token` for every entity), `true` = a fake wherever the tier calls
  //: for one. A name that is not in this table gets its composition printed and NO
  //: verdict: `config._BUILTIN_STRATEGIES` is a floor rather than a closed set, a
  //: deployment may register its own, and this page cannot know what that one
  //: promised. Silence there is the honest answer; guessing is the defect.
  const STRATEGY_FAKES = { tokenization: false, pseudonymization: true };

  // Returns `{ text, drift }`. `drift` is the WARN condition -- the request and the
  // emitted composition contradicting each other -- and is asserted only where the
  // contradiction is a fact rather than a suspicion:
  //
  //   tokenization + any fake      contradiction. That strategy cannot mint one, so
  //                                every fake on the wire came from an earlier call.
  //   pseudonymization + no fake   contradiction, with two readings the response
  //                                cannot separate; both are named rather than one
  //                                being chosen.
  //   pseudonymization + a mix     NOT flagged. Mixed is the correct output of an
  //                                ordinary run: the content tier emits a token by
  //                                design, so warning here would fire on runs that
  //                                are working and train the reviewer to skip it --
  //                                the mistake `renderScope` already had to undo.
  //                                The composition is printed either way, which is
  //                                the signal; the colour is reserved for the lie.
  function strategyClause(strategy, stats) {
    const asked = String(strategy || '(unset)');
    const clause = { text: asked + ' requested', drift: false };
    const s = stats || {};
    // Derived from the response or not said at all. A response with neither counter
    // supports no statement about composition, and the bare "X requested" is still
    // true -- it is the unqualified "strategy X" that was not.
    const total = Math.round('tokens_issued' in s ? Number(s.tokens_issued) : NaN);
    const fakes = Math.round('pseudonyms_issued' in s ? Number(s.pseudonyms_issued) : NaN);
    // `fakes > total` cannot happen -- both are counted over the one merged token
    // list -- so a response saying it is one this page cannot describe, not one to
    // paper over with a subtraction that would print a negative count of tokens.
    if (!Number.isFinite(total) || !Number.isFinite(fakes) || total < 0 || fakes < 0 ||
        fakes > total) {
      return clause;
    }
    if (total === 0) {
      clause.text = asked + ' requested · this run vaulted nothing, so the payload ' +
        'carries no surrogates of either kind';
      return clause;
    }
    const tokens = total - fakes;
    const shape = fakes === 0
      ? 'all ' + total + ' surrogates in the payload are bracketed tokens'
      : tokens === 0
        ? 'all ' + total + ' surrogates in the payload are realistic fake values'
        : fakes + ' of the ' + total + ' surrogates in the payload are realistic fake ' +
          'values, ' + tokens + ' are bracketed tokens';
    // Own property only. `result.strategy` is a server-supplied string, and a plain
    // index would resolve "constructor" or "__proto__" to something off
    // `Object.prototype` -- not a verdict either way here, because both branches
    // compare against a literal boolean, but a lookup on untrusted input that can
    // reach the prototype chain at all is the wrong shape to leave in a demo whose
    // subject is untrusted input.
    const promises = Object.prototype.hasOwnProperty.call(STRATEGY_FAKES, asked)
      ? STRATEGY_FAKES[asked] : undefined;
    let why = '';
    if (promises === false && fakes > 0) {
      clause.drift = true;
      why = ' · ' + asked + ' mints no fake values at all, so those ' + fakes + ' came ' +
        'from records an earlier call in THIS session created: the vault keys a record ' +
        'by (entity type, value) for the life of the session and has no strategy ' +
        'dimension. The fakes in panel 2 are invented values, not values taken from ' +
        'this document, and the label above them says ' + asked + '.';
    } else if (promises === true && fakes === 0) {
      clause.drift = true;
      why = ' · not one of them is a fake, which ' + asked + ' alone would not produce. ' +
        'Either an earlier call in THIS session already tokenised every value (the ' +
        'vault keys a record by (entity type, value) for the life of the session and ' +
        'has no strategy dimension), or no detected value falls in a tier this ' +
        'strategy pseudonymises. The response cannot tell those two apart.';
    }
    clause.text = asked + ' requested · ' + shape + why;
    return clause;
  }

  // `note` is a footer row when there are events and the empty-state row when there
  // are none. It exists because this table had exactly two states -- a row per event,
  // or "no events" -- and both of the things it could not say are things a reviewer
  // reads the panel to learn: that the page is showing a truncated list, and that the
  // lookup failed rather than the log being empty.
  function renderAudit(events, note) {
    const body = $('audit-body');
    const rows = events || [];
    if (!rows.length) {
      // The empty and the failed-lookup states have no hot row, and saying so is not
      // tidiness: `loadAudit`'s catch renders through here, so a stale index left
      // behind by the previous render would have the scroll below pointing at the one
      // row this branch does emit -- the muted "could not be loaded" line.
      S.hotRowIndex = null;
      body.innerHTML = '<tr><td colspan="5" class="muted">' + esc(note || 'no events') +
        '</td></tr>';
      return;
    }
    const tail = note ? '<tr><td colspan="5" class="muted">' + esc(note) + '</td></tr>' : '';
    // WHERE the first hot row is, recorded as an INDEX rather than marked with an id.
    // `.hot` already paints EGRESS_BLOCK and VAULT_MISS red, which is useless on a row
    // most of the way down a 260px box that opens at scrollTop 0 -- the complaint the
    // LIVE REVIEW strip makes about VAULT_DESTROY, and the same complaint for the row
    // the vault-miss demonstration exists to show. So something has to scroll to it.
    //
    // The first attempt gave that row `id="audit-hot"` and reached it with
    // `getElementById`, and `test_every_element_the_ui_addresses_exists_in_the_page`
    // correctly reddened: it holds every id app.js addresses against the ids
    // `index.html` DECLARES, and a row minted at runtime declares nothing. That
    // invariant is worth more than the convenience -- it is what catches a typo'd id
    // silently becoming a no-op -- so the position is carried here instead and the
    // lookup below goes through the table's own row list. Null when there is no hot
    // row, and rewritten on every render, so it can never point into a stale table.
    S.hotRowIndex = null;
    body.innerHTML = rows.map((e, i) => {
      const cls = (e.event_type === 'EGRESS_BLOCK' || e.event_type === 'VAULT_MISS') ? ' class="hot"'
        : (e.event_type === 'VAULT_DESTROY' ? ' class="warn-row"' : '');
      if (S.hotRowIndex === null && cls === ' class="hot"') S.hotRowIndex = i;
      return '<tr' + cls + '><td>' + esc(e.seq == null ? '' : e.seq) + '</td><td>' + esc(e.event_type) +
        '</td><td>' + esc(e.entity_type || '') + '</td><td>' + esc(e.token_id || '') +
        '</td><td class="detail">' + esc(JSON.stringify(e.detail || {})) + '</td></tr>';
    }).join('') + tail;
  }

  // The entity types `SCOPED_RULES` restricts away from `cat`, named. Requiring a
  // category closes the UNSET case; it does not close the WRONG one, and the wrong
  // one is the quieter of the two. Measured on fixtures/legal_memo.txt submitted as
  // `medical`: all five CASE_STRATEGY sentences reach the provider verbatim -- "We
  // are prepared to accept a structured payout over thirty-six months." among them --
  // while `entities_detected` reads 38, EXACTLY the count the correct `legal` run
  // reports. Every number on the page rated the weakened run equal or better, and
  // nothing anywhere said which rules had been switched off.
  function scopedOut(cat) {
    return Object.keys(SCOPED_RULES)
      .filter((t) => SCOPED_RULES[t].indexOf(cat) < 0)
      .sort();
  }

  // ---------- the scope note, and when it is a WARNING rather than a fact ----------
  //
  // This fired yellow on every run without exception, and could not do otherwise: every
  // doc_category in entities.yaml leaves at least one `only_in_doc_categories` rule set
  // out, so `scopedOut` is never empty. Measured on the correct pairing --
  // fixtures/medical_note.txt run as `medical`, the demo's own first click -- a yellow
  // caution sat directly under a green RUN_OK saying AMOUNT, CASE_STRATEGY and
  // CLIENT_IDENTITY did not run, which is true and is also the design working. A caution
  // that fires on 100% of passes trains a reviewer to skip it, and it is then unavailable
  // on the run it was written for.
  //
  // What it was written for is the WRONG category, which is a different fact from a
  // scoped one: legal_memo.txt submitted as `medical` walks all five CASE_STRATEGY
  // sentences to the provider while reporting entities_detected 38, the identical number
  // the correct `legal` run reports. So the note keeps both halves and separates them by
  // what the page can actually PROVE:
  //
  //   warn    The document declares its own category and the run used a different one,
  //           and at least one rule set that the declared category WOULD have run did
  //           not. That is a rule set actually suppressed, and it is the leak above.
  //   note    Everything else the reviewer should still be able to read: which rule sets
  //           this category leaves out. Same words, no alarm colour (`.banner.note`).
  //   hidden  The document declares a category, the run used it, and nothing the
  //           document's own category would have run was left out.
  //
  // `declared` is the demo dropdown's `data-cat` -- the category the bundled document IS
  // -- and it is the only ground truth this page has. A file the reviewer picked
  // themselves has none, so those runs get the neutral note rather than silence: deleting
  // it there would put the measured legal_memo defect back out of sight for exactly the
  // documents the page knows least about.
  function renderScope(cat, declared) {
    const el = $('scope-note');
    const skipped = scopedOut(cat);
    // Empty is unreachable with today's registry -- every category leaves at least one
    // rule set out -- but a registry that scoped nothing must not leave a stale note up.
    if (!skipped.length) { el.hidden = true; return; }
    // The rule sets the document's OWN category would have run and this one did not.
    // Empty when the categories agree, and also when they differ in the harmless
    // direction (a `general` document run as `medical` runs MORE rules, not fewer).
    const suppressed = declared && declared !== cat
      ? skipped.filter((t) => SCOPED_RULES[t].indexOf(declared) >= 0)
      : [];
    if (declared && !suppressed.length) { el.hidden = true; return; }
    // textContent, not innerHTML: nothing here is markup, and the interpolated values
    // (`cat`, `declared`) both come off <select> options this page wrote itself.
    el.className = suppressed.length ? 'banner warn' : 'banner note';
    el.textContent = suppressed.length
      ? 'MIS-CATEGORISED: this document is bundled as doc_category=' + declared +
        ' and you ran it as ' + cat + '. ' + suppressed.join(', ') + ' rules did not run ' +
        'for this document. entities.yaml scopes those entity types to other categories, ' +
        'so any such value in this document was not detected, not tokenised and not ' +
        'vaulted. The stats row cannot show this -- a run under the wrong category can ' +
        'report the same entities_detected as the right one.'
      : 'doc_category=' + cat + ': ' + skipped.join(', ') +
        ' rules did not run for this document. entities.yaml scopes those entity types ' +
        'to other categories, so any such value in this document was not detected, not ' +
        'tokenised and not vaulted. The stats row cannot show this -- a run under the ' +
        'wrong category can report the same entities_detected as the right one.';
    el.hidden = false;
  }

  // Every DOM sink a run fills, blanked in one place. Nothing here was ever cleared,
  // and both halves of that were visible on the demo's own scripted flow. A refused
  // run left panels 2-4, the stats row and the audit-run label showing the PREVIOUS
  // run beside panel 1's NEW document -- so the reviewer's whole visual check, "does
  // the outbound payload contain anything from the original?", was being made across
  // two unrelated documents. And Destroy session cleared nothing at all: the button
  // that exists to demonstrate irreversible erasure left the restored plaintext PHI
  // on screen under a banner saying it was gone.
  function resetRun(note) {
    $('p1').innerHTML = esc(note || IDLE);
    $('p2').innerHTML = esc(IDLE);
    $('p3').innerHTML = esc(IDLE);
    $('p4').innerHTML = esc(IDLE);
    // The title goes with the count. `c1` carries the reconciliation between the two
    // span numbers on the page (`C1_TITLE`), and a tooltip explaining "54 detected,
    // 52 masked" hanging off an empty counter is the previous run still talking.
    ['c1', 'c2', 'c3', 'c4'].forEach((id) => { $(id).textContent = ''; $(id).title = ''; });
    $('stats').innerHTML = '';
    $('audit-run').textContent = '';
    // The scope note describes ONE run's category. Left up, it would sit under the
    // next run's stats naming the previous run's dormant rule sets -- the same
    // cross-run mixture the rest of this function exists to prevent.
    $('scope-note').hidden = true;
  }

  function setBusy(on) {
    S.busy = on;
    $('btn-run').disabled = on;
    // The vault-miss control issues the same run through the same function, so it
    // freezes with Run for the same reasons -- and one more: it REWRITES the prompt
    // box before it starts, and the box is read across the awaits of a request that
    // may already be in flight.
    $('btn-miss').disabled = on;
    $('btn-destroy').disabled = on;
    // The two halves of the destroy gate freeze with the button they replace. Only one
    // of the three is visible at a time, so this is belt and braces -- but the armed
    // pair is the one that erases, and a control that erases must not be live while a
    // request this page has already started is still in flight.
    $('btn-destroy-confirm').disabled = on;
    $('btn-destroy-cancel').disabled = on;
    $('btn-session').disabled = on;
    // The three inputs a run reads AFTER it has started. Only the buttons were
    // disabled, so the file picker stayed live while a request was in flight; its
    // change listener nulls S.docId, and run() re-read that field across an await.
    // Measured: changing the file during the text fetch posts `"doc_id": null` and
    // the banner becomes VALIDATION_ERROR {"errors":1,"fields":"body.doc_id"},
    // naming a field the reviewer never saw.
    $('file').disabled = on;
    // The preset dropdown joined this list when it stopped being a label and started
    // deciding which bytes get uploaded: `ensureDoc` reads `S.armed` across an await
    // (the GET that fetches the fixture), so a preset changed mid-flight would post
    // one document's bytes under the next one's name and category.
    $('fixture').disabled = on;
    $('category').disabled = on;
    $('strategy').disabled = on;
    $('spin').hidden = !on;
  }

  // ---------- actions ----------
  //
  //: How `createSession` was reached. It changes the WORDS on the badge and in the
  //: banner and nothing else: both spellings run one mint -- the same owner capture,
  //: the same POST /sessions, the same replace-and-prove of the session it
  //: supersedes, the same audit read -- because a second minting path would be a
  //: second set of audit events to keep in step, and the audit story is the product.
  //:
  //: A string sentinel rather than a boolean, because `btn-session`'s listener IS
  //: `createSession`, so the first argument an explicit press calls it with is a
  //: click Event. `auto = !!arg` would therefore label every press on the button as
  //: automatic -- and the node harness, which fires with `{}`, would agree with it.
  //: Comparing against a literal makes the Event, the `{}` and a bare
  //: `createSession()` all read as the press they are.
  const MINT_BY_RUN = 'run';

  async function createSession(origin) {
    // THE GATE CLOSES WHEN ITS BUTTON IS PRESSED. `<details>` has no auto-close, and
    // `.guard-body` is `position: absolute` -- it has to be, or opening the gate shoves
    // the controls beside it sideways (style.css says so) -- so an open panel hangs
    // OVER the row below. Measured in Chrome at 1550px with the mint committed:
    // `details.open` true, `.guard-body` at [212,87,330,212], `#strategy` at
    // [373,142,160,27] underneath it, and `document.elementFromPoint(453,155)` -- the
    // select's own centre -- returning `SPAN.hint`. The strategy toggle is the control
    // that decides whether panels 2 and 3 show bracketed tokens or realistic fakes, so
    // a reviewer following the obvious order (mint a session, then switch strategy)
    // clicks a dead control immediately after using this one.
    //
    // First line of the function rather than the last: it is the press that commits,
    // not the outcome, that finishes the gate's job, so a mint that FAILS also hands
    // the controls back instead of leaving the panel over them beside a red banner.
    // Done here rather than in a second listener on the button so that every path
    // which commits a mint closes it -- including the node harness's bare
    // `createSession()`, where the element is a stub and this is a plain assignment.
    $('guard-session').open = false;
    // Whether Run minted this session because there was none. See `run`: the mint is
    // reached through this function precisely so that it is not a second path.
    const auto = origin === MINT_BY_RUN;
    // An armed destroy names the session on screen NOW. Minting replaces that session,
    // so a confirm left standing across the mint would be a live erase button pointing
    // at something the reviewer no longer has.
    setDestroyArmed(false);
    clearBanner();
    setBusy(true);
    try {
      // Read ONCE, and kept. This is the only moment the field and the session are
      // guaranteed to agree: the API records this string as the owner at
      // SESSION_CREATE and checks it on every audit read and on destroy. Re-reading
      // the field later reads whatever the field says now -- see `destroySession`.
      const owner = userId();
      // The session this click replaces, captured with ITS owner and not the field's
      // current contents -- same rule as `destroySession`, and for the same reason.
      const outgoing = S.sessionId;
      const outgoingOwner = sessionOwner();
      const r = await api('POST', '/sessions', { json: { user_id: owner } });
      S.sessionId = r.session_id;
      S.userId = owner;
      // Pressing Create session with one already live used to abandon it in silence:
      // no DELETE was issued, so the previous session key and its vault rows -- the
      // rows that map a token back to an original value -- stayed in the server's
      // process memory until the TTL reaped them, and the page had just thrown the id
      // away (`lastSessionId` is nulled below), so no control on it could ever erase
      // them. Verified in the harness: the second click issued POST /sessions and one
      // audit GET, and nothing else. On a page whose largest red button demonstrates
      // irreversible erasure, the small blue one above it quietly did the opposite.
      //
      // Ordered mint-then-destroy so a failed mint leaves the reviewer the session
      // they already had. The outcome is PROVED, not assumed: DELETE /sessions
      // answers 204 for a session it did not touch, so this makes the same
      // VAULT_DESTROY existed=1 read `destroySession` makes, and the banner below
      // says which of the two answers it got.
      const replaced = outgoing
        ? await replaceSession(outgoing, outgoingOwner)
        : { warn: false, text: '' };
      // The previous session's run is not this session's. Without the reset a fresh
      // session badge sat above the dead session's four panels, stats row, audit rows
      // and `run_id` label, and a reviewer reading the audit table under that badge
      // reasonably takes those events for the session it names. `lastSessionId` goes
      // with them, so the audit scope below cannot fall back to the old session once
      // a live one exists.
      S.lastSessionId = null;
      // With the note, because this is the one reset that happens while the user
      // still has a step to take: index.html's own panel-1 placeholder is an
      // instruction ("choose a document, press Run"), and blanking it to a dash on
      // the click that completes its first clause is a worse page. Not on the
      // automatic mint: there the reviewer has already pressed Run and the run is
      // about to paint the panel, so telling them to press it would be the page
      // narrating a step it is mid-way through.
      resetRun(auto ? null : NEXT_STEP);
      const when = new Date(r.expires_at * 1000).toLocaleTimeString();
      $('session-badge').className = 'badge ok';
      // The durable half of "where did this session come from". The banner below says
      // it too, but a banner is transient -- the run that minted this session
      // overwrites it with RUN_OK, or with its own refusal, seconds later -- and the
      // badge is this page's standing answer to "is there a session and whose is it".
      // A reviewer looking at a scoped run must never have to wonder whether they
      // created the scope or the page did.
      $('session-badge').textContent = 'session ' + r.session_id.slice(0, 12) + '… · ' +
        (auto ? 'auto-created by Run' : 'created') + ' · expires ' + when;
      banner(replaced.warn ? 'warn' : 'ok', auto ? 'SESSION_AUTOCREATED' : 'SESSION_CREATED',
        (auto ? 'No session was live, so Run created one before starting — same mint as the ' +
          '"Create session" button, same owner, same SESSION_CREATE row in the audit tail ' +
          'below. ' : '') +
        'Session key lives in process memory only.' + replaced.text);
      // Shows the new session's own SESSION_CREATE row, which is both the honest
      // replacement for the rows just cleared and the first evidence of this session.
      await loadAudit();
    } catch (e) { showError(e); } finally { setBusy(false); }
  }

  // Whether the erasure actually happened. `null` when the question could not be
  // asked at all, which is neither a yes nor a no.
  //
  // The 204 from DELETE /sessions is NOT the answer: that route returns 204 for an
  // unknown id, an expired session, an already-destroyed one and *someone else's*
  // alike, deliberately, so that it is not an ownership oracle (see
  // api/routes/sessions.py). It carries no information, and this page was reading it
  // as proof. The route records the outcome in the audit log instead: VAULT_DESTROY
  // carries `existed`, which is 1 only when a live, owned session key was popped and
  // its vault rows dropped. That read is owner-proved against SESSION_CREATE, so a
  // caller who could not destroy the session cannot fake the confirmation either.
  //
  // Its own request rather than the page `loadAudit` renders: that one asks for the
  // first AUDIT_LIMIT events of the whole session and one legal_brief_large run emits
  // 347, so on a session with a few runs behind it the destroy row is off the end of
  // that page. This asks for the one event type.
  async function destroyConfirmed(sessionId, owner) {
    let r;
    try {
      r = await api('GET', '/audit?session_id=' + encodeURIComponent(sessionId) +
        '&user_id=' + encodeURIComponent(owner) +
        '&event_type=' + encodeURIComponent(VAULT_DESTROY) +
        '&limit=' + DESTROY_PROBE_LIMIT);
    } catch (e) {
      return null;
    }
    return (r.events || []).some((e) => e.detail && Number(e.detail.existed) === 1);
  }

  // Erase the session a new one is replacing, and say -- in the words the banner
  // will print -- which of the three things happened. `{ warn }` picks the banner's
  // colour, because two of the three are the reviewer's problem and one is not.
  //
  // Best-effort by construction: the new session already exists by the time this
  // runs, so a failure here must not throw the whole click away. It reports instead.
  async function replaceSession(sessionId, owner) {
    const shown = sessionId.slice(0, 12) + '…';
    let code = null;
    try {
      await api('DELETE', '/sessions/' + encodeURIComponent(sessionId) +
        '?user_id=' + encodeURIComponent(owner));
    } catch (e) {
      code = e.code || 'ERROR';
    }
    if (code) {
      return { warn: true, text: ' The session it replaces (' + shown + ') could not be ' +
        'deleted (' + code + '), so its key and its vault rows are STILL LIVE in the ' +
        'server until the TTL reaps them.' };
    }
    const confirmed = await destroyConfirmed(sessionId, owner);
    if (confirmed === true) {
      return { warn: false, text: ' The session it replaces (' + shown + ') was destroyed ' +
        'first — the audit log records that erasure as existed=1, so its key and vault ' +
        'rows did not outlive it.' };
    }
    return { warn: true, text: ' The session it replaces (' + shown + ') was sent a delete, ' +
      'but the audit read that would prove the erasure ' +
      (confirmed === false ? 'says existed=0' : 'could not be completed') +
      ', and a 204 proves nothing here. Treat that session as STILL LIVE.' };
  }

  // ---------- the destroy gate: two deliberate steps, no modal ----------
  //
  // `btn-destroy` used to BE the destroy: one click, no confirmation, sitting under copy
  // that calls the erasure irreversible and beside the page's primary action. A reviewer
  // exploring the controls -- which is what a 45-minute live review is -- ended their own
  // session, and the recovery is a new session plus a re-run of everything that had been
  // set up. `window.confirm` is the reflex and is refused twice over: it is a modal this
  // page cannot word, style or explain, and the whole of `tests/test_ui_behaviour.py`
  // drives this file under node against a DOM stub with no `confirm`, so the gate would
  // be the one control on the page the suite could not exercise.
  //
  // The arm swaps `btn-destroy` OUT for two buttons that were not under the pointer a
  // moment earlier, so the second click cannot be the first click's momentum. Nothing
  // else changes: `destroySession` below is untouched by the gate and is still what the
  // confirm button calls, so every existing assertion about what a destroy DOES is about
  // the same function.
  const DESTROY_ARMED = 'ARMED. Confirm erases the session key and every vault row that maps ' +
    'a token back to an original value, for this session, with no undo. Cancel leaves it alone.';

  function setDestroyArmed(on) {
    S.destroyArmed = on;
    $('btn-destroy').hidden = on;
    $('btn-destroy-confirm').hidden = !on;
    $('btn-destroy-cancel').hidden = !on;
    $('destroy-state').textContent = on ? DESTROY_ARMED : '';
  }

  //: Step 1. Refuses before arming when there is nothing to destroy, so the two-step
  //: gate cannot ask a reviewer to confirm a no-op.
  function armDestroy() {
    if (S.busy) return;
    if (!S.sessionId) { banner('warn', 'NO_SESSION', 'Nothing to destroy.'); return; }
    setDestroyArmed(true);
  }

  //: Step 2. Disarms FIRST: `destroySession` awaits, and leaving the confirm button up
  //: across those awaits is a second erasure one click away from the first.
  function confirmDestroy() {
    if (S.busy) return;
    setDestroyArmed(false);
    return destroySession();
  }

  async function destroySession() {
    if (!S.sessionId) { banner('warn', 'NO_SESSION', 'Nothing to destroy.'); return; }
    setBusy(true);
    // Both captured before the awaits, and the owner comes from the session rather
    // than from the field. Retyping the field is how a reviewer changes user, and
    // the field is not what the vault is keyed by: with `userId()` here, creating a
    // session as one user and destroying it as another sent a non-owner delete,
    // which is answered 204 and destroys NOTHING, and every line below asserted the
    // erasure anyway. Verified against the live API: the same session then ran again
    // with 200 RUN_OK under a badge reading "session destroyed".
    const sid = S.sessionId;
    const owner = sessionOwner();
    try {
      // user_id is required: logout is owner-scoped, so a session is only
      // destroyed for the user it was created for.
      await api('DELETE', '/sessions/' + encodeURIComponent(sid) +
        '?user_id=' + encodeURIComponent(owner));
      const confirmed = await destroyConfirmed(sid, owner);
      if (confirmed !== true) {
        // Nothing below this point may be said. The session may well still be live,
        // so it stays in `S` -- pressing Run is then the reviewer's own check -- and
        // the panels keep their contents, because wiping the screen is itself a claim
        // that the data is gone. The badge is the one thing that must move: it is the
        // page's standing answer to "is this session alive", it is where the false
        // claim was read, and leaving it alone leaves whatever it happened to say.
        $('session-badge').className = 'badge err';
        $('session-badge').textContent = 'destroy NOT confirmed — session may still be live';
        await loadAudit();
        if (confirmed === false) {
          banner('err', 'DESTROY_NOT_CONFIRMED',
            'Nothing was erased. The API answered 204, but 204 is also what it answers ' +
            'for a session it did not touch -- it is deliberately not an ownership ' +
            'oracle -- and the audit log records this destroy with existed=0. The ' +
            'session was created for "' + owner + '"; it is either owned by someone ' +
            'else or already expired. Treat it as STILL LIVE.');
        } else {
          banner('warn', 'DESTROY_UNCONFIRMED',
            'The DELETE was accepted, but the audit read that would prove the erasure ' +
            'could not be completed, and a 204 on its own proves nothing here. Reload ' +
            'the audit tail and look for VAULT_DESTROY with existed=1 before believing ' +
            'the vault is gone.');
        }
        return;
      }
      // Kept so the audit panel can still be read after destruction. `loadAudit`
      // bails on a null `sessionId`, so nulling this was also what made the audit
      // tail go blank at exactly the moment VAULT_DESTROY lands in it — the one
      // event the destroy button exists to show.
      S.lastSessionId = sid;
      S.sessionId = null;
      $('session-badge').className = 'badge err';
      $('session-badge').textContent = 'session destroyed';
      // Says what the next run actually demonstrates. It used to promise "the
      // second run must fail" as though it showed the vault-miss path (build doc
      // section 9.10) — it does not, and cannot: the request is refused at the
      // session check (401 SESSION_EXPIRED) before the vault is consulted, so no
      // VAULT_MISS is reachable from a destroyed session in this architecture.
      // What it does demonstrate is the erasure itself, which is the stronger
      // property. See README Deviation 56.
      //
      // Still stated at full strength, and now earned: the sentence is printed only
      // on the branch where the log itself says a live, owned session key was popped
      // and its vault rows dropped.
      //
      // "Press Run again: ... SESSION_EXPIRED" is now something the page delivers
      // rather than something it promises. It was written when Run answered a missing
      // session with its own local NO_SESSION banner and no request at all, so this
      // sentence and the LIVE REVIEW strip both named a 401 that never arrived. `run`
      // keeps `lastSessionId` as the scope for exactly this next press -- see the
      // three-state comment there -- so the refusal the reviewer reads is the API's.
      banner('warn', 'VAULT_DESTROYED',
        'Session key and vault rows are gone — irreversibly, and confirmed: the audit ' +
        'log records this destroy as existed=1. Press Run again: the second run is ' +
        'refused with SESSION_EXPIRED before the vault is even consulted. The audit ' +
        'tail below shows VAULT_DESTROY.');
      // The screen has to agree with that banner. It did not: all four panels kept
      // the original document, the outbound payload and the RESTORED plaintext PHI,
      // and the stats row kept the destroyed run's timings, so the one control that
      // demonstrates irreversible erasure visually demonstrated the opposite. The
      // audit tail is deliberately left to be refreshed, not blanked -- it is what
      // the button exists to reveal.
      resetRun(CLEARED);
      await loadAudit();
    } catch (e) { showError(e); } finally { setBusy(false); }
  }

  // The bytes of one shipped demo document, as something FormData can post.
  //
  // `api` rather than a bare `fetch` so this call gets the same deadline, the same
  // NETWORK_UNREACHABLE reporting and the same abort handling as every other request
  // on the page; the route answers `text/plain`, so `api` hands back a string.
  //
  // String -> Blob is a byte-exact round trip here and that is checked rather than
  // assumed: the response declares `charset=utf-8`, `res.text()` decodes UTF-8 and
  // `new Blob([s])` re-encodes UTF-8, which is lossless for any valid UTF-8 -- and
  // the server refuses to serve a fixture that is not valid UTF-8 for exactly this
  // reason (see `_load_shipped_fixtures`). All four shipped documents are pure
  // ASCII, measured; `test_the_endpoint_hands_back_the_shipped_file_byte_for_byte`
  // pins the wire half and
  // `test_a_preset_run_and_a_hand_picked_run_of_one_fixture_detect_identically` pins
  // the stored half.
  //
  // A 404 here means this deployment did not ship `fixtures/`, which is a different
  // failure from "no such document for this user" -- so it gets its own code rather
  // than inheriting NOT_FOUND's sentence, which talks about ownership.
  async function presetBlob(name) {
    let text;
    try {
      text = await api('GET', '/fixtures/' + encodeURIComponent(name));
    } catch (e) {
      if (e && e.status === 404) {
        throw { code: 'PRESET_UNAVAILABLE', detail: 'This server is not serving the bundled ' +
          'demo document "' + name + '". Its fixtures/ directory is missing, so use the file ' +
          'picker with a document of your own.' };
      }
      throw e;
    }
    return new Blob([text], { type: 'text/plain' });
  }

  // Returns the document id rather than only writing it to `S`, so a run can hold
  // its own copy across the awaits that follow.
  async function ensureDoc(uid, cat) {
    // ONE upload path for both controls. The preset does not get a shortcut into the
    // store: it fetches the bytes the server ships and hands them to the same
    // multipart POST /documents the picker feeds, with the same `user_id` and the
    // same `doc_category`, so "chose the preset" and "found the same file on disk"
    // are indistinguishable to everything downstream -- extraction, the category
    // gating in entities.yaml, detection, the gate. A preset that called some
    // server-side "load fixture and store it" route would be a second ingestion path
    // to keep in step, and the demo's whole claim is about what the ONE path does.
    // Pinned end to end by
    // test_a_preset_run_and_a_hand_picked_run_of_one_fixture_detect_identically.
    const armed = S.armed;
    const f = armed && armed.kind === 'file' ? $('file').files[0] : null;
    if (!armed || (armed.kind === 'file' && !f)) {
      throw { code: 'NO_FILE', detail: 'Nothing is armed. Pick a demo document from the ' +
        'dropdown (one click -- it loads the document and sets its doc_category), or ' +
        'choose your own file with the picker beside it.' };
    }
    // doc_category was optional here and defaulted to unset, and unset is not a
    // neutral choice: entities.yaml gates entities behind `only_in_doc_categories`,
    // so it switches whole rule sets off. Measured on fixtures/financial_disclosure.txt
    // with the category left alone -- the natural Choose File, Run path -- a green
    // RUN_OK, entities_detected 26, tokens_issued 19, and panel 2 carrying "Brokerage
    // account [FIN_ACCOUNT_NUMBER_...] at Ridgeline Securities, balance $2,200,613.34."
    // plus every wire date and amount verbatim. Refused here rather than in the
    // markup alone because the <select> is only one of the ways the field can be
    // empty. Ordered after NO_FILE so the two preflights read in the order the
    // controls do.
    if (!cat) {
      throw { code: 'NO_CATEGORY', detail: 'Choose a doc_category first (medical, legal, ' +
        'financial or general) -- it decides which rule sets run, and an uncategorised ' +
        'document is scanned without the category-scoped ones.' };
    }
    // The cache key names the SOURCE as well as the document, so arming the preset for
    // medical_note.txt and then picking a file of your own that happens to be called
    // medical_note.txt cannot be served the previous upload -- a preset has no size and
    // no mtime, so name alone would collide. `arm` nulling `S.docId` covers the same
    // case and this is the second layer, deliberately: measured by deleting each,
    // either one alone still forces the re-upload and only deleting both serves the
    // bundled document under the reviewer's file name. Both are pinned, separately.
    const key = f
      ? 'file:' + f.name + ':' + f.size + ':' + f.lastModified + ':' + cat
      : 'preset:' + armed.name + ':' + cat;
    if (S.docId && S.uploadKey === key) return S.docId;
    const form = new FormData();
    if (f) {
      form.append('file', f, f.name);
    } else {
      form.append('file', await presetBlob(armed.name), armed.name);
    }
    form.append('user_id', uid);
    form.append('doc_category', cat);
    // `slow`: the PDF parse and the .docx expansion happen inside this request, so it
    // is not a transport-latency call and must not be held to the short budget.
    const r = await api('POST', '/documents', { form, slow: true });
    S.docId = r.doc_id;
    S.uploadKey = key;
    return r.doc_id;
  }

  // ---------- the vault-miss demonstration (build doc section 9.10) ----------
  //
  // 9.10 asks for a demo in which "'Destroy session' then 'run restore again'
  // demonstrates the vault-miss path live". The destroy sequence does not and cannot:
  // `/pipeline/run` calls `_require_session` before `services.orchestrator.run`, so a
  // destroyed session is refused 401 SESSION_EXPIRED before the vault is consulted --
  // measured against this build, the scripted three steps write VAULT_DESTROY and
  // exactly ZERO VAULT_MISS rows. It is not a defect one layer down either: `destroy`
  // pops the session KEY first (see `routes/sessions.py`), so `SessionRegistry.key`
  // raises SessionExpired before `SessionVault` is in a position to answer "miss" at
  // all. The erasure is the stronger property and it is what that sequence shows; the
  // vault-miss path needed its own control, and until this one existed the hatched
  // "not restored (vault miss)" key in the legend never fired on any flow this page
  // offers.
  //
  // WHAT THIS IS NOT: a simulation, a mock, or a second code path maintained beside
  // the real one. It presses the same `POST /pipeline/run`, same session, same
  // document, same strategy, same everything, with one sentence appended to the
  // prompt. The sentence carries a token that follows this build's surrogate grammar
  // exactly and whose 8-hex id this session never minted. Downstream, nothing knows
  // this button exists: the mock provider echoes tokens it finds in the payload
  // (`mock_provider.find_tokens`), `restorer._restore_tokens` meets an id outside the
  // run's `issued` set, and everything that follows is the shipped production
  // behaviour for a model that invented a placeholder -- a hash-chained VAULT_MISS row
  // classified `fabricated`, `vault_misses` in the stats strip, and
  // `[UNRESOLVED_ENTITY]` spliced into the answer by `restorer.py`. That is the same
  // path `demo.py` and `test_vault_miss_on_deobfuscation` exercise.
  //
  // WHY THE PAGE AND NOT A MODEL: to show a hallucinated token without a model that
  // hallucinates, something has to stand in for the model. That is the one synthetic
  // step and it is stated in the banner, on the strip, and in the prompt box itself --
  // which is rewritten IN FULL before the run so the reviewer reads the exact string
  // that was sent rather than taking this comment's word for it.
  //
  // WHY NO `POST /pipeline/restore`: it was the first design and it is worse twice
  // over. It would be a third route able to emit decrypted originals, against an
  // invariant `api/constants.py` and `routes/documents.py` both state in those words;
  // and `test_every_mutating_route_is_metered_including_ones_added_later` pins the
  // mutating route set BY VALUE so that adding one is a deliberate act someone
  // notices. Reusing `/pipeline/run` means the reviewer watches the real pipeline.

  //: One emitted token, anchored so a partial match cannot be mistaken for a whole
  //: surrogate. The optional `|hint` suffix is matched so it can be DISCARDED: the
  //: fabricated token is rebuilt from the three captured parts, so it never carries a
  //: hint (a hint welded to a restored value is a separate known wart, and a
  //: demonstration should not arrive wearing one).
  const TOKEN_PARTS = /^\[(PII|PHI|LEGAL|FIN)_([A-Z][A-Z0-9_]{0,63})_([0-9a-f]{8})(?:\|[a-z0-9-]{1,24})?\]$/;

  // The tokens the previous run ACTUALLY MINTED, as `{cat, type, id}`.
  //
  // Read out of `result.detections` -- one entry per span the engine acted on, each
  // carrying the surrogate it emitted -- and NOT by scanning the payload, which is how
  // the first version of this got it wrong in a way the browser caught immediately.
  // `context_injector` opens the payload with instructions that contain a
  // DOCUMENTATION EXAMPLE ("placeholders like [PHI_NAME_1a2b3c4d]"), which matches the
  // token grammar perfectly and is not a token: scanning from offset 0 made that
  // literal the first hit on every run, so the demonstration perturbed a string this
  // session never issued in the first place and the banner's "the same grammar as X
  // from the previous run" named something that was never minted. `renderMarks` was
  // bitten by the identical literal and answers it positionally, by scanning from the
  // <DOCUMENT> fence. This answers it by identity instead, which is stronger: a
  // detection IS the record that the engine masked that span.
  //
  // Membership in the payload past the fence is then required as well, because both
  // facts have to hold for the demonstration to mean anything -- minted (so "one hex
  // digit different from a real token" is true) and present in what the provider was
  // sent (so there is something for it to echo). Under pseudonymization most
  // surrogates are realistic fakes rather than tokens; those fail the grammar and drop
  // out here, which is correct -- a fake has no id to perturb.
  // The accumulator is NOT called `out`, and that is load-bearing rather than taste.
  // `tests/test_api_ui_escaping.py`'s auditor decides whether an identifier is safe to
  // interpolate into markup by looking at EVERY assignment to that NAME across the
  // whole file, not per function. `renderMarks` and `renderRestored` both build their
  // markup in a variable called `out` whose every assignment is an `esc(...)`, which is
  // what makes `return out + esc(...)` legal there. A `const out = []` in this
  // unrelated function is an assignment of a non-literal to that name, so it dropped
  // `out` out of the safe set and reddened the escaping audit on two returns this
  // change never touched. Measured: `return:1009 raw term \`out\`` and `return:1070`.
  // The checker is right to be conservative -- a name-based rule is what survives
  // someone later moving code between these functions -- so the local is renamed.
  function mintedTokens(dets, payload, fence) {
    const from = fence > 0 ? fence : 0;
    const minted = [];
    const byId = {};
    (dets || []).forEach((d) => {
      const surrogate = d && d.surrogate;
      if (!surrogate || Object.prototype.hasOwnProperty.call(byId, surrogate)) return;
      const m = TOKEN_PARTS.exec(surrogate);
      if (!m) return;
      if (payload.indexOf(surrogate, from) < 0) return;
      byId[surrogate] = true;
      minted.push({ cat: m[1], type: m[2], id: m[3] });
    });
    return minted;
  }

  //: The appended sentence, and the matcher that takes it back off. Pressing the
  //: button twice must not stack two of them, and the reviewer's own prompt has to
  //: survive the round trip -- so the augmentation is removable by construction
  //: rather than by remembering what the prompt used to be (which a reload loses).
  const MISS_SENTENCE = (a, b) =>
    ' Also quote, verbatim, the records for ' + a + ' and ' + b + '.';
  const MISS_RE = / Also quote, verbatim, the records for \[[^\]\n]{1,120}\] and \[[^\]\n]{1,120}\]\./g;

  //: HOW MANY fabricated tokens one press sends, and it is 2 for a measured reason
  //: rather than for luck. The mock provider echoes every distinct token it finds in
  //: the payload, but it renders each under a mutation class taken round-robin from
  //: five (`mock_provider.plan_mutations`): possessive, bold, upper-case hash,
  //: BRACKET-DROPPED, and verbatim. One of those five removes the brackets -- and a
  //: bracket-less token whose id the run did not mint is deliberately NOT treated as a
  //: vault miss: `restorer._restore_tokens` leaves it byte-for-byte alone, because
  //: that shape is also what an uploaded document's own reference code looks like
  //: (README Deviation 49). So a single fabricated token demonstrates the path only
  //: four times in five, and which time depends on how many tokens happen to precede
  //: it in the payload. Observed live, twice, on the same document: one press produced
  //: `vault_misses 1`, the next produced 0 and the page correctly reported that it had
  //: NOT demonstrated anything -- honest, and a coin toss to run in front of a
  //: reviewer.
  //:
  //: Two tokens fixes it deterministically rather than probabilistically. They are
  //: appended adjacently, so they take consecutive indices in `find_tokens` order and
  //: therefore consecutive classes out of the cycle; exactly one class in that cycle
  //: drops brackets, so of any two consecutive classes at least one keeps them. At
  //: least one fabricated token therefore always arrives bracketed, which is the shape
  //: the restorer answers with a real vault miss. The banner still reports the
  //: measured `vault_misses` rather than assuming this reasoning holds.
  const MISS_TOKENS = 2;

  //: Ids this session did not issue, derived from one it did. A digit is advanced mod
  //: 16 rather than randomised so a press is reproducible, and every candidate is
  //: checked against the run's OWN id set: flipping into a token that really was
  //: minted would quietly restore a real value, and the demo would show the exact
  //: opposite of what it claims. Every candidate differs from the source in exactly
  //: one hex digit, which is what makes the banner's description of it true. Returns
  //: fewer than asked -- possibly none -- rather than inventing anything; the caller
  //: refuses in that case.
  function unissuedIds(id, taken, want) {
    const found = [];
    for (let i = id.length - 1; i >= 0 && found.length < want; i--) {
      const digit = parseInt(id.charAt(i), 16);
      for (let bump = 1; bump < 16 && found.length < want; bump++) {
        const candidate = id.slice(0, i) + ((digit + bump) % 16).toString(16) + id.slice(i + 1);
        if (taken.indexOf(candidate) < 0 && found.indexOf(candidate) < 0) found.push(candidate);
      }
    }
    return found;
  }

  async function restoreAgain() {
    if (S.busy) return;
    setDestroyArmed(false);
    clearBanner();
    // Three refusals, each naming the control that fixes it. They are local and issue
    // no request on purpose: none of them is a question the server can answer, and a
    // round trip that can only fail is noise in the network panel a reviewer of a
    // security demo has open.
    const tokens = S.lastTokens;
    if (!tokens || !tokens.length) {
      banner('warn', 'NO_PREVIOUS_RUN',
        'There is no run to restore again yet. Press Run first: this control needs the ' +
        'tokens that run minted, so it can build one that looks exactly like them and ' +
        'was never issued. (A run whose payload carried no tokens at all cannot ' +
        'demonstrate a vault miss either -- there would be nothing for the provider to ' +
        'echo back.)');
      return;
    }
    if (!S.sessionId) {
      banner('warn', 'NO_LIVE_SESSION',
        'The vault-miss path needs a LIVE session, and this page does not have one. ' +
        'That is the whole point: a destroyed session is refused at the session check ' +
        'before the vault is ever consulted, which is why "Destroy session then Run" ' +
        'writes VAULT_DESTROY and no VAULT_MISS. Press "Create session", then Run, then ' +
        'this button.');
      return;
    }
    const source = tokens[0];
    const fakeIds = unissuedIds(source.id, tokens.map((t) => t.id), MISS_TOKENS);
    if (fakeIds.length < MISS_TOKENS) {
      banner('warn', 'NO_UNISSUED_ID',
        'Could not derive ' + MISS_TOKENS + ' token ids this session has not already ' +
        'issued from the previous run. Run a different document and try again.');
      return;
    }
    const name = (id) => '[' + source.cat + '_' + source.type + '_' + id + ']';
    const fakes = fakeIds.map(name);
    const real = name(source.id);
    // Written into the box, not held in a variable: the reviewer must be able to read
    // the exact prompt this run sends, and `run` reads the box, so what is on screen
    // and what is sent are the same string by construction rather than by agreement.
    const base = $('prompt').value.replace(MISS_RE, '').trim();
    $('prompt').value = (base + MISS_SENTENCE(fakes[0], fakes[1])).slice(0, 8000);
    S.missDemo = { fakes: fakes, real: real };
    await run();
  }

  async function run() {
    if (S.busy) return;
    // Same reason as in `createSession`: a confirm button left armed while the reviewer
    // has moved on to a run is an erasure one stray click away, and Run is the control
    // right next to it.
    setDestroyArmed(false);
    clearBanner();
    const prompt = $('prompt').value.trim();
    if (!prompt) {
      // The panels are cleared FIRST, which is what the other two preflight refusals
      // already did and this one did not. `resetRun` runs inside the `try` below, so
      // NO_FILE and NO_CATEGORY blank the screen before they banner -- verified in
      // Chrome, both leave all four panels at the placeholder -- while this branch
      // returned above it and left the PREVIOUS run fully rendered. Measured on
      // 127.0.0.1:8099 after a successful medical_note.txt run, emptying the prompt
      // box and pressing Run: a red `NO_PROMPT` banner over panel 1 holding 2 826
      // characters of the document, panel 2 holding 4 262, panel 4 holding 2 278
      // including its `[UNRESOLVED_ENTITY]` mark, the stats strip populated and
      // `#audit-run` still naming the previous run. Every one of those is the earlier
      // run's, under a banner that reads as this click's verdict -- the cross-run
      // mixture the whole of `resetRun` exists to prevent, and the reason its own
      // comment gives for existing.
      resetRun();
      banner('err', 'NO_PROMPT', 'Enter a prompt.');
      return;
    }
    // ---- the session this run is scoped by, and the three states it can be in ----
    //
    // Every step below is scoped by a session, and this page used to make the
    // reviewer go and mint one: no session meant a red NO_SESSION banner saying
    // "Press Create session first". Run is the biggest button on the page and sits
    // inside the red LIVE REVIEW strip; Create session is a small one ten controls
    // above it, so the very first thing a reviewer does -- choose a document, press
    // Run -- was answered by being sent to a different button. (The refusal itself
    // replaced something worse: with no preflight at all the click uploaded the
    // document, painted panel 1, posted `session_id: null`, and the API's 401 became
    // "Session key is gone" -- about a key that was never minted. That failure is
    // still fixed; what changed is that the answer is now to mint one.)
    //
    // NEVER HAD ONE -> mint it here and carry on. Through `createSession`, with no
    // second path: same owner capture, same POST /sessions, same SESSION_CREATE row,
    // same audit read. `MINT_BY_RUN` changes only what the badge and the banner say,
    // and they do say it -- the badge reads "auto-created by Run" for as long as the
    // session lives, and the RUN_OK banner below names it again.
    //
    // DESTROYED ON PURPOSE -> do NOT mint, and do not refuse locally either: run
    // against the dead id and let the SERVER refuse it. This is the scripted LIVE
    // REVIEW sequence (Run, Destroy session, Run), and the strip above the buttons
    // and the destroy banner both promise the same thing -- "the second run is
    // refused with SESSION_EXPIRED before the vault is consulted". Auto-minting here
    // would erase the demonstration; the old local NO_SESSION banner did not erase it
    // but did not show it either, so both notices were promising a 401 the page
    // answered itself, in a different code, without asking the server. Verified
    // against the live API: POST /pipeline/run with a destroyed session_id answers
    // 401 `{"code":"SESSION_EXPIRED"}`, and GET /documents/{id}/text still answers
    // 200 -- the document store is not the vault -- so panel 1 legitimately comes
    // back while panels 2-4 stay empty, which is the erasure, shown.
    //
    // `lastSessionId` is that signal and it is not a new one: `destroySession` sets
    // it ONLY on the branch where the audit log proved the erasure (existed=1), and
    // `createSession` clears it. A separate boolean would be a second field saying
    // the same thing, which is the drift this file keeps being bitten by. Sticky by
    // choice: it stays refusing until the reviewer presses "Create session", which
    // is exactly what the SESSION_EXPIRED sentence tells them to do, and a button
    // that quietly changes behaviour on the second press is worse than one that does
    // not.
    const minted = !S.sessionId && !S.lastSessionId;
    if (minted) {
      await createSession(MINT_BY_RUN);
      // The mint failed -- `createSession` has already banner'd why, and there is no
      // scope to run under. Stop here rather than falling through to a `sid` of null.
      if (!S.sessionId) return;
    }
    setBusy(true);
    // Captured ONCE, for the whole run. These were re-read from `S` and from the DOM
    // after each await, so a control touched mid-request was read by the next step.
    const uid = userId();
    const sid = S.sessionId || S.lastSessionId;
    const strategy = $('strategy').value;
    // Captured here for the same reason `strategy` is, and read twice: once to scope
    // the upload, once to name the rule sets the run did not use.
    const cat = $('category').value;
    // The category the DOCUMENT declares, as opposed to the one the run was given. Only
    // the bundled presets have one; see `renderScope`.
    const declared = S.armed && S.armed.kind === 'preset' ? (S.armed.cat || null) : null;
    // ---- the destroyed-session run does NOT go and fetch the plaintext ----
    //
    // `destroySession` has just printed "Session key and vault rows are gone --
    // irreversibly" and wiped the four panels to say so. Pressing Run again -- step 3 of
    // the LIVE REVIEW sequence printed in red above the button -- then re-fetched
    // `GET /documents/{id}/text`, which still answers 200 because the document store is
    // not the vault, and painted the whole original back into panel 1 BEFORE the API
    // refused the run. Measured on fixtures/medical_note.txt at 127.0.0.1:8073: 2,826
    // characters of cleartext PHI -- "Patient name: David Ochoa", MRN 9224297, the phone
    // number and the e-mail -- sitting under a red SESSION_EXPIRED banner and a badge
    // reading "session destroyed". Nothing there was false; the screen simply said the
    // opposite of the sentence above it, at the one moment the demo is making its
    // strongest claim.
    //
    // So the fetch is skipped rather than the panel blanked after the fact. Blanking
    // would leave the plaintext in the network tab of the devtools a reviewer of a
    // security demo has open, which is the same contradiction one pane further out. The
    // POST to /pipeline/run still happens against the dead id, so the refusal is still
    // the API's -- that is the demonstration and it is untouched.
    const destroyed = !S.sessionId && !!S.lastSessionId;
    try {
      resetRun();
      const docId = await ensureDoc(uid, cat);
      const doc = destroyed
        ? null
        : await api('GET', '/documents/' + encodeURIComponent(docId) +
          '/text?user_id=' + encodeURIComponent(uid));
      // Panel 1 is filled before the pipeline call so a reviewer can see which
      // document is in flight during a run that takes seconds. `resetRun` above has
      // already dropped panels 2-4, so a failure from here on leaves ONE document on
      // screen rather than a mixture of two. The counter says "not yet scanned"
      // because the spans only arrive with the response, and a bare "2826 chars"
      // beside an unhighlighted document reads as "the detector found nothing".
      if (doc) {
        $('p1').innerHTML = doc.chars ? esc(doc.text) : esc(NO_TEXT);
        $('c1').textContent = doc.chars + ' chars · not yet scanned';
      } else {
        $('p1').innerHTML = esc(ERASED);
      }

      const result = await api('POST', '/pipeline/run', {
        // `slow`: the provider call alone is allowed 3 x 60 s plus backoff.
        slow: true,
        json: {
          session_id: sid,
          user_id: uid,
          doc_id: docId,
          prompt: prompt,
          strategy: strategy,
        },
      });

      // Extraction legitimately returns "" for a page with no text layer, and the
      // panel then went blank -- placeholder wiped, nothing in its place -- under a
      // green RUN_OK banner and beside a confident summary of a document that
      // contained nothing.
      //
      // Guarded on `doc` for the branch above: with a destroyed session this page never
      // asked for the text, and a 200 here would mean the session was NOT destroyed
      // after all -- the API refuses that request at `_require_session`. Panel 1 then
      // keeps the erasure statement rather than throwing on a null, and the run's other
      // three panels still render, so a page that was wrong about the session says less
      // rather than crashing.
      if (doc) {
        $('p1').innerHTML = doc.chars ? renderOriginal(doc.text, result.detections) : esc(NO_TEXT);
        // "spans" alone did not say WHICH spans, and it is the number a reviewer
        // compares against `entities_detected` in the strip above. See `C1_TITLE`.
        // The comparison itself is printed here too, rather than left in the tooltip:
        // the two counts disagree on every run, and a reconciliation nobody hovers is
        // not on the page. See `C1_DETECTED` -- and it is omitted, not faked, when the
        // response did not carry the other number.
        const st = result.stats || {};
        const detected = Math.round('entities_detected' in st ? Number(st.entities_detected) : NaN);
        const masked = (result.detections || []).length;
        $('c1').textContent = doc.chars + ' chars · ' + masked +
          C1_MASKED +
          (Number.isFinite(detected) && detected >= 0 ? C1_DETECTED(detected, masked) : '');
        $('c1').title = C1_TITLE;
      }
      const fence = result.obfuscated_payload.indexOf(DOC_OPEN);
      // The tokens this run minted, kept for `restoreAgain`. See `mintedTokens` for
      // why this is read off the detections and cross-checked against the payload past
      // the fence rather than scanned out of the payload. Set on every successful run,
      // including one that IS a vault-miss run, so a second press perturbs a token of
      // the latest run rather than a stale one.
      S.lastTokens = mintedTokens(result.detections, result.obfuscated_payload, fence);
      $('p2').innerHTML = renderMarks(result.obfuscated_payload, result.detections, fence);
      $('c2').textContent = result.obfuscated_payload.length + ' chars';
      // Panel 3 is the provider's-eye view and was the one panel rendered with no
      // highlighting at all. Under pseudonymization that is the dangerous direction:
      // the outbound fakes ("Jamie Cain, MD") read to a reviewer as genuine clinical
      // prose, and the only way to tell a fake from an original was to diff panel 3
      // against panel 1 by eye. renderMarks already finds both forms -- the bracketed
      // grammar and the run's own emitted pseudonyms -- and was simply never called
      // on this string.
      $('p3').innerHTML = renderMarks(result.raw_llm_response, result.detections, 0);
      $('c3').textContent = result.raw_llm_response.length + ' chars';
      $('p4').innerHTML = renderRestored(result.raw_llm_response, result.restored_text, result.detections);
      $('c4').textContent = result.restored_text.length + ' chars';
      renderStats(result.stats || {});
      renderScope(cat, declared);
      // The strategy half is `strategyClause`: the composition the run EMITTED, not
      // the literal it was asked for. The code keeps its `RUN_OK` prefix on both
      // branches because the run did succeed either way -- what the drift branch
      // reports is the page's own label, not a pipeline failure -- and a reviewer
      // greps `RUN_OK`. The colour is the difference a reviewer sees first.
      //
      // The other half is "where did this session come from". `createSession`'s own
      // SESSION_AUTOCREATED banner is written and then overwritten by this one within
      // the same click, so without this clause the green verdict a reviewer actually
      // reads would say nothing about the scope having been minted for it.
      const strat = strategyClause(result.strategy, result.stats);
      // The vault-miss demonstration reports what it MEASURED, never what it intended.
      // `misses` comes out of the run's own stats, so the branch that says the
      // demonstration worked is the branch on which the pipeline says a token was not
      // resolved -- and if the fabricated token never came back (a provider that does
      // not echo, a gate that stripped it) the page says exactly that instead of
      // printing a claim the panels do not support. This is the same rule the destroy
      // banner follows: assert the erasure only on the branch where the audit log
      // proved it.
      const demo = S.missDemo;
      const misses = Math.round(Number((result.stats || {}).vault_misses));
      if (demo && Number.isFinite(misses) && misses > 0) {
        banner('warn', 'VAULT_MISS_DEMO',
          'run_id ' + result.run_id + ' · ' + strat.text + ' · vault_misses ' + misses +
          '. This page — not a model — appended ' + demo.fakes.join(' and ') + ' to your ' +
          'prompt: the same grammar as ' + demo.real + ' from the previous run, each with ' +
          'one hex digit of the id changed, so this session never issued them. (Two, ' +
          'because the mock renders each echoed token under one of five mutations and one ' +
          'of them drops the brackets — and an unbracketed token this run did not mint is ' +
          'deliberately left alone rather than called a miss. Two adjacent tokens take ' +
          'consecutive mutations, so at least one always arrives bracketed.) Everything ' +
          'after that is the ordinary pipeline: the provider echoed them, the restorer ' +
          'could not resolve what it did not issue, and the result is [UNRESOLVED_ENTITY] ' +
          'in panel 4 (hatched, per the legend) with a VAULT_MISS row in the audit tail ' +
          'below, scrolled to. That row is hash-chained like every other — press ' +
          '"Verify chain".');
      } else if (demo) {
        banner('err', 'VAULT_MISS_DEMO_NO_MISS',
          'run_id ' + result.run_id + ' · the run succeeded but recorded vault_misses ' +
          (Number.isFinite(misses) ? misses : '(not reported)') + ', so this press did NOT ' +
          'demonstrate the vault-miss path and this page will not claim it did. ' +
          demo.fakes.join(' and ') + ' were appended to the prompt (still in the box, ' +
          'verbatim) but did not come back bracketed in the provider\'s answer, so the ' +
          'restorer never had an unknown token it was willing to claim. A provider that ' +
          'does not echo its input cannot show this path from the outside; demo.py and ' +
          'test_vault_miss_on_deobfuscation drive the restorer directly.');
      } else {
        // The strategy half is `strategyClause`: the composition the run EMITTED, not
        // the literal it was asked for. The code keeps its `RUN_OK` prefix on both
        // branches because the run did succeed either way -- what the drift branch
        // reports is the page's own label, not a pipeline failure -- and a reviewer
        // greps `RUN_OK`. The colour is the difference a reviewer sees first.
        banner(strat.drift ? 'warn' : 'ok', strat.drift ? 'RUN_OK_STRATEGY_DRIFT' : 'RUN_OK',
          'run_id ' + result.run_id + ' · ' + strat.text +
          (minted ? ' · session ' + sid.slice(0, 12) + '… was auto-created by this Run: there ' +
            'was none, and every step above is scoped by it.' : ''));
      }
      $('audit-run').textContent = 'run_id ' + result.run_id;
      await loadAudit(result.run_id);
      // Only on the press that went looking for the row -- an ordinary Run never yanks
      // the page around. `renderAudit` has just recorded which row is the first hot one
      // (see `S.hotRowIndex`); without this the row is red somewhere down a 260px box
      // that opens at scrollTop 0, which is the exact complaint the LIVE REVIEW strip
      // makes about VAULT_DESTROY.
      //
      // Every step is feature-tested rather than assumed, because
      // `tests/test_ui_behaviour.py` drives this file under node against a DOM stub
      // whose elements are plain objects with no `rows` collection and no
      // `scrollIntoView`, and a demo control must not be the one thing that cannot be
      // tested there. `HTMLTableSectionElement.rows` in the browser, undefined in the
      // stub, and the whole block is then skipped.
      if (demo && S.hotRowIndex !== null) {
        const tableRows = $('audit-body').rows;
        const hotRow = tableRows ? tableRows[S.hotRowIndex] : null;
        if (hotRow && typeof hotRow.scrollIntoView === 'function') {
          hotRow.scrollIntoView({ block: 'center' });
        }
      }
    } catch (e) {
      showError(e);
      // The 422 body names the run that was refused. Without it the tail was
      // reloaded session-wide, which on a session that had already run put the
      // EGRESS_BLOCK row at position 79 of 84 inside a 260px scrolling box -- and
      // `audit-run` still read the PREVIOUS run's id, because only the success path
      // ever wrote it.
      const refused = (e.detail && e.detail.run_id) || null;
      if (refused) $('audit-run').textContent = 'run_id ' + refused + ' · refused';
      // For every refusal that reached the server, and it used to be only for
      // EGRESS_BLOCKED and SESSION_EXPIRED. `resetRun` above blanks the four panels,
      // the stats row and the #audit-run LABEL, and it deliberately does not touch
      // the table -- so every other server-side refusal (NOT_FOUND, RATE_LIMITED,
      // LLM_TRANSPORT_ERROR, CRYPTO_AUTH_FAILED, NETWORK_UNREACHABLE, a timeout) left
      // the PREVIOUS run's audit rows sitting under an emptied label, beside panel 1's
      // new document: exactly the cross-run mixture the rest of the reset exists to
      // prevent, on the rows a reviewer reads as the evidence. A reload that itself
      // fails is honest too -- `loadAudit`'s catch says the lookup failed rather than
      // rendering an empty log.
      //
      // Not for the two `ensureDoc` raises before it sends anything. NO_FILE and
      // NO_CATEGORY are refusals of the CLICK, not of a run: nothing was uploaded, no
      // run id exists, and the tail cannot have changed -- so an audit read here would
      // be the only request issued by a path whose whole point is that it issues none.
      //
      // PRESET_UNAVAILABLE is on the reloading side of that line and belongs there,
      // though the distinction is finer: it DID reach the server (the GET for the
      // bundled document), so this path is not one that issues no requests. The
      // fixtures route writes no audit row, so the reload re-renders the same tail
      // rather than showing something new -- which is the correct answer, not a
      // wasted call: it keeps the rows under the emptied label agreeing with the
      // panels beside them, which is what this reload is for.
      if (e.code !== 'NO_FILE' && e.code !== 'NO_CATEGORY') await loadAudit(refused);
    } finally {
      setBusy(false);
      // Consumed by THIS run and by no other. A refused vault-miss run must not leave
      // the flag armed for the reviewer's next ordinary press of Run, which would then
      // print a demonstration verdict about a run that carried no fabricated token.
      // The appended sentence deliberately stays in the prompt box: it is what was
      // sent, `MISS_RE` takes it back off on the next press of this control, and
      // silently rewriting the box on a failure would hide the input that failed.
      S.missDemo = null;
    }
  }

  async function loadAudit(runId) {
    // Falls back to the destroyed session's ID. `S.sessionId` is null after a
    // destroy, and bailing on that made the `SESSION_EXPIRED` refresh branch above
    // dead code AND blanked the panel exactly when VAULT_DESTROY appears in it.
    // The audit endpoint deliberately does not check liveness, so a destroyed
    // session's tail is still readable by its owner -- see README Deviation 18.
    const scope = S.sessionId || S.lastSessionId;
    if (!scope) return;
    try {
      // user_id is required and is *proved*: the API checks it against the owner
      // recorded in the log at SESSION_CREATE. Without it the log handed any
      // anonymous holder of a run_id the session_id, doc_id and user_id of the
      // run — i.e. both credential pairs it takes to read the original document
      // and to erase the vault.
      //
      // The proof is against the owner recorded for THIS session, so the claim has
      // to be the session's owner and not the field's current contents: retyping the
      // field emptied the tail (an unproved scope reads as zero events) at the exact
      // moment the tail is the evidence. `sessionOwner` falls back to the field.
      let q = '/audit?session_id=' + encodeURIComponent(scope) +
        '&user_id=' + encodeURIComponent(sessionOwner()) + '&limit=' + AUDIT_LIMIT;
      if (runId) q += '&run_id=' + encodeURIComponent(runId);
      const r = await api('GET', q);
      const events = r.events || [];
      // The section is headed "Audit tail" and shows the HEAD. Rows come back
      // ascending by seq and this asks for the first AUDIT_LIMIT of them, so on
      // legal_brief_large.txt -- a preset in this page's own dropdown -- one run's 347
      // events render as 200: one DETECT and 199 OBFUSCATE. The 147 dropped rows
      // include EGRESS_PASS, LLM_CALL and DEOBFUSCATE, i.e. the evidence that the gate
      // cleared the payload and that the provider was called at all, and nothing on
      // screen said the list was partial. Reaching the true tail needs either a count
      // round-trip or an `order` parameter GET /audit does not have; saying so is the
      // half that can be done here without either.
      renderAudit(events, events.length >= AUDIT_LIMIT
        ? 'showing the first ' + AUDIT_LIMIT + ' events of this scope — later rows, ' +
          'including EGRESS_PASS, LLM_CALL and DEOBFUSCATE, are not on screen. Re-query ' +
          'GET /audit with offset=' + AUDIT_LIMIT + ' to read them.'
        : null);
    } catch (e) {
      // "no events" is the EMPTY state. A lookup that failed is not an empty log, and
      // rendering it as one states the exact opposite of what this panel exists to
      // prove -- on the error paths, which is where loadAudit is called from.
      renderAudit([], 'audit tail could not be loaded (' + (e.code || 'ERROR') + ')');
    }
  }

  async function verifyChain() {
    // Its own in-flight flag rather than `setBusy`: the chain walk is a read, it is
    // legitimately usable while nothing else is happening, and it is the one button
    // `setBusy` deliberately leaves alive. What it must not be is startable twice.
    // The walk is priced in ROWS (audit.py: 5,000 per token, burst 24) and charged on
    // success, so on a log of any size an impatient double-click spends the bucket
    // and the second answer is the 429 the RATE_LIMITED sentence describes -- a
    // throttle the page inflicted on itself, reported as if the server had.
    if (S.verifying) return;
    S.verifying = true;
    $('btn-verify').disabled = true;
    try {
      const r = await api('GET', '/audit/verify');
      const el = $('verify-badge');
      el.className = 'badge ' + (r.valid ? 'ok' : 'err');
      // "(whole log)" is not decoration. This badge sits inside the Audit tail's own
      // <h2>, beside the run_id label and directly above a table filtered to one run:
      // 37 rows under a badge reading 26,844 events on the live instance. The
      // endpoint's session-scoped form exists and is not called here; the unscoped
      // count is the stronger tamper-evidence claim, so it stays -- named.
      el.textContent = 'chain: ' + (r.valid ? 'VALID' : 'BROKEN') + ' · ' + r.length +
        ' events (whole log)';
    } catch (e) {
      // A 429 here is the chain-walk meter, not a failed integrity check -- and the
      // badge kept its previous value, so a throttled click left "VALID" on screen
      // beside a red RATE_LIMITED banner.
      const el = $('verify-badge');
      el.className = 'badge muted';
      el.textContent = e.code === 'RATE_LIMITED' ? 'chain: throttled' : 'chain: not verified';
      showError(e);
    } finally {
      S.verifying = false;
      $('btn-verify').disabled = false;
    }
  }

  async function health() {
    try {
      const h = await api('GET', '/health');
      const el = $('health');
      el.className = 'badge ' + (h.status === 'ok' ? 'ok' : 'err');
      el.textContent = h.status + ' · ' + h.llm_provider + '/' + h.llm_model + ' · ' + h.spacy_model;
    } catch (e) { markUnreachable(); }
  }

  // ---------- the demo-document preset ----------
  // Build doc section 9.10 asks for an "upload fixture dropdown", and this is now
  // one. It could not be: a browser cannot read a path off disk and nothing served
  // `fixtures/` over HTTP, so the control listed four filenames, set `doc_category`,
  // and left the reviewer to find the same file on disk with the picker -- the hint
  // literally read "now pick fixtures/medical_note.txt with the file button". Naming
  // a document and then making you go and get it is friction on the first control a
  // reviewer touches; before the hint existed it was silent failure (zero requests,
  // `NO_FILE`). `api/routes/documents.py` now serves exactly these four names, so
  // one click arms the document AND its category, and Run uploads it through the
  // same `POST /documents` the picker uses.
  //
  // Two controls, one armed at a time, and the arming is state rather than a guess:
  // see `S.armed`. Every string is here rather than in the markup so the idle text
  // and the reset are one value. See README section 8's deviation ledger.
  const HINT_IDLE = 'nothing armed yet: choose a demo document (loads it and sets its ' +
    'doc_category), or pick a file of your own';
  const armedPreset = (name, cat) => 'ARMED: bundled fixtures/' + name +
    (cat ? ' as doc_category=' + cat : '') + '. Press Run.';
  const armedFile = (name, cat) => 'ARMED: your own file "' + name + '"' +
    (cat ? ' as doc_category=' + cat : ' (choose a doc_category)') +
    '. The demo-document dropdown is cleared.';

  // The page's answer to "which document does Run upload". `textContent`, never
  // `innerHTML`: a file name is a string off the reviewer's disk and this is the one
  // place the page prints one.
  function paintArmed() {
    const cat = $('category').value;
    const a = S.armed;
    $('fixture-hint').textContent = !a
      ? HINT_IDLE
      : (a.kind === 'preset' ? armedPreset(a.name, cat) : armedFile(a.name, cat));
  }

  // Arming either control disarms the other, in one function, so there is no order
  // of clicks that leaves both live or leaves the page saying one thing and
  // uploading another. The DOM side of the disarm is cosmetic but not optional: a
  // picker still showing "report.pdf" beside a hint that says a bundled document is
  // armed is exactly the ambiguity this replaced. `$('file').value = ''` is the
  // portable way to clear a file input -- assigning to `.files` throws in Chrome
  // unless the value is a real `FileList` -- and it is only the DISPLAY: `S.armed`
  // is what `ensureDoc` reads.
  function arm(next) {
    S.armed = next;
    // Any change of source invalidates the cached upload, or Run would re-serve the
    // previously uploaded document under the newly armed one's name.
    S.docId = null;
    S.uploadKey = null;
    if (!next || next.kind === 'preset') $('file').value = '';
    if (!next || next.kind === 'file') $('fixture').value = '';
    paintArmed();
  }

  // ---------- wiring ----------
  $('btn-session').addEventListener('click', createSession);
  // Three listeners for one action, which is the gate: `btn-destroy` only ARMS.
  $('btn-destroy').addEventListener('click', armDestroy);
  $('btn-destroy-confirm').addEventListener('click', confirmDestroy);
  $('btn-destroy-cancel').addEventListener('click', () => setDestroyArmed(false));
  $('btn-run').addEventListener('click', run);
  // Section 9.10's vault-miss demonstration. Not a variant of Run wired to the same
  // listener: it has its own preflights (a previous run to take a token from, a LIVE
  // session) and its own verdict, and it goes through `run` for everything else.
  $('btn-miss').addEventListener('click', restoreAgain);
  $('btn-verify').addEventListener('click', verifyChain);
  $('fixture').addEventListener('change', (ev) => {
    const opt = ev.target.selectedOptions[0];
    // The category travels with the document, so choosing a preset satisfies the
    // required `doc_category` too -- the reviewer does not set it twice. Applied
    // before `arm` so the armed line prints the category it just chose. An option
    // with no `data-cat` (the placeholder) leaves the field alone rather than
    // blanking it: the reviewer may have set it for a file of their own.
    if (opt && opt.dataset.cat) $('category').value = opt.dataset.cat;
    // `cat` is carried on the armed state, not just applied to the field, because it is
    // the one piece of ground truth this page has about what a document IS: the field
    // can be changed afterwards and the bundled document's own category cannot.
    // `renderScope` is what reads it -- see the three states there.
    arm(opt && opt.value
      ? { kind: 'preset', name: opt.value, cat: opt.dataset.cat || null }
      : null);
  });
  $('file').addEventListener('change', () => {
    const f = $('file').files[0];
    arm(f ? { kind: 'file', name: f.name } : null);
  });
  // The armed line names the category, so it has to be repainted when the category
  // moves under it -- otherwise arming medical_note.txt and then switching to
  // `legal` leaves the page claiming a `medical` run it is not about to make.
  $('category').addEventListener('change', paintArmed);
  $('prompt').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') run(); });
  // Browsers restore form controls across a reload and out of the bfcache WITHOUT
  // firing `change`, so this page can come back with a document already sitting in
  // the picker or an option already selected in the dropdown. Reading the DOM once
  // here is what keeps the armed line honest in that case: painting a bare
  // "nothing armed" over a picker visibly holding a file is the same
  // says-one-thing-does-another the armed state exists to remove. The picker wins if
  // the browser somehow restored both, and `arm` then clears the other, so there is
  // exactly one armed control after start-up whatever was restored.
  const restored = $('file').files[0];
  const restoredPreset = $('fixture').value;
  // The restored preset's category is read off the <option> the browser re-selected,
  // exactly as the `change` listener would have -- `dataset` is not available on a
  // <select> value, and a restored preset with no `cat` would make `renderScope` treat a
  // bundled document as one the page knows nothing about.
  const restoredOpt = restoredPreset
    ? Array.prototype.find.call($('fixture').options || [],
      (o) => o.value === restoredPreset)
    : null;
  arm(restored
    ? { kind: 'file', name: restored.name }
    : (restoredPreset
      ? { kind: 'preset', name: restoredPreset,
        cat: (restoredOpt && restoredOpt.dataset && restoredOpt.dataset.cat) || null }
      : null));
  // The markup ships the confirm pair `hidden`, so this changes nothing on a first load.
  // It is here so that the DOM, `S.destroyArmed` and the live region have exactly one
  // writer: a page restored out of the bfcache can come back with the arm mid-flight,
  // and a disarmed pair beside a live region still reading "ARMED" is the disagreement
  // this state exists to prevent.
  setDestroyArmed(false);
  health();
})();
