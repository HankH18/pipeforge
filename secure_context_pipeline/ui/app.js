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
    entities_detected: { why: 'SAFETY. Spans the detector returned over the document ' +
      'text, before any policy ran. The header of panel 1 counts a different set -- ' +
      'the spans this run actually masked -- and neither is a subset of the other. ' +
      'Hover that header for the arithmetic.' },
    prompt_entities_detected: { why: 'SAFETY. Spans the detector returned over the ' +
      'prompt you typed. The prompt is obfuscated on the same path the document is; ' +
      'its spans are absent from panel 1 because their offsets are prompt-space.' },
    tokens_issued: { why: 'SAFETY. Vault rows this run minted -- one per distinct ' +
      '(entity type, value), document and prompt together. Lower than ' +
      'entities_detected whenever a value occurs more than once.' },
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
  const NEXT_STEP = 'Session created. Choose a file and press Run.';

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

    SESSION_EXPIRED: () =>
      'Session key is gone — the vault cannot be read, so nothing can be obfuscated or restored. ' +
      'Press "Create session" for a new one, then re-run.',

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
  // green in the provider's-eye view with nothing on the page saying it is a fake
  // this run minted rather than a clinician named in the document. A reviewer's only
  // recourse was diffing panel 3 against panel 1 by eye, which is the manual check
  // the highlighting exists to replace.
  //
  // None of the three names an original value: the whole point is that panels 2 and 3
  // do not hold one. The pseudonym tip names the entity TYPE, which the payload's
  // own bracketed tokens print in clear anyway.
  const TOK_TIP = 'A surrogate token. The original it stands for is in the vault for this ' +
    'session and is not anywhere in this payload; panel 4 puts it back.';
  const RED_TIP = 'A redaction marker. The value was removed rather than tokenised -- ' +
    'irreversible by design, so it does not come back in panel 4.';
  const psTip = (t) => 'A PSEUDONYM this run minted for a ' + (t || 'detected value') +
    '. It reads like a real value and is not one: the original never left the vault.';

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
      const shown = isTiming(k) ? v.toFixed(1) + ' ms' : String(Math.round(v));
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

  // `note` is a footer row when there are events and the empty-state row when there
  // are none. It exists because this table had exactly two states -- a row per event,
  // or "no events" -- and both of the things it could not say are things a reviewer
  // reads the panel to learn: that the page is showing a truncated list, and that the
  // lookup failed rather than the log being empty.
  function renderAudit(events, note) {
    const body = $('audit-body');
    const rows = events || [];
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="5" class="muted">' + esc(note || 'no events') +
        '</td></tr>';
      return;
    }
    const tail = note ? '<tr><td colspan="5" class="muted">' + esc(note) + '</td></tr>' : '';
    body.innerHTML = rows.map((e) => {
      const cls = (e.event_type === 'EGRESS_BLOCK' || e.event_type === 'VAULT_MISS') ? ' class="hot"'
        : (e.event_type === 'VAULT_DESTROY' ? ' class="warn-row"' : '');
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

  function renderScope(cat) {
    const el = $('scope-note');
    const skipped = scopedOut(cat);
    // Empty is unreachable with today's registry -- every category leaves at least one
    // rule set out -- but a registry that scoped nothing must not leave a stale note up.
    if (!skipped.length) { el.hidden = true; return; }
    // textContent, not innerHTML: nothing here is markup, and the one interpolated
    // value (`cat`) comes off a <select> this page wrote the options for.
    el.textContent = 'doc_category=' + cat + ': ' + skipped.join(', ') +
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
    $('btn-destroy').disabled = on;
    $('btn-session').disabled = on;
    // The three inputs a run reads AFTER it has started. Only the buttons were
    // disabled, so the file picker stayed live while a request was in flight; its
    // change listener nulls S.docId, and run() re-read that field across an await.
    // Measured: changing the file during the text fetch posts `"doc_id": null` and
    // the banner becomes VALIDATION_ERROR {"errors":1,"fields":"body.doc_id"},
    // naming a field the reviewer never saw.
    $('file').disabled = on;
    $('category').disabled = on;
    $('strategy').disabled = on;
    $('spin').hidden = !on;
  }

  // ---------- actions ----------
  async function createSession() {
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
      // instruction ("Create a session, choose a file, press Run"), and blanking it
      // to a dash on the click that completes its first clause is a worse page.
      resetRun(NEXT_STEP);
      const when = new Date(r.expires_at * 1000).toLocaleTimeString();
      $('session-badge').className = 'badge ok';
      $('session-badge').textContent = 'session ' + r.session_id.slice(0, 12) + '… · expires ' + when;
      banner(replaced.warn ? 'warn' : 'ok', 'SESSION_CREATED',
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

  // Returns the document id rather than only writing it to `S`, so a run can hold
  // its own copy across the awaits that follow.
  async function ensureDoc(uid, cat) {
    const f = $('file').files[0];
    if (!f) throw { code: 'NO_FILE', detail: 'Choose a document first (fixtures/ or any file).' };
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
    const key = f.name + ':' + f.size + ':' + f.lastModified + ':' + cat;
    if (S.docId && S.uploadKey === key) return S.docId;
    const form = new FormData();
    form.append('file', f, f.name);
    form.append('user_id', uid);
    form.append('doc_category', cat);
    // `slow`: the PDF parse and the .docx expansion happen inside this request, so it
    // is not a transport-latency call and must not be held to the short budget.
    const r = await api('POST', '/documents', { form, slow: true });
    S.docId = r.doc_id;
    S.uploadKey = key;
    return r.doc_id;
  }

  async function run() {
    if (S.busy) return;
    clearBanner();
    const prompt = $('prompt').value.trim();
    if (!prompt) { banner('err', 'NO_PROMPT', 'Enter a prompt.'); return; }
    // The missing input the page did not preflight, and the one the whole demo is
    // scoped by. Run is the biggest button on the page, inside the red LIVE REVIEW
    // strip; Create session is a small one ten controls above it. Without this the
    // first click uploads the document, fills panel 1 with the original text, posts
    // `session_id: null`, and the API's 401 becomes the banner "Session key is gone"
    // -- about a key that was never minted. The empty `session_id` in that detail is
    // the only thing that gives it away.
    if (!S.sessionId) {
      banner('err', 'NO_SESSION', 'Press "Create session" first — that is where the vault key ' +
        'is minted, and every step below is scoped by it.');
      return;
    }
    setBusy(true);
    // Captured ONCE, for the whole run. These were re-read from `S` and from the DOM
    // after each await, so a control touched mid-request was read by the next step.
    const uid = userId();
    const sid = S.sessionId;
    const strategy = $('strategy').value;
    // Captured here for the same reason `strategy` is, and read twice: once to scope
    // the upload, once to name the rule sets the run did not use.
    const cat = $('category').value;
    try {
      resetRun();
      const docId = await ensureDoc(uid, cat);
      const doc = await api('GET', '/documents/' + encodeURIComponent(docId) +
        '/text?user_id=' + encodeURIComponent(uid));
      // Panel 1 is filled before the pipeline call so a reviewer can see which
      // document is in flight during a run that takes seconds. `resetRun` above has
      // already dropped panels 2-4, so a failure from here on leaves ONE document on
      // screen rather than a mixture of two. The counter says "not yet scanned"
      // because the spans only arrive with the response, and a bare "2826 chars"
      // beside an unhighlighted document reads as "the detector found nothing".
      $('p1').innerHTML = doc.chars ? esc(doc.text) : esc(NO_TEXT);
      $('c1').textContent = doc.chars + ' chars · not yet scanned';

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
      $('p1').innerHTML = doc.chars ? renderOriginal(doc.text, result.detections) : esc(NO_TEXT);
      // "spans" alone did not say WHICH spans, and it is the number a reviewer
      // compares against `entities_detected` in the strip above. See `C1_TITLE`.
      $('c1').textContent = doc.chars + ' chars · ' + (result.detections || []).length +
        C1_MASKED;
      $('c1').title = C1_TITLE;
      const fence = result.obfuscated_payload.indexOf(DOC_OPEN);
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
      renderScope(cat);
      banner('ok', 'RUN_OK', 'run_id ' + result.run_id + ' · strategy ' + result.strategy);
      $('audit-run').textContent = 'run_id ' + result.run_id;
      await loadAudit(result.run_id);
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
      if (e.code !== 'NO_FILE' && e.code !== 'NO_CATEGORY') await loadAudit(refused);
    } finally { setBusy(false); }
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

  // ---------- the fixture preset ----------
  // Build doc section 9.10 asks for an "upload fixture dropdown". This control
  // cannot upload: a browser cannot read a path off disk, and nothing serves
  // `fixtures/` over HTTP -- `_mount_ui` mounts `secure_context_pipeline/ui/`
  // alone, so `GET /fixtures/medical_note.txt` answers 404. Labelled "fixture"
  // and wired to set `doc_category` and nothing else, it promised the upload and
  // withheld it silently: picking `medical_note.txt` and pressing Run issued zero
  // requests and answered `NO_FILE`. The hint carries the half a dropdown can
  // still do -- naming the path to hand the file picker -- and both strings live
  // here rather than in the markup so the idle text and the reset are one value.
  // See README section 8's deviation ledger for the row against section 9.10.
  const HINT_IDLE = 'a preset, not an upload: it sets doc_category; the picker takes the file';
  const hintFor = (name) => (name
    ? 'now pick fixtures/' + name + ' with the file button'
    : HINT_IDLE);

  // ---------- wiring ----------
  $('btn-session').addEventListener('click', createSession);
  $('btn-destroy').addEventListener('click', destroySession);
  $('btn-run').addEventListener('click', run);
  $('btn-verify').addEventListener('click', verifyChain);
  $('fixture').addEventListener('change', (ev) => {
    const opt = ev.target.selectedOptions[0];
    if (opt && opt.dataset.cat) $('category').value = opt.dataset.cat;
    $('fixture-hint').textContent = hintFor(opt && opt.value);
  });
  $('file').addEventListener('change', () => { S.docId = null; S.uploadKey = null; });
  $('prompt').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') run(); });
  $('fixture-hint').textContent = HINT_IDLE;
  health();
})();
