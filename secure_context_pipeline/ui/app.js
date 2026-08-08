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
    docId: null, uploadKey: null, busy: false,
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

  const STAT_ORDER = ['detect_ms', 'obfuscate_ms', 'egress_ms', 'llm_ms', 'restore_ms',
    'total_ms', 'entities_detected', 'tokens_issued'];

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
  async function api(method, path, opts) {
    const o = opts || {};
    const init = { method, headers: {} };
    if (o.json) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(o.json); }
    if (o.form) { init.body = o.form; }
    let res;
    try {
      res = await fetch(path, init);
    } catch (err) {
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

  function showError(e) {
    const detail = detailText(e);
    let msg = detail;
    if (e.code === 'EGRESS_BLOCKED') {
      // Both of the gate's exits arrive under this one code, and they are not the
      // same claim. A deliberate block (vault_original / detector_rescan /
      // independent_pattern) is the control catching a leak -- the strongest thing
      // this product says about itself. The fail-safe wrapper in EgressGate.check
      // turns any internal exception into reason "gate_exception", hit_count 0: the
      // control fell over and blocked by default, having caught nothing. The UI said
      // the first sentence for both, with the distinguishing field visible only
      // inside the JSON tail.
      msg = ((e.detail && e.detail.reason) === 'gate_exception'
        ? 'The egress gate FAILED INTERNALLY and blocked by default. Nothing was sent -- and ' +
          'nothing was caught either: this is a gate error, not a caught leak. '
        : 'FAIL-CLOSED: the egress gate refused to release the payload. ' +
          'No provider call was made. ') + detail;
    } else if (e.code === 'SESSION_EXPIRED') {
      msg = 'Session key is gone — the vault cannot be read, so nothing can be obfuscated or restored. ' +
        'Create a new session to continue. ' + detail;
    } else if (e.code === 'RATE_LIMITED') {
      // Every route here is anonymous, so the meters are per source address:
      // a shared address can spend a budget this browser never touched.
      // The third meter is the one this page is most likely to trip: the chain walk
      // behind Verify chain is priced in ROWS (audit.py: 5,000 rows per token, burst
      // 24), and it is charged on success, so five clicks in a row on a large log
      // spend the bucket. The sentence named the two meters that had not fired.
      msg = 'Throttled — too many requests from this address. Durable writes, failed ' +
        'audit-scope lookups, and the chain walk behind Verify chain (priced per row of ' +
        'the log) are each metered per caller. Wait and retry. ' + detail;
    }
    banner('err', e.code || 'ERROR', msg.trim());
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
    const cat = new Map();
    (dets || []).forEach((d) => { if (d.surrogate) cat.set(d.surrogate, d.category); });
    const alt = surAlt(dets);
    const re = new RegExp(MARKS_SRC + (alt ? '|' + alt : ''), 'g');
    let out = esc(text.slice(0, start));
    let last = start;
    let m;
    re.lastIndex = start;
    while ((m = re.exec(text)) !== null) {
      const c = m[1] || (m[0].slice(0, 10) === '[REDACTED_' ? 'RED' : (cat.get(m[0]) || 'PII'));
      out += esc(text.slice(last, m.index));
      out += '<mark class="tok c-' + esc(c) + '">' + esc(m[0]) + '</mark>';
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

  function renderStats(stats) {
    const keys = STAT_ORDER.filter((k) => k in stats)
      .concat(Object.keys(stats).filter((k) => STAT_ORDER.indexOf(k) < 0));
    $('stats').innerHTML = keys.map((k) => {
      const v = Number(stats[k]);
      const shown = /_ms$/.test(k) ? v.toFixed(1) + ' ms' : String(Math.round(v));
      return '<span class="stat"><i>' + esc(k) + '</i>' + esc(shown) + '</span>';
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
    ['c1', 'c2', 'c3', 'c4'].forEach((id) => { $(id).textContent = ''; });
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
      const r = await api('POST', '/sessions', { json: { user_id: owner } });
      S.sessionId = r.session_id;
      S.userId = owner;
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
      banner('ok', 'SESSION_CREATED', 'Session key lives in process memory only.');
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
    const r = await api('POST', '/documents', { form });
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
      $('c1').textContent = doc.chars + ' chars · ' + (result.detections || []).length + ' spans';
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
      if (e.code === 'EGRESS_BLOCKED' || e.code === 'SESSION_EXPIRED') {
        // The 422 body names the run that was refused. Without it the tail was
        // reloaded session-wide, which on a session that had already run put the
        // EGRESS_BLOCK row at position 79 of 84 inside a 260px scrolling box -- and
        // `audit-run` still read the PREVIOUS run's id, because only the success path
        // ever wrote it.
        const refused = (e.detail && e.detail.run_id) || null;
        if (refused) $('audit-run').textContent = 'run_id ' + refused + ' · refused';
        await loadAudit(refused);
      }
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
    }
  }

  async function health() {
    try {
      const h = await api('GET', '/health');
      const el = $('health');
      el.className = 'badge ' + (h.status === 'ok' ? 'ok' : 'err');
      el.textContent = h.status + ' · ' + h.llm_provider + '/' + h.llm_model + ' · ' + h.spacy_model;
    } catch (e) { $('health').textContent = 'health: unreachable'; }
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
