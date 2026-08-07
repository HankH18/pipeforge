/* Secure Context Pipeline — demo UI. Vanilla JS, no build step, no network deps.
   Every string that originates from a document, an LLM, or an error body is
   HTML-escaped before it is inserted. Nothing untrusted is ever interpolated raw. */
'use strict';
(() => {
  const S = { sessionId: null, lastSessionId: null, docId: null, uploadKey: null, busy: false };

  const $ = (id) => document.getElementById(id);
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ESC[c]);
  const userId = () => $('user').value.trim() || 'demo-user';

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
  const EDGE_CLOSE = /[*_`]+$/;
  const EDGE_OPEN = /^(?:['’]s?)?[*_`]*(?:['’]s?)?/;
  const HINT_TAIL = /^\|[^\]})\n]{0,48}[\]})]/;

  const STAT_ORDER = ['detect_ms', 'obfuscate_ms', 'egress_ms', 'llm_ms', 'restore_ms',
    'total_ms', 'entities_detected', 'tokens_issued'];

  // ---------- transport ----------
  async function api(method, path, opts) {
    const o = opts || {};
    const init = { method, headers: {} };
    if (o.json) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(o.json); }
    if (o.form) { init.body = o.form; }
    const res = await fetch(path, init);
    if (res.status === 204) return null;
    const ct = res.headers.get('content-type') || '';
    const body = ct.indexOf('json') >= 0 ? await res.json() : await res.text();
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

  function showError(e) {
    const detail = typeof e.detail === 'string' ? e.detail : JSON.stringify(e.detail || {});
    let msg = detail;
    if (e.code === 'EGRESS_BLOCKED') {
      msg = 'FAIL-CLOSED: the egress gate refused to release the payload. No provider call was made. ' + detail;
    } else if (e.code === 'SESSION_EXPIRED') {
      msg = 'Session key is gone — the vault cannot be read, so nothing can be obfuscated or restored. ' +
        'Create a new session to continue. ' + detail;
    } else if (e.code === 'RATE_LIMITED') {
      // Every route here is anonymous, so the meters are per source address:
      // a shared address can spend a budget this browser never touched.
      msg = 'Throttled — too many requests from this address. Writes and failed audit-scope ' +
        'lookups are metered per caller. Wait and retry. ' + detail;
    }
    banner('err', e.code || 'ERROR', msg);
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

  // Panel 2: highlight surrogates (coloured per category) and [REDACTED_*] markers.
  function renderMarks(text, dets) {
    const cat = new Map();
    (dets || []).forEach((d) => { if (d.surrogate) cat.set(d.surrogate, d.category); });
    const alt = surAlt(dets);
    const re = new RegExp(MARKS_SRC + (alt ? '|' + alt : ''), 'g');
    let out = '';
    let last = 0;
    let m;
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
      if (gap !== '') out += i > 0 ? '<mark class="rest">' + esc(gap) + '</mark>' : esc(gap);
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

  function renderAudit(events) {
    const body = $('audit-body');
    if (!events || !events.length) {
      body.innerHTML = '<tr><td colspan="5" class="muted">no events</td></tr>';
      return;
    }
    body.innerHTML = events.map((e) => {
      const cls = (e.event_type === 'EGRESS_BLOCK' || e.event_type === 'VAULT_MISS') ? ' class="hot"'
        : (e.event_type === 'VAULT_DESTROY' ? ' class="warn-row"' : '');
      return '<tr' + cls + '><td>' + esc(e.seq == null ? '' : e.seq) + '</td><td>' + esc(e.event_type) +
        '</td><td>' + esc(e.entity_type || '') + '</td><td>' + esc(e.token_id || '') +
        '</td><td class="detail">' + esc(JSON.stringify(e.detail || {})) + '</td></tr>';
    }).join('');
  }

  function setBusy(on) {
    S.busy = on;
    $('btn-run').disabled = on;
    $('btn-destroy').disabled = on;
    $('btn-session').disabled = on;
    $('spin').hidden = !on;
  }

  // ---------- actions ----------
  async function createSession() {
    clearBanner();
    setBusy(true);
    try {
      const r = await api('POST', '/sessions', { json: { user_id: userId() } });
      S.sessionId = r.session_id;
      const when = new Date(r.expires_at * 1000).toLocaleTimeString();
      $('session-badge').className = 'badge ok';
      $('session-badge').textContent = 'session ' + r.session_id.slice(0, 12) + '… · expires ' + when;
      banner('ok', 'SESSION_CREATED', 'Session key lives in process memory only.');
    } catch (e) { showError(e); } finally { setBusy(false); }
  }

  async function destroySession() {
    if (!S.sessionId) { banner('warn', 'NO_SESSION', 'Nothing to destroy.'); return; }
    setBusy(true);
    try {
      // user_id is required: logout is owner-scoped, so a session is only
      // destroyed for the user it was created for.
      await api('DELETE', '/sessions/' + encodeURIComponent(S.sessionId) +
        '?user_id=' + encodeURIComponent(userId()));
      // Kept so the audit panel can still be read after destruction. `loadAudit`
      // bails on a null `sessionId`, so nulling this was also what made the audit
      // tail go blank at exactly the moment VAULT_DESTROY lands in it — the one
      // event the destroy button exists to show.
      S.lastSessionId = S.sessionId;
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
      banner('warn', 'VAULT_DESTROYED',
        'Session key and vault rows are gone — irreversibly. Press Run again: the ' +
        'second run is refused with SESSION_EXPIRED before the vault is even ' +
        'consulted. The audit tail below shows VAULT_DESTROY.');
      await loadAudit();
    } catch (e) { showError(e); } finally { setBusy(false); }
  }

  async function ensureDoc() {
    const f = $('file').files[0];
    if (!f) throw { code: 'NO_FILE', detail: 'Choose a document first (fixtures/ or any file).' };
    const cat = $('category').value;
    const key = f.name + ':' + f.size + ':' + f.lastModified + ':' + cat;
    if (S.docId && S.uploadKey === key) return;
    const form = new FormData();
    form.append('file', f, f.name);
    form.append('user_id', userId());
    if (cat) form.append('doc_category', cat);
    const r = await api('POST', '/documents', { form });
    S.docId = r.doc_id;
    S.uploadKey = key;
  }

  async function run() {
    if (S.busy) return;
    clearBanner();
    const prompt = $('prompt').value.trim();
    if (!prompt) { banner('err', 'NO_PROMPT', 'Enter a prompt.'); return; }
    setBusy(true);
    try {
      await ensureDoc();
      const doc = await api('GET', '/documents/' + encodeURIComponent(S.docId) +
        '/text?user_id=' + encodeURIComponent(userId()));
      $('p1').innerHTML = esc(doc.text);
      $('c1').textContent = doc.chars + ' chars';

      const result = await api('POST', '/pipeline/run', {
        json: {
          session_id: S.sessionId,
          user_id: userId(),
          doc_id: S.docId,
          prompt: prompt,
          strategy: $('strategy').value,
        },
      });

      $('p1').innerHTML = renderOriginal(doc.text, result.detections);
      $('c1').textContent = doc.chars + ' chars · ' + (result.detections || []).length + ' spans';
      $('p2').innerHTML = renderMarks(result.obfuscated_payload, result.detections);
      $('c2').textContent = result.obfuscated_payload.length + ' chars';
      $('p3').innerHTML = esc(result.raw_llm_response);
      $('c3').textContent = result.raw_llm_response.length + ' chars';
      $('p4').innerHTML = renderRestored(result.raw_llm_response, result.restored_text, result.detections);
      $('c4').textContent = result.restored_text.length + ' chars';
      renderStats(result.stats || {});
      banner('ok', 'RUN_OK', 'run_id ' + result.run_id + ' · strategy ' + result.strategy);
      $('audit-run').textContent = 'run_id ' + result.run_id;
      await loadAudit(result.run_id);
    } catch (e) {
      showError(e);
      if (e.code === 'EGRESS_BLOCKED' || e.code === 'SESSION_EXPIRED') await loadAudit(null);
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
      let q = '/audit?session_id=' + encodeURIComponent(scope) +
        '&user_id=' + encodeURIComponent(userId()) + '&limit=200';
      if (runId) q += '&run_id=' + encodeURIComponent(runId);
      const r = await api('GET', q);
      renderAudit(r.events);
    } catch (e) { renderAudit([]); }
  }

  async function verifyChain() {
    try {
      const r = await api('GET', '/audit/verify');
      const el = $('verify-badge');
      el.className = 'badge ' + (r.valid ? 'ok' : 'err');
      el.textContent = 'chain: ' + (r.valid ? 'VALID' : 'BROKEN') + ' · ' + r.length + ' events';
    } catch (e) { showError(e); }
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
