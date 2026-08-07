"""The demo UI's four render functions, executed rather than read.

``tests/test_api_ui_escaping.py`` audits ``ui/app.js`` as *text*: it proves every
value that becomes markup passes through ``esc()``, and that no grammar in the file
carries an unbounded quantifier. Both are static properties. Nothing anywhere ran
the file, so everything the escaping audit cannot see was untested -- which is most
of it: the splice order in ``renderOriginal``, the category chosen per token in
``renderMarks``, the literal alignment and the bail-out in ``renderRestored``, the
longest-first ordering in ``surAlt``, and the ``lastSessionId`` hand-off between
``destroySession`` and ``loadAudit`` that exists because the audit panel used to go
blank at exactly the moment ``VAULT_DESTROY`` landed in it.

``app.js`` is an IIFE with no exports, so the harness below appends one assignment
to the closure -- the last line before ``})();`` -- and evaluates the real shipped
file in node under a ~30-line DOM stub and a scripted ``fetch``. Nothing is
reimplemented here: every expected value in this module is a hand-written string,
never one built by calling the helper under test.

Skipped, not failed, where node is absent: the static audit in
``test_api_ui_escaping.py`` is the control that must run everywhere, and this file
is the behavioural layer on top of it.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_JS = REPO_ROOT / "secure_context_pipeline" / "ui" / "app.js"
INDEX_HTML = REPO_ROOT / "secure_context_pipeline" / "ui" / "index.html"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

#: Separates the harness's JSON result from anything the file may print.
SENTINEL = "<<<UI-RESULT>>>"
#: U+00B7, the separator ``renderOriginal`` builds its title attribute with.
MID = "·"

HARNESS = r"""
'use strict';
const fs = require('fs');
const SRC = fs.readFileSync(process.argv[2], 'utf8');

// ---- DOM stub: enough of an element for the UI's four sinks and its wiring ----
const nodes = new Map();
function el(id) {
  if (!nodes.has(id)) {
    nodes.set(id, {
      id: id, value: '', textContent: '', innerHTML: '', className: '',
      hidden: false, disabled: false, files: [], on: {},
      addEventListener: function (type, fn) { (this.on[type] = this.on[type] || []).push(fn); },
    });
  }
  return nodes.get(id);
}
globalThis.document = { getElementById: el };
globalThis.el = el;
// Dispatch. Unhandled is an error, not a no-op: an unwired control must be red.
globalThis.fire = function (id, type, ev) {
  const handlers = el(id).on[type] || [];
  if (!handlers.length) { throw new Error('#' + id + ' has no ' + type + ' listener'); }
  handlers.forEach(function (h) { h(ev || {}); });
};
globalThis.settle = function () { return new Promise(function (r) { setTimeout(r, 50); }); };
globalThis.FormData = class { constructor() { this.parts = []; } append() {} };

// ---- scripted transport: every request is recorded, the reply is the test's ----
const calls = [];
let responder = function () { return { status: 200, body: {} }; };
globalThis.calls = calls;
globalThis.respond = function (fn) { responder = fn; };
globalThis.fetch = async function (path, init) {
  const body = init && init.body;
  calls.push({
    path: path,
    method: (init && init.method) || 'GET',
    body: typeof body === 'string' ? body : (body ? '[form]' : null),
  });
  const r = responder(path, init) || { status: 200, body: {} };
  const status = r.status === undefined ? 200 : r.status;
  const isJson = r.text === undefined;
  return {
    status: status,
    ok: status >= 200 && status < 300,
    headers: { get: function () { return isJson ? 'application/json' : 'text/plain'; } },
    json: async function () { return r.body; },
    text: async function () { return r.text; },
  };
};

// ---- expose the closure --------------------------------------------------
// The one edit to the source: an export line spliced in ahead of the IIFE's own
// close. If the file stops ending that way the harness stops silently working,
// so it is an error rather than a fallback.
const TAIL = '\n})();\n';
if (!SRC.endsWith(TAIL)) {
  throw new Error('app.js no longer ends with `})();` -- the harness must be updated');
}
const EXPORTS = '\n  globalThis.UI = { S: S, esc: esc, surAlt: surAlt,' +
  ' renderOriginal: renderOriginal, renderMarks: renderMarks,' +
  ' renderRestored: renderRestored, renderStats: renderStats,' +
  ' renderAudit: renderAudit, destroySession: destroySession, loadAudit: loadAudit,' +
  ' createSession: createSession, verifyChain: verifyChain, showError: showError,' +
  ' run: run };' + TAIL;
(0, eval)(SRC.slice(0, -TAIL.length) + EXPORTS);
if (!globalThis.UI || typeof globalThis.UI.renderOriginal !== 'function') {
  throw new Error('the export splice did not take');
}
// `health()` fires on load; drop its request so tests see only their own.
calls.length = 0;

globalThis.emit = function (obj) {
  process.stdout.write('<<<UI-RESULT>>>' + JSON.stringify(obj));
};
"""


def _run(tmp_path: Path, body: str) -> dict:
    """Evaluate ``body`` against the real ``app.js`` in node; return what it emitted."""
    script = tmp_path / "ui_harness.js"
    script.write_text(
        HARNESS
        + "\n(async () => {\n"
        + body
        + "\n})().catch((e) => { console.error((e && e.stack) || String(e)); process.exit(1); });\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [str(NODE), str(script), str(APP_JS)],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert proc.returncode == 0, f"node failed:\n{proc.stdout}\n{proc.stderr}"
    assert SENTINEL in proc.stdout, f"harness emitted nothing:\n{proc.stdout}\n{proc.stderr}"
    return json.loads(proc.stdout.split(SENTINEL, 1)[1])


def _det(**kw: object) -> str:
    """A detection literal for the harness, with the fields the UI reads defaulted."""
    d = {
        "start": -1,
        "end": -1,
        "category": "PII",
        "entity_type": "PERSON",
        "action": "PSEUDO",
        "score": 0.9,
        "surrogate": None,
    }
    d.update(kw)
    return json.dumps(d)


# ---------------------------------------------------------------------------
# renderOriginal -- panel 1
# ---------------------------------------------------------------------------
def test_render_original_splices_spans_from_the_highest_offset_down(tmp_path: Path) -> None:
    """Panel 1 is built back-to-front so earlier offsets stay valid as it grows.

    The detections arrive from the API in document order; the function sorts them
    descending and walks a cursor down from the end of the text. Sort the other way
    and the ``d.end > cursor`` guard silently drops every span but the first, which
    looks like "the detector missed it" rather than like a rendering bug.
    """
    text = "Bob & Carl <x>"
    dets = [
        _det(start=0, end=3, surrogate="Ann"),
        _det(start=6, end=10, surrogate="Bea"),
    ]
    out = _run(
        tmp_path,
        f"emit({{ html: UI.renderOriginal({json.dumps(text)}, [{dets[0]}, {dets[1]}]) }});",
    )["html"]
    title = f'PERSON {MID} PSEUDO {MID} score 0.90 {MID} '
    assert out == (
        f'<mark class="c-PII" title="{title}Ann">Bob</mark>'
        " &amp; "
        f'<mark class="c-PII" title="{title}Bea">Carl</mark>'
        " &lt;x&gt;"
    )


def test_render_original_escapes_the_title_attribute_it_builds(tmp_path: Path) -> None:
    """A surrogate is generated text and lands inside ``title="..."``.

    Quote and angle bracket both have to be neutralised there, and an attribute
    context fails differently from a text context: ``&quot;`` is what stops a fake
    name from closing the attribute and opening an event handler.
    """
    dets = _det(start=0, end=3, surrogate='" onmouseover=x')
    out = _run(tmp_path, f'emit({{ html: UI.renderOriginal("Bob", [{dets}]) }});')["html"]
    assert 'onmouseover=x' in out
    assert '" onmouseover' not in out
    assert "&quot; onmouseover=x" in out


def test_render_original_drops_spans_that_do_not_fit_the_text(tmp_path: Path) -> None:
    """Out-of-range offsets must produce no mark at all, not an empty or clipped one.

    ``String.prototype.slice`` clamps instead of throwing, so a negative start or an
    end past the end of the document renders quietly wrong. The filter is the only
    thing standing between a stale offset and a mark drawn over the wrong characters.
    """
    dets = ", ".join([_det(start=-1, end=2), _det(start=2, end=2), _det(start=1, end=9)])
    out = _run(tmp_path, f'emit({{ html: UI.renderOriginal("abc", [{dets}]) }});')["html"]
    assert out == "abc"


def test_render_original_skips_a_span_already_covered_by_a_later_one(tmp_path: Path) -> None:
    """Overlapping detections must mark the region once, not twice.

    Two recognizers can claim overlapping spans of the same text. Without the
    ``d.end > cursor`` guard the earlier one re-emits characters the later one
    already consumed, so panel 1 shows the overlap duplicated.
    """
    dets = ", ".join([_det(start=0, end=4), _det(start=2, end=6)])
    out = _run(tmp_path, f'emit({{ html: UI.renderOriginal("abcdef", [{dets}]) }});')["html"]
    assert out.count("<mark") == 1
    assert out.endswith(">cdef</mark>")
    assert out.startswith("ab<mark")


# ---------------------------------------------------------------------------
# renderMarks -- panel 2
# ---------------------------------------------------------------------------
def test_render_marks_colours_tokens_markers_and_pseudonyms_apart(tmp_path: Path) -> None:
    """Each of the three things panel 2 can highlight gets its own category class.

    A tokenised surrogate carries its category in the token itself, a
    ``[REDACTED_*]`` marker has none and is deliberately given ``RED``, and a
    pseudonym is only classifiable via the detection list. Collapse any of the three
    and the panel still highlights -- in the wrong colour, which is the entire signal
    the panel carries.
    """
    text = "[REDACTED_SSN] & Christina Palmer said [PII_PERSON_1a2b3c4d]"
    dets = _det(surrogate="Christina Palmer", category="PHI")
    out = _run(tmp_path, f"emit({{ html: UI.renderMarks({json.dumps(text)}, [{dets}]) }});")["html"]
    assert out == (
        '<mark class="tok c-RED">[REDACTED_SSN]</mark>'
        " &amp; "
        '<mark class="tok c-PHI">Christina Palmer</mark>'
        " said "
        '<mark class="tok c-PII">[PII_PERSON_1a2b3c4d]</mark>'
    )


def test_render_marks_bounds_the_entity_type_body_at_sixty_four_characters(
    tmp_path: Path,
) -> None:
    """The ``{0,63}`` bound in ``MARKS_SRC`` is load-bearing, so it is exercised.

    ``surrogates.py`` calls the bound "a security property, not style" and caps an
    entity type at 64 characters; the UI grammar mirrors it. A 64-character body is a
    token, a 65-character one is not -- which is the observable difference between
    the bounded spelling and the ``[A-Z0-9_]*`` it replaced.
    """
    ok = "[PII_" + "A" * 64 + "_1a2b3c4d]"
    too_long = "[PII_" + "A" * 65 + "_1a2b3c4d]"
    text = ok + " " + too_long
    out = _run(tmp_path, f"emit({{ html: UI.renderMarks({json.dumps(text)}, []) }});")["html"]
    assert out.count("<mark") == 1
    assert f'<mark class="tok c-PII">{ok}</mark>' in out
    assert out.endswith(" " + too_long)


# ---------------------------------------------------------------------------
# surAlt -- the pseudonym alternation
# ---------------------------------------------------------------------------
def test_sur_alt_orders_longest_first_and_escapes_regex_metacharacters(
    tmp_path: Path,
) -> None:
    """Longest-first, deduplicated, regex-quoted -- the same rule as ``restorer.py``.

    Alternation in JavaScript is first-match, not longest-match, so ordering *is* the
    correctness property. Ties break lexicographically only so the panel is stable
    between runs. ``reEsc`` matters because a generated fake may legitimately contain
    ``.`` or ``(``: unescaped, ``A.B`` would match ``AxB`` in the response text.
    """
    dets = ", ".join(
        _det(surrogate=s) for s in ["Ann", "Ann Smith", "Ann", "A.B(x)", None, "Bob", "Amy"]
    )
    out = _run(tmp_path, f"emit({{ alt: UI.surAlt([{dets}]) }});")["alt"]
    assert out == r"Ann Smith|A\.B\(x\)|Amy|Ann|Bob"


def test_a_short_pseudonym_does_not_bite_a_chunk_out_of_a_longer_one(tmp_path: Path) -> None:
    """The ordering above, observed where it actually matters: in panel 2's output.

    ``Ann`` and ``Ann Smith`` are both surrogates of the same run. Ordered shortest
    first, the alternation matches ``Ann`` and leaves `` Smith`` sitting outside the
    highlight as though it were ordinary document text.
    """
    dets = ", ".join([_det(surrogate="Ann"), _det(surrogate="Ann Smith")])
    out = _run(tmp_path, f'emit({{ html: UI.renderMarks("Ann Smith", [{dets}]) }});')["html"]
    assert out == '<mark class="tok c-PII">Ann Smith</mark>'


# ---------------------------------------------------------------------------
# renderRestored -- panel 4
# ---------------------------------------------------------------------------
def test_render_restored_marks_the_gap_between_two_aligned_literals(tmp_path: Path) -> None:
    """Restoration is a substitution, so the text between tokens survives verbatim.

    Panel 4 anchors on those literals and calls everything between them a restored
    region. Only the gap may be marked: mark the literals too and the panel claims the
    model's own prose came out of the vault.
    """
    out = _run(
        tmp_path,
        'emit({ html: UI.renderRestored("Hello [PII_PERSON_1a2b3c4d], bye.",'
        ' "Hello Jane Roe, bye.", []) });',
    )["html"]
    assert out == 'Hello <mark class="rest">Jane Roe</mark>, bye.'


def test_render_restored_does_not_mark_text_that_precedes_the_first_anchor(
    tmp_path: Path,
) -> None:
    """Only a gap *between* two literals is a restored region; a preamble is not.

    Nothing was substituted before the first token, so text the model added ahead of
    it came out of the model, not out of the vault. Marking it -- which is what
    dropping the ``i > 0`` test does -- makes panel 4 attribute the model's own words
    to the restorer, and every other assertion in this file still passes.
    """
    out = _run(
        tmp_path,
        'emit({ html: UI.renderRestored("Hi [PII_PERSON_1a2b3c4d]!", "Oh Hi Jane!", []) });',
    )["html"]
    assert out == 'Oh Hi <mark class="rest">Jane</mark>!'


def test_render_restored_trims_a_possessive_the_restorer_reattached(tmp_path: Path) -> None:
    """``restorer.py`` re-attaches ``'s`` to the restored value; the anchor must not keep it.

    The apostrophe belongs to the *literal* in the raw response but to the *value* in
    the restored text, so aligning on the untrimmed literal puts the possessive
    outside the mark and shifts the boundary by two characters.
    """
    out = _run(
        tmp_path,
        "emit({ html: UI.renderRestored(\"[PII_PERSON_1a2b3c4d]'s report\","
        " \"Jane Roe's report\", []) });",
    )["html"]
    assert out == '<mark class="rest">Jane Roe&#39;s</mark> report'


def test_render_restored_falls_back_to_plain_text_when_a_literal_moved(tmp_path: Path) -> None:
    """If the model rewrote the prose around a token, panel 4 must guess nothing.

    Alignment failing means the offsets are unknown, and a highlight drawn from
    unknown offsets is a false claim about which characters were vaulted. The bail-out
    is to render the restored text plainly -- still escaped.
    """
    out = _run(
        tmp_path,
        'emit({ html: UI.renderRestored("Hello [PII_PERSON_1a2b3c4d], bye.",'
        ' "Greetings <b>Jane Roe</b>, bye.", []) });',
    )["html"]
    assert out == "Greetings &lt;b&gt;Jane Roe&lt;/b&gt;, bye."


def test_render_restored_falls_back_when_the_response_carries_no_token(tmp_path: Path) -> None:
    """No token means no anchor: there is nothing to align on and nothing to mark.

    This is the ordinary case for a prompt the model answered without echoing any
    surrogate, and it must not produce a mark covering the whole answer.
    """
    out = _run(
        tmp_path,
        'emit({ html: UI.renderRestored("No tokens here at all.", "No tokens here at all.", []) });',
    )["html"]
    assert out == "No tokens here at all."


def test_the_tolerant_grammar_stops_absorbing_drift_after_four_spaces(tmp_path: Path) -> None:
    """The ``\\s{0,4}`` bound, observed as behaviour rather than read off the source.

    Up to four spaces of model-introduced drift are absorbed into the token, so the
    bracket in front of it is not left behind in the alignment anchor and panel 4
    aligns. At five the token match no longer reaches the bracket, the anchor keeps
    it, alignment fails, and the panel falls back to plain text. Unbound the
    quantifier and the five-space case starts aligning too -- which is the same edit
    that makes the matcher quadratic.
    """
    body = """
const raw = (n) => 'Hi [' + ' '.repeat(n) + 'PII_PERSON_1a2b3c4d] bye';
emit({
  four: UI.renderRestored(raw(4), 'Hi Jane bye', []),
  five: UI.renderRestored(raw(5), 'Hi Jane bye', []),
});
"""
    out = _run(tmp_path, body)
    assert '<mark class="rest">Jane</mark>' in out["four"]
    assert out["five"] == "Hi Jane bye"


def test_the_bounded_grammars_survive_a_pathological_whitespace_run(tmp_path: Path) -> None:
    """A 60k-character whitespace run must render in milliseconds, not seconds.

    ``TOLERANT_SRC`` runs over ``result.raw_llm_response`` -- model output, uncapped --
    and the shipped MockProvider echoes its input, so a document carrying a long
    whitespace run comes straight back. With ``\\s*`` the matcher is quadratic in the
    run length -- 645 ms at 20k characters, 2,560 ms at 40k, i.e. roughly 26 s on a
    128k run, a frozen tab. Measured through this harness at 60k: 1-2 ms bounded,
    5,994 ms with the quantifier unbound. The 1.5 s budget sits three orders of
    magnitude above the first and four times below the second.
    """
    body = """
const raw = 'x' + ' '.repeat(60000) + 'y';
const t0 = Date.now();
const html = UI.renderRestored(raw, raw, []);
emit({ ms: Date.now() - t0, len: html.length });
"""
    out = _run(tmp_path, body)
    assert out["len"] == 60002, "the pathological input was not actually rendered"
    assert out["ms"] < 1500, f"renderRestored took {out['ms']} ms on a 60k whitespace run"


# ---------------------------------------------------------------------------
# esc
# ---------------------------------------------------------------------------
def test_esc_neutralises_every_character_that_can_open_markup(tmp_path: Path) -> None:
    """The escape table, executed: five characters in, five entities out, one pass.

    ``test_api_ui_escaping.py`` proves the table has the right five keys by reading
    it. This proves the replacement actually happens and, in particular, that it is a
    single pass -- escaping ``&`` after ``<`` would turn ``&lt;`` into ``&amp;lt;``
    and render the tag as visible text on every panel.
    """
    payload = "<img src=x onerror=\"alert('1')\"> & done"
    out = _run(tmp_path, f"emit({{ esc: UI.esc({json.dumps(payload)}) }});")["esc"]
    assert out == (
        "&lt;img src=x onerror=&quot;alert(&#39;1&#39;)&quot;&gt; &amp; done"
    )


# ---------------------------------------------------------------------------
# renderStats
# ---------------------------------------------------------------------------
def test_render_stats_uses_the_pipeline_order_and_formats_durations(tmp_path: Path) -> None:
    """Stage timings read in pipeline order, not in whatever order the JSON arrived.

    ``STAT_ORDER`` is the pipeline's own sequence; keys the API adds later are
    appended rather than dropped, so a new stat still shows up. Durations render to
    one decimal with a unit, counts as integers -- the difference between "12.3 ms"
    and "12.345".
    """
    stats = {"total_ms": 12.34, "detect_ms": 1.0, "later_addition": 2.6}
    out = _run(tmp_path, f"UI.renderStats({json.dumps(stats)}); emit({{ html: el('stats').innerHTML }});")
    assert out["html"] == (
        '<span class="stat"><i>detect_ms</i>1.0 ms</span>'
        '<span class="stat"><i>total_ms</i>12.3 ms</span>'
        '<span class="stat"><i>later_addition</i>3</span>'
    )


# ---------------------------------------------------------------------------
# destroySession / loadAudit -- the panel that used to go blank
# ---------------------------------------------------------------------------
DESTROY_BODY = """
respond((path, init) => {
  if ((init && init.method) === 'DELETE') return { status: 204 };
  if (path.indexOf('/audit') === 0) {
    return { status: 200, body: { events: [
      { seq: 7, event_type: 'VAULT_DESTROY', entity_type: null, token_id: null, detail: { n: 3 } },
      { seq: 6, event_type: 'EGRESS_BLOCK', entity_type: 'SSN', token_id: 't1', detail: {} },
    ] } };
  }
  return { status: 200, body: {} };
});
UI.S.sessionId = 'sess-abc';
await UI.destroySession();
emit({
  requests: calls.map((c) => c.method + ' ' + c.path),
  last: UI.S.lastSessionId,
  current: UI.S.sessionId,
  audit: el('audit-body').innerHTML,
});
"""


def test_destroy_session_keeps_the_id_so_the_audit_tail_can_still_be_read(
    tmp_path: Path,
) -> None:
    """The destroy button's whole point is to show ``VAULT_DESTROY`` -- so it must load it.

    ``loadAudit`` bails on a null scope, and ``destroySession`` nulls ``S.sessionId``.
    Without the ``lastSessionId`` hand-off the refresh that follows the destroy makes
    no request at all, and the panel goes blank at exactly the moment the one event
    the button exists to demonstrate is appended to it.
    """
    out = _run(tmp_path, DESTROY_BODY)
    assert out["current"] is None, "the live session id must be dropped on destroy"
    assert out["last"] == "sess-abc"
    audit_requests = [r for r in out["requests"] if "/audit" in r]
    assert len(audit_requests) == 1, out["requests"]
    assert "session_id=sess-abc" in audit_requests[0]
    assert "user_id=demo-user" in audit_requests[0]
    assert any(r.startswith("DELETE /sessions/sess-abc") for r in out["requests"]), out["requests"]


def test_the_destroyed_session_row_is_rendered_and_flagged(tmp_path: Path) -> None:
    """The audit rows the destroy path loads are marked by severity, and escaped.

    ``VAULT_DESTROY`` gets ``warn-row`` and an ``EGRESS_BLOCK`` gets ``hot``; the two
    classes are the only visual difference between a routine event and a refusal.
    The serialised ``detail`` map is escaped like everything else -- it is the one
    column that carries arbitrary API-supplied content.
    """
    out = _run(tmp_path, DESTROY_BODY)
    assert '<tr class="warn-row"><td>7</td><td>VAULT_DESTROY</td>' in out["audit"]
    assert '<tr class="hot"><td>6</td><td>EGRESS_BLOCK</td><td>SSN</td><td>t1</td>' in out["audit"]
    assert "{&quot;n&quot;:3}" in out["audit"]


# ---------------------------------------------------------------------------
# createSession / run / verifyChain -- the orchestration
# ---------------------------------------------------------------------------
def test_create_session_stores_the_id_and_sends_the_owner_from_the_field(
    tmp_path: Path,
) -> None:
    """Every later call is scoped by these two values, so both are pinned at the source.

    ``user_id`` is the owner the API records at ``SESSION_CREATE`` and checks on every
    audit read and on destroy; it comes from the field, trimmed, with a documented
    default. ``session_id`` is what makes the vault readable. A session created under
    an untrimmed or defaulted owner is one the user can never destroy.
    """
    body = """
respond(() => ({ status: 200, body: { session_id: 'sess-1234567890ab', expires_at: 1700000000 } }));
el('user').value = '  alice  ';
await UI.createSession();
const sent = calls.filter((c) => c.path === '/sessions');
emit({ sent: sent, id: UI.S.sessionId, badge: el('session-badge').className });
"""
    out = _run(tmp_path, body)
    assert out["id"] == "sess-1234567890ab"
    assert out["badge"] == "badge ok"
    assert len(out["sent"]) == 1 and out["sent"][0]["method"] == "POST"
    assert json.loads(out["sent"][0]["body"]) == {"user_id": "alice"}


RUN_SETUP = """
const RESULT = {
  run_id: 'r-1', strategy: 'pseudonymize',
  detections: [{ start: 0, end: 3, category: 'PII', entity_type: 'PERSON',
                 action: 'PSEUDO', score: 0.9, surrogate: 'Ann' }],
  obfuscated_payload: 'Ann met [REDACTED_PERSON].',
  raw_llm_response: 'Ann met Carl.',
  restored_text: 'Bob met Carl.',
  stats: { total_ms: 5.5 },
};
respond((path, init) => {
  const m = (init && init.method) || 'GET';
  if (m === 'POST' && path === '/documents') return { status: 200, body: { doc_id: 'doc-1' } };
  if (path.indexOf('/documents/doc-1/text') === 0) {
    return { status: 200, body: { text: 'Bob met Carl.', chars: 13 } };
  }
  if (path === '/pipeline/run') return PIPELINE_REPLY(RESULT);
  if (path.indexOf('/audit') === 0) return { status: 200, body: { events: [] } };
  return { status: 200, body: {} };
});
UI.S.sessionId = 'sess-1';
el('prompt').value = 'Summarise';
el('strategy').value = 'pseudonymize';
el('file').files = [{ name: 'note.txt', size: 3, lastModified: 11 }];
"""

RUN_BODY = RUN_SETUP + """
await UI.run();
await UI.run();
emit({
  requests: calls.map((c) => c.method + ' ' + c.path),
  pipeline: calls.filter((c) => c.path === '/pipeline/run').map((c) => c.body),
  p1: el('p1').innerHTML, p2: el('p2').innerHTML,
  p3: el('p3').innerHTML, p4: el('p4').innerHTML,
  counters: ['c1', 'c2', 'c3', 'c4'].map((c) => el(c).textContent),
  stats: el('stats').innerHTML,
  banner: el('banner').innerHTML,
  auditRun: el('audit-run').textContent,
  busy: UI.S.busy,
});
"""


def test_a_run_fills_all_four_panels_from_one_pipeline_response(tmp_path: Path) -> None:
    """The demo's whole story in one call: original, obfuscated, raw, restored.

    Each panel is fed a different field of the response, and swapping any two is a
    silent and catastrophic error in a demo whose point is that panel 2 never contains
    what panel 1 contains. The counters are pinned alongside because they are what a
    reviewer reads to confirm the panels are not showing the same string twice.
    """
    out = _run(tmp_path, RUN_BODY.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }"))
    title = f"PERSON {MID} PSEUDO {MID} score 0.90 {MID} Ann"
    assert out["p1"] == f'<mark class="c-PII" title="{title}">Bob</mark> met Carl.'
    assert out["p2"] == (
        '<mark class="tok c-PII">Ann</mark> met '
        '<mark class="tok c-RED">[REDACTED_PERSON]</mark>.'
    )
    assert out["p3"] == "Ann met Carl."
    assert out["p4"] == '<mark class="rest">Bob</mark> met Carl.'
    assert out["counters"] == ["13 chars " + MID + " 1 spans", "26 chars", "13 chars", "13 chars"]
    assert out["stats"] == '<span class="stat"><i>total_ms</i>5.5 ms</span>'
    assert out["banner"] == f"<b>RUN_OK</b> run_id r-1 {MID} strategy pseudonymize"
    assert out["auditRun"] == "run_id r-1"
    assert out["busy"] is False, "the buttons must be re-enabled after the run"


def test_a_run_sends_the_session_document_and_strategy_it_was_configured_with(
    tmp_path: Path,
) -> None:
    """The pipeline request carries the credentials the run is scoped by.

    Losing ``session_id`` from this body does not fail loudly -- it fails as an
    unscoped run against a vault the caller never proved it owns. The upload is also
    checked for reuse: the same file must not be re-uploaded on a second run, or every
    click leaves another copy of the document on the server.
    """
    out = _run(tmp_path, RUN_BODY.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }"))
    assert len(out["pipeline"]) == 2
    assert json.loads(out["pipeline"][0]) == {
        "session_id": "sess-1",
        "user_id": "demo-user",
        "doc_id": "doc-1",
        "prompt": "Summarise",
        "strategy": "pseudonymize",
    }
    uploads = [r for r in out["requests"] if r == "POST /documents"]
    assert len(uploads) == 1, f"the document was re-uploaded: {out['requests']}"
    assert any("run_id=r-1" in r for r in out["requests"]), out["requests"]


def test_a_blocked_run_shows_the_fail_closed_banner_and_still_refreshes_the_audit(
    tmp_path: Path,
) -> None:
    """The egress refusal is the headline control, so the UI must say what happened.

    "No provider call was made" is the claim the gate exists to support, and the audit
    tail has to be reloaded to show the ``EGRESS_BLOCK`` row that proves it -- that
    reload is on the error path, which nothing had ever executed.
    """
    out = _run(
        tmp_path,
        RUN_BODY.replace(
            "PIPELINE_REPLY(RESULT)",
            "{ status: 403, body: { code: 'EGRESS_BLOCKED', detail: 'SSN in payload' } }",
        ),
    )
    assert out["banner"].startswith("<b>EGRESS_BLOCKED</b> FAIL-CLOSED")
    assert "No provider call was made" in out["banner"]
    assert "SSN in payload" in out["banner"]
    assert out["p4"] == "", "no panel may show pipeline output for a refused run"
    audit = [r for r in out["requests"] if "/audit" in r]
    assert audit, f"the audit tail was not refreshed after the block: {out['requests']}"
    assert all("run_id=" not in r for r in audit), audit


def test_each_error_code_gets_its_own_explanation(tmp_path: Path) -> None:
    """Three failures a reviewer will actually hit, each explained differently.

    Collapsing them to the raw ``detail`` is the easy regression: the banner still
    turns red and still names the code, so nothing else notices, but the one sentence
    that tells the reviewer *why* -- the key is gone, the address is throttled -- is
    lost.
    """
    body = """
const seen = {};
for (const code of ['SESSION_EXPIRED', 'RATE_LIMITED', 'EGRESS_BLOCKED', 'HTTP_500']) {
  UI.showError({ code: code, detail: 'raw detail' });
  seen[code] = el('banner').innerHTML;
}
emit({ seen: seen, cls: el('banner').className });
"""
    out = _run(tmp_path, body)["seen"]
    assert "the vault cannot be read" in out["SESSION_EXPIRED"]
    assert "too many requests from this address" in out["RATE_LIMITED"]
    assert "the egress gate refused" in out["EGRESS_BLOCKED"]
    assert out["HTTP_500"] == "<b>HTTP_500</b> raw detail"
    assert len({out[k] for k in out}) == 4


def test_a_run_with_nothing_to_run_on_is_refused_before_any_request(tmp_path: Path) -> None:
    """Missing prompt and missing file are caught in the browser, not by the API.

    Both are the first thing a reviewer hits, and both must say which input is
    missing. Letting either through costs an upload or a pipeline call that can only
    fail, and the failure it produces names neither field.
    """
    body = RUN_SETUP + """
const out = {};
el('prompt').value = '   ';
await UI.run();
out.noPrompt = el('banner').innerHTML;
el('prompt').value = 'Summarise';
el('file').files = [];
await UI.run();
out.noFile = el('banner').innerHTML;
out.requests = calls.length;
emit(out);
"""
    out = _run(tmp_path, body.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }"))
    assert out["noPrompt"] == "<b>NO_PROMPT</b> Enter a prompt."
    assert out["noFile"] == "<b>NO_FILE</b> Choose a document first (fixtures/ or any file)."
    assert out["requests"] == 0, "a refused run must not reach the network"


def test_choosing_a_different_file_invalidates_the_upload_cache(tmp_path: Path) -> None:
    """The other half of the upload cache: picking a new file must force a new upload.

    The cache keyed on name/size/mtime is what stops a second run re-uploading, and
    this listener is what stops it from serving the *previous* document after the user
    picks another one. Without it the run silently pipelines the wrong file, which the
    panels cannot show because they render whatever the server returned for that id.
    """
    body = RUN_SETUP + """
await UI.run();
fire('file', 'change');
const cleared = { doc: UI.S.docId, key: UI.S.uploadKey };
el('file').files = [{ name: 'other.txt', size: 9, lastModified: 22 }];
await UI.run();
emit({ cleared: cleared, uploads: calls.filter((c) => c.path === '/documents').length });
"""
    out = _run(tmp_path, body.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }"))
    assert out["cleared"] == {"doc": None, "key": None}
    assert out["uploads"] == 2


def test_the_fixture_picker_carries_its_category_across(tmp_path: Path) -> None:
    """Choosing a bundled fixture sets the category the detector will be told to use.

    The category drives which entity set applies, so a fixture selected without it is
    scanned under the wrong policy. An option carrying no category must leave the
    field alone rather than blanking it.
    """
    body = """
el('category').value = 'legal';
fire('fixture', 'change', { target: { selectedOptions: [{ dataset: { cat: 'medical' } }] } });
const chosen = el('category').value;
fire('fixture', 'change', { target: { selectedOptions: [{ dataset: {} }] } });
emit({ chosen: chosen, afterBlank: el('category').value });
"""
    out = _run(tmp_path, body)
    assert out["chosen"] == "medical"
    assert out["afterBlank"] == "medical"


def test_the_fixture_preset_names_the_path_the_file_picker_still_needs(
    tmp_path: Path,
) -> None:
    """The dropdown cannot upload, so it has to say which file to hand the picker.

    Build doc section 9.10 asks for an "upload fixture dropdown". This is not one:
    a browser cannot read a path off disk, and nothing serves ``fixtures/`` over
    HTTP -- ``_mount_ui`` mounts ``secure_context_pipeline/ui/`` alone, measured
    ``GET /fixtures/medical_note.txt`` -> 404. Labelled "fixture" and wired to set
    ``doc_category`` and nothing else, it did half the job in silence: selecting
    ``medical_note.txt`` and pressing Run issued **zero** requests and answered
    ``NO_FILE``, on the first control a reviewer touches. Reselecting the blank
    option must put the idle text back, or the page goes on naming a file the user
    has just deselected.
    """
    body = """
const out = { idle: el('fixture-hint').textContent };
fire('fixture', 'change', { target: { selectedOptions: [
  { value: 'medical_note.txt', dataset: { cat: 'medical' } }] } });
out.picked = el('fixture-hint').textContent;
out.category = el('category').value;
fire('fixture', 'change', { target: { selectedOptions: [{ value: '', dataset: {} }] } });
out.cleared = el('fixture-hint').textContent;
emit(out);
"""
    out = _run(tmp_path, body)
    assert out["picked"] == "now pick fixtures/medical_note.txt with the file button"
    assert out["category"] == "medical", "the preset half must keep working"
    assert "not an upload" in out["idle"], out["idle"]
    assert "doc_category" in out["idle"], out["idle"]
    assert out["cleared"] == out["idle"], "deselecting must not leave a stale path up"


def test_every_element_the_ui_addresses_exists_in_the_page() -> None:
    """``$('...')`` in ``app.js`` and ``id="..."`` in ``index.html`` have to agree.

    Nothing checked that, and the harness above structurally cannot: its DOM stub
    mints an element for any id asked of it, which is what makes the render helpers
    drivable and also what makes a typo invisible to every test in this file. In a
    browser ``$('fixture-hnt')`` is ``null`` and the first property access on it
    throws, taking the rest of that listener with it -- and the ``change`` listener
    is where the fixture preset now lives, so the failure would be "the dropdown
    does nothing", which is exactly the defect this pair of files was just fixed
    for. Static, so it does not need node; it sits here because it guards a
    behaviour rather than the escaping control ``test_api_ui_escaping.py`` owns.
    """
    addressed = set(re.findall(r"\$\('([^']+)'\)", APP_JS.read_text(encoding="utf-8")))
    declared = set(re.findall(r'\bid="([^"]+)"', INDEX_HTML.read_text(encoding="utf-8")))
    assert addressed, "the id extraction found nothing -- the pattern no longer matches"
    assert "fixture-hint" in addressed, "the preset hint is no longer wired"
    assert addressed <= declared, sorted(addressed - declared)


def test_enter_in_the_prompt_box_starts_a_run_and_other_keys_do_not(tmp_path: Path) -> None:
    """Enter submits; every other key must not fire a pipeline run per keystroke.

    Dropping the key test turns each character typed into the prompt into an upload
    and a pipeline call -- the most expensive possible way to break a demo, and one no
    static reading of the file would catch.
    """
    body = RUN_SETUP + """
fire('prompt', 'keydown', { key: 'a' });
await settle();
const afterLetter = calls.length;
fire('prompt', 'keydown', { key: 'Enter' });
await settle();
emit({ afterLetter: afterLetter, ran: calls.filter((c) => c.path === '/pipeline/run').length });
"""
    out = _run(tmp_path, body.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }"))
    assert out["afterLetter"] == 0
    assert out["ran"] == 1


def test_verify_chain_reports_a_broken_hash_chain_as_broken(tmp_path: Path) -> None:
    """The tamper-evidence badge must not read VALID when the chain says otherwise.

    This badge is the only place the audit log's integrity check surfaces, and its two
    states are one ternary apart.
    """
    body = """
const out = {};
for (const valid of [true, false]) {
  respond(() => ({ status: 200, body: { valid: valid, length: 12 } }));
  await UI.verifyChain();
  out[String(valid)] = { text: el('verify-badge').textContent, cls: el('verify-badge').className };
}
emit(out);
"""
    out = _run(tmp_path, body)
    assert out["true"] == {"text": f"chain: VALID {MID} 12 events", "cls": "badge ok"}
    assert out["false"] == {"text": f"chain: BROKEN {MID} 12 events", "cls": "badge err"}


def test_destroy_with_no_live_session_sends_no_delete(tmp_path: Path) -> None:
    """Destroy is a no-op before a session exists, not a DELETE with a null id.

    Without the guard the button issues ``DELETE /sessions/null``, which is both a
    wasted write against the per-address rate limiter and a 4xx dressed up as a
    failed erasure -- the one operation a reviewer must be able to trust.
    """
    body = """
UI.S.sessionId = null;
await UI.destroySession();
emit({ requests: calls.map((c) => c.method + ' ' + c.path), banner: el('banner').innerHTML });
"""
    out = _run(tmp_path, body)
    assert out["requests"] == []
    assert out["banner"] == "<b>NO_SESSION</b> Nothing to destroy."


def test_load_audit_makes_no_request_when_no_session_has_ever_existed(tmp_path: Path) -> None:
    """Before the first session there is no scope to ask about, so nothing is asked.

    The audit endpoint requires a session id; sending ``undefined`` would spend a
    rate-limit budget on a request that can only 4xx. This is the guard the fallback
    above deliberately does *not* remove.
    """
    body = """
UI.S.sessionId = null;
UI.S.lastSessionId = null;
await UI.loadAudit();
emit({ requests: calls.map((c) => c.path), audit: el('audit-body').innerHTML });
"""
    out = _run(tmp_path, body)
    assert out["requests"] == []
    assert out["audit"] == ""


def test_a_failed_audit_lookup_empties_the_panel_instead_of_stranding_it(
    tmp_path: Path,
) -> None:
    """A rejected audit read must clear the table, not leave the previous run's rows up.

    ``loadAudit`` is called again after ``EGRESS_BLOCKED`` and ``SESSION_EXPIRED``,
    when the lookup itself may be refused. Stale rows under a fresh error banner read
    as though the failed run had produced them.
    """
    body = """
respond((path) => {
  if (path.indexOf('/audit') === 0) return { status: 403, body: { code: 'FORBIDDEN', detail: 'no' } };
  return { status: 200, body: {} };
});
UI.S.sessionId = 'sess-xyz';
UI.renderAudit([{ seq: 1, event_type: 'RUN_START', detail: {} }]);
const before = el('audit-body').innerHTML;
await UI.loadAudit();
emit({ before: before, after: el('audit-body').innerHTML });
"""
    out = _run(tmp_path, body)
    assert "RUN_START" in out["before"]
    assert out["after"] == '<tr><td colspan="5" class="muted">no events</td></tr>'
