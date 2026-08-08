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
from html.parser import HTMLParser
from pathlib import Path

import pytest

from secure_context_pipeline.detection.registry import EntityRegistry
from secure_context_pipeline.models import DOC_CATEGORIES

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_JS = REPO_ROOT / "secure_context_pipeline" / "ui" / "app.js"
INDEX_HTML = REPO_ROOT / "secure_context_pipeline" / "ui" / "index.html"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

#: Separates the harness's JSON result from anything the file may print.
SENTINEL = "<<<UI-RESULT>>>"
#: U+00B7, the separator ``renderOriginal`` builds its title attribute with.
MID = "·"
#: U+2014, the body ``resetRun`` puts back in a panel that holds nothing. It is
#: index.html's own placeholder for panels 2 to 4, kept in ``app.js`` so the reset
#: and the first paint are one value -- the same arrangement as ``HINT_IDLE``.
IDLE = "—"

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
// `append` was a no-op, so the multipart upload was the one request in the file whose
// CONTENT no test could see -- and `doc_category` travels in it. Files are recorded by
// name only; nothing here needs their bytes.
globalThis.FormData = class {
  constructor() { this.parts = []; }
  append(k, v) { this.parts.push([k, typeof v === 'string' ? v : '[file]']); }
};

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
    form: (body && body.parts) || null,
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
  ' scopedOut: scopedOut, run: run };' + TAIL;
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
        + "\n})().catch((e) => {\n"
        + "  console.error((e && e.stack) || String(e));\n"
        + "  process.exit(1);\n"
        + "});\n",
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
    title = f"PERSON {MID} PSEUDO {MID} score 0.90 {MID} "
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
    assert "onmouseover=x" in out
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
        'emit({ html: UI.renderRestored("[PII_PERSON_1a2b3c4d]\'s report",'
        ' "Jane Roe\'s report", []) });',
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
        'emit({ html: UI.renderRestored('
        '"No tokens here at all.", "No tokens here at all.", []) });',
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
    assert out == ("&lt;img src=x onerror=&quot;alert(&#39;1&#39;)&quot;&gt; &amp; done")


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
    out = _run(
        tmp_path, f"UI.renderStats({json.dumps(stats)}); emit({{ html: el('stats').innerHTML }});"
    )
    assert out["html"] == (
        '<span class="stat"><i>detect_ms</i>1.0 ms</span>'
        '<span class="stat"><i>total_ms</i>12.3 ms</span>'
        '<span class="stat"><i>later_addition</i>3</span>'
    )


# ---------------------------------------------------------------------------
# destroySession / loadAudit -- the panel that used to go blank
# ---------------------------------------------------------------------------
#: What ``DELETE /sessions`` records when it really did erase something, copied from
#: the live API: ``detail`` always carries ``existed`` and ``source``. Every scenario
#: below that expects the destroy path to make its claim has to answer the
#: confirmation probe with this, because 204 does not say it -- see
#: ``destroyConfirmed`` in ``app.js`` and the two tests at the bottom of this section.
DESTROYED_ROW = (
    "{ seq: 9, event_type: 'VAULT_DESTROY', entity_type: null, token_id: null,"
    " detail: { existed: 1, source: 'api_logout' } }"
)
#: The same row for a delete that touched nothing -- a non-owner, an unknown id, an
#: already-expired session. Measured on the live API: ``DELETE /sessions/<id>?
#: user_id=bob-demo`` against a session owned by ``alice-demo`` answers 204 and writes
#: exactly this.
UNTOUCHED_ROW = (
    "{ seq: 9, event_type: 'VAULT_DESTROY', entity_type: null, token_id: null,"
    " detail: { existed: 0, source: 'api_logout' } }"
)
#: The confirmation probe is a different query from the tail the panel renders: it
#: filters by event type. Scenarios script the two separately.
PROBE_MARK = "event_type=VAULT_DESTROY"

DESTROY_BODY = (
    """
respond((path, init) => {
  if ((init && init.method) === 'DELETE') return { status: 204 };
  if (path.indexOf('/audit') === 0) {
    // The destroy probe. Answered with the row the live API writes for a real
    // erasure; the tail below is a separate query and is unchanged.
    if (path.indexOf('"""
    + PROBE_MARK
    + """') >= 0) return { status: 200, body: { events: ["""
    + DESTROYED_ROW
    + """] } };
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
)


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
    # Was ``len([r for r in requests if "/audit" in r]) == 1``. The destroy path now
    # makes two audit reads and they are different queries -- the confirmation probe
    # (filtered to VAULT_DESTROY) and the tail this test is about -- so the count is
    # narrowed to the tail rather than relaxed. Both halves of the original
    # assertion, "exactly one tail load, scoped to the retained id", still hold.
    audit_requests = [r for r in out["requests"] if "/audit" in r and PROBE_MARK not in r]
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


def _destroy_scenario(probe: str, *, retype: str = "") -> str:
    """Create a session as ``alice-demo``, optionally retype the field, then destroy.

    ``probe`` is the reply the confirmation read gets; ``retype`` is JS run between
    the create and the destroy. Only the destroy's own requests are reported: the
    create's are dropped so the assertions read against one action.
    """
    return (
        """
respond((path, init) => {
  const m = (init && init.method) || 'GET';
  if (path === '/sessions' && m === 'POST') {
    return { status: 200, body: { session_id: 'sess-OWNED-0001', expires_at: 1700000000 } };
  }
  if (m === 'DELETE') return { status: 204 };
  if (path.indexOf('"""
        + PROBE_MARK
        + """') >= 0) return __PROBE__;
  if (path.indexOf('/audit') === 0) return { status: 200, body: { events: [] } };
  return { status: 200, body: {} };
});
el('user').value = 'alice-demo';
await UI.createSession();
"""
        + retype
        + """
el('p1').innerHTML = 'Patient name: David Ochoa';
el('p4').innerHTML = '<mark class="rest">David Ochoa</mark> has MRN 9224297.';
calls.length = 0;
await UI.destroySession();
emit({
  requests: calls.map((c) => c.method + ' ' + c.path),
  current: UI.S.sessionId, last: UI.S.lastSessionId, owner: UI.S.userId,
  badge: el('session-badge').textContent, banner: el('banner').innerHTML,
  p1: el('p1').innerHTML, p4: el('p4').innerHTML,
});
"""
    ).replace("__PROBE__", probe)


def test_destroy_addresses_the_owner_the_session_was_created_for_not_the_field(
    tmp_path: Path,
) -> None:
    """Retyping ``user_id`` mid-demo pointed Destroy at a session that user does not own.

    ``DELETE /sessions`` is owner-scoped and *silent* about it: a non-owner gets the
    same 204 as a real erasure, deliberately, so that the status code is not an
    ownership oracle. Reading the field at destroy time therefore produced the worst
    reachable outcome -- measured against the live API, a session created for
    ``alice-demo`` and destroyed as ``bob-demo`` answered 204, kept its key and its
    vault rows, and then ran again with 200 ``RUN_OK`` under a badge reading "session
    destroyed". The owner is pinned at create instead, where the field and the session
    are the same thing, and the confirmation read is scoped by it too.
    """
    out = _run(tmp_path, _destroy_scenario(
        "{ status: 200, body: { events: [" + DESTROYED_ROW + "] } }",
        retype="el('user').value = 'bob-demo';",
    ))
    assert out["owner"] == "alice-demo"
    deletes = [r for r in out["requests"] if r.startswith("DELETE ")]
    assert len(deletes) == 1, out["requests"]
    assert "user_id=alice-demo" in deletes[0], deletes
    assert "bob-demo" not in deletes[0], "the destroy followed the field, not the session"
    probes = [r for r in out["requests"] if PROBE_MARK in r]
    assert len(probes) == 1 and "user_id=alice-demo" in probes[0], out["requests"]
    # The tail is proved against the same recorded owner, or it reads as zero events
    # at the moment it is the evidence.
    tails = [r for r in out["requests"] if "/audit" in r and PROBE_MARK not in r]
    assert tails and all("user_id=alice-demo" in r for r in tails), out["requests"]


def test_destroy_does_not_claim_an_erasure_the_audit_log_does_not_confirm(
    tmp_path: Path,
) -> None:
    """204 is not proof, so it must not be reported as proof.

    ``DELETE /sessions`` answers 204 for an unknown id, an expired session, an
    already-destroyed one and someone else's alike -- it carries no information at
    all. This page treated it as proof of erasure and printed "Session key and vault
    rows are gone -- irreversibly" over a session that was still live. The route
    records the outcome where it can be read instead: ``VAULT_DESTROY`` with
    ``existed``. With ``existed=0`` nothing was destroyed, and nothing may be claimed:
    the session stays in ``S`` so Run still works and the reviewer can see for
    themselves, the badge keeps naming it, and the panels keep their contents --
    wiping the screen is itself a claim that the data is gone.
    """
    out = _run(tmp_path, _destroy_scenario(
        "{ status: 200, body: { events: [" + UNTOUCHED_ROW + "] } }"
    ))
    assert "DESTROY_NOT_CONFIRMED" in out["banner"], out["banner"]
    assert "existed=0" in out["banner"], out["banner"]
    assert "irreversibly" not in out["banner"], out["banner"]
    assert "STILL LIVE" in out["banner"], out["banner"]
    assert out["current"] == "sess-OWNED-0001", "an undestroyed session must stay live"
    assert out["badge"] == "destroy NOT confirmed \u2014 session may still be live", out["badge"]
    assert "David Ochoa" in out["p4"], "clearing the screen asserts the erasure too"
    assert "David Ochoa" in out["p1"]


def test_destroy_says_so_when_the_confirmation_read_itself_fails(tmp_path: Path) -> None:
    """A probe that could not be answered is not a "no" -- and it is not a "yes" either.

    The third outcome: the DELETE was accepted but the audit read that would prove the
    erasure did not come back. Reporting that as a destruction is the original defect;
    reporting it as a failed destroy would be a different false statement. It is
    reported as unconfirmed, and the state is left exactly where it was.
    """
    out = _run(tmp_path, _destroy_scenario(
        "{ status: 500, body: { code: 'AUDIT_DOWN', detail: 'no' } }"
    ))
    assert "DESTROY_UNCONFIRMED" in out["banner"], out["banner"]
    assert "irreversibly" not in out["banner"], out["banner"]
    assert out["current"] == "sess-OWNED-0001"
    assert out["badge"] == "destroy NOT confirmed \u2014 session may still be live", out["badge"]


def test_a_confirmed_destroy_still_makes_the_whole_irreversibility_claim(
    tmp_path: Path,
) -> None:
    """The claim is the demo's best moment; it is made in full, once it is true.

    ``existed=1`` is the log saying a live, owned session key was popped and its vault
    rows dropped -- and that read is owner-proved against ``SESSION_CREATE``, so a
    caller who could not destroy the session cannot fake the confirmation either. On
    that branch every consequence still follows: the id is dropped, the badge flips,
    the screen is cleared, and the banner says "irreversibly" without hedging.
    """
    out = _run(tmp_path, _destroy_scenario(
        "{ status: 200, body: { events: [" + DESTROYED_ROW + "] } }"
    ))
    assert "VAULT_DESTROYED" in out["banner"], out["banner"]
    assert "irreversibly" in out["banner"], out["banner"]
    assert "existed=1" in out["banner"], out["banner"]
    assert out["current"] is None and out["last"] == "sess-OWNED-0001"
    assert out["badge"] == "session destroyed"
    assert "David Ochoa" not in out["p4"] and out["p4"] == IDLE


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
// `doc_category` is a required input, not an optional one: unset, `ensureDoc` refuses
// the run with NO_CATEGORY before any request, because unset silently switches the
// `only_in_doc_categories` rule sets off. Every scenario below that expects a run to
// proceed therefore has to supply one, exactly as it supplies a prompt and a file.
el('category').value = 'legal';
"""

RUN_BODY = (
    RUN_SETUP
    + """
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
)


def test_a_run_fills_all_four_panels_from_one_pipeline_response(tmp_path: Path) -> None:
    """The demo's whole story in one call: original, obfuscated, raw, restored.

    Each panel is fed a different field of the response, and swapping any two is a
    silent and catastrophic error in a demo whose point is that panel 2 never contains
    what panel 1 contains. The counters are pinned alongside because they are what a
    reviewer reads to confirm the panels are not showing the same string twice.
    """
    out = _run(
        tmp_path, RUN_BODY.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }")
    )
    title = f"PERSON {MID} PSEUDO {MID} score 0.90 {MID} Ann"
    assert out["p1"] == f'<mark class="c-PII" title="{title}">Bob</mark> met Carl.'
    assert out["p2"] == (
        '<mark class="tok c-PII">Ann</mark> met <mark class="tok c-RED">[REDACTED_PERSON]</mark>.'
    )
    # Was ``== "Ann met Carl."``, i.e. panel 3 carrying no highlighting at all. That
    # is the one panel a reviewer reads as the provider's-eye view, and under
    # pseudonymization an unmarked surrogate is a realistic fake read as a real
    # value -- the failure README line 2069 calls "the dangerous one". The routing
    # this test exists to pin is unchanged and still asserted: the marked text is
    # ``raw_llm_response``'s and no other field's.
    assert out["p3"] == '<mark class="tok c-PII">Ann</mark> met Carl.'
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
    out = _run(
        tmp_path, RUN_BODY.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }")
    )
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
    # Was ``out["p4"] == ""``. The requirement in the message is unchanged and is
    # what the new value asserts more strongly: "" was merely "never written", and it
    # held only because this scenario's first run also failed. A run that follows a
    # SUCCESSFUL one left panels 2-4, the stats row and the audit-run label showing
    # that earlier run beside panel 1's new document -- see the refused-run test at
    # the bottom of this module, which is the case this one could not see.
    assert out["p4"] == IDLE, "no panel may show pipeline output for a refused run"
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
    body = (
        RUN_SETUP
        + """
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
    )
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
    body = (
        RUN_SETUP
        + """
await UI.run();
fire('file', 'change');
const cleared = { doc: UI.S.docId, key: UI.S.uploadKey };
el('file').files = [{ name: 'other.txt', size: 9, lastModified: 22 }];
await UI.run();
emit({ cleared: cleared, uploads: calls.filter((c) => c.path === '/documents').length });
"""
    )
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


# ---------------------------------------------------------------------------
# doc_category -- the input that decides which rule sets run
# ---------------------------------------------------------------------------
def test_the_category_control_offers_no_selectable_uncategorised_state() -> None:
    """``(none)`` was an option, it was the default, and it is not a neutral choice.

    ``entities.yaml`` gates entities behind ``only_in_doc_categories``, so an
    unclassified document is scanned with those rule sets **off**. Measured on
    ``fixtures/financial_disclosure.txt`` left at ``(none)``: a green ``RUN_OK``,
    ``entities_detected`` 26, and the outbound payload carrying "Brokerage account
    [FIN_ACCOUNT_NUMBER_...] at Ridgeline Securities, balance $2,200,613.34." with the
    whole wire ledger, dates and amounts, verbatim. The empty option survives as a
    ``disabled`` placeholder rather than being deleted, because a ``<select>`` with no
    empty option selects its FIRST one -- which would submit ``medical`` for every
    document nobody classified, trading a silent omission for a silent wrong answer.
    """
    src = INDEX_HTML.read_text(encoding="utf-8")
    assert '<select id="category">' in src, "the category control was renamed"
    block = src.split('<select id="category">', 1)[1].split("</select>", 1)[0]
    options = re.findall(r"<option\s*([^>]*)>([^<]*)</option>", block)
    assert len(options) == len(DOC_CATEGORIES) + 1, options
    placeholder, *real = options
    assert re.search(r'value=""', placeholder[0]), placeholder
    assert "disabled" in placeholder[0], "the uncategorised state is still submittable"
    assert "selected" in placeholder[0], "the control would default to a real category"
    values = [re.search(r'value="([^"]*)"', attrs).group(1) for attrs, _ in real]
    assert set(values) == set(DOC_CATEGORIES), values
    for attrs, label in real:
        assert "disabled" not in attrs and "selected" not in attrs, label


def test_a_run_without_a_doc_category_is_refused_before_any_request(tmp_path: Path) -> None:
    """The block half of the fix: Run must not proceed on an unset category.

    ``NO_FILE`` is the model for the message -- it names the control and says what to
    do with it -- because the reviewer meets both preflights the same way. Refused
    before any request, so an uncategorised document is never even uploaded: the
    upload is where ``doc_category`` is recorded, and a document stored without one
    stays scoped wrong for every later run against that id.
    """
    body = (
        RUN_SETUP
        + """
el('category').value = '';
await UI.run();
emit({
  banner: el('banner').innerHTML,
  requests: calls.length,
  note: el('scope-note').hidden,
});
"""
    )
    out = _run(tmp_path, body.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }"))
    assert out["banner"].startswith("<b>NO_CATEGORY</b> Choose a doc_category first")
    assert "(medical, legal, financial or general)" in out["banner"]
    assert "which rule sets run" in out["banner"]
    assert out["requests"] == 0, "an uncategorised document must not even be uploaded"
    assert out["note"] is True, "there is no run to describe"


def test_the_upload_carries_the_category_the_run_was_configured_with(tmp_path: Path) -> None:
    """The field only matters if it reaches ``POST /documents``, so read it off the wire.

    It used to be appended conditionally (``if (cat)``), which is the same silence the
    placeholder above removes: the request simply went without it and the server
    stored the document uncategorised. Now the value is guaranteed by the preflight
    and always sent.
    """
    body = (
        RUN_SETUP
        + """
el('category').value = 'financial';
await UI.run();
emit({ uploads: calls.filter((c) => c.path === '/documents').map((c) => c.form) });
"""
    )
    out = _run(tmp_path, body.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }"))
    assert len(out["uploads"]) == 1, out["uploads"]
    assert ["doc_category", "financial"] in out["uploads"][0], out["uploads"][0]


def test_a_run_names_the_rule_sets_its_category_switched_off(tmp_path: Path) -> None:
    """The half requiring a category does NOT fix: a category that is simply wrong.

    Measured on ``fixtures/legal_memo.txt`` submitted as ``medical``, all five
    ``CASE_STRATEGY`` sentences reach the provider verbatim -- "We are prepared to
    accept a structured payout over thirty-six months." among them -- while
    ``entities_detected`` reads **38**, exactly what the correct ``legal`` run reports.
    Every number on the page rated the weakened run equal or better and nothing named
    the rules that had been switched off. The expected strings here are hand-written;
    ``test_the_scoped_rule_map_mirrors_the_registry`` below is what keeps the mapping
    they encode tied to ``entities.yaml``.
    """
    body = (
        RUN_SETUP
        + """
el('category').value = 'medical';
await UI.run();
const first = { text: el('scope-note').textContent, hidden: el('scope-note').hidden };
el('category').value = 'legal';
el('file').files = [{ name: 'memo.txt', size: 9, lastModified: 12 }];
await UI.run();
emit({ first: first, second: el('scope-note').textContent });
"""
    )
    out = _run(tmp_path, body.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }"))
    assert out["first"]["hidden"] is False, "the note was never shown"
    assert out["first"]["text"].startswith(
        "doc_category=medical: AMOUNT, CASE_STRATEGY, CLIENT_IDENTITY rules did not run "
        "for this document."
    ), out["first"]["text"]
    assert "not detected, not tokenised and not vaulted" in out["first"]["text"]
    # The sentence that answers the measurement above: the stats row is what made the
    # weakened run look equal, so the note has to say the stats row cannot show it.
    assert "entities_detected" in out["first"]["text"]
    assert out["second"].startswith(
        "doc_category=legal: AMOUNT, DATE rules did not run for this document."
    ), out["second"]


def test_a_refused_run_leaves_no_scope_note_from_the_run_before_it(tmp_path: Path) -> None:
    """The note describes ONE run's category, so it cannot outlive that run.

    Left up, it would sit under the next run's stats naming the previous run's dormant
    rule sets -- the same cross-run mixture ``resetRun`` exists to prevent, and worse
    here because this note is read as a statement about what just happened.
    """
    body = (
        RUN_SETUP
        + """
el('category').value = 'medical';
await UI.run();
const shown = el('scope-note').hidden;
respond((path, init) => {
  const m = (init && init.method) || 'GET';
  if (m === 'POST' && path === '/documents') return { status: 200, body: { doc_id: 'doc-1' } };
  if (path.indexOf('/documents/doc-1/text') === 0) {
    return { status: 200, body: { text: 'Bob met Carl.', chars: 13 } };
  }
  if (path === '/pipeline/run') {
    return { status: 403, body: { code: 'EGRESS_BLOCKED', detail: 'SSN in payload' } };
  }
  return { status: 200, body: { events: [] } };
});
await UI.run();
emit({ shown: shown, after: el('scope-note').hidden, banner: el('banner').innerHTML });
"""
    )
    out = _run(tmp_path, body.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }"))
    assert out["shown"] is False, "the first run's note was never shown"
    assert out["banner"].startswith("<b>EGRESS_BLOCKED</b>")
    assert out["after"] is True, "a refused run kept the previous run's scope note"


def test_the_scoped_rule_map_mirrors_the_registry(
    tmp_path: Path, registry: EntityRegistry
) -> None:
    """``SCOPED_RULES`` in ``app.js`` must equal ``only_in_doc_categories``, or it lies.

    Nothing serves the registry to the browser -- ``_mount_ui`` mounts ``ui/`` alone and
    no endpoint returns the mapping -- so the page carries a mirror, and a mirror that
    drifts turns the note into a false statement about which controls ran. The two
    sides are read by machinery with nothing in common: the expectation comes from
    ``load_registry`` parsing the shipped ``entities.yaml``, the actual comes from node
    evaluating the shipped ``app.js``, and the map is reconstructed from
    ``scopedOut``'s answers rather than read out of the file as text.
    """
    cats = sorted(DOC_CATEGORIES)
    skipped = _run(tmp_path, f"emit({{ out: {json.dumps(cats)}.map((c) => UI.scopedOut(c)) }});")
    lists = skipped["out"]
    assert len(lists) == len(cats)
    # A type is scoped TO a category exactly when that category's run did not skip it.
    named = sorted({name for one in lists for name in one})
    mirrored = {
        name: sorted(c for c, one in zip(cats, lists, strict=True) if name not in one)
        for name in named
    }
    expected = {
        name: sorted(spec.only_in_doc_categories)
        for name, spec in registry.entities.items()
        if spec.only_in_doc_categories
    }
    assert expected, "the shipped registry scopes nothing -- this test proves nothing"
    assert mirrored == expected


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
    body = (
        RUN_SETUP
        + """
fire('prompt', 'keydown', { key: 'a' });
await settle();
const afterLetter = calls.length;
fire('prompt', 'keydown', { key: 'Enter' });
await settle();
emit({ afterLetter: afterLetter, ran: calls.filter((c) => c.path === '/pipeline/run').length });
"""
    )
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
    # The VALID/BROKEN contract this test was written for is unchanged. What was
    # added is the scope of the *number* beside it: the badge sits inside the Audit
    # tail's own <h2>, next to the run_id label and above a table filtered to one
    # run, and ``GET /audit/verify`` unscoped counts the whole server's log -- 37
    # rows on screen under a badge reading 26,844 events, measured on the live
    # instance. Without the two words the count reads as the table's row count.
    assert out["true"] == {"text": f"chain: VALID {MID} 12 events (whole log)", "cls": "badge ok"}
    assert out["false"] == {
        "text": f"chain: BROKEN {MID} 12 events (whole log)",
        "cls": "badge err",
    }


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
  if (path.indexOf('/audit') === 0) {
    return { status: 403, body: { code: 'FORBIDDEN', detail: 'no' } };
  }
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
    # Was ``== '<tr><td colspan="5" class="muted">no events</td></tr>'``. Clearing the
    # stale rows is the requirement in the docstring and is still asserted below; what
    # changed is that the failure is no longer rendered *as the empty state*. "no
    # events" is what this table says when the log holds nothing, and "we could not
    # read the log" is the opposite of what the panel exists to prove -- and it is
    # reached from the two error paths, which is where it is most likely to be read.
    assert "RUN_START" not in out["after"], "the stale rows must still be cleared"
    assert out["after"] == (
        '<tr><td colspan="5" class="muted">audit tail could not be loaded (FORBIDDEN)</td></tr>'
    )
    assert "no events" not in out["after"]


# ---------------------------------------------------------------------------
# the shipped markup -- copy, accessible names, live regions, landmarks
# ---------------------------------------------------------------------------
# The harness above cannot see any of this: its DOM stub mints an element for any
# id asked of it, so it has no attributes, no ancestry and no <label>. Every test
# below therefore parses `index.html` itself, with stdlib `html.parser` -- nothing
# installed, and no second implementation of the page to drift from the first.
_VOID_TAGS = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
     "param", "source", "track", "wbr"}
)
#: Elements whose accessible name may come from their own content (HTML-AAM). A
#: <select>'s content is its options and an <input>'s is nothing, so neither is here:
#: that is exactly why an unlabelled file picker announces as "Choose File" and an
#: unlabelled <select> announces as nothing at all.
_NAME_FROM_CONTENT = frozenset({"button", "a", "h1", "h2", "h3", "label", "legend"})
#: Tags that are landmarks with no naming required.
_IMPLICIT_LANDMARKS = frozenset({"header", "main", "footer", "nav", "aside", "form"})


class _Page(HTMLParser):
    """``index.html`` as a flat list of elements, each carrying attrs, text and ancestry."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._open: list[dict] = []
        self.elements: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        node = {
            "tag": tag,
            "attrs": {k: (v or "") for k, v in attrs},
            "text": "",
            "ancestors": [n["tag"] for n in self._open],
        }
        self.elements.append(node)
        if tag not in _VOID_TAGS:
            self._open.append(node)

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self._open) - 1, -1, -1):
            if self._open[i]["tag"] == tag:
                del self._open[i:]
                return

    def handle_data(self, data: str) -> None:
        for node in self._open:
            node["text"] += data


def _flat(text: str) -> str:
    """Collapse the markup's whitespace the way a rendering engine does."""
    return " ".join(text.split())


def _page() -> tuple[list[dict], dict[str, dict]]:
    parser = _Page()
    parser.feed(INDEX_HTML.read_text(encoding="utf-8"))
    by_id = {n["attrs"]["id"]: n for n in parser.elements if n["attrs"].get("id")}
    return parser.elements, by_id


def _accessible_name(node: dict, elements: list[dict], by_id: dict[str, dict]) -> str:
    """HTML-AAM, reduced to the four naming routes this page actually uses.

    Order matters and is the spec's: ``aria-labelledby`` beats ``aria-label`` beats a
    ``<label for>`` beats content. A dangling ``aria-labelledby`` names nothing, which is
    the failure mode a hand-check misses -- it looks labelled in the source.
    """
    attrs = node["attrs"]
    ref = attrs.get("aria-labelledby", "").strip()
    if ref:
        parts = []
        for rid in ref.split():
            target = by_id.get(rid)
            if target is None:
                return ""
            parts.append(target["attrs"].get("aria-label", "").strip() or _flat(target["text"]))
        return _flat(" ".join(parts))
    if attrs.get("aria-label", "").strip():
        return _flat(attrs["aria-label"])
    node_id = attrs.get("id")
    if node_id:
        for el in elements:
            if el["tag"] == "label" and el["attrs"].get("for") == node_id:
                return _flat(el["text"])
    if node["tag"] in _NAME_FROM_CONTENT:
        return _flat(node["text"])
    return _flat(attrs.get("title", ""))


def test_the_live_review_callout_names_the_erasure_not_a_vault_miss() -> None:
    """The page's loudest instruction must not promise an event the flow cannot emit.

    ``/pipeline/run`` calls ``_require_session`` before ``services.orchestrator.run``, so a
    destroyed session is refused ``401 SESSION_EXPIRED`` before the vault is consulted.
    Run live against the API, the three steps the callout scripts logged 38 events --
    ``SESSION_CREATE``, ``DETECT``, 32x ``OBFUSCATE``, ``REDACT``, ``EGRESS_PASS``,
    ``LLM_CALL``, ``DEOBFUSCATE``, ``VAULT_DESTROY`` -- and zero ``VAULT_MISS``. README
    Deviation 56 records the correction; it was applied to ``destroySession``'s banner and
    to the README, and missed here, leaving the retracted claim in the one copy a reviewer
    reads first and the banner three lines below it contradicting the label above it.
    """
    elements, _ = _page()
    tags = [n for n in elements if "tag" in n["attrs"].get("class", "").split()]
    assert len(tags) == 1, "the live-review callout moved; this test no longer reads it"
    callout = _flat(tags[0]["text"])
    # Everything the page puts in front of a user: rendered text plus every attribute
    # value (titles, aria names). HTML comments are excluded on purpose -- the comment
    # at the callout quotes the retracted claim in order to explain why it is gone.
    body = next(n for n in elements if n["tag"] == "body")
    shown = _flat(body["text"] + " " + " ".join(v for n in elements for v in n["attrs"].values()))
    assert "vault-miss" not in shown.lower(), "the retracted vault-miss claim is back"
    assert "VAULT_MISS" not in shown, "no VAULT_MISS is reachable from a destroyed session"
    assert "SESSION_EXPIRED" in callout, callout
    assert "VAULT_DESTROY" in callout, callout
    # The markup and the banner app.js raises at step 2 have to tell one story.
    assert "SESSION_EXPIRED before the vault is even" in APP_JS.read_text(encoding="utf-8")


def test_every_interactive_control_on_the_page_has_an_accessible_name() -> None:
    """A control with no name announces as its widget type, which is not a name.

    The file picker was the one control of the ten with none: a screen reader read it as
    "Choose File, button", and it is the mandatory step -- without a file every Run answers
    ``NO_FILE``, so an unnamed picker is the demo unable to start. WCAG 2.1 4.1.2. The
    ``fixture preset`` <label> in the same group points at the <select>, so it neither named
    the picker nor could be repurposed to.
    """
    elements, by_id = _page()
    controls = [n for n in elements if n["tag"] in {"input", "select", "button", "textarea"}]
    assert len(controls) >= 10, f"only {len(controls)} controls found -- the parse is wrong"
    unnamed = [
        n["attrs"].get("id") or n["tag"]
        for n in controls
        if not _accessible_name(n, elements, by_id)
    ]
    assert unnamed == [], f"controls with no accessible name: {unnamed}"
    assert _accessible_name(by_id["file"], elements, by_id) == "document"
    # The only sentence that tells the picker and the preset apart is the hint, so it is
    # the picker's description rather than loose text beside it.
    assert by_id["file"]["attrs"].get("aria-describedby") == "fixture-hint"
    assert "fixture-hint" in by_id, "the description points at nothing"


def test_the_outcome_surfaces_are_live_regions_and_the_bulk_panels_are_not() -> None:
    """Every security verdict is delivered by mutating an element; a plain <div> is silent.

    ``banner()`` flips ``#banner`` from hidden to visible carrying ``EGRESS_BLOCKED`` or
    ``SESSION_EXPIRED`` while focus stays on the Run button, so without ``role="alert"`` a
    fail-closed run is indistinguishable from a run that did nothing. WCAG 2.1 4.1.3. The
    inverse matters as much: the four <pre> bodies and the audit <tbody> carry the run's
    whole payload -- ``legal_brief_large.txt`` alone is 12k characters -- and announcing
    those on every run would bury the verdict, so they must stay quiet and be reachable as
    regions instead.
    """
    _, by_id = _page()
    assert by_id["banner"]["attrs"].get("role") == "alert"
    assert by_id["banner"]["attrs"].get("aria-live") == "assertive"
    # #scope-note carries which `only_in_doc_categories` rule sets did NOT run. It is
    # `status`, not `alert`: it is a standing fact about the run delivered beside the
    # verdict, and made an assertive region it would talk over RUN_OK on every run.
    for status_id in ("stats", "health", "session-badge", "verify-badge", "scope-note"):
        assert by_id[status_id]["attrs"].get("role") == "status", status_id
        assert by_id[status_id]["attrs"].get("aria-live") == "polite", status_id
    for bulk_id in ("p1", "p2", "p3", "p4", "audit-body"):
        attrs = by_id[bulk_id]["attrs"]
        assert "aria-live" not in attrs, f"#{bulk_id} would be read aloud in full"
        assert attrs.get("role") not in {"alert", "status"}, bulk_id


def test_no_block_of_the_page_sits_outside_a_landmark_or_a_live_region() -> None:
    """Landmark navigation has to reach the controls and the audit tail, not just the panels.

    ``<main>`` wraps the four panels alone, and a bare ``<section>`` is a landmark only when
    it has an accessible name -- so the control bar, the live-review pair, the legend and the
    audit tail were in no landmark at all, and "skip to main content" jumped past every
    control on the page. Naming them makes each a region; the two announced surfaces
    (``#banner``, ``#stats``) are exempt because a status message is delivered to the user
    rather than navigated to.
    """
    elements, by_id = _page()
    top = [n for n in elements if n["ancestors"] == ["html", "body"] and n["tag"] != "script"]
    assert {n["tag"] for n in top} >= {"header", "main", "section"}, top
    orphans = [
        n["attrs"].get("id") or n["attrs"].get("class") or n["tag"]
        for n in top
        if n["tag"] not in _IMPLICIT_LANDMARKS
        and n["attrs"].get("role") not in {"alert", "status"}
        and not _accessible_name(n, elements, by_id)
    ]
    assert orphans == [], f"top-level blocks in no landmark: {orphans}"
    # Each panel is individually addressable, and named by the half of its heading that
    # does not change: app.js rewrites #c1..#c4 on every run.
    panels = [n for n in elements if "panel" in n["attrs"].get("class", "").split()]
    assert len(panels) == 4
    names = [_accessible_name(n, elements, by_id) for n in panels]
    assert names == [
        f"1 {MID} Original text",
        f"2 {MID} Outbound obfuscated payload",
        f"3 {MID} Raw LLM response",
        f"4 {MID} Restored response",
    ], names
    assert all(n["attrs"].get("role") == "region" for n in panels)
    assert all(by_id[c]["attrs"].get("id") for c in ("c1", "c2", "c3", "c4"))


def test_the_audit_headings_name_does_not_change_when_the_chain_is_verified() -> None:
    """A section title that renames itself mid-session is not a title.

    The audit ``<h2>`` is a flex row that also carries the Verify button and the chain badge,
    so its computed name was "Audit tail Verify chain chain: unverified" -- and ``verifyChain``
    rewrites ``#verify-badge`` to "chain: VALID - 41 events", so the heading a user
    navigates by changed under them. The controls stay inside the heading because the rules
    that lay them out live in ``style.css``, which this change does not own, and the page's
    CSP (``style-src 'self'``) forbids an inline style; ``aria-label`` pins the name instead.
    """
    elements, by_id = _page()
    heading = by_id["audit-h"]
    assert heading["tag"] == "h2"
    assert _accessible_name(heading, elements, by_id) == "Audit tail"
    # The two mutating spans really are inside this heading -- otherwise the name was
    # already stable and this test proves nothing.
    assert "Verify chain" in heading["text"] and "chain: unverified" in heading["text"]
    assert "$('verify-badge')" in APP_JS.read_text(encoding="utf-8")
    audit = [n for n in elements if "audit" in n["attrs"].get("class", "").split()]
    assert [_accessible_name(n, elements, by_id) for n in audit] == ["Audit tail"]


# ---------------------------------------------------------------------------
# what the panels CLAIM -- the four surfaces read as evidence, and the states
# that made them say something the run did not support
# ---------------------------------------------------------------------------
#: A scripted run whose bodies are shaped like the live ones. `PIPELINE` is
#: substituted per test, exactly as `RUN_SETUP` above does it.
EVIDENCE_SETUP = """
respond((path, init) => {
  const m = (init && init.method) || 'GET';
  if (m === 'POST' && path === '/documents') return { status: 200, body: { doc_id: 'doc-A' } };
  if (path.indexOf('/documents/doc-A/text') === 0) {
    return { status: 200, body: { text: 'Bob met Carl.', chars: 13 } };
  }
  if (path === '/pipeline/run') return PIPELINE;
  if (path.indexOf('/audit') === 0) return { status: 200, body: { returned: 0, events: [] } };
  return { status: 200, body: {} };
});
UI.S.sessionId = 'sess-1';
el('prompt').value = 'Summarise';
el('file').files = [{ name: 'note.txt', size: 3, lastModified: 11 }];
//: Required, same as in `RUN_SETUP`: without it the run never reaches the pipeline.
el('category').value = 'legal';
"""

#: The title `renderRestored` hangs on the sentinel, hand-written rather than read
#: out of the file under test.
UNRES_TITLE = (
    "not restored: the vault could not resolve this token. "
    "See the VAULT_MISS row in the audit tail."
)


def test_panel_four_does_not_paint_an_unresolved_token_as_a_restored_value(
    tmp_path: Path,
) -> None:
    """The one value a run FAILED to restore must not wear the "restored" colour.

    ``restorer.py`` substitutes the fixed sentinel ``[UNRESOLVED_ENTITY]`` for a token
    id the vault never issued, and it lands in exactly the position a real original
    would, so the literal-alignment in ``renderRestored`` cannot tell them apart.
    Measured against the live API (medical_note.txt, a prompt carrying
    ``[PHI_NAME_deadbeef]``, ``vault_misses: 1``): panel 4 emitted 33 ``rest`` marks
    against ``stats.restored_count`` 32, and the 33rd was the failure -- in the
    legend's "restored region" teal, on the same screen as the ``VAULT_MISS`` row the
    audit table flags red. Two evidence surfaces, contradicting each other.

    The possessive is part of the same claim: ``restorer.py`` builds the piece as
    ``UNRESOLVED_ENTITY + possessive``, so an apostrophe-s left outside the mark is
    still a region painted as restored, and still one more of them than the run says.
    """
    raw = "Bob met [PII_NAME_1a2b3c4d] and [PII_NAME_deadbeef]'s team."
    restored = "Bob met Alice Cooper and [UNRESOLVED_ENTITY]'s team."
    out = _run(
        tmp_path,
        f"emit({{ html: UI.renderRestored({json.dumps(raw)}, {json.dumps(restored)}, []) }});",
    )["html"]
    assert out == (
        'Bob met <mark class="rest">Alice Cooper</mark> and '
        f'<mark class="tok unres" title="{UNRES_TITLE}">[UNRESOLVED_ENTITY]&#39;s</mark> team.'
    )
    assert out.count('<mark class="rest">') == 1, "one value was restored, not two"
    assert '<mark class="rest">[UNRESOLVED' not in out


def test_panel_three_marks_the_surrogates_the_provider_actually_saw(tmp_path: Path) -> None:
    """Panel 3 is the provider's-eye view, and it was the only panel with no marks.

    Under pseudonymization the surrogate is a realistic fake, so an unmarked panel 3
    reads as genuine prose: on a live run, panel 1 showed "physician Joshua Gonzalez,
    MD" and panel 3 the same line as "physician Jamie Cain, MD" with nothing to tell
    them apart -- README line 2069 calls a downstream human reading the fake as real
    "the dangerous one". Panel 2 marked "Jamie Cain" for the same run from the same
    detections; only this panel did not, and ``renderMarks`` was already able to.
    """
    body = (
        EVIDENCE_SETUP.replace(
            "PIPELINE",
            """{ status: 200, body: {
  run_id: 'r-9', strategy: 'pseudonymization',
  detections: [{ start: 8, end: 12, category: 'PII', entity_type: 'PERSON',
                 action: 'PSEUDO', score: 0.9, surrogate: 'Jamie Cain' }],
  obfuscated_payload: 'Seen by Jamie Cain, MD.',
  raw_llm_response: 'Jamie Cain, MD reviewed the chart.',
  restored_text: 'Joshua Gonzalez, MD reviewed the chart.',
  stats: {},
} }""",
        )
        + """
await UI.run();
emit({ p3: el('p3').innerHTML, c3: el('c3').textContent });
"""
    )
    out = _run(tmp_path, body)
    assert out["p3"] == '<mark class="tok c-PII">Jamie Cain</mark>, MD reviewed the chart.'
    assert out["c3"] == "34 chars", "the counter must still describe raw_llm_response"


def test_panel_two_does_not_highlight_the_instruction_block_s_own_example(
    tmp_path: Path,
) -> None:
    """A highlight in panel 2 claims "this value was replaced". Two of them did not.

    ``context_injector.TOKENIZATION_SYSTEM_PROMPT`` documents the contract with a
    literal example -- "placeholders like [PHI_NAME_1a2b3c4d]" -- and the payload
    carries the prompt as well as the document, so a token-shaped string typed into
    the prompt box sits in panel 2 too. Both matched the emitted-surrogate grammar and
    were coloured: measured on medical_note.txt, 53 marks against 52 spans with an
    ordinary prompt and 54 with ``Who is [PHI_NAME_deadbeef]?``, and the second one is
    the string the same run logs as ``VAULT_MISS``/``fabricated``. Neither is backed by
    a detection, a vault row or an audit ``token_id``, and the first highlight a
    reviewer sees was one of them.
    """
    payload = (
        "Certain values are replaced with opaque placeholders like [PHI_NAME_1a2b3c4d].\n"
        "Who is [PHI_NAME_deadbeef]?\n\n<DOCUMENT>\nPatient [PHI_NAME_11112222] was seen.\n"
        "</DOCUMENT>"
    )
    det = _det(start=8, end=11, category="PHI", surrogate="[PHI_NAME_11112222]")
    out = _run(
        tmp_path,
        f"emit({{ html: UI.renderMarks({json.dumps(payload)}, [{det}],"
        f" {json.dumps(payload)}.indexOf('<' + 'DOCUMENT' + '>')) }});",
    )["html"]
    assert out.count("<mark") == 1, out
    assert '<mark class="tok c-PHI">[PHI_NAME_11112222]</mark>' in out
    assert "like [PHI_NAME_1a2b3c4d]." in out, "the documentation example is plain text"
    assert "Who is [PHI_NAME_deadbeef]?" in out, "a token the reviewer typed is not ours"


BLOCKED_BODY = (
    EVIDENCE_SETUP.replace(
        "PIPELINE",
        """{ status: 422, body: { code: 'EGRESS_BLOCKED', detail: {
  session_id: 'sess-1', reason: 'independent_pattern', hit_count: 1,
  entity_types: 'SSN', run_id: 'run-BLOCKED' } } }""",
    )
    + """
// A successful run first, so the panels have something of the PREVIOUS run in them.
UI.renderStats({ total_ms: 5.5 });
['p1', 'p2', 'p3', 'p4'].forEach((id) => { el(id).innerHTML = 'RUN N-1'; });
['c1', 'c2', 'c3', 'c4'].forEach((id) => { el(id).textContent = '999 chars'; });
el('audit-run').textContent = 'run_id run-OK';
await UI.run();
emit({
  p1: el('p1').innerHTML, p2: el('p2').innerHTML,
  p3: el('p3').innerHTML, p4: el('p4').innerHTML,
  counters: ['c1', 'c2', 'c3', 'c4'].map((c) => el(c).textContent),
  stats: el('stats').innerHTML,
  auditRun: el('audit-run').textContent,
  audit: calls.filter((c) => c.path.indexOf('/audit') === 0).map((c) => c.path),
  banner: el('banner').innerHTML,
});
"""
)


def test_a_refused_run_leaves_nothing_of_the_run_before_it_on_screen(tmp_path: Path) -> None:
    """A refused run must not leave the previous run's evidence under its error banner.

    ``run()`` filled panel 1 from ``GET /documents/{id}/text`` before calling the
    pipeline and wrote panels 2-4, the stats row and the audit label only after it
    returned, and the ``catch`` cleared nothing. So every failure half-updated the
    screen: panel 1 advanced to the NEW document while panels 2-4 kept the OLD run --
    the fail-closed banner sat above a fully populated "3 · Raw LLM response" and a
    restored answer, for a payload the gate had just refused to send, and the
    reviewer's whole visual check ("does panel 2 contain anything from panel 1?") was
    being made across two unrelated documents. Only a page reload cleared it.
    """
    out = _run(tmp_path, BLOCKED_BODY)
    assert out["banner"].startswith("<b>EGRESS_BLOCKED</b>")
    assert out["p1"] == "Bob met Carl.", "panel 1 is the document the refused run was for"
    assert out["counters"][0] == "13 chars " + MID + " not yet scanned"
    assert [out["p2"], out["p3"], out["p4"]] == [IDLE, IDLE, IDLE]
    assert out["counters"][1:] == ["", "", ""]
    assert out["stats"] == "", "the refused run has no timings, and N-1's are not its own"


def test_a_refused_run_scopes_and_labels_the_audit_tail_by_the_run_that_was_refused(
    tmp_path: Path,
) -> None:
    """The 422 names the blocked run; the tail was reloaded unscoped and mislabelled.

    ``#audit-run`` was written in exactly one place -- the success path -- so after a
    block it went on naming the previous, successful run while the table below it had
    silently changed scope to the whole session. Measured on the live API: the
    ``EGRESS_BLOCK`` row landed at index 79 of the 84 rows that query returns, inside a
    260px scrolling box, i.e. off-screen at the moment it is the point of the demo.
    """
    out = _run(tmp_path, BLOCKED_BODY)
    assert out["auditRun"] == "run_id run-BLOCKED " + MID + " refused"
    assert out["audit"], "the tail must still be refreshed after a block"
    assert all("run_id=run-BLOCKED" in path for path in out["audit"]), out["audit"]


def test_destroying_the_session_clears_the_screen_it_says_is_gone(tmp_path: Path) -> None:
    """"Irreversibly" is a claim about the screen too, and the screen contradicted it.

    ``destroySession`` touched three things -- ``S.sessionId``, the badge and the
    banner -- and no panel, counter or stat. So the button that exists to demonstrate
    irreversible erasure left the original document, the outbound payload, the model's
    answer and the RESTORED plaintext PHI on screen, under a banner reading "Session
    key and vault rows are gone". The audit tail is deliberately still loaded: it is
    what the button exists to reveal.
    """
    body = (
        """
respond((path, init) => {
  if ((init && init.method) === 'DELETE') return { status: 204 };
  if (path.indexOf('/audit') === 0) {
    // ``detail`` was ``{}``, a body the API does not produce: every VAULT_DESTROY row
    // it writes carries ``existed`` and ``source``. The screen is only cleared on the
    // branch where the log confirms the erasure, so the scenario has to be a real one.
    return { status: 200, body: { returned: 1, events: ["""
        + DESTROYED_ROW
        + """] } };
  }
  return { status: 200, body: {} };
});
UI.S.sessionId = 'sess-abc';
el('p1').innerHTML = 'Patient name: David Ochoa';
el('p4').innerHTML = '<mark class="rest">David Ochoa</mark> has MRN 9224297.';
UI.renderStats({ total_ms: 20 });
el('audit-run').textContent = 'run_id run-OK';
await UI.destroySession();
emit({
  p1: el('p1').innerHTML, p4: el('p4').innerHTML,
  stats: el('stats').innerHTML, auditRun: el('audit-run').textContent,
  audit: el('audit-body').innerHTML, badge: el('session-badge').textContent,
});
"""
    )
    out = _run(tmp_path, body)
    assert "David Ochoa" not in out["p1"] and "David Ochoa" not in out["p4"]
    assert out["p4"] == IDLE
    assert "cleared" in out["p1"] and "vault rows" in out["p1"]
    assert out["stats"] == "" and out["auditRun"] == ""
    assert out["badge"] == "session destroyed"
    assert "VAULT_DESTROY" in out["audit"], "the tail is the one thing that must stay"


def test_creating_a_session_does_not_inherit_the_previous_session_s_run(tmp_path: Path) -> None:
    """A fresh session badge over the dead session's rows invites exactly one reading.

    ``createSession`` set three things and cleared nothing, so after Destroy -> Create
    the page showed "SESSION_CREATED" above the previous session's four panels, stats,
    audit rows and ``run_id`` label. A reviewer reading that table under that badge
    reasonably takes those events for the session it names. ``lastSessionId`` is
    dropped with them, or the audit scope keeps falling back to the dead session.
    """
    body = """
respond((path) => {
  if (path === '/sessions') {
    return { status: 200, body: { session_id: 'sess-NEW-000000', expires_at: 1700000000 } };
  }
  if (path.indexOf('/audit') === 0) return { status: 200, body: { returned: 0, events: [] } };
  return { status: 200, body: {} };
});
UI.S.lastSessionId = 'sess-OLD';
el('p4').innerHTML = '<mark class="rest">David Ochoa</mark>';
UI.renderStats({ total_ms: 20 });
el('audit-run').textContent = 'run_id run-OLD';
UI.renderAudit([{ seq: 1, event_type: 'RESTORE_OK', detail: {} }]);
el('p1').innerHTML = 'Patient name: David Ochoa';
await UI.createSession();
emit({
  p1: el('p1').innerHTML, p4: el('p4').innerHTML, stats: el('stats').innerHTML,
  auditRun: el('audit-run').textContent, audit: el('audit-body').innerHTML,
  last: UI.S.lastSessionId,
  audits: calls.filter((c) => c.path.indexOf('/audit') === 0).map((c) => c.path),
});
"""
    out = _run(tmp_path, body)
    assert out["p4"] == IDLE
    # Panel 1 is the one that carries an instruction rather than a dash: index.html's
    # placeholder is "Create a session, choose a file, press Run", and the click that
    # completes its first clause must not blank the other two.
    assert "David Ochoa" not in out["p1"]
    assert out["p1"] == "Session created. Choose a file and press Run."
    assert out["stats"] == "" and out["auditRun"] == ""
    assert "RESTORE_OK" not in out["audit"], "the dead session's rows are not this session's"
    assert out["last"] is None
    assert out["audits"] and all("session_id=sess-NEW-000000" in a for a in out["audits"])


def test_a_run_before_a_session_exists_is_refused_without_uploading_anything(
    tmp_path: Path,
) -> None:
    """"Session key is gone" about a key that was never minted, after an upload.

    Run is the biggest button on the page and sits inside the red LIVE REVIEW strip;
    Create session is a small one ten controls above it. Without a preflight the first
    click uploaded the document, painted panel 1 with the original text and then posted
    ``session_id: null``, which the API answers 401 SESSION_EXPIRED -- so the page
    reported a destroyed key, with an empty ``session_id`` in the detail as the only
    clue. The other two missing inputs were already preflighted by name.
    """
    body = (
        EVIDENCE_SETUP.replace("PIPELINE", "{ status: 200, body: {} }")
        + """
UI.S.sessionId = null;
await UI.run();
emit({ banner: el('banner').innerHTML, requests: calls.map((c) => c.method + ' ' + c.path) });
"""
    )
    out = _run(tmp_path, body)
    assert out["requests"] == [], "a run with no session must not reach the network"
    assert out["banner"].startswith("<b>NO_SESSION</b>")
    assert "vault key" in out["banner"]
    assert "gone" not in out["banner"], "nothing was destroyed; nothing was ever created"


def test_a_transport_failure_names_the_transport_instead_of_printing_an_empty_object(
    tmp_path: Path,
) -> None:
    """``ERROR {}`` was this UI's entire report for "the API is not reachable".

    ``api()`` only ever attached ``.code``/``.detail`` when a response came back, so a
    rejected ``fetch`` -- connection refused, DNS, CORS, abort -- propagated a native
    ``TypeError``, and ``showError``'s ``JSON.stringify(e.detail || {})`` rendered that
    as the two-character string ``{}``. The same banner appeared for an unparseable
    body and for any exception in the render path, and ``e.message``, the only field a
    native error populates, was never read. ``health()`` had a correct branch for this
    exact failure ("health: unreachable") ten lines below.
    """
    body = """
const out = {};
globalThis.fetch = async () => { throw new TypeError('Failed to fetch'); };
await UI.createSession();
out.network = el('banner').innerHTML;
UI.showError({ message: 'Cannot read properties of null' });
out.bare = el('banner').innerHTML;
UI.showError({ code: 'SESSION_EXPIRED', detail: { session_id: 'deadbeefdeadbeef' } });
out.expired = el('banner').innerHTML;
emit(out);
"""
    out = _run(tmp_path, body)
    assert out["network"].startswith("<b>NETWORK_UNREACHABLE</b>")
    assert "Could not reach the API" in out["network"]
    assert "Failed to fetch" in out["network"], "the transport's own words are the diagnostic"
    assert out["bare"] == "<b>ERROR</b> Cannot read properties of null"
    assert "{}" not in out["network"] + out["bare"] + out["expired"]
    assert "deadbeefdeadbeef" not in out["expired"], "a live session id is not a diagnostic"
    assert "the vault cannot be read" in out["expired"], "the explanation still has to be there"


def test_a_gate_that_failed_internally_is_not_reported_as_a_caught_leak(tmp_path: Path) -> None:
    """The strongest claim this product makes must not be printed when it is untrue.

    ``EgressGate.check`` wraps itself: any internal exception becomes
    ``EgressBlockedError(reason="gate_exception", hit_count=0)``, which reaches the UI
    under the same ``EGRESS_BLOCKED`` code as a deliberate block. Reproduced against
    the live API (83 KB fixture, warm session): ``{"reason":"gate_exception",
    "hit_count":0,"entity_types":""}`` -- and the banner read, character for character,
    the sentence written for a caught leak. "So what did it catch?" has the answer
    "nothing, it crashed", and the page had already said otherwise.
    """
    body = """
const out = {};
UI.showError({ code: 'EGRESS_BLOCKED', detail: { reason: 'gate_exception', hit_count: 0 } });
out.crash = el('banner').innerHTML;
UI.showError({ code: 'EGRESS_BLOCKED',
  detail: { reason: 'independent_pattern', hit_count: 1, entity_types: 'SSN' } });
out.caught = el('banner').innerHTML;
emit(out);
"""
    out = _run(tmp_path, body)
    assert "FAILED INTERNALLY" in out["crash"]
    assert "not a caught leak" in out["crash"]
    assert "FAIL-CLOSED" not in out["crash"], "the gate caught nothing; do not say it did"
    assert out["caught"].startswith("<b>EGRESS_BLOCKED</b> FAIL-CLOSED")
    assert "No provider call was made" in out["caught"]


def test_the_audit_tail_asks_for_a_page_that_holds_a_whole_run_and_says_when_it_cannot(
    tmp_path: Path,
) -> None:
    """The section is headed "Audit tail" and showed the head, silently.

    ``limit=200`` with no offset takes the FIRST 200 rows of a scope the API returns
    ascending by seq. Measured on ``legal_brief_large.txt``, a preset in this page's
    own fixture dropdown: one run emits 347 events and the panel rendered 200 of them
    -- one ``DETECT`` and 199 ``OBFUSCATE``. The 147 dropped included ``EGRESS_PASS``,
    ``LLM_CALL`` and ``DEOBFUSCATE``, i.e. the evidence that the gate cleared the
    payload and that the provider was called at all, and nothing on screen said the
    list was partial. The page is now ``MAX_AUDIT_PAGE``, the largest the endpoint
    will serve, which holds that run whole -- and a full page still says so, because
    at 1,001 events the same silence would return.
    """
    body = """
const page = (n) => ({ status: 200, body: { returned: n, events:
  Array.from({ length: n }, (_, i) => ({ seq: i, event_type: 'OBFUSCATE',
    entity_type: 'PERSON', token_id: 't', detail: {} })) } });
const out = {};
UI.S.sessionId = 'sess-1';
respond(() => page(1000));
await UI.loadAudit('r-1');
out.full = el('audit-body').innerHTML;
out.query = calls[calls.length - 1].path;
respond(() => page(347));
await UI.loadAudit('r-1');
out.wholeRun = el('audit-body').innerHTML;
emit(out);
"""
    out = _run(tmp_path, body)
    assert "limit=1000" in out["query"], out["query"]
    assert out["full"].count("<tr") == 1001, "1000 event rows plus one notice"
    assert "showing the first 1000 events" in out["full"]
    for terminal in ("EGRESS_PASS", "LLM_CALL", "DEOBFUSCATE"):
        assert terminal in out["full"], "the notice names the rows that fell off"
    assert "offset=1000" in out["full"]
    assert out["wholeRun"].count("<tr") == 347, "the 347-event run fits, with no notice"
    assert "showing the first" not in out["wholeRun"]


def test_a_throttled_chain_walk_is_not_left_reading_valid(tmp_path: Path) -> None:
    """A 429 on Verify chain is a meter, not a verdict, and the badge kept the verdict.

    ``GET /audit/verify`` is priced in rows (``CHAIN_WALK_ROWS_PER_TOKEN = 5_000``,
    ``CHAIN_WALK_BURST = 24``, charged on success), so on a large log the fifth click
    in a row 429s -- measured: four 200s then ``{"code":"RATE_LIMITED"}``. The catch
    only showed the banner, so "chain: VALID" stayed on screen beside it, and the
    banner's explanation named the two meters that had NOT fired.
    """
    body = """
const out = {};
respond(() => ({ status: 200, body: { valid: true, length: 26844 } }));
await UI.verifyChain();
out.ok = el('verify-badge').textContent;
respond(() => ({ status: 429, body: { code: 'RATE_LIMITED',
  detail: { retry_after_seconds: 0.2 } } }));
await UI.verifyChain();
out.throttled = el('verify-badge').textContent;
out.cls = el('verify-badge').className;
out.banner = el('banner').innerHTML;
emit(out);
"""
    out = _run(tmp_path, body)
    assert out["ok"] == "chain: VALID " + MID + " 26844 events (whole log)"
    assert out["throttled"] == "chain: throttled"
    assert "VALID" not in out["throttled"]
    assert out["cls"] == "badge muted"
    assert "chain walk behind Verify chain" in out["banner"]
    assert "too many requests from this address" in out["banner"]


def test_changing_the_file_mid_run_cannot_null_the_document_id(tmp_path: Path) -> None:
    """A control touched during a request must not be read by the next step of it.

    ``run()`` re-read ``S.docId`` after each await, and ``setBusy`` disabled only the
    three buttons -- so the file picker stayed live, its ``change`` listener nulled
    ``S.docId``, and the in-flight run posted ``"doc_id": null``. The live API answers
    that with ``VALIDATION_ERROR {"errors":1,"fields":"body.doc_id"}``, a banner naming
    a field the reviewer never saw, beside a panel 1 already painted with the document.
    """
    body = (
        EVIDENCE_SETUP.replace(
            "PIPELINE",
            """{ status: 200, body: { run_id: 'r-1', strategy: 'tokenization', detections: [],
  obfuscated_payload: 'p', raw_llm_response: 'a', restored_text: 'a', stats: {} } }""",
        ).replace(
            "return { status: 200, body: { text: 'Bob met Carl.', chars: 13 } };",
            """out.disabled = ['file', 'category', 'strategy'].map((i) => el(i).disabled);
    fire('file', 'change');
    return { status: 200, body: { text: 'Bob met Carl.', chars: 13 } };""",
        )
        + """
await UI.run();
out.sent = JSON.parse(calls.filter((c) => c.path === '/pipeline/run')[0].body);
out.after = ['file', 'category', 'strategy'].map((i) => el(i).disabled);
emit(out);
"""
    )
    out = _run(tmp_path, "const out = {};\n" + body)
    assert out["sent"]["doc_id"] == "doc-A", "the run posted the document it uploaded"
    assert out["disabled"] == [True, True, True], "the inputs a run reads must be held"
    assert out["after"] == [False, False, False], "and released when it ends"


def test_a_document_with_no_extractable_text_says_so_instead_of_going_blank(
    tmp_path: Path,
) -> None:
    """An image-only PDF is a 200 with ``text: ""``, and the panel simply emptied.

    Extraction legitimately yields "" for a page with no text operators, so the API is
    not at fault; the UI had no empty state for it. The result was a completely blank
    panel 1 -- placeholder wiped, nothing in its place -- under a green ``RUN_OK``
    banner, beside panels 3 and 4 holding a confident summary of a document that
    contained nothing. That reads as "the UI broke" or, worse, "the model invented a
    patient record".
    """
    body = (
        EVIDENCE_SETUP.replace(
            # Ordered: the in-flight probe is spliced in while the placeholder is still
            # a placeholder, or the anchor is gone by the time this runs.
            "if (path === '/pipeline/run') return PIPELINE;",
            "if (path === '/pipeline/run') { out.inflight = el('p1').innerHTML; return PIPELINE; }",
        )
        .replace(
            "PIPELINE",
            """{ status: 200, body: { run_id: 'r-1', strategy: 'tokenization', detections: [],
  obfuscated_payload: 'p', raw_llm_response: 'Summary.', restored_text: 'Summary.',
  stats: {} } }""",
        )
        .replace("body: { text: 'Bob met Carl.', chars: 13 }", "body: { text: '', chars: 0 }")
        + """
await UI.run();
out.p1 = el('p1').innerHTML;
out.c1 = el('c1').textContent;
out.banner = el('banner').innerHTML;
emit(out);
"""
    )
    out = _run(tmp_path, "const out = {};\n" + body)
    # Both paints, because they are two statements: the one before the pipeline call
    # (the reviewer looks at panel 1 while the run is in flight) and the one after it.
    assert "No text could be extracted" in out["inflight"]
    assert "No text could be extracted" in out["p1"]
    assert "scanned image with no text layer" in out["p1"]
    assert out["c1"] == "0 chars " + MID + " 0 spans"
    assert out["banner"].startswith("<b>RUN_OK</b>"), "the run did succeed; the document is empty"
