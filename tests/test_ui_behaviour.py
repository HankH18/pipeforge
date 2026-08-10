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

import ast
import base64
import importlib
import json
import pkgutil
import re
import secrets
import shutil
import subprocess
import sys
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from secure_context_pipeline.api.app import create_app
from secure_context_pipeline.api.constants import MAX_AUDIT_PAGE
from secure_context_pipeline.api.routes.documents import DEMO_FIXTURES
from secure_context_pipeline.api.schemas import MAX_ID_LEN, MAX_PROMPT_CHARS
from secure_context_pipeline.config import Settings
from secure_context_pipeline.detection.registry import EntityRegistry
from secure_context_pipeline.errors import PipelineError
from secure_context_pipeline.models import DOC_CATEGORIES

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_JS = REPO_ROOT / "secure_context_pipeline" / "ui" / "app.js"
INDEX_HTML = REPO_ROOT / "secure_context_pipeline" / "ui" / "index.html"
REGISTRY_PATH = REPO_ROOT / "entities.yaml"
MEDICAL_NOTE = REPO_ROOT / "fixtures" / "medical_note.txt"
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

#: What a mark in panel 2 or 3 says when you hover it, one per kind of mark.
#: Hand-written here, never imported from ``app.js`` -- the module docstring's rule.
#: They exist as constants only because two tests below assert the same rendering.
TOK_TIP = (
    "A surrogate token. The original it stands for is in the vault for this "
    "session and is not anywhere in this payload; panel 4 puts it back."
)
RED_TIP = (
    "A redaction marker. The value was removed rather than tokenised -- "
    "irreversible by design, so it does not come back in panel 4."
)


def _ps_tip(entity_type: str) -> str:
    """The pseudonym tooltip, which names the entity type and no value.

    Was ``"A PSEUDONYM this run minted for a {t}."``, and "this run minted" was false
    on precisely the run the tooltip is read on. The vault keys a record by (entity
    type, value) for the life of the session, so a run can re-emit a fake it did not
    mint: measured through the real API on ``fixtures/medical_note.txt`` as
    ``medical``, a ``tokenization`` run following a ``pseudonymization`` one in the
    same session re-emitted 18 of them -- and ``TokenizationStrategy.make_surrogate``
    returns ``plain_token`` for every entity, so it cannot have minted one. The
    response carries no per-record minted/reused flag, so the claim was not the page's
    to make. What replaces it is what the mark itself proves.
    """
    return (
        f"A PSEUDONYM standing in for a {entity_type}. It reads like a real value and "
        "is not one -- it was invented in this session (not necessarily by this run: "
        "the vault reuses a record for the life of the session) and the original never "
        "left the vault."
    )

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
// CONTENT no test could see -- and `doc_category` travels in it. A non-string part is
// recorded as its declared filename plus its bytes: the demo-document preset uploads a
// Blob the page built out of a GET, and "the same bytes the picker would have sent"
// is the property that makes a preset run and a hand-picked run the same run, so the
// bytes have to be visible here. Existing assertions index these rows by membership
// (`['doc_category', 'financial'] in parts`), which the extra columns leave alone.
globalThis.Blob = class {
  constructor(bits, opts) { this.bits = (bits || []).join(''); this.type = (opts || {}).type; }
};
globalThis.FormData = class {
  constructor() { this.parts = []; }
  append(k, v, filename) {
    if (typeof v === 'string') { this.parts.push([k, v]); return; }
    this.parts.push([k, '[file]', filename === undefined ? null : filename,
      v && v.bits !== undefined ? v.bits : null]);
  }
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
  // Awaited, so a responder may return a promise -- including one that never
  // settles, which is the only way to script "the API stopped answering". And the
  // abort signal is honoured, because a real `fetch` REJECTS when its signal fires
  // and the page's request deadline is built on exactly that rejection; a stub that
  // ignored the signal would let a timeout test pass with no timeout in the code.
  const pending = Promise.resolve(responder(path, init));
  const signal = init && init.signal;
  const raced = signal
    ? Promise.race([pending, new Promise(function (_resolve, reject) {
        const bail = function () { reject(new Error('aborted')); };
        if (signal.aborted) { bail(); return; }
        signal.addEventListener('abort', bail);
      })])
    : pending;
  const r = (await raced) || { status: 200, body: {} };
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
  ' scopedOut: scopedOut, run: run, health: health, TIMEOUT: TIMEOUT };' + TAIL;
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
    # The three ``title`` attributes are an ADDITION to what this assertion pinned,
    # not a relaxation of it: every class here is the one it always asserted, in the
    # same order, and the equality is still exact. The tooltips arrived with the
    # panel-2/3 hover text and are asserted in full by
    # ``test_a_mark_in_panel_two_or_three_says_which_of_the_three_kinds_it_is``.
    assert out == (
        f'<mark class="tok c-RED" title="{RED_TIP}">[REDACTED_SSN]</mark>'
        " &amp; "
        f'<mark class="tok c-PHI" title="{_ps_tip("PERSON")}">Christina Palmer</mark>'
        " said "
        f'<mark class="tok c-PII" title="{TOK_TIP}">[PII_PERSON_1a2b3c4d]</mark>'
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
    # The mark now also carries the panel-2/3 hover text; the class and the matched
    # token -- the two things this test is about -- are unchanged.
    assert f'<mark class="tok c-PII" title="{TOK_TIP}">{ok}</mark>' in out
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
    # Still one whole mark over the whole string; the tooltip is an addition to it.
    assert out == f'<mark class="tok c-PII" title="{_ps_tip("PERSON")}">Ann Smith</mark>'


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

    ``STAT_META``'s key order is the pipeline's own sequence; keys the API adds later
    are appended rather than dropped, so a new stat still shows up. Durations render to
    one decimal with a unit, counts as integers -- the difference between "12.3 ms"
    and "12.345".
    """
    stats = {"total_ms": 12.34, "detect_ms": 1.0, "later_addition": 2.6}
    out = _run(
        tmp_path, f"UI.renderStats({json.dumps(stats)}); emit({{ html: el('stats').innerHTML }});"
    )
    # The literal moved when the strip stopped printing 22 counters in one styling;
    # every property this assertion existed to pin is unchanged and still pinned here.
    # ``detect_ms`` before ``total_ms`` is the declared order and not the JSON's;
    # ``later_addition`` is a key ``STAT_META`` has never heard of and is APPENDED, not
    # dropped and not titled; 12.34 renders "12.3 ms" and 2.6 renders "3". What is new
    # is the class on each chip -- ``stat muted`` for a timing, bare ``stat`` for a
    # count -- and the ``title`` carrying the counter's meaning, which is the whole
    # point of the change and is asserted in its own right below.
    assert out["html"] == (
        '<span class="stat muted" title="TIMING. Detection over the document.">'
        "<i>detect_ms</i>1.0 ms</span>"
        '<span class="stat muted" title="TIMING. The whole run, end to end.">'
        "<i>total_ms</i>12.3 ms</span>"
        '<span class="stat"><i>later_addition</i>3</span>'
    )


#: One rendered chip: ``(class, title, key, value)``. Deliberately a parse of the real
#: markup rather than a second renderer -- every expected string below is hand-written.
_CHIP = re.compile(
    r'<span class="(?P<cls>[^"]*)"(?: title="(?P<title>[^"]*)")?>'
    r"<i>(?P<key>[^<]*)</i>(?P<value>[^<]*)</span>"
)

#: A run that reports every shape of counter the strip can print: a timing, three
#: volume counts, and all three counters whose clean reading is 0 -- one of them
#: non-zero. Deliberately supplied in an order NO grouping would produce by accident,
#: so "safety first, timings last" is a property of the code and not of this literal.
_MIXED_STATS = {
    "total_ms": 12.34,
    "vault_misses": 0,
    "egress_rescan_warnings": 3,
    "unresolved_lost": 2,
    "detect_ms": 1.0,
    "entities_detected": 54,
    "unresolved_fabricated": 0,
    "tokens_issued": 32,
}


def test_the_stats_strip_tells_a_safety_counter_apart_from_a_stopwatch(
    tmp_path: Path,
) -> None:
    """A reviewer must be able to see which of the 22 numbers is the security claim.

    The strip printed every counter in one identical chip with no key, so
    ``egress_rescan_warnings 3`` sat beside ``detect_ms 412.6 ms`` in the same grey
    box -- measured on ``fixtures/medical_note.txt``, which reports 22 of them. Two
    things were unavailable to a reviewer from the page alone: which numbers are the
    guarantee, and whether a non-zero one is fine. Both are now on the page: the
    timings recede to ``stat muted``, the three counters whose clean reading is 0
    carry the verdict colour of the value they are showing (``stat badge ok`` /
    ``stat badge err``), and every counter the build knows carries its meaning as a
    ``title``.

    Ordering is asserted because it is the cheapest half of the signal: the safety
    counters lead, and no arrangement of the input dict changes that.
    """
    out = _run(
        tmp_path,
        f"UI.renderStats({json.dumps(_MIXED_STATS)}); emit({{ html: el('stats').innerHTML }});",
    )
    chips = [m.groupdict() for m in _CHIP.finditer(out["html"])]
    assert [c["key"] for c in chips] == [
        # Safety first, in the pipeline's own sequence...
        "entities_detected",
        "tokens_issued",
        "egress_rescan_warnings",
        "vault_misses",
        "unresolved_fabricated",
        "unresolved_lost",
        # ...and the stopwatch last.
        "detect_ms",
        "total_ms",
    ], out["html"]
    by_key = {c["key"]: c for c in chips}
    # A timing is dim. A count of what the run did is not.
    assert by_key["detect_ms"]["cls"] == "stat muted"
    assert by_key["total_ms"]["cls"] == "stat muted"
    assert by_key["entities_detected"]["cls"] == "stat"
    assert by_key["tokens_issued"]["cls"] == "stat"
    # `egress_rescan_warnings` is a SAFETY counter and is deliberately NOT painted
    # red at 3: a high-severity re-hit raises EGRESS_BLOCKED and the payload never
    # reaches the provider, so a warning is by construction a hit the gate decided
    # not to deny. Colouring it would teach a reviewer to ignore the colour.
    assert by_key["egress_rescan_warnings"]["cls"] == "stat"
    # The three whose clean reading is 0, showing what they actually read.
    assert by_key["vault_misses"]["cls"] == "stat badge ok"
    assert by_key["unresolved_fabricated"]["cls"] == "stat badge ok"
    assert by_key["unresolved_lost"]["cls"] == "stat badge err", "2 lost tokens is not clean"
    # Every counter the build knows says what it counts, in words.
    unexplained = [c["key"] for c in chips if not (c["title"] or "").strip()]
    assert unexplained == [], f"counters printed with no meaning: {unexplained}"
    assert "not a leak" in by_key["egress_rescan_warnings"]["title"], (
        "the one counter whose non-zero value looks alarming and is not has to say so"
    )
    assert "0 is the clean reading" in by_key["vault_misses"]["title"]
    # The values are untouched by any of the above. One carries an on-screen qualifier
    # and it is the only one that may: ``entities_detected`` is the counter that
    # disagrees with panel 1's header on every run, and the reconciliation used to be
    # reachable only by hovering the OTHER number. Every other value is bare, which is
    # what stops the qualifier turning into decoration on chips that need none.
    assert [c["value"] for c in chips] == [
        f"54 {MID} before policy", "32", "3", "0", "0", "2", "1.0 ms", "12.3 ms",
    ]
    # The key stays the raw API field name -- the qualifier rides with the value, not
    # inside the ``<i>``, because the key is what a reviewer greps and what the stats
    # key section in ``index.html`` indexes by.
    assert by_key["entities_detected"]["key"] == "entities_detected"


def test_the_same_counter_turns_red_when_it_stops_reading_clean(tmp_path: Path) -> None:
    """The colour has to be the value's, not the key's.

    Painting ``vault_misses`` green because it is *usually* zero would make the strip
    reassuring on exactly the run where it should not be -- the vault-miss path
    ``demo.py`` and ``test_vault_miss_on_deobfuscation`` exist to demonstrate. Same
    key, two values, two classes.
    """
    body = (
        "UI.renderStats({ vault_misses: 0 }); const clean = el('stats').innerHTML;"
        "UI.renderStats({ vault_misses: 1 }); const miss = el('stats').innerHTML;"
        "emit({ clean: clean, miss: miss });"
    )
    out = _run(tmp_path, body)
    assert 'class="stat badge ok"' in out["clean"] and "</i>0</span>" in out["clean"]
    assert 'class="stat badge err"' in out["miss"] and "</i>1</span>" in out["miss"]


def test_the_page_carries_a_key_to_the_stats_strip_that_a_run_cannot_wipe() -> None:
    """Three styles mean nothing without a row saying what they mean.

    The key is a static part of ``index.html`` and sits OUTSIDE ``#stats``, because
    ``resetRun`` assigns ``$('stats').innerHTML = ''`` on every run -- a key placed
    inside the strip would survive exactly until the first click of Run. It is its own
    named ``<section>`` for the same reason every other block on this page is: a bare
    ``<section>`` is a landmark only when it has an accessible name.
    """
    elements, by_id = _page()
    keys = [
        n
        for n in elements
        if n["tag"] == "section" and _accessible_name(n, elements, by_id) == "stats strip key"
    ]
    assert len(keys) == 1, "the stats-strip key is missing or has been renamed"
    key = keys[0]
    assert "stats" not in key["ancestors"], "a key inside #stats is wiped by resetRun"
    assert key["attrs"].get("id") != "stats"
    text = _flat(key["text"])
    # Each of the three states app.js can emit, named in words a reviewer can act on.
    assert "green" in text and "clean value of 0" in text
    assert "red" in text and "audit tail" in text
    assert "dim" in text and "not a safety signal" in text
    assert "hover any counter" in text, "the per-counter meanings are tooltips; say so"
    # The swatches have to be the classes app.js actually emits, or the key is
    # explaining a colour that appears nowhere.
    swatches = [n["attrs"].get("class", "") for n in elements if n["tag"] == "i"]
    assert "badge ok" in swatches and "badge err" in swatches, swatches


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
fire('file', 'change');
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
    # Both marks grew the panel-2/3 hover text. The routing this line pins -- which
    # field feeds panel 2, and which class each of the two kinds of mark gets -- is
    # unchanged, and the equality is still exact.
    assert out["p2"] == (
        f'<mark class="tok c-PII" title="{_ps_tip("PERSON")}">Ann</mark> met '
        f'<mark class="tok c-RED" title="{RED_TIP}">[REDACTED_PERSON]</mark>.'
    )
    # Was ``== "Ann met Carl."``, i.e. panel 3 carrying no highlighting at all. That
    # is the one panel a reviewer reads as the provider's-eye view, and under
    # pseudonymization an unmarked surrogate is a realistic fake read as a real
    # value -- the failure README line 2069 calls "the dangerous one". The routing
    # this test exists to pin is unchanged and still asserted: the marked text is
    # ``raw_llm_response``'s and no other field's.
    assert out["p3"] == f'<mark class="tok c-PII" title="{_ps_tip("PERSON")}">Ann</mark> met Carl.'
    assert out["p4"] == '<mark class="rest">Bob</mark> met Carl.'
    # Panel 1's counter reads "spans masked" rather than "spans": it counts
    # ``result.detections``, which the orchestrator fills from ``obf.spans`` -- the
    # spans the ENGINE acted on -- and NOT ``stats.entities_detected``, which is what
    # the detector returned. The two are different numbers on a real document and the
    # header used to name neither. See ``test_the_two_span_counts_on_the_page_are_each
    # _labelled_for_what_they_count``. Everything else this line pinned is unchanged:
    # one span, and the three character counts that prove the panels are fed different
    # fields.
    assert out["counters"] == [
        "13 chars " + MID + " 1 spans masked", "26 chars", "13 chars", "13 chars",
    ]
    # The chip grew a class and a title; the timing, its formatting and the fact that
    # this response's single stat is the only chip rendered are unchanged.
    assert out["stats"] == (
        '<span class="stat muted" title="TIMING. The whole run, end to end.">'
        "<i>total_ms</i>5.5 ms</span>"
    )
    # Was ``"... {MID} strategy pseudonymize"``. ``result.strategy`` is what the caller
    # ASKED FOR (``orchestrator.run``'s ``chosen``) and the banner presented it as a
    # description of the run; it is not one, and the two come apart in a way that puts
    # realistic fake PII on screen under a ``tokenization`` label -- see
    # ``test_a_run_labels_the_strategy_as_requested_and_prints_what_was_emitted``. The
    # word "requested" is the whole of the change visible here: this reply's ``stats``
    # carry neither ``tokens_issued`` nor ``pseudonyms_issued``, so there is nothing to
    # derive a composition from and the page says nothing about one. The routing this
    # line pins -- ``run_id`` and the strategy both off the response -- is unchanged.
    assert out["banner"] == f"<b>RUN_OK</b> run_id r-1 {MID} pseudonymize requested"
    assert out["auditRun"] == "run_id r-1"
    assert out["busy"] is False, "the buttons must be re-enabled after the run"


def test_the_two_span_counts_on_the_page_are_each_labelled_for_what_they_count(
    tmp_path: Path,
) -> None:
    """Panel 1's header and ``entities_detected`` are different numbers, and both say so.

    On ``fixtures/medical_note.txt`` as ``medical`` the header read "52 spans" three
    lines under a strip reading ``entities_detected 54``, and nothing on the page
    reconciled them. Measured through ``PipelineOrchestrator.run`` on that fixture:

    * ``entities_detected`` is ``len(detections)`` -- what the DETECTOR returned over
      the document text, 54, before the engine applied any policy;
    * panel 1's count is ``len(result.detections)``, which the orchestrator fills from
      ``obf.spans`` -- one entry per span the ENGINE acted on, 52, every one of them a
      splice into the outbound payload.

    "52 of 54" is the tempting label and it is false in both directions:
    ``ObfuscationEngine._plan`` dropped 3 of the 54 at the ``MIN_SWEEP_LEN`` = 3
    enforceability floor ("MD", "RN", "MD", all typed ``ADDRESS``), and
    ``_sweep_residual`` ADDED one the detector never returned ("Larkspur Valley
    Hospital", already vaulted this session under another surface form): 54 - 3 + 1 =
    52, and neither set contains the other.

    The reply below reproduces exactly that shape -- two masked spans against
    ``entities_detected`` 3 -- and both numbers have to name their own set.
    """
    body = RUN_SETUP.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }").replace(
        "stats: { total_ms: 5.5 },",
        "stats: { entities_detected: 3, total_ms: 5.5 },",
    ).replace(
        "action: 'PSEUDO', score: 0.9, surrogate: 'Ann' }],",
        "action: 'PSEUDO', score: 0.9, surrogate: 'Ann' },"
        "{ start: 8, end: 12, category: 'PII', entity_type: 'PERSON',"
        " action: 'REDACTED', score: 0.4, surrogate: null }],",
    ) + """
await UI.run();
emit({
  c1: el('c1').textContent, c1title: el('c1').title || '',
  stats: el('stats').innerHTML,
});
"""
    out = _run(tmp_path, body)
    # The header names its own set AND prints the other number beside it, in words
    # that are true of the two sets. Was ``== "13 chars {MID} 2 spans masked"``, which
    # labelled panel 1's count honestly and left the disagreement itself -- 2 here, 3
    # in the strip, on every run -- reachable only by hovering. A reconciliation nobody
    # hovers is not on the page, so it is in the counter now; the tooltip keeps the
    # arithmetic. Strictly more is pinned here than before: both numbers, and the
    # relationship between them.
    # TEST WRONG: it pinned a claim the code cannot support, in the very scenario it
    # builds. `C1_DETECTED` is handed two integers and nothing else, and "neither set
    # contains the other" is a statement about set MEMBERSHIP. It happens to be true of
    # the medical_note measurement quoted in this docstring (54 detected, 3 dropped at
    # the enforceability floor, 1 swept in, 52 masked) -- but that fact came from
    # reading the engine, not from the numbers, and the page prints the sentence on
    # every run from the counts alone. Here the reply is 2 masked against 3 detected,
    # and from 2 and 3 there is no way to rule out the masked spans being 2 OF the 3:
    # the assertion required the page to state, as fact, something underivable and
    # possibly false. Measured in Chrome on legal_brief_large.txt it printed "detector
    # returned 739, neither set contains the other" beside "739 spans masked", where it
    # reads as a flat self-contradiction.
    #
    # The replacement is the same shape of check -- exact equality on the whole counter
    # -- against a clause DERIVED from the two numbers, and it is the arithmetic that is
    # actually available: a surplus of masked spans proves that many were not
    # detections (the residual sweep), a deficit proves that many detections were not
    # masked, and equal counts prove nothing about the sets and now say so. Everything
    # else this test pinned is untouched: both numbers still appear, each still names
    # its own set, and "N of M" is still forbidden below.
    assert out["c1"] == (
        "13 chars " + MID + " 2 spans masked " + MID +
        " detector returned 3, so at least 1 of them was not masked"
    )
    # ...and points at the other number, by name, with the reason they differ.
    tip = out["c1title"]
    assert "entities_detected" in tip, tip
    assert "Neither is a subset of the other" in tip, tip
    assert "54 detected, 3 dropped, 1 swept in, 52 masked" in tip, tip
    # The claim the earlier attempt correctly refused to write must not come back --
    # neither in the tooltip nor, now that both numbers are printed together, in the
    # line that prints them.
    assert "2 of 3" not in tip and "2 of 3" not in out["c1"]
    # And the strip's own counter says which set it counted ON SCREEN, not only on
    # hover: the chip a reviewer reads first is the one in the strip, and "hover the
    # other number" is not a thing anyone does to a count that looks fine.
    chips = {m.group("key"): m.groupdict() for m in _CHIP.finditer(out["stats"])}
    assert chips["entities_detected"]["value"] == f"3 {MID} before policy", chips
    assert chips["entities_detected"]["title"].startswith("SAFETY."), chips
    assert "before any policy ran" in chips["entities_detected"]["title"]
    assert "The header of panel 1 counts a different set" in chips["entities_detected"]["title"]
    assert "neither is a subset of the other" in chips["entities_detected"]["title"]


#: One run per (requested strategy, emitted composition) the banner has to describe,
#: driven through the real ``run()`` back to back in ONE session -- which is the
#: mechanism under test: the vault keys a record by (entity type, value) for the life
#: of the session, so run 2 inherits run 1's surrogates whatever strategy it asks for.
#:
#: The two counter values are the ones the live API reports. Measured through
#: ``PipelineOrchestrator.run`` over ``httpx.ASGITransport`` on
#: ``fixtures/medical_note.txt`` as ``medical``, one session, both orders:
#: ``tokens_issued`` 32 on all four runs; ``pseudonyms_issued`` 0 for both runs of the
#: tokenization-first session and 18 for both runs of the pseudonymization-first one.
_COMPOSITIONS = (
    # Direction B, the dangerous one: pseudonymization ran first, tokenization was
    # then selected, and the payload still carries 18 realistic fakes. Measured panel
    # 2 under that label: "Patient name: Steven Lee", "Phone: 468-376-2490",
    # "romerochristina@example.org".
    ("tokenization", {"tokens_issued": 32, "pseudonyms_issued": 18}),
    # Direction A: tokenization ran first, pseudonymization was then selected, and not
    # one fake reached the wire. Measured panel 2: "Patient name: [PII_NAME_09453c04]".
    ("pseudonymization", {"tokens_issued": 32, "pseudonyms_issued": 0}),
    # The two runs that are doing exactly what was asked.
    ("tokenization", {"tokens_issued": 32, "pseudonyms_issued": 0}),
    ("pseudonymization", {"tokens_issued": 32, "pseudonyms_issued": 18}),
    # A strategy name this page has never heard of. `config._BUILTIN_STRATEGIES` is a
    # floor, not a closed set.
    ("k-anonymity", {"tokens_issued": 32, "pseudonyms_issued": 18}),
    # A run that vaulted nothing: there is no composition, and no drift either.
    ("pseudonymization", {"tokens_issued": 0, "pseudonyms_issued": 0}),
    # The counters absent altogether. Nothing to derive from, so nothing may be said.
    ("pseudonymization", {"total_ms": 5.5}),
)


def _composition_banners(tmp_path: Path) -> list[dict]:
    """Drive ``run()`` once per row of ``_COMPOSITIONS``; return each banner."""
    body = RUN_SETUP.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }") + f"""
const cases = {json.dumps([list(c) for c in _COMPOSITIONS])};
const shots = [];
for (const c of cases) {{
  RESULT.strategy = c[0];
  RESULT.stats = c[1];
  await UI.run();
  shots.push({{ cls: el('banner').className, html: el('banner').innerHTML }});
}}
emit({{ shots: shots }});
"""
    return _run(tmp_path, body)["shots"]


def test_the_banner_prints_the_composition_the_run_emitted_not_the_strategy_asked_for(
    tmp_path: Path,
) -> None:
    """A run labelled ``tokenization`` can put 18 realistic fake identities on screen.

    ``PipelineResult.strategy`` is ``orchestrator.run``'s ``chosen`` -- the dropdown's
    value, or the server default. The banner printed it as ``strategy <name>``, i.e. as
    a description of what the run did, and it is not one. The vault keys a record by
    (entity type, value) for the **life of the session** and has no strategy dimension
    (``_surrogate_map``, ``_pseudonyms_issued``), so whichever strategy ran first owns
    every surrogate that value gets afterwards. That reuse is deliberate: it is what
    makes a pseudonym minted on run 1 still restore correctly on run 4.

    Measured through the real API over ``httpx.ASGITransport`` on
    ``fixtures/medical_note.txt`` as ``medical``, one session, both orders,
    ``tokens_issued`` 32 on every run:

    * pseudonymization then **tokenization** -> ``pseudonyms_issued`` 18, banner
      "strategy tokenization", panel 2 reading "Patient name: Steven Lee", "Phone:
      468-376-2490", "romerochristina@example.org", "Note filed 06/07/2024 by physician
      Benjamin Hansen, MD";
    * tokenization then **pseudonymization** -> ``pseudonyms_issued`` 0, banner
      "strategy pseudonymization", panel 2 reading "Patient name: [PII_NAME_09453c04]".

    The first is the dangerous one and it is dangerous *because* the label is
    reassuring: a reviewer inspecting panel 2 under the word "tokenization" reads
    eighteen invented values as this patient's real ones, and the only contradicting
    signal was a ``pseudonyms_issued`` chip whose meaning was hover-only.

    So the banner prints the composition, derived from the two counters the response
    already carries, and the requested name is labelled "requested" rather than stated.
    Nothing about what the pipeline emits changes.
    """
    drift, understated = _composition_banners(tmp_path)[:2]

    # -- direction B, in full. The exact string, because every clause of it is load
    # -- bearing: the count, the split, why a tokenization run can carry a fake at all,
    # -- and what that means for the panel directly below the banner.
    assert drift["html"] == (
        "<b>RUN_OK_STRATEGY_DRIFT</b> "
        f"run_id r-1 {MID} tokenization requested {MID} 18 of the 32 surrogates in the "
        f"payload are realistic fake values, 14 are bracketed tokens {MID} tokenization "
        "mints no fake values at all, so those 18 came from records an earlier call in "
        "THIS session created: the vault keys a record by (entity type, value) for the "
        "life of the session and has no strategy dimension. The fakes in panel 2 are "
        "invented values, not values taken from this document, and the label above "
        "them says tokenization."
    )
    # Yellow, not green. The run succeeded -- what is wrong is the page's own label --
    # so the code keeps its RUN_OK prefix and the colour carries the warning.
    assert drift["cls"] == "banner warn"
    # And the sentence that was there before must not be: "strategy tokenization",
    # unqualified, is the claim the whole change exists to stop making.
    assert "strategy tokenization" not in drift["html"], drift["html"]

    # -- direction A. Understating is still a false label, and it is still flagged --
    # but the reason is stated with both readings, because the response cannot
    # separate "already tokenised earlier in this session" from "nothing in a
    # pseudonymised tier" and picking one would be the same over-claim again.
    assert understated["cls"] == "banner warn"
    assert "<b>RUN_OK_STRATEGY_DRIFT</b>" in understated["html"]
    assert "pseudonymization requested" in understated["html"]
    assert "all 32 surrogates in the payload are bracketed tokens" in understated["html"]
    assert "The response cannot tell those two apart." in understated["html"]
    assert "strategy pseudonymization" not in understated["html"], understated["html"]


def test_a_run_doing_what_was_asked_still_prints_its_composition_and_stays_green(
    tmp_path: Path,
) -> None:
    """The colour is reserved for the lie; the composition is printed on every run.

    Two things this must not do. It must not go quiet when the request and the output
    agree -- then the number a reviewer needs is present only on the runs the page
    already decided to shout about, and "no clause" becomes indistinguishable from "a
    response with no counters".

    And it must not fire yellow on a *mixed* pseudonymization run, which is the correct
    output of an ordinary one: ``PseudonymizationStrategy.make_surrogate`` dispatches by
    tier and returns ``plain_token`` for the content tier, so 18 fakes and 14 tokens out
    of 32 is the design working. ``renderScope`` already had to undo a caution that
    fired on 100% of passes; a second one would teach a reviewer to skip both.
    """
    shots = _composition_banners(tmp_path)
    honest_tok, honest_ps = shots[2], shots[3]

    assert honest_tok["cls"] == "banner ok"
    assert honest_tok["html"] == (
        f"<b>RUN_OK</b> run_id r-1 {MID} tokenization requested {MID} all 32 surrogates "
        "in the payload are bracketed tokens"
    )
    assert honest_ps["cls"] == "banner ok"
    assert honest_ps["html"] == (
        f"<b>RUN_OK</b> run_id r-1 {MID} pseudonymization requested {MID} 18 of the 32 "
        "surrogates in the payload are realistic fake values, 14 are bracketed tokens"
    )


def test_the_banner_states_no_verdict_it_cannot_derive_from_the_response(
    tmp_path: Path,
) -> None:
    """Three responses that support less than a full verdict, each said honestly.

    This is the half that keeps the fix from becoming the defect it replaces. The page
    may say only what the response carries:

    * an unregistered strategy name -- ``config._BUILTIN_STRATEGIES`` is a floor, not a
      closed set -- has made no promise this page knows about, so its composition is
      printed and no agree/disagree verdict is reached;
    * a run that vaulted nothing has no composition to print, and saying "all 0
      surrogates are tokens" would be a shape claim about an empty payload;
    * a response carrying neither counter supports no statement at all, and the
      strategy is still labelled as the *request* -- which is true whatever was
      emitted, and is what the bare "strategy <name>" was not.
    """
    shots = _composition_banners(tmp_path)
    unknown, empty, no_counters = shots[4], shots[5], shots[6]

    # Composition printed, verdict withheld, green -- because "disagrees" is not a
    # thing this page can assert about a strategy whose promise it does not know.
    assert unknown["cls"] == "banner ok"
    assert unknown["html"] == (
        f"<b>RUN_OK</b> run_id r-1 {MID} k-anonymity requested {MID} 18 of the 32 "
        "surrogates in the payload are realistic fake values, 14 are bracketed tokens"
    )

    assert empty["cls"] == "banner ok"
    assert empty["html"] == (
        f"<b>RUN_OK</b> run_id r-1 {MID} pseudonymization requested {MID} this run "
        "vaulted nothing, so the payload carries no surrogates of either kind"
    )

    # Nothing derived, nothing claimed -- and no count invented to fill the gap.
    assert no_counters["cls"] == "banner ok"
    assert no_counters["html"] == (
        f"<b>RUN_OK</b> run_id r-1 {MID} pseudonymization requested"
    )
    for word in ("surrogates", "bracketed", "fake"):
        assert word not in no_counters["html"], no_counters["html"]


async def _two_runs_in_one_session(data_dir: Path, first: str, second: str) -> dict:
    """Run ``fixtures/medical_note.txt`` twice in ONE session, and return run 2's body.

    The real app, the real registry, the real vault, over ``httpx.ASGITransport`` -- no
    port, no ``./data``. ``MockProvider`` echoes, so no key and no network.
    """
    settings = Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=data_dir,
        registry_path=REGISTRY_PATH,
        llm_provider="mock",
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://scp.test") as http:
            created = await http.post("/sessions", json={"user_id": "demo-user"})
            assert created.status_code == 200, created.text
            session_id = created.json()["session_id"]
            uploaded = await http.post(
                "/documents",
                files={
                    "file": (
                        "medical_note.txt",
                        MEDICAL_NOTE.read_bytes(),
                        "text/plain",
                    )
                },
                data={"user_id": "demo-user", "doc_category": "medical"},
            )
            assert uploaded.status_code == 200, uploaded.text
            doc_id = uploaded.json()["doc_id"]
            body: dict = {}
            for strategy in (first, second):
                run = await http.post(
                    "/pipeline/run",
                    json={
                        "session_id": session_id,
                        "user_id": "demo-user",
                        "doc_id": doc_id,
                        "prompt": "Summarize this document and list the key facts.",
                        "strategy": strategy,
                    },
                )
                assert run.status_code == 200, run.text
                body = run.json()
            return body


async def test_the_real_pipeline_drives_the_drift_banner_and_the_span_reconciliation(
    tmp_path: Path,
) -> None:
    """The whole path, once, with nothing hand-written between the two ends.

    Every other test in this section hands ``app.js`` a reply a person typed. That
    proves the page reasons correctly about the shape it was given and proves nothing
    about the shape the pipeline actually sends -- which is the failure mode the banner
    was in: a page describing a response it had never been checked against. So this one
    runs ``fixtures/medical_note.txt`` twice in one real session,
    **pseudonymization then tokenization**, and feeds run 2's genuine
    ``PipelineResult`` into the real ``run()`` in node.

    Run 2 is the dangerous direction. It asked for ``tokenization``; the vault keys a
    record by (entity type, value) for the life of the session, so it re-emits run 1's
    fakes and the payload goes out carrying invented names, phone numbers, e-mail
    addresses and shifted dates -- all of it under a label that used to read "strategy
    tokenization" and nothing else.

    The expected numbers are read off the API's own response rather than written here,
    because the point is that the page and the pipeline agree; the hand-written part is
    the floor each one has to clear, which is what stops a degenerate response (no
    detections, no tokens) from making the whole test vacuous.
    """
    result = await _two_runs_in_one_session(
        tmp_path / "data", "pseudonymization", "tokenization"
    )
    total = round(result["stats"]["tokens_issued"])
    fakes = round(result["stats"]["pseudonyms_issued"])
    detected = round(result["stats"]["entities_detected"])
    masked = len(result["detections"])

    # The defect, reproduced against the live pipeline before anything is asserted
    # about the page. Floors, not equalities: the exact counts move with the registry.
    assert result["strategy"] == "tokenization"
    assert fakes >= 10, f"the reuse did not happen, so there is no drift to report: {fakes}"
    assert total >= 30 and fakes < total, (total, fakes)
    # ...and the fakes are really on the wire, not merely counted. A surrogate that the
    # emitted-token grammar does not match is a realistic fake by construction
    # (``orchestrator._is_pseudonym``), and it is spliced into the payload verbatim.
    payload = result["obfuscated_payload"]
    token_shaped = re.compile(r"\[[A-Z]+_[A-Z0-9_]+_[0-9a-f]{8}\]")
    fake_surrogates = [
        d["surrogate"]
        for d in result["detections"]
        if d.get("surrogate") and not token_shaped.fullmatch(d["surrogate"])
    ]
    assert fake_surrogates, "no pseudonym reached the payload, so this is not direction B"
    assert any(s in payload for s in fake_surrogates), "the fakes are counted but not emitted"
    # The two span counts really do disagree, on this run, with no help from a fixture.
    assert masked != detected, (masked, detected)

    body = f"""
const RESULT = {json.dumps(result)};
const DOC = {json.dumps(MEDICAL_NOTE.read_text(encoding="utf-8"))};
respond((path, init) => {{
  const m = (init && init.method) || 'GET';
  if (m === 'POST' && path === '/documents') return {{ status: 200, body: {{ doc_id: 'doc-1' }} }};
  if (path.indexOf('/documents/doc-1/text') === 0) {{
    return {{ status: 200, body: {{ text: DOC, chars: DOC.length }} }};
  }}
  if (path === '/pipeline/run') return {{ status: 200, body: RESULT }};
  if (path.indexOf('/audit') === 0) return {{ status: 200, body: {{ events: [] }} }};
  return {{ status: 200, body: {{}} }};
}});
UI.S.sessionId = 'sess-1';
el('prompt').value = 'Summarize this document and list the key facts.';
el('strategy').value = 'tokenization';
el('category').value = 'medical';
el('file').files = [{{ name: 'medical_note.txt', size: 2826, lastModified: 11 }}];
fire('file', 'change');
await UI.run();
emit({{
  banner: el('banner').innerHTML, cls: el('banner').className,
  c1: el('c1').textContent, stats: el('stats').innerHTML,
}});
"""
    out = _run(tmp_path, body)

    # The banner is yellow, names the drift, and carries the pipeline's own two counts.
    assert out["cls"] == "banner warn", out["banner"]
    assert out["banner"].startswith("<b>RUN_OK_STRATEGY_DRIFT</b>"), out["banner"]
    assert (
        f"{fakes} of the {total} surrogates in the payload are realistic fake values, "
        f"{total - fakes} are bracketed tokens"
    ) in out["banner"], out["banner"]
    assert "tokenization requested" in out["banner"], out["banner"]
    # The sentence a reviewer used to read over eighteen invented identities.
    assert "strategy tokenization" not in out["banner"], out["banner"]

    # Panel 1's header prints both span counts and the relationship that holds between
    # them, and the strip's chip says which set its number is -- both on screen.
    # Same verdict and same reasoning as the other site of this string (see the block at
    # `test_the_two_span_counts_on_the_page_are_each_labelled_for_what_they_count`): the
    # clause is now derived from the two counts instead of asserted over them. This one
    # runs against the REAL pipeline, so the branch it exercises depends on what the
    # engine actually did -- which is the point, and why the expectation is computed
    # from the same two numbers the page is given rather than hard-coded.
    if masked > detected:
        tail = (f"detector returned {detected}, so at least {masked - detected} masked "
                f"{'span was' if masked - detected == 1 else 'spans were'} not among them")
    elif masked < detected:
        tail = (f"detector returned {detected}, so at least {detected - masked} of them "
                f"{'was' if detected - masked == 1 else 'were'} not masked")
    else:
        tail = (f"detector returned {detected} — the same count, which does not make "
                f"them the same spans")
    assert out["c1"].endswith(f"{masked} spans masked {MID} {tail}"), out["c1"]
    # The claim that was there before must not come back by any route, including the
    # equal-count branch where it is at its most obviously unearned.
    assert "neither set contains the other" not in out["c1"], out["c1"]
    assert f"{masked} of {detected}" not in out["c1"], out["c1"]
    chips = {m.group("key"): m.group("value") for m in _CHIP.finditer(out["stats"])}
    assert chips["entities_detected"] == f"{detected} {MID} before policy", chips
    assert chips["pseudonyms_issued"] == str(fakes), chips


def _orchestrator_stat_keys() -> set[str]:
    """Every ``stats["<key>"] = ...`` the orchestrator assigns, by AST, not by hand."""
    source = (
        REPO_ROOT / "secure_context_pipeline" / "pipeline" / "orchestrator.py"
    ).read_text(encoding="utf-8")
    keys: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == "stats"
                and isinstance(target.slice, ast.Constant)
                and isinstance(target.slice.value, str)
            ):
                keys.add(target.slice.value)
    return keys


def test_the_counters_the_banner_reasons_from_are_counters_the_pipeline_emits() -> None:
    """A rename in ``orchestrator.py`` must not silence the banner instead of failing it.

    ``strategyClause`` prints a composition only when the response carries both
    counters, and prints nothing when it does not -- which is the honest answer to a
    response that supports no claim, and is also exactly what a *typo* looks like. Rename
    ``pseudonyms_issued`` in the pipeline and the drift warning stops firing for good,
    on a green suite, because every behavioural test above hands the page a
    hand-written reply that still spells it the old way. The banner would go back to
    "tokenization requested" with 18 fakes underneath it and nothing anywhere red.

    So the two names are pinned across the seam. Both halves are derived and they are
    derived by different means -- an AST walk over ``orchestrator.py`` for the keys the
    pipeline assigns, a text read of ``app.js`` for the keys the clause reads -- and
    they meet at a pair written out by hand here. Neither side can drift alone.
    """
    emitted = _orchestrator_stat_keys()
    # A walk that quietly found nothing must be red rather than vacuously green.
    assert len(emitted) >= 15, f"the AST walk over orchestrator.py is broken: {sorted(emitted)}"
    assert {"entities_detected", "tokens_issued", "restored_count"} <= emitted, sorted(emitted)

    read_by_the_banner = {"tokens_issued", "pseudonyms_issued"}
    missing = read_by_the_banner - emitted
    assert not missing, (
        "the banner's composition clause reads counters the pipeline no longer emits, so "
        f"it will print nothing instead of failing: {sorted(missing)}"
    )

    source = APP_JS.read_text(encoding="utf-8")
    clause = source.split("function strategyClause(", 1)[1].split("\n  }\n", 1)[0]
    for key in sorted(read_by_the_banner):
        assert f"'{key}' in s" in clause, f"strategyClause no longer reads {key}"
        assert f"s.{key}" in clause, f"strategyClause no longer reads {key}"
    # Panel 1's on-screen reconciliation reads the third one across the same seam.
    assert "'entities_detected' in st" in source, "panel 1 no longer reads entities_detected"


def test_a_refused_run_does_not_leave_the_span_reconciliation_on_an_empty_counter(
    tmp_path: Path,
) -> None:
    """``resetRun`` clears the counter, so it has to clear the counter's tooltip too.

    ``C1_TITLE`` states one run's arithmetic. Left behind, a tooltip saying "54
    detected, 3 dropped, 1 swept in, 52 masked" hangs off a blank counter above a
    refused run's empty panels -- the previous run still talking, which is the exact
    cross-run mixture ``resetRun`` exists to prevent.
    """
    body = RUN_SETUP.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }") + """
await UI.run();
const after = { c1: el('c1').textContent, title: el('c1').title || '' };
el('file').files = [];
fire('file', 'change');
await UI.run();
emit({ after: after, cleared: el('c1').textContent, title: el('c1').title || '' });
"""
    out = _run(tmp_path, body)
    assert out["after"]["c1"].endswith("spans masked") and out["after"]["title"] != ""
    assert out["cleared"] == ""
    assert out["title"] == "", "the previous run's span arithmetic is still on the page"


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


# ---------------------------------------------------------------------------
# the code-to-sentence table
# ---------------------------------------------------------------------------
#: One realistic error body per code the API can answer with, and a fragment of
#: the sentence the page must produce for it. Every body here is the shape the
#: named raise site actually builds -- ``api/routes/documents.py`` for the upload
#: codes, ``api/middleware.py::_send_too_large`` for ``REQUEST_TOO_LARGE``,
#: ``api/errors.py::_validation_handler`` for ``VALIDATION_ERROR``, and the
#: ``__init__`` of the matching ``PipelineError`` subclass for the rest -- so a
#: sentence that reads a field the API never sends fails here.
#:
#: The fragments are hand-written. Nothing in this file calls the table under test
#: to build an expectation, and each one names a CONTROL or an ACTION rather than
#: restating the code: that is the property the blob did not have, and a fragment
#: that only echoed the code would pass against the blob too.
_CODE_SENTENCES: tuple[tuple[str, dict[str, object], str], ...] = (
    (
        "UNPROCESSABLE_DOCUMENT",
        {"reason": "unsupported_document_type", "suffix": ".xyz", "detected": "unknown"},
        "Choose a .txt, .md, .pdf or .docx with the file picker.",
    ),
    ("EMPTY_UPLOAD", {"bytes": 0}, "Choose a document with text in it with the file picker"),
    (
        "UPLOAD_TOO_LARGE",
        {"max_bytes": 16 * 1024 * 1024, "bytes": 32 * 1024 * 1024},
        "Choose a smaller file with the file picker",
    ),
    (
        "REQUEST_TOO_LARGE",
        {"max_bytes": 17 * 1024 * 1024, "bytes": 32 * 1024 * 1024},
        "Choose a smaller file with the file picker.",
    ),
    (
        "INVALID_DOC_CATEGORY",
        {"value": "misc"},
        "Choose medical, legal, financial or general in the Category dropdown",
    ),
    (
        "VALIDATION_ERROR",
        {"errors": 1, "fields": "body.doc_id"},
        "The API rejected doc_id.",
    ),
    (
        "BAD_REQUEST",
        {"status": 400},
        "Re-choose the file with the file picker",
    ),
    (
        "NOT_FOUND",
        {"doc_id": "0f2c"},
        "check the User ID field still matches the session owner",
    ),
    (
        "AUDIT_SCOPE_REQUIRED",
        {"reason": "session_id_or_run_id_required"},
        'Press "Create session" first.',
    ),
    # Copied off the live API rather than read off the class. Measured on this build
    # against an ``audit.db`` with one 4 KiB page overwritten: ``POST /sessions``
    # answered 503 with exactly this body, and ``GET /audit`` and ``GET /audit/verify``
    # answered the same with ``operation`` reading ``query`` and ``length``. ``emit``
    # is the row here because it is the one that refuses a RUN; the other branch is
    # asserted in its own test below.
    (
        "AUDIT_UNAVAILABLE",
        {
            "reason": "audit_log_unreadable",
            "operation": "emit",
            "audit_db": "audit.db",
            "error": "DatabaseError",
            "remedy": "restore it from backup or start a fresh data directory",
        },
        "from backup, or point SCP_DATA_DIR at a fresh directory",
    ),
    # The audit log's two siblings, both found by
    # ``test_every_code_the_api_can_emit_has_a_sentence_in_the_page`` rather than
    # remembered. Neither has a handler of its own in ``api/errors.py``, so both fall
    # through to the base ``PipelineError`` registration and answer 500 carrying their
    # own code -- which is the code this page has to explain. Bodies copied from the
    # class constructors in ``vault/session_vault.py`` and ``store/document_store.py``.
    #
    # The fragments are the part that matters: each names the remedy that is TRUE FOR
    # THAT STORE, and the three remedies contradict each other. A shared "restore it
    # from backup" would be actively wrong for the vault.
    (
        "VAULT_UNAVAILABLE",
        {
            "reason": "vault_unreadable",
            "operation": "put",
            "vault_db": "vault.db",
            "error": "DatabaseError",
            "remedy": "start a fresh data directory and a new session",
        },
        "from backup will NOT work",
    ),
    (
        "DOCUMENT_STORE_UNAVAILABLE",
        {
            "reason": "document_store_unreadable",
            "operation": "put",
            "store_db": "documents.db",
            "error": "DatabaseError",
            "remedy": "restore it from backup or re-upload the document",
        },
        "choose the file again with the file picker",
    ),
    (
        "VAULT_MISS",
        {"session_id": "3f", "token_id": "PII_NAME_0a1b2c3d"},
        "has no vault entry to restore it from",
    ),
    ("CRYPTO_AUTH_FAILED", {"scope": "vault_row"}, "that is the tamper check firing"),
    ("NOT_READY", {}, "Wait a few seconds and press the button again."),
    ("CONFIG_ERROR", {"reason": "anthropic_api_key_missing"}, "Correct the API environment"),
    (
        "DETECTION_ERROR",
        {"chunk_index": 3, "reason": "model_unavailable"},
        "Try another document with the file picker",
    ),
    (
        "DETECTION_INVARIANT",
        {"reason": "overlapping_spans"},
        "refused to continue rather than obfuscate",
    ),
    ("PIPELINE_ERROR", {"reason": "unknown_strategy"}, "the server log carries the traceback"),
    ("LLM_ERROR", {"model": "claude"}, "Only the obfuscated payload was ever sent"),
    (
        "LLM_REFUSAL",
        {"model": "claude", "stop_reason": "refusal", "category": "self_harm", "attempt": 1},
        "Reword the prompt and run again.",
    ),
    (
        "LLM_TRANSPORT_ERROR",
        {"model": "claude", "reason": "timeout", "attempts": 3, "status_code": None},
        "check the API key and network",
    ),
    (
        "LLM_RESPONSE_ERROR",
        {"model": "claude", "reason": "no_text_blocks", "stop_reason": "end_turn"},
        "set the provider to mock to keep the demo moving",
    ),
    ("SESSION_EXPIRED", {"session_id": "3f"}, 'Press "Create session" for a new one'),
    ("RATE_LIMITED", {"retry_after_seconds": 4}, "Wait 4 seconds and retry."),
    ("EGRESS_BLOCKED", {"reason": "vault_original", "hit_count": 2}, "No provider call was made."),
    # The run path's other refusal, and the one whose remedy is arithmetic rather than
    # a different document. Body copied from ``PayloadTooLargeError.__init__``; the
    # fragment names the control (the file picker) and the action (split it), because
    # "too large" on its own is the unactionable half of this banner.
    (
        "PAYLOAD_TOO_LARGE",
        {
            "reason": "payload_over_context_limit",
            "session_id": "3f",
            "payload_chars": 812_004,
            "limit_chars": 250_000,
            "run_id": "9c",
            "remedy": "split the document and run each part as its own request",
        },
        "Split the document and upload each part with the file picker",
    ),
)


def _banners(tmp_path: Path, cases: object) -> dict[str, str]:
    """Drive ``showError`` once per ``(code, detail)`` pair; return the banner HTML."""
    body = f"""
const cases = {json.dumps(cases)};
const seen = {{}};
for (const c of cases) {{
  UI.showError({{ code: c[0], detail: c[1] }});
  seen[c[0]] = el('banner').innerHTML;
}}
emit({{ seen: seen }});
"""
    return _run(tmp_path, body)["seen"]


def test_every_api_error_code_gets_an_actionable_sentence(tmp_path: Path) -> None:
    """A banner must name a control or an action, not end in the detail map.

    What shipped was ``NO_FILE`` and ``NO_CATEGORY`` written as instructions and
    every other code rendered as ``<code> {"reason":"unsupported_document_type",
    "suffix":".xyz","detected":"unknown"}``. The blob is accurate and it is not an
    answer: it names no control on the page, and a reviewer reading it during the
    live review learns only that something in a document they cannot see was wrong.

    Two assertions per code, and the second is the one that binds. A sentence
    checked only for a substring can still be followed by the blob it was supposed
    to replace, so the rendering is also required to carry no ``{"`` -- with one
    exception, argued at the assertion.
    """
    seen = _banners(tmp_path, [[code, detail] for code, detail, _ in _CODE_SENTENCES])
    for code, _, fragment in _CODE_SENTENCES:
        assert seen[code].startswith(f"<b>{code}</b> "), seen[code]
        assert fragment.replace('"', "&quot;") in seen[code], f"{code}: {seen[code]}"
        if code == "EGRESS_BLOCKED":
            # The one code that still appends its detail, and deliberately: `reason`
            # (vault_original / detector_rescan / independent_pattern / gate_exception)
            # and `hit_count` are the demo's evidence that the gate fired and which
            # exit it took, and app.js's comment there calls that load-bearing. The
            # sentence must still come FIRST, which is what the blob-free codes get
            # for free.
            assert seen[code].index("No provider call") < seen[code].index("{&quot;")
            continue
        assert "{&quot;" not in seen[code], f"{code} still ends in a detail blob: {seen[code]}"


def _pipeline_error_codes() -> set[str]:
    """Every ``code`` a :class:`PipelineError` in this package can answer with.

    Imports the whole package first, because ``__subclasses__`` only sees classes that
    have been imported -- the same discovery ``test_crypto.py`` uses for the detail
    ceiling. Extracted so the two tests that need this set cannot drift into two
    copies of one rule; neither of their assertions changed when it moved here.
    """
    importlib.import_module("secure_context_pipeline")
    package = sys.modules["secure_context_pipeline"]
    for module in pkgutil.walk_packages(package.__path__, f"{package.__name__}."):
        importlib.import_module(module.name)

    def walk(cls: type[PipelineError]) -> Iterator[type[PipelineError]]:
        for sub in cls.__subclasses__():
            yield sub
            yield from walk(sub)

    return {PipelineError.code} | {sub.code for sub in walk(PipelineError)}


#: A code literal as the API writes one: SHOUT_CASE, three characters or more. Used
#: to reject the other strings that sit in the same argument positions (a route path,
#: a reason, a header name) without having to list them.
_CODE_LITERAL = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")

#: The two callables in ``api/`` that turn a status and a code into a response body:
#: ``ApiError(status, code, detail)`` -- the transport-level exception every route
#: raises -- and ``errors.py::_json(status, code, detail)``, which the handlers call
#: directly for the codes that have no exception class at all. Both take the code as
#: their SECOND POSITIONAL argument, which is what :func:`_transport_error_codes`
#: reads.
_CODE_CALLS = frozenset({"ApiError", "_json"})


def _code_strings(node: ast.expr) -> set[str]:
    """Every string literal ``node`` can evaluate to, following a conditional.

    ``errors.py::_http_exception_handler`` writes its two codes as
    ``code = "NOT_FOUND" if exc.status_code == 404 else "BAD_REQUEST"``, so a reader
    that only understood ``ast.Constant`` would find neither of them -- and
    ``BAD_REQUEST`` is the multipart-parse failure, i.e. the upload path, i.e. exactly
    the code a demo reviewer can trip by hand.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _code_strings(node.body) | _code_strings(node.orelse)
    return set()


def _transport_error_codes() -> dict[str, str]:
    """Every code literal in ``api/``, mapped to the source line that writes it.

    Parsed rather than imported, and parsed rather than grepped. Importing would only
    find the codes some request happened to reach; grepping ``"[A-Z_]+"`` over the
    package would sweep up log keys, event types and half the docstrings. The AST
    knows the difference between a string in an argument position that becomes a
    response body and a string that is prose.

    Three shapes are read, and between them they are every way this package names a
    code that has no exception class:

    * the second positional argument of :data:`_CODE_CALLS`;
    * a ``code=`` keyword -- ``api/middleware.py``'s two ``_send_*`` writers, which
      answer before any handler runs;
    * an assignment to a bare ``code``, including the conditional one.
    """
    api = REPO_ROOT / "secure_context_pipeline" / "api"
    sites: dict[str, str] = {}
    for path in sorted(api.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            found: set[str] = set()
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name in _CODE_CALLS and len(node.args) >= 2:
                    found |= _code_strings(node.args[1])
                for keyword in node.keywords:
                    if keyword.arg == "code":
                        found |= _code_strings(keyword.value)
            elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "code" for t in node.targets
            ):
                found |= _code_strings(node.value)
            for code in found:
                if _CODE_LITERAL.match(code):
                    sites.setdefault(code, f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    return sites


def test_every_code_the_api_can_emit_has_a_sentence_in_the_page(tmp_path: Path) -> None:
    """No new error code may reach the demo UI as a bare code again.

    ``AUDIT_UNAVAILABLE`` is why this exists. It was added to ``errors.py`` to replace
    an unactionable 500 -- a ``text/plain`` "Internal Server Error" with no ``code``,
    no CSP and no ``nosniff`` -- with something a person can act on, and it landed with
    no entry in ``app.js``'s SENTENCES table, so the page rendered the one code written
    for legibility as the word ``AUDIT_UNAVAILABLE`` and a JSON map. The guard that
    should have caught it was one indirection short: the test below walks the exception
    classes and requires each to appear in ``_CODE_SENTENCES``, and ``_CODE_SENTENCES``
    is hand-written, so the *transport* codes -- the ten with no class to walk -- were
    covered only by having been remembered.

    So both halves are derived here, and neither is a hand-copy:

    * the domain half from ``PipelineError.__subclasses__`` (:func:`_pipeline_error_codes`);
    * the transport half by PARSING ``api/`` for the literals that become a response
      body (:func:`_transport_error_codes`).

    And what is asserted is the page, not a list: every derived code is pushed through
    the real ``showError`` in node with an EMPTY detail, which is the one input under
    which the unknown-code fall-through renders ``<b>CODE</b>`` and nothing else. A
    code with a sentence produces prose; a code without one produces exactly the string
    ``test_an_unknown_error_code_still_renders_everything_the_body_carried`` pins. That
    makes this test independent of ``_CODE_SENTENCES`` entirely -- deleting a row there
    would not quiet it -- while ``test_every_api_error_code_gets_an_actionable_sentence``
    goes on asserting that the prose names a control, which no derivation can check.
    """
    transport = _transport_error_codes()
    domain = _pipeline_error_codes()
    # The derivations are the whole test, so a derivation that quietly found nothing
    # must be red rather than vacuously green. Each anchor is a code reached by a
    # different mechanism: a bare `ApiError`, a `code=` keyword in the middleware, the
    # conditional assignment in `_http_exception_handler`, and a `_json` call.
    assert {"NOT_READY", "REQUEST_TOO_LARGE", "BAD_REQUEST", "VALIDATION_ERROR"} <= set(
        transport
    ), f"the AST walk over api/ is broken -- it found {sorted(transport)}"
    assert {"AUDIT_UNAVAILABLE", "EGRESS_BLOCKED", "PIPELINE_ERROR"} <= domain, sorted(domain)

    codes = set(transport) | domain
    assert len(codes) >= 24, f"only {len(codes)} codes discovered: {sorted(codes)}"

    seen = _banners(tmp_path, [[code, {}] for code in sorted(codes)])
    silent = {
        code: transport.get(code, "PipelineError subclass")
        for code in sorted(codes)
        if seen[code].strip() == f"<b>{code}</b>"
    }
    assert not silent, (
        "these codes reach the demo UI as a bare code with no sentence -- add one to "
        f"the SENTENCES table in ui/app.js: {silent}"
    )


def test_the_two_halves_of_an_unreadable_audit_log_are_not_one_sentence(
    tmp_path: Path,
) -> None:
    """A refused run and an empty audit panel are different news under one code.

    ``AuditUnavailableError`` is raised by all three ``AuditLogger`` entry points, and
    ``operation`` is what tells them apart. Measured against the real API on an
    ``audit.db`` with one 4 KiB page overwritten: ``POST /sessions`` and ``POST
    /pipeline/run`` answer ``"emit"`` -- a WRITE the log refused, which under "no
    release without a record" refuses the run with it -- while ``GET /audit`` answers
    ``"query"`` and ``GET /audit/verify`` answers ``"length"``, both READS, which cost
    this page its tail and its chain badge and no run at all. The first question a
    reviewer asks is whether the run happened, and one sentence for both leaves it
    unanswered.

    Both must still say what to do, and the "what" cannot come from the body: the
    logger clips ``audit_db`` to the file NAME on purpose, so ``{"audit_db":
    "audit.db"}`` never says where the file is. The sentence supplies the setting an
    operator actually turns.
    """
    seen = _banners(
        tmp_path,
        [
            ["AUDIT_UNAVAILABLE", {"operation": "emit", "audit_db": "audit.db",
                                   "error": "DatabaseError"}],
            ["AUDIT_UNAVAILABLE", {"operation": "query", "audit_db": "audit.db",
                                   "error": "DatabaseError"}],
        ],
    )
    # `_banners` keys by code, so the two rows collapse; drive them one at a time.
    both = {}
    for operation in ("emit", "query", "length"):
        both[operation] = _banners(
            tmp_path,
            [
                [
                    "AUDIT_UNAVAILABLE",
                    {
                        "reason": "audit_log_unreadable",
                        "operation": operation,
                        "audit_db": "audit.db",
                        "error": "DatabaseError",
                        "remedy": "restore it from backup or start a fresh data directory",
                    },
                ]
            ],
        )["AUDIT_UNAVAILABLE"]
    assert seen["AUDIT_UNAVAILABLE"], "the table must answer for this code at all"

    assert "could not be WRITTEN" in both["emit"], both["emit"]
    assert "the run was refused" in both["emit"], both["emit"]
    assert "no release without a record" in both["emit"], both["emit"]

    for read in ("query", "length"):
        assert "could not be READ" in both[read], both[read]
        assert "No run was affected by this." in both[read], both[read]
        assert "refused" not in both[read], both[read]

    # Same remedy on both, naming the file from the body and the setting the body
    # cannot carry -- and no detail blob trailing the sentence.
    for operation, text in both.items():
        assert text.startswith("<b>AUDIT_UNAVAILABLE</b> "), text
        assert "restore audit.db" in text, (operation, text)
        assert "from backup, or point SCP_DATA_DIR at a fresh directory" in text, text
        assert "DatabaseError" in text, text
        assert "{&quot;" not in text, (operation, text)


def test_the_sentence_table_covers_every_error_class_the_package_defines(tmp_path: Path) -> None:
    """The list above must be the API's vocabulary, not the codes I remembered.

    ``_CODE_SENTENCES`` is hand-written, so on its own it proves only that the codes
    somebody thought of are explained. The domain half of the vocabulary is
    discoverable: every ``PipelineError`` subclass carries a ``code``, and the 500 /
    502 / 404 handlers in ``api/errors.py`` answer with that attribute verbatim. This
    walks the package for them -- the same discovery ``test_crypto.py`` uses for the
    detail ceiling -- and requires every code it finds to appear in the list. That is
    half of the guard and the cheap half; the test above is the other, and the two
    compose: a subclass added to a fourth module fails HERE until it is listed, and
    listing it fails THERE until ``app.js`` has a sentence for it.

    The transport-only codes (``NOT_READY``, ``EMPTY_UPLOAD``, ``UPLOAD_TOO_LARGE``,
    ``REQUEST_TOO_LARGE``, ``RATE_LIMITED``, ``UNPROCESSABLE_DOCUMENT``,
    ``AUDIT_SCOPE_REQUIRED``, ``VALIDATION_ERROR``, ``BAD_REQUEST``) have no class to
    walk -- they are string literals at the raise sites -- so they stay in the list
    above and are covered by the test before this one.
    """
    # The walk itself moved to `_pipeline_error_codes` so that the test above can use
    # the same one; nothing it asserts changed.
    codes = _pipeline_error_codes()
    assert len(codes) >= 11, f"subclass discovery found only {sorted(codes)} -- the walk is broken"
    listed = {code for code, _, _ in _CODE_SENTENCES}
    assert codes <= listed, f"no sentence for {sorted(codes - listed)}"


def test_an_unknown_error_code_still_renders_everything_the_body_carried(
    tmp_path: Path,
) -> None:
    """A code the table has never heard of must not be swallowed or generalised.

    The table is a mirror of an API that will grow, and the failure mode of a mirror
    is the code added tomorrow. Two wrong answers were available and both look tidy:
    render nothing, or render "something went wrong". Either makes the NEWEST failure
    the quietest thing on the page -- the one case where the raw map is the best
    information there is. Falling through to the previous rendering keeps it.
    """
    seen = _banners(
        tmp_path,
        [
            ["FUTURE_CODE", {"reason": "not_yet_invented", "count": 7}],
            ["HTTP_418", {}],
        ],
    )
    assert seen["FUTURE_CODE"] == (
        "<b>FUTURE_CODE</b> {&quot;reason&quot;:&quot;not_yet_invented&quot;,&quot;count&quot;:7}"
    )
    # An empty map still renders nothing rather than the literal "{}" -- the half of
    # this path that was already fixed, kept honest by the code that broke it.
    assert seen["HTTP_418"] == "<b>HTTP_418</b> "


def test_the_size_refusals_state_the_ceiling_and_the_size_that_hit_it(tmp_path: Path) -> None:
    """The two 413s carry the only numbers on this page a reviewer can act on.

    ``{"max_bytes":16777216,"bytes":33554432}`` is the ceiling and the overshoot in
    the unit nothing displays files in. Both are folded into the sentence in MB, and
    the two codes must stay distinguishable: ``REQUEST_TOO_LARGE`` is the whole
    multipart body counted by the ASGI middleware and ``UPLOAD_TOO_LARGE`` is the
    file field alone, which is why their ceilings differ by the framing slack.

    Expectations are hand-computed from powers of two, not from the constants: 16 MiB
    is 16 MB in this sentence because the divisor is 1048576, and if that divisor ever
    became 1000000 this test says so.
    """
    seen = _banners(
        tmp_path,
        [
            ["UPLOAD_TOO_LARGE", {"max_bytes": 16 * 1024 * 1024, "bytes": 33 * 1024 * 1024}],
            ["REQUEST_TOO_LARGE", {"max_bytes": 17 * 1024 * 1024, "bytes": 33 * 1024 * 1024}],
        ],
    )
    assert "the ceiling is 16 MB, this one is 33 MB" in seen["UPLOAD_TOO_LARGE"]
    assert "the ceiling is 17 MB, this one is 33 MB" in seen["REQUEST_TOO_LARGE"]
    # A body missing both numbers: the sentence has to survive it without printing
    # "undefined MB", which is the one rendering worse than the blob it replaced.
    bare = _banners(tmp_path, [["UPLOAD_TOO_LARGE", {}]])["UPLOAD_TOO_LARGE"]
    assert "undefined" not in bare and "NaN" not in bare, bare
    assert bare == "<b>UPLOAD_TOO_LARGE</b> That document is larger than this server accepts. " + (
        "Choose a smaller file with the file picker — fixtures/ has documents that fit."
    )


def test_a_pdf_with_no_text_layer_is_reported_with_its_page_count(tmp_path: Path) -> None:
    """``pdf_all_pages_failed`` is the upload failure a scanned PDF produces.

    The page count is the one number that separates "this file was never read" from
    "this file was read and every page of it was blank", and it is the difference
    between re-picking the file and going to find a text-bearing copy.
    """
    seen = _banners(
        tmp_path,
        [["UNPROCESSABLE_DOCUMENT", {"reason": "pdf_all_pages_failed", "pages": 12, "bytes": 900}]],
    )["UNPROCESSABLE_DOCUMENT"]
    assert "all 12 pages came back empty" in seen, seen
    assert "scan with no text layer" in seen


def test_a_validation_error_names_the_field_and_the_limit_that_bounds_it(
    tmp_path: Path,
) -> None:
    """The 422 that says which field failed must also say what the field allows.

    ``_validation_handler`` reduces FastAPI's body to ``{errors, fields}`` on purpose
    -- the default body embeds the caller's own ``input``, which on this API is
    derived from a document -- so the ceiling is not in the response and cannot be.
    The page therefore carries it, and a carried number drifts: these assertions read
    ``MAX_ID_LEN``, ``MAX_PROMPT_CHARS`` and ``MAX_AUDIT_PAGE`` out of the Python that
    enforces them and require each to appear in the banner ``app.js`` produces for
    that field. Nothing is shared between the two sides -- the expectation comes from
    importing ``api/schemas.py``, the actual from node evaluating ``app.js`` -- so
    raising a ceiling in Python turns this red instead of leaving the sentence
    telling a reviewer a limit that stopped being true.
    """
    seen = _banners(tmp_path, [["VALIDATION_ERROR", {"errors": 1, "fields": "body.prompt"}]])
    prompt = seen["VALIDATION_ERROR"]
    assert "The API rejected prompt." in prompt, prompt
    assert f"1 to {MAX_PROMPT_CHARS} characters" in prompt, prompt
    ids = _banners(tmp_path, [["VALIDATION_ERROR", {"errors": 2, "fields": "body.user_id"}]])
    assert f"1 to {MAX_ID_LEN} characters" in ids["VALIDATION_ERROR"], ids
    page = _banners(tmp_path, [["VALIDATION_ERROR", {"errors": 1, "fields": "query.limit"}]])
    assert f"1 to {MAX_AUDIT_PAGE} rows" in page["VALIDATION_ERROR"], page
    # Two fields at once, and a field with no ceiling of its own: the sentence still
    # has to name what was rejected rather than fall back to the map.
    both = _banners(
        tmp_path, [["VALIDATION_ERROR", {"errors": 2, "fields": "body.doc_id,body.strategy"}]]
    )["VALIDATION_ERROR"]
    assert "The API rejected doc_id, strategy." in both, both
    assert "{&quot;" not in both, both


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
fire('file', 'change');
await UI.run();
out.noFile = el('banner').innerHTML;
out.requests = calls.length;
emit(out);
"""
    )
    out = _run(tmp_path, body.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }"))
    assert out["noPrompt"] == "<b>NO_PROMPT</b> Enter a prompt."
    # This expectation was `"...Choose a document first (fixtures/ or any file)."` and it
    # is replaced rather than relaxed. The contract it encoded -- "name the control and
    # say what to do next" -- is unchanged and is asserted below in three further
    # clauses; what changed under it is the page, by decision and not by drift: the
    # dropdown now LOADS the document it names, so a refusal that says "choose a
    # document" without naming the one-click path describes a page that no longer
    # exists. Still an exact equality, and still the same shape of claim.
    assert out["noFile"] == (
        "<b>NO_FILE</b> Nothing is armed. Pick a demo document from the dropdown (one "
        "click -- it loads the document and sets its doc_category), or choose your own "
        "file with the picker beside it."
    )
    assert "demo document" in out["noFile"], "the refusal must name the one-click control"
    assert "picker" in out["noFile"], "and the other control, which is still there"
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
fire('file', 'change');
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


def test_choosing_a_preset_uploads_that_document_in_one_click(tmp_path: Path) -> None:
    """The dropdown LOADS the document it names. One click, then Run.

    This replaces ``test_the_fixture_preset_names_the_path_the_file_picker_still_needs``,
    which pinned the friction rather than the feature: the dropdown named a file and the
    hint told the reviewer to go and find it ("now pick fixtures/medical_note.txt with
    the file button"), because nothing served ``fixtures/`` over HTTP -- measured, ``GET
    /fixtures/medical_note.txt`` was a 404 and is now a 200. That test is deleted rather
    than relaxed, and everything it asserted is asserted here or in the two tests below,
    more strongly: the category still travels with the preset, the idle text still comes
    back on deselect, and the hint is still the single source of truth -- but the run in
    the middle now happens.

    The whole point is the wire, so the wire is what is read: exactly one ``GET
    /fixtures/medical_note.txt``, then a ``POST /documents`` whose multipart body carries
    the fetched bytes under the fixture's own filename and its own category. Nothing here
    reimplements the page; every expected string is hand-written.
    """
    body = (
        RUN_SETUP
        + """
// Start from a clean picker so the only armed thing is the preset, and a blank
// category so the preset is what fills it.
el('file').files = [];
fire('file', 'change');
el('category').value = '';
fire('fixture', 'change', { target: { selectedOptions: [
  { value: 'medical_note.txt', dataset: { cat: 'medical' } }] } });
const armed = { hint: el('fixture-hint').textContent, cat: el('category').value };
await UI.run();
emit({
  armed: armed,
  requests: calls.map((c) => c.method + ' ' + c.path),
  upload: (calls.find((c) => c.path === '/documents') || {}).form,
  banner: el('banner').innerHTML,
});
"""
    )
    out = _run(
        tmp_path,
        body.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }").replace(
            "  return { status: 200, body: {} };",
            "  if (path === '/fixtures/medical_note.txt') return { text: 'Patient: Bob.' };\n"
            "  return { status: 200, body: {} };",
        ),
    )
    # Selecting the preset satisfied the REQUIRED doc_category too -- the reviewer does
    # not set it twice -- and the page says which document is armed.
    assert out["armed"]["cat"] == "medical"
    assert out["armed"]["hint"] == (
        "ARMED: bundled fixtures/medical_note.txt as doc_category=medical. Press Run."
    )
    assert out["banner"].startswith("<b>RUN_OK</b>"), out["banner"]
    # One fetch of the fixture, then the ordinary upload -- not a second ingestion route.
    assert out["requests"][:2] == ["GET /fixtures/medical_note.txt", "POST /documents"], (
        out["requests"]
    )
    assert "POST /pipeline/run" in out["requests"]
    # The multipart body: the bytes the endpoint served, under the fixture's own name,
    # with the fixture's own category. `[key, '[file]', filename, bytes]` is the
    # harness's FormData row for a non-string part.
    assert ["file", "[file]", "medical_note.txt", "Patient: Bob."] in out["upload"], out["upload"]
    assert ["doc_category", "medical"] in out["upload"], out["upload"]
    assert ["user_id", "demo-user"] in out["upload"], out["upload"]


def test_arming_one_document_control_disarms_the_other_in_both_directions(
    tmp_path: Path,
) -> None:
    """Preset then file, and file then preset: exactly one is armed and the page says so.

    Two controls that can each supply the document is an ambiguity the moment the page
    keeps both: a preset armed on top of a leftover file, or a file chosen after a
    preset, each leave the reviewer unable to tell which document Run is about to send.
    ``S.armed`` is the single source of truth and the visible hint is painted from it, so
    every step here reads the two together -- a hint that agreed with nothing would be
    the same defect wearing a green test.
    """
    body = """
const out = { steps: [] };
const step = (label) => out.steps.push([label, UI.S.armed, el('fixture-hint').textContent,
  el('file').value, el('fixture').value]);
// A browser writes BOTH halves of each control's visible state: `files` plus the
// `value` the picker displays (a real one shows the fake `C:\\\\fakepath\\\\` path), and
// the <select>'s own `value`. The harness has to plant both or the assertions that a
// disarmed control stops SHOWING its document are vacuous -- reading '' from a
// property nothing ever set. Deleting `arm`'s two clearing lines was the mutation
// that proved it: this test stayed green until these two assignments existed.
const pickFile = () => {
  el('file').files = [{ name: 'mine.pdf', size: 7, lastModified: 1 }];
  el('file').value = 'C:\\\\fakepath\\\\mine.pdf';
  fire('file', 'change');
};
const pickPreset = (value, cat) => {
  el('fixture').value = value;
  fire('fixture', 'change', {
    target: { selectedOptions: [{ value: value, dataset: cat ? { cat: cat } : {} }] },
  });
};
step('idle');
pickFile();
el('category').value = 'general';
fire('category', 'change');
step('file');
pickPreset('legal_memo.txt', 'legal');
step('preset-over-file');
pickFile();
step('file-over-preset');
pickPreset('', null);
step('deselected');
emit(out);
"""
    out = _run(tmp_path, body)
    steps = {name: rest for name, *rest in out["steps"]}

    idle_armed, idle_hint, _, _ = steps["idle"]
    assert idle_armed is None
    assert idle_hint == (
        "nothing armed yet: choose a demo document (loads it and sets its doc_category), "
        "or pick a file of your own"
    )

    armed, hint, _, fixture_value = steps["file"]
    assert armed == {"kind": "file", "name": "mine.pdf"}
    assert hint == (
        'ARMED: your own file "mine.pdf" as doc_category=general. '
        "The demo-document dropdown is cleared."
    )
    assert fixture_value == "", "the dropdown must not still show a preset"

    armed, hint, file_value, _ = steps["preset-over-file"]
    # ``cat`` is the category the BUNDLED document declares (the <option>'s ``data-cat``),
    # and it rides on the armed state rather than only being written into the field
    # because the field can be changed afterwards and the document's own category cannot.
    # It is the only ground truth this page has about what a document is, and
    # ``renderScope`` is what spends it -- see
    # ``test_the_scope_note_is_a_warning_only_when_a_rule_set_was_really_suppressed``.
    # The equality is still exact and still whole-object.
    assert armed == {"kind": "preset", "name": "legal_memo.txt", "cat": "legal"}
    assert hint == "ARMED: bundled fixtures/legal_memo.txt as doc_category=legal. Press Run."
    assert file_value == "", "the picker must not go on displaying the file it lost"

    armed, hint, _, fixture_value = steps["file-over-preset"]
    assert armed == {"kind": "file", "name": "mine.pdf"}
    assert "mine.pdf" in hint
    assert fixture_value == "", "the preset must lose to a freshly picked file"

    armed, hint, _, _ = steps["deselected"]
    assert armed is None
    assert hint == idle_hint, "deselecting must put the idle text back, not a stale name"


def test_a_preset_and_a_hand_picked_file_of_the_same_name_are_not_one_upload(
    tmp_path: Path,
) -> None:
    """Two independent mechanisms stop one document being served for another, and this
    is the second one's witness.

    ``ensureDoc`` skips the upload when its cache key matches. A preset has no size and
    no mtime, so a key of ``name:category`` alone would match a preset run of
    ``medical_note.txt`` against a file of the reviewer's own that happens to be called
    ``medical_note.txt`` -- and the run would then pipeline the *bundled* document while
    the page displayed the reviewer's file name, the worst version of this ambiguity
    because both panels would look right.

    ``arm()`` also nulls ``S.docId`` on every change of source, which covers the same
    case, and that half is pinned by
    ``test_choosing_a_different_file_invalidates_the_upload_cache``. Measured by
    mutation rather than assumed: deleting either mechanism alone leaves this test
    green, and deleting both turns it red with exactly one upload -- the preset's --
    answering for both runs. So this pins the belt, that one pins the braces, and
    neither test is quietly certifying the other's mechanism.
    """
    body = (
        RUN_SETUP
        + """
el('file').files = [];
fire('file', 'change');
fire('fixture', 'change', { target: { selectedOptions: [
  { value: 'medical_note.txt', dataset: { cat: 'medical' } }] } });
await UI.run();
el('file').files = [{ name: 'medical_note.txt', size: 13, lastModified: 5 }];
fire('file', 'change');
await UI.run();
emit({
  uploads: calls.filter((c) => c.path === '/documents').map((c) => c.form),
  fetches: calls.filter((c) => c.path.indexOf('/fixtures/') === 0).length,
});
"""
    )
    out = _run(
        tmp_path,
        body.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }").replace(
            "  return { status: 200, body: {} };",
            "  if (path === '/fixtures/medical_note.txt') return { text: 'Patient: Bob.' };\n"
            "  return { status: 200, body: {} };",
        ),
    )
    assert len(out["uploads"]) == 2, out["uploads"]
    assert ["file", "[file]", "medical_note.txt", "Patient: Bob."] in out["uploads"][0]
    # The second upload is the reviewer's own file object, not the fetched bytes.
    assert ["file", "[file]", "medical_note.txt", None] in out["uploads"][1], out["uploads"][1]
    assert out["fetches"] == 1, "the second run must not re-fetch the bundled document"


def test_the_armed_line_follows_the_category_it_names(tmp_path: Path) -> None:
    """A category changed after arming must repaint the line that quotes it.

    The armed line is the page's answer to "what is Run about to do", and it names the
    ``doc_category`` because that input decides which ``only_in_doc_categories`` rule
    sets run. Painted once at arming time it would go quietly stale: arm
    ``medical_note.txt`` (medical), switch the category to ``legal``, and the page
    advertises a medical run it is not about to make -- the same
    says-one-thing-does-another the armed state exists to remove.
    """
    body = """
fire('fixture', 'change', { target: { selectedOptions: [
  { value: 'medical_note.txt', dataset: { cat: 'medical' } }] } });
const first = el('fixture-hint').textContent;
el('category').value = 'legal';
fire('category', 'change');
emit({ first: first, second: el('fixture-hint').textContent });
"""
    out = _run(tmp_path, body)
    assert out["first"] == (
        "ARMED: bundled fixtures/medical_note.txt as doc_category=medical. Press Run."
    )
    assert out["second"] == (
        "ARMED: bundled fixtures/medical_note.txt as doc_category=legal. Press Run."
    )


def test_the_preset_dropdown_is_frozen_while_a_run_is_in_flight(tmp_path: Path) -> None:
    """It decides which bytes get uploaded, so it joins the inputs ``setBusy`` locks.

    ``ensureDoc`` reads ``S.armed`` across an await -- the GET that fetches the fixture --
    so a preset changed mid-request would post one document's bytes under the next one's
    name and category. ``#file``, ``#category`` and ``#strategy`` were already frozen for
    exactly this reason; the dropdown was not, because until now it only set a label.

    Read while the request is genuinely in flight -- against ``NEVER``, the fetch that
    does not settle -- and again after the deadline releases it, because "frozen" is only
    worth having if it is also temporary.
    """
    body = (
        """
UI.S.sessionId = 'sess-1';
UI.TIMEOUT.fast = 300;
UI.TIMEOUT.slow = 300;
el('prompt').value = 'Summarise';
el('category').value = 'medical';
fire('fixture', 'change', { target: { selectedOptions: [
  { value: 'medical_note.txt', dataset: { cat: 'medical' } }] } });
respond("""
        + NEVER
        + """);
const held = ['fixture', 'file', 'category', 'strategy', 'btn-run'];
const running = UI.run();
await settle();
const during = held.map((id) => el(id).disabled);
await running;
emit({ during: during, after: held.map((id) => el(id).disabled) });
"""
    )
    out = _run(tmp_path, body)
    assert out["during"] == [True] * 5, "the preset dropdown stayed live during a run"
    assert out["after"] == [False] * 5, "and the deadline must hand every one of them back"


def test_a_preset_that_this_server_does_not_ship_is_its_own_named_failure(
    tmp_path: Path,
) -> None:
    """A 404 from ``/fixtures`` is "this build has no fixtures/", not "not your document".

    ``NOT_FOUND``'s sentence on this page is about *ownership* ("No such document for
    this user"), which is exactly wrong for a deployment that did not copy ``fixtures/``:
    it sends the reviewer looking at ``user_id`` instead of at the picker beside the
    dropdown. The upload must not be attempted either -- there are no bytes to send.
    """
    body = (
        RUN_SETUP
        + """
el('file').files = [];
fire('file', 'change');
fire('fixture', 'change', { target: { selectedOptions: [
  { value: 'medical_note.txt', dataset: { cat: 'medical' } }] } });
await UI.run();
emit({
  banner: el('banner').innerHTML,
  uploads: calls.filter((c) => c.path === '/documents').length,
});
"""
    )
    out = _run(
        tmp_path,
        body.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }").replace(
            "  return { status: 200, body: {} };",
            "  if (path.indexOf('/fixtures/') === 0) {\n"
            "    return { status: 404, body: { code: 'NOT_FOUND',\n"
            "      detail: { reason: 'fixture_not_installed' } } };\n"
            "  }\n"
            "  return { status: 200, body: {} };",
        ),
    )
    assert out["banner"].startswith("<b>PRESET_UNAVAILABLE</b>"), out["banner"]
    assert "medical_note.txt" in out["banner"]
    assert "file picker" in out["banner"]
    assert "No such document for this user" not in out["banner"]
    assert out["uploads"] == 0, "there were no bytes to upload"


def test_the_ui_dropdown_and_the_server_allow_list_are_the_same_four_documents() -> None:
    """The markup's options and the server's allow-list must not drift apart.

    Two independently-written tables describe the same four documents: the ``<option
    value=... data-cat=...>`` list in ``index.html``, which decides what the page arms and
    under which category, and ``DEMO_FIXTURES`` in ``api/routes/documents.py``, which
    decides what the server will serve. Drift has two shapes and both are silent -- an
    option the server refuses is a dead control that 404s on the first click, and an
    option whose ``data-cat`` disagrees with the server's is a document scanned under a
    category nobody chose for it, which is the ``wrong category`` failure the scope note
    exists to expose arriving from the page's own markup.

    Read out of the shipped HTML and compared against the imported table. There is no
    fetch at page load on purpose -- the options are static -- so this is the join that
    binds them.
    """
    elements, _ = _page()
    options = [n for n in elements if n["tag"] == "option" and n["parent_id"] == "fixture"]
    assert len(options) == len(DEMO_FIXTURES) + 1, options
    named = [n for n in options if n["attrs"].get("data-cat") is not None]
    from_markup = {n["attrs"]["value"]: n["attrs"]["data-cat"] for n in named}
    assert len(from_markup) == len(named), "a duplicated option value"
    assert from_markup == dict(DEMO_FIXTURES), (from_markup, dict(DEMO_FIXTURES))
    # And the placeholder stays value-less, or a <select> with no empty option would arm
    # the first document for anyone who never touched the control.
    placeholders = [n for n in options if n["attrs"].get("data-cat") is None]
    assert [n["attrs"].get("value") for n in placeholders] == [""], placeholders


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
fire('file', 'change');
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
            # The id of the nearest ancestor that has one. `ancestors` is tag names
            # only, which cannot tell the demo-document <select>'s <option>s from the
            # doc_category <select>'s -- and the test that binds the dropdown to the
            # server's allow-list has to read exactly one of those two lists.
            "parent_id": next(
                (n["attrs"]["id"] for n in reversed(self._open) if n["attrs"].get("id")),
                None,
            ),
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
    # TEST WRONG, and specifically the SCOPE of the ban -- the rule behind it is kept
    # and tightened. These two lines banned the substrings "vault-miss" and "VAULT_MISS"
    # from the WHOLE PAGE, which was a sound proxy for the real rule ("this callout must
    # not sell its sequence as a vault-miss demo") only for as long as the page had no
    # flow that could produce one. It now has one: the run bar carries "Restore again
    # with an unissued token", which re-sends the same document and the same LIVE
    # session through the same POST /pipeline/run with a correctly-shaped token id this
    # session never minted. Driven in Chrome, that press measured `vault_misses 1`,
    # `unresolved_fabricated 1`, `[UNRESOLVED_ENTITY]` in panel 4 and a real hash-chained
    # row `VAULT_MISS {"category":"PII","classification":"fabricated","reason":
    # "token_not_in_vault","stage":"deobfuscate"}` at seq 107. A page-wide ban on the
    # word therefore forbids the page from naming, truthfully, the one thing build doc
    # section 9.10 asks it to demonstrate -- it had become a rule against honesty.
    #
    # The regression it was written for is unchanged and is now asserted DIRECTLY on the
    # callout rather than through a page-wide proxy, which is strictly more precise: the
    # old form would have passed a callout re-labelled "vault-miss demonstration" as
    # long as somebody also deleted the words elsewhere, and would have failed a page
    # that told the truth. Re-measured on the same run: the destroy sequence itself
    # still writes ZERO VAULT_MISS rows (600 session-scoped rows, none of them one), so
    # the claim being forbidden is still false and the ban still bites.
    # So the rule is asserted as a rule. A vault miss may be mentioned here in exactly
    # two ways, and if it is mentioned at all BOTH have to be present: the callout must
    # say that its own three steps produce none, and it must name the control that does,
    # so no reader can be left attributing the miss to this sequence. A regression that
    # re-labels these steps "the vault-miss demo" cannot satisfy either clause without
    # ceasing to make the false claim, which is what the old page-wide ban was reaching
    # for -- and unlike that ban, this cannot be satisfied by deleting the word from
    # somewhere else on the page, and does not fire on a page that is telling the truth.
    if "vault-miss" in callout.lower() or "VAULT_MISS" in callout:
        assert "writes none" in callout.lower(), (
            "the callout mentions a vault miss without saying that THIS sequence "
            f"produces none: {callout}"
        )
        assert "restore again with an unissued token" in callout.lower(), (
            "the callout mentions a vault miss without naming the control that "
            f"actually produces one, so the claim reads as being about these steps: {callout}"
        )
    assert "SESSION_EXPIRED" in callout, callout
    assert "VAULT_DESTROY" in callout, callout
    # The markup and the banner app.js raises at step 2 have to tell one story.
    assert "SESSION_EXPIRED before the vault is even" in APP_JS.read_text(encoding="utf-8")


def test_every_interactive_control_on_the_page_has_an_accessible_name() -> None:
    """A control with no name announces as its widget type, which is not a name.

    The file picker was the one control of the ten with none: a screen reader read it as
    "Choose File, button", and it is the mandatory step -- without a document every Run
    answers ``NO_FILE``, so an unnamed picker is the demo unable to start. WCAG 2.1
    4.1.2. The <label> in the same group points at the <select>, so it neither named the
    picker nor could be repurposed to.
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
    # This asserted ``== "document"``, against a page where the <select> beside it was
    # labelled ``fixture preset`` and only set a category. Both controls now load a
    # document, so "document" stopped distinguishing them -- two controls whose names do
    # not say which is which is the same 4.1.2 failure one step along. The equality is
    # still exact, and the pair is now asserted together rather than one of them alone.
    assert _accessible_name(by_id["file"], elements, by_id) == "your own file"
    assert _accessible_name(by_id["fixture"], elements, by_id) == "demo document"
    # The hint is the ARMED state -- which of the two Run will upload -- so it describes
    # both controls rather than sitting as loose text beside them.
    assert by_id["file"]["attrs"].get("aria-describedby") == "fixture-hint"
    assert by_id["fixture"]["attrs"].get("aria-describedby") == "fixture-hint"
    assert "fixture-hint" in by_id, "the description points at nothing"
    # Arming happens by mutating this one span while focus is elsewhere, so it has to
    # announce. WCAG 2.1 4.1.3, the same argument #banner carries.
    assert by_id["fixture-hint"]["attrs"].get("role") == "status"
    assert by_id["fixture-hint"]["attrs"].get("aria-live") == "polite"


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
fire('file', 'change');
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
    # The mark grew the hover text that says, in words, the thing this docstring says
    # the colour alone could not: "Jamie Cain" is a fake. Same class, same span.
    assert out["p3"] == (
        f'<mark class="tok c-PII" title="{_ps_tip("PERSON")}">Jamie Cain</mark>'
        ", MD reviewed the chart."
    )
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
    # Plus the hover text; the one mark and its class are what this test is about.
    assert f'<mark class="tok c-PHI" title="{TOK_TIP}">[PHI_NAME_11112222]</mark>' in out
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
    # placeholder is "Create a session, choose a demo document or your own file, press
    # Run", and the click that completes its first clause must not blank the other two.
    #
    # This asserted "Session created. Choose a file and press Run." The sentence is
    # replaced, not relaxed: the page now has two ways to choose a document and one of
    # them is not a file the reviewer has to find, so an instruction naming only the
    # picker sends them to the harder path. Exact equality either way.
    assert "David Ochoa" not in out["p1"]
    assert out["p1"] == (
        "Session created. Choose a demo document or your own file, then press Run."
    )
    assert out["stats"] == "" and out["auditRun"] == ""
    assert "RESTORE_OK" not in out["audit"], "the dead session's rows are not this session's"
    assert out["last"] is None
    assert out["audits"] and all("session_id=sess-NEW-000000" in a for a in out["audits"])


#: ``RUN_SETUP``'s bodies plus the one route it never needed -- ``POST /sessions`` --
#: and no session in ``S``. Appended *after* ``RUN_SETUP`` so the later ``respond``
#: and the later assignment win. The minted id is 32 hex characters because that is
#: what the live API returns (measured: ``a8994568680548cf9e869c9f39b8864b``), and the
#: badge and banner print ``slice(0, 12)`` of it, so a short stub id would let a test
#: pass against a page that truncates wrongly. Hand-written, like every other body in
#: this module.
MINTED_ID = "a8994568680548cf9e869c9f39b8864b"
MINT_SETUP = (
    """
respond((path, init) => {
  const m = (init && init.method) || 'GET';
  if (m === 'POST' && path === '/sessions') {
    return { status: 200, body: { session_id: '"""
    + MINTED_ID
    + """', expires_at: 1700000000 } };
  }
  if (m === 'DELETE' && path.indexOf('/sessions/') === 0) return { status: 204 };
  if (m === 'POST' && path === '/documents') return { status: 200, body: { doc_id: 'doc-1' } };
  if (path.indexOf('/documents/doc-1/text') === 0) {
    return { status: 200, body: { text: 'Bob met Carl.', chars: 13 } };
  }
  if (path === '/pipeline/run') return { status: 200, body: RESULT };
  if (path.indexOf('/audit') === 0) return { status: 200, body: { events: [] } };
  return { status: 200, body: {} };
});
UI.S.sessionId = null;
UI.S.lastSessionId = null;
calls.length = 0;
"""
)


def test_a_run_with_no_session_mints_one_through_the_button_s_own_path(
    tmp_path: Path,
) -> None:
    """Choose a document, press Run. One control, one click, and the run is scoped.

    This REPLACES ``test_a_run_before_a_session_exists_is_refused_without_uploading_
    anything``, and the replacement is a change of product decision, not a relaxation.
    That test pinned the fix made in ``b82964a``: with no preflight at all the first
    click uploaded the document, painted panel 1, posted ``session_id: null`` and let
    the API's 401 become the banner "Session key is gone" -- about a key that was never
    minted. Two requirements were folded into one implementation there, and only one of
    them was the requirement. **Never post a null session, and never report a destroyed
    key that never existed** is the requirement, and it is asserted below more directly
    than it could be before: the old test proved the null post impossible by stopping
    the run at the door, so it never saw a wire; this one lets the run happen and reads
    the ``session_id`` off ``POST /pipeline/run``. **"Press Create session first"** was
    the implementation, and it is the friction the user objected to -- Run is the
    biggest button on the page, inside the red LIVE REVIEW strip, and it answered the
    first thing a reviewer does by sending them to a small button ten controls above.

    Three further properties, each of which a lazier auto-mint would break:

    * ONE ``POST /sessions``, carrying the owner from the field -- the mint goes
      through ``createSession``, so it is the button's path and not a second one.
      A forked minting path is a second set of audit events to keep in step.
    * The audit read ``createSession`` makes is still made, so the ``SESSION_CREATE``
      row is on screen: that row is the audit story's answer to "where did this
      session come from".
    * The badge and the RUN_OK banner both say the session was created by Run. The
      badge is the durable half -- ``createSession``'s own banner is overwritten by
      ``RUN_OK`` within the same click.
    """
    body = (
        RUN_SETUP.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }")
        + MINT_SETUP
        + """
await UI.run();
emit({
  requests: calls.map((c) => c.method + ' ' + c.path.split('?')[0]),
  sessions: calls.filter((c) => c.path === '/sessions').map((c) => c.body),
  pipeline: calls.filter((c) => c.path === '/pipeline/run').map((c) => c.body),
  badge: el('session-badge').textContent,
  badgeClass: el('session-badge').className,
  banner: el('banner').innerHTML,
  live: UI.S.sessionId,
});
"""
    )
    out = _run(tmp_path, body)
    # The mint, then the run, in that order and with nothing minted twice.
    assert out["requests"] == [
        "POST /sessions",
        "GET /audit",
        "POST /documents",
        "GET /documents/doc-1/text",
        "POST /pipeline/run",
        "GET /audit",
    ], out["requests"]
    assert out["sessions"] == ['{"user_id":"demo-user"}'], "one mint, owner from the field"
    # The requirement the replaced test existed for, now read off the wire instead of
    # inferred from the absence of one.
    assert json.loads(out["pipeline"][0])["session_id"] == MINTED_ID
    assert out["live"] == MINTED_ID
    # Visible, not silent. The badge is the standing answer and outlives the banner.
    assert "auto-created by Run" in out["badge"], out["badge"]
    assert MINTED_ID[:12] in out["badge"], out["badge"]
    assert out["badgeClass"] == "badge ok"
    assert out["banner"].startswith("<b>RUN_OK</b>"), out["banner"]
    assert "was auto-created by this Run" in out["banner"], out["banner"]
    assert "every step above is scoped by it" in out["banner"], out["banner"]
    # Carried over verbatim from the replaced test: nothing was destroyed here, and a
    # page that says so about a session it just created is the original defect again.
    assert "gone" not in out["banner"], "nothing was destroyed; nothing was ever created"


def test_the_create_session_button_is_never_labelled_as_the_automatic_mint(
    tmp_path: Path,
) -> None:
    """An explicit press must still read as one, and the trap here is a truthy argument.

    ``btn-session``'s listener *is* ``createSession``, so an explicit press calls it
    with a click ``Event`` as its first argument -- and the harness fires with ``{}``.
    Had the automatic mint been signalled with a boolean, ``auto = !!arg`` would have
    labelled every deliberate press "auto-created by Run", which is a page lying about
    provenance in the one place a reviewer looks to establish it. Fired through the
    real listener rather than by calling the function, because the listener is the
    thing that supplies the argument.

    The other half is that the button still works at all: ``Destroy session`` needs
    something to destroy, and a reviewer demonstrating the lifecycle needs to mint on
    purpose. So the request is asserted too, not just the wording.
    """
    body = (
        RUN_SETUP.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }")
        + MINT_SETUP
        + """
fire('btn-session', 'click', {});
await settle();
emit({
  requests: calls.map((c) => c.method + ' ' + c.path.split('?')[0]),
  badge: el('session-badge').textContent,
  banner: el('banner').innerHTML,
  live: UI.S.sessionId,
});
"""
    )
    out = _run(tmp_path, body)
    assert out["requests"] == ["POST /sessions", "GET /audit"], out["requests"]
    assert out["live"] == MINTED_ID
    assert "auto" not in out["badge"], out["badge"]
    assert "created" in out["badge"], out["badge"]
    assert out["banner"].startswith("<b>SESSION_CREATED</b>"), out["banner"]
    assert "Run created one" not in out["banner"], out["banner"]


def test_the_live_review_sequence_still_gets_its_refusal_from_the_server(
    tmp_path: Path,
) -> None:
    """Run, Destroy session, Run -- and the third step must NOT quietly mint a session.

    This is the sequence printed in the red strip above the buttons, and both that
    strip and ``destroySession``'s own banner promise the same outcome: "the second run
    is refused with SESSION_EXPIRED before the vault is consulted, and the audit tail
    shows VAULT_DESTROY". Auto-minting here would delete the demonstration outright, so
    the page keeps the destroyed id (``S.lastSessionId``, set only on the branch where
    the audit log proved the erasure) and runs against it.

    It is refused BY THE API, which is the part worth pinning. The behaviour this
    replaces was a local ``NO_SESSION`` banner and zero requests -- so the two notices
    promising a 401 were describing something the page answered itself, in a different
    code, without asking anyone. Verified against the live API on this build: ``POST
    /pipeline/run`` with a destroyed ``session_id`` answers ``401 {"code":
    "SESSION_EXPIRED"}``, and ``GET /documents/{id}/text`` still answers 200 because
    the document store is not the vault.

    Sticky by design: the refusal repeats until the reviewer presses "Create session",
    which is exactly what the ``SESSION_EXPIRED`` sentence tells them to do. A button
    that demonstrates a refusal once and then silently does something else on the next
    press would be worse than the friction it removed.
    """
    body = (
        RUN_SETUP.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }")
        + MINT_SETUP
        + """
// Step 1: a run with no session mints one and succeeds.
await UI.run();
const firstRun = calls.filter((c) => c.path === '/pipeline/run').length;
// Step 2: Destroy, confirmed the way the live API confirms it -- the probe row with
// existed=1, which is the only thing `destroySession` accepts as proof.
respond((path, init) => {
  const m = (init && init.method) || 'GET';
  if (m === 'DELETE') return { status: 204 };
  if (path.indexOf('""" + PROBE_MARK + """') >= 0) {
    return { status: 200, body: { events: [""" + DESTROYED_ROW + """] } };
  }
  if (path.indexOf('/audit') === 0) return { status: 200, body: { events: [""" + DESTROYED_ROW +
        """] } };
  return { status: 200, body: {} };
});
await UI.destroySession();
const destroyedBadge = el('session-badge').textContent;
// Step 3: press Run again. The API answers the way the live one does.
respond((path, init) => {
  const m = (init && init.method) || 'GET';
  if (m === 'POST' && path === '/sessions') {
    return { status: 200, body: { session_id: 'MUST-NOT-BE-MINTED', expires_at: 1700000000 } };
  }
  if (m === 'POST' && path === '/documents') return { status: 200, body: { doc_id: 'doc-1' } };
  if (path.indexOf('/documents/doc-1/text') === 0) {
    return { status: 200, body: { text: 'Bob met Carl.', chars: 13 } };
  }
  if (path === '/pipeline/run') {
    return { status: 401, body: { code: 'SESSION_EXPIRED', detail: { session_id: '"""
        + MINTED_ID
        + """' } } };
  }
  if (path.indexOf('/audit') === 0) {
    return { status: 200, body: { events: [""" + DESTROYED_ROW + """] } };
  }
  return { status: 200, body: {} };
});
calls.length = 0;
await UI.run();
emit({
  firstRun: firstRun,
  destroyedBadge: destroyedBadge,
  requests: calls.map((c) => c.method + ' ' + c.path.split('?')[0]),
  pipeline: calls.filter((c) => c.path === '/pipeline/run').map((c) => c.body),
  banner: el('banner').innerHTML,
  live: UI.S.sessionId,
  audit: el('audit-body').innerHTML,
  p1: el('p1').innerHTML,
  p2: el('p2').innerHTML, p3: el('p3').innerHTML, p4: el('p4').innerHTML,
});
"""
    )
    out = _run(tmp_path, body)
    assert out["firstRun"] == 1, "step 1 must actually have run"
    assert out["destroyedBadge"] == "session destroyed"
    # The whole point: no mint on the third step.
    assert "POST /sessions" not in out["requests"], out["requests"]
    assert out["live"] is None
    # And the run was made against the DESTROYED id, so the refusal is the API's.
    assert json.loads(out["pipeline"][0])["session_id"] == MINTED_ID
    assert out["banner"].startswith("<b>SESSION_EXPIRED</b>"), out["banner"]
    assert "the vault cannot be read" in out["banner"], out["banner"]
    assert 'Press &quot;Create session&quot; for a new one' in out["banner"], out["banner"]
    # The strip promises the audit tail shows VAULT_DESTROY, and the refusal path
    # reloads it. Panels 2-4 stay empty: the erasure, shown rather than asserted.
    assert "VAULT_DESTROY" in out["audit"], out["audit"]
    assert out["p2"] == IDLE and out["p3"] == IDLE and out["p4"] == IDLE
    # ...and so does panel 1, which is the half this sequence used to contradict. Step 3
    # re-fetched the document text -- ``GET /documents/{id}/text`` still answers 200,
    # because the document store is not the vault -- and painted the whole original back
    # under a banner reading "Session key and vault rows are gone". Measured against the
    # live API on ``fixtures/medical_note.txt``: 2,826 characters of cleartext PHI,
    # "Patient name: David Ochoa" among them, under a red SESSION_EXPIRED. The request is
    # not made at all now rather than the panel being blanked afterwards: a blanked panel
    # leaves the same plaintext one devtools pane away, on a page a reviewer of a security
    # demo has devtools open on.
    assert "GET /documents/doc-1/text" not in out["requests"], out["requests"]
    assert "Bob met Carl." not in out["p1"], out["p1"]
    assert "not fetched" in out["p1"], out["p1"]
    # And it says precisely what was erased, so a reviewer who then presses "Create
    # session" and sees the document come back reads the design rather than a retraction.
    assert "session key and the vault rows" in out["p1"], out["p1"]


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
    # "spans masked", not "spans": the counter now says which of the page's two span
    # numbers it is. The property this line pins -- that an empty extraction is
    # reported as zero of everything rather than left blank -- is unchanged.
    assert out["c1"] == "0 chars " + MID + " 0 spans masked"
    assert out["banner"].startswith("<b>RUN_OK</b>"), "the run did succeed; the document is empty"


# ---------------------------------------------------------------------------
# UI audit loop 6 -- the page's own failure modes: a request that never answers,
# a session abandoned rather than destroyed, a mark that says nothing, a header
# badge frozen at load time, and a chain walk that can be started twice.
# ---------------------------------------------------------------------------
#: A responder that never settles. A real ``fetch`` is only *rejected* by its abort
#: signal, and the harness honours that, so this is the whole of "the API stopped
#: answering": no reply, no error, no close.
NEVER = "function () { return new Promise(function () {}); }"


def test_a_request_that_never_answers_gives_the_controls_back(tmp_path: Path) -> None:
    """A stalled reply used to lock every control on the page until a reload.

    ``setBusy(true)`` disables Run, Destroy, Create session, the file picker and both
    ``<select>``s for the whole of a request, and ``api`` had no deadline: a server
    killed mid-run, a proxy holding the socket open, a laptop suspended between the
    send and the answer, all left the page dead with the spinner turning and ``#banner``
    empty. Measured in this harness against a fetch that never settles, before the fix:
    ``btn-run``, ``btn-destroy``, ``btn-session``, ``#file``, ``#category`` and
    ``#strategy`` all read ``disabled: true`` and stayed that way.

    The budgets are shortened to milliseconds here for the obvious reason. What is
    being exercised is the deadline, the abort and the release, not their length.
    """
    body = (
        RUN_SETUP.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }")
        + """
UI.TIMEOUT.fast = 10;
UI.TIMEOUT.slow = 10;
respond("""
        + NEVER
        + """);
await UI.run();
emit({
  banner: el('banner').innerHTML,
  disabled: ['btn-run', 'btn-destroy', 'btn-session', 'file', 'category', 'strategy']
    .map((id) => el(id).disabled),
  spinHidden: el('spin').hidden,
  busy: UI.S.busy,
});
"""
    )
    out = _run(tmp_path, body)
    assert out["banner"].startswith("<b>REQUEST_TIMEOUT</b>"), out["banner"]
    assert "stopped waiting and gave the controls back" in out["banner"]
    assert "may still be running on the server" in out["banner"], (
        "an aborted request is not a request that did not happen; the banner must say so"
    )
    assert out["disabled"] == [False] * 6, "every control the run held must be released"
    assert out["spinHidden"] is True
    assert out["busy"] is False


def test_the_two_posts_that_do_server_side_work_get_the_longer_budget(
    tmp_path: Path,
) -> None:
    """One deadline for every call would have to abort runs the server was answering.

    ``/pipeline/run`` may legitimately spend ``llm_timeout_s`` (60 s) on each of
    ``MAX_ATTEMPTS`` (3) provider attempts plus two backoff sleeps capped at
    ``MAX_BACKOFF_S`` (10 s) -- 200 s of ceiling before detection, obfuscation and the
    gate's three passes are counted -- so it is held to ``TIMEOUT.slow``. A document
    text read is a database fetch and a decrypt, and is held to ``TIMEOUT.fast``.

    Both halves are asserted from one scenario, because "the slow one is slower" is
    only worth anything alongside "the fast one is fast": the text read is hung with
    ``fast`` at 10 ms and must give up, and the pipeline call is hung with ``slow``
    far out of reach and must still be waiting when the test looks.
    """
    hung_text = RUN_SETUP.replace(
        "return { status: 200, body: { text: 'Bob met Carl.', chars: 13 } };",
        "return new Promise(function () {});",
    ).replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }")
    out = _run(
        tmp_path,
        hung_text
        + """
UI.TIMEOUT.fast = 10;
UI.TIMEOUT.slow = 60000;
await UI.run();
emit({ banner: el('banner').innerHTML, busy: UI.S.busy });
""",
    )
    assert out["banner"].startswith("<b>REQUEST_TIMEOUT</b>"), (
        "a hung /documents/{id}/text is held to the fast budget"
    )
    assert out["busy"] is False

    hung_run = RUN_SETUP.replace(
        "if (path === '/pipeline/run') return PIPELINE_REPLY(RESULT);",
        "if (path === '/pipeline/run') return new Promise(function () {});",
    )
    still = _run(
        tmp_path,
        hung_run
        + """
UI.TIMEOUT.fast = 10;
// Not 240000: the pending deadline keeps node's event loop alive until it fires,
// and 1 s is already a hundred times the fast budget being ruled out.
UI.TIMEOUT.slow = 1000;
UI.run();
await settle();
await settle();
emit({ banner: el('banner').innerHTML, busy: UI.S.busy });
""",
    )
    assert still["banner"] == "", (
        "the pipeline call must not be abandoned at the fast budget -- the server is "
        "allowed 200 s for the provider alone"
    )
    assert still["busy"] is True, "and the page is still, correctly, waiting"


#: A second ``POST /sessions`` answers with this; the first answers ``sess-old``.
REPLACEMENT_SETUP = """
respond((path, init) => {
  const m = (init && init.method) || 'GET';
  if (path === '/sessions' && m === 'POST') {
    return { status: 200, body: { session_id: MINTED.shift(), expires_at: 1700000000 } };
  }
  if (m === 'DELETE') return DELETE_REPLY;
  if (path.indexOf('/audit') === 0) {
    if (path.indexOf('""" + PROBE_MARK + """') >= 0) {
      return { status: 200, body: { events: [PROBE_ROW] } };
    }
    return { status: 200, body: { events: [] } };
  }
  return { status: 200, body: {} };
});
const MINTED = ['sess-old-000000', 'sess-new-000000'];
el('user').value = 'alice';
await UI.createSession();
calls.length = 0;
await UI.createSession();
emit({
  live: UI.S.sessionId,
  last: UI.S.lastSessionId,
  banner: el('banner').innerHTML,
  kind: el('banner').className,
  sent: calls.map((c) => c.method + ' ' + c.path),
});
"""


def test_creating_a_second_session_destroys_the_one_it_replaces(tmp_path: Path) -> None:
    """"Create session" over a live session used to abandon it, not replace it.

    No ``DELETE`` was issued, so the previous session key and its vault rows -- the
    rows that map a token back to an original value -- stayed in the server's process
    memory until the TTL reaped them, and the page had just nulled ``lastSessionId``,
    so no control on it could ever erase them. Measured in this harness before the fix:
    the second click issued ``POST /sessions`` and one audit ``GET``, and nothing else.
    On a page whose largest button demonstrates irreversible erasure, the small one
    above it quietly created the opposite.

    The erasure is *proved*, not assumed, for the reason ``destroyConfirmed`` exists:
    ``DELETE /sessions`` answers 204 for a session it did not touch, so the claim in
    the banner is made only when ``VAULT_DESTROY`` carries ``existed=1``.
    """
    out = _run(
        tmp_path,
        "const DELETE_REPLY = { status: 204 };\nconst PROBE_ROW = "
        + DESTROYED_ROW
        + ";\n"
        + REPLACEMENT_SETUP,
    )
    assert out["live"] == "sess-new-000000"
    deletes = [c for c in out["sent"] if c.startswith("DELETE ")]
    # The OLD id, and the owner the OLD session was created for -- same rule as
    # ``destroySession``: the field can drift, and a non-owner delete erases nothing.
    assert deletes == ["DELETE /sessions/sess-old-000000?user_id=alice"], out["sent"]
    assert any(PROBE_MARK in c for c in out["sent"]), (
        "the erasure has to be read back out of the log, not inferred from the 204"
    )
    assert out["kind"] == "banner ok"
    assert "was destroyed first" in out["banner"]
    assert "existed=1" in out["banner"]
    assert "sess-old-000…" in out["banner"], "name the session that was erased"


def test_a_replacement_the_log_does_not_confirm_is_not_called_an_erasure(
    tmp_path: Path,
) -> None:
    """``existed=0`` means the delete touched nothing, and the banner must say so.

    Same trap as the Destroy button's: the 204 is deliberately not an ownership
    oracle, so a replacement whose ``VAULT_DESTROY`` row reads ``existed=0`` left a
    live session behind. Claiming the erasure there would be the exact false claim
    ``destroyConfirmed`` was written to stop, moved to a different button.
    """
    out = _run(
        tmp_path,
        "const DELETE_REPLY = { status: 204 };\nconst PROBE_ROW = "
        + UNTOUCHED_ROW
        + ";\n"
        + REPLACEMENT_SETUP,
    )
    assert out["live"] == "sess-new-000000", "the new session is live either way"
    assert out["kind"] == "banner warn", "an unproved erasure is not a green outcome"
    assert "existed=0" in out["banner"]
    assert "STILL LIVE" in out["banner"]
    assert "was destroyed first" not in out["banner"]


def test_a_replacement_whose_delete_failed_says_the_old_vault_is_still_there(
    tmp_path: Path,
) -> None:
    """A refused DELETE must not be swallowed by the click that succeeded.

    The new session exists by the time the delete runs, so the failure cannot throw
    the click away -- it has to be reported instead. The failing code is named because
    it is the difference between "expired already" and "the server refused you".
    """
    out = _run(
        tmp_path,
        "const DELETE_REPLY = { status: 429, body: { code: 'RATE_LIMITED' } };\n"
        "const PROBE_ROW = " + DESTROYED_ROW + ";\n" + REPLACEMENT_SETUP,
    )
    assert out["live"] == "sess-new-000000"
    assert out["kind"] == "banner warn"
    assert "could not be deleted (RATE_LIMITED)" in out["banner"]
    assert "STILL LIVE" in out["banner"]
    assert not any(PROBE_MARK in c for c in out["sent"]), (
        "there is nothing to confirm when the delete itself was refused"
    )


def test_a_mark_in_panel_two_or_three_says_which_of_the_three_kinds_it_is(
    tmp_path: Path,
) -> None:
    """Panels 2 and 3 highlighted three different things and explained none of them.

    Panel 1's marks have carried entity type, action, score and surrogate since the
    first build. The two panels that show the SUBSTITUTE carried no ``title`` at all,
    so the only thing separating a vault-backed token, an irreversible redaction
    marker and a realistic fake was a colour -- and the legend beside it names a
    CATEGORY, not a kind. Panel 3 is where that bites: "Jamie Cain, MD" in PHI green,
    in the provider's-eye view, with nothing on the page saying it is a fake this run
    minted rather than a clinician out of the document.

    The tooltips name no original value, which is the point: panels 2 and 3 do not
    hold one. The pseudonym tip names the entity TYPE, which the payload's own
    bracketed tokens print in clear anyway.
    """
    text = "[FIN_ACCOUNT_NUMBER_1a2b3c4d] and [REDACTED_SSN] for Christina Palmer"
    dets = ", ".join(
        [
            _det(surrogate="Christina Palmer", category="PHI", entity_type="PERSON"),
            _det(surrogate="[FIN_ACCOUNT_NUMBER_1a2b3c4d]", category="FIN"),
        ]
    )
    out = _run(
        tmp_path, f"emit({{ html: UI.renderMarks({json.dumps(text)}, [{dets}]) }});"
    )["html"]
    assert out == (
        f'<mark class="tok c-FIN" title="{TOK_TIP}">[FIN_ACCOUNT_NUMBER_1a2b3c4d]</mark>'
        " and "
        f'<mark class="tok c-RED" title="{RED_TIP}">[REDACTED_SSN]</mark>'
        " for "
        f'<mark class="tok c-PHI" title="{_ps_tip("PERSON")}">Christina Palmer</mark>'
    )
    # The three sentences have to differ, or the tooltip is decoration: the whole
    # point is that a reviewer can tell a restorable token from an irreversible
    # redaction from a fake.
    assert len({TOK_TIP, RED_TIP, _ps_tip("PERSON")}) == 3
    # And none of them may carry a value. "Bob" is the original behind the pseudonym
    # in every other scenario in this file; it must not appear here.
    assert "Bob" not in out


def test_a_pseudonym_with_no_detection_behind_it_still_gets_an_honest_tooltip(
    tmp_path: Path,
) -> None:
    """The category fallback is ``PII``; the tooltip must not invent an entity type.

    ``renderMarks`` colours an unclassifiable pseudonym ``PII`` rather than dropping
    the highlight. The tooltip follows the same rule -- it says a pseudonym was minted
    and declines to name a type it does not have, because a wrong type in a tooltip is
    worse than no type.
    """
    out = _run(
        tmp_path,
        'emit({ html: UI.renderMarks("Ann", [{ surrogate: "Ann" }]) });',
    )["html"]
    assert out == f'<mark class="tok c-PII" title="{_ps_tip("detected value")}">Ann</mark>'


def test_a_dead_api_moves_the_header_badge_it_used_to_leave_reading_ok(
    tmp_path: Path,
) -> None:
    """The health badge was written once, at load, and then never moved again.

    Kill the server mid-demo and every action banners ``NETWORK_UNREACHABLE`` while the
    header still reads a green "ok · mock/... · en_core_web_lg", describing a process
    that is gone -- the two halves of the UI reporting one fact differently, which is
    the complaint ``api``'s network branch was written to fix in the first place. The
    class matters as much as the text: ``health()``'s own catch set the words and left
    ``class="badge muted"``, so the one badge that says the API is down was dim grey,
    indistinguishable from the "health: …" it starts as.
    """
    out = _run(
        tmp_path,
        """
respond(() => ({ status: 200, body: { status: 'ok', llm_provider: 'mock',
  llm_model: 'm', spacy_model: 'en_core_web_lg' } }));
await UI.health();
const before = el('health').className + ' | ' + el('health').textContent;
// The server dies. `fetch` REJECTS -- it does not answer -- which is the shape
// `api` turns into NETWORK_UNREACHABLE.
respond(() => { throw new TypeError('Failed to fetch'); });
UI.S.sessionId = 'sess-1';
await UI.verifyChain();
emit({ before: before, cls: el('health').className,
       text: el('health').textContent, banner: el('banner').innerHTML });
""",
    )
    assert out["before"] == "badge ok | ok · mock/m · en_core_web_lg"
    assert out["banner"].startswith("<b>NETWORK_UNREACHABLE</b>")
    assert out["text"] == "health: unreachable"
    assert out["cls"] == "badge err", "the page's colour for a failed outcome, not dim grey"


def test_the_chain_walk_cannot_be_started_twice(tmp_path: Path) -> None:
    """Verify chain is the one button ``setBusy`` leaves alive, and it had no guard.

    The walk is priced in ROWS (``audit.py``: 5,000 per token, burst 24) and charged on
    success, so on a log of any size an impatient double-click spends the bucket and
    the second answer is the 429 the ``RATE_LIMITED`` sentence describes -- a throttle
    the page inflicted on itself and then reported as though the server had. One
    in-flight walk, one request.
    """
    out = _run(
        tmp_path,
        """
let release;
respond(() => new Promise((r) => { release = () => r({ status: 200,
  body: { valid: true, length: 41 } }); }));
const first = UI.verifyChain();
await settle();
const during = el('btn-verify').disabled;
fire('btn-verify', 'click');
fire('btn-verify', 'click');
await settle();
const mid = calls.length;
release();
await first;
await settle();
emit({ during: during, mid: mid, after: el('btn-verify').disabled,
       calls: calls.length, badge: el('verify-badge').textContent });
""",
    )
    assert out["during"] is True, "the button is held while its own request is in flight"
    assert out["mid"] == 1, "two more clicks during the walk must issue no more requests"
    assert out["calls"] == 1
    assert out["after"] is False, "and released when it finishes"
    assert out["badge"] == "chain: VALID · 41 events (whole log)"


def test_a_refused_run_reloads_the_audit_tail_whatever_refused_it(tmp_path: Path) -> None:
    """Only two error codes used to refresh the tail; every other one left it stale.

    ``resetRun`` blanks the four panels, the stats row and the ``#audit-run`` LABEL and
    deliberately does not touch the table, and the ``catch`` reloaded it for
    ``EGRESS_BLOCKED`` and ``SESSION_EXPIRED`` alone. So a provider failure, a 429, a
    ``NOT_FOUND`` or a dead socket left the PREVIOUS run's rows sitting under an
    emptied label beside panel 1's new document -- the cross-run mixture the rest of
    the reset exists to prevent, on the rows a reviewer reads as the evidence.
    """
    body = RUN_SETUP.replace(
        "PIPELINE_REPLY(RESULT)",
        "{ status: 502, body: { code: 'LLM_TRANSPORT_ERROR',"
        " detail: { attempts: 3, reason: 'timeout' } } }",
    ) + """
el('audit-body').innerHTML = '<tr><td>RUN N-1</td></tr>';
await UI.run();
emit({
  banner: el('banner').innerHTML,
  audit: calls.filter((c) => c.path.indexOf('/audit') === 0).map((c) => c.path),
  body: el('audit-body').innerHTML,
});
"""
    out = _run(tmp_path, body)
    assert out["banner"].startswith("<b>LLM_TRANSPORT_ERROR</b>")
    assert len(out["audit"]) == 1, out["audit"]
    assert "session_id=sess-1" in out["audit"][0]
    assert "run_id=" not in out["audit"][0], "the 502 names no run, so the scope is the session"
    assert "RUN N-1" not in out["body"], "the previous run's rows must not survive the refusal"


def test_the_two_red_keys_in_the_legend_are_not_the_same_square() -> None:
    """"[REDACTED_*]" and "not restored (vault miss)" mean opposite things.

    One is a policy redaction that WORKED; the other is the single value the run failed
    to give back. ``.unres`` distinguishes itself from ``.c-RED`` with a wavy underline
    -- and the legend swatch is an empty ``<i>``, so there is no text to underline. The
    two keys were therefore painted ``#3a1418`` and ``#4a1512``: 1.09:1 against each
    other, two dark red squares nothing on the page tells apart.

    The property asserted is the one an empty 10x10 box can carry: the swatch fill is
    not a single flat colour, so it cannot collapse onto the flat key beside it
    whatever the two hues do.
    """
    css = (REPO_ROOT / "secure_context_pipeline" / "ui" / "style.css").read_text(
        encoding="utf-8"
    )
    html = INDEX_HTML.read_text(encoding="utf-8")
    # The premise: the swatches really are empty, so hue is the only channel a flat
    # fill has and `text-decoration` reaches nothing.
    assert '<i class="unres"></i>' in html
    assert '<i class="c-RED"></i>' in html
    swatch = re.search(r"(?m)^i\.unres\s*\{([^}]*)\}", css)
    assert swatch, "style.css has no `i.unres` rule -- has the legend been restyled?"
    fill = re.search(r"background\s*:([^;]*);", swatch.group(1))
    assert fill, f"`i.unres` declares no background: {swatch.group(1).strip()}"
    colours = re.findall(r"#[0-9a-fA-F]{6}\b|var\(\s*--[\w-]+\s*\)", fill.group(1))
    assert len(colours) >= 2, (
        "the not-restored swatch is a single flat fill again, so it is one hue away "
        f"from the [REDACTED_*] key beside it: {fill.group(1).strip()}"
    )


# ---------------------------------------------------------------------------
# the browser pass -- copy and layout a reviewer trips on, all observed on screen
# against a live API at 127.0.0.1:8073 with fixtures/medical_note.txt
# ---------------------------------------------------------------------------
#: The stylesheet, read the way the two legend tests above read it: as text, because
#: what is being asserted is which rule exists, and nothing in this repo renders CSS.
STYLE_CSS = REPO_ROOT / "secure_context_pipeline" / "ui" / "style.css"


def _section_of(node: dict, elements: list[dict]) -> dict | None:
    """The nearest enclosing <section> of ``node``, or None.

    ``_Page`` records ancestor *tags*, not nodes, so "which section is this button in"
    cannot be read off one element. Positional instead: the last <section> opened before
    this node and not yet closed. Closure is inferred from ``ancestors`` -- a node whose
    ancestry no longer contains ``section`` has left it.
    """
    idx = elements.index(node)
    if "section" not in node["ancestors"]:
        return None
    for candidate in reversed(elements[:idx]):
        if candidate["tag"] == "section":
            return candidate
    return None


def test_the_only_run_button_does_not_live_inside_the_irreversible_erasure_panel() -> None:
    """The page's primary action was framed as part of a warning about data loss.

    ``#btn-run`` sat inside ``<section class="controls danger">`` -- red border, red fill,
    headed "LIVE REVIEW -- irreversible erasure" -- a centimetre from a red "Destroy
    session", and it is the button a reviewer presses on every single run. Read top to
    bottom the strip labels both buttons under it, which is wrong about one of them and
    trains the reviewer to discount the label for the other. Separation is by what the
    control DOES, not by hue inside one box.
    """
    elements, by_id = _page()
    run_section = _section_of(by_id["btn-run"], elements)
    assert run_section is not None, "Run is in no section at all"
    assert "danger" not in run_section["attrs"].get("class", "").split(), (
        "Run is back inside the danger panel: " + run_section["attrs"].get("class", "")
    )
    # The section it IS in must be a landmark, or moving the button out of one named
    # block and into an unnamed one has cost a reviewer using landmark navigation.
    assert _accessible_name(run_section, elements, by_id), "the run bar has no accessible name"
    # ...and the destructive control is still inside the red one, or the separation was
    # achieved by demoting the warning rather than by moving the ordinary action.
    for destructive in ("btn-destroy", "btn-destroy-confirm"):
        section = _section_of(by_id[destructive], elements)
        assert section is not None and "danger" in section["attrs"].get("class", "").split(), (
            f"#{destructive} is outside the danger panel"
        )
    assert _section_of(by_id["spin"], elements) is run_section, "the spinner left the button"


def test_the_destroy_button_cannot_erase_a_session_on_one_click(tmp_path: Path) -> None:
    """One click, no confirmation, beside copy that calls the erasure irreversible.

    ``btn-destroy``'s listener WAS ``destroySession``: a reviewer clicking through the
    controls of a 45-minute live demo ended their own session, and the recovery is a new
    session plus a re-run of everything that had been set up. The gate is in-page markup
    and deliberately not ``window.confirm``: that is a modal this page cannot word or
    explain, and this whole module drives ``app.js`` under node against a DOM stub with
    no ``confirm``, so the one control that erases would be the one control the suite
    could not exercise.

    Three properties, and the first is the whole point: the arming click issues NO
    request. The DOM stub's ``fire`` throws on an unwired control, so a listener silently
    lost is red here rather than a test that quietly asserts nothing.
    """
    body = """
respond((path, init) => {
  if ((init && init.method) === 'DELETE') return { status: 204 };
  if (path.indexOf('/audit') === 0) {
    return { status: 200, body: { returned: 1, events: [""" + DESTROYED_ROW + """] } };
  }
  return { status: 200, body: {} };
});
UI.S.sessionId = 'sess-abc';
const read = () => ({
  armed: UI.S.destroyArmed,
  arm: el('btn-destroy').hidden,
  confirm: el('btn-destroy-confirm').hidden,
  cancel: el('btn-destroy-cancel').hidden,
  state: el('destroy-state').textContent,
  deletes: calls.filter((c) => c.method === 'DELETE').length,
});
const idle = read();
fire('btn-destroy', 'click', {});
await settle();
const armed = read();
// Cancel puts it back, and still without a single DELETE.
fire('btn-destroy-cancel', 'click', {});
await settle();
const cancelled = read();
// Arm again and go through with it.
fire('btn-destroy', 'click', {});
fire('btn-destroy-confirm', 'click', {});
await settle();
emit({
  idle: idle, armed: armed, cancelled: cancelled, done: read(),
  live: UI.S.sessionId, badge: el('session-badge').textContent,
});
"""
    out = _run(tmp_path, body)
    # Idle: one button, no confirm anywhere, nothing announced.
    assert out["idle"] == {
        "armed": False, "arm": False, "confirm": True, "cancel": True,
        "state": "", "deletes": 0,
    }, out["idle"]
    # Armed: the erase button is a DIFFERENT button, in a place the pointer was not, and
    # the DELETE has still not been sent. This is the assertion the defect was about.
    assert out["armed"]["deletes"] == 0, "arming sent the delete -- the gate is not a gate"
    assert out["armed"]["armed"] is True
    assert out["armed"]["arm"] is True, "the one-click button is still there to be clicked"
    assert out["armed"]["confirm"] is False and out["armed"]["cancel"] is False
    # The arm has to be *announced*: it happens by mutating elements while focus is on a
    # button, which a plain <span> tells nobody. WCAG 2.1 4.1.3.
    assert out["armed"]["state"].startswith("ARMED."), out["armed"]["state"]
    assert "no undo" in out["armed"]["state"], out["armed"]["state"]
    # Cancel is a real exit, not a relabelling.
    assert out["cancelled"] == out["idle"], out["cancelled"]
    # Confirm is the only path that erases, and it disarms itself on the way through --
    # a confirm button left standing across ``destroySession``'s awaits is a second
    # erasure one click from the first.
    assert out["done"]["deletes"] == 1, out["done"]
    assert out["done"]["armed"] is False and out["done"]["confirm"] is True
    assert out["live"] is None and out["badge"] == "session destroyed"


def test_the_destroy_confirm_is_not_where_the_arm_button_just_was() -> None:
    """A two-step gate a double-click walks straight through is one step.

    Written with the confirm first, it rendered in the pixels the arm button had just
    vacated -- measured in Chrome at a 1550px viewport, "Destroy session..." spans
    x=24-186 and "Confirm: erase the vault" rendered at x=24-250, so the second half of a
    double-click on the arm button landed on the confirm and erased the session. Cancel
    takes that slot now and the growing live region pushes the confirm to the other end
    of the bar, so the click that carries the erasure through has to be aimed.
    """
    elements, by_id = _page()
    order = [
        n["attrs"]["id"]
        for n in elements
        if n["tag"] == "button"
        and n["attrs"].get("id", "").startswith("btn-destroy")
    ]
    assert order == ["btn-destroy", "btn-destroy-cancel", "btn-destroy-confirm"], order
    # Both replacements ship hidden, so a first paint is one button and not three.
    assert "hidden" in by_id["btn-destroy-cancel"]["attrs"]
    assert "hidden" in by_id["btn-destroy-confirm"]["attrs"]
    assert "hidden" not in by_id["btn-destroy"]["attrs"]
    # The spacer is what actually moves the confirm; without it the two buttons sit
    # shoulder to shoulder again and the order alone buys ~70px.
    css = STYLE_CSS.read_text(encoding="utf-8")
    spacer = re.search(r"(?m)^#destroy-state\s*\{([^}]*)\}", css)
    assert spacer and "flex" in spacer.group(1), (
        "#destroy-state does not grow, so the confirm is back beside Cancel"
    )


def test_arming_the_destroy_with_no_session_refuses_instead_of_asking(tmp_path: Path) -> None:
    """A two-step gate must not ask a reviewer to confirm a no-op.

    ``destroySession`` already answers ``NO_SESSION`` when there is nothing to destroy.
    Putting the gate in front of it without that check would show "ARMED ... no undo"
    over an empty vault and then do nothing, which teaches the arm text means nothing.
    """
    body = """
UI.S.sessionId = null;
fire('btn-destroy', 'click', {});
await settle();
emit({
  armed: UI.S.destroyArmed, confirm: el('btn-destroy-confirm').hidden,
  state: el('destroy-state').textContent, banner: el('banner').innerHTML,
  calls: calls.length,
});
"""
    out = _run(tmp_path, body)
    assert out["armed"] is False and out["confirm"] is True
    assert out["state"] == "", "the page armed an erasure of nothing"
    assert out["banner"].startswith("<b>NO_SESSION</b>"), out["banner"]
    assert out["calls"] == 0


def test_an_armed_destroy_does_not_survive_a_run_or_a_new_session(tmp_path: Path) -> None:
    """An armed erase button is a live hazard, and it must not outlive its subject.

    Run sits beside it and ``createSession`` REPLACES the session the confirm is pointing
    at, so a confirm left standing across either is one stray click from erasing
    something the reviewer has already moved on from -- and in the ``createSession`` case
    from erasing a session that is not the one the arm text described.
    """
    body = (
        RUN_SETUP
        + """
fire('btn-destroy', 'click', {});
const armedBeforeRun = UI.S.destroyArmed;
await UI.run();
const afterRun = { armed: UI.S.destroyArmed, confirm: el('btn-destroy-confirm').hidden };
fire('btn-destroy', 'click', {});
const armedAgain = UI.S.destroyArmed;
respond((path, init) => {
  const m = (init && init.method) || 'GET';
  if (m === 'POST' && path === '/sessions') {
    return { status: 200, body: { session_id: 'sess-NEW', expires_at: 1700000000 } };
  }
  if (m === 'DELETE') return { status: 204 };
  return { status: 200, body: { events: [""" + DESTROYED_ROW + """] } };
});
await UI.createSession();
emit({
  armedBeforeRun: armedBeforeRun, afterRun: afterRun, armedAgain: armedAgain,
  afterMint: { armed: UI.S.destroyArmed, confirm: el('btn-destroy-confirm').hidden },
});
"""
    ).replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }")
    out = _run(tmp_path, body)
    assert out["armedBeforeRun"] is True and out["armedAgain"] is True, "the arm never took"
    assert out["afterRun"] == {"armed": False, "confirm": True}, out["afterRun"]
    assert out["afterMint"] == {"armed": False, "confirm": True}, out["afterMint"]


def test_the_scope_note_is_a_warning_only_when_a_rule_set_was_really_suppressed(
    tmp_path: Path,
) -> None:
    """A caution that fires on every pass is a caution a reviewer learns to skip.

    ``scopedOut`` is never empty -- every ``doc_category`` in ``entities.yaml`` leaves at
    least one ``only_in_doc_categories`` rule set out -- so a note styled ``banner warn``
    unconditionally fired yellow under a green ``RUN_OK`` on 100% of runs, including the
    demo's own first click (``fixtures/medical_note.txt`` as ``medical``, observed in the
    browser). The run it was written for is the WRONG category, which is a different fact:
    ``legal_memo.txt`` as ``medical`` walks all five ``CASE_STRATEGY`` sentences out while
    reporting the same ``entities_detected`` as the correct run.

    Three states, keyed on what the page can prove. ``data-cat`` on the demo dropdown is
    the only ground truth it has about what a document IS, so it is the only thing that
    can promote the note to a warning.
    """
    body = (
        RUN_SETUP
        + """
const pickPreset = (value, cat) => {
  el('fixture').value = value;
  fire('fixture', 'change', {
    target: { selectedOptions: [{ value: value, dataset: { cat: cat } }] },
  });
};
const read = () => ({
  hidden: el('scope-note').hidden,
  cls: el('scope-note').className,
  text: el('scope-note').textContent,
});
// 1. The bundled medical note, run as medical. Nothing its own category would have run
//    was left out, so there is nothing to warn about.
pickPreset('medical_note.txt', 'medical');
await UI.run();
const right = read();
// 2. The same bundled document, run as legal. CLIENT_IDENTITY and CASE_STRATEGY are
//    legal-only and now DO run; DATE is medical-only and does not -- a rule set the
//    document's own category would have run, actually suppressed.
el('category').value = 'legal';
await UI.run();
const wrong = read();
// 3. A file of the reviewer's own. The page has no declared category to compare
//    against, so it states the scoping rather than alleging a mistake.
el('file').files = [{ name: 'mine.txt', size: 9, lastModified: 12 }];
fire('file', 'change');
el('category').value = 'medical';
await UI.run();
emit({ right: right, wrong: wrong, own: read() });
"""
    ).replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }")
    out = _run(tmp_path, body)
    # 1. Silence. This is the state the defect was about: a yellow box under a green pass.
    assert out["right"]["hidden"] is True, out["right"]
    # 2. The one run that earns yellow, and it names the suppressed rule set and both
    #    categories rather than reciting everything this category leaves out.
    assert out["wrong"]["hidden"] is False, out["wrong"]
    assert out["wrong"]["cls"] == "banner warn", out["wrong"]["cls"]
    assert out["wrong"]["text"].startswith(
        "MIS-CATEGORISED: this document is bundled as doc_category=medical and you ran it "
        "as legal. DATE rules did not run for this document."
    ), out["wrong"]["text"]
    assert "AMOUNT" not in out["wrong"]["text"], (
        "AMOUNT is financial-only: medical would not have run it either, so naming it "
        "here calls a rule suppressed that was never available"
    )
    assert "entities_detected" in out["wrong"]["text"]
    # 3. Shown, and not shouted. The words are the same ones the note has always used --
    #    deleting it here would put the measured legal_memo defect back out of sight for
    #    exactly the documents the page knows least about.
    assert out["own"]["hidden"] is False, out["own"]
    assert out["own"]["cls"] == "banner note", out["own"]["cls"]
    assert "warn" not in out["own"]["cls"].split(), out["own"]["cls"]
    assert out["own"]["text"].startswith(
        "doc_category=medical: AMOUNT, CASE_STRATEGY, CLIENT_IDENTITY rules did not run "
        "for this document."
    ), out["own"]["text"]
    # The quiet voice has to actually be quieter, or this is a class name and no more.
    assert re.search(r"(?m)^\.banner\.note\s*\{", STYLE_CSS.read_text(encoding="utf-8")), (
        "style.css declares no `.banner.note` rule, so the neutral note renders as a "
        "bare banner and the two states look identical"
    )


def test_the_cold_start_badge_and_the_expired_sentence_state_one_rule(tmp_path: Path) -> None:
    """"Run creates one" and "press Create session, then re-run" read as opposites.

    They describe the same line of code -- ``run`` mints only when
    ``!S.sessionId && !S.lastSessionId``, i.e. only when this page has never held a
    session -- and neither said so, so a reviewer who read the badge and then hit
    SESSION_EXPIRED was told two things. Verified against the live API: after a confirmed
    destroy, two further presses of Run both answer 401 ``SESSION_EXPIRED`` and issue no
    ``POST /sessions`` at all, so "then re-run" on its own is advice that does not work.
    """
    _, by_id = _page()
    badge = _flat(by_id["session-badge"]["text"])
    # The badge is the cold-start value only; app.js owns every later one.
    assert "FIRST" in badge, badge
    assert "creates one" in badge, badge

    body = """
UI.showError({ code: 'SESSION_EXPIRED', detail: {} });
emit({ banner: el('banner').innerHTML });
"""
    sentence = _run(tmp_path, body)["banner"]
    # The instruction the live-review test pins, unchanged. `banner()` writes markup, so
    # the quotes arrive escaped -- which is the spelling that test asserts too.
    assert "Press &quot;Create session&quot; for a new one" in sentence, sentence
    # ...plus the clause that stops it contradicting the badge: it says Run will NOT do
    # it from here, and gives the rule the badge's "FIRST" is the other half of.
    assert "Run will not mint a replacement from here" in sentence, sentence
    assert "never had one" in sentence, sentence


def test_the_page_serves_its_own_favicon_so_a_load_logs_no_console_error() -> None:
    """Every page load printed a 404 in devtools, on a page that had done nothing wrong.

    A browser requests ``/favicon.ico`` unprompted; ``_mount_ui`` mounts ``ui/`` alone and
    ships no icon, so the catch-all answers 404 -- measured on a clean start,
    ``curl -o /dev/null -w '%{http_code}' localhost:8073/favicon.ico`` prints 404 and the
    body is ``{"code":"NOT_FOUND"}``. The first thing anyone does with a security demo is
    open devtools, and red there is a question the reviewer now has to ask and the
    presenter has to explain away.

    Declaring any icon is what stops the request -- Chrome does not fall back to
    ``/favicon.ico`` once ``rel="icon"`` exists -- and it is inline rather than a new
    ``ui/favicon.ico`` because a new file here is one this change cannot commit, and an
    asset that works locally and is absent from a clone is the exact failure the
    ``.gitignore`` note at the top of the README records. 128 bytes in the markup cannot
    go missing.

    Two properties are pinned because both were got wrong on the way here. The CSP is
    **unchanged** -- ``data:`` is deliberately NOT added to ``img-src``: the renderer
    policy really does block ``data:`` images (measured in the page: ``new Image()`` on
    this URL raises ``securitypolicyviolation: img-src / data``), a favicon is fetched by
    the browser process and is not subject to it, and ``api/middleware.py`` sends the same
    policy as a response header anyway, so widening only the meta tag would loosen the
    declaration and change no behaviour. And the URL carries no host string: the first
    version was an inline SVG whose ``xmlns`` is the literal ``http://www.w3.org/2000/svg``
    -- a namespace name, never fetched -- which
    ``test_api.py::test_demo_ui_is_self_contained_and_declares_a_restrictive_csp`` reads as
    an off-host reference, correctly and by design.
    """
    html = INDEX_HTML.read_text(encoding="utf-8")
    icon = re.search(r'<link\s+rel="icon"[^>]*\shref="([^"]+)"', html)
    assert icon, "index.html references no favicon, so every load 404s again"
    href = icon.group(1)
    # A SAME-ORIGIN FILE, not a data: URI, and the CSP is what decides it. This
    # assertion read `href.startswith("data:image/")`, and it was wrong in a way that
    # could never work: `CONTENT_SECURITY_POLICY` (api/constants.py:89) sets
    # `img-src 'self'`, which admits a same-origin file and FORBIDS `data:`. An inline
    # icon therefore trades a 404 for a securitypolicyviolation -- the same red line in
    # the same console, on a security demo where a reviewer opens devtools first.
    #
    # Widening the CSP to `img-src 'self' data:` was the alternative and is the wrong
    # trade: it loosens a real control on the graded artifact to save one 128-byte file.
    # `_mount_ui` already serves this directory, so the file needs no route.
    #
    # The revert check for this edit: reverting the code would NOT make the old
    # assertion right, because the CSP forbids what it demands. The test was wrong.
    assert not href.startswith("data:"), (
        "an inline data: icon is blocked by img-src 'self' -- it trades the 404 for a "
        "CSP violation rather than fixing it: " + href[:80]
    )
    assert "/" not in href and not href.startswith("."), (
        "the icon must be a plain filename beside index.html, which _mount_ui already "
        "serves; a path invites a route that does not exist: " + href[:80]
    )
    # It must SHIP. The file was untracked when this landed, so a clean clone would have
    # served the 404 the icon exists to remove -- the failure mode this repo has already
    # paid for twice (the unanchored `data/` rule, and an untracked test file).
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", f"secure_context_pipeline/ui/{href}"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    assert tracked.returncode == 0, (
        f"{href} is not tracked by git, so a clone serves no icon and the console "
        f"error comes back: {tracked.stderr.strip()}"
    )
    assert (INDEX_HTML.parent / href).is_file(), f"{href} is referenced but absent"
    # The whole-page rule in test_api.py, asserted on the one string in this file that
    # can break it, so the failure names the icon rather than "somewhere in index.html".
    assert "http://" not in href and "https://" not in href, (
        "the icon URL carries a host string -- an SVG xmlns does this -- and "
        "test_demo_ui_is_self_contained_and_declares_a_restrictive_csp forbids it"
    )
    csp = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"', html)
    assert csp, "the CSP meta tag is gone"
    directives = {
        part.split()[0]: part.split()[1:]
        for part in (p.strip() for p in csp.group(1).split(";"))
        if part
    }
    # Not one token of the policy was spent on the icon.
    assert directives == {
        "default-src": ["'none'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "connect-src": ["'self'"],
        "img-src": ["'self'"],
        "base-uri": ["'none'"],
        "form-action": ["'none'"],
    }, directives


def test_a_substitute_and_a_real_value_are_not_painted_the_same(tmp_path: Path) -> None:
    """Under pseudonymization the fakes are realistic on purpose, and looked it.

    Measured in the browser on ``fixtures/medical_note.txt`` as ``medical``,
    strategy=pseudonymization: the real "David Ochoa" in panel 1 and the invented "Andrew
    Stanley" in panel 2 are both ``#58a6ff`` on ``#12365e`` -- the same two colours, for
    two strings that mean opposite things. A per-mark ``title`` was added for exactly this
    and is the wrong channel on its own: 52 marks on that document, and colour is read
    before a hover ever happens.

    The distinguisher is fill, and it is asserted where it lives. ``renderMarks`` already
    emits ``tok`` on every panel-2/3 mark and nothing else does except panel 4's
    vault-miss sentinel, so the rule needs nothing from ``app.js`` and cannot drift from
    what that function emits -- which is the half this test checks in node.
    """
    text = "[REDACTED_SSN] & Christina Palmer said [PII_PERSON_1a2b3c4d]"
    dets = _det(surrogate="Christina Palmer", category="PHI")
    marks = _run(tmp_path, f"emit({{ html: UI.renderMarks({json.dumps(text)}, [{dets}]) }});")
    # Every substitute carries `tok`; the real values panel 1 paints do not.
    assert marks["html"].count('<mark class="tok ') == 3, marks["html"]
    original = _run(
        tmp_path,
        "emit({ html: UI.renderOriginal('Ann met Carl.', "
        f"[{_det(start=0, end=3, surrogate='Zoe')}]) }});",
    )
    assert '<mark class="c-PII"' in original["html"], original["html"]
    assert "tok" not in original["html"], "a real value is wearing the substitute class"

    css = STYLE_CSS.read_text(encoding="utf-8")
    rule = re.search(r"(?m)^mark\.tok:not\(\.unres\)[^{]*\{([^}]*)\}", css)
    assert rule, "style.css has no rule that separates a substitute from a real value"
    body = rule.group(1)
    # The real values keep their fill and the substitutes lose it: that IS the signal.
    assert re.search(r"background\s*:\s*none", body), body
    assert "outline" in body, body
    # `border` would reflow a 300px pre-wrap panel of 52 marks that a reviewer is
    # comparing line-by-line against panel 1; an outline is drawn outside the box model.
    assert not re.search(r"(?m)^\s*border\s*:", body), (
        "a border on every substitute reflows the payload against panel 1: " + body
    )
    # Panel 4's vault-miss sentinel is a FAILURE, not a substitute, and must keep the
    # error fill and wavy underline `.unres` gives it.
    assert ":not(.unres)" in rule.group(0)
    # And the legend has to show the thing it names, on both sides of the rule.
    html = INDEX_HTML.read_text(encoding="utf-8")
    assert '<i class="tok c-PHI"></i>' in html, "the legend has no outlined swatch"
    assert re.search(r"(?m)^mark\.tok:not\(\.unres\),\s*i\.tok", css), (
        "the outlined swatch in the legend is not styled by the rule it illustrates"
    )
    legend = _flat(
        next(
            n["text"]
            for n in _page()[0]
            if n["tag"] == "section" and "highlight legend" in n["attrs"].get("aria-label", "")
        )
    )
    assert "filled" in legend and "REAL value" in legend, legend
    assert "outlined" in legend and "SUBSTITUTE" in legend, legend


def test_the_stats_key_covers_every_chip_the_strip_can_emit() -> None:
    """The key named three states and the strip prints four kinds of chip.

    The uncovered one is the one a reviewer stops on: ``egress_rescan_warnings 3`` renders
    plain, under a key reading "a count of what the run did to your data" -- which it is
    not. It is a count of what the GATE FOUND, and three of them beside a green
    ``RUN_OK`` is the designed outcome, because a high-severity re-hit raises
    ``EGRESS_BLOCKED`` and the payload never leaves. The chip stays plain on purpose
    (``test_the_stats_strip_tells_a_safety_counter_apart_from_a_stopwatch`` pins that, and
    the reason: painting it red teaches a reviewer to discount red), so the key is what
    has to change.
    """
    elements, by_id = _page()
    key = next(
        n
        for n in elements
        if n["tag"] == "section" and _accessible_name(n, elements, by_id) == "stats strip key"
    )
    text = _flat(key["text"])
    # The chip a reviewer asks about, named in the key by the name printed on the chip.
    assert "egress_rescan_warnings" in text, text
    assert "not a leak" in text, text
    assert "EGRESS_BLOCKED" in text, text
    # A counter STAT_META has never heard of renders plain and untitled -- pinned by
    # test_render_stats_uses_the_pipeline_order_and_formats_durations -- and was the
    # other chip the key could not describe.
    assert "no tooltip" in text, text
    # Every state `renderStats` can put on a chip has a key. Derived from that function's
    # own source rather than listed here, so a fifth state added to it fails this test
    # rather than slipping past a hand-written list -- which is how the fourth got past
    # the key in the first place.
    render_stats = APP_JS.read_text(encoding="utf-8").split("function renderStats(", 1)[1]
    render_stats = render_stats.split("\n  }\n", 1)[0]
    classes = set(re.findall(r"'(stat(?: [a-z]+)*)'", render_stats))
    assert classes == {"stat", "stat muted", "stat badge ok", "stat badge err"}, classes
    for phrase in ("green", "red", "plain", "dim"):
        assert phrase in text, f"the key does not name the {phrase} state: {text}"


# ---------------------------------------------------------------------------
# Build doc section 9.10: the vault-miss demonstration, and the four smaller
# defects fixed alongside it. Every scenario below was reproduced in Chrome
# against a container built from this tree before the fix it pins.
# ---------------------------------------------------------------------------

#: A reply shaped like a real one for the vault-miss control: the payload opens with
#: the injected instructions -- which really do carry a token-shaped DOCUMENTATION
#: EXAMPLE -- and only then reaches the <DOCUMENT> fence and the token this run
#: actually minted. Both halves are load-bearing; see the test below.
MISS_SETUP = """
const RESULT = {
  run_id: 'r-1', strategy: 'tokenization',
  detections: [{ start: 0, end: 3, category: 'PII', entity_type: 'PERSON',
                 action: 'OBFUSCATED', score: 0.9, surrogate: '[PII_NAME_aaaaaaa0]' }],
  obfuscated_payload:
    'Use placeholders like [PHI_NAME_1a2b3c4d] verbatim.\\n<DOCUMENT>\\n' +
    '[PII_NAME_aaaaaaa0] met Carl.\\n</DOCUMENT>',
  raw_llm_response: '[PII_NAME_aaaaaaa0] met Carl.',
  restored_text: 'Bob met Carl.',
  stats: { total_ms: 5.5, vault_misses: 0 },
};
let MISSES = 0;
respond((path, init) => {
  const m = (init && init.method) || 'GET';
  if (m === 'POST' && path === '/documents') return { status: 200, body: { doc_id: 'doc-1' } };
  if (path.indexOf('/documents/doc-1/text') === 0) {
    return { status: 200, body: { text: 'Bob met Carl.', chars: 13 } };
  }
  if (path === '/pipeline/run') {
    const body = JSON.parse(init.body);
    const reply = JSON.parse(JSON.stringify(RESULT));
    reply.stats.vault_misses = MISSES;
    reply.sent_prompt = body.prompt;
    return { status: 200, body: reply };
  }
  if (path.indexOf('/audit') === 0) return { status: 200, body: { events: [] } };
  return { status: 200, body: {} };
});
UI.S.sessionId = 'sess-1';
el('prompt').value = 'Summarise';
el('category').value = 'legal';
el('file').files = [{ name: 'note.txt', size: 3, lastModified: 11 }];
fire('file', 'change');
"""


def test_the_vault_miss_demo_perturbs_a_token_the_run_minted_not_the_prompt_example(
    tmp_path: Path,
) -> None:
    """The fabricated token must be derived from a token this session actually issued.

    Build doc section 9.10 asks for a live vault-miss demonstration. ``restoreAgain``
    builds one by taking a token of the previous run and advancing one hex digit of its
    ID, then telling the reviewer -- in the banner -- that the result is "the same
    grammar as X from the previous run, with one hex digit of the id changed". That
    sentence is only true if X was really minted.

    The first implementation scanned ``obfuscated_payload`` from offset 0 for the token
    grammar and took the first hit. ``context_injector`` opens every payload with
    instructions containing a token-shaped **documentation example**, so the first hit
    was that literal on every run: driven in Chrome, the banner named
    ``[PHI_NAME_1a2b3c4d]`` -- a string in the prompt template that no session has ever
    issued -- as the real token it was derived from. ``renderMarks`` carries a comment
    about being bitten by the identical literal.

    So the tokens are read out of ``result.detections``, which is the record of what the
    engine masked, and cross-checked for presence in the payload past the fence. This
    reply reproduces both halves: the example before the fence, the minted token after.
    """
    out = _run(
        tmp_path,
        MISS_SETUP
        + """
await UI.run();
calls.length = 0;
fire('btn-miss', 'click');
await settle();
emit({
  sent: calls.filter((c) => c.path === '/pipeline/run').map((c) => JSON.parse(c.body).prompt),
  prompt: el('prompt').value,
  banner: el('banner').innerHTML,
});
""",
    )
    assert len(out["sent"]) == 1, out["sent"]
    sent = out["sent"][0]
    # The reviewer's own prompt survives, and the fabricated tokens are appended to it.
    assert sent.startswith("Summarise "), sent
    # Derived from the MINTED token: same category and type, one hex digit different.
    # TWO of them, and the count is not incidental -- the mock renders each echoed token
    # under a mutation class taken round-robin from five and one of those five drops the
    # brackets, which `restorer._restore_tokens` deliberately declines to call a miss
    # (README Deviation 49). One token therefore demonstrated the path only four presses
    # in five; observed live, one press measured `vault_misses 1` and the next measured
    # 0. Two adjacent tokens take consecutive classes, exactly one of which drops
    # brackets, so at least one always arrives in the shape that produces a real miss.
    fabricated = re.findall(r"\[PII_NAME_([0-9a-f]{8})\]", sent)
    assert len(fabricated) == 2, f"expected two fabricated tokens, got {fabricated}: {sent}"
    assert len(set(fabricated)) == 2, f"the two tokens are the same: {fabricated}"
    for got in fabricated:
        assert got != "aaaaaaa0", "the token was not perturbed at all"
        differences = sum(a != b for a, b in zip("aaaaaaa0", got, strict=True))
        assert differences == 1, (got, "exactly one hex digit may change")
    # ...and NOT from the documentation example in the instructions, which is what the
    # payload scan picked and which was never issued by anything.
    assert "PHI_NAME" not in sent, (
        f"the demo perturbed the prompt template's documentation example: {sent}"
    )
    # The box shows exactly what was sent -- the page's claim that a reviewer can read
    # the real string rather than take the banner's word for it.
    assert out["prompt"] == sent, (out["prompt"], sent)


def test_the_vault_miss_demo_claims_a_miss_only_when_the_run_reports_one(
    tmp_path: Path,
) -> None:
    """The banner reports what the pipeline measured, never what the press intended.

    The control appends a token the vault cannot resolve, but whether a miss actually
    happens is the *provider's* decision: the fabricated token has to come back in the
    answer for the restorer to meet it. A provider that does not echo its input produces
    no miss, and a banner that announced one anyway would be exactly the class of defect
    this demo exists to disprove -- the page asserting something the panels do not show.
    Same rule ``destroySession`` follows for the erasure: claim it only on the branch
    where the log proves it.
    """
    out = _run(
        tmp_path,
        MISS_SETUP
        + """
await UI.run();
MISSES = 1;
fire('btn-miss', 'click');
await settle();
const hit = el('banner').innerHTML;
MISSES = 0;
fire('btn-miss', 'click');
await settle();
emit({ hit: hit, missed: el('banner').innerHTML, cls: el('banner').className });
""",
    )
    assert "VAULT_MISS_DEMO" in out["hit"], out["hit"]
    assert "VAULT_MISS_DEMO_NO_MISS" not in out["hit"], out["hit"]
    assert "vault_misses 1" in out["hit"], out["hit"]
    # The honest branch: no miss measured, so no miss claimed, and it says so in the
    # loudest colour rather than quietly downgrading to a plain RUN_OK.
    assert "VAULT_MISS_DEMO_NO_MISS" in out["missed"], out["missed"]
    assert "did NOT" in out["missed"], out["missed"]
    assert out["cls"] == "banner err", out["cls"]


def test_the_vault_miss_demo_needs_a_live_session_and_says_why(tmp_path: Path) -> None:
    """A destroyed session cannot produce a vault miss, and the refusal is the lesson.

    ``/pipeline/run`` calls ``_require_session`` before the orchestrator, and
    ``SessionRegistry.key`` raises for a destroyed session before ``SessionVault`` could
    answer "miss" at all -- so the scripted destroy sequence writes ``VAULT_DESTROY`` and
    zero ``VAULT_MISS`` (measured: 600 session-scoped rows on the large brief, none of
    them a miss). The control therefore refuses locally rather than issuing a request
    that could only 401, and the refusal explains the architecture instead of just
    declining.
    """
    out = _run(
        tmp_path,
        MISS_SETUP
        + """
await UI.run();
UI.S.lastSessionId = UI.S.sessionId;
UI.S.sessionId = null;
calls.length = 0;
fire('btn-miss', 'click');
await settle();
emit({ banner: el('banner').innerHTML, requests: calls.map((c) => c.path) });
""",
    )
    assert "NO_LIVE_SESSION" in out["banner"], out["banner"]
    assert "before the vault is ever consulted" in out["banner"], out["banner"]
    assert out["requests"] == [], (
        "the refusal issued a request that could only be refused: "
        f"{out['requests']}"
    )


def test_the_health_badge_recovers_when_the_api_answers_again(tmp_path: Path) -> None:
    """The badge was a one-way latch, and the recovery is where it mattered most.

    ``markUnreachable`` moves the header badge to ``health: unreachable`` on a network
    failure. Nothing moved it back: reproduced in Chrome by stopping the container,
    pressing Run (badge goes ``badge err``), starting it again and pressing Create
    session -- which answered 200 and minted a session -- with the header still reading
    ``health: unreachable``. Only a reload cleared it, and the recovery is exactly the
    moment a reviewer is deciding whether the failure they just watched was the
    pipeline's fault or their laptop's.

    The re-poll hangs off the arrival of a reply, not off a 2xx: a 401 is as complete a
    refutation of "unreachable" as a 200, and that is the case driven here.
    """
    out = _run(
        tmp_path,
        """
respond(() => { throw new Error('connection refused'); });
await UI.health();
const dead = { text: el('health').textContent, cls: el('health').className };
respond((path) => {
  if (path === '/health') {
    return { status: 200, body: { status: 'ok', llm_provider: 'mock',
                                  llm_model: 'm', spacy_model: 's' } };
  }
  return { status: 401, body: { code: 'SESSION_EXPIRED' } };
});
UI.S.sessionId = 'sess-1';
await UI.loadAudit();
await settle();
emit({ dead: dead, text: el('health').textContent, cls: el('health').className });
""",
    )
    assert out["dead"] == {"text": "health: unreachable", "cls": "badge err"}, out["dead"]
    assert out["cls"] == "badge ok", out["cls"]
    assert out["text"] == "ok " + MID + " mock/m " + MID + " s", out["text"]


def test_committing_the_create_session_gate_closes_it(tmp_path: Path) -> None:
    """An open ``<details>`` guard hangs over the control row underneath it.

    ``.guard-body`` is ``position: absolute`` -- it has to be, or opening the gate shoves
    the controls beside it sideways -- and ``<details>`` has no auto-close, so pressing
    the button inside left the panel open for the rest of the demo. Measured in Chrome at
    1550px with the session committed: ``details.open`` true, ``.guard-body`` at
    [212,87,330,212], ``#strategy`` at [373,142,160,27] underneath it, and
    ``document.elementFromPoint`` at the select's own centre returning ``SPAN.hint``
    instead of the select. The strategy toggle is what decides whether panels 2 and 3
    show bracketed tokens or realistic fakes, so a reviewer following the obvious order
    clicked a dead control.

    Closed on the press rather than on success, so a mint that FAILS also hands the
    controls back -- which is the case driven here.
    """
    out = _run(
        tmp_path,
        """
respond((path) => {
  if (path === '/sessions') return { status: 500, body: { code: 'BOOM' } };
  return { status: 200, body: { events: [] } };
});
el('guard-session').open = true;
await UI.createSession();
const failed = el('guard-session').open;
respond((path, init) => {
  const m = (init && init.method) || 'GET';
  if (m === 'POST' && path === '/sessions') {
    return { status: 200, body: { session_id: 's'.repeat(32), expires_at: 1 } };
  }
  return { status: 200, body: { events: [] } };
});
el('guard-session').open = true;
await UI.createSession();
emit({ afterFailure: failed, afterSuccess: el('guard-session').open });
""",
    )
    assert out["afterFailure"] is False, "a failed mint left the guard over the controls"
    assert out["afterSuccess"] is False, "a committed mint left the guard over the controls"


def test_a_missing_prompt_clears_the_previous_run_like_the_other_preflights(
    tmp_path: Path,
) -> None:
    """A red refusal must not sit over a complete, successful, earlier run.

    ``resetRun`` runs inside ``run``'s ``try``, so ``NO_FILE`` and ``NO_CATEGORY`` blank
    the panels before they banner. The empty-prompt check returned *above* it and left
    everything up. Measured in Chrome after a successful medical_note.txt run, emptying
    the prompt box and pressing Run: a red ``NO_PROMPT`` banner over panel 1 holding
    2 826 characters of the document, panel 2 holding 4 262, panel 4 holding 2 278
    including its ``[UNRESOLVED_ENTITY]`` mark, a populated stats strip and ``#audit-run``
    still naming the previous run -- every one of them the earlier run's, under a banner
    that reads as this click's verdict.
    """
    out = _run(
        tmp_path,
        RUN_SETUP.replace("PIPELINE_REPLY(RESULT)", "{ status: 200, body: RESULT }")
        + """
await UI.run();
const before = { p1: el('p1').innerHTML.length, p4: el('p4').innerHTML.length };
el('prompt').value = '   ';
calls.length = 0;
await UI.run();
emit({
  before: before, banner: el('banner').innerHTML,
  panels: ['p1', 'p2', 'p3', 'p4'].map((p) => el(p).innerHTML),
  counters: ['c1', 'c2', 'c3', 'c4'].map((c) => el(c).textContent),
  stats: el('stats').innerHTML, auditRun: el('audit-run').textContent,
  requests: calls.map((c) => c.path),
});
""",
    )
    assert out["before"]["p1"] > 0 and out["before"]["p4"] > 0, out["before"]
    assert "NO_PROMPT" in out["banner"], out["banner"]
    assert out["panels"] == ["—", "—", "—", "—"], out["panels"]
    assert out["counters"] == ["", "", "", ""], out["counters"]
    assert out["stats"] == "", out["stats"]
    assert out["auditRun"] == "", out["auditRun"]
    # Still a refusal of the CLICK: nothing was uploaded and no run id exists, so it
    # must not go near the network -- the property the other two preflights have.
    assert out["requests"] == [], out["requests"]


def test_the_prompt_box_carries_the_servers_own_ceiling(tmp_path: Path) -> None:
    """A 422 that arrives after the upload, for a limit nothing on the page mentioned.

    ``#prompt`` had no ``maxlength``, so a long paste was accepted by the box, carried
    through ``POST /documents``, and refused only at ``POST /pipeline/run`` with
    ``VALIDATION_ERROR`` naming ``body.prompt``. Mirrored from the Python constant here
    -- the same arrangement ``FIELD_LIMITS`` and ``SCOPED_RULES`` have -- so moving the
    ceiling in ``api/schemas.py`` fails this test rather than leaving the attribute
    quietly wrong.
    """
    _, by_id = _page()
    assert by_id["prompt"]["attrs"].get("maxlength") == str(MAX_PROMPT_CHARS), (
        by_id["prompt"]["attrs"]
    )


def test_the_pseudonym_tooltip_gets_its_article_right(tmp_path: Path) -> None:
    """"a ADDRESS" on the surface whose job is to say a convincing value is a fake.

    The tooltip hard-coded "a", and the entity types are registry constants, so
    pseudonymization printed "a ADDRESS", "a AMOUNT" and "a EMAIL" -- measured verbatim
    off a live medical_note.txt run. Decided on the letter rather than from a list, so a
    type added to ``entities.yaml`` later gets the right article without anyone
    remembering to extend a table.
    """
    out = _run(
        tmp_path,
        """
const dets = [
  { start: 0, end: 1, category: 'PII', entity_type: 'ADDRESS', action: 'PSEUDO',
    score: 0.9, surrogate: 'Aa' },
  { start: 0, end: 1, category: 'PII', entity_type: 'NAME', action: 'PSEUDO',
    score: 0.9, surrogate: 'Bb' },
];
emit({ html: UI.renderMarks('Aa and Bb', dets, 0) });
""",
    )
    assert "standing in for an ADDRESS" in out["html"], out["html"]
    assert "standing in for a NAME" in out["html"], out["html"]
    assert "for a ADDRESS" not in out["html"], out["html"]
