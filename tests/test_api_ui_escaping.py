"""The demo UI's HTML-escaping control, checked mechanically (build doc section 16).

``ui/app.js`` opens with the claim that "every string that originates from a
document, an LLM, or an error body is HTML-escaped before it is inserted; nothing
untrusted is ever interpolated raw", and ``tests/test_api.py``'s CSP test says in
its own docstring that "escaping is the control and is asserted in the JS itself".
It was not asserted anywhere. Searching the whole ``tests/`` tree for ``esc(``,
``escapeHtml`` or ``&lt;`` turned up nothing, and deleting ``esc()`` from the
three sinks that render network-derived strings --

    $('p3').innerHTML = esc(result.raw_llm_response)   # raw model output
    $('p1').innerHTML = esc(doc.text)                  # the document's own text
    el.innerHTML = '<b>' + esc(code) + '</b> ' + esc(msg)   # an error body

-- left the suite green. Driving the real ``app.js`` in a JS runtime with the
payload ``<img src=x onerror="alert(1)"><script>...</script>`` confirms both
directions: unmutated, panel 3 and the banner receive ``&lt;img src=x ...``;
with ``esc()`` removed they receive the tag verbatim. The response CSP
(``script-src 'self'``, no ``unsafe-inline``) stops that markup from *executing*,
which is why this is the second line and not the first -- but HTML injection into
the page is uncontested without escaping, and the LLM's output is by definition
attacker-influenced text: build doc section 16 requires treating it as untrusted.

Rather than depend on a JS runtime being installed wherever this suite runs, the
control is asserted by reading the source: every expression that becomes markup
is decomposed into its concatenation terms, and every term must be a literal, an
``esc(...)`` call, a call to one of the file's own markup builders, or a local
accumulator that is itself only ever built from those. The checker is exercised
against fourteen mutations of the real file at the bottom of this module, so it
cannot pass by failing to look.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_JS = REPO_ROOT / "secure_context_pipeline" / "ui" / "app.js"
STYLE_CSS = REPO_ROOT / "secure_context_pipeline" / "ui" / "style.css"

#: A single-quoted, double-quoted or backtick literal, whole.
_LITERAL = re.compile(r"""^(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`)$""")
#: The callee of ``a.b.c(...)``.
_CALL = re.compile(r"^(?:[A-Za-z_$][\w$]*\s*\.\s*)*(?P<name>[A-Za-z_$][\w$]*)\s*\(")
#: ``xs.map(cb).join(sep)`` is the only chained form the UI uses to build a row
#: list; ``cb``'s own body is checked separately by the markup and return rules.
_SAFE_METHODS = frozenset({"map", "join"})
_KEYWORDS = frozenset({"if", "else", "for", "while", "return", "switch", "catch", "function"})
_FUNC_HEAD = re.compile(r"function\s*[A-Za-z_$][\w$]*\s*\([^()]*\)\s*$|function\s*\([^()]*\)\s*$")


def _blank(source: str) -> str:
    """Blank the *contents* of every string, regex and comment, offsets preserved.

    Splitting an expression on ``+`` is only meaningful once a ``'+'`` inside a
    string literal or a ``/[.*+?]/`` character class can no longer be mistaken
    for an operator. Every index into the result is still valid in the original.
    """
    out = list(source)
    i, n, prev = 0, len(source), ""
    while i < n:
        ch = source[i]
        if ch in "\"'`":
            j = i + 1
            while j < n and source[j] != ch:
                j += 2 if source[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = "\n" if source[k] == "\n" else "."
            i, prev = min(j, n - 1) + 1, ch
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            j = source.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            j = source.find("*/", i)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                out[k] = "\n" if source[k] == "\n" else " "
            i = j
            continue
        if ch == "/" and prev in "(,=:[!&|?+-*%~^<>":
            j = i + 1
            while j < n and source[j] not in "/\n":
                j += 2 if source[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = "."
            i, prev = min(j, n - 1) + 1, "/"
            continue
        if not ch.isspace():
            prev = ch
        i += 1
    return "".join(out)


def _split(blank: str, seps: str) -> list[tuple[int, int]]:
    """Spans between top-level (bracket-depth zero) occurrences of ``seps``."""
    spans: list[tuple[int, int]] = []
    depth = start = 0
    for idx, ch in enumerate(blank):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and ch in seps:
            spans.append((start, idx))
            start = idx + 1
    spans.append((start, len(blank)))
    return spans


def _matching_paren(blank: str, open_idx: int) -> int:
    """Index of the ``)`` closing the ``(`` at ``open_idx``, or end of source.

    Must run on the blanked text: a ``")"`` inside a string literal would otherwise
    close the argument list early and truncate the argument being checked.
    """
    depth = 0
    for idx in range(open_idx, len(blank)):
        if blank[idx] in "([{":
            depth += 1
        elif blank[idx] in ")]}":
            depth -= 1
            if depth == 0:
                return idx
    return len(blank)


def _interpolations(term: str) -> list[str] | None:
    """The ``${...}`` expressions inside a backtick literal, or ``None`` if not one.

    A template literal is a *concatenation written without a ``+``*, and the checker
    used to be blind to exactly that: ``_LITERAL`` matched any backtick string whole,
    so ``` `<pre>${result.raw_llm_response}</pre>` ``` assigned to ``.innerHTML``
    read as a plain string literal and the audit returned no problems. Measured
    against the real ``app.js`` before this existed -- substituting that expression
    for the ``$('p3').innerHTML`` line left ``audit_escaping`` reporting ``[]``,
    while the same injection written as ``'<pre>' + result.raw_llm_response`` was
    caught. The escape hatch was the syntax, not the sink.

    ``app.js`` uses no interpolated template literal today (152 backticks, zero
    ``${``), so this is a *latent* hole rather than a live one -- which is the reason
    it is worth closing here rather than in the file: the checker is what a future
    edit has to get past, and this is the shape that would have walked through.

    Brace-matched rather than regex-matched, because ``${obj.fn({a: 1})}`` nests and
    a non-greedy ``\\$\\{(.*?)\\}`` would stop at the inner brace and hand back a
    fragment that parses as safe. Returns ``[]`` for a backtick literal with no
    interpolation, which is genuinely a constant and stays safe.
    """
    if len(term) < 2 or not term.startswith("`") or not term.endswith("`"):
        return None
    found: list[str] = []
    i, n = 1, len(term) - 1
    while i < n:
        if term[i] == "\\":
            i += 2
            continue
        if term.startswith("${", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if term[j] in "{([":
                    depth += 1
                elif term[j] in "})]":
                    depth -= 1
                j += 1
            found.append(term[i + 2 : j - 1])
            i = j
            continue
        i += 1
    return found


def _terms(expr: str, blank: str) -> list[str]:
    """The pieces of ``expr`` that are concatenated into the result.

    ``cond ? a : b`` contributes ``a`` and ``b`` but not ``cond`` -- a condition
    is evaluated, never interpolated. Redundant parentheses are unwrapped so a
    nested ternary is not mistaken for an opaque expression.
    """
    expr, blank = expr.strip(), blank.strip()
    while blank.startswith("(") and blank.endswith(")") and len(_split(blank[1:-1], ")")) == 1:
        expr, blank = expr[1:-1].strip(), blank[1:-1].strip()
    branches = _split(blank, "?")
    if len(branches) > 1:
        rest = branches[0][1] + 1
        found: list[str] = []
        for a, b in _split(blank[rest:], ":"):
            found += _terms(expr[rest + a : rest + b], blank[rest + a : rest + b])
        return found
    return [expr[a:b].strip() for a, b in _split(blank, "+")]


def _stmt_end(blank: str, start: int) -> int:
    """Index of the ``;`` or unbalanced closer that ends the expression."""
    depth = 0
    for idx in range(start, len(blank)):
        ch = blank[idx]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return idx
            depth -= 1
        elif ch == ";" and depth == 0:
            return idx
    return len(blank)


def _function_bodies(blank: str) -> list[tuple[int, int]]:
    """Span of every *function* body. Never an ``if``/``for``/``while`` block."""
    spans: list[tuple[int, int]] = []
    for idx, ch in enumerate(blank):
        if ch != "{":
            continue
        before = blank[:idx].rstrip()
        if not (before.endswith("=>") or _FUNC_HEAD.search(before)):
            continue
        depth = 0
        for j in range(idx, len(blank)):
            if blank[j] == "{":
                depth += 1
            elif blank[j] == "}":
                depth -= 1
                if depth == 0:
                    spans.append((idx, j))
                    break
    return spans


def audit_escaping(source: str) -> tuple[list[str], list[str]]:
    """``(unescaped terms, expressions checked)`` for a JavaScript source file.

    Three families of expression become markup in this UI, and all three are
    checked:

    1. every write to a DOM markup sink: assignment to ``.innerHTML`` or
       ``.outerHTML``, the second argument of ``.insertAdjacentHTML(...)``, and
       every argument of ``document.write``/``writeln``;
    2. every ``+`` chain that concatenates an HTML *tag* literal, wherever it
       appears (this is what covers the insides of the ``render*`` helpers);
    3. every ``return`` out of a function that builds markup, which catches a
       raw value returned in a chain that happens to carry no tag of its own.

    Rule 1 used to read "every assignment to ``.innerHTML`` -- **the only DOM sink
    the file uses**", and that parenthesis was doing load-bearing work while nothing
    checked it. ``innerHTML`` is indeed the only sink ``app.js`` uses today, but the
    checker exists to constrain what the file may become, and the three sinks now
    listed alongside it were each one keystroke away and each audited clean:
    ``$('p3').outerHTML = result.raw_llm_response`` returned no problems. The claim
    is now *also* asserted rather than only stated --
    :func:`test_innerHTML_is_the_only_dom_sink_the_shipped_file_uses` fails if
    ``app.js`` grows one of the others, so the two statements cannot drift apart.

    A term is accepted only if it is a string literal, a template literal whose every
    ``${...}`` interpolation is itself accepted (:func:`_interpolations`), an
    ``esc(...)`` call, a call to one of this file's own markup builders, a
    ``map``/``join`` chain, or an identifier every assignment to which is itself
    accepted -- computed as a fix-point, which is what admits the ``out``/``html``/
    ``cls`` accumulators without admitting ``doc.text``.
    """
    blank = _blank(source)
    # An HTML *tag* literal. The lone `'<'` key in the escape table is not one,
    # and must not make the whole module count as markup-producing.
    markup_at = [
        m.start()
        for m in re.finditer(r"['\"]", blank)
        if re.match(r"<[A-Za-z/!]", source[m.start() + 1 : m.start() + 3])
    ]
    bodies = _function_bodies(blank)
    # The innermost function body around a literal is the one that builds it.
    markup_bodies = sorted(
        {max((s for s in bodies if s[0] < p < s[1]), key=lambda s: s[0]) for p in markup_at}
    )
    markup_funcs: set[str] = set()
    for start, _ in markup_bodies:
        head = blank[:start]
        named = re.search(r"function\s+([A-Za-z_$][\w$]*)\s*\([^()]*\)\s*$", head)
        if named:
            markup_funcs.add(named.group(1))
            continue
        arrow = re.search(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\([^()]*\)\s*=>\s*$", head)
        if arrow:
            markup_funcs.add(arrow.group(1))

    def is_safe(term: str, idents: frozenset[str]) -> bool:
        # Template literals FIRST: `_LITERAL` matches a backtick string whole, so
        # asking it before this would call `<pre>${raw}</pre>` a constant. A template
        # literal is safe exactly when every one of its interpolations is.
        interpolated = _interpolations(term)
        if interpolated is not None:
            return all(
                is_safe(t, idents)
                for expr in interpolated
                for t in _terms(expr, _blank(expr))
            )
        if not term or _LITERAL.match(term) or term in idents:
            return True
        call = _CALL.match(term)
        if call:
            name = call.group("name")
            if name == "esc" or name in markup_funcs or name in _SAFE_METHODS:
                return True
        return False

    assigns: dict[str, list[tuple[str, str]]] = {}
    for m in re.finditer(r"(?:\b(?:let|const|var)\s+)?(?P<n>[A-Za-z_$][\w$]*)\s*\+?=(?!=)", blank):
        name = m.group("n")
        if name in _KEYWORDS:
            continue
        end = _stmt_end(blank, m.end())
        assigns.setdefault(name, []).append(
            (source[m.end() : end].strip(), blank[m.end() : end].strip())
        )

    idents: frozenset[str] = frozenset()
    for _ in range(16):
        # An accumulator may name itself (`out += ...`); its *other* assignments
        # are what decide whether it is safe.
        grown = {
            name
            for name, exprs in assigns.items()
            if all(all(is_safe(t, idents | {name}) for t in _terms(e, b)) for e, b in exprs)
        }
        grown |= set(idents)
        if grown == set(idents):
            break
        idents = frozenset(grown)

    problems: list[str] = []
    checked: list[str] = []
    seen: set[tuple[int, int]] = set()

    def check(lo: int, hi: int, kind: str) -> None:
        if (lo, hi) in seen:
            return
        seen.add((lo, hi))
        expr, blk = source[lo:hi].strip(), blank[lo:hi].strip()
        line = source.count("\n", 0, lo) + 1
        checked.append(f"{kind}:{line} {' '.join(expr.split())[:70]}")
        for term in _terms(expr, blk):
            if not is_safe(term, idents):
                problems.append(f"{kind}:{line} raw term `{' '.join(term.split())[:60]}`")

    # Assignment sinks. `outerHTML` parses its right-hand side as markup exactly as
    # `innerHTML` does -- it replaces the element instead of its children, which is a
    # difference in what is destroyed, not in what is executed. Modelling only
    # `innerHTML` meant one keystroke moved a raw value out of the checker's sight:
    # `$('p3').outerHTML = result.raw_llm_response` audited clean.
    for m in re.finditer(r"\.(innerHTML|outerHTML)\s*=(?!=)", blank):
        check(m.end(), _stmt_end(blank, m.end()), m.group(1))

    # Call sinks, where the markup is an ARGUMENT rather than a right-hand side, so
    # the assignment scan above cannot see them at all.
    #   el.insertAdjacentHTML(position, markup)  -- the SECOND argument is parsed
    #   document.write(...) / document.writeln(...) -- every argument is
    for m in re.finditer(r"\.insertAdjacentHTML\s*\(", blank):
        lo = m.end()
        hi = _matching_paren(blank, m.end() - 1)
        args = _split(blank[lo:hi], ",")
        if len(args) >= 2:
            check(lo + args[1][0], lo + args[1][1], "insertAdjacentHTML")

    for m in re.finditer(r"\bdocument\s*\.\s*write(?:ln)?\s*\(", blank):
        lo = m.end()
        hi = _matching_paren(blank, m.end() - 1)
        for a, b in _split(blank[lo:hi], ","):
            check(lo + a, lo + b, "document.write")

    for pos in markup_at:
        lo = pos
        depth = 0
        while lo > 0:
            ch = blank[lo - 1]
            if ch in ")]}":
                depth += 1
            elif ch in "([{":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and (ch in ";,?:" or (ch == "=" and blank[lo - 2] not in "=!<>")):
                break
            elif depth == 0 and re.search(r"\breturn$", blank[:lo].rstrip()):
                lo = len(blank[:lo].rstrip())
                break
            lo -= 1
        hi = pos
        depth = 0
        while hi < len(blank):
            ch = blank[hi]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and ch in ";,?:":
                break
            hi += 1
        check(lo, hi, "markup")

    for start, end in markup_bodies:
        for m in re.finditer(r"\breturn\b", blank[start:end]):
            at = start + m.end()
            check(at, _stmt_end(blank, at), "return")

    return problems, checked


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_the_demo_ui_escapes_every_string_that_becomes_markup() -> None:
    """No expression that reaches the DOM may carry an unescaped value.

    ``raw_llm_response`` is the sharp end: it is whatever the model returned, and
    a document can ask the model to return anything. ``doc.text`` is the user's
    own document, and an error ``detail`` is a body from the network. All three
    were interpolated into ``innerHTML``, and all three could lose ``esc()``
    without a single test noticing.
    """
    problems, checked = audit_escaping(APP_JS.read_text(encoding="utf-8"))
    assert not problems, "\n".join(problems)
    assert len(checked) >= 15, (
        f"only {len(checked)} markup expressions found in app.js -- the checker has "
        f"stopped finding the code it is supposed to be checking:\n" + "\n".join(checked)
    )


def test_the_escape_helper_covers_every_character_that_can_open_markup() -> None:
    """``esc`` is the whole control, so its table is checked, not assumed.

    Dropping ``'`` or ``"`` from the map would leave every attribute-context
    interpolation (``title="..."`` in panel 1, ``class="..."`` in the audit
    table) injectable while every other assertion in this file still passed:
    the term is still spelled ``esc(...)``.
    """
    source = APP_JS.read_text(encoding="utf-8")
    table = source.split("const ESC = {", 1)[1].split("};", 1)[0]
    entries = dict(re.findall(r"""['"](.)['"]\s*:\s*['"](&[#\w]+;)['"]""", table))
    assert set(entries) == set("&<>\"'"), entries

    definition = source.split("const esc =", 1)[1].split(";", 1)[0]
    assert ".replace(" in definition, definition
    character_class = re.search(r"/\[([^\]]*)\]/g", definition)
    assert character_class, definition
    for character in "&<>\"'":
        assert character in character_class.group(1), (character, definition)
    assert "ESC[" in definition, definition


def test_the_escaping_checker_catches_every_way_the_control_can_be_removed() -> None:
    """The checker is only evidence if it fails when the control is gone.

    Each pair below is a single-hunk edit to the real ``app.js``. The first three
    are the mutations that survived the whole suite unchanged; the rest walk the
    same deletion through every other place a value becomes markup, including the
    two ``return`` paths that carry no tag literal of their own.
    """
    source = APP_JS.read_text(encoding="utf-8")
    mutations = {
        # Both sinks moved rather than changed: panel 3 now goes through the marking
        # renderer (it was the one panel with no highlighting, so an outbound
        # pseudonym read as a real value), and panel 1 branches on an empty
        # extraction. The mutation is still "delete the control from this sink".
        "panel 3 renders the LLM response raw": (
            "$('p3').innerHTML = renderMarks(result.raw_llm_response, result.detections, 0);",
            "$('p3').innerHTML = result.raw_llm_response;",
        ),
        "panel 1 renders the document text raw": (
            "$('p1').innerHTML = doc.chars ? esc(doc.text) : esc(NO_TEXT);",
            "$('p1').innerHTML = doc.chars ? doc.text : esc(NO_TEXT);",
        ),
        "renderMarks emits a raw unscanned head": (
            "let out = esc(text.slice(0, start));",
            "let out = text.slice(0, start);",
        ),
        "the error banner renders a response body raw": (
            "el.innerHTML = '<b>' + esc(code) + '</b> ' + esc(msg);",
            "el.innerHTML = '<b>' + code + '</b> ' + msg;",
        ),
        "renderOriginal splices a raw document slice": (
            "esc(text.slice(d.start, d.end)) + '</mark>'",
            "text.slice(d.start, d.end) + '</mark>'",
        ),
        "renderOriginal puts a raw value in a title attribute": (
            "title=\"' + esc(title) +",
            "title=\"' + title +",
        ),
        "renderOriginal returns a raw leading slice": (
            "return esc(text.slice(0, cursor)) + html;",
            "return text.slice(0, cursor) + html;",
        ),
        "renderMarks returns a raw trailing slice": (
            "return out + esc(text.slice(last));",
            "return out + text.slice(last);",
        ),
        "renderMarks emits a raw matched token": (
            "'\">' + esc(m[0]) + '</mark>'",
            "'\">' + m[0] + '</mark>'",
        ),
        # The restored region is now emitted per piece, because the one piece that is
        # NOT a restored value -- restorer.py's [UNRESOLVED_ENTITY] sentinel -- is
        # split out of the same gap and marked as itself.
        "renderRestored marks a raw restored region": (
            "'<mark class=\"rest\">' + esc(parts[k]) + '</mark>'",
            "'<mark class=\"rest\">' + parts[k] + '</mark>'",
        ),
        "renderRestored emits a raw unresolved sentinel": (
            "esc(UNRESOLVED + own) + '</mark>'",
            "(UNRESOLVED + own) + '</mark>'",
        ),
        "renderRestored appends a raw literal run": ("out += esc(lit);", "out += lit;"),
        "renderRestored bails out to raw text": (
            "if (!lits.length) return esc(restored);",
            "if (!lits.length) return restored;",
        ),
        # The chip's class is no longer the fixed literal `stat`: the strip now styles a
        # timing, a count and a must-be-zero safety counter apart, so the class is chosen
        # per key and the opening tag is `'<span class="' + cls + '"' + tip + '><i>'`.
        # Only the anchor moved -- the mutation is the same deletion of `esc` from the
        # two values, and the two values are the same two.
        "renderStats emits a raw stat key": (
            "'><i>' + esc(k) + '</i>' + esc(shown) +",
            "'><i>' + k + '</i>' + shown +",
        ),
        # The second sink `renderStats` grew: every counter the strip knows now carries
        # its plain-English meaning as a `title`, which is an attribute context.
        "renderStats puts a raw counter meaning in a title attribute": (
            "' title=\"' + esc(meta.why) + '\"'",
            "' title=\"' + meta.why + '\"'",
        ),
        "renderAudit emits a raw entity type": (
            "'</td><td>' + esc(e.entity_type || '')",
            "'</td><td>' + (e.entity_type || '')",
        ),
        "renderAudit emits a raw serialised detail map": (
            "esc(JSON.stringify(e.detail || {}))",
            "JSON.stringify(e.detail || {})",
        ),
        # The four below are not "delete esc from an existing sink" -- they are the
        # ways a value reaches the DOM *around* the shape the checker modelled. Every
        # one of them audited clean before `_interpolations` and the extra sinks
        # existed, on a file whose docstring claimed all three families were covered.
        # They stay in the battery because each is one keystroke from the real line.
        "panel 3 interpolates the LLM response into a template literal": (
            "$('p3').innerHTML = renderMarks(result.raw_llm_response, result.detections, 0);",
            "$('p3').innerHTML = `<pre>${result.raw_llm_response}</pre>`;",
        ),
        "panel 3 writes the LLM response through outerHTML": (
            "$('p3').innerHTML = renderMarks(result.raw_llm_response, result.detections, 0);",
            "$('p3').outerHTML = result.raw_llm_response;",
        ),
        "panel 3 writes the LLM response through insertAdjacentHTML": (
            "$('p3').innerHTML = renderMarks(result.raw_llm_response, result.detections, 0);",
            "$('p3').insertAdjacentHTML('beforeend', result.raw_llm_response);",
        ),
        "the LLM response is written straight to the document": (
            "$('p3').innerHTML = renderMarks(result.raw_llm_response, result.detections, 0);",
            "document.write(result.raw_llm_response);",
        ),
    }
    for name, (before, after) in mutations.items():
        assert source.count(before) == 1, (name, source.count(before))
        problems, _ = audit_escaping(source.replace(before, after))
        assert problems, f"the checker does not notice: {name}"


def test_the_checker_does_not_cry_wolf_on_the_escaped_form_of_each_new_sink() -> None:
    """Each sink added above must accept the *correct* spelling, or it is not a control.

    A checker that reports a problem no matter what is written is as useless as one
    that never does -- it just fails in the safe direction, and the first person to
    hit it deletes the rule. So every mutation row in the battery has a mirror here
    where the same sink is written with ``esc(...)``, and the audit must come back
    empty. The template-literal pair is the one that matters most: interpolation is
    ordinary modern JS and a rule that banned it outright would be worked around
    rather than satisfied.
    """
    source = APP_JS.read_text(encoding="utf-8")
    anchor = "$('p3').innerHTML = renderMarks(result.raw_llm_response, result.detections, 0);"
    assert source.count(anchor) == 1
    safe_forms = {
        "template literal, interpolation escaped": (
            "$('p3').innerHTML = `<pre>${esc(result.raw_llm_response)}</pre>`;"
        ),
        "template literal, no interpolation at all": "$('p3').innerHTML = `<pre>idle</pre>`;",
        "outerHTML, escaped": "$('p3').outerHTML = esc(result.raw_llm_response);",
        "insertAdjacentHTML, escaped": (
            "$('p3').insertAdjacentHTML('beforeend', esc(result.raw_llm_response));"
        ),
        "document.write, escaped": "document.write(esc(result.raw_llm_response));",
    }
    for name, replacement in safe_forms.items():
        problems, _ = audit_escaping(source.replace(anchor, replacement))
        assert not problems, f"false positive on the safe spelling of {name}: {problems}"


def test_innerHTML_is_the_only_dom_sink_the_shipped_file_uses() -> None:
    """``audit_escaping``'s rule 1 says so; this is that claim checked rather than assumed.

    The checker now models four DOM markup sinks, but the file is supposed to use
    exactly one. Both facts are worth holding: the checker is wide so a future edit
    cannot slip out of it, and ``app.js`` is narrow so the reviewer has one shape to
    read. The narrow claim is the one that was written down and never verified.

    ``srcdoc`` and ``document.domain`` are in the pattern because they are markup and
    origin sinks respectively that no amount of escaping makes safe here; if one ever
    appears, the right response is to remove it, not to teach the checker about it.
    """
    source = _blank(APP_JS.read_text(encoding="utf-8"))
    forbidden = re.compile(
        r"\.outerHTML\s*=(?!=)"
        r"|\.insertAdjacentHTML\s*\("
        r"|\bdocument\s*\.\s*write(?:ln)?\s*\("
        r"|\.srcdoc\s*=(?!=)"
        r"|\bdocument\s*\.\s*domain\s*=(?!=)"
    )
    hits = [
        f"line {source.count(chr(10), 0, m.start()) + 1}: {m.group(0).strip()}"
        for m in forbidden.finditer(source)
    ]
    assert not hits, (
        "app.js has grown a DOM sink other than innerHTML. audit_escaping does cover "
        f"these, but rule 1's premise -- and the reviewer's one-shape reading -- is "
        f"that innerHTML is the only one: {hits}"
    )
    assert ".innerHTML" in source, "premise: innerHTML is still the sink the UI uses"


def test_no_regex_source_in_the_ui_carries_an_unbounded_quantifier() -> None:
    """Every quantifier in `app.js`'s grammars is bounded, as `surrogates.py`'s is.

    `TOLERANT_SRC` is commented "mirrors TOKEN_RE" and did not: it used `\\s*` and
    `[A-Z0-9_]*` where the Python grammar uses `\\s{0,4}` and `[A-Z0-9_]{0,63}`,
    and `surrogates.py` calls those bounds "a security property, not style".

    The consequence is not theoretical. The pattern runs over
    `result.raw_llm_response` -- model output, uncapped -- and the shipped
    MockProvider echoes its input, so a document carrying a long whitespace run
    comes straight back. Measured in node against the real file: 645 ms at 20,000
    characters, 2,560 ms at 40,000 -- a clean 4x per doubling, i.e. ~26 s on a
    128k run, a frozen tab. Bounded, the same inputs are 0 ms and 1 ms. No shipped
    fixture triggers it (longest whitespace run: 46 characters), which is why it
    survived: this asserts the property rather than waiting for a fixture to grow.

    The property was real and the ENUMERATION was not. This looked only for
    ``const <NAME>_SRC = <string>;``, so by construction it could see ``MARKS_SRC``
    and ``TOLERANT_SRC`` and nothing else -- and the file also declares three regex
    *literals*, one of which had the same defect. ``EDGE_CLOSE`` was ``/[*_`]+$/``,
    unanchored at the start, so on a markdown run that is not at the end of the
    string the engine restarts a maximal match at every position inside the run and
    fails ``$`` each time: measured in node, 100 ms at 8,000 characters, 398 ms at
    16,000, 1,609 ms at 32,000, and 6.7 s through ``renderRestored`` at 64,000. A
    green run over an incomplete enumeration is not evidence about the file, so the
    literals are enumerated too, and the enumeration is checked for completeness
    against an independent census -- a fourth pattern fails this test until it is
    looked at.
    """
    source = APP_JS.read_text(encoding="utf-8")
    grammars = re.findall(r"^\s*const (\w*_SRC) = ([\s\S]*?);$", source, re.MULTILINE)
    assert grammars, "no regex-source constants found in app.js -- has it been renamed?"
    literals = re.findall(r"^\s*const ([A-Z_][A-Z0-9_]*) = (/.*/[a-z]*);$", source, re.MULTILINE)
    assert literals, "no regex literals found in app.js -- has the finder stopped matching?"

    # The census is deliberately a DIFFERENT rule from the finder above: every
    # top-level `const NAME =` whose right-hand side begins with a slash holds a
    # regex, whatever it looks like after that. If the two disagree, the finder has
    # stopped seeing a pattern that exists, which is the failure this test just had.
    census = {
        name
        for name, rhs in re.findall(r"^\s*const ([A-Z_][A-Z0-9_]*) = (.*)$", source, re.MULTILINE)
        if rhs.lstrip().startswith("/")
    }
    assert {name for name, _ in literals} == census, sorted(
        census.symmetric_difference({name for name, _ in literals})
    )
    grammars = grammars + literals

    offenders: list[str] = []
    for name, literal in grammars:
        # `*` and `+` applied to a character class or an escape are the unbounded
        # spellings. A bounded `{0,4}` is fine, and so is a literal `*` inside a
        # character class (there is one, in the markdown-edge trimmers).
        for match in re.finditer(r"(\\[sSwWdD]|\[[^\]]+\])([*+])", literal):
            offenders.append(f"{name}: {match.group(0)!r}")
    assert offenders == [], (
        "unbounded quantifier(s) in a UI grammar: "
        + ", ".join(offenders)
        + " -- bound them the way surrogates.py bounds TOKEN_RE"
    )


# ---------------------------------------------------------------------------
# style.css -- the control boundary (WCAG 2.1 1.4.11 Non-text Contrast, AA)
#
# This lives here rather than in ``test_ui_behaviour.py`` for the reason given at
# the top of this module: it is a static property of a shipped asset, and it must
# run on machines with no JS runtime. Nothing below shares an expression with the
# stylesheet -- CSS states colours, this states the arithmetic over them.
# ---------------------------------------------------------------------------
#: A six-digit hex colour, whole.
_HEX = re.compile(r"#[0-9a-fA-F]{6}\b")
#: ``var(--name)``, as the stylesheet spells its indirections.
_VAR = re.compile(r"var\(\s*(--[\w-]+)\s*\)")


def _relative_luminance(colour: str) -> float:
    """WCAG 2.1 relative luminance of a ``#rrggbb`` string.

    The definition, not an approximation: each channel is scaled to 0..1, linearised
    through the sRGB transfer curve, then weighted 0.2126/0.7152/0.0722.
    """
    channels = []
    for offset in (1, 3, 5):
        c = int(colour[offset : offset + 2], 16) / 255
        channels.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
    red, green, blue = channels
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _contrast(one: str, other: str) -> float:
    """The WCAG contrast ratio between two ``#rrggbb`` strings, 1.0 .. 21.0."""
    first, second = _relative_luminance(one), _relative_luminance(other)
    return (max(first, second) + 0.05) / (min(first, second) + 0.05)


def _block(css: str, selector: str) -> str:
    """The declarations of the rule that ``selector`` starts, verbatim.

    Anchored at the start of a line so that ``body`` cannot be answered by ``.body``
    and ``.controls`` cannot be answered by ``.controls.danger``.
    """
    match = re.search(r"(?m)^" + re.escape(selector) + r"\s*\{([^}]*)\}", css)
    assert match, f"style.css has no `{selector}` rule -- has the UI been restyled?"
    return match.group(1)


def _colour(block: str, prop: str, root: dict[str, str]) -> str:
    """The colour a declaration resolves to, following one level of ``var()``."""
    match = re.search(prop + r"\s*:([^;]*);", block)
    assert match, f"no `{prop}` declaration in `{block.strip()}`"
    value = match.group(1)
    var = _VAR.search(value)
    if var:
        assert var.group(1) in root, f"undefined custom property {var.group(1)}"
        value = root[var.group(1)]
    found = _HEX.findall(value)
    assert len(found) == 1, f"`{prop}: {value.strip()}` is not one plain hex colour"
    return found[0].lower()


def test_the_control_border_stays_visible_against_fill_and_surround() -> None:
    """`input`, `select` and the plain `button` must read as controls, not as text.

    WCAG 2.1 1.4.11 (AA) asks 3:1 for "the visual information required to identify
    a user interface component" -- for these, the 1px border, since the fill only
    beats the bar behind it by 1.11:1 and cannot carry the cue on its own.

    Shipped, that border was `--line` (#2b3542): 1.55:1 against the field fill
    #0b0f14 and 1.39:1 against `.controls`' #151b23, i.e. an edge the eye does not
    reliably separate from the surface. Run and Destroy escaped it only because
    `button.go` and `button.danger-btn` set a border-colour of their own.

    The four surfaces below are every background a bordered control sits on in
    `index.html`: the control bar, the red Destroy bar, the audit panel (the
    "Verify chain" button lives in its `h2`) and the page itself.
    """
    css = STYLE_CSS.read_text(encoding="utf-8")
    root = dict(re.findall(r"(--[\w-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;", _block(css, ":root")))

    controls = _block(css, "input, select, button")
    border = _colour(controls, "border", root)
    surfaces = {
        "the control's own fill": _colour(controls, "background", root),
        ".controls (the control bar)": _colour(_block(css, ".controls"), "background", root),
        ".controls.danger (Destroy bar)": _colour(
            _block(css, ".controls.danger"), "background", root
        ),
        ".panel (audit panel h2)": _colour(_block(css, ".panel"), "background", root),
        "body (the page)": _colour(_block(css, "body"), "background", root),
    }
    thin = {
        f"{where} {surface}: {_contrast(border, surface):.2f}:1"
        for where, surface in surfaces.items()
        if _contrast(border, surface) < 3.0
    }
    assert thin == set(), (
        f"the control border {border} falls under WCAG 1.4.11's 3:1 against "
        + ", ".join(sorted(thin))
    )


def test_the_contrast_arithmetic_rejects_the_hairline_it_replaced() -> None:
    """The check above must be able to fail, so measure the value it was written for.

    #2b3542 on #0b0f14 is the shipped-before pairing; 1.55:1 is the hand-computed
    ratio from the audit. A checker that cannot reproduce the failure it exists to
    prevent is decoration.
    """
    assert _contrast("#2b3542", "#0b0f14") == pytest.approx(1.547, abs=0.005)
    assert _contrast("#2b3542", "#151b23") == pytest.approx(1.394, abs=0.005)
    # Anchors on the ends of the scale: identical colours are 1:1, black on white 21:1.
    assert _contrast("#151b23", "#151b23") == pytest.approx(1.0)
    assert _contrast("#000000", "#ffffff") == pytest.approx(21.0)


# ---------------------------------------------------------------------------
# index.html -- four claims a reviewer hit in a real browser
#
# Same rationale as the stylesheet section above: these are static properties of
# shipped assets, so they belong beside the other asset checks and must run where
# no JS runtime is installed. Each one is a promise the markup makes to the person
# driving the demo, and each was measured wrong in Chrome 151 before the fix.
# ---------------------------------------------------------------------------
INDEX_HTML = REPO_ROOT / "secure_context_pipeline" / "ui" / "index.html"
UI_DIR = INDEX_HTML.parent

#: ``<link rel="icon" ... href="...">``, however the two attributes are ordered.
_ICON = re.compile(r'<link\s+rel="icon"[^>]*\shref="([^"]+)"')
#: The whole ``<details class="guard">`` element, contents included.
_GUARD = re.compile(r"<details class=\"guard\">(.*?)</details>", re.S)
#: The red LIVE REVIEW strip's own text, comments already stripped by the caller.
_STRIP = re.compile(r"<span class=\"tag\">(.*?)</span>", re.S)


def _markup() -> str:
    """``index.html`` with its HTML comments removed.

    Every claim below is about what the page *renders*. This file carries more
    comment than markup -- the favicon note alone is 40 lines -- and those notes
    quote the very strings these tests forbid, in order to say why they are gone.
    Searching the raw file would therefore find the retracted copy in the sentence
    retracting it and pass, which is the check believing its own footnote.
    """
    return re.sub(r"<!--.*?-->", "", INDEX_HTML.read_text(encoding="utf-8"), flags=re.S)


def _flat(fragment: str) -> str:
    """A markup fragment as one line of visible text, tags dropped."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment)).strip()


def test_the_page_icon_is_same_origin_so_the_page_cannot_block_its_own_favicon() -> None:
    """The icon added to silence a 404 was itself blocked, and traded one red line for two.

    The first fix declared the icon as an inline ``data:image/png;base64,...`` URI, on the
    written premise that "a favicon is fetched by the browser process and is not subject
    to" ``img-src 'self'``. Measured against the running page, that is not what the
    browser does: Chrome 151.0.7922.77 driven by playwright-core, cold load of
    127.0.0.1:8075 with nothing clicked, logged TWO console errors, both ``Loading the
    image 'data:image/png;base64,iVBOR...' violates the following Content Security Policy
    directive: "img-src 'self'". The action has been blocked.`` A ``<link rel="icon">``
    fetch is a renderer image fetch and ``img-src`` governs it. The same measurement
    after this change: 0 console errors, and ``/favicon.png`` in the network log with no
    ``/favicon.ico`` request at all.

    So the property is not "an icon is declared" -- the blocked one satisfied that -- it
    is that the icon is reachable UNDER the page's own policy. Same-origin is the whole
    of it: ``_mount_ui`` mounts this directory at ``/``, so a file beside this one is
    served from the origin ``'self'`` already permits, and not one token of the CSP had
    to be spent. Widening ``img-src`` instead would have had to happen twice --
    ``api/constants.py`` sends the same policy as a response header and the stricter of
    the two wins -- and ``test_api.py`` refuses any source that is not ``'none'`` or
    ``'self'``.
    """
    html = INDEX_HTML.read_text(encoding="utf-8")
    icon = _ICON.search(_markup())
    assert icon, "index.html declares no icon, so every load asks for /favicon.ico and 404s"
    href = icon.group(1)

    # A scheme is what takes the fetch outside `'self'`. `data:` is the specific one
    # measured as blocked; the rule is written against the general case so that `blob:`
    # or a CDN cannot arrive later and pass a check aimed only at the last mistake.
    assert not re.match(r"^[a-zA-Z][\w+.-]*:", href), (
        f"the icon URL {href[:60]!r} carries a scheme, so it is not fetched from 'self' "
        f"and the page's own img-src blocks it -- which is the console error back"
    )
    assert not href.startswith("//"), f"protocol-relative icon URL: {href}"

    # Same-origin only helps if the origin actually serves it. This is the untracked-asset
    # failure the inline version was written to avoid, checked instead of feared.
    served = UI_DIR / href
    assert served.is_file(), (
        f"index.html points at {href}, which is not in {UI_DIR.name}/ -- the 404 is back, "
        f"and this is the missing-from-a-clone failure the .gitignore note records"
    )
    assert served.stat().st_size > 0, f"{href} is an empty file"

    # The point of doing it this way: the policy is untouched, so the two copies of it
    # still agree and nothing had to be loosened to show a 16x16 icon.
    csp = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"', html)
    assert csp, "the CSP meta tag is gone"
    directives = {
        part.split()[0]: part.split()[1:]
        for part in (p.strip() for p in csp.group(1).split(";"))
        if part
    }
    assert directives.get("img-src") == ["'self'"], directives.get("img-src")
    assert "data:" not in csp.group(1), "img-src was widened for the icon after all"


def test_the_icon_rule_rejects_every_form_that_was_measured_blocked() -> None:
    """The check above must fail on the markup it was written against, or it proves nothing.

    Three shapes, and the first is the one that actually shipped and actually logged the
    two errors. A checker that passes the inline base64 URI is a checker that would have
    let the defect through, whatever it says about the current file.
    """
    blocked = (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9h",
        "blob:127.0.0.1/8a7c",
        "//example.invalid/favicon.png",
    )
    for href in blocked:
        scheme = bool(re.match(r"^[a-zA-Z][\w+.-]*:", href)) or href.startswith("//")
        assert scheme, f"{href} would be accepted as same-origin by the rule above"
    # And the shipped form must NOT trip it, or the rule is simply "reject everything".
    shipped = _ICON.search(_markup())
    assert shipped and not re.match(r"^[a-zA-Z][\w+.-]*:", shipped.group(1))


def test_creating_a_session_is_gated_because_it_erases_the_session_it_replaces() -> None:
    """The confirmation guard was on the wrong button.

    ``Destroy session...`` is double-gated -- arm, then a Confirm pushed to the far end of
    the bar -- and ``Create session`` was a one-click, hintless, friendly-blue
    ``class="go"`` primary at the top left that erases exactly the same thing:
    ``createSession`` deletes the outgoing session before it reports success. Measured
    against the live API with a session live, one click issued ``200 POST /sessions``
    followed by ``204 DELETE /sessions/<the live one>``, with nothing asked first.

    The gate is markup rather than app.js state, and that is what this file can assert:
    ``<details>`` is a native two step that leaves the id, the listener and ``setBusy``'s
    ``$('btn-session').disabled`` exactly as they were. Measured in Chrome 151 at 1550px
    after the change: from the default state a real mouse click at the commit button's own
    centre issues **0** requests to ``/sessions`` (``elementFromPoint`` there returns
    BODY, ``checkVisibility()`` is false, and ``.focus()`` will not move focus to it), a
    click on the summary opens the disclosure and issues 0, a second click on those same
    pixels issues 0 -- the impatient-double-click hole the destroy gate was re-ordered for
    -- and the commit button sits 207px below and 99px across from the summary's centre.
    """
    markup = _markup()
    guard = _GUARD.search(markup)
    assert guard, "the <details class=\"guard\"> around Create session is gone"
    inside = guard.group(1)

    assert 'id="btn-session"' in inside, (
        "#btn-session is outside the guard, so one click erases the live vault again"
    )
    assert 'id="btn-session"' not in markup.replace(inside, ""), "a second, ungated create button"

    # The summary is the arm, so it has to come first; a button ahead of it in the
    # disclosure would be reachable by the same click that opens it.
    summary = re.search(r"<summary>(.*?)</summary>", inside, re.S)
    assert summary, "the guard has no <summary>, which is the step that arms it"
    assert inside.index("<summary>") < inside.index('id="btn-session"')
    # The SESSION_EXPIRED banner tells a reviewer to press these words by name.
    assert "Create session" in _flat(summary.group(1)), _flat(summary.group(1))

    # The consequence has to be ON the control, between the two movements -- the whole
    # complaint was that the page only explained the erasure afterwards, in the banner.
    body = re.search(r'<div class="guard-body">(.*?)</div>', inside, re.S)
    assert body, "the guard has no body, so the consequence is still unstated before the click"
    sentence = _flat(body.group(1))
    # Printed BEFORE the commit button, not under it: the consequence has to be read on
    # the way to the click, which is the whole difference from the banner that said it
    # afterwards.
    assert inside.index("</span>") < inside.index('id="btn-session"'), (
        "the consequence sentence sits after the commit button, so the click comes first"
    )
    for word in ("REPLACES", "erases", "existed=1", "vault row"):
        assert word in sentence, (word, sentence)

    # Run is the page's repeatable, non-destructive primary and must be the only blue
    # button on it; `.go` on the erasing control is what made the accident inviting.
    session_button = re.search(r"<button[^>]*id=\"btn-session\"[^>]*>", inside)
    assert session_button, inside
    assert "go" not in re.findall(r'class="([^"]*)"', session_button.group(0))[0].split(), (
        "Create session is styled as the friendly primary again"
    )
    assert re.search(r'<button id="btn-run" class="go big">', markup), (
        "Run is no longer the primary -- the blue was moved, not removed"
    )


def test_the_gate_summary_keeps_the_border_the_contrast_rule_measures() -> None:
    """The gate's arm is a ``<summary>``, and a summary is not a ``button``.

    ``test_the_control_border_stays_visible_against_fill_and_surround`` reads the
    ``input, select, button`` rule, so a control that is none of those three inherits none
    of that guarantee -- and this one replaced a real ``<button>``. WCAG 2.1 1.4.11 wants
    3:1 for the edge that says "this is a control": ``--line`` (#2b3542) manages 1.55:1
    against the #0b0f14 fill and 1.39:1 against the #151b23 bar, ``--control-line``
    (#5e6c7c) manages 3.58 and 3.23. This pins the summary to the second one, and pins
    its two surfaces to the pairings that test already computes, so the gate cannot drift
    onto a surround nothing has measured.
    """
    css = STYLE_CSS.read_text(encoding="utf-8")
    root = dict(re.findall(r"(--[\w-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;", _block(css, ":root")))
    summary = _block(css, "details.guard > summary")
    controls = _block(css, "input, select, button")

    assert _colour(summary, "border", root) == _colour(controls, "border", root), (
        "the gate's arm no longer carries the same edge as the controls beside it"
    )
    # Its own fill, and the bar it sits on, are both already-measured surfaces.
    assert _colour(summary, "background", root) == _colour(controls, "background", root)
    assert _contrast(_colour(summary, "border", root), _colour(summary, "background", root)) >= 3.0
    assert _contrast(
        _colour(summary, "border", root), _colour(_block(css, ".controls"), "background", root)
    ) >= 3.0
    # The open panel reuses `--panel`, which is `.controls`' own fill: no new surface.
    assert _colour(_block(css, ".guard-body"), "background", root) == _colour(
        _block(css, ".controls"), "background", root
    ), "the open guard introduced a background nothing has computed a contrast against"


def test_the_live_review_strip_does_not_promise_a_row_the_tail_does_not_show() -> None:
    """"...and the audit tail shows VAULT_DESTROY" is a promise the screen does not keep.

    Driven end to end in Chrome 151 at 1550x950 against 127.0.0.1:8075 -- arm
    legal_brief_large.txt, Run, Destroy session, Confirm -- the row is fetched and
    rendered: 349 rows, and ``1745 VAULT_DESTROY {"existed":1,"source":"api_logout"}`` is
    the last of them. It is also 8068px down a box ``style.css`` caps at 260px, opened at
    ``scrollTop`` 0 with NINE rows visible, so a reviewer who takes the sentence at its
    word reads SESSION_CREATE, DETECT and seven OBFUSCATE and sees no destroy at all. On a
    session past ``AUDIT_LIMIT`` the row is not in the page in the first place.

    The strip therefore has to say what will actually be on screen and how to reach the
    row. Asserted as a rule and not as a snapshot of today's wording: the forbidden thing
    is a bare claim that the tail SHOWS the row, and the required thing is that the copy
    place it at the end and send the reader there.
    """
    strip = _STRIP.search(_markup())
    assert strip, "the LIVE REVIEW strip is gone"
    text = _flat(strip.group(1))

    assert "VAULT_DESTROY" in text, "the strip no longer names the row at all"
    for promise in ("audit tail shows VAULT_DESTROY", "audit tail below shows VAULT_DESTROY"):
        assert promise not in text, (
            f"the strip promises {promise!r}; measured, that row is 8068px below the fold "
            f"of a 260px box that opens showing nine rows"
        )
    assert "LAST row" in text, "nothing tells the reader where in the tail the row is"
    assert "scroll" in text.lower(), "nothing tells the reader the row needs scrolling to"
    assert "349" in text, "the copy does not say how far -- the number is what sets the expectation"


def test_panels_2_and_3_name_the_provider_where_the_payload_is_read() -> None:
    """"Raw LLM response" reads as a live model call, and the only disclosure was far away.

    The header badge reads ``ok - mock/claude-opus-5 - en_core_web_lg`` with no title
    attribute, three quarters of a 1550px page from panel 3. The other tell is ``llm_ms``,
    measured at 0.1-1.0 ms across every run, and the stats legend tells the reader in so
    many words that a timing chip is "not a safety signal". A reviewer who believes a real
    model saw panel 2's contents has drawn the wrong conclusion about what was proved.

    The label is unconditional because it is true in both configurations:
    ``Settings.llm_provider`` defaults to ``"mock"`` and ``anthropic`` is reachable only by
    setting ``SCP_LLM_PROVIDER``, so naming the switch is what keeps a static string
    honest on a page that cannot know. Naming it is the assertion -- a bare "mock provider"
    would be a new false claim the moment somebody sets a key, which is the failure mode
    this whole file exists for.
    """
    markup = _markup()
    for panel, heading in (("p2-provider", "h-p2"), ("p3-provider", "h-p3")):
        span = re.search(r'<span id="' + panel + r'"(.*?)</span>', markup, re.S)
        assert span, f"#{panel} is gone, so that panel names no provider"
        text = _flat(span.group(1))
        assert "mock" in text, (panel, text)
        assert "SCP_LLM_PROVIDER" in text, (
            f"#{panel} states the provider unconditionally; the page cannot know it "
            f"statically, so it has to name the switch that decides it: {text!r}"
        )
        # It sits in the heading, beside the words it qualifies, and NOT inside the span
        # `aria-labelledby` points at -- a region whose name grows a sentence is worse
        # than one with no qualifier at all.
        h2 = re.search(r"<h2>(.*?)</h2>", markup[markup.index('id="' + heading + '"') - 40 :], re.S)
        assert h2 and panel in h2.group(1), f"#{panel} left the heading of #{heading}"
        named = re.search(r'<span id="' + heading + r'">(.*?)</span>', markup, re.S)
        assert named and panel not in named.group(1), (
            f"#{panel} is inside #{heading}, so the region's accessible name now carries it"
        )
