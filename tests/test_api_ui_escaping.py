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

    1. every assignment to ``.innerHTML`` -- the only DOM sink the file uses;
    2. every ``+`` chain that concatenates an HTML *tag* literal, wherever it
       appears (this is what covers the insides of the ``render*`` helpers);
    3. every ``return`` out of a function that builds markup, which catches a
       raw value returned in a chain that happens to carry no tag of its own.

    A term is accepted only if it is a string literal, an ``esc(...)`` call, a
    call to one of this file's own markup builders, a ``map``/``join`` chain, or
    an identifier every assignment to which is itself accepted -- computed as a
    fix-point, which is what admits the ``out``/``html``/``cls`` accumulators
    without admitting ``doc.text``.
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

    for m in re.finditer(r"\.innerHTML\s*=(?!=)", blank):
        check(m.end(), _stmt_end(blank, m.end()), "innerHTML")

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
        "renderStats emits a raw stat key": (
            "'<span class=\"stat\"><i>' + esc(k) + '</i>' + esc(shown) + '</span>'",
            "'<span class=\"stat\"><i>' + k + '</i>' + shown + '</span>'",
        ),
        "renderAudit emits a raw entity type": (
            "'</td><td>' + esc(e.entity_type || '')",
            "'</td><td>' + (e.entity_type || '')",
        ),
        "renderAudit emits a raw serialised detail map": (
            "esc(JSON.stringify(e.detail || {}))",
            "JSON.stringify(e.detail || {})",
        ),
    }
    for name, (before, after) in mutations.items():
        assert source.count(before) == 1, (name, source.count(before))
        problems, _ = audit_escaping(source.replace(before, after))
        assert problems, f"the checker does not notice: {name}"


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
