"""Context injector -- payload assembly and the token contract (build doc section 9.5.2).

Assembles ``{system prompt} + {user prompt} + {obfuscated document}`` and exposes
the exact serialized string that will be sent, so the egress gate scans the real
bytes rather than a reconstruction of them.

Rule 4 of the token contract is the co-reference mitigation. It reduces -- it does
not eliminate -- indirect references like "the patient". That is acceptable and
documented: under tokenization the model only ever saw a *token*, so a paraphrase
of it exposes nothing. See README section 13.4 Q2.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

__all__ = [
    "PSEUDONYMIZATION_SYSTEM_PROMPT",
    "TOKENIZATION_SYSTEM_PROMPT",
    "ContextInjector",
    "InjectedPayload",
]

# Verbatim from build doc section 9.5.2 -- do not reword without re-running section 10.7.
#
# NOTE the second example's hash: ``2f4a`` is **four** hex characters, and this
# pipeline only ever emits eight. That is a contradiction inside the build doc
# itself -- section 7 declares ``token_id`` as "8 hex chars" and section 9.7's
# ``TOKEN_RE`` requires ``[0-9a-fA-F]{8}``, while section 9.5.2 prints four and
# calls the block "the exact system prompt". Reproducing all three verbatim is not
# possible, so this is a decision rather than an oversight, and it went the way it
# did for a reason that is not "the spec said so":
#
# The literal is **outside** the token grammar, and that makes it inert:
#
# * ``TOKEN_RE`` does not match it (verified in ``tests/test_egress_gate.py``), so
#   the restorer leaves it alone and the post-restore residual assertion stays
#   silent. A model that echoes the example produces a placeholder that resolves to
#   nothing -- cosmetic, and it carries no original either way.
# * Making it eight hex would be *worse*. It would then match ``TOKEN_RE``, the
#   vault would have no entry for a hash we invented for a prompt, and every run
#   where the model echoed the example would substitute ``[UNRESOLVED_ENTITY]`` and
#   emit a ``VAULT_MISS`` audit event. ``VAULT_MISS`` is supposed to mean "a token
#   resolved to nothing", i.e. a real anomaly worth a compliance look; minting
#   fake ones from our own prompt text would put noise into exactly the log
#   section 9.8 exists to keep trustworthy.
# * It is not a skip-list hole. ``EgressGate._protected_spans`` does not cover it,
#   so pass 2 re-scans it like any other prose -- more scrutiny than a real token
#   gets, not less -- and pass 1 never exempts it, so a vaulted original appearing
#   inside it would still block. The shipped detector finds zero entities in either
#   system prompt, so the exposure costs not even a ``rescan_warnings`` increment.
#
# Recorded in README Deviations. The alternative -- normalise to eight hex and
# accept the spurious ``VAULT_MISS`` -- is a one-line change plus an update to
# ``test_token_contract_is_the_specified_prompt_verbatim``.
TOKENIZATION_SYSTEM_PROMPT = """\
You are assisting with analysis of documents processed by a privacy pipeline.
Certain values are replaced with opaque placeholders like [PHI_NAME_1a2b3c4d].
Some placeholders carry a descriptive suffix after a pipe, e.g.
[PHI_MEDICATION_2f4a|oral-antidiabetic]; the suffix describes the entity's
class and may inform your reasoning.
Rules:
1. Treat each placeholder as the literal name or value of the entity it stands for.
2. Whenever you refer to such an entity, reproduce its placeholder exactly,
   character for character, including the square brackets and any suffix.
3. Never modify, abbreviate, translate, split, or explain placeholders, and never
   invent placeholders that do not appear in the input.
4. When referring to a specific entity, prefer its placeholder over a paraphrase
   such as "the patient" or "the client"."""

# Pseudonymization needs no contract: the fakes read as ordinary values, so there
# is nothing for the model to preserve character-for-character.
PSEUDONYMIZATION_SYSTEM_PROMPT = """\
You are assisting with analysis of documents processed by a privacy pipeline.
Answer the user's question using only the document provided."""


class InjectedPayload(BaseModel):
    """What goes to the provider, plus the exact string the egress gate scans."""

    model_config = ConfigDict(frozen=True)

    system: str
    user: str

    @property
    def serialized(self) -> str:
        """The fully serialized outbound payload: system + user, exactly as sent.

        The gate scans *this*. If the provider call ever stops sending exactly
        these two strings, this property must change with it.
        """
        return f"{self.system}\n\n{self.user}"

    @property
    def char_count(self) -> int:
        return len(self.serialized)


class ContextInjector:
    """Assembles the outbound payload for a given strategy."""

    def __init__(self, *, document_label: str = "DOCUMENT") -> None:
        self._label = document_label
        self._compiled: re.Pattern[str] | None = None

    def system_prompt(self, strategy: str) -> str:
        if strategy == "pseudonymization":
            return PSEUDONYMIZATION_SYSTEM_PROMPT
        return TOKENIZATION_SYSTEM_PROMPT

    def build(
        self,
        *,
        strategy: str,
        user_prompt: str,
        obfuscated_document: str,
    ) -> InjectedPayload:
        """Assemble the payload, fencing the document so it reads as data.

        The fence is what lets the model tell the document apart from the
        instruction, so a document containing prompt-like text is quoted content
        rather than a second instruction. That only holds while the document cannot
        *close* the fence: an uploaded file whose body contains ``</DOCUMENT>``
        would otherwise end the quoted region early and have everything after it
        read as top-level instruction -- the fence would be doing the opposite of
        its job, and doing it invisibly.

        Any fence-shaped tag in the body is therefore neutralised first, so the only
        ``<DOCUMENT>``/``</DOCUMENT>`` in the payload are the ones assembled here.
        The same applies to ``user_prompt``: it is interpolated into the same
        structure and, in a deployment where the prompt and the document come from
        different actors, is no more trusted than the document.

        This is a defence in depth against confusion, not against a determined
        injection -- an LLM has no hard parser and no privilege boundary. The
        confidentiality guarantee does not rest on it: under tokenization the model
        only ever sees placeholders, so a successful injection reaches surrogates,
        not originals. Neutralisation happens *before* the egress gate scans, so the
        gate still scans exactly the bytes that will be sent.
        """
        user = (
            f"{self._neutralize_fence(user_prompt.strip())}\n\n"
            f"<{self._label}>\n"
            f"{self._neutralize_fence(obfuscated_document)}\n"
            f"</{self._label}>"
        )
        return InjectedPayload(system=self.system_prompt(strategy), user=user)

    def _neutralize_fence(self, text: str) -> str:
        """Defuse any opening/closing fence tag inside untrusted text.

        Matched case-insensitively and tolerant of inner whitespace, because the
        model reads ``</document>`` and ``</ DOCUMENT >`` as the same delimiter even
        though ``str.replace`` does not. The replacement keeps the characters
        visible -- nothing is deleted, so no content silently disappears from the
        payload the gate is about to scan -- while no longer being a tag: it can
        never re-form one, since the pattern requires ``<`` immediately followed by
        an optional ``/`` and then the label.
        """
        return self._fence_re.sub(lambda m: f"&lt;{m.group(0)[1:]}", text)

    @property
    def _fence_re(self) -> re.Pattern[str]:
        if self._compiled is None:
            self._compiled = re.compile(rf"</?\s*{re.escape(self._label)}\s*>", re.IGNORECASE)
        return self._compiled
