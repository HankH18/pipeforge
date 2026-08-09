"""Tokenization: every entity becomes an opaque typed token (build doc section 9.3).

    Patient [PII_NAME_1a2b3c4d] was seen on [PHI_DATE_9f01ab23].

This is the conservative mode and the default. The surrogate leaks exactly two
things -- the category and the entity type -- and both are already implied by the
sentence the token sits in. Nothing about the *value* survives: no length, no
shape, no plausible-looking substitute a downstream reader could mistake for real
data. That last property is why this mode, not pseudonymization, is the right
default: a pseudonym that escapes the pipeline still looks like a person.

The cost is fluency. The model sees a symbol where a name was, which reads worse
than a name and occasionally invites the model to comment on the token. The
pipeline's answer is the token contract in the system prompt (build doc section
9.5.2), not a friendlier surrogate.

**Hints are off here by default.** The build doc pins the shipped format to the
literal ``[PHI_NAME_a3f2]`` shape, so a class-annotated token is opt-in via
``StrategyContext.options["hints"] = True``; with hints on, a per-entity
``hint: true`` in ``entities.yaml`` (Tier-3 gazetteer entities) emits
``[PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]``. Entities without ``hint: true``
are unaffected either way -- the registry stays the only place that decides.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from secure_context_pipeline.models import Detection
from secure_context_pipeline.obfuscation.strategies.base import (
    ObfuscationStrategy,
    RestoreMode,
    StrategyContext,
    register_strategy,
)

if TYPE_CHECKING:  # pragma: no cover -- import cycle avoidance only
    from secure_context_pipeline.vault.session_vault import SessionVault

# No module logger here on purpose: this strategy has no branch worth a log line.
# Nothing it does can fail, degrade or retry -- it formats one token and returns.

__all__ = ["HINTS_OPTION", "TokenizationStrategy"]

#: ``StrategyContext.options`` key turning class-annotated tokens on. Default off.
HINTS_OPTION = "hints"


@register_strategy
class TokenizationStrategy(ObfuscationStrategy):
    """``[CATEGORY_ENTITYTYPE_hash8]`` for every entity, in every tier.

    There is no tier dispatch by design: the whole point of this mode is that the
    surrogate carries no value-derived information, and a tier is a statement
    about what the *value* means to the model.
    """

    name = "tokenization"

    #: Every surrogate this class emits comes from ``plain_token``, so the token ID
    #: is inside the string and the restorer needs nothing else. The narrow claim of
    #: the two, and true here for the same reason the class has no tier dispatch.
    restores_via = RestoreMode.TOKEN_ID

    def __init__(self, ctx: StrategyContext) -> None:
        super().__init__(ctx)
        self._hints_enabled = bool(self.option(HINTS_OPTION, False))

    @property
    def hints_enabled(self) -> bool:
        """Whether per-entity ``hint: true`` is honoured. Off unless configured."""
        return self._hints_enabled

    async def make_surrogate(
        self,
        detection: Detection,
        token_id: str,
        vault: SessionVault,
        *,
        session_id: str,
    ) -> str:
        """The plain token. ``vault`` is unused -- nothing here can collide.

        A token embeds the token ID, which the engine has already made unique
        within the session, so unlike a pseudonym it needs no collision guard and
        no vault read.
        """
        hint = self.hint_for(detection) if self._hints_enabled else None
        return self.plain_token(detection, token_id, hint)
