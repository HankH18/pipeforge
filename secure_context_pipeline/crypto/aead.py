"""AES-256-GCM helpers with mandatory AAD binding (build doc section 8).

Only ``cryptography``'s ``AESGCM`` is used -- no primitive is ever hand-rolled.

Every call takes AAD, and AAD is never optional. That is what makes the
isolation guarantees cryptographic rather than procedural:

* documents bind to ``doc:<user_id>:<doc_id>``, so a blob decrypted with another
  user's derived key fails authentication rather than returning plaintext;
* vault entries bind to ``<session_id>:<token_id>``, so a row copied into
  another session -- or onto another token ID -- fails authentication even if an
  attacker has write access to the database.

**Why colon-joining two identifiers is safe here.** AAD binding is only worth
anything if the encoding is injective: if two distinct ``(user_id, doc_id)`` pairs
could produce the same AAD bytes, a ciphertext would authenticate under a binding
it was not created for. ``a + b":" + b`` is *not* injective in general --
``("alice:x", "1")`` and ``("alice", "x:1")`` collide -- and ``user_id`` is
attacker-chosen (it is the entire auth claim at this tier), so this needs an
argument rather than a shrug.

The argument is that the **right-hand** component of each pair is fixed-width and
validated at its own boundary, which makes the join parseable from the right:

* ``doc_id`` is 32 lowercase hex (``uuid4().hex``), re-checked on every lookup by
  ``document_store._DOC_ID_RE``;
* ``token_id`` is 8 lowercase hex -- all ``derive_token_id`` can return, and all
  ``surrogates.format_surrogate`` will emit.

So the last 32 (or 8) characters are unambiguously the right component and
everything before the final separator is unambiguously the left one, whatever the
left component contains. That property is asserted in ``tests/test_crypto.py``
(``test_doc_aad_framing_is_unambiguous``,
``test_vault_aad_framing_is_unambiguous``) so that widening either identifier to a
variable-width form fails a test rather than quietly weakening the binding.

A production build would not lean on a caller's format at all: it would
length-prefix each component (or use a structured AAD) so injectivity is a
property of the encoder. The build doc specifies these exact AAD bytes, so the
constraint is documented and tested here instead of the format being changed.
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secure_context_pipeline.errors import CryptoAuthError

__all__ = [
    "KEY_LEN",
    "NONCE_LEN",
    "decrypt",
    "decrypt_split",
    "doc_aad",
    "encrypt",
    "encrypt_split",
    "vault_aad",
]

NONCE_LEN = 12
KEY_LEN = 32


def _check_key(key: bytes) -> None:
    """Refuse anything that is not a 256-bit key.

    ``AESGCM`` would happily accept a 16- or 24-byte key and silently downgrade
    the whole design's "AES-256" claim. Reported as a :class:`CryptoAuthError`
    rather than a config error on purpose: callers already treat that as
    "produced no plaintext", so an impossible key length fails closed on the read
    path instead of being mapped onto some other outcome. Every key reaching here
    is HKDF output or ``secrets.token_bytes(32)``, so it is a guard, not a
    routine path.
    """
    if len(key) != KEY_LEN:
        raise CryptoAuthError(scope=f"bad_key_length_{len(key)}")


def encrypt_split(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt to a ``(nonce, ciphertext)`` pair, for callers with two columns.

    A fresh 12-byte nonce is drawn per call from ``secrets``; nonces are never
    reused or derived.
    """
    _check_key(key)
    nonce = secrets.token_bytes(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_split(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, *, scope: str) -> bytes:
    """Decrypt a ``(nonce, ciphertext)`` pair. Raises :class:`CryptoAuthError` on any failure.

    ``scope`` is a short machine code naming the call site (e.g. ``"vault"``,
    ``"document"``); it lands in the error detail so operators can tell *where*
    authentication failed without learning *what* failed to decrypt.
    """
    _check_key(key)
    if len(nonce) != NONCE_LEN:
        raise CryptoAuthError(scope=f"{scope}_bad_nonce")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoAuthError(scope=scope) from exc


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt to a single ``nonce || ciphertext`` blob, for file-backed callers."""
    nonce, ciphertext = encrypt_split(key, plaintext, aad)
    return nonce + ciphertext


def decrypt(key: bytes, blob: bytes, aad: bytes, *, scope: str) -> bytes:
    """Decrypt a ``nonce || ciphertext`` blob produced by :func:`encrypt`."""
    if len(blob) < NONCE_LEN:
        raise CryptoAuthError(scope=f"{scope}_truncated")
    return decrypt_split(key, blob[:NONCE_LEN], blob[NONCE_LEN:], aad, scope=scope)


def doc_aad(user_id: str, doc_id: str) -> bytes:
    """AAD for a document blob: ``doc:<user_id>:<doc_id>``.

    Injective because ``doc_id`` is fixed-width 32-hex; see the module docstring.
    """
    return b"doc:" + user_id.encode("utf-8") + b":" + doc_id.encode("utf-8")


def vault_aad(session_id: str, token_id: str) -> bytes:
    """AAD for a vault entry: ``<session_id>:<token_id>``.

    Injective because ``token_id`` is fixed-width 8-hex; see the module docstring.
    """
    return session_id.encode("utf-8") + b":" + token_id.encode("utf-8")
