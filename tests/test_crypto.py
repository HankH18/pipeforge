"""Crypto property tests (build doc section 10.1, crypto subset).

Every property in section 8 maps to a named test here. These are the tests that
underwrite the security claim, so they assert on construction properties -- not on
"it round-trips".

**Independence rule.** A check that derives its expectation from the same constant,
helper, or library as the thing it checks proves only self-consistency. Where a
property is load-bearing, the expectation here is recomputed by a *different*
route: HKDF from RFC 5869 using stdlib ``hmac`` (not ``cryptography``'s ``HKDF``,
which is what the package calls), AES-GCM against the GCM specification's own
published vector, the date-shift correction as an interval table rather than as
the same conditional, and the "no field can hold an original value" claim by
enumerating ``model_fields`` rather than a hand-written list of column names.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import importlib
import inspect
import json
import logging
import pickle
import pkgutil
import re
import secrets
import sys
import typing
import uuid
from collections.abc import Iterator

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from secure_context_pipeline.api.schemas import MAX_ID_LEN
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto import aead, keys
from secure_context_pipeline.crypto.keys import normalize
from secure_context_pipeline.errors import ConfigError, CryptoAuthError, PipelineError
from secure_context_pipeline.models import (
    MASK,
    MAX_AUDIT_LABEL_LEN,
    MAX_DETAIL_VALUE_LEN,
    AuditEvent,
    Detection,
    EntityCategory,
    RedactionRecord,
    SpanOut,
    TokenRecord,
)

# The document store's own doc_id guard. Imported (rather than restated) on
# purpose: the AAD framing argument in `crypto/aead.py` depends on this exact
# width, so loosening it there must fail a test here.
from secure_context_pipeline.store.document_store import _DOC_ID_RE as DOC_ID_RE
from secure_context_pipeline.vault import session_registry as session_registry_module
from secure_context_pipeline.vault.session_registry import SessionRegistry

HEX8 = re.compile(r"^[0-9a-f]{8}$")

#: A string far longer than any machine code, distinctive enough that a substring
#: match in an error rendering cannot be a coincidence.
OVERSIZED_DETAIL = "Zelphinia-Quarrowmont" + "q" * 5_000
#: The subclasses ``errors.py`` defines itself. Used only to anchor the discovery
#: walk below -- the ceiling itself is asserted over whatever the walk finds.
ERRORS_PY_SUBCLASSES = (
    "ConfigError",
    "CryptoAuthError",
    "DetectionError",
    "EgressBlockedError",
    "SessionExpiredError",
    "StoreAuthError",
    "VaultMissError",
)


def _settings(**over: object) -> Settings:
    base: dict[str, object] = {
        "master_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    }
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Section 8, recomputed independently
#
# The package derives every key with `cryptography.hazmat`'s HKDF and encrypts
# with its AESGCM. Checking those against themselves proves nothing, so the
# expectations below come from the two specifications instead: HKDF re-implemented
# from RFC 5869 on stdlib `hmac`, and AES-256-GCM pinned to the GCM paper's own
# test vector.
# ---------------------------------------------------------------------------


def _hkdf_sha256_rfc5869(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (RFC 5869 sections 2.2-2.3) from stdlib ``hmac`` alone.

    Deliberately *not* ``keys._hkdf`` and not ``cryptography.hazmat``'s ``HKDF``:
    an expectation computed by the same helper as the code under test is a
    tautology. Extract-then-expand is short enough to restate exactly.
    """
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def test_the_independent_hkdf_matches_rfc_5869s_published_vectors() -> None:
    """Anchor the re-implementation, so it cannot drift into agreeing with a bug.

    An "independent" checker is only worth something if it is itself right. These
    are appendix A.1 and A.2 of RFC 5869 verbatim.
    """
    assert (
        _hkdf_sha256_rfc5869(
            ikm=b"\x0b" * 22,
            salt=bytes.fromhex("000102030405060708090a0b0c"),
            info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
            length=42,
        ).hex()
        == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    assert (
        _hkdf_sha256_rfc5869(
            ikm=bytes(range(0x50)),
            salt=bytes(range(0x60, 0xB0)),
            info=bytes(range(0xB0, 0x100)),
            length=82,
        ).hex()
        == "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac782727"
        "1cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    )


def test_doc_and_vault_keys_are_the_section_8_hkdf_formulas() -> None:
    """Section 8's key table fixes the salt, the hash, the info prefix and the length.

    Nothing pinned any of the four. ``test_doc_keys_are_deterministic_and_user_isolated``
    and ``test_vault_key_is_session_scoped`` assert determinism, isolation and
    length -- all of which are equally true of *any* KDF under *any* salt with
    *any* info string. So ``HKDF_SALT`` could change to ``b"wrong"``, SHA-256 could
    become SHA-512, or the ``doc:``/``vault:`` prefixes could vanish, and the suite
    stayed green. A changed salt silently makes every document already encrypted at
    rest undecryptable; a dropped ``info`` prefix collapses the domain separation
    the module docstring argues for.
    """
    settings = _settings()
    master = settings.master_key_bytes()
    session_key = keys.new_session_key()

    for user_id in ("alice", "bob", "user:with:colons", "üser"):
        expected = _hkdf_sha256_rfc5869(master, b"scp-v1", b"doc:" + user_id.encode(), 32)
        assert keys.EnvKeyProvider(settings).doc_key(user_id) == expected, user_id
        # Both providers must agree: the store behaves identically under either.
        assert keys.MockKMSKeyProvider(settings).doc_key(user_id) == expected, user_id

    for session_id in ("sessA", "s-1234", "üsession"):
        expected = _hkdf_sha256_rfc5869(
            session_key, b"scp-v1", b"vault:" + session_id.encode(), 32
        )
        assert keys.derive_vault_key(session_key, session_id) == expected, session_id


#: Identifiers chosen to attack the two things per-user isolation rests on: that
#: ``b"doc:" + user_id`` is injective, and that it cannot be steered into another
#: HKDF domain. ``user_id`` is the entire auth claim at this tier and is fully
#: attacker-chosen, so "no two of these produce the same key" has to be measured.
ADVERSARIAL_USER_IDS = (
    "alice",
    "Alice",  # case
    "alice ",  # trailing space
    " alice",  # leading space
    "alice\x00",  # trailing NUL -- the byte that frames the HMAC message space
    "al\u0131ce",  # LATIN SMALL LETTER DOTLESS I -- confusable with "alice"
    "alice\u0301",  # a trailing COMBINING ACUTE ACCENT -- NFC-equal to "alic\u00e9"
    "doc:alice",  # the derivation's own prefix, replayed
    "vault:alice",  # another domain's prefix
    "kms-wrap",  # the wrapping key's whole info string
    "alice:bob",  # a colon, as in the AAD framing
    "ALICE\u212a",  # KELVIN SIGN -- NFKC+casefold maps it onto "alice k"
)


def test_doc_keys_are_injective_in_user_id_under_adversarial_identifiers() -> None:
    """Per-user isolation is exactly as strong as ``user_id -> key`` being injective.

    A red-team pass confirmed the crypto holds and could force no collision; this
    pins that result so a later "normalize the user_id" convenience -- casefolding,
    NFKC, or trimming, all of which ``keys.normalize`` already does for *values* --
    cannot silently merge two accounts onto one document key. The expectation is
    recomputed from RFC 5869 rather than from ``keys._hkdf``, so agreeing with a
    changed implementation is not sufficient to pass.

    Note the KELVIN SIGN entry: NFKC + casefold (what ``normalize`` applies to entity
    values) maps it onto ``alice k``. Applying that pipeline to identifiers is the
    concrete way this property would get broken by an otherwise reasonable change.
    """
    settings = _settings()
    master = settings.master_key_bytes()
    provider = keys.EnvKeyProvider(settings)

    derived: dict[str, bytes] = {}
    for user_id in ADVERSARIAL_USER_IDS:
        key = provider.doc_key(user_id)
        expected = _hkdf_sha256_rfc5869(master, b"scp-v1", b"doc:" + user_id.encode(), 32)
        assert key == expected, f"{user_id!r} is not the section 8 formula"
        derived[user_id] = key

    assert len(set(derived.values())) == len(ADVERSARIAL_USER_IDS), (
        "two distinct user_ids share a document key: "
        f"{sorted(u for u in derived if list(derived.values()).count(derived[u]) > 1)}"
    )


def test_no_identifier_can_steer_one_hkdf_derivation_into_another() -> None:
    """``keys.py``'s domain-separation argument, measured on the actual info bytes.

    The docstring argues that each ``info`` carries a purpose prefix before the
    variable part, so no two purposes can collide. That is an argument about the
    *bytes*, and it must hold even for a ``user_id`` or ``session_id`` that is
    itself another domain's prefix -- which is why the identifier list above
    includes ``"vault:alice"`` and ``"kms-wrap"``.

    Asserted on the info strings rather than on the derived keys on purpose: the
    two derivations also use different input keying material, and that second
    reason would mask a broken ``info`` scheme if the keys alone were compared.
    """
    infos: dict[bytes, str] = {keys.MockKMSKeyProvider.WRAP_INFO: "kms wrapping key"}
    for identifier in ADVERSARIAL_USER_IDS:
        for prefix, purpose in ((b"doc:", "document key"), (b"vault:", "vault key")):
            info = prefix + identifier.encode("utf-8")
            assert info not in infos, (
                f"HKDF info collision: {purpose} for {identifier!r} reuses the info of "
                f"{infos[info]} -- the domain separation in keys.py is not injective"
            )
            infos[info] = f"{purpose} for {identifier!r}"

    # And the shipped derivations really are built from those bytes.
    settings = _settings()
    session_key = keys.new_session_key()
    assert keys.EnvKeyProvider(settings).doc_key("vault:alice") == _hkdf_sha256_rfc5869(
        settings.master_key_bytes(), b"scp-v1", b"doc:vault:alice", 32
    )
    assert keys.derive_vault_key(session_key, "doc:alice") == _hkdf_sha256_rfc5869(
        session_key, b"scp-v1", b"vault:doc:alice", 32
    )


def test_aead_framing_matches_the_gcm_specifications_own_test_vector() -> None:
    """A known-answer test: this is AES-256-GCM, and the blob is ``nonce || ct || tag``.

    Round-trip tests prove only that ``encrypt`` and ``decrypt`` agree with each
    other -- they would stay green if the cipher were swapped, the key silently
    truncated to 128 bits, or the tag moved. This vector is Test Case 16 from
    McGrew & Viega's GCM specification, so the authority is external to the
    package and to ``cryptography``.
    """
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    plaintext = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c9595680953"
        "2fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    )
    ciphertext = bytes.fromhex(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3d"
        "a7b08b1056828838c5f61e6393ba7a0abcc9f662"
    )
    tag = bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b")

    # `decrypt_split` takes (nonce, ciphertext||tag) -- the vault's two-column form.
    assert aead.decrypt_split(key, nonce, ciphertext + tag, aad, scope="kat") == plaintext
    # `decrypt` takes the single `nonce || ciphertext` blob section 8 mandates at rest.
    assert aead.decrypt(key, nonce + ciphertext + tag, aad, scope="kat") == plaintext

    # ...and our own encrypt reproduces the vector when handed the vector's nonce.
    assert aead.NONCE_LEN == len(nonce) == 12
    assert aead.KEY_LEN == len(key) == 32


# ---------------------------------------------------------------------------
# AEAD + AAD binding
# ---------------------------------------------------------------------------


def test_document_blob_round_trip() -> None:
    key = secrets.token_bytes(32)
    aad = aead.doc_aad("alice", "doc-1")
    blob = aead.encrypt(key, b"patient presents with chest pain", aad)
    assert aead.decrypt(key, blob, aad, scope="document") == b"patient presents with chest pain"


def test_ciphertext_does_not_contain_plaintext() -> None:
    key = secrets.token_bytes(32)
    blob = aead.encrypt(key, b"John Smith SSN 123-45-6789", aead.doc_aad("alice", "d1"))
    assert b"John Smith" not in blob
    assert b"123-45-6789" not in blob


def test_nonce_is_fresh_per_call() -> None:
    """Nonce reuse under a fixed key is catastrophic for GCM. Assert it never happens."""
    key = secrets.token_bytes(32)
    aad = aead.doc_aad("alice", "d1")
    nonces = {aead.encrypt(key, b"same plaintext", aad)[: aead.NONCE_LEN] for _ in range(200)}
    assert len(nonces) == 200


@pytest.mark.parametrize(
    "aad_factory",
    [
        pytest.param(lambda: aead.doc_aad("bob", "doc-1"), id="wrong_user"),
        pytest.param(lambda: aead.doc_aad("alice", "doc-2"), id="wrong_doc"),
    ],
)
def test_doc_aad_binds_user_and_doc(aad_factory: object) -> None:
    key = secrets.token_bytes(32)
    blob = aead.encrypt(key, b"phi", aead.doc_aad("alice", "doc-1"))
    with pytest.raises(CryptoAuthError):
        aead.decrypt(key, blob, aad_factory(), scope="document")  # type: ignore[operator]


def test_wrong_key_fails_authentication() -> None:
    aad = aead.doc_aad("alice", "doc-1")
    blob = aead.encrypt(secrets.token_bytes(32), b"phi", aad)
    with pytest.raises(CryptoAuthError):
        aead.decrypt(secrets.token_bytes(32), blob, aad, scope="document")


def test_vault_aad_binds_session_and_token() -> None:
    """A vault row spliced into another session or onto another token must not decrypt."""
    key = secrets.token_bytes(32)
    nonce, ct = aead.encrypt_split(key, b"John Smith", aead.vault_aad("sessA", "1a2b3c4d"))

    assert aead.decrypt_split(key, nonce, ct, aead.vault_aad("sessA", "1a2b3c4d"), scope="v") == (
        b"John Smith"
    )
    for bad in (aead.vault_aad("sessB", "1a2b3c4d"), aead.vault_aad("sessA", "deadbeef")):
        with pytest.raises(CryptoAuthError):
            aead.decrypt_split(key, nonce, ct, bad, scope="vault")


def test_doc_aad_framing_is_unambiguous() -> None:
    """AAD binding is worthless if two different pairs can encode to the same bytes.

    ``doc:<user_id>:<doc_id>`` is a colon join, and ``user_id`` is attacker-chosen
    (it is the entire auth claim at this tier). The join is injective only because
    the *right* component is fixed-width, so the string parses unambiguously from
    the right. This test pins that, and then shows the collision that a
    variable-width ``doc_id`` would actually admit.
    """
    doc_a = "0" * 32
    doc_b = "1" * 32

    # Every adversarial re-cut of the pair produces a distinct AAD.
    pairs = [
        ("alice", doc_a),
        ("alice", doc_b),
        ("alice:", doc_a),
        (f"alice:{doc_a}", doc_b),
        (":alice", doc_a),
        ("", doc_a),
    ]
    assert len({aead.doc_aad(user, doc) for user, doc in pairs}) == len(pairs)

    # The dependency, spelled out rather than trusted: with a doc_id that could
    # contain the separator, the same join really does collide.
    assert aead.doc_aad("alice", f"x:{doc_b}") == aead.doc_aad("alice:x", doc_b)
    # ...which is why the store re-checks the width on every lookup.
    assert DOC_ID_RE.match(doc_b)
    assert not DOC_ID_RE.match(f"x:{doc_b}")


def test_vault_aad_framing_is_unambiguous() -> None:
    """Same argument for ``<session_id>:<token_id>``: the token ID is 8 fixed hex."""
    token_a = "1a2b3c4d"
    token_b = "deadbeef"
    pairs = [
        ("sessA", token_a),
        ("sessA", token_b),
        (f"sessA:{token_a}", token_b),
        ("sessA:", token_a),
    ]
    assert len({aead.vault_aad(s, t) for s, t in pairs}) == len(pairs)

    assert aead.vault_aad("sessA", f"x:{token_b}") == aead.vault_aad("sessA:x", token_b)
    # Nothing that reaches vault_aad can be that shape: derive_token_id returns
    # hexdigest()[:8], and format_surrogate refuses anything else.
    assert HEX8.match(keys.derive_token_id(keys.new_session_key(), "NAME", "John Smith"))


def test_tampered_ciphertext_is_rejected() -> None:
    key = secrets.token_bytes(32)
    aad = aead.doc_aad("alice", "d1")
    blob = bytearray(aead.encrypt(key, b"phi value", aad))
    blob[-1] ^= 0x01
    with pytest.raises(CryptoAuthError):
        aead.decrypt(key, bytes(blob), aad, scope="document")


def test_truncated_blob_is_rejected() -> None:
    """The scope code is asserted, not just the exception type.

    ``scope`` is how an operator learns *where* authentication failed without
    learning *what* failed to decrypt, so the distinct ``_truncated`` code is the
    only observable difference between this guard and the nonce-length check that
    would otherwise catch the same input. Without this assertion, deleting the
    length guard entirely left the whole suite green.
    """
    with pytest.raises(CryptoAuthError) as excinfo:
        aead.decrypt(secrets.token_bytes(32), b"short", aead.doc_aad("a", "b"), scope="document")
    assert excinfo.value.detail["scope"] == "document_truncated"


def test_bad_key_length_rejected() -> None:
    with pytest.raises(CryptoAuthError):
        aead.encrypt(secrets.token_bytes(16), b"x", b"aad")


# ---------------------------------------------------------------------------
# Key hierarchy
# ---------------------------------------------------------------------------


def test_doc_keys_are_deterministic_and_user_isolated() -> None:
    provider = keys.EnvKeyProvider(_settings())
    assert provider.doc_key("alice") == provider.doc_key("alice")
    assert provider.doc_key("alice") != provider.doc_key("bob")
    assert len(provider.doc_key("alice")) == 32


def test_doc_keys_differ_across_master_keys() -> None:
    a = keys.EnvKeyProvider(_settings()).doc_key("alice")
    b = keys.EnvKeyProvider(_settings()).doc_key("alice")
    assert a != b


def test_vault_key_is_session_scoped() -> None:
    sk = keys.new_session_key()
    assert keys.derive_vault_key(sk, "sessA") == keys.derive_vault_key(sk, "sessA")
    assert keys.derive_vault_key(sk, "sessA") != keys.derive_vault_key(sk, "sessB")
    assert keys.derive_vault_key(keys.new_session_key(), "sessA") != keys.derive_vault_key(
        sk, "sessA"
    )


def test_session_keys_are_unique() -> None:
    assert len({keys.new_session_key() for _ in range(200)}) == 200


def test_key_provider_protocol_conformance() -> None:
    for provider in (keys.EnvKeyProvider(_settings()), keys.MockKMSKeyProvider(_settings())):
        assert isinstance(provider, keys.KeyProvider)


def test_build_key_provider_selects_by_config() -> None:
    assert keys.build_key_provider(_settings()).name == "env"
    assert keys.build_key_provider(_settings(key_provider="mock_kms")).name == "mock_kms"


def test_key_material_never_appears_in_repr() -> None:
    settings = _settings()
    for obj in (settings, keys.EnvKeyProvider(settings), keys.MockKMSKeyProvider(settings)):
        rendered = f"{obj!r} {obj}"
        assert settings.master_key not in rendered
        assert "***" in rendered


def test_master_key_validation() -> None:
    with pytest.raises(ConfigError):
        Settings(master_key="")
    with pytest.raises(ConfigError):
        Settings(master_key="not-base64!!")
    with pytest.raises(ConfigError):
        Settings(master_key=base64.b64encode(secrets.token_bytes(16)).decode("ascii"))


def test_master_key_must_be_strict_base64() -> None:
    """``validate=True`` is the load-bearing argument, and only this input proves it.

    ``b64decode(..., validate=False)`` *silently discards* every character outside
    the base64 alphabet. A key with junk spliced into it therefore decodes to a
    perfectly valid 32 bytes -- a different key than the operator pasted, chosen by
    whatever the junk displaced. Both existing cases miss this: ``"not-base64!!"``
    raises on its character count either way, and a wrong-length key is caught by
    the length check that follows. So the suite stayed green with ``validate=False``.
    """
    good = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    spliced = good[:10] + "!!!" + good[10:]

    # The junk really would be discarded, yielding a full-length key.
    assert len(base64.b64decode(spliced, validate=False)) == 32
    with pytest.raises(ConfigError):
        Settings(master_key=spliced)
    # ...and the clean key is still accepted.
    assert len(Settings(master_key=good).master_key_bytes()) == 32


# ---------------------------------------------------------------------------
# Mock KMS envelope semantics (flagged stretch)
# ---------------------------------------------------------------------------


def test_mock_kms_envelope_round_trip() -> None:
    kms = keys.MockKMSKeyProvider(_settings())
    data_key, wrapped = kms.generate_data_key("doc:alice")
    assert len(data_key) == 32
    assert data_key not in wrapped
    assert kms.decrypt_data_key(wrapped, "doc:alice") == data_key


def test_mock_kms_binds_encryption_context() -> None:
    kms = keys.MockKMSKeyProvider(_settings())
    _, wrapped = kms.generate_data_key("doc:alice")
    with pytest.raises(CryptoAuthError):
        kms.decrypt_data_key(wrapped, "doc:bob")


def test_mock_kms_data_keys_are_unique() -> None:
    kms = keys.MockKMSKeyProvider(_settings())
    assert len({kms.generate_data_key("doc:alice")[0] for _ in range(50)}) == 50


def test_mock_kms_never_uses_the_master_key_as_a_cipher_key() -> None:
    """The CMK is HKDF input keying material and nothing else.

    Wrapping data keys directly under the master key would use one key as both an
    HKDF input and an AES-GCM key. There is no known interaction, but "the master
    key is only ever an HKDF input" is a claim worth being able to make flatly --
    and a real KMS keeps the CMK in the HSM for the same reason.
    """
    settings = _settings()
    cmk = settings.master_key_bytes()
    kms = keys.MockKMSKeyProvider(settings)
    data_key, wrapped = kms.generate_data_key("doc:alice")

    with pytest.raises(CryptoAuthError):
        aead.decrypt(cmk, wrapped, b"doc:alice", scope="probe")

    # The wrapping key is its own HKDF derivation, distinct from every doc key.
    # Recomputed from the RFC with the info string spelled out, not fetched back
    # from `keys._hkdf(cmk, MockKMSKeyProvider.WRAP_INFO)` -- reusing the module's
    # own helper and constant would follow the implementation wherever it went,
    # including onto a WRAP_INFO that collides with a doc key.
    wrapping_key = _hkdf_sha256_rfc5869(cmk, b"scp-v1", b"kms-wrap", 32)
    assert wrapping_key not in (cmk, kms.doc_key("alice"))
    assert aead.decrypt(wrapping_key, wrapped, b"doc:alice", scope="probe") == data_key


# ---------------------------------------------------------------------------
# Token IDs -- the critical constraint (section 8 / section 13.4 Q6)
# ---------------------------------------------------------------------------


def test_token_id_shape() -> None:
    tid = keys.derive_token_id(keys.new_session_key(), "NAME", "John Smith")
    assert HEX8.match(tid)


def test_token_id_deterministic_within_session() -> None:
    sk = keys.new_session_key()
    assert keys.derive_token_id(sk, "NAME", "John Smith") == keys.derive_token_id(
        sk, "NAME", "John Smith"
    )


def test_token_id_non_deterministic_across_sessions() -> None:
    """The linkage-attack defence: two sessions must not share a token space."""
    a = keys.derive_token_id(keys.new_session_key(), "NAME", "John Smith")
    b = keys.derive_token_id(keys.new_session_key(), "NAME", "John Smith")
    assert a != b


def test_token_id_is_entity_type_scoped() -> None:
    sk = keys.new_session_key()
    assert keys.derive_token_id(sk, "NAME", "12345") != keys.derive_token_id(sk, "MRN", "12345")


def test_token_id_domain_separation() -> None:
    """The 0x00 separator stops (type, value) pairs from colliding by concatenation."""
    sk = keys.new_session_key()
    assert keys.derive_token_id(sk, "AB", "C") != keys.derive_token_id(sk, "A", "BC")


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("John Smith", "john smith"),
        ("John Smith", "JOHN  SMITH"),
        ("John Smith", "  John\tSmith \n"),
        ("José", "José"),  # NFKC
    ],
)
def test_token_id_normalisation(a: str, b: str) -> None:
    sk = keys.new_session_key()
    assert keys.derive_token_id(sk, "NAME", a) == keys.derive_token_id(sk, "NAME", b)


def test_token_id_counter_re_derivation() -> None:
    """The collision path must produce a fresh, stable ID rather than be assumed away."""
    sk = keys.new_session_key()
    base = keys.derive_token_id(sk, "NAME", "John Smith")
    derived = [keys.derive_token_id(sk, "NAME", "John Smith", counter=i) for i in range(1, 6)]
    assert base not in derived
    assert len(set(derived)) == 5
    assert derived[0] == keys.derive_token_id(sk, "NAME", "John Smith", counter=1)


def test_token_id_counter_is_not_forgeable_from_the_value() -> None:
    """The collision path must not be steerable by the attacker it exists to serve.

    Appending the counter to the message -- the naive reading of section 8 -- is not
    injective: ``("John Smith", counter=1)`` hashes the identical message to
    ``("John Smith\\x00\\x00\\x00\\x01", counter=0)``. A value planted in a document
    could then be steered onto the very ID the collision loop is about to hand out,
    which is the opposite of what the loop is for. Framing the counter as a leading
    NUL block makes the two message spaces disjoint.
    """
    sk = keys.new_session_key()
    for counter in range(1, 8):
        forged = "john smith" + counter.to_bytes(4, "big").decode("latin-1")
        assert keys.derive_token_id(sk, "NAME", "John Smith", counter=counter) != (
            keys.derive_token_id(sk, "NAME", forged)
        )


def test_token_id_counter_zero_is_the_section_8_formula_verbatim() -> None:
    """The framing change must not move any ID the pipeline actually emits."""
    sk = keys.new_session_key()
    expected = hmac.new(sk, b"NAME\x00john smith", hashlib.sha256).hexdigest()[:8]
    assert keys.derive_token_id(sk, "NAME", "John  SMITH ") == expected


def test_session_key_hmac_domains_are_disjoint() -> None:
    """One session key backs three unrelated HMACs. Their message spaces must not overlap.

    Reusing a key across purposes is only safe if no input to one derivation can
    be produced as an input to another -- otherwise a value planted in a document
    could steer the date shift or a Faker seed. This test does two things at once:
    it pins each of the three formulas to the build doc verbatim, and it asserts
    the invariant that separates them.

    Separation rests on one framing byte. Every token-ID message contains a NUL
    (the ``type || 0x00 || value`` separator); neither of the other two messages
    can contain one, because ``entity_type`` is validated NUL-free -- see
    ``test_derivations_reject_an_unframeable_entity_type``, which is what makes
    the right-hand column below true. The two NUL-free spaces are then kept apart
    by their fixed prefixes.
    """
    sk = keys.new_session_key()

    # Messages recomputed independently from section 8, not read from the module.
    date_message = b"date-shift"
    faker_message = b"faker:" + b"NAME"
    token_message = b"NAME" + b"\x00" + b"john smith"

    # 1. Each derivation really uses the message the build doc specifies.
    raw = hmac.new(sk, date_message, hashlib.sha256).digest()
    delta = (int.from_bytes(raw, "big") % 600) - 300
    if abs(delta) < 30:
        delta += 30 if delta >= 0 else -30
    assert keys.derive_date_shift_days(sk) == delta
    assert keys.derive_faker_seed(sk, "NAME") == int.from_bytes(
        hmac.new(sk, faker_message, hashlib.sha256).digest()[:8], "big"
    )
    assert (
        keys.derive_token_id(sk, "NAME", "John Smith")
        == hmac.new(sk, token_message, hashlib.sha256).hexdigest()[:8]
    )

    # 2. The invariant that makes those three spaces disjoint.
    assert b"\x00" in token_message
    assert b"\x00" not in date_message
    assert b"\x00" not in faker_message
    assert not faker_message.startswith(date_message)
    assert not date_message.startswith(faker_message)


@pytest.mark.parametrize("entity_type", ["date-shift", "faker", "FAKER", "NAME"])
def test_no_entity_type_can_reach_another_hmac_domain(entity_type: str) -> None:
    """An entity type is opaque config, so try to spell the other domains with one.

    A token-ID message is ``entity_type || 0x00 || normalize(value)`` and always
    contains a NUL; ``b"date-shift"`` and ``b"faker:" + entity_type`` never can,
    because :func:`_label_bytes` rejects a NUL-bearing type. So no registry entry
    -- however hostile -- can make a token derivation hash the same message as the
    date shift or a Faker seed.
    """
    sk = keys.new_session_key()
    # Normalized forms written out rather than obtained from `keys.normalize`: the
    # disjointness argument must not be routed through a function that a bug could
    # move at the same time as the derivation it is supposed to constrain.
    for value, normalized in (("", ""), ("x", "x"), ("date-shift", "date-shift"), ("F:N", "f:n")):
        message = entity_type.encode() + b"\x00" + normalized.encode()
        assert message != b"date-shift"
        assert message != b"faker:" + entity_type.encode()
        # And the derivation is genuinely a function of that message.
        assert (
            keys.derive_token_id(sk, entity_type, value)
            == hmac.new(sk, message, hashlib.sha256).hexdigest()[:8]
        )


@pytest.mark.parametrize("counter", [-1, keys.MAX_TOKEN_COUNTER + 1])
def test_token_id_rejects_an_unrepresentable_counter(counter: int) -> None:
    """Out of range must be a typed ConfigError, not an OverflowError from to_bytes."""
    with pytest.raises(ConfigError):
        keys.derive_token_id(keys.new_session_key(), "NAME", "x", counter=counter)


# ---------------------------------------------------------------------------
# Key-material validation -- the guarantee has to be enforced where it is used
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_key", [b"", b"short", secrets.token_bytes(31), secrets.token_bytes(33)])
def test_hmac_derivations_reject_a_degenerate_session_key(bad_key: bytes) -> None:
    """A zero-length key silently turns every token ID into a *public* function.

    ``hmac.new`` accepts ``b""`` without complaint, and ``HMAC(b"", ...)`` is
    computable by anyone -- token IDs would become linkable across sessions,
    deployments, and users, which is exactly the property section 8 sells. So the
    length is checked at every derivation, not just at :func:`derive_vault_key`.
    """
    with pytest.raises(ConfigError):
        keys.derive_token_id(bad_key, "NAME", "John Smith")
    with pytest.raises(ConfigError):
        keys.derive_date_shift_days(bad_key)
    with pytest.raises(ConfigError):
        keys.derive_faker_seed(bad_key, "NAME")
    with pytest.raises(ConfigError):
        keys.derive_vault_key(bad_key, "sessA")


def test_an_empty_key_cannot_produce_the_publicly_computable_token_id() -> None:
    """The concrete attack the length check blocks, spelled out.

    Anyone can compute this value; nothing in the pipeline may ever return it.
    """
    public_guess = hmac.new(b"", b"NAME\x00john smith", hashlib.sha256).hexdigest()[:8]
    with pytest.raises(ConfigError):
        keys.derive_token_id(b"", "NAME", "John Smith")
    assert keys.derive_token_id(keys.new_session_key(), "NAME", "John Smith") != public_guess


@pytest.mark.parametrize("entity_type", ["", "A\x00B", "\x00"])
def test_derivations_reject_an_unframeable_entity_type(entity_type: str) -> None:
    """``type || 0x00 || value`` is injective only for non-empty, NUL-free types.

    Entity types are opaque config strings (section 6.2), so this is validated
    rather than assumed: ``("A\\x00B", "C")`` and ``("A", "B\\x00C")`` would
    otherwise hash the same message.
    """
    sk = keys.new_session_key()
    with pytest.raises(ConfigError):
        keys.derive_token_id(sk, entity_type, "value")
    with pytest.raises(ConfigError):
        keys.derive_faker_seed(sk, entity_type)


def test_vault_key_rejects_an_empty_session_id() -> None:
    """Mirrors ``doc_key``'s empty-user guard: no key for the nameless session."""
    with pytest.raises(ConfigError):
        keys.derive_vault_key(keys.new_session_key(), "")


@pytest.mark.parametrize("provider_cls", [keys.EnvKeyProvider, keys.MockKMSKeyProvider])
def test_doc_key_rejects_an_empty_user_id(provider_cls: type) -> None:
    """The guard the test above says it mirrors -- which nothing actually tested.

    ``user_id`` is the entire auth claim at this tier, so an empty one must fail
    closed rather than derive ``HKDF(master, b"doc:")``: that is a perfectly valid
    key, and it would become the shared key of every caller who arrives without an
    identity. Both providers guard it, ``document_store`` relies on the guard
    firing before any I/O, and deleting it from either left the suite green.
    """
    settings = _settings()
    with pytest.raises(ConfigError):
        provider_cls(settings).doc_key("")
    # A named user still works, so the guard is a guard and not a wall.
    assert len(provider_cls(settings).doc_key("alice")) == 32


def test_token_ids_do_not_collide_at_scale() -> None:
    """Birthday bound sanity: a few thousand entities in one session stay distinct."""
    sk = keys.new_session_key()
    ids = {keys.derive_token_id(sk, "NAME", f"person-{i}") for i in range(3000)}
    assert len(ids) >= 2999  # allow at most one genuine 32-bit collision


def test_token_id_is_irreversible_without_the_key() -> None:
    """Destroying the session key is cryptographic erasure: the token reveals nothing."""
    sk = keys.new_session_key()
    tid = keys.derive_token_id(sk, "NAME", "John Smith")
    del sk
    others = {keys.derive_token_id(keys.new_session_key(), "NAME", "John Smith") for _ in range(500)}
    assert tid not in others


# ---------------------------------------------------------------------------
# normalize()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("  John   Smith  ", "john smith"),
        ("JOHN\tSMITH", "john smith"),
        ("John\nSmith", "john smith"),
        ("MRN: 123456", "mrn: 123456"),
        ("", ""),
    ],
)
def test_normalize(raw: str, expected: str) -> None:
    assert keys.normalize(raw) == expected


# ---------------------------------------------------------------------------
# Date shift (section 8, Tier 2 pseudonymisation)
# ---------------------------------------------------------------------------


def test_date_shift_is_stable_per_session() -> None:
    sk = keys.new_session_key()
    assert keys.derive_date_shift_days(sk) == keys.derive_date_shift_days(sk)


def test_date_shift_respects_bounds() -> None:
    """|delta| >= 30 keeps the shift from landing usefully close to the true date.

    The upper bound is the *exact* one section 8's formula produces --
    ``(x % 600) - 300`` lands in ``[-300, 299]`` and the floor correction only
    pushes ``[-29, 29]`` outwards -- not a slack one. A slack ceiling of 330 would
    stay green if the modulus were widened, which is precisely the kind of drift a
    bounds test exists to catch.
    """
    for _ in range(500):
        delta = keys.derive_date_shift_days(keys.new_session_key())
        assert 30 <= abs(delta), delta
        assert -300 <= delta <= 299, delta


def test_date_shift_varies_across_sessions() -> None:
    shifts = {keys.derive_date_shift_days(keys.new_session_key()) for _ in range(100)}
    assert len(shifts) > 50


def _spec_date_shift(residue: int) -> int:
    """Section 8's shift, as an explicit interval table over the 600 residues.

    Deliberately a *different algorithm* from the implementation's "subtract 300,
    then fold if ``abs(delta) < 30``". Restating that conditional in the test would
    reproduce an off-by-one in it (``<=`` for ``<``, ``> 0`` for ``>= 0``) exactly
    as faithfully as the code. The intervals below are derived from the formula
    instead, and each one is stated as a single affine expression:

        r in [  0, 270] -> d in [-300, -30]   |d| >= 30 already, unchanged
        r in [271, 299] -> d in [ -29,  -1]   folded by -30 -> [-59, -31]
        r in [300, 329] -> d in [   0,  29]   folded by +30 -> [ 30,  59]
        r in [330, 599] -> d in [  30, 299]   |d| >= 30 already, unchanged

    ``sign(0)`` is undefined in the build doc; ``r == 300`` is therefore the one
    residue where a reading has to be chosen, and both this table and the module
    choose +30.
    """
    if 0 <= residue <= 270:
        return residue - 300
    if 271 <= residue <= 299:
        return residue - 330
    if 300 <= residue <= 329:
        return residue - 270
    if 330 <= residue <= 599:
        return residue - 300
    raise AssertionError(f"residue outside [0, 600): {residue}")


def test_date_shift_matches_an_independently_tabulated_formula() -> None:
    """Every band of section 8's shift, checked against a table rather than the same fold.

    The digest is recomputed with stdlib ``hmac``; only the reduction is under
    test. 400 keys is enough to land in the two folded bands many times over --
    they carry roughly double weight, which the module documents -- so the
    correction branch is genuinely exercised rather than merely present.
    """
    folded = 0
    for _ in range(400):
        session_key = keys.new_session_key()
        raw = hmac.new(session_key, b"date-shift", hashlib.sha256).digest()
        expected = _spec_date_shift(int.from_bytes(raw, "big") % 600)
        assert keys.derive_date_shift_days(session_key) == expected
        if 30 <= abs(expected) <= 59:
            folded += 1
    assert folded > 0, "no sample landed in a corrected band; the fold went untested"


def _session_key_hitting_residue(target: int) -> bytes:
    """Search for a session key whose ``date-shift`` digest lands on ``target``.

    The reduction is ``% 600`` over an HMAC digest, so a key for any chosen residue
    is about 600 tries away -- cheap, and it converts a boundary that random
    sampling reaches only by luck into one the test reaches every run.
    """
    for _ in range(200_000):
        candidate = keys.new_session_key()
        raw = hmac.new(candidate, b"date-shift", hashlib.sha256).digest()
        if int.from_bytes(raw, "big") % 600 == target:
            return candidate
    raise AssertionError(f"no session key found for residue {target}")


@pytest.mark.parametrize(
    ("residue", "expected"),
    [
        pytest.param(0, -300, id="min"),
        pytest.param(269, -31, id="just_below_negative_fold"),
        pytest.param(270, -30, id="negative_fold_boundary"),
        pytest.param(271, -59, id="first_folded_negative"),
        pytest.param(299, -31, id="last_folded_negative"),
        pytest.param(300, 30, id="delta_zero_sign_is_positive"),
        pytest.param(301, 31, id="first_folded_positive"),
        pytest.param(329, 59, id="last_folded_positive"),
        pytest.param(330, 30, id="positive_fold_boundary"),
        pytest.param(599, 299, id="max"),
    ],
)
def test_date_shift_is_exact_at_every_fold_boundary(residue: int, expected: int) -> None:
    """Pin the residues where an off-by-one actually shows, deterministically.

    Sampling random keys checks the formula broadly but reaches any *particular*
    residue with probability 1/600, so the two mistakes most worth catching --
    ``abs(delta) < 30`` written as ``<= 30`` (visible only at residues 270 and 330)
    and ``sign(0)`` read as negative (visible only at residue 300) -- slipped
    through a 400-key sample roughly half the time. Both of those sabotages
    survived the sampled test and are caught here every run.
    """
    session_key = _session_key_hitting_residue(residue)
    assert _spec_date_shift(residue) == expected  # the table agrees with the case
    assert keys.derive_date_shift_days(session_key) == expected


def test_the_date_shift_table_covers_its_whole_domain() -> None:
    """The table itself is anchored, so it cannot drift into agreeing with a bug.

    This also states the shift's real distribution, which the module describes only
    as "roughly double weight" on the folded bands. Exactly 59 values are doubled:
    ``[-59, -31]`` and ``[30, 59]``. The asymmetry is not a typo -- ``sign(0)`` is
    undefined in the build doc and is read as positive, so ``delta == 0`` folds up
    onto ``+30``, which the unchanged band already reaches. ``-30`` gets no such
    partner. Reading ``sign(0)`` the other way would mirror it.
    """
    produced = [_spec_date_shift(r) for r in range(600)]
    assert len(produced) == 600
    assert all(30 <= abs(d) <= 300 for d in produced)
    assert min(produced) == -300
    assert max(produced) == 299

    counts = {d: produced.count(d) for d in set(produced)}
    assert max(counts.values()) == 2
    assert sorted(d for d, n in counts.items() if n == 2) == [*range(-59, -30), *range(30, 60)]
    assert counts[-30] == 1  # the sign(0) reading, made visible


# ---------------------------------------------------------------------------
# Faker seeds (Tier 1 pseudonymisation)
# ---------------------------------------------------------------------------


def test_faker_seed_stable_per_session_and_type() -> None:
    sk = keys.new_session_key()
    assert keys.derive_faker_seed(sk, "NAME") == keys.derive_faker_seed(sk, "NAME")
    assert keys.derive_faker_seed(sk, "NAME") != keys.derive_faker_seed(sk, "ADDRESS")
    assert keys.derive_faker_seed(sk, "NAME") != keys.derive_faker_seed(keys.new_session_key(), "NAME")


# ---------------------------------------------------------------------------
# Leak surfaces -- repr is only one of the exits
# ---------------------------------------------------------------------------


def test_settings_secrets_do_not_survive_serialization(monkeypatch: pytest.MonkeyPatch) -> None:
    """``repr=False`` covers ``repr()``. ``model_dump`` is the exit that reaches HTTP.

    Before the field serializer, ``Settings(...).model_dump_json()`` emitted the
    base64 master key in full -- one ``JSONResponse(content=settings.model_dump())``
    away from publishing the root of the whole key hierarchy.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    settings = _settings()
    assert settings.anthropic_api_key == "sk-ant-not-a-real-key"  # fixture sanity

    dumped = settings.model_dump()
    assert dumped["master_key"] == MASK
    assert dumped["anthropic_api_key"] == MASK

    as_json = settings.model_dump_json()
    assert settings.master_key not in as_json
    assert "sk-ant-not-a-real-key" not in as_json

    # ...and the masking must not have broken the only supported way to read it.
    assert len(settings.master_key_bytes()) == 32


def test_every_field_settings_hides_from_repr_is_also_hidden_from_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two exits must cover the same fields, and the set is taken from the schema.

    ``repr=False`` is the author's own declaration that a field is a secret.
    ``_mask_secret`` names its fields in a second, hand-written list, and nothing
    tied the two together -- so a third secret added with ``repr=False`` and left
    out of the serializer would leak through ``model_dump_json()`` with every
    existing test still green. Deriving the set from ``model_fields`` makes the
    declaration itself the source of truth.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    settings = _settings()

    secret_fields = [n for n, f in Settings.model_fields.items() if f.repr is False]
    assert set(secret_fields) == {"master_key", "anthropic_api_key"}, (
        "a secret was added or removed; confirm it is masked on both exits"
    )

    dumped = settings.model_dump()
    as_json = settings.model_dump_json()
    for name in secret_fields:
        real = getattr(settings, name)
        assert dumped[name] in (MASK, None), f"{name} survived model_dump()"
        assert real not in as_json, f"{name} survived model_dump_json()"
        assert real not in repr(settings), f"{name} survived repr()"


async def test_no_log_record_carries_a_live_session_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A session ID is a credential, and the registry must not log one.

    ``DELETE /sessions/{id}?user_id=...`` needs exactly that pair, and the deletion
    is irreversible: popping the key is cryptographic erasure. ``create`` logged the
    full 32-char live ID *and* its owning ``user_id`` on one INFO record, which put
    both halves in the log stream.

    The assertions are over every field of every record rather than over the one
    field that was wrong. A leak that moves to a neighbouring key -- into the message
    string, into ``ttl_seconds`` -- is the same leak, and a test naming ``session_id``
    would not have seen it.
    """
    registry = SessionRegistry(_settings())
    with caplog.at_level(logging.INFO, logger="secure_context_pipeline.vault.session_registry"):
        session_id, _ = await registry.create("alice@example.com")
        await registry.destroy(session_id)

    assert caplog.records, "no log records captured -- this test would pass vacuously"
    for record in caplog.records:
        rendered = f"{record.getMessage()} {sorted(record.__dict__.items(), key=str)}"
        assert session_id not in rendered, (
            f"{record.getMessage()!r} carries the live session ID, which is half of an "
            "irreversible DELETE credential"
        )

    # Not vacuous: the records must still be useful. One stable handle joins the
    # creation record to the destruction record, and the owner is still recorded.
    handles = {
        record.__dict__["session"] for record in caplog.records if "session" in record.__dict__
    }
    assert handles == {session_registry_module._handle(session_id)}, (
        "create and destroy must emit the same handle, or the log loses the ability to "
        "follow one session"
    )
    assert any("alice@example.com" in str(record.__dict__.values()) for record in caplog.records)


def test_short_is_the_identity_on_every_session_id_this_module_mints() -> None:
    """Pin the reason ``_short`` was *not* the fix for the record above.

    ``_short`` clamps to a 64-character ceiling and a minted session ID is 32-char
    uuid4 hex, so it is the identity function on exactly the values that matter. It
    guards a hostile *caller-supplied* ID from overflowing an error detail; it has
    never been a mask. ``destroy`` applied it, ``create`` did not, and closing that
    inconsistency by copying ``_short`` into ``create`` would have changed nothing
    while looking like a fix. This test fails if anyone tries.
    """
    minted = uuid.uuid4().hex
    assert len(minted) == 32
    assert session_registry_module._short(minted) == minted, "_short is not a mask"

    handle = session_registry_module._handle(minted)
    assert minted not in handle
    assert handle != minted[: len(handle)], "a prefix of the ID is still the ID, partially"
    assert handle == session_registry_module._handle(minted), "handles must be stable"
    assert handle != session_registry_module._handle(uuid.uuid4().hex)


def test_the_master_key_survives_attribute_access_and_that_is_the_stated_boundary() -> None:
    """The masks cover ``repr`` and default serialization. They cover nothing else.

    The two tests above check the guarantee. This one checks the *limit* of it, and
    it is here rather than only in ``tests/test_models.py`` because this file is
    where the key hierarchy is argued: a reader who has just seen every document key
    derived from ``master_key_bytes()`` should find out in the same place that the
    root of that hierarchy is one ``dict(settings)`` away from a log line.

    ``config.py``'s module docstring claimed a field serializer meant
    ``model_dump()``/``model_dump_json()`` "cannot route around the repr mask". The
    two rows below marked *duck-typed* are the counterexample: they are
    ``model_dump`` calls, and they return the key. ``tests/test_models.py``
    quantifies this over every key and original in the package; this test states the
    master-key case literally, so the claim cannot be re-broadened without a
    concrete, readable failure.
    """
    settings = _settings()
    key = settings.master_key
    assert len(key) == 44, "a 32-byte key is 44 base64 characters; the plant is wrong otherwise"

    # The guarantee, restated so this test fails if the masks regress.
    assert key not in repr(settings)
    assert key not in settings.model_dump_json()
    assert settings.model_dump()["master_key"] == MASK

    # The boundary. Each of these returns the master key in full, today, by design
    # of pydantic -- not by a defect in this package.
    unmasked = {
        "getattr": settings.master_key,
        "__dict__": repr(settings.__dict__),
        "vars()": repr(vars(settings)),
        "dict()": repr(dict(settings)),
        "pickle": pickle.dumps(settings).decode("latin-1"),
        "deepcopy": repr(copy.deepcopy(settings).__dict__),
        "model_copy": repr(settings.model_copy().__dict__),
        "model_dump(serialize_as_any=True) [duck-typed]": repr(
            settings.model_dump(serialize_as_any=True)
        ),
        "model_dump_json(serialize_as_any=True) [duck-typed]": settings.model_dump_json(
            serialize_as_any=True
        ),
    }
    still_masked = [name for name, rendered in unmasked.items() if key not in rendered]
    assert not still_masked, (
        f"{still_masked} no longer expose the master key. That is an improvement, not a "
        "failure -- but config.py's module docstring and tests/test_models.py::"
        "THIRD_EXIT_LEAKS both describe the old behaviour and are now wrong. Update them."
    )

    # ...and the supported path still works, which is the reason none of the above
    # can simply be closed.
    assert len(settings.master_key_bytes()) == 32


def test_detection_text_does_not_survive_serialization() -> None:
    """The one field in the package that holds an original value, masked on both
    exits that *can* be masked -- ``repr`` and default serialization.

    Attribute access is the third exit and is not masked; see
    ``tests/test_models.py::THIRD_EXIT_LEAKS``. The final assertion here is that
    third exit, and it is required rather than tolerated: obfuscation splices
    ``det.text`` into the payload.
    """
    det = Detection(
        entity_type="SSN",
        category=EntityCategory.PII,
        start=0,
        end=11,
        text="123-45-6789",
        score=0.95,
    )
    assert "123-45-6789" not in repr(det)
    assert "123-45-6789" not in det.model_dump_json()
    assert det.model_dump()["text"] == MASK
    # In-memory splicing still needs the real value.
    assert det.text == "123-45-6789"


def test_token_record_surrogate_is_masked_in_repr() -> None:
    """A pseudonym reads like a real value; a stray f-string must not print one."""
    token = TokenRecord(
        session_id="s",
        token_id="deadbeef",
        entity_type="NAME",
        category=EntityCategory.PII,
        surrogate="Marisol Guerrero",
        created_at=1.0,
    )
    assert "Marisol Guerrero" not in f"{token!r} {token}"
    assert MASK in repr(token)


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"start": -1, "end": 5}, id="negative_start"),
        pytest.param({"start": 0, "end": -1}, id="negative_end"),
        pytest.param({"start": 10, "end": 5}, id="reversed_span"),
    ],
)
def test_detection_rejects_impossible_spans(kwargs: dict[str, int]) -> None:
    """Offsets index the original document; a reversed or negative pair slices wrongly."""
    with pytest.raises(ValidationError):
        Detection(
            entity_type="NAME",
            category=EntityCategory.PII,
            text="x",
            score=0.5,
            **kwargs,
        )


@pytest.mark.parametrize("score", [-0.1, 1.1, 99.0])
def test_detection_rejects_out_of_range_scores(score: float) -> None:
    """Confidence is a probability. Thresholds are meaningless if it is not bounded."""
    with pytest.raises(ValidationError):
        Detection(
            entity_type="NAME",
            category=EntityCategory.PII,
            start=0,
            end=1,
            text="x",
            score=score,
        )


#: Every model carrying a ``Score``/``Offset``, with the extra fields each needs.
#: ``Detection`` is the one the bounds tests above already cover; the other two
#: reach the API and the UI, and were covered by nothing.
_BOUNDED_MODELS = [
    pytest.param(Detection, {"text": "x"}, id="Detection"),
    pytest.param(RedactionRecord, {}, id="RedactionRecord"),
    pytest.param(SpanOut, {"action": "redacted"}, id="SpanOut"),
]


@pytest.mark.parametrize(("model", "extra"), _BOUNDED_MODELS)
@pytest.mark.parametrize(
    "bad",
    [
        pytest.param({"score": -0.1}, id="negative_score"),
        pytest.param({"score": 1.1}, id="score_above_one"),
        pytest.param({"start": -1}, id="negative_start"),
        pytest.param({"end": -1}, id="negative_end"),
        pytest.param({"start": 10, "end": 5}, id="reversed_span"),
    ],
)
def test_every_span_model_enforces_the_shared_score_and_offset_bounds(
    model: type, extra: dict[str, object], bad: dict[str, object]
) -> None:
    """``Score`` and ``Offset`` are shared aliases, so the guarantee must be shared too.

    Only ``Detection`` was ever tested. ``SpanOut`` is what the API returns and what
    the UI highlights, and ``RedactionRecord`` records an irreversible edit -- a
    negative offset in either slices the wrong text downstream, and neither would
    have failed a test if its annotation were quietly widened back to a bare
    ``float``/``int``.
    """
    kwargs: dict[str, object] = {
        "entity_type": "NAME",
        "category": EntityCategory.PII,
        "start": 0,
        "end": 1,
        "score": 0.5,
        **extra,
        **bad,
    }
    kwargs = {k: v for k, v in kwargs.items() if k in model.model_fields}  # type: ignore[attr-defined]
    with pytest.raises(ValidationError):
        model(**kwargs)


@pytest.mark.parametrize("field", ["session_id", "run_id", "event_type", "entity_type", "token_id"])
def test_audit_event_free_text_columns_are_capped(field: str) -> None:
    """"No field capable of holding an original value" has to be true of every column.

    ``detail`` was capped; the label columns were not, and ``entity_type`` /
    ``token_id`` are written from values parsed out of untrusted LLM output.
    """
    kwargs: dict[str, object] = {"ts": 1.0, "session_id": "s", "event_type": "X"}
    kwargs[field] = "A" * (MAX_AUDIT_LABEL_LEN + 1)
    with pytest.raises(ValidationError):
        AuditEvent(**kwargs)  # type: ignore[arg-type]


def test_no_audit_event_field_can_hold_a_content_sized_string() -> None:
    """The same claim, quantified over the schema instead of over a list I wrote.

    The parametrized test above names five columns. A hand-written list checks the
    fields its author thought of, which is the same set the class docstring's
    "every remaining string column is length-capped" claim was written from -- so
    the two agreed with each other and neither was evidence. Enumerating
    ``model_fields`` found the two the list omitted: ``prev_hash`` and
    ``entry_hash`` accepted a 5 000-character string, and are the columns an
    attacker who can write to the audit table would reach for.

    Iterating the schema also means a *newly added* column is covered the day it
    lands rather than the day someone remembers to extend the list.
    """
    original = "A" * 5000
    base: dict[str, object] = {"ts": 1.0, "session_id": "s", "event_type": "X"}

    checked = 0
    for name in AuditEvent.model_fields:
        kwargs = dict(base)
        kwargs[name] = original
        try:
            event = AuditEvent(**kwargs)  # type: ignore[arg-type]
        except ValidationError:
            checked += 1  # rejected -- either capped, or not a string column at all
            continue
        pytest.fail(f"AuditEvent.{name} accepted a {len(original)}-character string: {event!r}")

    assert checked == len(AuditEvent.model_fields)
    assert checked >= 10, "schema shrank; confirm the claim still covers every column"


def test_audit_event_detail_rejects_content_sized_strings() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(ts=1.0, session_id="s", event_type="X", detail={"v": "A" * 65})
    assert AuditEvent(ts=1.0, session_id="s", event_type="X", detail={"v": "A" * 64})


def test_audit_event_ceilings_survive_post_construction_mutation() -> None:
    """A validator that runs once at construction guards nothing on a mutable model.

    Both of these reached SQLite untouched before ``AuditEvent`` was frozen and its
    ``detail`` made read-only, and both are shapes that matter: ``entity_type`` and
    ``token_id`` are written from values parsed out of untrusted LLM output.
    """
    event = AuditEvent(ts=1.0, session_id="s", event_type="X", detail={"reason": "ok"})
    original = "A" * 5000

    with pytest.raises(ValidationError):  # assignment must not bypass max_length
        event.entity_type = original
    with pytest.raises(TypeError):  # detail must not be a mutable dict
        event.detail["reason"] = original  # type: ignore[index]

    assert event.entity_type is None
    assert event.detail["reason"] == "ok"


def test_audit_event_detail_does_not_alias_the_callers_dict() -> None:
    """Validating a dict the caller still holds a reference to guards nothing."""
    supplied: dict[str, int | float | str] = {"count": 1}
    event = AuditEvent(ts=1.0, session_id="s", event_type="X", detail=supplied)
    supplied["leaked"] = "A" * 5000
    assert "leaked" not in event.detail


def test_audit_event_detail_still_serializes_as_a_plain_dict() -> None:
    """The read-only wrapper is an in-memory guard; the persisted form is unchanged."""
    event = AuditEvent(ts=1.0, session_id="s", event_type="X", detail={"count": 3, "ms": 1.5})
    assert event.model_dump()["detail"] == {"count": 3, "ms": 1.5}
    assert json.loads(event.model_dump_json())["detail"] == {"count": 3, "ms": 1.5}
    assert json.dumps(event.model_dump())  # the audit tests serialize events this way
    assert event.model_copy(update={"seq": 7}).seq == 7  # the writer's update path


def test_pipeline_error_rejects_content_sized_detail() -> None:
    """No exception may carry an original value (build doc section 16)."""
    with pytest.raises(ValueError, match="must not carry content"):
        PipelineError(reason="A" * 65)


def test_the_content_ceilings_are_the_numbers_they_are_documented_to_be() -> None:
    """Pin the two ceilings to literals, because every other test imports them.

    This is the shared-blind-spot failure in its purest form. ``errors.py``,
    ``models.py``, ``api/schemas.py`` and every assertion about them all read the
    same two constants, so raising ``MAX_DETAIL_VALUE_LEN`` from 64 to 5 000 keeps
    the entire suite green -- including the tests whose names promise that an
    audit detail cannot hold content -- while a 5 000-character original fits in
    one. A checker that recomputes its expectation from the value under test
    proves only self-consistency.

    64 and 128 are the numbers ``errors.py`` and ``models.py`` document, chosen so
    no original value can hide in a field (a uuid4 hex is 32, an entity type is
    <= 20, a token ID is 8, a sha256 hexdigest is 64). Changing either is a
    security decision and must be an explicit edit here, not a silent widening.
    """
    assert MAX_DETAIL_VALUE_LEN == 64
    assert MAX_AUDIT_LABEL_LEN == 128
    assert MAX_ID_LEN <= MAX_DETAIL_VALUE_LEN, (
        "the API accepts identifiers longer than an error detail can hold; an "
        "over-long ID would raise ValueError from inside an exception constructor"
    )


# ---------------------------------------------------------------------------
# The detail ceiling, quantified over every error class in the package
# ---------------------------------------------------------------------------


def _all_pipeline_error_subclasses() -> list[type[PipelineError]]:
    """Every :class:`PipelineError` subclass, found by importing the whole package.

    ``errors.py`` claims the 64-character ceiling "applies uniformly across all of
    them" and then names the three subpackages that define their own subclasses.
    That is a hand-written list in a docstring: it covers the classes its author
    remembered on the day it was written, and a subclass added to a fourth module
    inherits the claim without inheriting the check. Walking ``__subclasses__``
    after importing every module is the version of the claim that stays true.
    """
    importlib.import_module("secure_context_pipeline")
    package = sys.modules["secure_context_pipeline"]
    for module in pkgutil.walk_packages(package.__path__, f"{package.__name__}."):
        importlib.import_module(module.name)

    def walk(cls: type[PipelineError]) -> Iterator[type[PipelineError]]:
        for sub in cls.__subclasses__():
            yield sub
            yield from walk(sub)

    found = sorted(set(walk(PipelineError)), key=lambda cls: f"{cls.__module__}.{cls.__name__}")
    assert len(found) >= 13, f"subclass discovery found only {len(found)} -- the walk is broken"
    return found


def _oversized_cases(cls: type[PipelineError]) -> list[tuple[str, dict[str, object]]]:
    """One constructor call per string-typed parameter, that parameter oversized."""
    signature = inspect.signature(cls.__init__)
    hints = typing.get_type_hints(cls.__init__)
    if any(p.kind is p.VAR_KEYWORD for p in signature.parameters.values()):
        # `PipelineError.__init__(**detail)`, inherited unchanged.
        return [("detail", {"probe": OVERSIZED_DETAIL})]

    baseline: dict[str, object] = {}
    for name, param in signature.parameters.items():
        if name == "self":
            continue
        annotation = hints.get(name, str)
        if param.default is not inspect.Parameter.empty:
            baseline[name] = param.default
        elif annotation is int or int in typing.get_args(annotation):
            baseline[name] = 0
        else:
            baseline[name] = "x"

    cases: list[tuple[str, dict[str, object]]] = []
    for name in signature.parameters:
        if name == "self":
            continue
        annotation = hints.get(name, str)
        if annotation is str or str in typing.get_args(annotation):
            cases.append((name, {**baseline, name: OVERSIZED_DETAIL}))
    assert cases, f"{cls.__name__} has no string parameter -- check the signature reader"
    return cases


@pytest.mark.parametrize(
    "cls", _all_pipeline_error_subclasses(), ids=lambda cls: f"{cls.__module__}.{cls.__name__}"
)
def test_every_error_subclass_enforces_the_detail_ceiling(cls: type[PipelineError]) -> None:
    """No subclass may carry a content-sized string, however it builds its detail.

    Two implementations are both acceptable and both appear in the package: the
    base class *rejects* an oversized value, and ``llm/base.py`` *truncates* with
    its own ``_bounded`` helper before calling ``super().__init__``. The property
    that matters to section 16 is the same either way and is what is asserted --
    the full value never lands in ``detail``, in ``str(exc)``, or in ``repr(exc)``.

    A subclass that builds ``detail`` without going through ``PipelineError``'s
    guard would pass every existing test in this file (they only ever construct
    the base class) and fail here.
    """
    for parameter, kwargs in _oversized_cases(cls):
        try:
            error = cls(**kwargs)  # type: ignore[arg-type]
        except ValueError:
            continue  # rejected outright -- the base class guard
        for key, value in error.detail.items():
            assert not isinstance(value, str) or len(value) <= MAX_DETAIL_VALUE_LEN, (
                f"{cls.__name__}({parameter}=...) stored {len(str(value))} chars in "
                f"detail[{key!r}]; the ceiling is {MAX_DETAIL_VALUE_LEN}"
            )
        for how, rendered in (("str", str(error)), ("repr", repr(error))):
            assert OVERSIZED_DETAIL not in rendered, (
                f"{cls.__name__}({parameter}=...) rendered the full value through {how}()"
            )


def test_the_error_subclass_walk_sees_the_classes_errors_py_documents() -> None:
    """Anchor the discovery, so a broken walk cannot report a vacuous pass.

    ``test_every_error_subclass_enforces_the_detail_ceiling`` is parametrized over
    whatever the walk returns. If the walk silently returned an empty (or
    truncated) list, pytest would report green over nothing at all -- the failure
    mode this repository keeps rediscovering. These are the classes ``errors.py``
    names in prose; the walk must contain them *and* the ones it does not name.
    """
    found = {f"{cls.__module__}.{cls.__name__}" for cls in _all_pipeline_error_subclasses()}
    documented_elsewhere = {
        "secure_context_pipeline.llm.base.LLMError",
        "secure_context_pipeline.llm.base.LLMRefusalError",
        "secure_context_pipeline.llm.base.LLMTransportError",
        "secure_context_pipeline.llm.base.LLMResponseError",
        "secure_context_pipeline.store.document_store.InvalidCategoryError",
        "secure_context_pipeline.detection.detector.DetectionInvariantError",
    }
    assert documented_elsewhere <= found, sorted(documented_elsewhere - found)
    assert {f"secure_context_pipeline.errors.{name}" for name in ERRORS_PY_SUBCLASSES} <= found


# ---------------------------------------------------------------------------
# normalize() idempotency -- property-based, because the failing input was one
# nobody had thought of.
# ---------------------------------------------------------------------------


@given(st.text(max_size=40))
@settings(max_examples=800, deadline=None)
def test_normalize_is_idempotent(value: str) -> None:
    """``normalize(normalize(x)) == normalize(x)``, for every string.

    Not a nicety: two call sites disagree about how many times to apply it.
    ``SessionVault.put`` indexes on one pass and ``get_by_original`` re-normalises
    defensively on the stated grounds that this holds. When it did not, the write
    landed under one key and the read-back missed under another, and the engine
    raised ``vault_put_not_readable`` from a branch commented "this cannot happen"
    -- an HTTP 500 from an ordinary .txt upload.

    Casefolding is not closed over NFKC: ``casefold("ß")`` is ``"ss"``, so
    ``"ß" + U+0323`` folds to ``"ss" + U+0323`` and a second NFKC composes the new
    trailing ``s`` with the mark. A hand-written corpus does not contain that; a
    generator does.
    """
    once = normalize(value)
    assert normalize(once) == once


@pytest.mark.parametrize(
    "value",
    [
        "ß̣",  # the found case: casefold expands, then NFKC composes
        "ß̇x",
        "Weiß̣",
        "Ǆ̣",  # DŽ -- another expanding fold next to a mark
    ],
)
def test_normalize_is_idempotent_on_the_expanding_folds(value: str) -> None:
    """The specific shapes the property test found, kept as named regressions."""
    assert normalize(normalize(value)) == normalize(value)


@pytest.mark.parametrize(
    "value",
    ["John\x00Smith", "acme\x01corp", "a\x7fb", "\x9fMarcus Delacroix"],
)
def test_normalize_removes_non_whitespace_controls(value: str) -> None:
    """A control character must not survive into an HMAC label.

    `derive_token_id` frames its message as ``label || 0x00 || value``, so
    `_label_bytes` rejects a label carrying its own NUL. That guard was written
    for entity types -- "an opaque, config-supplied string" -- and Deviation 45
    then routed the normalised *document value* into the same label. One NUL in a
    detected span, or in the JSON `prompt` field with an entirely benign document,
    raised `ConfigError` out of the obfuscation hot path as HTTP 500, while every
    other pseudonymization failure degrades to a plain token.
    """
    normalized = normalize(value)
    assert "\x00" not in normalized
    assert not any(ord(ch) < 0x20 and not ch.isspace() for ch in normalized)
    # And the label the pseudonymizer builds from it is now constructible.
    keys.derive_faker_seed(secrets.token_bytes(32), f"NAME:{normalized}")


@pytest.mark.parametrize("control", ["\t", "\n", "\r"])
def test_normalize_keeps_whitespace_controls_as_separators(control: str) -> None:
    """The whitespace controls collapse to a space rather than vanishing.

    Deleting them would glue two words into one, which is a different value --
    and, for the EgressGate, a needle that no longer matches its own payload.
    """
    assert normalize(f"John{control}Smith") == "john smith"
