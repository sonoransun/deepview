"""VeraCrypt / TrueCrypt cipher-cascade registry.

Each cascade knows how to consume a derived 64-byte *header_key* (in
practice ``header_enc_key || header_tweak_key``) and the 448-byte
encrypted header blob and produce the decrypted plaintext header. The
cascades exposed here enumerate the cipher order VeraCrypt's source
uses in ``Common/Crypto.c``: the outermost cipher in a cascade is the
*first* listed (data is encrypted first-to-last on write, so decrypt
last-to-first on read).

Only AES-XTS is decrypted with a real :mod:`cryptography` primitive —
Serpent and Twofish have no stable pure-Python or ``cryptography``
backend, so we expose their descriptors (for detection / metadata) but
raise :class:`NotImplementedError` on ``decrypt_header`` when they are
selected. Wiring a third-party backend later is a local change here.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


_HEADER_CIPHERTEXT_LEN = 448


def _aes_xts_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt *ciphertext* as a single 448-byte XTS unit with sector 0.

    VeraCrypt derives a 64-byte buffer = ``aes_key (32) || tweak_key (32)``
    and encrypts the header as if it were a single sector 0 payload.
    """
    if len(key) < 64:
        raise ValueError(f"AES-XTS header key must be >= 64 bytes, got {len(key)}")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    tweak = (0).to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key[:64]), modes.XTS(tweak))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _aes_xts_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Inverse of :func:`_aes_xts_decrypt`. Used by test fixtures."""
    if len(key) < 64:
        raise ValueError(f"AES-XTS header key must be >= 64 bytes, got {len(key)}")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    tweak = (0).to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key[:64]), modes.XTS(tweak))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def _unwired(cipher_list: tuple[str, ...]) -> Callable[[bytes, bytes], bytes]:
    def _raise(_key: bytes, _ct: bytes) -> bytes:
        raise NotImplementedError(
            f"cascade {'-'.join(cipher_list)} needs a Serpent/Twofish backend "
            "— install a compatible primitive or declare the cascade "
            "detect-only"
        )

    return _raise


@dataclass(frozen=True)
class CipherCascade:
    """Descriptor for a VeraCrypt cipher cascade.

    Attributes
    ----------
    name:
        Human / CLI name, e.g. ``"aes-xts"`` or ``"aes-twofish-xts"``.
    ciphers:
        Ciphers in *encryption* order — the outermost layer is
        ``ciphers[0]``. For decryption, callers reverse this.
    key_bytes:
        Total master key material in bytes across the cascade (every
        cipher consumes 32 bytes of primary key + 32 bytes of tweak).
    decrypt_header:
        Takes ``(header_key, 448-byte-ciphertext)`` and returns the
        plaintext header. See module docstring for the XTS specifics.
    encrypt_header:
        Inverse for tests — raises for unwired cascades.
    first_cipher_name:
        Name fed into :class:`DecryptedVolumeLayer` for the outermost
        cipher (today always the first entry).
    """

    name: str
    ciphers: tuple[str, ...]
    key_bytes: int
    decrypt_header: Callable[[bytes, bytes], bytes]
    encrypt_header: Callable[[bytes, bytes], bytes]

    @property
    def first_cipher_name(self) -> str:
        return self.ciphers[0]


_AES_XTS = CipherCascade(
    name="aes-xts",
    ciphers=("aes",),
    key_bytes=64,
    decrypt_header=_aes_xts_decrypt,
    encrypt_header=_aes_xts_encrypt,
)

_SERPENT_XTS = CipherCascade(
    name="serpent-xts",
    ciphers=("serpent",),
    key_bytes=64,
    decrypt_header=_unwired(("serpent",)),
    encrypt_header=_unwired(("serpent",)),
)

_TWOFISH_XTS = CipherCascade(
    name="twofish-xts",
    ciphers=("twofish",),
    key_bytes=64,
    decrypt_header=_unwired(("twofish",)),
    encrypt_header=_unwired(("twofish",)),
)

_AES_TWOFISH = CipherCascade(
    name="aes-twofish-xts",
    ciphers=("aes", "twofish"),
    key_bytes=128,
    decrypt_header=_unwired(("aes", "twofish")),
    encrypt_header=_unwired(("aes", "twofish")),
)

_AES_TWOFISH_SERPENT = CipherCascade(
    name="aes-twofish-serpent-xts",
    ciphers=("aes", "twofish", "serpent"),
    key_bytes=192,
    decrypt_header=_unwired(("aes", "twofish", "serpent")),
    encrypt_header=_unwired(("aes", "twofish", "serpent")),
)

_SERPENT_AES = CipherCascade(
    name="serpent-aes-xts",
    ciphers=("serpent", "aes"),
    key_bytes=128,
    decrypt_header=_unwired(("serpent", "aes")),
    encrypt_header=_unwired(("serpent", "aes")),
)

_SERPENT_TWOFISH_AES = CipherCascade(
    name="serpent-twofish-aes-xts",
    ciphers=("serpent", "twofish", "aes"),
    key_bytes=192,
    decrypt_header=_unwired(("serpent", "twofish", "aes")),
    encrypt_header=_unwired(("serpent", "twofish", "aes")),
)

_TWOFISH_SERPENT = CipherCascade(
    name="twofish-serpent-xts",
    ciphers=("twofish", "serpent"),
    key_bytes=128,
    decrypt_header=_unwired(("twofish", "serpent")),
    encrypt_header=_unwired(("twofish", "serpent")),
)


# Ordering matters — AES first because it is the overwhelming default
# and the only cascade with a real decrypt path today. The rest are
# declared for completeness so `detect()` can enumerate them if a
# future backend plugs in.
ALL_CASCADES: tuple[CipherCascade, ...] = (
    _AES_XTS,
    _SERPENT_XTS,
    _TWOFISH_XTS,
    _AES_TWOFISH,
    _SERPENT_AES,
    _TWOFISH_SERPENT,
    _AES_TWOFISH_SERPENT,
    _SERPENT_TWOFISH_AES,
)


def wired_cascades() -> tuple[CipherCascade, ...]:
    """Return only cascades whose ``decrypt_header`` is actually wired."""
    wired: list[CipherCascade] = []
    for cascade in ALL_CASCADES:
        if cascade.decrypt_header is _aes_xts_decrypt:
            wired.append(cascade)
    return tuple(wired)


def cascade_by_name(name: str) -> CipherCascade | None:
    for c in ALL_CASCADES:
        if c.name == name:
            return c
    return None


__all__ = [
    "CipherCascade",
    "ALL_CASCADES",
    "wired_cascades",
    "cascade_by_name",
]
