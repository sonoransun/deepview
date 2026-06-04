"""Known-Answer-Tests (KAT) for the container cipher modes.

Covers the four block-cipher modes wired into
:class:`~deepview.storage.containers.layer.DecryptedVolumeLayer`
(XTS-AES, CBC-ESSIV, CBC-plain64, CTR-AES) and the AES-XTS header
cascade in :mod:`deepview.storage.containers._cipher_cascades`.

Two complementary strategies are used:

* **Round-trip** — encrypt a deterministic plaintext with
  :mod:`cryptography` (itself a NIST-validated backend), feed the
  ciphertext through our decrypt path, and assert we recover the
  original bytes. This validates the cipher wiring end to end.
* **Frozen IV/tweak vectors** — a pure round-trip cannot catch a
  *symmetric* IV bug (one where encrypt and decrypt agree on the same
  wrong IV). So we additionally pin the exact, non-obvious IV
  derivation that matters most — CBC-ESSIV's ``IV = AES-ECB(SHA256(key),
  sector_LE16)`` — against a frozen expected value, and confirm a
  wrong IV fails to decrypt.

All tests are skipped on a core install without the ``containers``
extra (no ``cryptography``), keeping CI green there.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.ciphers import (  # noqa: E402
    Cipher,
    algorithms,
    modes,
)

from deepview.core.types import LayerMetadata, ScanResult  # noqa: E402
from deepview.interfaces.layer import DataLayer  # noqa: E402
from deepview.storage.containers._cipher_cascades import (  # noqa: E402
    _aes_xts_decrypt,
    _aes_xts_encrypt,
    cascade_by_name,
    wired_cascades,
)
from deepview.storage.containers.layer import DecryptedVolumeLayer  # noqa: E402

SECTOR = 512


class _MemLayer(DataLayer):
    """Read-only in-memory :class:`DataLayer` shim for KAT fixtures."""

    def __init__(self, data: bytes, name: str = "kat") -> None:
        self._data = bytes(data)
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        end = min(offset + length, len(self._data))
        out = self._data[max(0, offset):end]
        if pad and len(out) < length:
            out = out + b"\x00" * (length - len(out))
        return out

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._data)

    def scan(
        self, scanner: object, progress_callback: Callable | None = None
    ) -> Iterator[ScanResult]:
        yield from ()

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(0, len(self._data) - 1)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name=self._name)


# ---------------------------------------------------------------------------
# Reference encryptors (mirror the IV/tweak derivation in layer.py exactly).
# ---------------------------------------------------------------------------


def _enc_xts(key: bytes, sectors: list[bytes]) -> bytes:
    out = bytearray()
    for i, block in enumerate(sectors):
        tweak = i.to_bytes(16, "little")
        out.extend(Cipher(algorithms.AES(key), modes.XTS(tweak)).encryptor().update(block))
    return bytes(out)


def _essiv_iv(key: bytes, sector: int) -> bytes:
    essiv_key = hashlib.sha256(key).digest()
    sector_block = sector.to_bytes(16, "little")
    return Cipher(algorithms.AES(essiv_key), modes.ECB()).encryptor().update(sector_block)


def _enc_cbc_essiv(key: bytes, sectors: list[bytes]) -> bytes:
    out = bytearray()
    for i, block in enumerate(sectors):
        iv = _essiv_iv(key, i)
        out.extend(Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(block))
    return bytes(out)


def _enc_cbc_plain64(key: bytes, sectors: list[bytes]) -> bytes:
    out = bytearray()
    for i, block in enumerate(sectors):
        iv = i.to_bytes(16, "little")
        out.extend(Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(block))
    return bytes(out)


def _enc_ctr(key: bytes, sectors: list[bytes]) -> bytes:
    out = bytearray()
    for i, block in enumerate(sectors):
        nonce = i.to_bytes(16, "little")
        out.extend(Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor().update(block))
    return bytes(out)


def _sectors(n: int, seed: int) -> list[bytes]:
    return [
        bytes(((s * 256 + i * seed + 11) & 0xFF) for i in range(SECTOR))
        for s in range(n)
    ]


# ---------------------------------------------------------------------------
# XTS-AES
# ---------------------------------------------------------------------------


def test_kat_xts_aes256_roundtrip() -> None:
    key = bytes(range(64))  # AES-256-XTS
    blocks = _sectors(4, seed=13)
    plaintext = b"".join(blocks)
    ciphertext = _enc_xts(key, blocks)

    layer = DecryptedVolumeLayer(
        _MemLayer(ciphertext),
        cipher_name="aes",
        key=key,
        sector_size=SECTOR,
        mode="xts",
        iv_mode="tweak",
    )
    # Full read and a targeted middle sector read must both agree.
    assert layer.read(0, 4 * SECTOR) == plaintext
    assert layer.read(2 * SECTOR, SECTOR) == plaintext[2 * SECTOR:3 * SECTOR]


def test_kat_xts_aes128_roundtrip() -> None:
    key = bytes(range(32))  # AES-128-XTS (two 16-byte half-keys)
    blocks = _sectors(2, seed=7)
    plaintext = b"".join(blocks)
    ciphertext = _enc_xts(key, blocks)

    layer = DecryptedVolumeLayer(
        _MemLayer(ciphertext),
        cipher_name="aes",
        key=key,
        sector_size=SECTOR,
        mode="xts",
    )
    assert layer.read(0, 2 * SECTOR) == plaintext


def test_kat_xts_tweak_is_sector_keyed() -> None:
    """A sector decrypted at index 1 must NOT equal the same ciphertext
    decrypted as index 0 — proves the tweak is the sector number."""
    key = bytes(range(64))
    block = _sectors(1, seed=3)[0]
    ct_at_1 = _enc_xts(key, [b"\x00" * SECTOR, block])[SECTOR:]

    layer = DecryptedVolumeLayer(
        _MemLayer(b"\x00" * SECTOR + ct_at_1),
        cipher_name="aes",
        key=key,
        sector_size=SECTOR,
        mode="xts",
    )
    # Reading sector 1 recovers the block; reading the same ciphertext as
    # sector 0 (via a fresh layer where it sits at offset 0) does not.
    assert layer.read(SECTOR, SECTOR) == block
    wrong = DecryptedVolumeLayer(
        _MemLayer(ct_at_1), cipher_name="aes", key=key, sector_size=SECTOR, mode="xts"
    )
    assert wrong.read(0, SECTOR) != block


# ---------------------------------------------------------------------------
# CBC-ESSIV (SHA-256)
# ---------------------------------------------------------------------------


def test_kat_cbc_essiv_roundtrip() -> None:
    key = bytes(range(32))  # AES-256-CBC
    blocks = _sectors(3, seed=5)
    plaintext = b"".join(blocks)
    ciphertext = _enc_cbc_essiv(key, blocks)

    layer = DecryptedVolumeLayer(
        _MemLayer(ciphertext),
        cipher_name="aes",
        key=key,
        sector_size=SECTOR,
        mode="cbc-essiv",
        iv_mode="essiv-sha256",
    )
    assert layer.read(0, 3 * SECTOR) == plaintext
    assert layer.read(SECTOR, SECTOR) == plaintext[SECTOR:2 * SECTOR]


def test_kat_cbc_essiv_iv_derivation_is_pinned() -> None:
    """Freeze the exact ESSIV IV: ``AES-ECB(SHA256(key), sector_LE16)``.

    A pure round-trip can't catch a *symmetric* IV bug (encrypt and
    decrypt agreeing on a wrong IV), so we pin the canonical IV value
    for sector 7 under the all-ascending 32-byte key. This is the dm-crypt
    / LUKS1 convention and matches ``luks.py``'s reference path.
    """
    key = bytes(range(32))
    expected_iv = bytes.fromhex("4e1a000085e881e0f6ce130bc5941373")
    assert _essiv_iv(key, 7) == expected_iv

    # And a sector encrypted with that exact IV must decrypt through our
    # path (which derives the same IV internally) at sector index 7.
    block = _sectors(1, seed=9)[0]
    ct = Cipher(algorithms.AES(key), modes.CBC(expected_iv)).encryptor().update(block)
    # Lay the ciphertext at sector 7 inside a zero-padded image.
    image = bytearray(b"\x00" * (8 * SECTOR))
    image[7 * SECTOR:8 * SECTOR] = ct
    layer = DecryptedVolumeLayer(
        _MemLayer(bytes(image)),
        cipher_name="aes",
        key=key,
        sector_size=SECTOR,
        mode="cbc-essiv",
        iv_mode="essiv-sha256",
    )
    assert layer.read(7 * SECTOR, SECTOR) == block


def test_kat_cbc_essiv_wrong_iv_mode_fails() -> None:
    """Decrypting ESSIV ciphertext with plain64 IV must NOT recover the
    plaintext — confirms the ESSIV path is actually applying ESSIV."""
    key = bytes(range(32))
    blocks = _sectors(1, seed=2)
    plaintext = blocks[0]
    ciphertext = _enc_cbc_essiv(key, blocks)

    layer = DecryptedVolumeLayer(
        _MemLayer(ciphertext),
        cipher_name="aes",
        key=key,
        sector_size=SECTOR,
        mode="cbc-plain64",
        iv_mode="plain64",
    )
    assert layer.read(0, SECTOR) != plaintext


# ---------------------------------------------------------------------------
# CBC-plain64
# ---------------------------------------------------------------------------


def test_kat_cbc_plain64_roundtrip() -> None:
    key = bytes(range(32))
    blocks = _sectors(3, seed=17)
    plaintext = b"".join(blocks)
    ciphertext = _enc_cbc_plain64(key, blocks)

    layer = DecryptedVolumeLayer(
        _MemLayer(ciphertext),
        cipher_name="aes",
        key=key,
        sector_size=SECTOR,
        mode="cbc-plain64",
        iv_mode="plain64",
    )
    assert layer.read(0, 3 * SECTOR) == plaintext
    # Unaligned read crossing a sector boundary.
    assert layer.read(SECTOR - 16, 48) == plaintext[SECTOR - 16:SECTOR + 32]


# ---------------------------------------------------------------------------
# CTR-AES
# ---------------------------------------------------------------------------


def test_kat_ctr_roundtrip() -> None:
    key = bytes(range(32))
    blocks = _sectors(4, seed=23)
    plaintext = b"".join(blocks)
    ciphertext = _enc_ctr(key, blocks)

    layer = DecryptedVolumeLayer(
        _MemLayer(ciphertext),
        cipher_name="aes",
        key=key,
        sector_size=SECTOR,
        mode="ctr",
        iv_mode="plain64",
    )
    assert layer.read(0, 4 * SECTOR) == plaintext
    assert layer.read(3 * SECTOR, SECTOR) == plaintext[3 * SECTOR:4 * SECTOR]


def test_kat_ctr_counter_resets_per_sector() -> None:
    """Each sector's CTR keystream must restart at the sector number; a
    sector encrypted as #2 only decrypts at index 2, not index 0."""
    key = bytes(range(32))
    block = _sectors(1, seed=4)[0]
    ct_at_2 = _enc_ctr(key, [b"\x00" * SECTOR] * 2 + [block])[2 * SECTOR:]

    layer = DecryptedVolumeLayer(
        _MemLayer(b"\x00" * (2 * SECTOR) + ct_at_2),
        cipher_name="aes",
        key=key,
        sector_size=SECTOR,
        mode="ctr",
    )
    assert layer.read(2 * SECTOR, SECTOR) == block
    wrong = DecryptedVolumeLayer(
        _MemLayer(ct_at_2), cipher_name="aes", key=key, sector_size=SECTOR, mode="ctr"
    )
    assert wrong.read(0, SECTOR) != block


# ---------------------------------------------------------------------------
# Cross-mode / wiring guards
# ---------------------------------------------------------------------------


def test_unsupported_cipher_raises() -> None:
    layer = DecryptedVolumeLayer(
        _MemLayer(b"\x00" * SECTOR),
        cipher_name="serpent",
        key=bytes(64),
        sector_size=SECTOR,
        mode="xts",
    )
    with pytest.raises(NotImplementedError):
        layer.read(0, SECTOR)


def test_pad_outside_range_needs_no_crypto() -> None:
    """A fully out-of-range padded read returns zeros without touching the
    cipher backend (regression guard for the lazy-import ordering)."""
    layer = DecryptedVolumeLayer(
        _MemLayer(b"\x00" * SECTOR),
        cipher_name="aes",
        key=bytes(64),
        sector_size=SECTOR,
        mode="xts",
        data_length=SECTOR,
    )
    assert layer.read(SECTOR + 100, 32, pad=True) == b"\x00" * 32


# ---------------------------------------------------------------------------
# _cipher_cascades AES-XTS header path
# ---------------------------------------------------------------------------

_HDR_LEN = 448


def test_kat_cascade_aes_xts_roundtrip() -> None:
    """The VeraCrypt header cascade decrypts what it encrypts (sector 0)."""
    key = bytes((i * 7 + 3) & 0xFF for i in range(64))
    plaintext = bytes((i & 0xFF) for i in range(_HDR_LEN))
    ciphertext = _aes_xts_encrypt(key, plaintext)
    assert ciphertext != plaintext
    assert _aes_xts_decrypt(key, ciphertext) == plaintext


def test_kat_cascade_aes_xts_matches_layer_sector0() -> None:
    """The cascade's sector-0 XTS unit equals what DecryptedVolumeLayer
    would produce for a 448-byte (28 * 16) sector at index 0."""
    key = bytes((i * 5 + 1) & 0xFF for i in range(64))
    plaintext = bytes(((i * 3) & 0xFF) for i in range(_HDR_LEN))
    ciphertext = _aes_xts_encrypt(key, plaintext)

    layer = DecryptedVolumeLayer(
        _MemLayer(ciphertext),
        cipher_name="aes",
        key=key,
        sector_size=_HDR_LEN,
        mode="xts",
        data_length=_HDR_LEN,
    )
    assert layer.read(0, _HDR_LEN) == plaintext


def test_cascade_rejects_wrong_length_ciphertext() -> None:
    key = bytes(range(64))
    with pytest.raises(ValueError):
        _aes_xts_decrypt(key, b"\x00" * (_HDR_LEN - 1))
    with pytest.raises(ValueError):
        _aes_xts_encrypt(key, b"\x00" * (_HDR_LEN + 16))


def test_cascade_rejects_short_key() -> None:
    with pytest.raises(ValueError):
        _aes_xts_decrypt(b"\x00" * 32, b"\x00" * _HDR_LEN)


def test_wired_cascades_only_aes() -> None:
    """Only the AES-XTS cascade has a real decrypt path today; the
    Serpent/Twofish cascades are detect-only and excluded from the
    wired set."""
    wired = wired_cascades()
    assert len(wired) == 1
    assert wired[0].name == "aes-xts"
    # The unwired cascades still resolve by name (for detection metadata)
    # but raise NotImplementedError when asked to decrypt.
    serpent = cascade_by_name("serpent-xts")
    assert serpent is not None
    with pytest.raises(NotImplementedError):
        serpent.decrypt_header(bytes(64), b"\x00" * _HDR_LEN)
