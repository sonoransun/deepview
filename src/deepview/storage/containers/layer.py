"""Per-sector decrypting :class:`DataLayer` for encrypted containers.

``DecryptedVolumeLayer`` wraps another :class:`DataLayer` holding raw
ciphertext and exposes the decrypted plaintext as a normal byte-addressable
layer. Decryption is lazy and sector-keyed: a :meth:`read` that spans
multiple sectors reads each sector's ciphertext from the underlying layer,
computes the per-sector IV / tweak according to *iv_mode* / *mode*,
decrypts it through ``cryptography.hazmat.primitives.ciphers`` (lazy
imported so a core install without the ``containers`` extra still imports
this module), and slices the requested range out of the assembled buffer.

A small LRU cache of decrypted sectors is kept to make sequential /
neighbouring reads cheap — the default cap of 256 sectors is enough for
partition table + superblock probes without ballooning memory.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Literal

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


DEFAULT_SECTOR_CACHE_CAP = 256
# Backwards-compatible alias; prefer ``DEFAULT_SECTOR_CACHE_CAP``.
_SECTOR_CACHE_CAP = DEFAULT_SECTOR_CACHE_CAP


CipherMode = Literal["xts", "cbc-essiv", "cbc-plain64", "ctr"]
IVMode = Literal["plain64", "essiv-sha256", "tweak"]


class DecryptedVolumeLayer(DataLayer):
    """A :class:`DataLayer` that decrypts sectors on demand.

    Parameters
    ----------
    underlying:
        Backing layer holding the raw ciphertext.
    cipher_name:
        Name of the block cipher (e.g. ``"aes"``). Currently AES is the
        only cipher wired; other ciphers will plug in through the same
        factory once their adapters land.
    key:
        Raw cipher key. For XTS the key must be 32 or 64 bytes (two
        half-keys concatenated for AES-128-XTS / AES-256-XTS).
    sector_size:
        Sector length in bytes; the default of 512 matches the LUKS /
        VeraCrypt / BitLocker convention.
    data_offset:
        Byte offset inside *underlying* at which the encrypted payload
        starts. Everything before this offset is header / metadata.
    data_length:
        Usable plaintext length in bytes. ``None`` means "all remaining
        bytes after *data_offset*".
    mode:
        Block-cipher mode. ``"xts"`` covers LUKS2 / VeraCrypt / BitLocker;
        ``"cbc-essiv"`` / ``"cbc-plain64"`` cover legacy LUKS1 /
        dm-crypt; ``"ctr"`` is reserved for FileVault2 and similar.
    iv_mode:
        IV derivation. ``"plain64"`` is the sector number rendered as
        little-endian 8 bytes padded to the cipher block. ``"tweak"`` is
        the sector number rendered as a 16-byte little-endian tweak for
        XTS. ``"essiv-sha256"`` hashes the key with SHA-256 and encrypts
        the sector number with the hash as the ESSIV key.
    name:
        Optional display name for :attr:`metadata`.
    sector_cache_cap:
        Maximum number of decrypted sectors retained in the LRU cache.
        Default ``DEFAULT_SECTOR_CACHE_CAP`` (256) — tune upwards for
        high-IOPS workloads where the same region is re-read across
        many scanners.
    """

    def __init__(
        self,
        underlying: DataLayer,
        *,
        cipher_name: str,
        key: bytes,
        sector_size: int = 512,
        data_offset: int = 0,
        data_length: int | None = None,
        mode: CipherMode = "xts",
        iv_mode: IVMode = "plain64",
        name: str = "",
        sector_cache_cap: int = DEFAULT_SECTOR_CACHE_CAP,
    ) -> None:
        if sector_size <= 0 or sector_size % 16 != 0:
            raise ValueError("sector_size must be a positive multiple of 16")
        if data_offset < 0:
            raise ValueError("data_offset must be non-negative")
        if sector_cache_cap < 1:
            raise ValueError("sector_cache_cap must be >= 1")

        self._underlying = underlying
        self._cipher_name = cipher_name.lower()
        self._key = key
        self._sector_size = sector_size
        self._data_offset = data_offset
        self._mode = mode
        self._iv_mode = iv_mode
        self._sector_cache_cap = sector_cache_cap

        if data_length is None:
            remaining = underlying.maximum_address + 1 - data_offset
            if remaining < 0:
                remaining = 0
            data_length = remaining
        if data_length < 0:
            raise ValueError("data_length must be non-negative")

        self._data_length = data_length
        self._name = name or f"crypt:{cipher_name}-{mode}"
        self._sector_cache: OrderedDict[int, bytes] = OrderedDict()

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""

        # Lazy import so core installs without the `containers` extra can
        # still import this module.
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        end = offset + length
        if offset < 0 or end > self._data_length:
            if pad:
                clamped_start = max(offset, 0)
                clamped_end = min(end, self._data_length)
                if clamped_start >= clamped_end:
                    return b"\x00" * length
                inner = self.read(clamped_start, clamped_end - clamped_start, pad=False)
                head = b"\x00" * max(0, -offset)
                tail = b"\x00" * max(0, end - self._data_length)
                return head + inner + tail
            raise ValueError(
                f"read out of bounds: offset={offset} length={length} "
                f"data_length={self._data_length}"
            )

        first_sector = offset // self._sector_size
        last_sector = (end - 1) // self._sector_size
        result = bytearray()
        for sector in range(first_sector, last_sector + 1):
            plaintext = self._decrypt_sector(sector, Cipher, algorithms, modes)
            start = 0
            stop = self._sector_size
            if sector == first_sector:
                start = offset - sector * self._sector_size
            if sector == last_sector:
                stop = end - sector * self._sector_size
            result.extend(plaintext[start:stop])
        return bytes(result)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("DecryptedVolumeLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return (
            offset >= 0
            and length >= 0
            and offset + length <= self._data_length
        )

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        """Delegate scanning to *scanner* over the decrypted stream."""
        remaining = self._data_length
        pos = 0
        chunk = max(self._sector_size, 64 * 1024)
        while remaining > 0:
            take = min(chunk, remaining)
            data = self.read(pos, take)
            for result in scanner.scan(data, offset=pos):
                yield result
            pos += take
            remaining -= take
            if progress_callback and self._data_length > 0:
                progress_callback(pos / self._data_length)

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        if self._data_length == 0:
            return 0
        return self._data_length - 1

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _decrypt_sector(
        self,
        sector: int,
        cipher_cls: type,
        algorithms: object,
        modes: object,
    ) -> bytes:
        """Return the plaintext of *sector*, consulting the LRU cache."""
        cached = self._sector_cache.get(sector)
        if cached is not None:
            self._sector_cache.move_to_end(sector)
            return cached

        phys = self._data_offset + sector * self._sector_size
        ciphertext = self._underlying.read(phys, self._sector_size)
        if len(ciphertext) < self._sector_size:
            ciphertext = ciphertext + b"\x00" * (
                self._sector_size - len(ciphertext)
            )

        plaintext = self._decrypt_block(
            sector, ciphertext, cipher_cls, algorithms, modes
        )

        self._sector_cache[sector] = plaintext
        if len(self._sector_cache) > self._sector_cache_cap:
            self._sector_cache.popitem(last=False)
        return plaintext

    def _decrypt_block(
        self,
        sector: int,
        ciphertext: bytes,
        cipher_cls: type,
        algorithms: object,
        modes: object,
    ) -> bytes:
        if self._cipher_name != "aes":
            raise NotImplementedError(
                f"cipher '{self._cipher_name}' not wired yet in DecryptedVolumeLayer"
            )

        algo_aes = algorithms.AES  # type: ignore[attr-defined]

        if self._mode == "xts":
            tweak = self._xts_tweak(sector)
            cipher = cipher_cls(algo_aes(self._key), modes.XTS(tweak))  # type: ignore[attr-defined]
            return cipher.decryptor().update(ciphertext)

        if self._mode in ("cbc-essiv", "cbc-plain64"):
            iv = self._cbc_iv(sector)
            cipher = cipher_cls(algo_aes(self._key), modes.CBC(iv))  # type: ignore[attr-defined]
            return cipher.decryptor().update(ciphertext)

        if self._mode == "ctr":
            nonce = self._ctr_nonce(sector)
            cipher = cipher_cls(algo_aes(self._key), modes.CTR(nonce))  # type: ignore[attr-defined]
            return cipher.decryptor().update(ciphertext)

        raise NotImplementedError(f"mode '{self._mode}' not supported")

    def _xts_tweak(self, sector: int) -> bytes:
        # XTS always uses a 16-byte little-endian tweak regardless of iv_mode.
        return sector.to_bytes(16, "little")

    def _cbc_iv(self, sector: int) -> bytes:
        if self._iv_mode == "plain64":
            return sector.to_bytes(16, "little")
        if self._iv_mode == "essiv-sha256":
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers import (
                Cipher as _Cipher,
            )
            from cryptography.hazmat.primitives.ciphers import (
                algorithms as _algs,
            )
            from cryptography.hazmat.primitives.ciphers import modes as _modes

            digest = hashes.Hash(hashes.SHA256())
            digest.update(self._key)
            essiv_key = digest.finalize()
            sector_block = sector.to_bytes(16, "little")
            enc = _Cipher(
                _algs.AES(essiv_key), _modes.ECB()  # noqa: S305 — ESSIV by spec
            ).encryptor()
            return enc.update(sector_block) + enc.finalize()
        # tweak fallthrough — treat as plain64 for CBC.
        return sector.to_bytes(16, "little")

    def _ctr_nonce(self, sector: int) -> bytes:
        return sector.to_bytes(16, "little")


__all__ = [
    "DecryptedVolumeLayer",
    "CipherMode",
    "IVMode",
    "DEFAULT_SECTOR_CACHE_CAP",
]
