"""BitLocker detection test using a synthesized BPB.

We build a 4 KiB synthetic volume whose first sector contains a
standard BPB prefix and the BitLocker FVE OEM-ID signature at byte
offset 3, then assert that :meth:`BitLockerUnlocker.detect` returns a
:class:`ContainerHeader` with ``format == "bitlocker"``.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.containers.bitlocker import BitLockerUnlocker


class _MemLayer(DataLayer):
    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)

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
        return LayerMetadata(name="mem")


def _synth_bitlocker_bpb() -> bytes:
    """Build a 4 KiB image whose sector 0 carries the BitLocker signature."""
    sector = bytearray(b"\x00" * 512)
    # Bytes 0..2 — JMP short (EB 58 90 is the canonical BitLocker prefix).
    sector[0] = 0xEB
    sector[1] = 0x58
    sector[2] = 0x90
    # Bytes 3..10 — OEM-ID "-FVE-FS-".
    sector[3:11] = b"-FVE-FS-"
    # Boot sector signature.
    sector[510] = 0x55
    sector[511] = 0xAA
    # Pad to 4 KiB so data_length is a meaningful value.
    return bytes(sector) + b"\x00" * (4096 - 512)


def test_bitlocker_detect_positive() -> None:
    layer = _MemLayer(_synth_bitlocker_bpb())
    header = BitLockerUnlocker().detect(layer)
    assert header is not None
    assert header.format == "bitlocker"
    assert header.sector_size == 512
    assert header.cipher.startswith("aes")
    assert header.data_offset == 0
    assert header.data_length > 0
    assert header.kdf == "pbkdf2_sha256"
    # The raw payload should include the signature bytes.
    assert b"-FVE-FS-" in header.raw


def test_bitlocker_detect_negative_random() -> None:
    # Random-looking 512 bytes without the signature should not match.
    layer = _MemLayer(b"\xAA" * 4096)
    assert BitLockerUnlocker().detect(layer) is None


def test_bitlocker_detect_negative_too_short() -> None:
    # Image shorter than the OEM-ID offset + length.
    layer = _MemLayer(b"\x00" * 5)
    assert BitLockerUnlocker().detect(layer) is None
