"""Synthetic NAND dump helpers for storage tests."""
from __future__ import annotations

from pathlib import Path


def build_nand_dump(
    path: Path,
    pages: int,
    page_size: int,
    spare_size: int,
    *,
    data_fill: bytes = b"\xAB",
    spare_fill: bytes = b"\xCD",
) -> bytes:
    """Write a deterministic raw NAND dump with interleaved data+spare.

    Each page's data area starts with a 4-byte big-endian page index so
    tests can verify slicing / iteration ordering, then is padded with
    *data_fill*. The spare area is filled with *spare_fill*.

    Returns the full byte contents that were written so tests can assert
    byte-level equality without re-reading from disk.
    """
    assert pages >= 0
    assert page_size > 0
    assert spare_size >= 0
    assert len(data_fill) == 1
    assert len(spare_fill) == 1

    buf = bytearray()
    for index in range(pages):
        header = index.to_bytes(4, "big")
        data = header + data_fill * (page_size - len(header))
        assert len(data) == page_size
        spare = spare_fill * spare_size
        buf.extend(data)
        buf.extend(spare)
    path.write_bytes(bytes(buf))
    return bytes(buf)
