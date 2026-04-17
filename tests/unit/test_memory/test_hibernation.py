"""Tests for ``HibernationLayer``.

Hibernation dumps rely on a Windows ``PO_MEMORY_IMAGE`` header followed by
a chain of ``_PO_MEMORY_RANGE_TABLE`` records pointing at Xpress-compressed
page runs. The pure-Python Xpress decoder ships as a partial implementation,
so these tests exercise the **fallback (raw pass-through) path** — which is
the code path real-world callers will hit until slice 7 is done.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from deepview.core.exceptions import FormatError
from deepview.memory.formats.hibernation import HibernationLayer


def _build_minimal_hiberfil(
    path: Path,
    magic: bytes = b"hibr",
    page_size: int = 0x1000,
    total_pages: int = 4,
) -> None:
    """Write a tiny synthetic hiberfil that parses but relies on fallback.

    The header's offsets match the ``PO_MEMORY_IMAGE`` layout the layer
    parses (``PageSize`` at 0x18, ``TotalPages`` at 0x4C,
    ``FirstTablePage`` at 0x58). The "page runs" that follow are just
    deterministic filler — the fallback path reads them verbatim.
    """
    header = bytearray(page_size)
    header[0:4] = magic
    struct.pack_into("<I", header, 0x4, 1)  # Version
    struct.pack_into("<I", header, 0x8, 0)  # CheckSum
    struct.pack_into("<I", header, 0xC, page_size)  # LengthSelf
    struct.pack_into("<Q", header, 0x10, 0)  # PageSelf
    struct.pack_into("<I", header, 0x18, page_size)  # PageSize
    struct.pack_into("<I", header, 0x4C, total_pages)  # TotalPages
    # First table page = 1 (second page in the file). We leave it mostly
    # zeroed so the table walk terminates cleanly and we fall through to
    # raw mode.
    struct.pack_into("<Q", header, 0x58, 1)
    struct.pack_into("<Q", header, 0x60, total_pages + 1)  # LastFilePage

    body = bytearray()
    # Page 1: empty table (PageCount=0 terminates the walk).
    body.extend(b"\x00" * page_size)
    # Pages 2..n: filler with identifiable per-page pattern so the raw
    # passthrough read back is easy to verify.
    for i in range(total_pages):
        body.extend(bytes([i & 0xFF]) * page_size)

    path.write_bytes(bytes(header) + bytes(body))


# ---------------------------------------------------------------------------
# Construction / validation
# ---------------------------------------------------------------------------


class TestHibernationMagic:
    def test_rejects_bad_magic(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.sys"
        bad.write_bytes(b"XXXX" + b"\x00" * 0x1000)
        with pytest.raises(FormatError):
            HibernationLayer(bad)

    def test_accepts_hibr_lower(self, tmp_path: Path) -> None:
        p = tmp_path / "h.sys"
        _build_minimal_hiberfil(p, magic=b"hibr")
        layer = HibernationLayer(p)
        try:
            assert layer.compression_status in ("decoded", "undecoded")
        finally:
            layer.close()

    def test_accepts_wake_upper(self, tmp_path: Path) -> None:
        p = tmp_path / "h.sys"
        _build_minimal_hiberfil(p, magic=b"WAKE")
        layer = HibernationLayer(p)
        try:
            assert layer.compression_status in ("decoded", "undecoded")
        finally:
            layer.close()


# ---------------------------------------------------------------------------
# Read behaviour (fallback path)
# ---------------------------------------------------------------------------


class TestHibernationRead:
    def test_constructs_and_reads_page(self, tmp_path: Path) -> None:
        p = tmp_path / "hib.sys"
        _build_minimal_hiberfil(p, total_pages=4)
        layer = HibernationLayer(p)
        try:
            # The synthetic hiberfil has a zero-PageCount table, so we
            # expect the layer to fall through to raw mode.
            assert layer.compression_status == "undecoded"
            data = layer.read(0, 4096)
            assert len(data) == 4096
            # First four bytes are the "hibr" magic at file offset 0.
            assert data[:4] == b"hibr"
        finally:
            layer.close()

    def test_read_with_pad_past_eof(self, tmp_path: Path) -> None:
        p = tmp_path / "hib.sys"
        _build_minimal_hiberfil(p, total_pages=2)
        layer = HibernationLayer(p)
        try:
            data = layer.read(layer.maximum_address + 10, 128, pad=True)
            assert data == b"\x00" * 128
        finally:
            layer.close()

    def test_write_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "hib.sys"
        _build_minimal_hiberfil(p)
        layer = HibernationLayer(p)
        try:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"\x00")
        finally:
            layer.close()

    def test_minimum_and_maximum_addresses(self, tmp_path: Path) -> None:
        p = tmp_path / "hib.sys"
        _build_minimal_hiberfil(p, total_pages=4)
        layer = HibernationLayer(p)
        try:
            assert layer.minimum_address == 0
            assert layer.maximum_address > 0
        finally:
            layer.close()

    def test_metadata(self, tmp_path: Path) -> None:
        p = tmp_path / "hib.sys"
        _build_minimal_hiberfil(p)
        layer = HibernationLayer(p, name="mydump")
        try:
            md = layer.metadata
            assert md.name == "mydump"
            assert md.os == "windows"
        finally:
            layer.close()


class TestHibernationLifecycle:
    def test_context_manager(self, tmp_path: Path) -> None:
        p = tmp_path / "hib.sys"
        _build_minimal_hiberfil(p)
        with HibernationLayer(p) as layer:
            assert layer.read(0, 4) == b"hibr"

    def test_del_cleanup(self, tmp_path: Path) -> None:
        p = tmp_path / "hib.sys"
        _build_minimal_hiberfil(p)
        layer = HibernationLayer(p)
        layer.read(0, 4)
        del layer  # must not raise
