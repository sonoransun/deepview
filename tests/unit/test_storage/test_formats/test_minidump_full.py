"""Tests for the Windows minidump full-memory layer."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from deepview.core.exceptions import FormatError
from deepview.storage.formats.minidump_full import (
    MinidumpFullLayer,
    Memory64Run,
)


_MDMP_HEADER_FMT = "<IIIIIIQ"
_MDMP_DIR_FMT = "<III"
_MEM64_LIST_HEADER_FMT = "<QQ"
_MEM64_DESCRIPTOR_FMT = "<QQ"


def _build_minidump(
    path: Path,
    runs: list[tuple[int, bytes]],
) -> None:
    """Build a minimal MDMP file containing a Memory64ListStream.

    *runs* is an ordered list of ``(virtual_address, payload)`` tuples.
    Written layout::

        header | dir[0] | mem64_list_header | descriptor[]... | payload...
    """
    number_of_streams = 1
    header_size = struct.calcsize(_MDMP_HEADER_FMT)
    dir_size = struct.calcsize(_MDMP_DIR_FMT)
    list_hdr_size = struct.calcsize(_MEM64_LIST_HEADER_FMT)
    desc_size = struct.calcsize(_MEM64_DESCRIPTOR_FMT)

    stream_directory_rva = header_size
    mem64_rva = stream_directory_rva + dir_size
    desc_start = mem64_rva + list_hdr_size
    desc_end = desc_start + len(runs) * desc_size
    # Align payload start on 8 bytes.
    payload_start = (desc_end + 7) & ~7
    total_payload = sum(len(p) for _a, p in runs)
    base_rva = payload_start

    buf = bytearray()
    # MINIDUMP_HEADER
    buf.extend(
        struct.pack(
            _MDMP_HEADER_FMT,
            0x504D444D,  # 'MDMP'
            0x0000A793,  # version
            number_of_streams,
            stream_directory_rva,
            0,  # checksum
            0,  # timestamp
            0,  # flags
        )
    )
    assert len(buf) == header_size

    # MINIDUMP_DIRECTORY entry: Memory64ListStream = 9.
    mem64_stream_size = list_hdr_size + len(runs) * desc_size
    buf.extend(struct.pack(_MDMP_DIR_FMT, 9, mem64_stream_size, mem64_rva))
    assert len(buf) == mem64_rva

    # MINIDUMP_MEMORY64_LIST header.
    buf.extend(struct.pack(_MEM64_LIST_HEADER_FMT, len(runs), base_rva))
    # Descriptors.
    for va, payload in runs:
        buf.extend(struct.pack(_MEM64_DESCRIPTOR_FMT, va, len(payload)))
    # Pad to payload_start.
    while len(buf) < payload_start:
        buf.append(0)
    # Payloads, back-to-back.
    for _va, payload in runs:
        buf.extend(payload)
    assert len(buf) == payload_start + total_payload

    path.write_bytes(bytes(buf))


class TestMinidumpFull:
    def test_read_single_run(self, tmp_path: Path) -> None:
        payload = bytes(range(256)) * 2  # 512 B
        dump = tmp_path / "single.dmp"
        _build_minidump(dump, [(0x1000, payload)])

        with MinidumpFullLayer(dump) as layer:
            assert layer.read(0x1000, 512) == payload
            assert layer.read(0x1000 + 16, 32) == payload[16:48]
            assert layer.is_valid(0x1000, 512)
            assert not layer.is_valid(0x0FFF, 1)

    def test_read_two_runs(self, tmp_path: Path) -> None:
        a = b"\xAA" * 256
        b = b"\xBB" * 128
        dump = tmp_path / "two.dmp"
        _build_minidump(dump, [(0x2000, a), (0x5000, b)])

        with MinidumpFullLayer(dump) as layer:
            runs = layer.runs
            assert [r.virtual_address for r in runs] == [0x2000, 0x5000]
            assert all(isinstance(r, Memory64Run) for r in runs)
            assert layer.read(0x2000, 256) == a
            assert layer.read(0x5000, 128) == b
            assert layer.minimum_address == 0x2000
            assert layer.maximum_address == 0x5000 + 128 - 1

    def test_out_of_bounds_pad_returns_zeros(self, tmp_path: Path) -> None:
        payload = b"\xCC" * 64
        dump = tmp_path / "pad.dmp"
        _build_minidump(dump, [(0x1000, payload)])

        with MinidumpFullLayer(dump) as layer:
            # Reading entirely in the gap should zero-fill with pad=True.
            assert layer.read(0x0800, 32, pad=True) == b"\x00" * 32
            # Straddling a valid run and a gap: first bytes real, tail zeros.
            out = layer.read(0x1000 + 48, 32, pad=True)
            assert out == payload[48:64] + b"\x00" * 16

    def test_out_of_bounds_no_pad_returns_empty(self, tmp_path: Path) -> None:
        payload = b"\xCC" * 64
        dump = tmp_path / "nopad.dmp"
        _build_minidump(dump, [(0x1000, payload)])

        with MinidumpFullLayer(dump) as layer:
            # No pad, entirely-in-gap read returns empty bytes.
            assert layer.read(0x0800, 32) == b""

    def test_bad_signature_raises(self, tmp_path: Path) -> None:
        dump = tmp_path / "bad.dmp"
        dump.write_bytes(b"XXXX" + b"\x00" * 60)
        with pytest.raises(FormatError):
            MinidumpFullLayer(dump)

    def test_write_raises(self, tmp_path: Path) -> None:
        payload = b"\xEE" * 16
        dump = tmp_path / "wr.dmp"
        _build_minidump(dump, [(0, payload)])
        with MinidumpFullLayer(dump) as layer:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"x")

    def test_metadata_defaults(self, tmp_path: Path) -> None:
        payload = b"\xDD" * 8
        dump = tmp_path / "meta.dmp"
        _build_minidump(dump, [(0x1000, payload)])
        with MinidumpFullLayer(dump) as layer:
            meta = layer.metadata
            assert meta.name == "minidump_full"
            assert meta.minimum_address == 0x1000
            assert meta.maximum_address == 0x1000 + 8 - 1
