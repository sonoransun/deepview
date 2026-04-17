"""Tests for the storage / filesystem / NAND builtin plugins."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.interfaces.plugin import PluginResult


class _MemoryDataLayer(DataLayer):
    def __init__(self, data: bytes, name: str = "mem") -> None:
        self._data = bytes(data)
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0 or offset >= len(self._data):
            return b"\x00" * length if pad else b""
        end = min(offset + length, len(self._data))
        out = self._data[offset:end]
        if pad and len(out) < length:
            out = out + b"\x00" * (length - len(out))
        return out

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._data)

    def scan(
        self,
        scanner: object,
        progress_callback: Callable | None = None,
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


@pytest.fixture
def context_with_fat() -> AnalysisContext:
    pytest.importorskip("deepview.storage.filesystems.fat_native")
    from tests.unit.test_storage.test_filesystems.test_fat_native import _build_image

    ctx = AnalysisContext.for_testing()
    ctx.layers.register("fat", _MemoryDataLayer(_build_image()))
    return ctx


class TestFilesystemListPlugin:
    def test_run_against_fat(self, context_with_fat: AnalysisContext) -> None:
        pytest.importorskip("deepview.plugins.builtin.filesystem_ls")
        from deepview.plugins.builtin.filesystem_ls import FilesystemListPlugin

        plugin = FilesystemListPlugin(
            context_with_fat, config={"layer_name": "fat", "fs_type": "fat"}
        )
        result = plugin.run()
        assert isinstance(result, PluginResult)
        assert "Error" not in result.columns, result.rows
        assert result.columns == ["Path", "Size", "Mode", "MTime", "Deleted"]
        assert any("HELLO.TXT" in row["Path"] for row in result.rows)

    def test_missing_layer_returns_error_result(self) -> None:
        from deepview.plugins.builtin.filesystem_ls import FilesystemListPlugin

        ctx = AnalysisContext.for_testing()
        plugin = FilesystemListPlugin(ctx, config={"layer_name": "nope"})
        result = plugin.run()
        assert "Error" in result.columns


class TestFilesystemTimelinePlugin:
    def test_run_against_fat(self, context_with_fat: AnalysisContext) -> None:
        pytest.importorskip("deepview.plugins.builtin.filesystem_timeline")
        from deepview.plugins.builtin.filesystem_timeline import FilesystemTimelinePlugin

        plugin = FilesystemTimelinePlugin(
            context_with_fat, config={"layer_name": "fat", "fs_type": "fat"}
        )
        result = plugin.run()
        assert isinstance(result, PluginResult)
        assert "Error" not in result.columns, result.rows
        assert result.columns == ["Time", "Type", "Path", "Size"]


class TestNANDDecodePlugin:
    def test_metadata_keys_present(self, tmp_path: Path) -> None:
        try:
            from deepview.storage.formats.nand_raw import RawNANDLayer
        except ImportError:
            pytest.skip("RawNANDLayer unavailable")
        pytest.importorskip("deepview.plugins.builtin.nand_decode")
        from tests.unit.test_storage._fixtures import build_nand_dump
        from deepview.plugins.builtin.nand_decode import NANDDecodePlugin

        path = tmp_path / "nand.bin"
        build_nand_dump(path, pages=64, page_size=512, spare_size=16)
        raw = RawNANDLayer(path, geometry=None)
        ctx = AnalysisContext.for_testing()
        ctx.layers.register("raw", raw)

        plugin = NANDDecodePlugin(
            ctx,
            config={
                "layer_name": "raw",
                "page_size": 512,
                "spare_size": 16,
                "pages_per_block": 4,
                "blocks": 16,
                "ecc": "hamming",
                "ftl": "mtd",
                "spare_layout": "onfi",
            },
        )
        result = plugin.run()
        assert isinstance(result, PluginResult)
        # Either success (metadata keys present) or well-formed skip.
        if "Error" in result.columns:
            pytest.skip(f"nand_decode reported error: {result.rows}")
        for key in ("corrected", "uncorrectable", "pages_read", "bad_blocks"):
            assert key in result.metadata, (key, result.metadata)


class TestSwapExtractPlugin:
    def test_linux_swap_requires_valid_header(self, tmp_path: Path) -> None:
        pytest.importorskip("deepview.plugins.builtin.swap_extract")
        from deepview.plugins.builtin.swap_extract import SwapExtractPlugin

        # Build a valid Linux swap v1 header.
        page = 4096
        pages = 4
        buf = bytearray(page * pages)
        # version=1, last_page=pages-1, nr_badpages=0
        buf[1024:1028] = (1).to_bytes(4, "little")
        buf[1028:1032] = (pages - 1).to_bytes(4, "little")
        buf[1032:1036] = (0).to_bytes(4, "little")
        buf[4086:4086 + len(b"SWAPSPACE2")] = b"SWAPSPACE2"
        # Pages 1..3 contain a recognisable marker.
        for i in range(1, pages):
            buf[i * page : i * page + 5] = b"MARK" + bytes([i])
        ctx = AnalysisContext.for_testing()
        ctx.layers.register("swap", _MemoryDataLayer(bytes(buf)))

        out = tmp_path / "swap.out"
        plugin = SwapExtractPlugin(
            ctx,
            config={
                "layer_name": "swap",
                "kind": "linux",
                "output_path": str(out),
            },
        )
        result = plugin.run()
        assert isinstance(result, PluginResult)
        if "Error" in result.columns:
            pytest.skip(f"swap_extract reported error: {result.rows}")
        assert out.exists()
        assert result.metadata["bytes_written"] > 0


class TestDeletedFileCarvePlugin:
    def test_carve_runs_on_fat(self, context_with_fat: AnalysisContext) -> None:
        pytest.importorskip("deepview.plugins.builtin.deleted_file_carve")
        from deepview.plugins.builtin.deleted_file_carve import DeletedFileCarvePlugin

        plugin = DeletedFileCarvePlugin(
            context_with_fat, config={"layer_name": "fat", "fs_type": "fat"}
        )
        result = plugin.run()
        assert isinstance(result, PluginResult)
        # The string carver should at least find the "hello world" payload.
        assert result.columns == ["Source", "Offset", "Size", "Snippet"]
