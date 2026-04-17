"""Tests for the ``deepview storage`` CLI group."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import click
import pytest
from click.testing import CliRunner
from rich.console import Console

from deepview.cli.commands.storage import storage
from deepview.core.context import AnalysisContext
from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer


class _MemoryDataLayer(DataLayer):
    """Minimal in-memory DataLayer for exercising storage CLI plumbing."""

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


def _make_runner_with_context(
    context: AnalysisContext,
) -> tuple[CliRunner, click.Group]:
    """Wrap the ``storage`` group in a root Click group that injects context."""

    @click.group()
    @click.pass_context
    def _root(ctx: click.Context) -> None:
        ctx.ensure_object(dict)
        ctx.obj["context"] = context
        ctx.obj["console"] = Console(record=True, width=200)

    _root.add_command(storage)
    return CliRunner(), _root


class TestStorageList:
    def test_list_on_empty_registry(self) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["storage", "list"])
        assert result.exit_code == 0, result.output
        assert "Registered layers" in result.output
        assert "Filesystem adapters" in result.output
        assert "FTL translators" in result.output
        assert "ECC decoders" in result.output

    def test_list_reports_registered_layer(self) -> None:
        ctx = AnalysisContext.for_testing()
        ctx.layers.register("demo", _MemoryDataLayer(b"\x00" * 32))
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["storage", "list"])
        assert result.exit_code == 0, result.output
        assert "demo" in result.output


class TestStorageInfo:
    def test_info_unknown_layer_aborts(self) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["storage", "info", "--layer", "nope"])
        assert result.exit_code != 0
        assert "Layer not found" in result.output

    def test_info_on_fat_image_hits_fat_adapter(self) -> None:
        pytest.importorskip("deepview.storage.filesystems.fat_native")
        from tests.unit.test_storage.test_filesystems.test_fat_native import _build_image

        ctx = AnalysisContext.for_testing()
        ctx.layers.register("fat", _MemoryDataLayer(_build_image()))
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["storage", "info", "--layer", "fat"])
        assert result.exit_code == 0, result.output
        # The FAT adapter should always register and probe successfully here.
        assert "filesystem:fat" in result.output


class TestStorageWrap:
    def _build_minimal_nand(self, tmp_path: Path) -> Path:
        from tests.unit.test_storage._fixtures import build_nand_dump

        path = tmp_path / "nand.bin"
        # 4 blocks * 4 pages * 512 bytes data + 16 spare = tiny but valid.
        build_nand_dump(path, pages=16, page_size=512, spare_size=16)
        return path

    def test_wrap_registers_output_layer(self, tmp_path: Path) -> None:
        # Use RawNANDLayer if available so we go through a real composition.
        try:
            from deepview.storage.formats.nand_raw import RawNANDLayer
        except ImportError:
            pytest.skip("RawNANDLayer unavailable")

        nand_path = self._build_minimal_nand(tmp_path)
        # Flat-file raw layer (no geometry — CLI rebuilds geometry anyway).
        raw = RawNANDLayer(nand_path, geometry=None)
        ctx = AnalysisContext.for_testing()
        ctx.layers.register("raw", raw)

        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(
            root,
            [
                "storage",
                "wrap",
                "--layer",
                "raw",
                "--out",
                "wrapped",
                # No --ecc/--ftl -> wrap_nand returns the backing layer
                # unchanged, which is the simplest successful path.
                "--page-size",
                "512",
                "--spare-size",
                "16",
                "--pages-per-block",
                "4",
                "--blocks",
                "4",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "wrapped" in ctx.layers.list_layers()

    def test_wrap_unknown_layer_aborts(self) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(
            root,
            ["storage", "wrap", "--layer", "nope", "--out", "x"],
        )
        assert result.exit_code != 0


class TestStorageMount:
    def test_mount_fat_layer_registers_handle(self) -> None:
        pytest.importorskip("deepview.storage.filesystems.fat_native")
        from tests.unit.test_storage.test_filesystems.test_fat_native import _build_image

        ctx = AnalysisContext.for_testing()
        ctx.layers.register("fat", _MemoryDataLayer(_build_image()))
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(
            root, ["storage", "mount", "--layer", "fat", "--fs", "fat"]
        )
        assert result.exit_code == 0, result.output
        assert ctx.layers.has("fat-fs")
