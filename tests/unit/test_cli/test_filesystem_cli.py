"""Tests for the ``deepview filesystem`` CLI group."""
from __future__ import annotations

from collections.abc import Callable, Iterator

import click
import pytest
from click.testing import CliRunner
from rich.console import Console

from deepview.cli.commands.filesystem import filesystem as filesystem_cmd
from deepview.core.context import AnalysisContext
from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer


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


def _make_root(context: AnalysisContext) -> tuple[CliRunner, click.Group]:
    @click.group()
    @click.pass_context
    def _root(ctx: click.Context) -> None:
        ctx.ensure_object(dict)
        ctx.obj["context"] = context
        ctx.obj["console"] = Console(record=True, width=200)

    _root.add_command(filesystem_cmd)
    return CliRunner(), _root


@pytest.fixture
def fat_context() -> AnalysisContext:
    pytest.importorskip("deepview.storage.filesystems.fat_native")
    from tests.unit.test_storage.test_filesystems.test_fat_native import _build_image

    ctx = AnalysisContext.for_testing()
    ctx.layers.register("fat", _MemoryDataLayer(_build_image()))
    return ctx


class TestFilesystemLS:
    def test_ls_root_shows_hello_txt(self, fat_context: AnalysisContext) -> None:
        runner, root = _make_root(fat_context)
        result = runner.invoke(
            root, ["filesystem", "ls", "--layer", "fat", "--fs-type", "fat"]
        )
        assert result.exit_code == 0, result.output
        assert "HELLO.TXT" in result.output

    def test_ls_auto_probe_finds_fat(self, fat_context: AnalysisContext) -> None:
        runner, root = _make_root(fat_context)
        result = runner.invoke(root, ["filesystem", "ls", "--layer", "fat"])
        assert result.exit_code == 0, result.output
        assert "HELLO.TXT" in result.output

    def test_ls_unknown_layer_aborts(self) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_root(ctx)
        result = runner.invoke(root, ["filesystem", "ls", "--layer", "nope"])
        assert result.exit_code != 0


class TestFilesystemStat:
    def test_stat_hello_txt(self, fat_context: AnalysisContext) -> None:
        runner, root = _make_root(fat_context)
        result = runner.invoke(
            root,
            [
                "filesystem",
                "stat",
                "--layer",
                "fat",
                "--fs-type",
                "fat",
                "--path",
                "/HELLO.TXT",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "HELLO.TXT" in result.output
        assert "size" in result.output


class TestFilesystemFind:
    def test_find_glob(self, fat_context: AnalysisContext) -> None:
        runner, root = _make_root(fat_context)
        result = runner.invoke(
            root,
            [
                "filesystem",
                "find",
                "--layer",
                "fat",
                "--fs-type",
                "fat",
                "--pattern",
                "*.TXT",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "HELLO.TXT" in result.output
