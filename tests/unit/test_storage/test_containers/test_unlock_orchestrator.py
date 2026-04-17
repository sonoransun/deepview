"""Tests for :class:`UnlockOrchestrator` via a fake :class:`Unlocker`."""
from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from typing import ClassVar

import pytest

pytest.importorskip("cryptography")

from deepview.core.context import AnalysisContext  # noqa: E402
from deepview.core.events import (  # noqa: E402
    ContainerUnlockedEvent,
    ContainerUnlockFailedEvent,
)
from deepview.core.types import LayerMetadata, ScanResult  # noqa: E402
from deepview.interfaces.layer import DataLayer  # noqa: E402
from deepview.storage.containers.layer import DecryptedVolumeLayer  # noqa: E402
from deepview.storage.containers.unlock import (  # noqa: E402
    ContainerHeader,
    KeySource,
    MasterKey,
    Unlocker,
    UnlockOrchestrator,
)


class MemoryDataLayer(DataLayer):
    """In-memory DataLayer shim used for all tests in this module."""

    def __init__(self, data: bytes, name: str = "mem") -> None:
        self._data = bytes(data)
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
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


class FakeUnlocker(Unlocker):
    """Always detects; unlocks only for :class:`MasterKey`."""

    format_name: ClassVar[str] = "fake"

    def __init__(self) -> None:
        self.attempts: list[str] = []

    def detect(
        self, layer: DataLayer, offset: int = 0
    ) -> ContainerHeader | None:
        return ContainerHeader(
            format="fake",
            cipher="aes-xts-plain64",
            sector_size=512,
            data_offset=0,
            data_length=layer.maximum_address + 1,
            kdf="none",
            kdf_params={"dklen": 32},
            raw=b"",
        )

    async def unlock(
        self,
        layer: DataLayer,
        header: ContainerHeader,
        source: KeySource,
        *,
        try_hidden: bool = False,
    ) -> DecryptedVolumeLayer:
        self.attempts.append(type(source).__name__)
        if not isinstance(source, MasterKey):
            raise ValueError("FakeUnlocker only accepts MasterKey")
        # Provide a DecryptedVolumeLayer over the same backing layer.
        return DecryptedVolumeLayer(
            layer,
            cipher_name="aes",
            key=source.key,
            sector_size=512,
            data_offset=0,
            data_length=header.data_length,
            mode="xts",
            iv_mode="tweak",
            name="fake-plain",
        )


def _make_ctx_without_offload() -> AnalysisContext:
    """Return an AnalysisContext whose ``offload`` is stubbed out.

    The offload subsystem isn't required by the orchestrator tests
    (MasterKey.derive ignores it), so we install a harmless sentinel so
    even importing the real engine module is avoided.
    """
    ctx = AnalysisContext.for_testing()
    ctx._offload_engine = object()  # type: ignore[assignment]
    return ctx


def test_auto_unlock_with_master_key_succeeds() -> None:
    ctx = _make_ctx_without_offload()
    # Register a 2 KiB blob as the "encrypted" backing layer.
    backing = MemoryDataLayer(b"\x11" * 2048, name="disk")
    ctx.layers.register("disk", backing)

    orch = UnlockOrchestrator(ctx)
    fake = FakeUnlocker()
    orch.register(fake)

    # Collect events.
    unlocked_events: list[ContainerUnlockedEvent] = []
    failed_events: list[ContainerUnlockFailedEvent] = []
    ctx.events.subscribe(
        ContainerUnlockedEvent, lambda e: unlocked_events.append(e)
    )
    ctx.events.subscribe(
        ContainerUnlockFailedEvent, lambda e: failed_events.append(e)
    )

    # Stage a MasterKey candidate via the memory-key path. We bypass
    # `_collect_memory_keys` by passing `scan_keys=False` and manually
    # wiring a MasterKey through the passphrase/keyfile list isn't
    # allowed — so we monkey-patch `_collect_memory_keys`.
    orch._collect_memory_keys = lambda: [MasterKey(key=bytes(range(32)))]  # type: ignore[method-assign]

    results = asyncio.run(
        orch.auto_unlock(backing, passphrases=(), scan_keys=True)
    )

    assert len(results) == 1
    assert isinstance(results[0], DecryptedVolumeLayer)
    assert results[0].metadata.name == "fake-plain"
    assert len(unlocked_events) == 1
    assert unlocked_events[0].format == "fake"
    assert unlocked_events[0].layer == "disk"
    assert unlocked_events[0].produced_layer == "fake-plain"
    assert failed_events == []
    assert fake.attempts == ["MasterKey"]


def test_auto_unlock_with_no_candidates_emits_failure() -> None:
    ctx = _make_ctx_without_offload()
    backing = MemoryDataLayer(b"\x22" * 2048, name="disk2")

    orch = UnlockOrchestrator(ctx)
    orch.register(FakeUnlocker())

    failed_events: list[ContainerUnlockFailedEvent] = []
    unlocked_events: list[ContainerUnlockedEvent] = []
    ctx.events.subscribe(
        ContainerUnlockFailedEvent, lambda e: failed_events.append(e)
    )
    ctx.events.subscribe(
        ContainerUnlockedEvent, lambda e: unlocked_events.append(e)
    )

    results = asyncio.run(
        orch.auto_unlock(backing, passphrases=(), scan_keys=False)
    )

    assert results == []
    assert unlocked_events == []
    assert len(failed_events) == 1
    assert failed_events[0].format == "fake"
    assert failed_events[0].layer == "disk2"


def test_available_unlockers_reports_names() -> None:
    ctx = _make_ctx_without_offload()
    orch = UnlockOrchestrator(ctx)
    # Clear auto-discovered modules (none exist yet anyway).
    orch._unlockers.clear()
    orch.register(FakeUnlocker())
    assert orch.available_unlockers() == ["fake"]
