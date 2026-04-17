"""Edge-case tests for :class:`UnlockOrchestrator`.

Complements ``test_unlock_orchestrator.py`` — focuses on key-length
filtering, detect() fail-open behaviour, source priority ordering, and
the exact event surface emitted on success / failure. Builtin adapter
auto-discovery is disabled per test by overriding ``_discover_builtin``
so the orchestrator only sees the injected :class:`FakeUnlocker`.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from tests._factories import (  # noqa: E402
    FakeUnlocker,
    MemoryDataLayer,
)

from deepview.core.events import (  # noqa: E402
    ContainerUnlockedEvent,
    ContainerUnlockFailedEvent,
    ContainerUnlockStartedEvent,
)
from deepview.storage.containers.unlock import (  # noqa: E402
    ContainerHeader,
    MasterKey,
    UnlockOrchestrator,
)


def _make_header(*, dklen: int = 32) -> ContainerHeader:
    return ContainerHeader(
        format="fake",
        cipher="aes-xts-plain64",
        sector_size=512,
        data_offset=0,
        data_length=4096,
        kdf="none",
        kdf_params={"dklen": dklen},
        raw=b"",
    )


def _make_orchestrator(context, unlocker) -> UnlockOrchestrator:
    """Build an orchestrator with builtin auto-discovery suppressed."""
    # Suppress the sibling-module import walk that _discover_builtin
    # triggers so the test is isolated from whatever real adapters ship.
    UnlockOrchestrator._discover_builtin = lambda self: None  # type: ignore[method-assign]
    orch = UnlockOrchestrator(context)
    orch.register(unlocker)
    # Offload engine isn't needed because MasterKey.derive ignores it,
    # but stash a sentinel so nothing inadvertently constructs the real
    # engine during teardown.
    context._offload_engine = object()  # type: ignore[attr-defined]
    return orch


def test_master_key_length_filter_skips_mismatched_keys(context) -> None:
    """Master keys whose length != header.kdf_params['dklen'] are skipped."""
    backing = MemoryDataLayer(b"\x11" * 4096, name="disk")
    good_a = MasterKey(key=b"A" * 32)
    good_b = MasterKey(key=b"B" * 32)
    bad = MasterKey(key=b"C" * 16)

    fake = FakeUnlocker("fake", header=_make_header(dklen=32),
                       accept_keys=[good_a.key])
    orch = _make_orchestrator(context, fake)

    orch._collect_memory_keys = lambda: [bad, good_a, good_b]  # type: ignore[method-assign]

    results = asyncio.run(orch.auto_unlock(backing, scan_keys=True))

    assert len(results) == 1
    # Only the 32-byte keys should have reached the unlocker. Because
    # good_a unlocks successfully we expect the loop to stop there.
    tried_keys = [key for (_src, key) in fake.unlock_calls]
    assert bad.key not in tried_keys
    assert tried_keys == [good_a.key]


def test_detect_exception_is_fail_open(context, caplog) -> None:
    """An unlocker whose detect() raises must be logged and skipped."""
    backing = MemoryDataLayer(b"\x22" * 2048, name="disk")
    first = FakeUnlocker("boomer",
                        detect_error=RuntimeError("boom"))
    # A second unlocker that would succeed — proves the orchestrator
    # continues past the failed detect().
    second = FakeUnlocker("fake", header=_make_header(dklen=32),
                          accept_keys=[b"k" * 32])

    UnlockOrchestrator._discover_builtin = lambda self: None  # type: ignore[method-assign]
    orch = UnlockOrchestrator(context)
    orch.register(first)
    orch.register(second)
    context._offload_engine = object()  # type: ignore[attr-defined]

    orch._collect_memory_keys = lambda: [MasterKey(key=b"k" * 32)]  # type: ignore[method-assign]

    with caplog.at_level(logging.INFO, logger="deepview.storage.containers.unlock"):
        results = asyncio.run(orch.auto_unlock(backing, scan_keys=True))

    assert len(results) == 1
    assert first.detect_calls == 1
    assert first.unlock_calls == []
    assert second.detect_calls == 1
    # The orchestrator logs at INFO when detect() raises.
    assert any("detect() raised" in rec.message for rec in caplog.records)


def test_source_priority_order_master_keyfile_passphrase(
    context, tmp_path: Path
) -> None:
    """Sources are tried master_key → keyfile → passphrase."""
    backing = MemoryDataLayer(b"\x33" * 2048, name="disk")
    # Accept none of the keys — we only want to capture the try order.
    fake = FakeUnlocker("fake", header=_make_header(dklen=32),
                        accept_keys=[b"never-matches"])
    orch = _make_orchestrator(context, fake)

    # Stub the offload path the Passphrase uses so the derive call
    # doesn't actually invoke a real KDF — raising from derive is fine,
    # the orchestrator treats it the same as a rejected key (continues).
    keyfile = tmp_path / "kf.bin"
    keyfile.write_bytes(b"keyfile-bytes")

    mk = MasterKey(key=b"M" * 32)
    orch._collect_memory_keys = lambda: [mk]  # type: ignore[method-assign]

    # Passphrase.derive will try to use the offload engine; we install
    # a stub that raises so it's treated as a failed attempt — but the
    # orchestrator only records the unlocker's own unlock_calls via
    # FakeUnlocker, which derives through the source synchronously.
    # For the FakeUnlocker the source.derive(None, header) is called
    # directly, so we just need the KeySource objects not to explode
    # before unlock_calls is appended. MasterKey + Keyfile are fine;
    # Passphrase's derive reaches into engine.submit — we short-circuit
    # by monkey-patching the orchestrator's ordering loop observation
    # via the source kinds recorded on unlock_calls.
    #
    # Simpler: swap Passphrase with a lightweight source that behaves
    # like the real one. We do that by importing Passphrase and
    # overriding its derive on the specific instance the orchestrator
    # constructs — easiest is to monkey-patch the class method for the
    # duration of the test.
    from deepview.storage.containers.unlock import Passphrase

    async def _fake_pp_derive(self, engine, header):  # type: ignore[no-untyped-def]
        return b"P" * 32

    orig = Passphrase.derive
    Passphrase.derive = _fake_pp_derive  # type: ignore[assignment]
    try:
        asyncio.run(orch.auto_unlock(
            backing,
            passphrases=["pw"],
            keyfiles=[keyfile],
            scan_keys=True,
        ))
    finally:
        Passphrase.derive = orig  # type: ignore[assignment]

    # Recorded tuples are (source, key_bytes). The source types reflect
    # the ordering the orchestrator used.
    kinds = [type(src).__name__ for (src, _k) in fake.unlock_calls]
    assert kinds == ["MasterKey", "Keyfile", "Passphrase"]


def test_all_sources_exhausted_publishes_failed_event(context) -> None:
    """Failure path: ContainerUnlockFailedEvent.reason == 'all candidate keys exhausted'."""
    backing = MemoryDataLayer(b"\x44" * 2048, name="disk")
    fake = FakeUnlocker("fake", header=_make_header(dklen=32),
                        accept_keys=[b"nothing-matches"])
    orch = _make_orchestrator(context, fake)

    orch._collect_memory_keys = lambda: [MasterKey(key=b"M" * 32)]  # type: ignore[method-assign]

    failed: list[ContainerUnlockFailedEvent] = []
    unlocked: list[ContainerUnlockedEvent] = []
    context.events.subscribe(ContainerUnlockFailedEvent, lambda e: failed.append(e))
    context.events.subscribe(ContainerUnlockedEvent, lambda e: unlocked.append(e))

    results = asyncio.run(orch.auto_unlock(backing, scan_keys=True))

    assert results == []
    assert unlocked == []
    assert len(failed) == 1
    assert failed[0].format == "fake"
    assert failed[0].layer == "disk"
    assert failed[0].reason == "all candidate keys exhausted"


def test_success_publishes_started_then_unlocked_in_order(context) -> None:
    """On success: ContainerUnlockStartedEvent fires before ContainerUnlockedEvent."""
    backing = MemoryDataLayer(b"\x55" * 2048, name="disk")
    fake = FakeUnlocker("fake", header=_make_header(dklen=32),
                        accept_keys=[b"K" * 32])
    orch = _make_orchestrator(context, fake)

    orch._collect_memory_keys = lambda: [MasterKey(key=b"K" * 32)]  # type: ignore[method-assign]

    seen: list[str] = []
    context.events.subscribe(
        ContainerUnlockStartedEvent,
        lambda e: seen.append(f"started:{e.format}:{e.key_source}"),
    )
    context.events.subscribe(
        ContainerUnlockedEvent,
        lambda e: seen.append(f"unlocked:{e.format}:{e.produced_layer}"),
    )

    results = asyncio.run(orch.auto_unlock(backing, scan_keys=True))

    assert len(results) == 1
    assert seen == [
        "started:fake:master_key",
        "unlocked:fake:unlocked:fake",
    ]
