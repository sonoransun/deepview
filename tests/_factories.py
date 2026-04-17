"""Shared test factories for Deep View test modules.

Hub for cross-subsystem helpers so tests can focus on behavior rather than
re-inventing in-memory DataLayer shims, partition-table builders, and
fake KeySource / Unlocker classes. Keep genuinely storage-specific
builders in ``tests/unit/test_storage/_fixtures.py``; put anything that
crosses subsystem boundaries here.

Public API:

- :class:`MemoryDataLayer` — in-memory :class:`DataLayer` conforming to
  the contract (``read`` returns exactly N bytes, OOB raises unless
  ``pad=True``, ``write`` refused).
- :func:`build_mbr` / :func:`build_gpt` — minimal byte-exact partition
  table builders; pair nicely with :class:`MemoryDataLayer`.
- :class:`FakeEventBus` — records published events; supports
  subscribe / unsubscribe / publish with the same surface as
  :class:`deepview.core.events.EventBus`.
- :class:`FakeKeySource`, :class:`FakeUnlocker` — parameterised
  helpers for testing :class:`~deepview.storage.containers.unlock.UnlockOrchestrator`.
- :func:`synthetic_encrypted_volume` — round-trip-encrypt a plaintext
  buffer and return a backing :class:`MemoryDataLayer` + expected
  plaintext, suitable for :class:`DecryptedVolumeLayer` tests.
"""
from __future__ import annotations

import struct
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from deepview.core.events import Event
from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer


# ---------------------------------------------------------------------------
# MemoryDataLayer
# ---------------------------------------------------------------------------


class MemoryDataLayer(DataLayer):
    """In-memory :class:`DataLayer` backed by a single ``bytes`` buffer.

    Replaces the five local duplicates across
    ``test_storage_plugins.py``, ``test_volume_unlock_plugin.py``,
    ``test_unlock_orchestrator.py``, etc. Honours the full DataLayer
    contract so regression tests on read/pad/OOB stay consistent.
    """

    def __init__(self, data: bytes, *, name: str = "memory") -> None:
        self._data = bytes(data)
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        if length == 0:
            return b""
        end = offset + length
        size = len(self._data)
        if end > size:
            if pad:
                head = self._data[max(offset, 0) : size] if offset < size else b""
                return head + b"\x00" * (length - len(head))
            raise ValueError(
                f"read out of bounds: offset={offset} length={length} size={size}"
            )
        return self._data[offset:end]

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("MemoryDataLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        return offset + length <= len(self._data)

    def scan(
        self,
        scanner: Any,  # PatternScanner duck-type
        progress_callback: Callable[..., None] | None = None,
    ) -> Iterator[ScanResult]:
        method = getattr(scanner, "scan", None)
        if method is None:
            return iter(())
        return method(self._data, offset=0)

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(len(self._data) - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )


# ---------------------------------------------------------------------------
# Partition table builders
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MBREntry:
    """One MBR partition entry. All LBAs are 512-byte sectors."""

    type_byte: int = 0x83  # Linux by default
    start_lba: int = 2048
    sector_count: int = 2048
    boot: bool = False


def build_mbr(entries: list[MBREntry] | list[tuple[int, int, int]]) -> bytes:
    """Return a valid 512-byte MBR sector with up to 4 partition entries.

    *entries* may be either :class:`MBREntry` instances or the
    3-tuple shorthand ``(type_byte, start_lba, sector_count)``.
    """
    if len(entries) > 4:
        raise ValueError("MBR supports at most 4 primary partitions")
    sector = bytearray(512)
    for i, entry in enumerate(entries):
        if isinstance(entry, tuple):
            entry = MBREntry(
                type_byte=entry[0],
                start_lba=entry[1],
                sector_count=entry[2],
            )
        base = 446 + i * 16
        sector[base] = 0x80 if entry.boot else 0x00
        # CHS fields left zero; BIOS uses LBA.
        sector[base + 4] = entry.type_byte & 0xFF
        struct.pack_into("<I", sector, base + 8, entry.start_lba)
        struct.pack_into("<I", sector, base + 12, entry.sector_count)
    sector[510] = 0x55
    sector[511] = 0xAA
    return bytes(sector)


@dataclass(frozen=True)
class GPTEntry:
    """One GPT partition entry.

    ``type_guid`` is a :class:`uuid.UUID` identifying the partition type
    (e.g. Linux filesystem = ``0FC63DAF-8483-4772-8E79-3D69D8477DE4``).
    """

    type_guid: uuid.UUID
    first_lba: int
    last_lba: int
    name: str = ""
    unique_guid: uuid.UUID = field(
        default_factory=lambda: uuid.uuid4()
    )


def build_gpt(
    entries: list[GPTEntry],
    *,
    num_entry_slots: int = 128,
    entry_size: int = 128,
) -> bytes:
    """Return a GPT header + entry array suitable for testing.

    The output is ``512`` (protective-ignorable) + ``512`` (header) +
    ``num_entry_slots * entry_size`` bytes. *entries* populates the
    first ``len(entries)`` slots; remaining slots are zeroed. Includes
    the EFI PART signature and minimal field set; CRC fields are left
    zero — :func:`deepview.storage.partition.parse_partitions` does not
    validate CRCs.
    """
    header = bytearray(92)
    header[0:8] = b"EFI PART"
    # partition_entries_lba = 2, num_entries, entry_size
    struct.pack_into("<Q", header, 72, 2)
    struct.pack_into("<I", header, 80, num_entry_slots)
    struct.pack_into("<I", header, 84, entry_size)

    table = bytearray(num_entry_slots * entry_size)
    for i, entry in enumerate(entries):
        base = i * entry_size
        table[base : base + 16] = entry.type_guid.bytes_le
        table[base + 16 : base + 32] = entry.unique_guid.bytes_le
        struct.pack_into("<Q", table, base + 32, entry.first_lba)
        struct.pack_into("<Q", table, base + 40, entry.last_lba)
        name_bytes = entry.name.encode("utf-16-le")[: 72]
        table[base + 56 : base + 56 + len(name_bytes)] = name_bytes

    # Prepend an empty protective MBR sector so the disk image is
    # well-formed; parse_partitions ignores it once it finds GPT.
    return bytes(512) + bytes(header) + bytes(512 - len(header)) + bytes(table)


LINUX_FS_TYPE = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
EFI_SYSTEM_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")


# ---------------------------------------------------------------------------
# FakeEventBus
# ---------------------------------------------------------------------------


class FakeEventBus:
    """Drop-in replacement for :class:`EventBus` that records every publish.

    Only the public surface (``subscribe`` / ``unsubscribe`` /
    ``publish``) is implemented; ``subscribe_async`` / ``publish_async``
    are delegated to the sync path (tests that need true async
    behaviour should use a real ``EventBus``).
    """

    def __init__(self) -> None:
        self.events: list[Event] = []
        self._handlers: dict[type[Event], list[Callable[..., None]]] = defaultdict(list)

    def subscribe(
        self, event_type: type[Event], handler: Callable[..., None]
    ) -> None:
        self._handlers[event_type].append(handler)

    def subscribe_async(
        self, event_type: type[Event], handler: Callable[..., None]
    ) -> None:
        # Tests that rely on async fan-out should use a real EventBus.
        self.subscribe(event_type, handler)

    def unsubscribe(
        self, event_type: type[Event], handler: Callable[..., None]
    ) -> None:
        if handler in self._handlers.get(event_type, []):
            self._handlers[event_type].remove(handler)

    def publish(self, event: Event) -> None:
        self.events.append(event)
        for event_type, handlers in list(self._handlers.items()):
            if isinstance(event, event_type):
                for handler in list(handlers):
                    handler(event)

    async def publish_async(self, event: Event) -> None:
        self.publish(event)

    def events_of(self, event_type: type[Event]) -> list[Event]:
        """Return recorded events whose concrete type matches *event_type*."""
        return [e for e in self.events if isinstance(e, event_type)]

    def clear(self) -> None:
        self.events.clear()


# ---------------------------------------------------------------------------
# Container unlock helpers
# ---------------------------------------------------------------------------


class FakeKeySource:
    """Record-keeping :class:`KeySource` that returns a fixed key or raises.

    Usage::

        src = FakeKeySource("master", keys=[b"k" * 32])
        src = FakeKeySource("passphrase", error=RuntimeError("kdf blew up"))
    """

    def __init__(
        self,
        name: str,
        *,
        keys: list[bytes] | None = None,
        error: BaseException | None = None,
    ) -> None:
        self.name = name
        self._keys = list(keys or [])
        self._error = error
        self.derive_calls: list[Any] = []

    async def derive(self, engine: Any, header: Any) -> bytes:
        self.derive_calls.append((engine, header))
        if self._error is not None:
            raise self._error
        if not self._keys:
            raise RuntimeError(f"FakeKeySource {self.name!r} exhausted")
        return self._keys.pop(0)


class FakeUnlocker:
    """Deterministic :class:`Unlocker` for orchestrator tests.

    Parameters:
        format_name: value for :attr:`format_name`.
        header: :class:`ContainerHeader` returned by ``detect``, or ``None``
            to simulate "format not detected".
        accept_keys: iterable of key bytes that ``unlock`` accepts;
            anything else raises ``RuntimeError``.
        detect_error: optional exception raised by ``detect``.
    """

    format_name = ""

    def __init__(
        self,
        format_name: str,
        *,
        header: Any = None,
        accept_keys: list[bytes] | None = None,
        detect_error: BaseException | None = None,
    ) -> None:
        self.format_name = format_name
        self._header = header
        self._accept_keys = list(accept_keys or [])
        self._detect_error = detect_error
        self.detect_calls: int = 0
        self.unlock_calls: list[tuple[Any, bytes]] = []

    def detect(self, layer: Any, offset: int = 0) -> Any:
        self.detect_calls += 1
        if self._detect_error is not None:
            raise self._detect_error
        return self._header

    async def unlock(
        self,
        layer: Any,
        header: Any,
        source: Any,
        *,
        try_hidden: bool = False,
    ) -> Any:
        from deepview.offload.engine import OffloadEngine  # local to avoid cycle
        # engine may be whatever the orchestrator provides; we only need the
        # derived key, not the engine itself.
        del OffloadEngine
        key = await source.derive(None, header)  # type: ignore[arg-type]
        self.unlock_calls.append((source, key))
        if self._accept_keys and key not in self._accept_keys:
            raise RuntimeError(f"{self.format_name}: key rejected")
        # Return a sentinel "unlocked" object with a .metadata.name for the
        # orchestrator's ContainerUnlockedEvent payload.
        return _UnlockedSentinel(name=f"unlocked:{self.format_name}")


@dataclass(frozen=True)
class _UnlockedSentinel:
    """Minimal stand-in for a :class:`DecryptedVolumeLayer`."""

    name: str

    @property
    def metadata(self) -> Any:
        return self

    def __getattr__(self, item: str) -> Any:
        # Treat any unexpected attribute access as absent, so the
        # orchestrator's metadata.name lookup works without pulling in
        # the full DecryptedVolumeLayer surface.
        raise AttributeError(item)


# ---------------------------------------------------------------------------
# Synthetic encrypted volume (AES-XTS round-trip)
# ---------------------------------------------------------------------------


def synthetic_encrypted_volume(
    plaintext: bytes,
    *,
    key: bytes = b"k" * 64,  # AES-256-XTS needs 64 bytes
    sector_size: int = 512,
) -> tuple[MemoryDataLayer, bytes]:
    """Encrypt *plaintext* sector-by-sector with AES-XTS and return the
    backing :class:`MemoryDataLayer` + the original plaintext.

    Requires the ``cryptography`` extra; callers guard with
    ``pytest.importorskip('cryptography')``.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(plaintext) % sector_size != 0:
        pad = sector_size - (len(plaintext) % sector_size)
        plaintext = plaintext + b"\x00" * pad

    ciphertext = bytearray()
    for sector_idx in range(len(plaintext) // sector_size):
        tweak = sector_idx.to_bytes(16, "little")
        cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
        enc = cipher.encryptor()
        start = sector_idx * sector_size
        ciphertext.extend(enc.update(plaintext[start : start + sector_size]))

    return MemoryDataLayer(bytes(ciphertext), name="xts-backing"), plaintext


__all__ = [
    "MemoryDataLayer",
    "MBREntry",
    "GPTEntry",
    "build_mbr",
    "build_gpt",
    "LINUX_FS_TYPE",
    "EFI_SYSTEM_TYPE",
    "FakeEventBus",
    "FakeKeySource",
    "FakeUnlocker",
    "synthetic_encrypted_volume",
]
