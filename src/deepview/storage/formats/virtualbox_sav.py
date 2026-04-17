"""VirtualBox saved-state (``.sav``) memory layer.

VirtualBox's SSM ("Saved State Machine") format begins with the magic bytes
``"SSM"`` followed by a header describing a sequence of tagged 8-byte-aligned
records. The full format is version-dependent and not formally documented;
this slice makes a best-effort attempt to locate the RAM region by scanning
for the "SSM RAM" unit tag near the top of the file. If the heuristic fails
we expose the whole file as a flat byte stream (fall-back passthrough) so
callers can still hex-inspect / YARA-scan it.
"""
from __future__ import annotations

import mmap
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from deepview.core.exceptions import FormatError
from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


_SSM_MAGIC = b"SSM"
# Signature that introduces a unit record in SSM v2.x. Used as a heuristic
# anchor to locate the start of a named unit. Empirically observed in
# VirtualBox SSM dumps; treated as a hint only.
_UNIT_SIG = b"\x00VBoxInternal"
# Tag substrings that identify the RAM region across VirtualBox versions.
_RAM_TAGS: tuple[bytes, ...] = (b"pgm", b"PGM", b"RAM", b"ram")


class VirtualBoxSavLayer(DataLayer):
    """SSM-prefixed VirtualBox saved state.

    Attempts to isolate the RAM sub-region; falls back to a flat passthrough
    if the header cannot be confidently parsed. The parse fall-back is
    surfaced via ``parsed_ram`` and ``metadata.name``.
    """

    def __init__(self, path: Path, name: str = "") -> None:
        self._path = path
        self._name = name or "virtualbox_sav"
        self._size = path.stat().st_size
        self._file: BinaryIO | None = open(path, "rb")
        self._mmap: mmap.mmap | None = None
        if self._size > 0:
            self._mmap = mmap.mmap(
                self._file.fileno(), 0, access=mmap.ACCESS_READ
            )

        head = self._peek(0, 16)
        if not head.startswith(_SSM_MAGIC):
            raise FormatError(
                f"Not a VirtualBox SSM file (bad magic: {head[:3]!r})"
            )

        # Try to locate the RAM region. On failure, keep everything.
        self._ram_offset, self._ram_size, self._parsed_ram = self._locate_ram()

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _peek(self, offset: int, length: int) -> bytes:
        if self._mmap is None:
            return b""
        if offset < 0 or offset >= self._size:
            return b""
        end = min(offset + length, self._size)
        return bytes(self._mmap[offset:end])

    def _locate_ram(self) -> tuple[int, int, bool]:
        """Return ``(file_offset, size, parsed_successfully)``.

        The default is the whole file: ``(0, size, False)``. The heuristic
        looks for a unit-descriptor string that contains one of ``_RAM_TAGS``
        and, if found, assumes the RAM payload follows it; we cap the size
        at whatever bytes remain in the file.
        """
        if self._mmap is None or self._size == 0:
            return 0, self._size, False
        # Scan only a reasonable slice of the header region — the RAM tag
        # always sits near the start of the saved state on observed dumps.
        scan_limit = min(self._size, 4 * 1024 * 1024)
        window = bytes(self._mmap[0:scan_limit])
        best: int | None = None
        for tag in _RAM_TAGS:
            needle = _UNIT_SIG + b"/"
            # First try the structured path "\x00VBoxInternal/<Component>/<Tag>".
            idx = 0
            while True:
                idx = window.find(needle, idx)
                if idx < 0:
                    break
                # Look within a 128-byte window after the prefix for the tag.
                tail = window[idx : idx + 128]
                if tag in tail:
                    # Heuristic: RAM payload starts at the next 16-byte boundary
                    # after the null-terminated unit name. Find the trailing NUL.
                    nul = window.find(b"\x00", idx + 1)
                    if nul > 0:
                        candidate = (nul + 16) & ~0xF
                        if best is None or candidate < best:
                            best = candidate
                idx += len(needle)
        if best is None or best >= self._size:
            return 0, self._size, False
        return best, self._size - best, True

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        if offset < 0 or offset >= self._ram_size:
            return b"\x00" * length if pad else b""
        file_start = self._ram_offset + offset
        file_end = min(file_start + length, self._ram_offset + self._ram_size)
        if self._mmap is None:
            return b"\x00" * length if pad else b""
        data = bytes(self._mmap[file_start:file_end])
        if pad and len(data) < length:
            data += b"\x00" * (length - len(data))
        return data

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("VirtualBoxSavLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return (
            offset >= 0
            and length >= 0
            and offset + length <= self._ram_size
        )

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        if self._mmap is None or self._ram_size == 0:
            return
        chunk_size = 4 * 1024 * 1024
        overlap = 4096
        offset = 0
        while offset < self._ram_size:
            end = min(offset + chunk_size, self._ram_size)
            file_start = self._ram_offset + offset
            file_end = self._ram_offset + end
            chunk = bytes(self._mmap[file_start:file_end])
            for result in scanner.scan(chunk, offset=offset):
                yield result
            if progress_callback is not None:
                progress_callback(end / self._ram_size)
            offset = end - overlap if end < self._ram_size else end

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(self._ram_size - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        suffix = " (ram)" if self._parsed_ram else " (flat)"
        return LayerMetadata(
            name=self._name + suffix,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    @property
    def parsed_ram(self) -> bool:
        """True if the RAM region was located; False for flat-passthrough."""
        return self._parsed_ram

    @property
    def ram_offset(self) -> int:
        return self._ram_offset

    @property
    def ram_size(self) -> int:
        return self._ram_size

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self._mmap is not None:
            try:
                self._mmap.close()
            except ValueError:
                pass
            self._mmap = None
        if self._file is not None:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None

    def __enter__(self) -> VirtualBoxSavLayer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

