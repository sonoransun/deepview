"""Multi-encoding string carver with entropy-based filtering.

Extracts printable strings from memory in multiple encodings, skipping
high-entropy regions that are likely encrypted or compressed.

References:
    - Unicode Consortium encoding specifications
    - ICU character detection algorithms
    - Mandiant FLOSS (FLARE Obfuscated String Solver)
"""
from __future__ import annotations

import math
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.types import ScanResult

if TYPE_CHECKING:
    from deepview.interfaces.layer import DataLayer


# Chunk size for layer scanning (4 MiB with 1 KiB overlap)
_CHUNK_SIZE = 4 * 1024 * 1024
_OVERLAP = 1024

# Supported encodings and their null-terminator byte widths
SUPPORTED_ENCODINGS: dict[str, int] = {
    "ascii": 1,
    "utf-8": 1,
    "utf-16-le": 2,
    "utf-16-be": 2,
    "shift_jis": 1,
    "euc-kr": 1,
    "iso-8859-1": 1,
    "cp1252": 1,
}

# Printable ASCII range for the fast-path scanner
_ASCII_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
# UTF-16LE pattern: ASCII char + \x00 repeated (common for Windows strings)
_UTF16LE_PATTERN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
# UTF-16BE pattern
_UTF16BE_PATTERN = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")


@dataclass(slots=True)
class CarvedString:
    """A string extracted from memory."""

    offset: int
    encoding: str
    value: str
    length: int
    context_entropy: float


class StringCarver:
    """Extract printable strings from binary data across multiple encodings.

    Skips high-entropy regions (likely encrypted/compressed) and deduplicates
    results by (offset, encoding) pair.
    """

    def __init__(
        self,
        *,
        min_length: int = 4,
        encodings: list[str] | None = None,
        entropy_threshold: float = 7.5,
        entropy_window: int = 256,
    ):
        self._min_length = min_length
        self._encodings = encodings or ["ascii", "utf-16-le"]
        self._entropy_threshold = entropy_threshold
        self._entropy_window = entropy_window

        for enc in self._encodings:
            if enc not in SUPPORTED_ENCODINGS:
                raise ValueError(
                    f"Unsupported encoding: {enc}. "
                    f"Supported: {', '.join(SUPPORTED_ENCODINGS)}"
                )

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Compute Shannon entropy in bits per byte."""
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        length = len(data)
        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / length
                entropy -= p * math.log2(p)
        return entropy

    def _is_high_entropy(self, data: bytes, offset: int) -> bool:
        """Check if the region around *offset* exceeds the entropy threshold."""
        start = max(0, offset - self._entropy_window // 2)
        end = min(len(data), offset + self._entropy_window // 2)
        window = data[start:end]
        if len(window) < 32:
            return False
        return self.shannon_entropy(window) > self._entropy_threshold

    def carve(self, data: bytes, base_offset: int = 0) -> Iterator[CarvedString]:
        """Extract strings from a bytes buffer.

        Yields CarvedString instances for each match found across the
        configured encodings.
        """
        seen: set[tuple[int, str]] = set()

        for encoding in self._encodings:
            for match in self._scan_encoding(data, encoding):
                abs_offset = base_offset + match.offset
                key = (abs_offset, encoding)
                if key in seen:
                    continue
                seen.add(key)

                if self._is_high_entropy(data, match.offset):
                    continue

                # Compute local entropy for context
                start = max(0, match.offset)
                end = min(len(data), match.offset + match.length * SUPPORTED_ENCODINGS.get(encoding, 1))
                ctx_entropy = self.shannon_entropy(data[start:end])

                yield CarvedString(
                    offset=abs_offset,
                    encoding=encoding,
                    value=match.value,
                    length=match.length,
                    context_entropy=ctx_entropy,
                )

    def _scan_encoding(self, data: bytes, encoding: str) -> Iterator[CarvedString]:
        """Scan for strings in a specific encoding."""
        if encoding == "ascii" or encoding == "utf-8":
            yield from self._scan_ascii(data)
        elif encoding == "utf-16-le":
            yield from self._scan_utf16le(data)
        elif encoding == "utf-16-be":
            yield from self._scan_utf16be(data)
        else:
            yield from self._scan_generic(data, encoding)

    def _scan_ascii(self, data: bytes) -> Iterator[CarvedString]:
        for m in _ASCII_PRINTABLE.finditer(data):
            text = m.group().decode("ascii")
            if len(text) >= self._min_length:
                yield CarvedString(
                    offset=m.start(),
                    encoding="ascii",
                    value=text,
                    length=len(text),
                    context_entropy=0.0,
                )

    def _scan_utf16le(self, data: bytes) -> Iterator[CarvedString]:
        for m in _UTF16LE_PATTERN.finditer(data):
            try:
                text = m.group().decode("utf-16-le")
            except UnicodeDecodeError:
                continue
            if len(text) >= self._min_length:
                yield CarvedString(
                    offset=m.start(),
                    encoding="utf-16-le",
                    value=text,
                    length=len(text),
                    context_entropy=0.0,
                )

    def _scan_utf16be(self, data: bytes) -> Iterator[CarvedString]:
        for m in _UTF16BE_PATTERN.finditer(data):
            try:
                text = m.group().decode("utf-16-be")
            except UnicodeDecodeError:
                continue
            if len(text) >= self._min_length:
                yield CarvedString(
                    offset=m.start(),
                    encoding="utf-16-be",
                    value=text,
                    length=len(text),
                    context_entropy=0.0,
                )

    def _scan_generic(self, data: bytes, encoding: str) -> Iterator[CarvedString]:
        """Brute-force sliding window decode for non-ASCII encodings."""
        char_width = SUPPORTED_ENCODINGS[encoding]
        i = 0
        while i < len(data) - self._min_length * char_width:
            # Try decoding a window
            window = data[i : i + 256 * char_width]
            try:
                decoded = window.decode(encoding, errors="strict")
            except (UnicodeDecodeError, LookupError):
                i += char_width
                continue

            # Find the longest printable prefix
            printable = []
            for ch in decoded:
                if ch.isprintable() or ch in ("\t", "\n", "\r"):
                    printable.append(ch)
                else:
                    break

            text = "".join(printable)
            if len(text) >= self._min_length:
                yield CarvedString(
                    offset=i,
                    encoding=encoding,
                    value=text,
                    length=len(text),
                    context_entropy=0.0,
                )
                i += len(text) * char_width
            else:
                i += char_width

    # ------------------------------------------------------------------
    # PatternScanner-compatible interface
    # ------------------------------------------------------------------

    def scan(self, data: bytes, offset: int = 0) -> Iterator[ScanResult]:
        """Scan a buffer, yielding ScanResult for each carved string."""
        for cs in self.carve(data, base_offset=offset):
            yield ScanResult(
                offset=cs.offset,
                length=cs.length,
                rule_name=f"string_{cs.encoding}",
                data=cs.value.encode("utf-8", errors="replace")[:256],
                metadata={
                    "encoding": cs.encoding,
                    "string_value": cs.value,
                    "context_entropy": cs.context_entropy,
                },
            )

    def scan_layer(
        self,
        layer: DataLayer,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        """Scan an entire DataLayer in chunks."""
        start = layer.minimum_address
        end = layer.maximum_address
        total = end - start
        pos = start

        while pos < end:
            chunk_end = min(pos + _CHUNK_SIZE, end)
            try:
                data = layer.read(pos, chunk_end - pos, pad=True)
            except Exception:
                pos += _CHUNK_SIZE - _OVERLAP
                continue

            yield from self.scan(data, offset=pos)

            if progress_callback and total > 0:
                progress_callback((pos - start) / total)

            pos += _CHUNK_SIZE - _OVERLAP

    def load_rules(self, path: Path) -> None:
        """No-op for StringCarver (no rule files)."""

    @property
    def rule_count(self) -> int:
        return len(self._encodings)
