"""On-demand memory peek + YARA + string carving on a live pid."""
from __future__ import annotations

from typing import Iterator

from deepview.core.types import ScanResult
from deepview.inspect.live_layer import LiveProcessLayer


class MemoryPeek:
    """Thin orchestrator around :class:`LiveProcessLayer`."""

    def __init__(self, pid: int) -> None:
        self._pid = pid
        self._layer = LiveProcessLayer(pid)

    @property
    def layer(self) -> LiveProcessLayer:
        return self._layer

    def read_range(self, va: int, length: int) -> bytes:
        return self._layer.read(va, length)

    def scan_yara(self, rules_path: str) -> Iterator[ScanResult]:
        """Run a YARA ruleset over every readable region of the process."""
        try:
            from deepview.scanning.yara_engine import YaraScanner
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"YARA scanner unavailable: {e}") from e
        scanner = YaraScanner.from_rules_file(rules_path)
        yield from self._layer.scan(scanner)

    def carve_strings(self, min_length: int = 6) -> list[str]:
        """Yield printable strings from every readable region."""
        try:
            from deepview.scanning.string_carver import StringCarver
        except Exception:
            return []
        carver = StringCarver(min_length=min_length)
        collected: list[str] = []
        for region in self._layer.regions:
            if "r" not in region.perms:
                continue
            try:
                data = self._layer.read(region.start, region.end - region.start, pad=True)
            except Exception:  # noqa: BLE001
                continue
            for s in carver.carve(data):
                collected.append(s.value)
        return collected

    def close(self) -> None:
        self._layer.close()
