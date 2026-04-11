"""Lazy ``/proc/kallsyms`` parser and address → symbol resolver.

/proc/kallsyms is a sorted, whitespace-delimited file mapping kernel
symbol addresses to names. On hosts with ``kptr_restrict`` set, all
addresses are zero to non-root; we detect that and degrade to
name-only lookups. The resolver uses a bisect over a cached list so
repeated lookups stay O(log n) without pulling any dependency.
"""
from __future__ import annotations

import bisect
import threading
from pathlib import Path
from typing import Iterator

from deepview.core.logging import get_logger

log = get_logger("tracing.linux.kallsyms")


_PATH = Path("/proc/kallsyms")


class KallsymsResolver:
    """Read-once, bisect-lookup kernel symbol table."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._addrs: list[int] = []
        self._names: list[str] = []
        self._by_name: dict[str, int] = {}
        self._loaded = False
        self._restricted = False

    def load(self, force: bool = False) -> None:
        with self._lock:
            if self._loaded and not force:
                return
            self._addrs.clear()
            self._names.clear()
            self._by_name.clear()
            if not _PATH.exists():
                self._loaded = True
                return
            pairs: list[tuple[int, str]] = []
            try:
                with _PATH.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) < 3:
                            continue
                        try:
                            addr = int(parts[0], 16)
                        except ValueError:
                            continue
                        name = parts[2]
                        pairs.append((addr, name))
                        self._by_name.setdefault(name, addr)
            except OSError as e:
                log.debug("kallsyms_read_failed", error=str(e))
                self._loaded = True
                return
            pairs.sort(key=lambda kv: kv[0])
            self._addrs = [p[0] for p in pairs]
            self._names = [p[1] for p in pairs]
            self._restricted = all(a == 0 for a in self._addrs) if self._addrs else True
            self._loaded = True
            log.info(
                "kallsyms_loaded",
                entries=len(self._addrs),
                restricted=self._restricted,
            )

    @property
    def restricted(self) -> bool:
        self.load()
        return self._restricted

    def resolve(self, address: int) -> tuple[str, int] | None:
        """Return ``(symbol, offset)`` for *address*, or ``None``.

        The symbol is the nearest predecessor in the sorted table;
        ``offset`` is ``address - symbol_addr``. Returns ``None`` if
        the table is empty or the host restricts addresses.
        """
        self.load()
        if not self._addrs or self._restricted:
            return None
        idx = bisect.bisect_right(self._addrs, address) - 1
        if idx < 0:
            return None
        return self._names[idx], address - self._addrs[idx]

    def address_of(self, name: str) -> int | None:
        """Lookup the address of a named kernel symbol."""
        self.load()
        if self._restricted:
            return None
        return self._by_name.get(name)

    def contains(self, name: str) -> bool:
        """Check symbol existence without exposing an address."""
        self.load()
        return name in self._by_name

    def iter_prefix(self, prefix: str) -> Iterator[str]:
        """Yield all symbols whose name starts with *prefix*."""
        self.load()
        for name in self._names:
            if name.startswith(prefix):
                yield name


_DEFAULT: KallsymsResolver | None = None


def default_resolver() -> KallsymsResolver:
    """Return a lazily-initialised process-wide resolver."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = KallsymsResolver()
    return _DEFAULT
