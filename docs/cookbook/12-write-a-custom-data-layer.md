# Recipe 12: Write a custom `DataLayer`

Implement the `DataLayer` ABC for a hypothetical compressed-page-table
backing store — a disk-backed dict of `{page_index: compressed_bytes}`
that looks like linear memory from the outside.

!!! note "Extras required"
    Stdlib only (we use `zlib` for compression — pick whatever codec
    fits your backing store).

## The recipe

```python
from __future__ import annotations
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Mapping

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.interfaces.scanner import PatternScanner


class CompressedPageTableLayer(DataLayer):
    """A read-only DataLayer over a dict of zlib-compressed 4 KiB pages.

    The *pages* argument maps page index (0-based) to compressed bytes;
    missing pages are treated as zero-filled holes. Useful for evidence
    stored as sparse, deduplicated blobs (e.g. a cloud-native memory
    capture format).
    """

    PAGE_SIZE = 4096

    def __init__(
        self,
        pages: Mapping[int, bytes],
        *,
        total_pages: int,
        name: str = "compressed",
    ) -> None:
        self._pages = dict(pages)
        self._total_pages = total_pages
        self._name = name
        # tiny LRU: decompress is cheap but not free.
        self._cache: dict[int, bytes] = {}

    # -- abstract methods ------------------------------------------------
    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("negative offset/length")
        end = offset + length
        out = bytearray()
        cur = offset
        while cur < end:
            page_idx, within = divmod(cur, self.PAGE_SIZE)
            page = self._page_bytes(page_idx)
            if page is None:
                if not pad:
                    raise IOError(
                        f"hole at page={page_idx} (pad=False)"
                    )
                page = b"\x00" * self.PAGE_SIZE
            chunk = page[within:within + (end - cur)]
            out.extend(chunk)
            cur += len(chunk)
            if len(chunk) == 0:       # pathological: guard infinite loop
                break
        return bytes(out)

    def write(self, offset: int, data: bytes) -> None:
        raise IOError("CompressedPageTableLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        end = offset + length - 1
        for page_idx in range(offset // self.PAGE_SIZE,
                              end // self.PAGE_SIZE + 1):
            if page_idx not in self._pages:
                return False
        return 0 <= offset < self.maximum_address + 1

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        # Delegate page-by-page so the scanner doesn't need the whole image
        # decompressed at once.
        for page_idx in sorted(self._pages):
            page = self._page_bytes(page_idx) or b""
            base = page_idx * self.PAGE_SIZE
            for hit in scanner.scan(page):
                yield ScanResult(
                    offset=base + hit.offset,
                    length=hit.length,
                    pattern=hit.pattern,
                    data=hit.data,
                )
            if progress_callback is not None:
                progress_callback(base, self.maximum_address + 1)

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return self._total_pages * self.PAGE_SIZE - 1

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            size=self._total_pages * self.PAGE_SIZE,
            source_path=Path("<in-memory>"),
        )

    # -- private helpers ------------------------------------------------
    def _page_bytes(self, page_idx: int) -> bytes | None:
        if page_idx not in self._pages:
            return None
        if page_idx in self._cache:
            return self._cache[page_idx]
        decompressed = zlib.decompress(self._pages[page_idx])
        self._cache[page_idx] = decompressed
        return decompressed
```

## Using it

```python
layer = CompressedPageTableLayer(
    pages={0: zlib.compress(b"\x90" * 4096), 2: zlib.compress(b"X" * 4096)},
    total_pages=4,
)
print(layer.read(0, 16).hex())
print(layer.is_valid(4096, 4096))     # False — page 1 missing
print(layer.read(8192, 8, pad=True))  # b'XXXXXXXX'
```

## What to notice

- **Every abstract method is implemented.** The ABC refuses to
  instantiate otherwise — mypy's strict mode will also catch a missing
  override. The full contract lives in
  [`interfaces/layer.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/interfaces/layer.py).
- **`pad=True` returns zeros for holes.** This matches the Volatility-3
  convention used by every in-tree layer, so downstream consumers
  (scanners, parsers, translators) don't need special cases.
- **`scan` delegates but preserves offsets.** The hit is reported in
  the *layer's* address space, not the page-local one.
- **`write` raises rather than silently dropping.** Read-only layers
  should be explicit.

!!! tip "Composition"
    Because every layer satisfies the same contract, you can stack this
    one under the ECC layer, the unlocker's DecryptedVolumeLayer, or
    anything in between. See
    [Recipe 02](02-stack-nand-ecc-ftl.md) and
    [Recipe 07](07-nested-decrypt-luks-in-veracrypt.md) for nesting
    examples.

!!! warning "Testing"
    New layers should land with unit tests under
    `tests/unit/test_storage/` (or the relevant subsystem). Fixtures in
    `tests/conftest.py` expose a ready-to-use
    `AnalysisContext.for_testing()` — see the `context` fixture.

## Cross-links

- Interface: [`reference/interfaces.md#datalayer`](../reference/interfaces.md).
- Animation: [`overview/data-layer-composition.md`](../overview/data-layer-composition.md).
- Guide: [`guides/extending-deepview.md`](../guides/extending-deepview.md).
