# Recipe 02: Stack NAND + ECC + FTL

Compose a raw NAND dump through an ECC decoder and then a flash-translation
layer — all as stacked `DataLayer` instances that present corrected,
linearized bytes to whatever consumes them.

!!! note "Extras required"
    `pip install -e ".[storage,ecc]"` — optionally `[compression]` if the
    chip uses UBI with zlib-compressed nodes.

## The recipe

```python
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.storage.formats.nand_raw import RawNANDLayer
from deepview.storage.geometry import NANDGeometry, SpareLayout
from deepview.storage.ecc.bch import BCHDecoder
from deepview.storage.ftl.ubi import UBITranslator

ctx = AnalysisContext()

# --- 1. Describe the chip ----------------------------------------------
geom = NANDGeometry(
    page_size=2048,
    spare_size=64,
    pages_per_block=64,
    blocks=2048,
    planes=1,
    spare_layout=SpareLayout.onfi(spare_size=64),
)

# --- 2. Raw backing layer ----------------------------------------------
raw = RawNANDLayer(Path("/evidence/chip.bin"), geometry=geom)

# --- 3. Wrap via the StorageManager ------------------------------------
# wrap_nand builds ECCDataLayer(raw, decoder, geom) -> LinearizedFlashLayer(...)
ecc = BCHDecoder(t=8)
ftl = UBITranslator(geom)

linear = ctx.storage.wrap_nand(raw, geom, ecc=ecc, ftl=ftl)
ctx.layers.register("linear", linear)

# --- 4. Read like any other DataLayer ---------------------------------
print(linear.read(0, 64).hex())
print("max_addr =", linear.maximum_address)
```

## What happened

The call graph is exactly three layers tall:

```
read(addr) -> LinearizedFlashLayer (physical-from-logical)
           -> ECCDataLayer          (per-page decode + correct)
           -> RawNANDLayer          (mmap of chip.bin)
```

Each layer satisfies the `DataLayer` contract
([`interfaces/layer.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/interfaces/layer.py)).
The ECC layer intercepts reads, slices the ECC bytes out of the spare
region per the `SpareLayout`, decodes each page, and returns corrected
payload bytes. The FTL layer translates logical LBAs into physical
block/page addresses using the translator's in-memory map.

!!! tip "Skip components you don't need"
    `wrap_nand(raw, geom, ecc=None, ftl=None)` returns `raw` unchanged.
    You can pass only the ECC decoder for an SPI chip without an FTL,
    or only the FTL when you trust the bytes to be ECC-clean already
    (e.g. a JTAG-mediated dump after hardware correction).

!!! warning "Spare layout matters"
    If `spare_layout` is wrong the ECC layer will feed garbage to the
    decoder and every page will look corrupt. Prefer the vendor preset
    if you know the chip: `SpareLayout` ships `onfi()` and adapters ship
    `samsung_klm()`, `toshiba_tc58()`, `micron_mt29f()` under
    [`storage/ecc/layouts.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/storage/ecc/layouts.py).

## Equivalent CLI

```bash
deepview storage wrap \
    --in chip.bin --geometry onfi-2k64 \
    --ecc bch8 --ftl ubi \
    --register-as linear
```

## Cross-links

- Architecture: [`architecture/storage.md`](../architecture/storage.md).
- Animated visual: [`overview/data-layer-composition.md`](../overview/data-layer-composition.md).
- ECC/FTL interfaces: [`reference/interfaces.md`](../reference/interfaces.md).
