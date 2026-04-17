# Raw NAND dump

A raw NAND dump is the byte-for-byte output of reading every page of a
NAND chip — including the **spare area** (aka **OOB**, "out of band")
that the flash controller normally uses for bad-block markers and ECC
codewords. For forensic acquisition this is the lowest-level
representation available: no wear-levelling has been undone, no ECC
has been applied, no FTL (Flash Translation Layer) has been walked.

## File structure

A raw NAND image is laid out **page-by-page**, with each page's data
bytes followed immediately by its spare bytes:

```
+-------+------+-------+------+-------+------+       +-------+------+
| data0 | OOB0 | data1 | OOB1 | data2 | OOB2 |  ...  | dataN | OOBN |
+-------+------+-------+------+-------+------+       +-------+------+
```

No header, no magic, no signatures. You cannot identify a raw NAND
dump by peeking at offset 0 — you must know (or infer) the geometry
out of band.

## Page geometry

The canonical ONFI (Open NAND Flash Interface) geometry values are:

| Capability      | Data size (bytes) | Spare size (bytes) | `page_size + spare` |
| --------------- | ----------------: | -----------------: | ------------------: |
| SLC, small page | 512               | 16                 | 528                 |
| SLC, large page | 2 048             | 64                 | 2 112               |
| MLC / TLC       | 4 096             | 224 or 256         | 4 320 / 4 352       |
| TLC 3D          | 8 192             | 448 / 640 / 768    | 8 640 / 8 832 / 8 960 |
| TLC / QLC 3D    | 16 384            | 1 024 / 1 280      | 17 408 / 17 664    |

Deep View's `NANDGeometry` dataclass captures:

| Field               | Description                                                 |
| ------------------- | ----------------------------------------------------------- |
| `page_size`         | Data bytes per page.                                         |
| `spare_size`        | OOB bytes per page.                                          |
| `pages_per_block`   | Usually 64 / 128 / 256 / 512.                                |
| `blocks_per_plane`  | Device-specific, from ONFI parameter page.                   |
| `planes_per_lun`    | Usually 1 or 2.                                              |
| `luns_per_target`   | Number of LUNs on the chip.                                  |
| `total_pages`       | `pages_per_block × blocks_per_plane × planes_per_lun × luns`.|

`NANDGeometry.total_page_size = page_size + spare_size` is the stride
from one page's start to the next.

## Spare / OOB area layout (ONFI default)

The OOB area is formally split between the **bad-block marker** (BBM)
and the ECC. ONFI defines:

| Offset within spare | Size | Field                | Description                                   |
| ------------------: | ---: | -------------------- | --------------------------------------------- |
| `+0x00`             |  1   | Bad-block marker     | `0xFF` = good block, anything else = bad.     |
| `+0x01`             | …    | Metadata / ECC       | Controller-specific.                          |

For 2 KiB pages the historical JFFS2 / UBI layout uses an **OOB map**
where:

| Byte(s)             | Purpose                                               |
| ------------------- | ----------------------------------------------------- |
| `+0x00`             | Bad-block marker.                                     |
| `+0x01 .. +0x07`    | Reserved / filesystem-specific.                       |
| `+0x08 .. +0x0F`    | Cleanmarkers / sequence number.                       |
| `+0x10 .. +0x3F`    | ECC (4 × 12-byte BCH codewords over 4 × 512 sectors). |

**ECC algorithms seen in the wild:**

* Hamming (512 B data / 3 B ECC) — tiny SLC devices.
* BCH-8 or BCH-12 (512 B data / ~14 B ECC) — SLC large page.
* BCH-24 or BCH-40 (1 KiB data / ~42 B ECC) — MLC.
* LDPC (hardware controller-specific) — modern TLC / QLC 3D.

Deep View **does not** attempt ECC correction at this layer; that is
the `ECCDataLayer` wrapper's responsibility (see
`src/deepview/storage/ecc/`).

## Bad-block markers

A block is "factory bad" or "runtime bad" when the BBM byte in the
**first page's spare area** of that block is not `0xFF`. The standard
"scan-the-chip" procedure is:

```
for block in range(total_blocks):
    page_index = block * pages_per_block
    spare = read(page_index.spare_offset, spare_size)
    if spare[0] != 0xFF:
        mark_bad(block)
```

Some controllers additionally mark the **second** page's BBM on the
assumption that programming disturb may corrupt the first page;
consult the ONFI parameter page for the chip in question.

## Linear-byte addressing

`RawNANDLayer.read(offset, length)` simply indexes into the interleaved
stream — the caller is responsible for knowing where data stops and
OOB starts. When a `NANDGeometry` is supplied, iterate structured
pages:

```python
layer = RawNANDLayer(Path("chip.nand"), geom)
for meta, data, spare in layer.iter_pages():
    # meta.block, meta.page, meta.data_offset, meta.spare_offset
    ...
```

`iter_pages()` stops cleanly at the last complete page if the file is
truncated mid-page.

## Known variations

!!! note "Ex-swap NAND dumps"
    Dumps made with `flashcp` or `nanddump --noecc` may include only
    the data area, not the OOB. Set `spare_size = 0` in the geometry
    — this turns `iter_pages` into a simple page walker.

!!! note "BBT-reserved blocks"
    The Linux NAND subsystem reserves the last 4 blocks of the chip
    for the Bad-Block Table (BBT). These blocks are not filesystem
    data; their OOB will have an unusual magic (`"Bbt0"` / `"1tbB"`).

!!! warning "Controller-remapped pages"
    If the dump was taken *through* a flash controller (as opposed to
    a chip-off acquisition), the FTL has already remapped logical
    pages. Expect the raw layer to be useless for FTL-aware
    forensics — plug in an FTL layer (`deepview.storage.ftl`).

!!! warning "Interleaved plane dumps"
    Some chips return pages in plane-interleaved order
    (plane0-page0, plane1-page0, plane0-page1, ...) rather than strict
    ascending page order. `NANDGeometry.total_pages` counts across
    planes, so `iter_pages` stride is correct, but the block
    numbering may need a plane unshuffle.

## Gotchas

* **Endianness.** NAND is a byte stream; ECC codewords have their own
  endianness defined by the controller.
* **No file magic.** Feed `NANDGeometry` the correct `(page, spare)`
  tuple or `iter_pages` will silently desync. A quick sanity check:
  the first byte of each page's spare area should be `0xFF` on an
  erased / factory-good device.
* **Huge files.** A 512 GiB TLC dump is routine; `mmap`-based access
  is mandatory (Deep View already uses it). Ensure the host has a
  64-bit Python interpreter and enough VA space.

## Parser

* Implementation: `src/deepview/storage/formats/nand_raw.py`
* Class: `RawNANDLayer(DataLayer)`
* Geometry: `src/deepview/storage/geometry.py::NANDGeometry`
* ECC: `src/deepview/storage/ecc/` (Hamming, BCH, LDPC wrappers).
* FTL: `src/deepview/storage/ftl/` (YAFFS2, UBIFS, JFFS2 linearisation).

## References

* [ONFI 5.1 specification](https://www.onfi.org/specifications)
* [Linux MTD / NAND subsystem documentation](https://www.kernel.org/doc/html/latest/driver-api/mtdnand.html)
* [`mtd-utils`: `nanddump`, `nandwrite`, `mtdinfo`](https://git.infradead.org/mtd-utils.git)
* [“Forensic analysis of flash memory” — DFRWS 2011](https://dfrws.org/)
* [Brian Murphy — BCH for NAND flash](https://github.com/linux-nand)
