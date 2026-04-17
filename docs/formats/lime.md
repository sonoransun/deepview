# LiME (Linux Memory Extractor)

LiME is the de-facto standard format for acquiring Linux physical memory
on live systems. The LKM-based acquirer emits one **range header** per
contiguous physical-memory range, immediately followed by that range's
bytes. The file is a simple concatenation of `(header, bytes)` pairs —
there is no directory, no checksum, and no index.

## Signature

* **Magic (offset 0):** `0x4C694D45` — ASCII `"LiME"`, little endian.
* **Header size:** 32 bytes (`4 + 4 + 8 + 8 + 8`).
* **Encoding of the header:** little endian throughout.

The magic appears at the start of **every** range, not just the first,
so the parser can recover from a truncated range by resyncing on the
next `"LiME"` tag.

## Range header layout

| Offset | Size | Field      | Description                                                                       |
| -----: | ---: | ---------- | --------------------------------------------------------------------------------- |
| `0x00` | 4    | `magic`    | `0x4C694D45` (`"LiME"`, little endian).                                           |
| `0x04` | 4    | `version`  | LiME format version. `1` is the only value ever observed in the wild.             |
| `0x08` | 8    | `s_addr`   | Start physical address of this range (inclusive).                                 |
| `0x10` | 8    | `e_addr`   | End physical address of this range (**inclusive**, not exclusive).                |
| `0x18` | 8    | `reserved` | Reserved; zero-filled by the acquirer.                                            |

Header struct (used by the parser):

```python
LIME_HEADER_FMT = "<IIqqq"   # magic, version, s_addr, e_addr, reserved
LIME_HEADER_SIZE = 32
```

The bytes of the range follow **immediately** after the header. The
range is `e_addr - s_addr + 1` bytes long — the inclusivity of `e_addr`
is critical and is a common source of off-by-one bugs.

## Body layout

```
+--------+------------+   +--------+------------+   +--------+-----
| hdr 0  | bytes 0... |   | hdr 1  | bytes 1... |   | hdr 2  | ...
+--------+------------+   +--------+------------+   +--------+-----
^        ^            ^   ^        ^            ^
|        s_addr..e_addr   |        s_addr..e_addr
offset 0                  offset 32 + len(range0)
```

Each `hdr[i].s_addr` can be non-contiguous with `hdr[i-1].e_addr + 1`;
most real dumps have gaps corresponding to MMIO holes, reserved BIOS
regions, and ACPI tables that the acquirer chose not to capture.

## Reading back an address

Given a physical address `P`:

1. Walk the range table linearly (Deep View stores the ranges in an
   in-memory list — typical dumps have ≲ 32 ranges so binary search is
   unnecessary).
2. The range `R` satisfying `R.s_addr ≤ P ≤ R.e_addr` resolves to file
   offset `R.file_offset + (P - R.s_addr)`.
3. If no range contains `P`, `LiMEMemoryLayer.read(P, n)` returns `b""`
   unless `pad=True`, which zero-fills gaps.

## Known variations

!!! note "Version drift"
    LiME advertises a `version` field, but every commit in the upstream
    repo since 2011 has written `1`. Deep View does not gate on the
    version and accepts any value as long as the magic matches.

!!! note "File alignment"
    LiME does **not** pad ranges to a page boundary. A 3 727-byte range
    occupies exactly 3 727 bytes on disk; the next header starts on the
    following byte. Do not assume page-aligned offsets.

!!! warning "Zero-length ranges"
    Historical versions of the LKM occasionally emitted `s_addr == 0 &&
    e_addr == 0`, which is a *one-byte range* (inclusive), not empty.
    The parser treats this as a single byte to match the acquirer.

!!! warning "Corrupted `reserved` field"
    Some third-party clones (notably the Android `mem_lime` fork) write
    a timestamp or checksum into `reserved`. Treat the field as opaque
    — do not validate it.

## Gotchas

* **End address is inclusive.** The byte at `e_addr` is part of the
  range. Python's slicing convention is half-open; forgetting to add 1
  will silently drop the last byte of every range.
* **Ranges are not required to be sorted** — LiME emits them in the
  order the kernel reports them, which is typically ascending but not
  guaranteed on NUMA systems. Parsers doing sparse lookups should sort.
* **File truncation.** The acquirer buffers writes in userspace; if the
  process is SIGKILLed mid-dump the last range will be short. Deep
  View's parser rejects dumps whose declared range extends past EOF
  (`FormatError: LiME range extends past end of file`).
* **Cap on range size.** Deep View refuses a single range larger than
  1 TiB (`_MAX_RANGE_SIZE = 1 << 40`) as a defence against crafted
  headers that try to force a huge allocation.

## Parser

* Implementation: `src/deepview/memory/formats/lime_format.py`
* Class: `LiMEMemoryLayer(DataLayer)`
* Exposed struct: `LiMERange(start, end, file_offset)`

The class implements the full `DataLayer` ABC — `read`, `write`
(read-only NotImplementedError), `is_valid`, `scan`, `minimum_address`,
`maximum_address`, `metadata` — so any Volatility-3-style plugin
operating on a `DataLayer` also works against a LiME file.

## References

* [LiME GitHub (504ensicsLabs/LiME)](https://github.com/504ensicsLabs/LiME)
* [Volatility 3 LiME layer](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/layers/lime.py)
* [“LiME — Linux Memory Extractor” (DFRWS 2012)](https://www.sciencedirect.com/science/article/pii/S1742287612000412)
