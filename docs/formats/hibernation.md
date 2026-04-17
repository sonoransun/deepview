# Windows hibernation file (`hiberfil.sys`)

When a Windows box hibernates (`S4`) the `power.sys` / `NTOSKRNL`
subsystem writes a compressed snapshot of physical RAM to
`C:\hiberfil.sys`. Unlike the crash-dump format the layout is
versioned: Microsoft has shipped at least three on-disk encodings since
Windows XP. Deep View parses the Windows 7 / 8 / 10 / 11 layout, which
uses `PO_MEMORY_IMAGE` as the file header, a linked chain of
`PO_MEMORY_RANGE_TABLE` structures, and either **Xpress** or
**Xpress-Huffman** compressed page runs.

Because the in-tree Xpress-Huffman decoder is partial, the parser
implements a fallback: if any table cannot be decoded (or if
`decompress_xpress` raises `NotImplementedError`), the layer switches
to **raw pass-through mode** — the file is served verbatim so YARA
scans and string carvers still work. The attribute
`HibernationLayer.compression_status` is either `"decoded"` or
`"undecoded"`.

## Signatures

Hiberfil files start with one of four 4-byte ASCII magics:

| Magic (hex)      | ASCII   | Meaning                                |
| ---------------- | ------- | -------------------------------------- |
| `68 69 62 72`    | `hibr`  | Hibernation image (lowercase).         |
| `48 49 42 52`    | `HIBR`  | Hibernation image (uppercase; Win8+).  |
| `77 61 6B 65`    | `wake`  | Post-resume marker (file already decommissioned). |
| `57 41 4B 45`    | `WAKE`  | Post-resume marker (uppercase).        |

A `wake` / `WAKE` magic indicates that the OS has already resumed and
is in the process of discarding the image. The bytes are still
mostly-valid and the parser accepts them, but expect sparse or
inconsistent page tables.

## `PO_MEMORY_IMAGE` header (used fields)

The full struct has drifted between builds (entries for
`NoHiberPtes`, `ResumeContext`, `PerfInfo`, `ACPI` tables, `FeatureFlags`,
...). Deep View reads only the fields it needs to locate page runs:

| Offset  | Size | Field                 | Description                                                |
| ------: | ---: | --------------------- | ---------------------------------------------------------- |
| `0x000` |  4   | `Signature`           | One of `hibr`/`HIBR`/`wake`/`WAKE`.                         |
| `0x004` |  4   | `Version`             | Build-dependent. Not gated.                                |
| `0x008` |  4   | `CheckSum`            | CRC-style checksum (not validated).                        |
| `0x00C` |  4   | `LengthSelf`          | Length of the image descriptor itself.                     |
| `0x010` |  8   | `PageSelf`            | Page index where `PO_MEMORY_IMAGE` lives.                  |
| `0x018` |  4   | `PageSize`            | Page size in bytes. Expected `0x1000` / `0x2000` / `0x4000`. |
| `0x01C` |  8   | `SystemTime`          | `FILETIME` at hibernation.                                 |
| `0x044` |  4   | `FreeMapCheck`        | Internal consistency token.                                |
| `0x048` |  4   | `WakeCheck`           | Wake marker; non-zero after resume starts.                 |
| `0x04C` |  4   | `TotalPages`          | Total pages covered (the ultimate RAM size / `PageSize`).  |
| `0x058` |  8   | `FirstTablePage`      | Page index of the first `PO_MEMORY_RANGE_TABLE`.           |
| `0x060` |  8   | `LastFilePage`        | Last populated file page (used only as a safety bound).    |

!!! warning "Offsets drift across builds"
    The offsets above are the Deep View parser's working set. Windows
    7, 8.1, 10, 11 do not all agree byte-for-byte — the fields we
    actually rely on (`Signature`, `PageSize`, `TotalPages`,
    `FirstTablePage`) have been stable since Windows 7. If any of them
    fail to decode, the parser degrades to raw passthrough instead of
    raising.

## `PO_MEMORY_RANGE_TABLE` chain

Each table lives at page index `TablePage`:

```c
struct _PO_MEMORY_RANGE_TABLE {
    uint32_t PageCount;    // number of (StartPage, EndPage) ranges
    uint32_t _pad;
    uint64_t NextTable;    // page index of next table, 0 = terminator
    MemoryRange Ranges[PageCount];
};

struct MemoryRange {
    uint64_t StartPage;    // PFN (inclusive)
    uint64_t EndPage;      // PFN (inclusive)
};
```

### Table header

| Offset | Size | Field       | Description                                           |
| -----: | ---: | ----------- | ----------------------------------------------------- |
| `0x00` |  4   | `PageCount` | Number of range records that follow.                  |
| `0x04` |  4   | `_pad`      | Alignment padding; ignored.                           |
| `0x08` |  8   | `NextTable` | Page index of next table, or 0 to terminate.          |

### Range record (16 bytes each)

| Offset | Size | Field       | Description                                           |
| -----: | ---: | ----------- | ----------------------------------------------------- |
| `0x00` |  8   | `StartPage` | First PFN of this range (inclusive).                  |
| `0x08` |  8   | `EndPage`   | Last PFN of this range (inclusive).                   |

## Page run encoding

Compressed page bytes sit **sequentially** starting one page after the
range table (`cursor = (FirstTablePage + 1) × PageSize`). Each range
consumes exactly `run_pages × PageSize` of compressed bytes in the
cursor stream, after which the next range takes over.

The compressor is one of:

* **Xpress** — LZ-style, used on older Windows builds. Relatively
  small dictionaries; pure-Python decode implemented in
  `deepview.storage.encodings.xpress`.
* **Xpress-Huffman** — Huffman-coded Xpress variant introduced around
  Windows 8.1 for improved ratios. The Deep View decoder currently
  raises `NotImplementedError` on complex Huffman streams; the layer
  downgrades to raw passthrough when this happens.

## Safety caps

To defend against crafted `hiberfil.sys`:

| Cap                              | Value    | Enforced in                        |
| -------------------------------- | -------- | ---------------------------------- |
| Maximum table chain length       | 4 096    | `_MAX_TABLES`                      |
| Maximum ranges per table         | 65 536   | `_MAX_RANGES_PER_TABLE`            |
| LRU cache of decompressed pages  | 256      | `_LRU_SIZE`                        |
| Cycle detection (visited PFN)    | via `seen`| `_parse_tables`                    |

## Addressing

`HibernationLayer.read(offset, length)`:

1. Compute `pfn = offset // PageSize`, `intra = offset % PageSize`.
2. Look up `(file_off, comp_size)` in `self._page_map[pfn]`.
3. Fetch `comp = mmap[file_off : file_off + comp_size]`.
4. Decompress via `decompress_xpress(comp, PageSize)`.
5. Cache the page in the 256-entry LRU, then return
   `page[intra : intra + length]` (clipped to the page).

In undecoded mode (`compression_status == "undecoded"`) the layer
serves raw file bytes from `offset` directly, treating the hibernation
file as a flat passthrough.

## Known variations

!!! note "ARM64 / Surface Pro X"
    `PageSize = 0x4000` (16 KiB) appears on some ARM64 builds. Only
    values in `(0x1000, 0x2000, 0x4000)` are honoured; anything else
    falls back to 4 KiB and the parser may or may not recover.

!!! note "Server 2022 encrypted hibernation"
    When `HibernateEnabledDefault` is enabled on an encrypted Server
    2022 installation, the hibernation file is itself encrypted with a
    per-boot key. The magic bytes are present but page content
    decompresses to ciphertext; Deep View cannot currently decrypt it.

!!! warning "FreeMapCheck + WakeCheck"
    Do **not** treat a non-zero `WakeCheck` as authoritative — some OEM
    images pre-populate it to force a full boot. Parse the header
    regardless and let the user decide.

## Gotchas

* **Compressed size is not in the header.** The parser assumes each
  run's compressed span equals `run_pages × PageSize`; the Xpress
  decoder then size-checks on the decompressed side. This is
  approximate — Xpress compresses most pages to < 4 KiB, leaving dead
  bytes in the stream. Mid-stream resync is best-effort.
* **Undecoded mode is not silent.** Clients should branch on
  `layer.compression_status` before drawing conclusions from virtual
  addresses.
* **ranges are inclusive both ends** — `end - start + 1` pages per
  range, same as LiME.

## Parser

* Implementation: `src/deepview/memory/formats/hibernation.py`
* Class: `HibernationLayer(DataLayer)`
* Decoder (lazy import): `deepview.storage.encodings.xpress.decompress_xpress`

## References

* [Sandman Project — hibernation file analysis](https://www.msuiche.net/pres/SSTIC08_HibernationFile.pdf)
* [MS-XCA: Xpress Compression Algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/)
* [MSDN: Power Management — Hibernation](https://learn.microsoft.com/en-us/windows/win32/power/system-power-states)
* [Volatility 3 hibernation layer](https://github.com/volatilityfoundation/volatility3/tree/develop/volatility3/framework/layers)
