# Windows kernel crash dump (`.dmp`)

Windows writes full / kernel / bitmap crash dumps (`MEMORY.DMP`) through
the `crashdmp.sys` driver when the kernel bugchecks. The format is
undocumented by Microsoft but has been reverse-engineered across the
Volatility, Rekall, WinDbg, and CrowdStrike public toolchains; the
layout below reflects the fields Deep View actually consumes.

Three dump flavours share the same magic namespace:

* **Full dump** (`DumpType = 1`) — every page of RAM, written as
  contiguous *runs* described in the header's `PhysicalMemoryBlock`.
* **Kernel dump** (`DumpType = 2`) — identical on-disk structure, but
  only kernel-mode pages are written.
* **Bitmap dump** (`DumpType = 5`) — a secondary `_BITMAP_DUMP` header
  follows the primary header; a bitmap lists PFNs that are present.

## Signatures

| Architecture | Signature (offset `0x00`) | `ValidDump` (offset `0x04`) | Header size |
| ------------ | ------------------------- | --------------------------- | ----------: |
| x86 (32-bit) | `"PAGE"` (`50 41 47 45`)  | `"DUMP"`                    | `0x1000`    |
| x64 (64-bit) | `"PAGEDU64"`              | `"DU64"`                    | `0x2000`    |

The page size is **always 4 096** for Windows crash dumps (`PAGE_SIZE =
0x1000`).

## 32-bit `DUMP_HEADER` (partial)

| Offset  | Size | Field                    | Description                                     |
| ------: | ---: | ------------------------ | ----------------------------------------------- |
| `0x000` |  4   | `Signature`              | `"PAGE"`.                                       |
| `0x004` |  4   | `ValidDump`              | `"DUMP"`.                                       |
| `0x008` |  4   | `MajorVersion`           | NT major version (e.g. `0x0F = 15`).            |
| `0x00C` |  4   | `MinorVersion`           | NT minor build number.                          |
| `0x010` |  4   | `DirectoryTableBase`     | CR3 of the idle process at the time of dump.    |
| `0x014` |  4   | `PfnDatabase`            | Kernel `MmPfnDatabase`.                         |
| `0x018` |  4   | `PsLoadedModuleList`     | Kernel loaded-module list head.                 |
| `0x01C` |  4   | `PsActiveProcessHead`    | Kernel active-process list head.                |
| `0x020` |  4   | `MachineImageType`       | `0x014C = i386`.                                |
| `0x024` |  4   | `NumberProcessors`       | Logical processor count.                        |
| `0x028` |  4   | `BugCheckCode`           | Bugcheck code (0 for a user-requested dump).    |
| `0x02C` | 16   | `BugCheckParameter[1..4]`| 4 × ULONG parameters.                           |
| `0x064` | 700  | `PhysicalMemoryBlock`    | `_PHYSICAL_MEMORY_DESCRIPTOR` (see below).      |
| `0xF88` |  4   | `DumpType`               | `1` = full, `2` = kernel, `5` = bitmap.         |
| `0x1000`|  —   | *end of header*          | Page runs begin immediately after.              |

## 64-bit `DUMP_HEADER64` (partial)

| Offset  | Size | Field                    | Description                                     |
| ------: | ---: | ------------------------ | ----------------------------------------------- |
| `0x000` |  8   | `Signature` + `ValidDump`| `"PAGEDU64"`.                                   |
| `0x008` |  4   | `MajorVersion`           |                                                 |
| `0x00C` |  4   | `MinorVersion`           |                                                 |
| `0x010` |  8   | `DirectoryTableBase`     | CR3 (now 64-bit).                               |
| `0x018` |  8   | `PfnDatabase`            |                                                 |
| `0x020` |  8   | `PsLoadedModuleList`     |                                                 |
| `0x028` |  8   | `PsActiveProcessHead`    |                                                 |
| `0x030` |  4   | `MachineImageType`       | `0x8664 = x86-64`, `0xAA64 = aarch64`.          |
| `0x034` |  4   | `NumberProcessors`       |                                                 |
| `0x038` |  4   | `BugCheckCode`           |                                                 |
| `0x040` | 32   | `BugCheckParameter[1..4]`| 4 × ULONG64.                                    |
| `0x088` | 7936 | `PhysicalMemoryBlock64`  | 64-bit descriptor (see below).                  |
| `0xF98` |  4   | `DumpType`               |                                                 |
| `0x2000`|  —   | *end of header*          | Page runs begin immediately after.              |

## PhysicalMemoryBlock (Full / Kernel dumps)

```c
struct _PHYSICAL_MEMORY_DESCRIPTOR {
    ULONG NumberOfRuns;       // 32-bit variant, ULONG64 for 64-bit hdr? See note
    ULONG NumberOfPages;      // total page count across all runs
    PHYSICAL_MEMORY_RUN Runs[NumberOfRuns];
};
```

| Offset (`_H*_PHYSICAL_MEMORY_BLOCK`) | Size (32-bit / 64-bit) | Field         | Notes |
| ------------------------------------ | ---------------------: | ------------- | ----- |
| `+0x00`                              | 4 / 4                  | `NumberOfRuns`| Deep View caps this at 4 096 for safety. |
| `+0x04`                              | 4 / 4                  | `NumberOfPages` | Total page count. |
| `+0x08 + i * RunStride`              | `RunStride`            | `Run[i]`      | `RunStride` is 8 on x86 (two ULONGs), 16 on x64 (two ULONG64s). |

Each run:

| Offset within run | Size | Field        | Description                                     |
| ----------------: | ---: | ------------ | ----------------------------------------------- |
| `+0x00`           | 4/8  | `BasePage`   | First PFN (page frame number) of the run.       |
| `+0x04` / `+0x08` | 4/8  | `PageCount`  | Number of contiguous pages in the run.          |

The runs are stored **in PFN order**. The i-th run's bytes start at
file offset `HeaderSize + Σ_{j<i}(run[j].PageCount × 0x1000)`.

!!! note "`NumberOfRuns` width"
    The Windows header uses `ULONG` (32-bit) for this count in both the
    32-bit and 64-bit dump headers — only the *run entries* grow.
    Deep View parses both as 32-bit to match the OS layout.

## `BITMAP_DUMP` secondary header (Bitmap dumps only)

Starts at offset `HEADER_SIZE` (`0x1000` / `0x2000`).

| Offset (relative) | Size | Field              | Description                                    |
| -----------------: | ---: | ------------------ | ---------------------------------------------- |
| `+0x00`            |  4   | `Signature`        | `"SDMP"` (observed), `"DMP\0"` tolerated.      |
| `+0x04`            |  4   | `ValidDump`        | `"DUMP"`.                                      |
| `+0x08`            |  8   | *reserved*         | Zero-filled.                                   |
| `+0x10`            |  8   | `FirstPage`        | File offset of the first present page.         |
| `+0x18`            |  8   | `TotalPresentPages`| Population count of the bitmap.                |
| `+0x20`            |  8   | `Pages`            | Bit count of the bitmap (covers 1 bit / PFN).  |
| `+0x28`            | `⌈Pages/8⌉` | `Bitmap[]` | 1 bit per PFN; 1 = present, 0 = absent.        |

Present pages are packed back-to-back starting at `FirstPage`. The
`n`-th set bit corresponds to file offset
`FirstPage + n × 0x1000`, which Deep View materialises as a list of
`(BasePage, PageCount, FileOffset)` runs using
`CrashDumpLayer._runs_from_bitmap()`.

## Addressing

Deep View exposes a *physical-address* view:

1. Compute `pfn = offset // 0x1000`.
2. Find the run `R` with `R.base_page ≤ pfn < R.base_page + R.page_count`.
3. File offset = `R.file_offset + (pfn - R.base_page) × 0x1000 + (offset % 0x1000)`.

## Known variations

!!! note "BitLocker-encrypted system partition"
    When BitLocker is active, the `DumpType` is set normally but the
    encrypted VMK is **not** exported into the header — only a crash
    dump triggered by a kernel-mode bugcheck while the volume is
    unlocked captures recoverable memory.

!!! note "Active Dump (`DumpType = 7`)"
    Windows 10+ introduced "Active Memory Dump" which filters out
    hypervisor pages. On-disk it is structurally identical to a full
    dump; Deep View treats `DumpType >= 1` uniformly.

!!! note "Automatic dumps on Server Core"
    Windows 2022 Server Core defaults to **kernel dump** regardless of
    configured `CrashControl`. Expect `DumpType = 2`.

## Gotchas

* **Header size depends on arch.** The parser inspects the first 8
  bytes to discriminate; getting this wrong misaligns `DumpType` and
  `PhysicalMemoryBlock` by 4 KiB.
* **Truncated tail** — corrupted writeout leaves the trailing run
  short. Deep View zero-fills with `pad=True` and continues rather
  than raising.
* **Little endian.** Every multi-byte field is LE. Don't mix with the
  big-endian scalars in LUKS headers.
* **ARM64 dumps** use `MachineImageType = 0xAA64` and `PAGEDU64`; the
  rest of the layout is identical to x64.

## Parser

* Implementation: `src/deepview/memory/formats/crashdump.py`
* Class: `CrashDumpLayer(DataLayer)`
* Dataclass: `_Run(base_page, page_count, file_offset)`

Accessors exposed on the instance:

* `is_64bit` — bool.
* `dump_type` — 1 (full), 2 (kernel), 5 (bitmap).
* `directory_table_base` — kernel CR3 for translation plugins.
* `runs` — list of `_Run` for enumeration.

## References

* [Volatility 3 Windows crash-dump layer](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/layers/crash.py)
* [MSDN: "Varieties of Kernel-Mode Dump Files"](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files)
* [ReactOS `DUMP_HEADER` layout](https://doxygen.reactos.org/)
* [Comae / Magnet: DumpIt documentation](https://www.magnetforensics.com/resources/dumpit-for-windows/)
