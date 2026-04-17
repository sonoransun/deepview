# Windows minidump (`.dmp`, `MiniDumpWithFullMemory`)

Windows minidumps are the userland crash-dump format emitted by
`MiniDumpWriteDump` (`dbghelp.dll`) and consumed by WinDbg, the Visual
Studio debugger, and the CLR. A minidump is a small TLV container — a
`MINIDUMP_HEADER` points at a stream directory, and each stream carries
a specific kind of evidence: thread lists, module lists, registers, and
(for full dumps) raw memory ranges.

Deep View parses the `MiniDumpWithFullMemory` flavour which carries a
`Memory64ListStream` (stream type 9). The descriptor array enumerates
contiguous virtual-address ranges; their bytes sit back-to-back at a
single `BaseRva` offset.

## Signature

* **Magic (offset `0x00`, LE `DWORD`):** `0x504D444D` — ASCII `"MDMP"`.
* **Version low word (offset `0x04`):** `MINIDUMP_VERSION = 0xA793`.

## `MINIDUMP_HEADER` (32 bytes)

| Offset | Size | Field                  | Description                                              |
| -----: | ---: | ---------------------- | -------------------------------------------------------- |
| `0x00` |  4   | `Signature`            | `0x504D444D` (`"MDMP"`).                                  |
| `0x04` |  4   | `Version`              | Low word = `MINIDUMP_VERSION`, high word = implementation.|
| `0x08` |  4   | `NumberOfStreams`      | Number of entries in the stream directory.              |
| `0x0C` |  4   | `StreamDirectoryRva`   | File offset of the `MINIDUMP_DIRECTORY` array.          |
| `0x10` |  4   | `CheckSum`             | Optional CRC; usually 0. Not validated.                 |
| `0x14` |  4   | `TimeDateStamp`        | `time_t` when the dump was written.                     |
| `0x18` |  8   | `Flags`                | `MINIDUMP_TYPE` bitmask (`0x2 = WithFullMemory`, ...).  |

Fixed struct length = 32 bytes. Parsed as `"<IIIIIIQ"`.

## `MINIDUMP_DIRECTORY` entry (12 bytes each)

Array of `NumberOfStreams` entries starting at `StreamDirectoryRva`.

| Offset | Size | Field         | Description                                             |
| -----: | ---: | ------------- | ------------------------------------------------------- |
| `+0x00`|  4   | `StreamType`  | `MINIDUMP_STREAM_TYPE`. Deep View looks for `9`.        |
| `+0x04`|  4   | `DataSize`    | Size of the stream body.                                |
| `+0x08`|  4   | `Rva`         | File offset of the stream body.                         |

Selected `StreamType` values:

| Value | Name                            | Purpose                              |
| ----: | ------------------------------- | ------------------------------------ |
|   `3` | `ThreadListStream`              | `MINIDUMP_THREAD[]`.                 |
|   `4` | `ModuleListStream`              | `MINIDUMP_MODULE[]` (DLLs loaded).   |
|   `5` | `MemoryListStream`              | Short-form memory ranges (< 4 GiB).  |
|   `6` | `ExceptionStream`               | Faulting context.                    |
|   `7` | `SystemInfoStream`              | CPU / OS build.                      |
|   `9` | `Memory64ListStream`            | **Full-memory ranges.** Deep View consumer. |
|  `15` | `UnloadedModuleListStream`      | Recently unloaded DLLs.              |
|  `16` | `MiscInfoStream`                | Process times, process ID.           |
|  `21` | `MemoryInfoListStream`          | `MEMORY_BASIC_INFORMATION`-equivalent. |

## `MINIDUMP_MEMORY64_LIST` stream body

Pointed at by a directory entry with `StreamType == 9`.

| Offset | Size | Field                    | Description                                             |
| -----: | ---: | ------------------------ | ------------------------------------------------------- |
| `+0x00`|  8   | `NumberOfMemoryRanges`   | Count of descriptors that follow.                      |
| `+0x08`|  8   | `BaseRva`                | File offset where the **concatenated** range bytes start. |
| `+0x10`| 16 × N | `MINIDUMP_MEMORY_DESCRIPTOR64[]` | One descriptor per range.                |

### `MINIDUMP_MEMORY_DESCRIPTOR64` (16 bytes each)

| Offset | Size | Field                  | Description                                             |
| -----: | ---: | ---------------------- | ------------------------------------------------------- |
| `+0x00`|  8   | `StartOfMemoryRange`   | Virtual-address start of the range.                     |
| `+0x08`|  8   | `DataSize`             | Size of the range in bytes.                             |

The actual bytes for descriptor `i` live at file offset
`BaseRva + Σ_{j<i}(descriptor[j].DataSize)`. Deep View materialises the
runs as a sorted list keyed by `StartOfMemoryRange` and uses
`bisect_right` for O(log N) lookup.

## Reading an address

```python
def find_run(va: int) -> Memory64Run | None:
    idx = bisect_right(run_starts, va) - 1
    if idx < 0:
        return None
    r = runs[idx]
    if r.virtual_address <= va < r.virtual_address + r.size:
        return r
    return None
```

`read(offset, length, pad=False)` walks the runs; unmapped gaps return
empty bytes unless `pad=True` zero-fills them.

## Known variations

!!! note "32-bit vs 64-bit minidumps"
    The `Memory64ListStream` exists in both architectures — Microsoft
    adopted 64-bit addresses even for 32-bit dumps from Windows XP
    onward. A matching `MemoryListStream` (type 5) exists with 32-bit
    RVAs for legacy consumers; Deep View does not parse it.

!!! note "Truncated dumps"
    A crashed process can leave `DataSize` set to a range that extends
    past EOF. Deep View rejects this (`"Minidump run i extends past
    EOF"`) rather than silently aliasing into adjacent runs.

!!! note "`MiniDumpWithDataSegs` and friends"
    Partial minidumps that only carry thread state (`WithDataSegs`,
    `WithIndirectlyReferencedMemory`, ...) produce no Memory64 stream.
    The parser leaves `runs` empty and `read()` returns zeros. Use the
    stream directory directly for module / thread analysis.

!!! warning "Non-monotonic run order"
    The descriptors are **not** required to be sorted. Deep View sorts
    them on load; if you consume the struct directly be sure to sort.

## Gotchas

* **RVA vs VA.** `Rva` fields are file offsets. `StartOfMemoryRange`
  and `StartOfModule` are virtual addresses. Don't confuse them.
* **Stream directory size cap.** Deep View checks
  `StreamDirectoryRva + NumberOfStreams * 12 <= file_size` before
  reading — corrupted dumps with a gigantic `NumberOfStreams` fail
  fast.
* **`Flags == 0x00` dumps** often still carry a `Memory64ListStream`
  if the caller explicitly requested `MiniDumpWithFullMemory | 0`.
  Do not gate on the flag; check for the stream directly.

## Parser

* Implementation: `src/deepview/storage/formats/minidump_full.py`
* Class: `MinidumpFullLayer(DataLayer)`
* Dataclass: `Memory64Run(virtual_address, file_offset, size)`

## References

* [MSDN: `MINIDUMP_HEADER` structure](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_header)
* [MSDN: `MINIDUMP_MEMORY64_LIST` structure](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory64_list)
* [MSDN: `MINIDUMP_DIRECTORY`](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_directory)
* [MSDN: `MINIDUMP_TYPE` flags](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_type)
* [Volatility 3 minidump layer](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/layers/physical.py)
