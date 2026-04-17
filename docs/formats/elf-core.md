# ELF core dumps

Linux's `kdump`, `crash(8)`, and several userspace acquisition tools
(notably `avml` and `microsoft/avml-convert`) emit a full-system
physical-memory image as an **ELF64 core file**. The layout reuses the
well-known ELF program-header table: each populated physical range is a
`PT_LOAD` segment whose `p_paddr` field records the physical address at
which the bytes were captured.

Deep View supports 64-bit little-endian ELF core files
(`EI_CLASS == ELFCLASS64`, `EI_DATA == ELFDATA2LSB`). 32-bit cores are
rejected with `FormatError`.

## Signature

* **Magic (offset 0):** `7F 45 4C 46` — `"\x7fELF"`.
* **EI_CLASS (offset 4):** `2` (`ELFCLASS64`). Must be 64-bit.
* **EI_DATA (offset 5):** `1` (`ELFDATA2LSB`). Little endian.
* **`e_type` (offset 16):** `ET_CORE = 4` for core files (Deep View does
  not enforce this — PT_LOAD segments with `p_paddr` work for any
  `e_type`).

## ELF64 header (relevant fields only)

| Offset | Size | Field         | Description                                                   |
| -----: | ---: | ------------- | ------------------------------------------------------------- |
| `0x00` | 16   | `e_ident`     | Identification — `7F 45 4C 46` + class/data/version flags.    |
| `0x10` |  2   | `e_type`      | `ET_CORE = 4` for core dumps.                                 |
| `0x12` |  2   | `e_machine`   | `0x3E` (x86-64), `0xB7` (aarch64), etc.                       |
| `0x14` |  4   | `e_version`   | `1` (`EV_CURRENT`).                                           |
| `0x18` |  8   | `e_entry`     | Ignored for cores.                                            |
| `0x20` |  8   | `e_phoff`     | **File offset of program-header table.**                      |
| `0x28` |  8   | `e_shoff`     | Section-header offset (usually 0 for cores).                  |
| `0x30` |  4   | `e_flags`     | Architecture-specific flags.                                  |
| `0x34` |  2   | `e_ehsize`    | ELF header size (64).                                         |
| `0x36` |  2   | `e_phentsize` | Size of one program header — **56** for ELF64.                |
| `0x38` |  2   | `e_phnum`     | Number of program headers. Capped at 65 536 by the parser.    |
| `0x3A` |  2   | `e_shentsize` | Section-header entry size (usually `0x40`).                   |
| `0x3C` |  2   | `e_shnum`     | Number of section headers.                                    |
| `0x3E` |  2   | `e_shstrndx`  | Section-name string-table index.                              |

Total header size = 64 bytes.

## Program header (ELF64, 56 bytes)

| Offset | Size | Field       | Description                                                         |
| -----: | ---: | ----------- | ------------------------------------------------------------------- |
| `0x00` |  4   | `p_type`    | Segment type. Deep View consumes `PT_LOAD = 1` and ignores the rest. |
| `0x04` |  4   | `p_flags`   | `PF_X=1 | PF_W=2 | PF_R=4`. Purely informational for memory layers. |
| `0x08` |  8   | `p_offset`  | File offset of the segment bytes.                                   |
| `0x10` |  8   | `p_vaddr`   | Virtual address (in the captured kernel's address space).           |
| `0x18` |  8   | `p_paddr`   | **Physical address.** Populated by kdump for PT_LOAD segments.      |
| `0x20` |  8   | `p_filesz`  | Segment size on disk (what Deep View serves).                       |
| `0x28` |  8   | `p_memsz`   | In-memory size. May exceed `p_filesz` for BSS-style holes.          |
| `0x30` |  8   | `p_align`   | Alignment requirement (ignored by readers).                         |

## Segment types

* `PT_LOAD = 1` — loadable segment carrying the physical-memory bytes.
  Every populated range of RAM is expressed as one PT_LOAD.
* `PT_NOTE = 4` — a blob of ELF notes. In core dumps this carries CPU
  state (`NT_PRSTATUS`), the process list (`NT_TASKSTRUCT`), and on
  some ARM64 builds the DT_VADDR/DT_PADDR translation table.
  Deep View's memory layer does **not** parse PT_NOTE — it is kept for
  higher-level plugins (Volatility 3, kexec).

## NT_PRSTATUS record (PT_NOTE body)

PT_NOTE segments are a sequence of `(namesz, descsz, type, name, desc)`
records. The `NT_PRSTATUS` record (`type = 1`) carries register state
at the moment of the crash. Padding rules:

| Offset      | Size       | Field      | Description                                |
| ----------- | ---------- | ---------- | ------------------------------------------ |
| `0x00`      |  4         | `n_namesz` | Length of `name` including NUL.            |
| `0x04`      |  4         | `n_descsz` | Length of `desc`.                          |
| `0x08`      |  4         | `n_type`   | `NT_PRSTATUS = 1`, `NT_PRPSINFO = 3`, etc. |
| `0x0C`      | `n_namesz` | `name`     | ASCII, usually `"CORE\0"`.                 |
| align(4)    | `n_descsz` | `desc`     | Type-specific body (CPU registers).        |
| align(4)    |  —         | padding    | Next record is 4-byte aligned.             |

## Physical vs. virtual address space

The layer's `use_physical` flag selects which address the segment is
keyed by:

* `use_physical=True` (default) — lookups go through `p_paddr`. This
  is what acquisition tools write and what memory-analysis plugins
  expect.
* `use_physical=False` — lookups go through `p_vaddr`. Useful when the
  core contains user-process memory rather than system RAM.

## Known variations

!!! note "Sparse PT_LOAD with p_filesz < p_memsz"
    Some ARM64 kdump configurations elide zero pages: `p_memsz` records
    the full virtual range but `p_filesz` only the present bytes. Deep
    View currently serves `p_filesz` bytes and returns empty for the
    zero tail; set `pad=True` on `read` to zero-fill.

!!! note "kexec hole ranges"
    `PT_LOAD` segments with `p_paddr = 0` and `p_filesz = 0` are
    padding the table to preserve ELF alignment. The parser skips them
    implicitly because `_find_segment` uses `p_filesz` for containment.

!!! note "AArch64 `NT_VMCOREDD`"
    The dump-device note carries vendor metadata (serial number,
    firmware build). Never needed to address pages; safe to skip.

!!! warning "Compressed ELF cores"
    `makedumpfile -c` produces a compressed ELF-like stream that is
    **not** a valid ELF core (the `p_filesz` field is misleading).
    Deep View rejects these — decompress with `makedumpfile -R`
    first.

## Gotchas

* **`e_phnum == PN_XNUM (0xFFFF)`** — when there are more than 65 534
  program headers, the ELF spec moves the count to `sh_info` of the
  section-zero header. Deep View caps `e_phnum` at 65 536 and surfaces
  `FormatError` if that boundary is exceeded; in practice no real core
  dump hits this.
* **Duplicate PT_LOAD for same physical address** — kdump on certain
  NUMA layouts emits overlapping segments. The first match wins in
  Deep View's linear search; subsequent duplicates are unreachable.
* **Signed `p_offset` arithmetic** — on a 32-bit Python build with an
  unusually large core (> 2 GiB), use `int(p_offset)` explicitly.
  Deep View already does this via `struct.unpack_from("<Q", ...)`.

## Parser

* Implementation: `src/deepview/memory/formats/elf_core.py`
* Class: `ELFCoreLayer(DataLayer)`
* Exposed struct: `ELFSegment(vaddr, paddr, file_offset, file_size, mem_size, flags)`

## References

* [ELF-64 Object File Format](https://uclibc.org/docs/elf-64-gen.pdf)
* [System V Application Binary Interface — Core Dumps](https://www.sco.com/developers/gabi/latest/ch5.pheader.html)
* [Linux kernel Documentation/admin-guide/kdump/kdump.rst](https://www.kernel.org/doc/html/latest/admin-guide/kdump/kdump.html)
* [avml: Acquire Volatile Memory for Linux](https://github.com/microsoft/avml)
