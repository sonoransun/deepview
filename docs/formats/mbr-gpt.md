# MBR and GPT partition tables

Disk images (raw, eMMC, NAND after FTL) and virtual-machine images are
almost always partitioned via one of two schemes:

* **MBR** (Master Boot Record) — original PC partition table. 512-byte
  sector 0, boot code + four primary partition entries, `55 AA` boot
  signature at offset `0x1FE`.
* **GPT** (GUID Partition Table) — EFI-era replacement. Header at
  LBA 1 (offset `0x200`), partition entry array at a pointer in the
  header, with a backup copy at the end of the disk.

Deep View's `deepview.storage.partition` module handles both schemes
via a `Partition` dataclass. Detection is automatic: if GPT is present
the MBR is treated as a *protective MBR* and skipped.

## MBR

### Sector 0 layout (512 bytes)

| Offset  | Size | Field                    | Description                                             |
| ------: | ---: | ------------------------ | ------------------------------------------------------- |
| `0x000` | 446  | `BootCode`               | Boot code / loader; IBM-compatible PCs ran this from real mode. Modern systems ignore it or embed tiny loaders. |
| `0x1BE` | 16   | `Partition[0]`            | Primary partition entry 0.                              |
| `0x1CE` | 16   | `Partition[1]`            | Primary partition entry 1.                              |
| `0x1DE` | 16   | `Partition[2]`            | Primary partition entry 2.                              |
| `0x1EE` | 16   | `Partition[3]`            | Primary partition entry 3.                              |
| `0x1FE` |  2   | `BootSignature`          | **`55 AA`** — required for any valid MBR.               |

### Partition entry (16 bytes each)

| Offset | Size | Field                     | Description                                             |
| -----: | ---: | ------------------------- | ------------------------------------------------------- |
| `+0x0` |  1   | `BootIndicator`           | `0x80` = active/bootable, `0x00` = not bootable.        |
| `+0x1` |  3   | `StartingCHS`             | Cylinder/Head/Sector — **ignored** on any post-LBA system. |
| `+0x4` |  1   | **`PartitionType`**       | System ID byte. See table below for well-known values.  |
| `+0x5` |  3   | `EndingCHS`               | Ignored.                                                |
| `+0x8` |  4   | `StartingLBA`             | First LBA of the partition (LE uint32).                 |
| `+0xC` |  4   | `SectorCount`             | Number of sectors in the partition (LE uint32).         |

Bytes → bytes conversion: `start_offset = StartingLBA * 512`,
`size = SectorCount * 512`.

### Common `PartitionType` values

| Type byte | Meaning                                             |
| --------- | --------------------------------------------------- |
| `0x00`    | Empty / unused. Skipped by Deep View.                |
| `0x07`    | NTFS / exFAT / HPFS.                                 |
| `0x0B`    | FAT32 with CHS.                                      |
| `0x0C`    | FAT32 with LBA.                                      |
| `0x0F`    | Extended partition (LBA).                            |
| `0x27`    | Hidden NTFS — recovery partitions on modern Windows. |
| `0x82`    | Linux swap / Solaris.                                |
| `0x83`    | Linux native filesystem.                             |
| `0x8E`    | Linux LVM.                                           |
| `0xA5`    | FreeBSD.                                             |
| `0xA8`    | macOS (UFS) — legacy.                                |
| `0xAB`    | Apple Boot.                                          |
| `0xAF`    | Apple HFS+/HFSX.                                     |
| `0xEE`    | **GPT Protective MBR.** Covers the entire disk so legacy tools treat the disk as full. |
| `0xEF`    | EFI System Partition (FAT).                          |
| `0xFB`    | VMware VMFS.                                         |

Deep View emits the type byte as a hex string (`f"0x{type_byte:02x}"`)
in the `Partition.type_id` field.

### Extended partitions

`0x05` and `0x0F` partition types delimit an **extended partition**.
Inside that region sits a chain of EBRs (Extended Boot Records) which
have the same 512-byte layout as an MBR but only use the first two
partition entries. Deep View's current parser **does not walk
extended chains** — it records the extended partition as a single
slice and leaves further subdivision to downstream carvers.

## GPT

GPT lives at LBA 1 of the disk (offset `0x200` for 512-byte sectors, or
`0x1000` for 4 KiB-native drives). A protective MBR at LBA 0 keeps
pre-EFI tools from misrecognising the disk.

### GPT header (92 bytes at LBA 1)

| Offset  | Size | Field                     | Description                                               |
| ------: | ---: | ------------------------- | --------------------------------------------------------- |
| `0x00`  |  8   | `Signature`               | **`"EFI PART"`** (`45 46 49 20 50 41 52 54`).             |
| `0x08`  |  4   | `Revision`                | `0x00010000` for GPT 1.0.                                 |
| `0x0C`  |  4   | `HeaderSize`              | Usually `92`.                                             |
| `0x10`  |  4   | `HeaderCRC32`             | CRC32 of this header with `HeaderCRC32` zeroed out.       |
| `0x14`  |  4   | *reserved*                | Zero.                                                     |
| `0x18`  |  8   | `MyLBA`                   | LBA of this header (normally `1`).                        |
| `0x20`  |  8   | `AlternateLBA`            | LBA of the backup header (normally `disk_size_lba - 1`).  |
| `0x28`  |  8   | `FirstUsableLBA`          | First LBA usable for partitions.                          |
| `0x30`  |  8   | `LastUsableLBA`           | Last LBA usable for partitions.                           |
| `0x38`  | 16   | `DiskGUID`                | Unique GUID for the disk.                                 |
| `0x48`  |  8   | `PartitionEntryLBA`       | LBA of the partition entry array (normally `2`).          |
| `0x50`  |  4   | `NumberOfPartitionEntries`| Usually `128`.                                            |
| `0x54`  |  4   | `SizeOfPartitionEntry`    | Usually `128`.                                            |
| `0x58`  |  4   | `PartitionEntryArrayCRC32`| CRC32 of the entire partition entry array.                |

Deep View parses only the fields it needs:
`PartitionEntryLBA` (offset 72), `NumberOfPartitionEntries` (offset 80),
`SizeOfPartitionEntry` (offset 84).

### GPT partition entry (≥ 128 bytes)

| Offset  | Size | Field                     | Description                                               |
| ------: | ---: | ------------------------- | --------------------------------------------------------- |
| `0x00`  | 16   | `PartitionTypeGUID`       | Filesystem / usage identifier.                            |
| `0x10`  | 16   | `UniquePartitionGUID`     | Per-partition unique ID.                                  |
| `0x20`  |  8   | `StartingLBA`             | First LBA (LE uint64).                                    |
| `0x28`  |  8   | `EndingLBA`               | Last LBA (inclusive; LE uint64).                          |
| `0x30`  |  8   | `Attributes`              | Bit flags (system, read-only, hidden, shadow copy, ...).  |
| `0x38`  | 72   | `PartitionName`           | UTF-16LE, up to 36 characters.                            |

Byte offset = `StartingLBA * 512`; size = `(EndingLBA - StartingLBA + 1) * 512`.

### Partition type GUIDs (common)

| GUID (lowercase)                                      | Meaning                          |
| ----------------------------------------------------- | -------------------------------- |
| `c12a7328-f81f-11d2-ba4b-00a0c93ec93b`                | EFI System Partition (ESP).      |
| `ebd0a0a2-b9e5-4433-87c0-68b6b72699c7`                | Microsoft Basic Data.            |
| `e3c9e316-0b5c-4db8-817d-f92df00215ae`                | Microsoft Reserved (MSR).        |
| `de94bba4-06d1-4d40-a16a-bfd50179d6ac`                | Windows Recovery.                |
| `0fc63daf-8483-4772-8e79-3d69d8477de4`                | Linux Filesystem.                |
| `a19d880f-05fc-4d3b-a006-743f0f84911e`                | Linux RAID.                      |
| `0657fd6d-a4ab-43c4-84e5-0933c84b4f4f`                | Linux swap.                      |
| `e6d6d379-f507-44c2-a23c-238f2a3df928`                | Linux LVM.                       |
| `933ac7e1-2eb4-4f13-b844-0e14e2aef915`                | Linux `/home`.                   |
| `48465300-0000-11aa-aa11-00306543ecac`                | Apple HFS+.                      |
| `7c3457ef-0000-11aa-aa11-00306543ecac`                | Apple APFS.                      |
| `426f6f74-0000-11aa-aa11-00306543ecac`                | Apple Boot.                      |

GUIDs in GPT are stored in **mixed-endian** form: the first three
fields are little-endian, the last two are big-endian — matching
Microsoft's `EFI_GUID` in-memory representation. Deep View uses
`uuid.UUID(bytes_le=...)` to decode.

## Sector sizes

| Disk type                  | Logical sector | Physical sector |
| -------------------------- | -------------: | --------------: |
| Classic HDD                | 512            | 512             |
| Advanced Format HDD (AF)   | 512 (emulated) | 4 096           |
| 4Kn HDD                    | 4 096          | 4 096           |
| eMMC                       | 512            | 512 (logical)   |
| NVMe                       | 512 or 4 096   | 4 096           |

Both parsers assume 512-byte logical sectors. For 4Kn images, convert
LBA → byte offset as `lba * 4096`.

## Known variations

!!! note "Hybrid MBR"
    Some Apple (Boot Camp) and TiVo disks ship a *hybrid MBR* — a
    real MBR that duplicates the GPT's layout in four primary slots.
    Deep View's MBR parser sees the duplicated entries; consumers
    should prefer the GPT's entries.

!!! note "Protective MBR with `0xEE`"
    If sector 0 contains a single partition entry of type `0xEE`
    covering the entire disk, it's a protective MBR. Deep View's
    MBR parser will still report it as a single-partition disk; the
    GPT parser then takes over.

!!! warning "Backup GPT may disagree"
    The primary GPT at LBA 1 and the backup GPT at the last LBA must
    carry matching CRC32s. If they don't, the disk has been
    tampered with or partially overwritten. Deep View currently
    reads only the primary; cross-check manually if chain-of-custody
    is critical.

!!! warning "Extended MBR chains"
    MBR entries with type `0x05` / `0x0F` point to an extended
    partition that contains a linked list of EBRs. The current
    parser surfaces the extended partition as a single slice — it
    does not walk the EBR chain. Carve inside with the filesystem
    layer.

## Gotchas

* **Little-endian scalars** throughout MBR and GPT headers.
* **GPT entries' `EndingLBA` is inclusive** (same as LiME / hiberfil).
  Use `(end - start + 1)` for the length.
* **128 partition entries × 128 bytes = 16 KiB** is the standard GPT
  reservation — Deep View uses the header-advertised values and does
  not hard-code this.
* **Protective MBR 0xEE partitions** can report a `SectorCount` of
  `0xFFFFFFFF` (max uint32) when the disk is larger than 2 TiB.
  Interpret that value as "whole disk" rather than literal.

## Parser

* Implementation: `src/deepview/storage/partition.py`
* Dataclass: `Partition(index, scheme, type_id, name, start_offset, size, boot, uuid)`.
* Parsers: `_parse_mbr(layer) -> list[Partition]`, `_parse_gpt(layer) -> list[Partition]`.

## References

* [UEFI Specification v2.10 — "GUID Partition Table"](https://uefi.org/specifications)
* [Microsoft: "Windows and GPT FAQ"](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-and-gpt-faq)
* [Wikipedia: Master Boot Record](https://en.wikipedia.org/wiki/Master_boot_record)
* [Wikipedia: GUID Partition Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)
* [`gdisk`, `sgdisk` man pages](https://www.rodsbooks.com/gdisk/)
* [Apple: "About Startup Disks"](https://support.apple.com/)
