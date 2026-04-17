# Format Reference

This section is the byte-level reference for every memory image, storage
image, and encrypted-container format that Deep View's parsers recognise.
Each page covers the magic signature, on-disk header layout, body/payload
encoding, known vendor variations, gotchas, and the Deep View parser file
that implements it.

The pages are reference material aimed at operators who need to explain
*why* a parser returned a particular value, forensic analysts writing
carvers, and contributors adding new formats. Nothing here is a tutorial
— see the `cookbook/` and `guides/` sections for that.

## Conventions

* Byte offsets are written in hexadecimal with a `0x` prefix; sizes are
  decimal bytes unless a unit is attached.
* Endianness is called out explicitly. LiME / ELF core / Windows
  crash-dump / minidump / VeraCrypt master key material are **little
  endian**. VeraCrypt header scalars, LUKS1 and LUKS2 scalars are
  **big endian**.
* Where the spec uses a non-power-of-two struct size (e.g. LUKS1 =
  592 bytes) the table reproduces the exact on-disk layout — do not
  align fields in code that consumes these.

## Memory-image formats

| Format             | Magic                          | Parser                                                                                       |
| ------------------ | ------------------------------ | -------------------------------------------------------------------------------------------- |
| [LiME](lime.md)    | `0x4C694D45` (`"LiME"`)        | `src/deepview/memory/formats/lime_format.py`                                                 |
| [ELF core](elf-core.md) | `7F 45 4C 46` (`"\x7fELF"`) | `src/deepview/memory/formats/elf_core.py`                                                    |
| [Crash dump](crashdump.md) | `"PAGE"` / `"PAGEDU64"`  | `src/deepview/memory/formats/crashdump.py`                                                   |
| [Hibernation](hibernation.md) | `"hibr"` / `"HIBR"` / `"wake"` / `"WAKE"` | `src/deepview/memory/formats/hibernation.py`                                     |
| [Minidump](minidump.md) | `"MDMP"`                   | `src/deepview/storage/formats/minidump_full.py`                                              |

## Virtualisation-layer memory

| Format                                 | Magic / sidecar                                   | Parser                                              |
| -------------------------------------- | ------------------------------------------------- | --------------------------------------------------- |
| [VMware `.vmem`](vmware-vmem.md)       | flat + optional `.vmss` / `.vmsn` (`0xBED2BED0`)  | `src/deepview/storage/formats/vmware_vmem.py`       |
| [VirtualBox `.sav`](virtualbox-sav.md) | `"SSM"` + tagged records                          | `src/deepview/storage/formats/virtualbox_sav.py`    |
| [Hyper-V `.vmrs`](hyperv-vmrs.md)      | `"VMRS"` + companion `.bin`                       | `src/deepview/storage/formats/hyperv_vmrs.py`       |

## Hardware-assisted acquisition

| Format                          | Structure                                       | Parser                                             |
| ------------------------------- | ----------------------------------------------- | -------------------------------------------------- |
| [Raw NAND](nand-raw.md)         | page + spare/OOB interleaved                    | `src/deepview/storage/formats/nand_raw.py`         |
| [Raw eMMC](emmc-raw.md)         | 512-byte sectors + boot1/boot2/RPMB             | `src/deepview/storage/formats/emmc_raw.py`         |
| [SPI flash](spi-flash.md)       | flat NOR + optional `"SFDP"` table              | `src/deepview/storage/formats/spi_flash.py`        |
| [JTAG RAM](jtag-ram.md)         | flat + JSON region sidecar                      | `src/deepview/storage/formats/jtag_ram.py`         |
| [GPU VRAM](gpu-vram.md)         | flat passthrough + vendor tag                   | `src/deepview/storage/formats/gpu_vram.py`         |

## Encrypted containers

| Format                                  | Signature                           | Parser                                             |
| --------------------------------------- | ----------------------------------- | -------------------------------------------------- |
| [LUKS1](luks1.md)                       | `"LUKS\xba\xbe"` + version 1        | `src/deepview/storage/containers/luks.py`          |
| [LUKS2](luks2.md)                       | `"LUKS\xba\xbe"` + version 2        | `src/deepview/storage/containers/luks.py`          |
| [BitLocker](bitlocker.md)               | BPB.OEMID = `"-FVE-FS-"`            | `src/deepview/storage/containers/bitlocker.py`    |
| [FileVault 2](filevault2.md)            | `"CS"` @0x10 or `"NXSB"` @0x20      | `src/deepview/storage/containers/filevault2.py`   |
| [VeraCrypt / TrueCrypt](veracrypt.md)   | `"VERA"` / `"TRUE"` inside header   | `src/deepview/storage/containers/veracrypt.py`    |

## Partitioning

| Format                | Signature                 | Parser (partition probe)                        |
| --------------------- | ------------------------- | ----------------------------------------------- |
| [MBR / GPT](mbr-gpt.md) | `0x55AA` / `"EFI PART"` | `src/deepview/storage/partition.py`             |

---

## Quick magic map

| Offset  | Bytes                    | Format                          |
| ------- | ------------------------ | ------------------------------- |
| `0x00`  | `4C 69 4D 45`            | LiME                            |
| `0x00`  | `7F 45 4C 46`            | ELF core                        |
| `0x00`  | `50 41 47 45`            | 32-bit Windows crash dump       |
| `0x00`  | `50 41 47 45 44 55 36 34`| 64-bit Windows crash dump       |
| `0x00`  | `68 69 62 72` / `48 49 42 52` | Windows hiberfil.sys       |
| `0x00`  | `4D 44 4D 50`            | Windows minidump                |
| `0x00`  | `53 53 4D`               | VirtualBox saved state          |
| `0x00`  | `56 4D 52 53`            | Hyper-V `.vmrs`                 |
| `0x00`  | `4C 55 4B 53 BA BE`      | LUKS1 / LUKS2                   |
| `0x03`  | `2D 46 56 45 2D 46 53 2D`| BitLocker (`-FVE-FS-`)          |
| `0x10`  | `43 53`                  | Core Storage (FileVault 2)      |
| `0x20`  | `4E 58 53 42`            | APFS container (`NXSB`)         |
| `0x40`  | `56 45 52 41` / `54 52 55 45` | VeraCrypt / TrueCrypt (after salt, encrypted) |
| `0x1FE` | `55 AA`                  | MBR boot signature              |
| `0x200` | `45 46 49 20 50 41 52 54`| GPT header (`"EFI PART"`)       |
| `0x000` | `53 46 44 50`            | SPI-NOR SFDP table              |

## See also

* [Volatility 3 symbol table docs](https://volatility3.readthedocs.io/)
  — most Windows / Linux memory-layout details cross-reference the
  Volatility symbol model.
* [Sleuth Kit](https://www.sleuthkit.org/sleuthkit/docs/) — filesystem
  / partition table references.
* [LUKS2 on-disk format](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS2-docs)
  — canonical upstream spec.
