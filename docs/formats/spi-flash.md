# SPI-NOR flash dump

A SPI-NOR flash chip is a serial NOR device with a simple byte-
addressed interface — no pages, no spare area, no bad-block management.
Forensic SPI acquisitions (via flashrom, Dediprog, Bus Pirate, CH341A,
or in-circuit RoA probes) produce a **flat byte stream** equal in
length to the chip's declared density.

Many (but not all) modern SPI-NOR chips include an **SFDP** (Serial
Flash Discoverable Parameters) block at a vendor-defined offset
(commonly `0x000000` when dumping the descriptor region alone, or
pointed at by an Intel Flash Descriptor in larger images). When
present, SFDP self-describes the chip's density, erase-block layout,
and command set.

## File structure

```
+-------------------------------------------------+
| SPI-NOR address space (1 MiB - 256 MiB, flat)   |
+-------------------------------------------------+
```

* **Block size:** configurable (4 KiB sub-sector most common; 64 KiB
  sector; 256 KiB block).
* **Magic:** optional — only SFDP carries one. Image without SFDP is
  un-fingerprintable from its contents alone.

## SFDP header (optional, offset 0 of the descriptor region)

| Offset  | Size | Field                   | Description                                            |
| ------: | ---: | ----------------------- | ------------------------------------------------------ |
| `0x000` |  4   | `Signature`             | `"SFDP"` (`0x50 0x44 0x46 0x53`, little-endian DWORD `0x50444653`). |
| `0x004` |  1   | `MinorVersion`          | Observed `0x05` (JEDEC 2016) … `0x08`.                 |
| `0x005` |  1   | `MajorVersion`          | Always `0x01`.                                         |
| `0x006` |  1   | `NumParameterHeaders`   | `N-1`: N parameter headers follow (JEDEC Basic is always #0). |
| `0x007` |  1   | `UnusedFF`              | `0xFF`.                                                |
| `0x008` |  8   | `JEDECBasicFPTHeader`   | Parameter header for the JEDEC Basic Flash Parameter Table. |
| `0x010` |  8 × N | Additional parameter headers | Vendor-specific tables.                          |

### Parameter header (8 bytes each)

| Offset | Size | Field                    | Description                                             |
| -----: | ---: | ------------------------ | ------------------------------------------------------- |
| `+0x00`|  1   | `IDLSB`                  | Parameter ID low byte.                                  |
| `+0x01`|  1   | `MinorRev`               | Table minor revision.                                   |
| `+0x02`|  1   | `MajorRev`               | Table major revision (always `0x01`).                   |
| `+0x03`|  1   | `LengthDWords`           | Size of the pointed-at table in DWORDs.                 |
| `+0x04`|  3   | `PointerToTable`         | 24-bit offset (LE) to the table, from the start of SFDP.|
| `+0x07`|  1   | `IDMSB`                  | Parameter ID high byte. `IDLSB = 0x00, IDMSB = 0xFF` is the JEDEC Basic table. |

## JEDEC Basic Flash Parameter Table (BFPT, 1st DWORD)

| DWORD | Offset | Field                   | Meaning                                                 |
| ----: | -----: | ----------------------- | ------------------------------------------------------- |
|  1    | `+0x00`| Erase / write flags     | 4 KiB erase support, block-protect scheme, write granularity. |
|  2    | `+0x04`| **Flash density**       | `bit 31 == 0` → `value + 1` **bits**; `bit 31 == 1` → `2^(value & 0x7FFFFFFF)` **bits**. |
|  3    | `+0x08`| Fast read capabilities  | 1-1-1 / 1-1-2 / 1-2-2 / 1-1-4 / 1-4-4 support flags.    |
|  4..N | ...    | Sector / block erase type codes, power-down, reset.                                      |

### Deep View's density shortcut

`SPIFlashLayer._probe_sfdp()` takes a **conservative shortcut**: it
assumes the first parameter table starts immediately after the SFDP
header and reads the density DWORD at offset `0x34`:

```python
density = struct.unpack_from("<I", mmap_, 0x34)[0]
if density & 0x80000000:
    bits = 1 << (density & 0x7FFFFFFF)
else:
    bits = density + 1
total_size = bits // 8
```

The result is stashed in `layer.total_size` and
`layer.sfdp_detected = True`.

!!! warning "The shortcut can be wrong"
    A spec-complete parser would read the BFPT pointer from the
    JEDEC parameter header at offset `0x08` and follow it. Deep
    View's shortcut works for every chip whose dump starts at SFDP
    (the BFPT follows immediately in practice) but misreports size
    when the image is the full descriptor region of an Intel-PCH
    firmware and SFDP sits inside a subregion. In that case,
    `total_size` falls back to the file size, which is the correct
    read anyway.

## Common SPI-NOR magics in firmware images

Although SPI-NOR chips themselves have no file magic, the firmware
images written to them do. These are useful when walking a dump:

| Magic               | At offset            | Meaning                                |
| ------------------- | -------------------- | -------------------------------------- |
| `5A A5 F0 0F`       | `0x00`               | Intel Flash Descriptor ("Descriptor Region"). |
| `_FVH`              | `0x38` into Firmware Volume | UEFI firmware volume header.    |
| `KMDF` / `STDT`     | varies               | Intel bootguard / startup ACM.         |
| `BIOS_START`        | varies               | AMD PSP firmware.                      |
| `NARM` / `UEFI`     | varies               | Coreboot / TianoCore blobs.            |

## Known variations

!!! note "SFDP optional"
    Chips predating JEDEC JESD216 (e.g. many older Winbond / SST
    parts) do not carry SFDP at all. Without SFDP the only way to
    know the density is either the file size or a lookup table
    keyed on the JEDEC ID returned by `RDID` (opcode `0x9F`) —
    neither is visible from the dumped bytes.

!!! note "Multiple parameter tables"
    Vendor-specific tables (Winbond ID 0xEF, Macronix 0xC2, ISSI
    0x9D, ...) add register maps, OTP regions, security-register
    layouts. Deep View ignores them; carve them if needed from
    `layer.total_size + parameter_pointer`.

!!! note "`flashrom --ich` dumps"
    flashrom's ICH (Intel chipset) mode emits a multi-region image
    containing `Descriptor`, `BIOS`, `ME`, `GbE`, and `EC`
    subregions. Use `UEFITool` or `ifdtool` to split them before
    per-region analysis.

!!! warning "Bit endianness quirks"
    SFDP scalars are little-endian, but the BFPT density's bit-31
    flag is tested **after** LE decode. Do not byte-swap.

## Gotchas

* **Images that are only the descriptor region.** If the full flash
  is 16 MiB and the acquirer dumped only the 4 KiB descriptor, the
  SFDP density field still points at the 16 MiB chip — but the file
  is 4 KiB. Deep View's `total_size` will overstate the file, and
  reads past EOF return empty / zero-padded bytes.
* **`0xFF`-pattern unused regions.** Erased SPI-NOR pages read
  `0xFF`. Long stretches of `0xFF` are not truncation; they are a
  legitimate erased region.
* **Sector size ≠ file length.** `SPIFlashLayer.sector_size` is a
  *probe hint* for carvers, not the actual chip physics — the
  constructor accepts any `sector_size >= 1`.

## Parser

* Implementation: `src/deepview/storage/formats/spi_flash.py`
* Class: `SPIFlashLayer(DataLayer)`
* Instance attributes: `total_size`, `sfdp_detected`.

## References

* [JEDEC JESD216F: Serial Flash Discoverable Parameters](https://www.jedec.org/standards-documents/docs/jesd216f)
* [`flashrom` project](https://flashrom.org/)
* [Intel Firmware Descriptor reference](https://www.intel.com/content/dam/doc/application-note/io-controller-hub-10-firmware-hub-spi-flash-design-guide.pdf)
* [UEFITool — UEFI firmware parser](https://github.com/LongSoft/UEFITool)
* [`SFDP_basic.xml` in flashrom tree](https://github.com/flashrom/flashrom/blob/master/sfdp.c)
