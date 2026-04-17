# Raw eMMC dump

An eMMC ("Embedded MultiMediaCard") is a packaged flash device with an
on-chip controller that hides the raw NAND behind a standard 512-byte
sector interface. Unlike a raw NAND chip-off acquisition, an eMMC
dump is **sector-addressed** — the host never sees pages, OOB, bad
blocks, or wear-levelling metadata. The controller exposes several
hardware partitions: a user area, two boot partitions, an RPMB
(Replay-Protected Memory Block) partition, and up to four general-purpose
partitions.

## File structure

A typical raw eMMC image is the **concatenation of all hardware
partitions** the acquirer extracted, in the following order (vendor
tools vary — `mmc` on Linux writes user-only, Corellium / Cellebrite
often concatenate boot1 + boot2 + user):

```
+--------+--------+------+---------+-------+------+------+
| boot1  | boot2  | RPMB | user    |  GP1  | GP2  | ...  |
+--------+--------+------+---------+-------+------+------+
   4 MiB    4 MiB  4 MiB  ~chip    variable
```

* **Block size: always 512 bytes.** eMMC 4.5+ also supports 4 KiB
  sectors but always presents a 512-byte logical block to the host.
* **No file-level header / magic.** The only signatures present are
  those of any partition tables that happen to sit at standard
  offsets (MBR boot signature `0x55AA`, GPT `"EFI PART"` at LBA 1).

## Hardware partitions

Each physical eMMC partition gets its own sector-0. When concatenated
into a single raw image, Deep View probes the hints below.

| Partition  | Conventional size | Typical content                                      |
| ---------- | ----------------: | ---------------------------------------------------- |
| boot1      | 4 MiB             | Primary bootloader / ROM.                            |
| boot2      | 4 MiB             | Secondary bootloader / recovery loader.              |
| RPMB       | 4 MiB             | Replay-protected, HMAC-signed.                       |
| User       | Remaining         | OS, data, usually GPT-partitioned.                   |
| GP1..GP4   | Variable          | General-purpose partitions (optional).               |

!!! note "The 4 MiB figure is a hint, not a spec"
    eMMC boot partitions are configurable in 128 KiB increments via
    `EXT_CSD[BOOT_SIZE_MULT]`. Deep View hard-codes `4 MiB` as the
    most-seen default; when the file is at least `3 × guess` bytes
    the layer populates `boot1_offset = 0`, `boot2_offset = guess`,
    `rpmb_offset = 2 × guess`. Override by consulting
    `EXT_CSD[177]` directly if you acquired the register file.

## Probe signatures

`EMMCRawLayer` inspects two canonical sectors:

| Offset  | Size | Content                  | Indicates                                   |
| ------: | ---: | ------------------------ | ------------------------------------------- |
| `0x1FE` |  2   | `55 AA`                  | MBR boot signature at LBA 0.                |
| `0x200` |  8   | `"EFI PART"`             | GPT header at LBA 1 (when image is GPT-formatted). |

Instance attributes populated by `_probe_partitions()`:

```python
has_mbr: bool
has_gpt: bool
boot1_offset: int | None
boot2_offset: int | None
rpmb_offset: int | None
```

## eMMC register blocks (sidecar, not in the image)

Full forensic acquisition also captures the eMMC's on-chip registers
— these live **outside** the user data and must be read with CMD8 /
CMD9 via the eMMC controller. Deep View does not attempt to parse
them; they belong in an acquisition-metadata JSON sidecar.

| Register  | Size      | Key fields                                                         |
| --------- | --------: | ------------------------------------------------------------------ |
| CID       | 16 bytes  | Manufacturer ID, OEM ID, product name, serial number, revision.    |
| CSD       | 16 bytes  | Sector size, write-protection, erase group, max clock.             |
| EXT_CSD   | 512 bytes | BOOT_SIZE_MULT (`[177]`), RPMB_SIZE_MULT (`[168]`), LIFE_TIME_EST. |
| OCR       | 4 bytes   | Voltage window.                                                    |

`EXT_CSD[BOOT_SIZE_MULT] × 128 KiB` = boot-partition size; this is
the authoritative source and should override Deep View's 4 MiB
default when available.

## Sector addressing

```
block_size = 512
sector_to_offset(lba) = lba * 512
offset_to_sector(off) = off // 512
```

The layer's `block_size` is user-configurable at construction time
(`EMMCRawLayer(path, block_size=4096)` for a rare 4 KiB logical
variant) but the **probe offsets remain in bytes** regardless.

## Known variations

!!! note "`mmc-utils` dumps are user-only"
    The common Linux command `dd if=/dev/mmcblk0` reads only the user
    area — boot1 / boot2 / RPMB are separate `mmcblkNbootN` / `rpmb`
    devices. When processing such a dump, `boot1_offset` / `boot2_offset`
    will remain `None` because the file is too small to trigger the
    `3 × guess` heuristic.

!!! note "RPMB integrity"
    RPMB sectors are authenticated with an HMAC-SHA256 over the
    on-chip RPMB key, which is **not** exposed via the sector
    interface. A raw RPMB dump is informational — you can read the
    counter and nonce but cannot verify signatures without the key.

!!! warning "Replay tokens"
    If you re-image an eMMC after pulling an RPMB dump, the monotonic
    counter in the RPMB partition will have advanced. Forensic
    acquisitions should flag this to establish chain-of-custody.

!!! warning "Secure Erase / TRIM"
    eMMC 4.5+ implements `SANITIZE` which hardware-erases every flash
    page. Post-sanitize dumps contain only `0x00` or `0xFF` bytes
    (vendor-specific); the underlying NAND is physically wiped.

## Gotchas

* **Partition offsets are heuristic.** Trust
  `EXT_CSD[BOOT_SIZE_MULT] * 0x20000` when available.
* **boot1 / boot2 are sometimes write-protected by `BOOT_WP`.** The
  acquirer may have only read boot1 while boot2 returned `0xFF`.
  Check for long zero / 0xFF runs.
* **User area may itself be GPT-partitioned.** Use
  `deepview.storage.partition` to enumerate logical partitions once
  you know where the user area starts.

## Parser

* Implementation: `src/deepview/storage/formats/emmc_raw.py`
* Class: `EMMCRawLayer(DataLayer)`
* Related: `src/deepview/storage/partition.py` for MBR / GPT parsing.

## References

* [JEDEC JESD84-B51: eMMC Electrical Standard](https://www.jedec.org/standards-documents/docs/jesd84-b51)
* [Linux kernel `Documentation/mmc/mmc-dev-parts.rst`](https://www.kernel.org/doc/html/latest/driver-api/mmc/mmc-dev-parts.html)
* [`mmc-utils` source tree](https://git.kernel.org/pub/scm/utils/mmc/mmc-utils.git)
* [“Acquiring eMMC chip data for forensic analysis” — Christopher Tarnovsky](https://www.usenix.org/conference/woot12)
* [Joe Grand's eMMC chip-off tutorials](https://www.grandideastudio.com/)
