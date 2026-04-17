# Glossary

Terms used across the Deep View codebase and documentation. Definitions
are short (2-4 sentences); cross-links point to the module or doc page
where the term lives.

!!! tip "Conventions"
    Deep-View-specific names are in `monospace`. Generic forensics
    acronyms are expanded on first mention.

---

### AF-split (Anti-Forensic split)
LUKS keyslot storage technique that diffuses a master key across many
sectors so deleting any one of them renders the slot unrecoverable.
Implemented in [`storage/containers/_af_split.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/storage/containers/_af_split.py);
consumed by `LUKSUnlocker` when decrypting a slot.

### AnalysisContext
Central session object. Owns configuration, the event bus, the layer
registry, the artifact store, and lazy-constructs `plugins`, `offload`,
`storage`, and `unlocker` subsystems on first access. See
[`core/context.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/core/context.py)
and [`architecture/`](architecture/storage.md).

### Argon2id
Memory-hard KDF selected by LUKS2 by default. Deep View dispatches
Argon2id derivation through `context.offload` so it doesn't block the
caller; the CPU reference implementation lives in
`deepview.offload.kdf.argon2id` and a GPU variant is honestly stubbed
(see [`architecture/offload.md`](architecture/offload.md)).

### BCH (Bose-Chaudhuri-Hocquenghem)
Cyclic error-correcting code family widely used on NAND flash. Deep
View ships `BCHDecoder(t=...)` with `t` in {4, 8, 16, 32}; invoked
automatically by `ECCDataLayer` when the storage manager detects a BCH
spare layout.

### BitLocker
Microsoft's full-volume encryption system. Deep View unlocks BitLocker
via `pybde` (the libbde Python binding) — we don't reimplement the
format. Master keys extracted from memory bypass the passphrase/recovery
key path; see [Recipe 06](cookbook/06-extract-key-from-memory.md).

### DataLayer
The fundamental Volatility-3-style abstraction for a byte-addressable
data source. Every memory/disk/container/filesystem-file view in Deep
View implements `read`/`write`/`is_valid`/`scan` plus three
metadata properties. See
[`interfaces/layer.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/interfaces/layer.py)
and [Recipe 12](cookbook/12-write-a-custom-data-layer.md).

### DMA acquisition
Direct-memory-access capture that reads physical RAM without the
target OS's cooperation. Transports: Thunderbolt, PCIe, FireWire. Each
is a dual-use capability and the CLI gates all of them behind
`--confirm --authorization-statement --enable-dma` and a root check.

### ECC (Error-correcting code)
Generic term for codes that detect and correct bit flips. NAND flash,
eMMC, and some SPI chips embed ECC bytes in each page's spare area.
Deep View's `ECCDataLayer` decodes per-page so downstream consumers
see corrected payloads — see
[`architecture/storage.md`](architecture/storage.md).

### ELF core dump
Core-file format used by Linux crash captures, `gcore`, and many live
acquisition tools. `ELFCoreLayer` parses the program headers and
presents the concatenated `PT_LOAD` segments as a linear address
space.

### EnCase
Proprietary forensic suite from OpenText. Its `.E01` container is
supported read-only via the `libewf` Python binding when the
`[storage_ewf]` extra is installed — Deep View surfaces the stream as
a plain `DataLayer`.

### ext_csd
eMMC "Extended CSD" register — a 512-byte metadata block that
describes the part's geometry, boot partitions, RPMB partition size,
and write-protect state. `EMMCRawLayer` parses ext_csd to seed the
`NANDGeometry` used by the FTL translator.

### FileVault 2
Apple's full-volume encryption for APFS (and legacy Core Storage on
HFS+). Deep View detects the header via `FileVault2Unlocker` and
delegates AES-XTS decryption to the Apple-documented layout; recovery
keys are just 128-bit binary values passed as `MasterKey`.

### FTL (Flash translation layer)
Firmware layer inside an SSD/eMMC/UFS part that maps logical block
addresses to physical NAND pages, handles wear levelling, and quarantines
bad blocks. Deep View's `FTLTranslator` ABC abstracts the mapping;
concrete implementations ship for UBI, JFFS2, MTD passthrough, and raw
bad-block remapping.

### FVEK (Full Volume Encryption Key)
BitLocker's per-volume AES key. Extracted from kernel memory by
`EncryptionKeyScanner` under `key_type="bitlocker"`, then passed to
`BitLockerUnlocker` as a `MasterKey` — see
[Recipe 06](cookbook/06-extract-key-from-memory.md).

### GPT (GUID Partition Table)
UEFI-era partition format replacing MBR; uses 128-bit type GUIDs and
supports partitions larger than 2 TiB. `parse_partitions` prefers GPT
and falls back to MBR — see
[`storage/partition.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/storage/partition.py).

### Hibernation file
Windows `hiberfil.sys` — a compressed snapshot of RAM written on S4
suspend. `HibernationLayer` decompresses the
Xpress-Huffman-compressed pages on demand; also reachable as the
`DumpFormat.HIBERFIL` path in `MemoryManager.open_layer`.

### Hidden volume
VeraCrypt/TrueCrypt feature where a second, plausibly-deniable volume
is stored in the trailing region of an outer container. Probe via
`unlocker.unlock(layer, header, source, try_hidden=True)`. See
[Recipe 07](cookbook/07-nested-decrypt-luks-in-veracrypt.md).

### IPMI
Intelligent Platform Management Interface — out-of-band server
management protocol. Deep View's `IPMIProvider` speaks IPMI 2.0 over
LAN and can stream memory via the BMC when the vendor supports it;
triggered via `deepview remote-image ipmi`.

### IOMMU
CPU unit that mediates DMA access for peripherals. When enabled it
blocks DMA attacks (Thunderbolt / PCIe FPGA rigs) against arbitrary
physical addresses. The Thunderbolt/PCIe providers print a warning
when IOMMU is active and abort unless `--force` is set.

### Intel AMT
Intel Active Management Technology — out-of-band remote management
baked into vPro CPUs. `IntelAMTProvider` uses WS-MAN to trigger a
BMC-side memory dump over TLS. Requires vendor-issued certificates;
see [`architecture/remote-acquisition.md`](architecture/remote-acquisition.md).

### KDF (Key Derivation Function)
Algorithm that stretches a passphrase into a cipher key. Deep View
routes KDF work (PBKDF2, Argon2id, scrypt variants) through the
offload engine so the caller thread is never blocked on expensive
derivations.

### LBA (Logical Block Address)
Sector-aligned address used by storage interfaces (ATA, NVMe, SCSI).
An FTL translator maps LBAs to physical NAND pages. Partition tables
and filesystems use LBAs natively.

### LiME
"Linux Memory Extractor" — kernel module + userspace glue that dumps
physical memory in a custom container format. `LiMEProvider` wraps it
on Linux hosts; `LiMERemoteProvider` runs the same module on a remote
target via SSH. The dump format is parsed by `LiMEMemoryLayer`.

### LUKS / LUKS2
Linux Unified Key Setup — the `cryptsetup` on-disk format. LUKS1 uses
PBKDF2; LUKS2 defaults to Argon2id and supports multiple keyslots and
integrity metadata. `LUKSUnlocker` handles both versions; see
[Recipe 05](cookbook/05-unlock-luks-with-passphrase.md).

### MasterKey
`KeySource` subclass that carries a pre-known cipher key (extracted
from memory, recovered from a backup, or derived externally). Bypasses
the container's KDF entirely — fast enough to brute-force over a pool
of candidates.

### MBR (Master Boot Record)
Legacy partition format in the first 512-byte sector. Supports up to
four primary partitions (extended partitions bolted on). Parsed as a
fallback when GPT is absent.

### mmap
POSIX memory-mapped-file API. Deep View's `RawMemoryLayer` /
`RawNANDLayer` use `mmap` so that multi-gigabyte images are paged in
on demand instead of eagerly read — essential for tractable access to
large evidence files.

### NAND
Non-volatile flash-memory technology used in SSDs, eMMC, UFS, and SPI
flash. Pages are the read unit, blocks are the erase unit, and the
"spare area" beside each page carries ECC bytes and bad-block markers.
`NANDGeometry` captures all of this.

### OOB (Out-of-band data)
Synonym for NAND spare area — the extra bytes beside each page holding
ECC, bad-block markers, and filesystem metadata. Modelled as
`SpareLayout` with one `SpareRegion` per kind.

### ONFI
Open NAND Flash Interface — vendor-neutral standard for NAND
parameter pages and spare-area layouts. `SpareLayout.onfi(...)` is a
ready-made preset; specific vendors ship separate presets when they
deviate from the standard.

### Passphrase
`KeySource` subclass that runs a user string through the container's
KDF. The derivation is dispatched to `context.offload` so the caller
awaits a future instead of blocking. See
[Recipe 05](cookbook/05-unlock-luks-with-passphrase.md).

### PBKDF2
Password-Based Key Derivation Function 2 (RFC 2898). Reference
implementation in `deepview.offload.kdf.pbkdf2_sha256`; also available
as a standalone GPU-OpenCL kernel. LUKS1 and TrueCrypt both use it.

### PCIe Screamer / PCILeech
Open-hardware FPGA devices for DMA-based memory acquisition over PCI
Express. `PCIeDMAProvider` wraps the `leechcore` library to drive
them. Every PCIe-DMA invocation requires root and gets a verbose
banner — see [`architecture/remote-acquisition.md`](architecture/remote-acquisition.md).

### Reed-Solomon
Block error-correcting code used by some NAND parts, optical media,
and QR codes. `ReedSolomonDecoder` ships as an optional ECC adapter;
invoked the same way as `BCHDecoder` through `StorageManager.wrap_nand`.

### Slack space
Bytes inside an allocated filesystem cluster that follow the logical
end-of-file. Historically fertile hiding ground; some filesystem
adapters surface slack as synthetic entries via
`Filesystem.unallocated()`.

### SMR (Shingled magnetic recording)
Overlapped-track HDD technology that forces write-group granularity
for rewrites. Doesn't change read paths (so Deep View reads SMR disks
like any other), but recovery is harder because overwritten sectors
are often reused asymmetrically.

### SOL (Serial-over-LAN)
IPMI/AMT feature that tunnels a physical serial console over the
management network. Not used for memory acquisition directly; useful
for observing BIOS/early-boot state during a remote capture.

### Spare area
See [OOB](#oob-out-of-band-data). The terms are interchangeable in
Deep View docs.

### TCP/IP reconstruction
Read-only analysis pass that walks kernel structures inside a memory
image and reassembles in-flight TCP streams. Lives under
[`memory/network/tcp_reconstruct.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/memory/network/tcp_reconstruct.py)
— *not* the live mangling engine in `networking/`.

### TrueCrypt
Discontinued predecessor to VeraCrypt. `TrueCryptUnlocker` handles the
`TRUE` magic; the format shares a codepath with VeraCrypt but fixes
iteration counts (no PIM).

### TSK (The Sleuth Kit)
Brian Carrier's classic filesystem-forensics library. Python binding
`pytsk3` is an optional fallback (`[storage_tsk]` extra) for exotic or
damaged filesystems where Deep View's native adapters decline.

### UBI / UBIFS
Unsorted Block Images (UBI) is a wear-levelling layer above raw NAND;
UBIFS is the filesystem on top. `UBITranslator` handles the LEB-to-PEB
mapping; the filesystem itself is a native adapter under
[`storage/filesystems/`](https://github.com/your-org/deepseek/tree/main/src/deepview/storage/filesystems).

### VeraCrypt
Actively-maintained fork of TrueCrypt with stronger KDFs and PIM
support. `VeraCryptUnlocker` probes every supported KDF × cipher
cascade combination — each attempt is a full PBKDF2 derivation and is
expected to take measurable CPU time.

### VirtualAddressLayer
A `DataLayer` that applies page-table translation to a physical
backing layer. Lives in
[`memory/translation/virtual_layer.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/memory/translation/virtual_layer.py);
built by `PageTableWalker` on demand.

### Volatility
Volatility 3 — the reference open-source memory-forensics framework.
Deep View imports `volatility3` as a library (never as a subprocess)
and registers plugin output via `VolatilityEngine`. The extra that
installs it is `[memory]`.

### WS-MAN (WS-Management)
SOAP-over-HTTP protocol used by Intel AMT for remote management.
`IntelAMTProvider` speaks WS-MAN over TLS and authenticates via the
AMT admin credentials stored indirectly via `RemoteEndpoint.tls_ca` +
`password_env`.

### Xpress / Xpress-Huffman
Microsoft compression format used in `hiberfil.sys` and some
RAM-compression paths. `HibernationLayer` decompresses it lazily, page
by page, to avoid materialising the whole dump.

### WKdm
Compression algorithm used by macOS RAM compression and by Linux
`zswap` in its "wkdm" codec. Detected heuristically during memory
analysis and transparently decompressed by the relevant layer.

### zram / zswap
Linux kernel features that compress cold anonymous pages in RAM or
the swap device. Deep View recognises zram/zswap pools during memory
analysis and exposes them as compressed-page-backed `DataLayer`s so
the rest of the pipeline sees decompressed bytes.
