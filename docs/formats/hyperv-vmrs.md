# Hyper-V `.vmrs` + `.bin` saved state

Microsoft Hyper-V saves a VM's runtime state to a pair of files:

| File        | Role                                                       |
| ----------- | ---------------------------------------------------------- |
| `{vm}.vmrs` | **Metadata.** Describes guest physical-address descriptors, device state, and CPU state. |
| `{vm}.bin`  | **Raw RAM backing store.** Flat file holding the guest's physical memory bytes. |

Hyper-V's runtime-savedstate format is Microsoft-internal; no public
spec exists. Deep View parses the `.vmrs` header heuristically, and
when it cannot recover a Guest Physical Address Descriptor List (GPADL)
it falls back to exposing the `.bin` as a flat guest-physical-address
image, which is the behaviour WinDbg / `hvixe` / community forensic
tools rely on today.

## Signatures

The `.vmrs` file starts with either of these 4-byte magics at offset
`0x00`:

| Magic (hex)     | ASCII       | Notes                              |
| --------------- | ----------- | ---------------------------------- |
| `56 4D 52 53`   | `"VMRS"`    | Windows Server 2016+ generation 2. |
| `D0 0D F0 0D`   | — (binary)  | Older binary-framed variant.       |

The `.bin` file has **no** magic — it is a flat byte stream of guest
physical memory, the same way VMware `.vmem` is.

## `.vmrs` header (best-effort fields)

| Offset  | Size | Field             | Description                                             |
| ------: | ---: | ----------------- | ------------------------------------------------------- |
| `0x00`  |  4   | `Magic`           | `"VMRS"` or `D0 0D F0 0D`.                              |
| `0x04`  |  4   | `Version`         | Observed `0x01` … `0x03` across 2016 / 2019 / 2022.     |
| `0x08`  |  4   | `HeaderSize`      | Total bytes consumed by the header.                     |
| `0x0C`  |  4   | `RegionCount`     | Number of GPADL entries that follow.                    |
| `0x10`  |  8   | `RegionTableOffset` | Absolute offset where the GPADL table begins.         |
| `0x18`  |  8   | `ConfigBlobOffset`| Offset of the CPU / device state XML/JSON blob.         |
| `0x20`  | `HeaderSize - 0x20` | `VendorBlob` | Reserved / vendor-specific. |

!!! warning "Byte-exact layout is not public"
    Field offsets above are observed across a small Deep View fixture
    set; they match the structures referenced in leaked Hyper-V
    documentation and in community reverse-engineering work. Do not
    treat them as normative — the fallback flat mode is in place
    precisely because the format is unstable.

## GPADL (Guest Physical Address Descriptor List)

Hyper-V allocates guest memory in extents; a GPADL entry describes one
such extent:

```c
struct GPADLEntry {
    uint64_t GuestPhysicalAddress;   // start of the region in guest GPA space
    uint64_t RegionSize;              // bytes
    uint64_t BinFileOffset;           // corresponding offset into .bin
    uint32_t Flags;                   // PROT / present / etc.
    uint32_t Reserved;
};
```

| Offset within entry | Size | Field                    | Description                           |
| ------------------: | ---: | ------------------------ | ------------------------------------- |
| `+0x00`             |  8   | `GuestPhysicalAddress`   | Guest PA where the region starts.     |
| `+0x08`             |  8   | `RegionSize`             | Size in bytes (page-aligned).         |
| `+0x10`             |  8   | `BinFileOffset`          | Byte offset into the `.bin` file.     |
| `+0x18`             |  4   | `Flags`                  | GPADL flags; present, RAM vs MMIO.    |
| `+0x1C`             |  4   | `Reserved`               | Zero.                                 |

Addressing via the GPADL:

1. Find the entry containing the guest PA `P`.
2. File offset = `Entry.BinFileOffset + (P - Entry.GuestPhysicalAddress)`.

## Fallback: flat `.bin`

When Deep View's `.vmrs` heuristic cannot produce a GPADL, the layer
simply serves the `.bin` as a flat guest-physical-address image — the
same assumption used by the public forensic tooling (including WinDbg
`.kdfiles` redirection and the Volatility 3 community `hyperv` plugin).
The `parsed_gpadl` property tells callers which mode is in effect.

## Body layout

```
.vmrs : [0x00: magic][header fields][GPADL table][device state blob][CPU state blob]
.bin  : [--- flat guest RAM, indexed by GPA offset ---]
```

## Known variations

!!! note "Generation 1 vs Generation 2 VMs"
    Generation 1 VMs use legacy BIOS + emulated IDE / floppy and their
    `.bin` has the classic 0xA0000–0xFFFFF VGA hole materialised.
    Generation 2 VMs use UEFI and no such hole; everything below 4 GiB
    is contiguous.

!!! note "Nested virtualization"
    L1 Hyper-V inside Hyper-V produces nested `.vmrs` pairs. The outer
    pair describes the L1 hypervisor's RAM; the L2 guest's memory is
    *inside* the L1 `.bin`. Unwrapping requires an L1-specific parser.

!!! note "Shielded VMs"
    A shielded VM's `.bin` is AES-256-XTS encrypted with a key that
    only the Host Guardian Service can unwrap. Deep View cannot read
    shielded memory without an externally provided key.

## Gotchas

* **Always check that the `.bin` exists before opening a `.vmrs`.**
  Deep View raises `FileNotFoundError` on construction if the `.bin`
  is missing — the default extension swap is `path.with_suffix(".bin")`.
* **Heuristic match only.** If `parsed_gpadl` is False, treat the
  `.bin` as a flat byte stream and avoid using the `regions` array.
* **Windows page size.** Hyper-V guest memory pages are 4 KiB
  regardless of host / guest OS. ARM64 Hyper-V (Windows 11 ARM) still
  uses 4 KiB in the saved-state file.

## Parser

* Implementation: `src/deepview/storage/formats/hyperv_vmrs.py`
* Class: `HyperVVMRSLayer(DataLayer)`
* Dataclass: `GPADLRegion(guest_address, size, file_offset)`
* Properties: `parsed_gpadl`, `vmrs_path`, `bin_path`, `regions`.

## References

* [“Hyper-V internals” — Pavel Yosifovich, Windows Internals 7th ed.](https://www.microsoftpressstore.com/store/windows-internals-part-2-9780135462409)
* [`vmcore2windows` — community `.vmrs` inspector](https://github.com/microsoft)
* [MSDN: "Saved State" under Hyper-V documentation](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/)
* [Volatility 3 community hypervisor layers](https://github.com/volatilityfoundation/community3)
