# VMware `.vmem` + `.vmss` / `.vmsn` sidecar

VMware Workstation, Fusion, and ESXi write the guest's physical RAM to a
flat file alongside the VM state. Three file extensions are relevant:

| Extension | Purpose                                                       |
| --------- | ------------------------------------------------------------- |
| `.vmem`   | **Flat** byte-for-byte guest RAM. No header, no trailer.      |
| `.vmss`   | Suspended-state metadata (register context, device state, which RAM regions are populated). |
| `.vmsn`   | Snapshot-state metadata (same structure as `.vmss`).          |

For suspended / snapshotted VMs the trio is always `{vm}.vmem` +
`{vm}.vmss` or `{vm}.vmsn`. The VM's `.vmdk` disk is not involved at
this layer.

## `.vmem` layout

A `.vmem` file is a **flat guest-physical-address image** — offset `N`
in the file is guest physical address `N`. No header, no padding, no
checksums. The file size equals the VM's configured RAM (plus
occasionally a sparse region at the end for reserved MMIO holes that
VMware chose to materialise as zeroes).

This is why pointing Volatility 3 / WinDbg / `strings` directly at a
`.vmem` "just works" — the format is exactly the raw physical-memory
format.

Deep View's `VMwareVMEMLayer` adds two capabilities on top:

* **Sparse-region awareness.** If a sibling `.vmss` / `.vmsn` parses to
  a region table, the layer serves holes as zeros rather than file
  bytes; reads into gaps honour the `pad=` flag.
* **Best-effort sidecar detection** — auto-discovers the sibling by
  swapping the extension (`path.with_suffix(".vmss")` / `".vmsn"`).

## `.vmss` / `.vmsn` header

VMware's Core Dump File format ("CDF"). Deep View recognises three
magic values at offset `0x00`:

| Magic (LE uint32) | Hex bytes       | Product family                 |
| ----------------- | --------------- | ------------------------------ |
| `0xBED2BED0`      | `D0 BE D2 BE`   | Workstation / Fusion (classic) |
| `0xBED2BED3`      | `D3 BE D2 BE`   | Newer Workstation (64-bit variant) |
| `0xBED2BED2`      | `D2 BE D2 BE`   | ESXi `.vmsn`                   |

### Header prefix (first 12 bytes we parse)

| Offset | Size | Field        | Description                                                        |
| -----: | ---: | ------------ | ------------------------------------------------------------------ |
| `0x00` |  4   | `Magic`      | One of the three values above.                                     |
| `0x04` |  4   | `Version`    | Tag-encoding version. Not gated.                                   |
| `0x08` |  4   | `GroupCount` | Number of "groups" in the tag directory.                           |

Following the header is a **group table** of `GroupCount` entries,
each pointing to a variable-length stream of tagged records:

```
Group {
    char     name[64];          // NUL-padded ASCII
    uint64_t offset;             // file offset of first tag
    uint64_t size;               // byte length of tag stream
};

Tag {
    uint16_t flags;
    uint8_t  name_length;
    char     name[name_length];  // no NUL
    uint16_t nindices;
    uint32_t indices[nindices];
    variable payload;
};
```

The "memory" group carries the `regionsCount`, `regionPPN[]`,
`regionSize[]`, and `regionPageNum[]` arrays that a spec-complete
parser would use to synthesize a region table.

!!! warning "Deep View does **not** walk the full tag tree"
    Parsing the VMware tag stream correctly requires tracking
    group-level payload offsets, variable-length names, and per-tag
    flag semantics. The current implementation only validates the
    12-byte magic / version / group-count prefix and then returns an
    empty region list, which causes `VMwareVMEMLayer` to fall back to
    flat-file mode. Callers needing sparse semantics should run a
    dedicated sidecar-aware tool (e.g. `vmss2core`) first, or ship
    their own region table.

## Body layout

```
.vmem : [---------- flat guest RAM (size = configured RAM) ----------]
                                               (offset == GPA)

.vmss : [header 0x00][group table][tag streams][memory region map...][device state]
```

## Sparse read semantics

When `is_sparse` is `True` and a `regions` list is populated:

1. Find region `R` with `R.start ≤ offset < R.start + R.size`.
2. File offset = `R.file_offset + (offset - R.start)`.
3. For holes, `read(..., pad=True)` zero-fills; `pad=False` returns
   partial bytes (the prefix up to the hole).

Flat mode (`is_sparse == False`) behaves like `RawMemoryLayer` —
`offset` maps directly to file offset.

## Known variations

!!! note "`.vmem` is not always RAM"
    Some ESXi configurations write thin-provisioned VM swap files with
    the `.vmem` extension. These are *not* memory images — the file
    size is the reserved swap space, not the configured RAM, and the
    content is zero-filled unless VM-initiated paging occurred. The
    sidecar magic check is the reliable discriminator.

!!! note "VMware Workstation snapshot chain"
    Snapshot chains produce `VMNAME-Snapshot1.vmsn`,
    `VMNAME-Snapshot2.vmsn`, ... Each snapshot has its own `.vmem`.
    Deep View pairs them by extension swap only; if the user renames
    the files, pass `vmss_path=` explicitly.

!!! warning "Encrypted VMs"
    VMware VM encryption (both `encryption.data` keys and vSphere VM
    encryption) renders the `.vmem` / `.vmss` pair opaque. The magic
    bytes of the state files are replaced with the `VMCRYPT` signature
    at an offset Deep View does not parse; `.vmem` is left encrypted
    with AES-256-XTS and is not recoverable without the key.

## Gotchas

* **No checksum.** Truncated `.vmem` files (typical of interrupted
  `vmrun stop` commands) are indistinguishable from complete dumps
  except by comparing the file size to the VM's configured RAM.
* **64 KiB stride MMIO holes.** For VMs configured with PCI
  passthrough, the guest's 0xC0000000–0xFFFFFFFF MMIO hole is
  materialised as zeroes in `.vmem`. Pattern scans should expect
  legitimate large runs of zeros.
* **Large `.vmem` files.** Deep View `mmap`s the whole file; ensure
  your process has enough virtual address space (64-bit Python
  strongly recommended for VMs larger than 2 GiB).

## Parser

* Implementation: `src/deepview/storage/formats/vmware_vmem.py`
* Class: `VMwareVMEMLayer(DataLayer)`
* Dataclass: `VMwareRegion(start, size, file_offset)`
* Related: [Volatility 3 `vmwareinfo` plugin](https://volatility3.readthedocs.io/en/latest/volatility3.framework.plugins.windows.html)

## References

* [VMware `vmss2core` tool](https://flings.vmware.com/vmss2core)
* [Volatility 3 VMware layer](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/layers/vmware.py)
* [“Forensic Analysis of VMware Disk and Memory Images” — SANS](https://www.sans.org/white-papers/35477/)
* [Nir Izraeli — vmx86 reverse-engineering notes](https://github.com/nirizr)
