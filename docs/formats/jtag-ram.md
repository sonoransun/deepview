# JTAG RAM dump

A JTAG acquisition produces a **flat binary** extracted through a
debug-probe interface (OpenOCD, Segger J-Link, Lauterbach TRACE32,
Flyswatter, ARM DSTREAM, ...). The binary represents one or more
contiguous regions of the target's virtual address space and carries
no intrinsic magic or header — it is literally the bytes the probe
shifted out of the CPU's memory bus.

To attribute addresses to bytes, the acquirer ships a **JSON sidecar**
alongside the binary that records virtual-address-to-file-offset
mappings. When the sidecar is present, Deep View exposes the dump as a
multi-region `DataLayer`; when it is absent the layer is a flat
passthrough of the binary.

## File structure

```
prefix-stub.bin  : [--- raw bytes as dumped by the probe ---]
prefix-stub.json : [--- array of region descriptors ---]
```

No magic bytes, no header, no alignment requirements — the binary
can be any size.

## Sidecar JSON schema

```json
[
    {
        "offset":      536870912,
        "size":        32768,
        "name":        "SRAM",
        "file_offset": 0
    },
    {
        "offset":      134217728,
        "size":        262144,
        "name":        "Flash",
        "file_offset": 32768
    }
]
```

| Field          | Type    | Required | Description                                                         |
| -------------- | ------- | -------- | ------------------------------------------------------------------- |
| `offset`       | integer | yes      | Virtual address where this region starts in the target.             |
| `size`         | integer | yes      | Number of bytes the region spans.                                   |
| `name`         | string  | yes      | Human-readable label ("SRAM", "Flash", "OCRAM", ...).               |
| `file_offset`  | integer | no (default 0) | Byte offset into the `.bin` where this region's data begins.   |

**Validation rules applied by the parser:**

* The document must be a JSON array.
* Each element must be an object.
* `offset` and `size` must both be integers; missing either drops the entry.
* `file_offset` (when present) must be an integer.
* Negative values are rejected.
* If `file_offset + size > file_size`, the entry is **clamped** to
  what fits (this matches real-world dumps that end mid-region).
* Entries that survive validation are **sorted by `offset`** on load.

### Minimal sidecar (one region, offset 0)

```json
[{"offset": 0, "size": 4096, "name": "stub", "file_offset": 0}]
```

## Addressing

When `is_multi_region` is True:

1. Find the region `R` with `R.virtual_address ≤ va < R.virtual_address + R.size`.
2. File offset = `R.file_offset + (va - R.virtual_address)`.
3. Reads that cross a region boundary stitch adjacent regions.
4. Reads into unmapped gaps return empty; `pad=True` zero-fills.

When no sidecar is loaded, `read(offset, length)` indexes the file
directly — the layer is a flat passthrough.

## OpenOCD conventions

OpenOCD's `dump_image` command emits `.bin` files; the common practice
is to accompany them with a JSON sidecar written by a companion
script. Example OpenOCD session:

```tcl
init
halt
dump_image sram.bin 0x20000000 0x8000
dump_image flash.bin 0x08000000 0x40000
```

A companion Python script reads each `dump_image` invocation and emits:

```json
[
  {"offset": 0x20000000, "size": 0x8000,  "name": "SRAM",  "file_offset": 0},
  {"offset": 0x08000000, "size": 0x40000, "name": "Flash", "file_offset": 0x8000}
]
```

## Segger J-Link conventions

`JLink.exe` / `JLinkExe` emits Motorola S-Record (`.mot`), Intel HEX
(`.hex`), or raw `.bin` via `savebin`:

```
J-Link> savebin sram.bin 0x20000000 0x8000
J-Link> savebin flash.bin 0x08000000 0x40000
```

Users who want a Deep View-compatible sidecar concatenate the binaries
and generate the JSON manually (Segger ships no standard sidecar).

## Known variations

!!! note "Multiple JTAG chains / TAPs"
    Some SoCs expose several CPUs on the JTAG chain (Cortex-A + Cortex-M
    coprocessor). Each TAP has its own address space; dump them into
    separate JTAG RAM layers and compose them at a higher level.

!!! note "Cache coherency"
    JTAG reads can hit stale cache lines if the target CPU is not
    properly halted with `arm semihosting` / `cortex_a dbginit`. Always
    halt and flush caches before dumping — a cached dump looks identical
    to an uncached one byte-wise but may miss recent writes to DRAM.

!!! warning "Security monitor regions"
    On TrustZone-enabled devices, non-secure JTAG probes can only read
    NS-world memory. Secure-world RAM is returned as `0x00` or
    `0xBADBAD00` by the debug-access port. Mark such regions as
    untrusted in the sidecar.

## Gotchas

* **Sidecar location.** By default Deep View looks for
  `path.with_suffix(".json")`. Pass `sidecar=` explicitly to override.
* **Region sort order.** Sidecars may be authored out of order; the
  parser sorts internally but consumers reading `layer.regions` should
  not assume the file order survives.
* **Overlapping regions.** The parser does not reject overlaps; the
  first matching region in the sorted list wins lookups. Authors
  should avoid overlap.

## Parser

* Implementation: `src/deepview/storage/formats/jtag_ram.py`
* Class: `JTAGRAMLayer(DataLayer)`
* Dataclass: `JTAGRegion(name, virtual_address, size, file_offset)`
* Properties: `is_multi_region`, `regions`.

## References

* [OpenOCD user's guide — `dump_image`](https://openocd.org/doc/html/General-Commands.html)
* [Segger J-Link Commander manual](https://wiki.segger.com/J-Link_Commander)
* [Lauterbach TRACE32 — memory dump commands](https://www.lauterbach.com/frames.html?home.html)
* [ARM DSTREAM user guide](https://developer.arm.com/documentation/dui0481)
* [“Debugging with JTAG” — Intel hobbyist guide](https://www.intel.com/content/www/us/en/docs/programmable/)
