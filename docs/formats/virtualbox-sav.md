# VirtualBox Saved State (`.sav`, SSM)

Oracle VirtualBox saves a suspended VM's execution state — including
RAM, device state, and CPU context — to a `{vm}.sav` file located
alongside the `.vbox` config. The internal format is called **SSM**
("Saved State Machine") and is produced by the `SSMR3` routines in
`VMM.r0`. SSM is a sequence of tagged, typed, variable-length units —
RAM is just one such unit, stored under a name like
`VBoxInternal/PGM/RAM` or `VBoxInternal/Memory/RAM`.

The SSM format is **not** formally documented; the authoritative
reference is the VirtualBox source
(`src/VBox/VMM/VMMR3/SSM.cpp`). Deep View implements a best-effort
heuristic parser that locates the RAM payload via substring search and
falls back to flat-file mode if it cannot find one.

## Signature

* **Magic (offset `0x00`):** ASCII `"SSM"` (three bytes, no trailing
  NUL). Followed by a version byte and header metadata.

The magic is the only fully-trusted discriminator — the remainder of
the header has rotated multiple times across VirtualBox 4.x / 5.x /
6.x / 7.x.

## Known header preamble (heuristic reading)

| Offset | Size | Field             | Description                                               |
| -----: | ---: | ----------------- | --------------------------------------------------------- |
| `0x00` |  3   | `Magic`           | `"SSM"`.                                                  |
| `0x03` |  1   | `MagicPadding`    | Typically `0x20` (space).                                 |
| `0x04` |  4   | `VersionMajor`    | Observed 1..4 across VirtualBox releases.                 |
| `0x08` |  4   | `VersionMinor`    | Observed 0..2.                                            |
| `0x0C` |  4   | `MachineId`       | Hash of the VM UUID and revision; opaque.                 |
| `0x10` | …    | `UnitDirectory`   | Offset / count pair into the tag stream (version-dependent). |

!!! warning "Deep View does not rely on any of these"
    Only the leading `"SSM"` bytes are checked. Everything after
    offset `0x03` is treated as opaque for the purposes of RAM
    localisation.

## Unit record layout (approximate)

Each logical unit in SSM is introduced by a NUL-prefixed full path
that looks like:

```
\x00VBoxInternal/<Component>/<SubComponent>/<Tag>\x00...payload...
```

Component names seen in the wild: `PGM`, `Memory`, `CPUM`, `TM`, `PDM`.
The RAM unit's tag substring is `RAM` or `ram`, and the component is
`PGM` or `Memory`. The 8-byte record header that follows the name carries
the unit version, flags, and payload size — but the field order has
changed across VirtualBox releases so Deep View does not decode it.

## Deep View's RAM localisation heuristic

```
1. Cap scan window to min(file_size, 4 MiB).
2. For each tag in ("pgm", "PGM", "RAM", "ram"):
     find substring "\x00VBoxInternal/" in the window
     if the surrounding 128 bytes contain the tag:
         find the next NUL after the unit-name start
         candidate payload offset = align_up(nul + 16, 16)
         track the smallest candidate
3. If a candidate was found and it lies within the file, use it as the
   RAM file offset; otherwise expose the whole file flat.
```

This matches every VirtualBox 5.x–7.x saved-state file in the Deep
View fixture set but is explicitly a heuristic — users with atypical
builds should pass `path` to a flat-file layer directly.

## Fallback flat-passthrough mode

When RAM cannot be located, `VirtualBoxSavLayer` exposes the entire
`.sav` file as a flat stream starting at offset 0. `metadata.name` is
suffixed with `" (flat)"` so consumers can tell; when RAM is found the
suffix is `" (ram)"`.

## Known variations

!!! note "`.sav` vs `Snapshots/*.sav`"
    Saved states produced by "Save the machine state" land at
    `VirtualBox VMs/<name>/<vm>.sav`. Snapshot saves land under
    `Snapshots/{uuid}.sav`. Both share the identical SSM layout.

!!! note "Compressed units"
    VirtualBox compresses individual units when
    `SSMR3RegisterInternal` passes `SSM_UNIT_FLAGS_COMPRESSED`. RAM is
    normally stored **uncompressed** for performance on resume;
    compressed units are uncommon but possible.

!!! warning "Encrypted VMs"
    VirtualBox 6.0+ supports VM encryption via DEK-wrapped
    keystores (`Encryption` section in `.vbox`). Saved-state files of
    encrypted VMs have a VMRC-wrapped payload that Deep View cannot
    decrypt — the heuristic will either fail cleanly (flat mode) or
    match a false-positive offset. Always check `parsed_ram`.

## Gotchas

* **Little-endian scalars** everywhere. SSM is always LE regardless of
  host arch.
* **Heuristic can misfire** on VMs with unusual configurations (e.g.
  non-default guest page size, large numbers of PCI passthrough
  devices). Surface the `parsed_ram` attribute to the user; do not
  silently trust it.
* **16-byte alignment assumption** — the heuristic aligns the RAM
  payload offset up to 16 bytes past the trailing NUL of the unit
  name. This matches `SSMR3PutU8 / SSMR3PutStruct` alignment but is
  not guaranteed by the format spec.

## Parser

* Implementation: `src/deepview/storage/formats/virtualbox_sav.py`
* Class: `VirtualBoxSavLayer(DataLayer)`
* Instance attributes:
  * `parsed_ram: bool` — true if RAM offset located.
  * `ram_offset: int`, `ram_size: int` — payload window.

## References

* [VirtualBox source: `src/VBox/VMM/VMMR3/SSM.cpp`](https://www.virtualbox.org/browser/vbox/trunk/src/VBox/VMM/VMMR3/SSM.cpp)
* [Volatility 3 VirtualBox layer (community)](https://github.com/volatilityfoundation/community3)
* [VirtualBox manual: "Saving VM state"](https://www.virtualbox.org/manual/UserManual.html)
* [“A first look at VirtualBox SSM format” — DFIR community](https://volatility-labs.blogspot.com/)
