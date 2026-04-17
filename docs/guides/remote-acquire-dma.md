# Remote acquisition via DMA — Thunderbolt / PCIe / FireWire

Direct Memory Access (DMA) is the most invasive acquisition path Deep
View supports. A DMA-capable interface (Thunderbolt 3/4, a PCIe
ScreamerM.2 card, or a legacy FireWire bus) can read physical memory
directly, bypassing the target OS entirely. That is its power — and
why the command requires three orthogonal opt-ins before it runs a
single read.

This guide covers:

1. The three DMA transports (`dma-tb`, `dma-pcie`, `dma-fw`) and what
   hardware they require.
2. The **IOMMU / VT-d** probe — when DMA succeeds, fails, or returns
   garbage.
3. A troubleshooting subsection for when DMA doesn't work.

!!! warning "Dual-use, root-only, and opt-in"
    DMA acquisition can read the memory of any machine you can
    physically connect to. It does not require the target's consent,
    credentials, or awareness. Deep View's CLI requires `--confirm`,
    `--authorization-statement`, `--enable-dma`, **and** root — any
    missing gate aborts the command.

## Prerequisites

- Deep View installed with the remote-acquisition + hardware extras:
  ```bash
  sudo pip install -e ".[dev,remote_acquisition,hardware]"
  ```
- Root on the analyst workstation (not the target; the target stays
  unmodified).
- A DMA interface matching the transport:

  | Transport | Hardware | Python dep |
  |---|---|---|
  | `dma-tb` | Thunderbolt 3/4 + PCILeech / ScreamerM.2 | `leechcore` |
  | `dma-pcie` | PCIe ScreamerM.2 card | `leechcore`, optional `chipsec` |
  | `dma-fw` | FireWire 400/800 bus | `libforensic1394` Python bindings |

- A target machine with a compatible port and either:
  - IOMMU / VT-d **disabled** (DMA reads everything), OR
  - IOMMU / VT-d **enabled** with DMA-attack whitelisting
    misconfigured (vendor-specific).

!!! warning "IOMMU / VT-d is a correctness issue"
    Modern Intel / AMD CPUs have an IOMMU that mediates DMA. If the
    target has IOMMU on and locked, your DMA reads return the value
    of whatever the IOMMU remaps the request to — often all zeroes or
    bogus data. Deep View probes IOMMU state in the preflight and
    warns loudly if it detects protection.

## Command

DMA commands share the `remote-image` common options **plus** an
`--enable-dma` flag:

```bash
sudo deepview remote-image dma-tb \
    --host target.example.com \
    --output target.mem.dma.raw \
    --format raw \
    --confirm \
    --authorization-statement=file:/secure/case-123-auth.txt \
    --enable-dma
```

The `--host` is decorative for DMA transports — the target is
identified by the cable you plugged in, not a network address. It is
still required so the audit log records what the analyst intended to
acquire.

## What happens under the hood

```mermaid
sequenceDiagram
    autonumber
    participant CLI as deepview remote-image dma-tb
    participant PRE as _dma_preflight
    participant GATE as _authorize_and_banner
    participant FAC as build_remote_provider
    participant P as DMAThunderboltProvider
    participant LC as leechcore FFI
    participant TGT as Target RAM (physical)
    participant BUS as EventBus
    CLI->>PRE: enable_dma? + root?
    PRE-->>CLI: ok (else UsageError)
    CLI->>GATE: confirm? + auth? + banner + 5s delay
    GATE-->>CLI: ok
    CLI->>FAC: build_remote_provider("dma-tb", endpoint)
    FAC->>LC: leechcore_open(device="tb")
    LC-->>FAC: device_handle
    CLI->>P: acquire(target, output_path, format)
    P->>BUS: RemoteAcquisitionStartedEvent(transport="dma-thunderbolt")
    P->>LC: probe_iommu()
    alt IOMMU detected + locked
        LC-->>P: IOMMUBlocked
        P->>BUS: RemoteAcquisitionProgressEvent(stage="iommu_warning", ...)
        note over P: prints "IOMMU/VT-d appears<br/>to be active; reads may return zeros"
    else IOMMU absent / bypassable
        LC-->>P: IOMMUAbsent
    end
    loop chunks of 4 MiB until max_addr
        P->>LC: read_physical(offset, 4 MiB)
        LC->>TGT: DMA TLP
        TGT-->>LC: bytes
        LC-->>P: chunk
        P->>BUS: RemoteAcquisitionProgressEvent(bytes_done, bytes_total)
    end
    P->>BUS: RemoteAcquisitionCompletedEvent(size_bytes, elapsed_s)
    P-->>CLI: AcquisitionResult
```

### IOMMU probe sample output

```
WARNING: Remote memory acquisition is a dual-use capability. You have attested
authorization via file:/secure/case-123-auth.txt. Proceeding against
target.example.com via dma-thunderbolt in 5 seconds. Press ^C to abort.
[leechcore] opened tb device (ScreamerM.2 firmware v2.4.1)
[iommu-probe] reading 16 scattered physical pages...
[iommu-probe] mean entropy = 7.98 bits/byte; non-zero pages = 16/16
[iommu-probe] IOMMU appears INACTIVE — DMA reads returning plausible data
[progress] 256 MiB / 16384 MiB (1.6%) throughput=198.3 MB/s
[progress] 512 MiB / 16384 MiB (3.1%) throughput=201.1 MB/s
...
```

Or, on a protected target:

```
[iommu-probe] reading 16 scattered physical pages...
[iommu-probe] mean entropy = 0.02 bits/byte; non-zero pages = 0/16
[iommu-probe] WARNING: IOMMU / VT-d appears ACTIVE on target; DMA reads are
returning all zeroes. Continue the capture anyway, or ^C to abort.
[progress] 256 MiB / 16384 MiB (1.6%) throughput=208.7 MB/s
...
```

!!! warning "Zero-returning captures are useless"
    If the IOMMU probe says "returning all zeroes," keep going only if
    you need to record that the target was protected. Otherwise
    abort, hibernate the target, and dump via cold-boot instead.

## Scenario — Thunderbolt vs. PCIe vs. FireWire

### `dma-tb` (Thunderbolt)

Most common today. Works against any target with a Thunderbolt 3/4
port that enumerates external PCI devices. Requires a PCILeech-
firmware-flashed ScreamerM.2 or FPGA in a Thunderbolt enclosure.

```bash
sudo deepview remote-image dma-tb \
    --host TB-TARGET \
    --output tb.mem.raw --format raw \
    --confirm --authorization-statement=env:AUTH --enable-dma
```

### `dma-pcie` (PCIe card)

Direct-plugged PCIe ScreamerM.2 in an M.2 slot on the target. Faster
than TB (no Thunderbolt protocol overhead) but requires case access.

```bash
sudo deepview remote-image dma-pcie \
    --host PCIE-TARGET \
    --output pcie.mem.raw --format raw \
    --confirm --authorization-statement=env:AUTH --enable-dma
```

### `dma-fw` (FireWire)

Legacy — Macs and old PCs with 1394 ports. Much slower (~100 MB/s
peak) and most modern hardware has no FW port at all. Included for
archive-case work.

```bash
sudo deepview remote-image dma-fw \
    --host FW-TARGET \
    --output fw.mem.raw --format raw \
    --confirm --authorization-statement=env:AUTH --enable-dma
```

## Verification

Same as for SSH acquisition — the capture is a raw memory image, so
validate it by loading and listing processes:

```bash
deepview memory load tb.mem.raw --register-as=tb_mem
deepview memory ps --layer=tb_mem | head
```

If the process list is empty or all PIDs are zero, either the capture
is empty (IOMMU blocked) or the kernel version isn't supported by
Volatility 3. Check `deepview memory kernel-hints --layer=tb_mem` to
identify the target OS.

## When DMA fails — troubleshooting

### 1. "DMA refuses to run without --enable-dma"

You forgot `--enable-dma`. That's the dual-use opt-in; the CLI
deliberately does not imply it. Add the flag and rerun.

### 2. "DMA refuses to run as non-root"

DMA needs `CAP_SYS_RAWIO` / raw PCI access. Run with `sudo` or as root.

### 3. "leechcore_open failed: no device"

The DMA hardware isn't visible to your kernel. Check:

- **Thunderbolt**: `boltctl list` should show the ScreamerM.2 as
  authorized (not "rejected"). On Linux, `boltctl authorize <id>`
  first.
- **PCIe**: `lspci | grep -i xilinx` (or matching vendor) should
  enumerate the card. Reseat if not.
- **FireWire**: `lsmod | grep firewire_ohci`; load the module with
  `sudo modprobe firewire_ohci` if missing.

### 4. "IOMMU active, all reads are zeroes"

The target's firmware enabled IOMMU DMA protection. Options:

- **Cold boot**: power-cycle the target with memory-preserving DIMMs
  (Cold Boot Attack) and capture before firmware re-asserts IOMMU.
  Deep View doesn't automate this — it is a physical-procedure step.
- **Firmware bypass**: vendor-specific (some ThinkPads, some Macs).
  Out of scope for this guide.
- **Switch to SSH** (see [remote-acquire-ssh.md](remote-acquire-ssh.md))
  — if you can get root on the target, SSH+dd is slower but
  IOMMU-transparent.

### 5. DMA reads are *mostly* valid but some pages are zeroes

IOMMU is configured with a whitelist (e.g. Intel BIOS Guard). Those
whitelisted pages are readable; everything else returns zeros. You
can still carve strings / keys / credentials from the readable pages;
full filesystem-level analysis won't work.

### 6. Thunderbolt 4 on locked Windows targets

Windows 11 ships with "Kernel DMA Protection" that rejects
unauthorized Thunderbolt devices at the firmware level. `boltctl` /
the Thunderbolt Control Center will refuse to authorize. Physical
access to pre-authorize the device or a different transport is
required.

## Common pitfalls

!!! warning "Never run DMA on production without a change window"
    DMA reads can occasionally crash the target (rare, ~0.1% on modern
    kernels). Schedule the capture during an approved maintenance
    window.

!!! warning "Do not share DMA capture files without scrubbing"
    A DMA capture includes every byte of physical RAM — kernel
    credentials, TLS session keys, TPM-unsealed secrets, open-file
    plaintext. Treat the output file like a high-sensitivity
    artifact. Deep View writes it to the `--output` path with
    `0600` permissions by default.

!!! note "Expect lower throughput than theoretical max"
    Thunderbolt 3 is spec'd at 40 Gbps, but real DMA reads top out at
    ~200 MB/s due to round-trip latency. A 16 GiB capture takes
    ~80 seconds on good hardware, ~5 minutes on flaky cables.

## What's next?

- [Remote acquisition over SSH](remote-acquire-ssh.md) — the
  network-based alternative when DMA hardware isn't available.
- [Architecture → Remote acquisition](../architecture/remote-acquisition.md)
  — full transport factory + authorization gate state diagrams.
- [Reference → Events](../reference/events.md#remoteacquisitionevent)
  — progress event schemas.
- [Reference → Extras](../reference/extras.md#remote_acquisition) —
  `leechcore`, `chipsec`, and FireWire dependencies matrix.
