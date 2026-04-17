# GPU VRAM dump

A captured GPU VRAM image is the byte-for-byte output of reading a
discrete graphics card's video memory — no file format, no header, no
magic. The acquisition tool (NVIDIA NVML, AMD ROCm runtime, Intel
Level Zero, or a direct PCI-BAR-mapped read from a privileged
userspace helper) writes the raw bytes as they appear in the GPU's
address space, typically starting at the BAR1 base.

Deep View's `GPUVRAMLayer` is a **flat passthrough** layer. It records
a vendor tag in metadata so downstream plugins can dispatch vendor-
specific post-processing (texture decoding, shader-heap walking,
compute-launch descriptor recovery) but performs no parsing itself.

## File structure

```
+-----------------------------------------------------------+
| GPU VRAM (flat, byte-for-byte as read from the BAR / DMA) |
+-----------------------------------------------------------+
```

* **No magic bytes.** VRAM is an opaque blob of framebuffers, tiled
  textures, shader code, compute kernels, ring buffers, and descriptor
  arrays.
* **Typical sizes:** 4 GiB (consumer), 16 GiB / 24 GiB (workstation),
  48 GiB / 80 GiB / 192 GiB (data-center GPUs).

## Vendor tag

The constructor accepts an explicit vendor literal:

```python
GPUVRAMLayer(path, vendor="nvidia")   # "nvidia" | "amd" | "intel" | "unknown"
```

The tag is attached to `LayerMetadata.name` as `gpu_vram:{vendor}` so
it survives through the layer registry and downstream reporting.

## Vendor-specific structure hints

Deep View does not parse any of these — they are offered as leads for
a carver or custom scanner walking the flat dump.

### NVIDIA

| Structure               | Recognition hint                                             |
| ----------------------- | ------------------------------------------------------------ |
| PushBuffer ring         | 4-byte `0x20000000`..`0x23FFFFFF` header methods (opcode+subchannel). |
| Shader Local Memory     | Alignment: 512 B; `TEX2D` descriptors at 32 B stride.        |
| ELF-in-VRAM SASS        | `7F 45 4C 46 02 01 01` prefix of compiled CUBIN sections.    |
| MMIO mirrors            | `0x000..0x10000` often reflects PRAMIN / PFB register fields. |

NVIDIA cards have a **BAR0 (MMIO)**, **BAR1 (VRAM window)**, and
sometimes **BAR2 (doorbell)**. A VRAM dump typically represents BAR1;
BAR0 dumps look completely different and should be labelled as such.

### AMD (GCN / RDNA / CDNA)

| Structure               | Recognition hint                                             |
| ----------------------- | ------------------------------------------------------------ |
| RLCV save-state         | Magic string `"RLCV"` followed by a 4-byte length.           |
| Compiled AMDGPU ELFs    | Standard ELF magic (`7F 45 4C 46`) with `e_machine = 0xE0`.  |
| HSA queue descriptors   | 64 B aligned, carry `hsa_queue_type_t` discriminator.        |
| Framebuffer tiling      | DCC compression metadata blocks: `0x00000001` + 64 B header. |

### Intel (Arc / iGPU)

| Structure               | Recognition hint                                             |
| ----------------------- | ------------------------------------------------------------ |
| Graphics Address Table  | 8 B PTE entries with bit 0 = valid, bit 1 = writable.        |
| Gen* Surface State      | 16 B SURFACE_STATE descriptors (Gen12+: 64 B).               |
| Kernel ELFs (Level Zero)| `7F 45 4C 46 02 01 01` prefix + `"ELFOSABI_AMDGPU_HSA"` variant. |

## Addressing

Flat: offset `N` in the file is byte `N` of the captured VRAM. The
layer intentionally exposes no address translation — GPU page tables
live in the MMIO BAR0 region, which is not part of this dump.

## Known variations

!!! note "Partial BAR reads"
    Many consumer drivers only expose a **paged window** of VRAM via
    BAR1 (e.g. 256 MiB). Acquisition tools that walk this window are
    explicitly serialising non-contiguous snapshots — the resulting
    file may not be a single coherent VRAM image.

!!! note "Unified memory"
    On iGPUs (Intel Arc iGPU, AMD APUs, Apple M-series) "VRAM" is a
    carve-out of system RAM. A `gpu_vram` dump from such a device is
    structurally indistinguishable from a `raw` memory image; the
    vendor tag is the only context.

!!! warning "Encrypted memory regions"
    NVIDIA Hopper (H100) implements CMMA (Confidential Compute Memory
    Aware) which encrypts VRAM with keys held in the TEE. Dumps from
    these devices may contain encrypted pages indistinguishable from
    random data.

!!! warning "Live-VRAM acquisition pitfalls"
    VRAM is constantly mutating — a naive dump races with active GPU
    workloads and will capture half-updated framebuffers, partially-
    written descriptor arrays, and torn rings. Quiesce the GPU
    (`cuda_device_reset`, `hipDeviceReset`, `zeContextDestroy`)
    before dumping.

## Gotchas

* **No acquisition included.** Deep View deliberately avoids importing
  `pycuda`, `rocm`, or `level_zero` at this layer. Acquisition is the
  responsibility of a future `gpu` acquisition provider; this layer
  only consumes what was already captured.
* **Endianness is host-native.** NVIDIA / AMD / Intel GPUs are all
  little-endian at the bus level; framebuffers, descriptors, and
  textures are read and written in LE.
* **Don't mix vendor dumps.** A layer created with `vendor="nvidia"`
  should not be pointed at an AMD dump — the tag is informational only,
  but downstream plugins dispatch on it.

## Parser

* Implementation: `src/deepview/storage/formats/gpu_vram.py`
* Class: `GPUVRAMLayer(DataLayer)`
* Vendor literal: `Vendor = Literal["nvidia", "amd", "intel", "unknown"]`.

## References

* [NVIDIA Management Library (NVML)](https://developer.nvidia.com/nvidia-management-library-nvml)
* [ROCm: `rocm-smi`](https://rocm.docs.amd.com/)
* [Intel oneAPI Level Zero](https://spec.oneapi.io/level-zero/latest/)
* [“GPU Forensics: A Primer” — DFRWS 2020](https://dfrws.org/)
* [NVIDIA open-gpu-kernel-modules source (`src/`)](https://github.com/NVIDIA/open-gpu-kernel-modules)
