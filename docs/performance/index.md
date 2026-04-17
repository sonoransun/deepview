# Performance — What's Fast, What's Slow

This page is the map. Each row in the table below answers three questions for
one Deep View primitive: how fast does it go on a reasonable box, what is the
bottleneck in practice, and what (if anything) you can do about it.

!!! warning "All numbers are synthetic"
    Throughput figures on this page come from informal runs on a single
    workstation (16-core Ryzen / 64 GiB DDR4 / NVMe Gen3). They are honest
    order-of-magnitude guides, not benchmarks. Real performance depends on
    your disk, CPU, memory pressure, image layout, and whether `psutil`
    reports you have any RAM left after the kernel page cache sees the image.
    Run the [profiling](profiling.md) workflow on your own hardware before
    making capacity decisions.

## Summary

| Operation | Typical throughput | Bottleneck | Mitigation |
|---|---|---|---|
| Raw memory read (`mmap`) | ~3 GB/s | Page-cache / disk I/O | None — already kernel-backed |
| LiME multi-region read | ~1 GB/s | Per-region seek, `file.read` copies | Prefer raw / ELF-core if the acquisition tool offers it |
| Hibernation read (decompressed) | ~80 MB/s | Xpress decompression (pure Python) | LRU page-run cache; first touch is slow, reads repeat cheaply |
| Hibernation read (raw pass-through) | ~3 GB/s | `mmap` | Triggered automatically when `compression_status == "undecoded"` |
| Crashdump full read | ~700 MB/s | Page-run table walk + `mmap` copy | Covered; no action needed |
| Crashdump bitmap read | ~500 MB/s | Bitmap PFN lookup per page | None — `mmap`-backed, dominant cost is PFN search |
| ECC decode (Hamming, pure Python) | ~5 MB/s | Python bit ops | Install `galois` for BCH when the correction depth allows |
| ECC decode (BCH-8 via `galois`) | ~50 MB/s | GF(2^13) arithmetic | Adequate for batch; no faster pure-Python path |
| LUKS unlock (PBKDF2-SHA-256, 100k iter) | ~0.3 s/passphrase (CPU) | KDF | ProcessPool offload (default); GPU for batches |
| LUKS unlock (Argon2id 64 MiB × 3 × 4) | ~0.5 s/passphrase (CPU) | Memory-hard KDF | **GPU-resistant by design** — ProcessPool only |
| VeraCrypt unlock (SHA-512 × 500k) | ~0.8 s/passphrase (CPU) | PRF rounds | ProcessPool; `gpu-cuda` / `gpu-opencl` on batches |
| Filesystem walk (FAT, native parser) | ~10 MB/s | Pure-Python directory traversal | Install TSK if available and let the TSK provider handle it |
| Filesystem walk (TSK ext4) | ~200 MB/s | `libtsk` in C | Library path is already optimal |
| SSH-DD acquisition | Network-bound | TCP throughput, SSH cipher | Prefer AES-NI cipher suites; avoid TLS-over-SSH wrappers |
| Thunderbolt DMA acquisition | ~700 MB/s read | `leechcore` + IOMMU translation | Disable IOMMU (security tradeoff — see below) |
| DecryptedVolumeLayer read (LUKS sector) | ~400 MB/s warm | `cryptography.hazmat` + LRU lookup | 256-sector LRU covers probe / superblock; scans stream past |
| ZRAM page read (cold) | ~50 MB/s | LZ4 / zstd / LZO decompression | 256-page `lru_cache`; repeated reads are essentially free |
| Offload submit (process) | ~10 K jobs/s sustained | Pickle overhead per job | Batch via `submit_many`; payload as `bytes`, not nested `dict` |
| Offload submit (thread) | ~100 K jobs/s sustained | Queue lock | Use only for GIL-releasing or I/O-bound work |
| Offload submit (GPU batch, 10 K PBKDF2) | ~25 K derivations/s | Kernel launch amortized over batch | Submit ≥ 10 K candidates in one job; single-shot loses to CPU |
| Event bus publish | ~500 K events/s | Subscriber dispatch | Queues bounded, overflow drops silently — see [memory-overhead](memory-overhead.md) |

## Choosing the right knob

!!! tip "Start here"
    1. If reads are slow, look at the format (see the rows above) before
       reaching for concurrency.
    2. If the KDF is slow, decide **batch vs. single**. GPU only wins at
       batch ≥ 10 000. See [offload-throughput](offload-throughput.md).
    3. If memory is tight, monitor RSS — every format layer is `mmap`-backed,
       so RSS is dominated by cached pages, not our code. See
       [memory-overhead](memory-overhead.md).
    4. If startup feels sluggish, remember that every heavy import is lazy.
       See [startup-time](startup-time.md).

## What this directory covers

| Page | Topic |
|---|---|
| [offload-throughput.md](offload-throughput.md) | Thread vs. process vs. GPU; when each wins; benchmark methodology |
| [memory-overhead.md](memory-overhead.md) | `mmap` and LRU caches; bounded RSS; event-queue drop policy |
| [startup-time.md](startup-time.md) | CLI cold-start costs; lazy attribute access on `AnalysisContext` |
| [profiling.md](profiling.md) | `-X importtime`, `cProfile`, `py-spy`, `memray`; reading flame graphs |

## Disclaimers

!!! warning "Your mileage will vary"
    - Anything with a JIT warm-up (GPU kernels, `galois` first import) is
      slower on the first call. Amortize over a real batch before declaring
      victory.
    - Disk layout matters more than most of the table. A sparse LiME dump
      on a fragmented btrfs filesystem will not hit the ~1 GB/s multi-region
      number above. Use [profiling](profiling.md) to see where the seconds
      actually go.
    - The KDF rows assume a single modern x86 core. ARM64 (Apple Silicon)
      is typically 1.2–1.5× faster per core for PBKDF2-SHA-256 but slower
      per core for Argon2id due to AVX2 tuning of `argon2-cffi`.
    - GPU rows assume a recent NVIDIA or AMD consumer card with current
      drivers. Integrated GPUs rarely beat CPU on any KDF.

## Related architecture pages

- [Offload architecture](../architecture/offload.md) — dispatch model, event
  emission, backend registration.
- [Storage architecture](../architecture/storage.md) — container unlock
  pipeline, how `DecryptedVolumeLayer` composes with `RawMemoryLayer`.
- [Data-layer composition](../overview/data-layer-composition.md) — why every
  format exposes the same `read` / `scan` surface.
