# Memory Overhead

Deep View is designed to hold very large images in one process — a 64 GiB
raw memory dump is unremarkable. This page describes how we keep resident
set size (RSS) bounded even when the addressable data is much larger.

## mmap is the default backing strategy

Every on-disk memory-image format uses `mmap.mmap(..., access=mmap.ACCESS_READ)`:

- [`RawMemoryLayer`](../reference/interfaces.md#datalayer) — maps the whole
  file with `length=0` (the kernel-pick-size sentinel).
- `CrashDumpLayer` — maps the file and does all header parsing against the
  `mmap` object using `struct.unpack_from` (zero-copy into the mapping).
- `HibernationLayer` — maps the file; reads for decompressed pages slice
  the mapping by offset.
- `LiMEMemoryLayer` — does **not** use `mmap` (it parses region headers
  linearly via `file.read`). See below for why this matters.

The practical consequence: when you open a 64 GiB raw dump, the process's
*virtual* address space grows by 64 GiB, but RSS grows only by the pages
the kernel has actually faulted in. `top` will show VSZ in the tens of GiB
and RSS in the low hundreds of MiB — that is correct and expected.

!!! note "Why `mmap` and not `pread`?"
    `mmap` + slice reads compile down to one `memcpy` out of the kernel
    page cache. The kernel does the readahead and eviction for us, which
    is exactly what we want for random-access scans across a dump that's
    much larger than RAM.

## LRU caches per layer

A few layers cache *decoded* data — not the backing bytes, which are
already in the kernel page cache, but the post-processing result:

### `DecryptedVolumeLayer` — 256-sector LRU

Located in `deepview.storage.containers.layer`, the decrypt path keeps an
`OrderedDict[int, bytes]` of decrypted sectors:

```python
_SECTOR_CACHE_CAP = 256
self._sector_cache: OrderedDict[int, bytes] = OrderedDict()
```

At the default 512-byte sector size this caps the cache at **128 KiB per
DecryptedVolumeLayer instance**. Rationale:

- Sequential / neighbouring reads (partition table probes, superblock
  parses, directory walks) are cheap — they hit the cache.
- Whole-volume scans stream past the cache without thrashing because
  `scan()` reads 64 KiB chunks and moves linearly forward.
- 128 KiB × N layers is bounded and trivial.

### `HibernationLayer` — 256 page-run LRU

`_LRU_SIZE = 256` in `deepview.memory.formats.hibernation` bounds the
decompressed-run cache. Each run is at least one 4 KiB page, often 64 KiB,
so the cap is roughly **1–16 MiB per HibernationLayer**. First read of a
run pays the Xpress decode cost (~80 MB/s); subsequent reads within the
LRU window are effectively free.

### `ZRAMLayer` — 256-page `lru_cache`

`deepview.storage.encodings.zram_layer` wraps `_decompress_page` in
`functools.lru_cache(maxsize=256)`. One logical page is 4 KiB, so the
cache caps at **1 MiB per ZRAMLayer instance**. LZ4 / zstd / LZO
decompression is fast but not free — keeping the last 256 touched pages
hot dominates observed throughput for sequential scans.

!!! warning "The caches are per-instance, not global"
    Opening the same zram device twice produces two `ZRAMLayer` objects
    with two independent caches. This is intentional — they are thread-safe
    only because they are not shared — but you should not open dozens of
    instances expecting cache coherence.

## Plugin lifecycle

Plugins in `deepview.plugins` subscribe through `PluginRegistry` which is
itself **lazy** — constructed on first access of `context.plugins`. A
plugin that is discovered but never invoked costs only:

- The `@register_plugin` decorator side-effect (one entry in the global
  `_REGISTERED_PLUGINS` dict).
- A class object in memory. No instances are created until `run()` is
  called.

`context.plugins` iterates discovered plugins in tier order
(built-in → entry-point → directory scan); constructing the registry does
not instantiate plugins either.

!!! tip "Measuring plugin RSS"
    Use `memray run -o out.bin $(which deepview) plugins` to see exactly
    which plugins contribute to allocations during the discovery pass.
    The directory-scan tier is the most likely source of surprises if
    you have many third-party plugins.

## Event bus: bounded queues drop on overflow

The core `EventBus` is synchronous (publish → call subscribers in order),
so it has no memory overhead of its own. The `TraceEventBus` used by the
tracing subsystem is different: it is async and fans out to per-subscriber
queues.

**The queues are bounded and drop on overflow.** A subscriber that is
slower than the producer sees its queue fill up, and the producer increments
a per-queue drop counter rather than blocking. This is a deliberate design
choice: an eBPF firehose at 500 K events/s must never backpressure the
kernel poll thread.

!!! warning "If you see dropped events, **fix the consumer**, not the queue"
    The fix is never to increase the queue size. Either narrow the trace
    filter (see `tracing/filters.py` and the `FilterExpr.compile` step)
    or move the expensive consumer work off the critical path.

Consequences for RSS:

- Queues are sized in the tens to hundreds of events. A stuck subscriber
  costs kilobytes, not megabytes.
- `psutil.Process().memory_info().rss` will **not** climb over time in a
  long-running `deepview monitor` session even at sustained high event
  rates — that's the invariant we enforce.

## Recommended RSS monitoring

If you want to watch Deep View's memory footprint during a long analysis,
use `psutil` directly:

```python
import psutil, time, os

proc = psutil.Process(os.getpid())
while True:
    mi = proc.memory_info()
    print(f"rss={mi.rss/1e6:.1f} MB  vsz={mi.vms/1e9:.1f} GB")
    time.sleep(5)
```

Or externally from another terminal:

```bash
watch -n2 "ps -o pid,rss,vsz,cmd -p $(pgrep -f deepview) | awk '{printf \"%s  rss=%.0fMB  vsz=%.1fGB  %s\\n\", \\$1, \\$2/1024, \\$3/1024/1024, \\$4}'"
```

!!! tip "Expected RSS budget"
    - Core install, no extras, one 64 GiB raw image open: **~150 MB RSS**.
    - Same + 10 K-candidate LUKS unlock (`process` backend, 8 workers):
      **~400 MB RSS** (each worker forks from the parent at that point
      and inherits the parent's footprint).
    - Same + `deepview monitor` with eBPF tracing and the Rich dashboard:
      **~250 MB RSS**; event throughput has no effect on RSS because
      queues are bounded.

If you exceed those numbers by an order of magnitude, something is wrong
— probably a plugin creating an unbounded list, or a scanner accumulating
results into memory instead of streaming. Use [profiling](profiling.md)
to find it.

## Related reading

- [Offload throughput](offload-throughput.md) — why ProcessPool worker
  count multiplies RSS.
- [Data-layer composition](../overview/data-layer-composition.md) — every
  `DataLayer` implements the same `read` / `scan` contract, which is what
  makes `mmap`-backed streaming possible.
- [Profiling](profiling.md) — `memray` for allocation traces,
  `py-spy dump` for finding the subscriber that's too slow.
