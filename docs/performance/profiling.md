# Profiling Deep View

When throughput is lower than the [index](index.md) suggests, or when
you're shipping a feature that might regress a hot path, measure — don't
guess. This page covers the four tools we reach for and how to read what
they produce.

!!! warning "Measure your box, not ours"
    Every number quoted elsewhere in this directory is synthetic. The
    entire point of this page is to show you how to replace those numbers
    with real ones from your environment.

## Tool selection

| Tool | Use when | Overhead | What it answers |
|---|---|---|---|
| `python -X importtime` | Startup feels slow | ~5% wall-clock | "Which imports cost the most?" |
| `cProfile` | Algorithmic bottleneck suspected | ~30% wall-clock | "Which Python frames burn CPU?" |
| `py-spy` | Production / long-running | <2% wall-clock | Same as `cProfile`, no code changes |
| `memray` | RSS growing unexpectedly | ~2× wall-clock | "Which allocation sites leak?" |

!!! tip "Rule of thumb"
    Reach for `py-spy` first. It's a sampling profiler, so the overhead
    is low enough to run against a production `deepview monitor` without
    disturbing it, and the flame graph usually tells you where to look
    next in under a minute.

## `python -X importtime`

Already covered in [startup-time](startup-time.md). The short version:

```bash
python -X importtime -m deepview --help 2> importtime.log
```

Parse the output by cumulative self-time. Anything in `deepview.*` over
~30 ms at the top level is a bug — heavy imports should be lazy.

## `cProfile`

Best for CPU-bound work where you want frame-level detail and can afford
the overhead:

```bash
python -m cProfile -o profile.bin -m deepview scan memory.dump --yara-rules rules.yar
python -c "
import pstats
p = pstats.Stats('profile.bin')
p.sort_stats('cumulative').print_stats(30)
"
```

Interpret with `snakeviz`:

```bash
pip install snakeviz
snakeviz profile.bin
```

!!! note "cProfile misses native code"
    Time spent inside `hashlib`, `cryptography.hazmat`, `capstone`, and
    any other C extension is attributed to the Python frame that called
    it. If a frame's `tottime` is close to its `cumtime`, the work is
    happening in the native callee, not in your Python.

## `py-spy`

The go-to for live-system profiling. Two modes:

### Record a flame graph

```bash
py-spy record --duration 30 --output flame.svg -- deepview monitor
```

Opens `flame.svg` in a browser. Each box is a frame; width is fraction
of samples; stacks grow upward. Look for:

- **Wide boxes at the top** — that frame is where CPU actually goes.
  Often it's `sha256_update` or `mmap.__getitem__` for Deep View workloads.
- **Tall thin spires** — deep call stacks with no obvious hot leaf. These
  are usually a sign of framework overhead (e.g. the Rich render loop)
  and are cheap per sample but called often.
- **Unexpected frames in `deepview.tracing.stream`** — if the fan-out
  dispatch is wide, a subscriber is synchronous on the producer thread
  when it should be async.

### Attach to a running process

```bash
py-spy top --pid $(pgrep -f 'deepview monitor')
```

Live `top`-style view. Useful when the process has been running for
hours and you want to see where *current* time goes.

### Dump the stacks of a stuck process

```bash
py-spy dump --pid $(pgrep -f deepview)
```

Prints the Python stack of every thread. Essential when the process looks
hung — usually reveals one thread waiting on a `Queue.get` it can never
satisfy.

## `memray`

For allocation traces and leak hunting:

```bash
memray run -o trace.bin $(which deepview) scan memory.dump
memray flamegraph trace.bin    # writes memray-flamegraph-trace.html
memray stats trace.bin         # summary table
memray tree trace.bin          # call-tree view
```

!!! tip "`memray` tracks high-water mark by default"
    Use `memray flamegraph --leaks trace.bin` to surface only allocations
    that were **never freed** by the end of the run. That's usually what
    you want for leak hunting.

What leaks look like in Deep View:

- A plugin holding a list of every `ScanResult` it has seen — shows up
  as `list.append` called from `plugins/…` with monotonic growth.
- A cache without a max size — shows up as `OrderedDict.__setitem__`
  without a matching `popitem`.
- A subscriber to `TraceEventBus` that buffers events for later — shows
  up as `collections.deque.append` that never pops.

## Reading flame graphs

A flame graph (from `py-spy record` or `memray flamegraph`) is a stack
plot where:

- **x-axis** is "fraction of samples", not time. Wider = more time.
- **y-axis** is call depth. The root is at the bottom (or top, depending
  on the renderer — both `py-spy` and `memray` default to root-at-bottom).
- **Colour** is arbitrary / visual grouping only.

To interpret one:

1. Look for the widest box in the top half. That's the hot leaf.
2. Follow it down — every parent frame in that stack also has that width
   (at minimum). That's your call chain.
3. If two wide boxes at the top share a parent, the work is split
   between them inside that parent.
4. Narrow stacks tall off to the sides are usually noise; ignore unless
   you're chasing a specific rare path.

!!! note "Differential flame graphs"
    `py-spy` supports comparing two recordings with `py-spy record
    --format=speedscope`. Upload both to
    [speedscope.app](https://www.speedscope.app/) and use the "Sandwich"
    view to spot regressions.

## Detecting leaks in bounded queues

The `TraceEventBus` queues are [designed to drop on overflow](memory-overhead.md#event-bus-bounded-queues-drop-on-overflow).
If a subscriber is too slow, the drop counter goes up; RSS does not.
So a "leak" in the trace subsystem looks like:

- RSS steady.
- Per-subscriber drop counter climbing.
- Subscriber's own internal buffer growing (if it has one).

```python
for name, stats in context.events.subscriber_stats().items():
    print(f"{name}: dropped={stats.dropped}  queue_depth={stats.depth}")
```

If `dropped` is non-zero and climbing, the fix is **not** to increase the
queue cap — it's to make the subscriber faster, or to narrow the filter
upstream (see `tracing/filters.py::FilterExpr.compile`).

## A worked example

Suppose `deepview scan` on a 32 GiB image is 4× slower than the
[index](index.md) predicts.

Step 1: sanity-check the format with `py-spy`:

```bash
py-spy record --duration 10 -o scan.svg -- deepview scan image.dump
```

Read the graph. You expect the wide box at the top to be `memmove` or
`yara.scan`. If instead it's `LiMEMemoryLayer.read`, you're not on the
happy path for `mmap`-backed I/O — LiME's multi-region read goes through
`file.seek` + `file.read` every call. Fix: re-acquire as raw if possible.

Step 2: if the scanner itself is slow, switch to `cProfile` for frame
detail:

```bash
python -m cProfile -o scan.bin -m deepview scan image.dump
snakeviz scan.bin
```

Step 3: if RSS is growing, `memray run` and look at the flame graph with
`--leaks`. A scanner plugin accumulating `ScanResult` objects into a
list instead of yielding them is the usual culprit.

## Related reading

- [Startup time](startup-time.md) — the `-X importtime` workflow.
- [Memory overhead](memory-overhead.md) — expected RSS budget and the
  event-queue drop-on-overflow contract.
- [Offload throughput](offload-throughput.md) — the built-in
  `deepview offload benchmark` is itself a profiling tool.
