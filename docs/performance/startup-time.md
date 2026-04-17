# Startup Time

Deep View is a CLI. Cold-start time is the first thing every user feels.
This page documents the budget, where the budget goes, and how to measure.

!!! warning "Synthetic numbers"
    Figures below come from the reference box in
    [offload-throughput](offload-throughput.md). Your hardware, Python
    version, and SSD will all shift these by 10–50%.

## The budget

| Command | Target | Typical actual | What runs |
|---|---|---|---|
| `deepview --help` | < 200 ms | ~150 ms | Click group import; zero subsystem construction |
| `deepview doctor` | 500–1000 ms | ~800 ms | Probes every optional extra via lazy import |
| `deepview plugins` | 300–600 ms | ~500 ms | All three plugin tiers; no plugin `run()` |
| `deepview status` | < 400 ms | ~300 ms | Builds `AnalysisContext` without probing extras |
| `AnalysisContext.for_testing()` | < 100 ms | ~60 ms | Used in `tests/conftest.py::context`; deliberately skinny |

These are measured with `hyperfine --warmup 3 --runs 10 'deepview --help'`.

## Why `--help` is fast

`deepview` is registered via `pyproject.toml` → `[project.scripts]` →
`deepview.cli.app:main`. That module imports Click and the command groups,
but nothing else. Subsystem modules are pulled in lazily inside the
command functions. So:

- `cli/app.py` imports the Click root → ~80 ms.
- Each command group (`memory`, `tracing`, `unlock`, …) is imported when
  Click resolves it. For `--help` this means **importing the group
  objects for display purposes only** — not their implementation modules.
- Result: `deepview --help` touches disk roughly as much as `click --help`
  would for any Click app of this size.

!!! tip "Don't break it"
    If you add a new command, put the expensive imports **inside the
    function body**, not at module top. The existing commands follow this
    pattern without exception; `doctor` in particular is the canonical
    reference for how to probe optional dependencies lazily.

## Why `doctor` is slower

`deepview doctor` deliberately imports every optional dependency to report
which are installed:

- `volatility3`, `yara-python`, `frida`, `lief`, `capstone`, `pyhidra`,
  `leechcore`, `chipsec`, `pycuda`, `pyopencl`, `numpy`, `scipy`,
  `galois`, `netfilterqueue`, `bcc`, `pyroute2`, `psutil`, `argon2-cffi`,
  `cryptography` — one probe each.
- Every import is wrapped in `try/except ImportError` so a missing extra
  is reported as absent, not as a crash.

At ~40 ms per heavy import times ~20 extras, 800 ms is honest.

!!! note "Running `doctor` repeatedly is wasteful"
    Once you know what's installed, you don't need to run `doctor` again
    until you change the environment. Don't call it from scripts.

## AnalysisContext first-access costs

`AnalysisContext` is instantiated by `cli/app.py` before command dispatch
and stashed in the Click `ctx.obj`. Every expensive subsystem is a lazy
attribute:

| Attribute | First-access cost | Cached? |
|---|---|---|
| `context.config` | ~20 ms (TOML parse + pydantic validate) | Yes, at construction |
| `context.platform` | ~10 ms (`PlatformInfo.detect()`) | Yes, at construction |
| `context.events` | <1 ms (empty bus) | Yes |
| `context.layers` | <1 ms (empty registry) | Yes |
| `context.plugins` | ~300 ms (three-tier discovery) | Yes, first access only |
| `context.offload` | ~50 ms (pool fork + GPU probe) | Yes, first access only |
| `context.artifacts` | <1 ms | Yes |

So the observable cost of `deepview status` is dominated by `config` +
`platform` (both eager) and comes in under 400 ms. Commands that actually
touch plugins or the offload engine pay the extra budget the first time
they access those attributes.

!!! tip "Fast testing"
    `AnalysisContext.for_testing()` skips the plugin registry and uses an
    in-memory config; construction is well under 100 ms. The `context`
    fixture in `tests/conftest.py` uses it, which is why `pytest` feels
    snappy despite loading the full package.

## Measuring

### `python -X importtime`

```bash
PYTHONUNBUFFERED=1 python -X importtime -m deepview --help 2> importtime.log
```

The output is a tree of self-time / cumulative-time per import. Sort by
the `cumulative` column to find anything that costs more than ~30 ms at
the top level. Good targets: any first-party module in
`deepview.*` that takes >50 ms at import is a bug.

### `hyperfine`

```bash
hyperfine --warmup 3 --runs 20 \
    'deepview --help' \
    'deepview plugins' \
    'deepview doctor'
```

Warmup runs prime the page cache for the Python interpreter and the
`deepview` script itself; without warmup the first invocation is
dominated by disk reads, which hides regressions.

### `py-spy record` for cold start

```bash
py-spy record --duration 3 --output startup.svg -- python -m deepview --help
```

The flame graph shows where cold-start wall-clock goes. Most frames
should be `_bootstrap._find_and_load` — imports of Click, pydantic, and
our own top-level modules.

## Common regressions

!!! warning "Things that will ruin startup"
    - Top-level `import volatility3` or `import yara` anywhere in the
      Deep View package. Both take hundreds of milliseconds.
    - Eager instantiation of `AnalysisContext` subsystems (don't touch
      `context.plugins` at import time).
    - A directory-scan plugin that does work at import time instead of
      in `run()`. Use `deepview plugins` to surface which plugins the
      registry finds; a new one that takes >100 ms to register is
      almost certainly doing work it shouldn't.

## Related reading

- [Profiling](profiling.md) — `-X importtime` and `py-spy` in depth.
- [Extending Deep View](../guides/extending-deepview.md) — how to add a
  plugin without hurting startup.
