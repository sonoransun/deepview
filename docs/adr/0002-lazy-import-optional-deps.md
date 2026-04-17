# 0002. Lazy-import optional dependencies

- **Status:** Accepted
- **Date:** 2026-04-15

## Context

Deep View depends on many heavy, platform-specific, or licence-sensitive
libraries: `volatility3`, `yara-python`, `frida`, `lief`, `capstone`,
`pyhidra`, `leechcore`, `chipsec`, `bcc`, `pyroute2`, `netfilterqueue`,
`pycuda`, `pyopencl`, `numpy`, `scipy`, and more. None of them are
universally installable:

- `bcc` requires Linux + kernel headers + root.
- `pycuda` requires an NVIDIA toolchain.
- `frida` pulls a native agent that some corporate environments
  block.
- `volatility3` is Python-version-sensitive and large.
- `leechcore` requires a matching DLL per OS.

Forcing all of them to be required would make `pip install deepview`
fail on most machines. Segregating them under `[project.optional-dependencies]`
extras — `memory`, `instrumentation`, `hardware`, `gpu`, `linux_monitoring`,
etc. — solves *installation*, but not *import*. If `deepview/memory/manager.py`
does `import volatility3` at module top, then a user with a core-only
install sees `ModuleNotFoundError` the moment `deepview doctor` is run.

We need a consistent rule for how to consume these libraries.

## Decision

**Every optional dependency is imported lazily, inside the function or
method that first needs it.** Module top-level `import` statements are
reserved for the Python stdlib and for required dependencies
(pydantic, click, rich, structlog).

When the lazy import fails, the code path:

1. Logs a structured `ModuleNotFoundError` through `deepview.core.logging`
   at `DEBUG` level (not `WARNING` — users who never use the feature
   shouldn't see noise).
2. Raises a domain-specific error (e.g., `MemoryEngineUnavailable`) or
   returns a `PluginResult` with `status="skipped"` and a human-readable
   hint listing the extras that would enable it.
3. Is covered by a `requires_*` pytest marker so CI without the extra
   doesn't fail the test.

`TYPE_CHECKING` imports remain at module top, guarded by
`from __future__ import annotations` so they never execute at runtime.
This gives mypy the types without costing runtime.

## Consequences

### Positive

- `pip install deepview` and `deepview doctor` succeed on a vanilla
  Python 3.10 machine with no optional extras installed.
- `pytest` on the same machine runs the full unit suite; platform /
  tool-specific tests skip via markers.
- The `doctor` command can enumerate which extras are missing and print
  the exact `pip install` line that fixes each one.
- Adding a new optional library never forces a breaking change on
  existing users — it's additive.

### Negative

- **Imports happen on hot paths.** A function called inside a tight
  loop must not lazy-import on every call — it should import once at
  the top of the function body and rely on Python's module cache, or
  cache the imported symbol on an instance / class attribute. We accept
  this as a code-review item.
- **Type annotations for optional libraries are awkward.** We paper
  over it with `TYPE_CHECKING` and string-form annotations.
- **Error paths are more complex.** Every feature needs to decide what
  to do when its library is absent. We settle on "skip with
  actionable hint" for CLI and "raise domain error" for API callers.

### Neutral

- Startup becomes marginally faster (no eager import of huge libraries)
  at the cost of first-use being slightly slower. Both effects are
  small.

## Alternatives considered

### Option A — Require everything, split wheels by platform

Publish `deepview-linux`, `deepview-macos`, `deepview-windows`, each
with only its platform's deps. Rejected because:

- Triples the release matrix.
- Doesn't help when a single platform has optional extras (e.g.,
  GPU on Linux).
- PyPI projects with near-identical names are a user-experience mess.

### Option B — One giant install with `extras_require=["all"]`

Always install everything; let `pip` fail if one dep doesn't build.
Rejected because a single failing wheel (e.g., `bcc` on macOS) would
block installation entirely.

### Option C — Import at module top, catch `ImportError`

Wrap each top-level import in a `try/except`, set the symbol to `None`,
and check for `None` at call sites. Rejected because:

- `try/except ImportError` around dozens of imports bloats every
  module.
- Static analyzers (`mypy --strict`) fight it.
- Errors surface at import time for modules the user never calls,
  which is exactly what we want to avoid.

### Option D — A wrapper module (`deepview.deps`) that centralises imports

A single `_lazy("volatility3")` helper at each call site, with caching.
Considered and partially adopted — we do have small helpers in a few
places — but we resisted making it a hard rule because a local lazy
`import` inside the function that uses it is the most readable pattern
for most callers.

## References

- Example: `src/deepview/cli/commands/doctor.py` — enumerates extras and
  reports missing ones.
- Example: `src/deepview/memory/analysis/volatility.py` — lazy-imports
  `volatility3` inside `analyze()`.
- Example: `src/deepview/tracing/linux/procfs.py` — stdlib only, does
  NOT need the rule (counter-example).
- `pyproject.toml` `[project.optional-dependencies]` — the extras
  matrix this ADR relies on.
- Related ADR: [0010](0010-strict-mypy-and-py310-baseline.md) — the
  typing rules that make lazy imports manageable.
