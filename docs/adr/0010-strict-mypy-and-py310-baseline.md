# 0010. Strict mypy + Python 3.10 baseline

- **Status:** Accepted
- **Date:** 2026-04-15

## Context

Deep View is a forensics toolkit whose correctness matters. A silent
off-by-one in a page-table walker, a shape error in an event handler,
or a `None` returned where `bytes` was expected can corrupt an
analysis and mislead an investigator. Static type checking catches an
important class of these bugs before the code runs, and the Python
typing ecosystem has matured enough (PEP 604 unions, PEP 612 paramspec,
PEP 646 tuple generics, PEP 695 generic aliases) that type hints carry
real weight.

Two distinct but related questions:

1. **How strict should mypy be?** Mypy's strict mode enables
   `disallow_untyped_defs`, `disallow_any_generics`,
   `warn_return_any`, and several other checks that together force
   complete annotations.
2. **What Python version is the baseline?** A modern baseline
   unlocks PEP 604 (`str | None`), `match` statements, better
   dataclass semantics, `ExceptionGroup`, and `tomllib`. An older
   baseline buys a wider install base.

The project has no legacy users to support; v0.2 is an early release.
We want to pick a baseline that is modern enough to use the good
features but old enough to be broadly available in 2026.

## Decision

**Mypy runs in strict mode (`--strict`) over `src/`. The baseline
Python version is 3.10.** Every module must begin with
`from __future__ import annotations` so that all annotations are
evaluated lazily and PEP 604 union syntax works uniformly.

Concretely, `pyproject.toml` declares:

- `requires-python = ">=3.10"`
- `[tool.mypy] strict = true`, `python_version = "3.10"`
- `[tool.ruff] target-version = "py310"`, `line-length = 100`

Conventions that follow from the baseline:

- **PEP 604 unions** (`str | None`) everywhere; no `Optional[...]`
  (except where it meaningfully communicates "this may be absent"
  intent).
- **Dataclasses** (`@dataclass`, `@dataclass(frozen=True)`) for
  structured data; no ad-hoc dicts with typed-dict aliases except at
  API boundaries.
- **Explicit return types** on every function, including `-> None`.
- **`TYPE_CHECKING` guarded imports** for types that are only needed
  at annotation time — this couples well with ADR 0002's lazy-import
  rule.
- **No `Any` without a reason.** If `Any` appears, a comment on the
  same line explains why.
- **`match` statements are welcome** where a switch on type or
  sentinel improves clarity.

CI enforces: `ruff check src tests` + `mypy src` must pass on every PR.

## Consequences

### Positive

- **A large class of bugs dies at commit time.** Wrong argument
  order, `None` leaks, event-schema drift, and refactor slips all
  get flagged.
- **Typed events + strict mypy** (per ADR 0008) combine to give the
  event bus end-to-end type safety.
- **Refactors are cheap.** A rename propagates through the type
  checker; broken call sites are enumerated.
- **Readable signatures.** `str | None` is shorter and clearer than
  `Optional[str]`; the codebase is uniform in style.
- **Modern dataclass semantics.** Python 3.10's `slots=True`,
  `kw_only=True`, and `match_args` are available.
- **`tomllib` in stdlib** for config parsing (no `tomli` dependency).

### Negative

- **Contributor friction.** A first-time contributor who isn't used
  to strict typing pays a learning cost. We document the conventions
  in `CONTRIBUTING.md` and keep the examples in the codebase
  consistent.
- **Some libraries are untyped.** Third-party deps without stubs
  (e.g., older versions of `leechcore`, `frida`) force us into
  `# type: ignore[no-any-unimported]` locally. Ruff and mypy both
  accept scoped ignores; we keep them minimal and documented.
- **Py310 excludes Debian-stable / Ubuntu-LTS default Pythons from
  a few years ago.** Every modern distribution ships 3.10+ by
  2026; we accept the cut.
- **`from __future__ import annotations` is easy to forget.** Ruff's
  `FA` ruleset catches missing imports as a linter error.

### Neutral

- The baseline is not a promise that we will never move. Python 3.12
  ships meaningful PEP 695 improvements (`type` statements for
  generic aliases). When the ecosystem catches up, we will consider
  moving the floor; that decision will get its own ADR.
- Ruff and mypy configurations are kept in `pyproject.toml` so a
  contributor running `ruff check` locally gets the same rules as CI.

## Alternatives considered

### Option A — Gradual typing (non-strict)

Allow untyped defs; let contributors add annotations incrementally.
Rejected because the value of static typing decays rapidly once
`Any` creeps into call chains: one untyped function makes several
downstream checks useless. Strict-from-the-start is cheaper than
strict-later.

### Option B — Python 3.8 baseline

Broader install base. Rejected because:

- PEP 604 unions and `from __future__ import annotations`
  work but mypy treats some features inconsistently in 3.8.
- `tomllib` is stdlib from 3.11 (we still ship a 3.10-compatible
  fallback with `tomli`).
- `match` statements require 3.10. We wanted them.

### Option C — Python 3.12 baseline

The newest features — PEP 695 generic syntax, `ExceptionGroup`-heavy
workflows — are attractive. Rejected for 2026: 3.12 is not yet on
every CI runner / Debian stable, and 3.10 is enough for what we need
today.

### Option D — Pyright instead of mypy

Faster, with better inference on some modern features. Rejected
because mypy is the ecosystem default, better integrated with
pre-commit and with most editors, and sufficient for our uses.
We may revisit if pyright ships a plugin API that clearly beats
mypy for our specific needs.

### Option E — No type checking

Historical norm for Python; minimises friction. Rejected — see the
opening Context paragraph.

## References

- `pyproject.toml` — the authoritative declaration of version,
  strict mode, and line length.
- `CLAUDE.md` — "mypy is in strict mode and ruff target is py310
  with a 100-char line limit — match the existing style
  (`from __future__ import annotations`, PEP-604 unions, dataclasses
  over ad-hoc dicts for structured data)."
- Mypy strict mode docs: https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-strict
- PEP 563: postponed evaluation of annotations.
- PEP 604: union operator `|`.
- Related ADR: [0002 — Lazy imports](0002-lazy-import-optional-deps.md)
  — the `TYPE_CHECKING` guard is the mechanism.
- Related ADR: [0008 — Events over callbacks](0008-events-not-callbacks.md)
  — typed events depend on this baseline.
