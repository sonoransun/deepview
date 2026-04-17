# Architecture Decision Records

Architecture Decision Records (ADRs) track significant design choices made
across the Deep View codebase. Each ADR is short, immutable once accepted,
and records the *why* of a choice so future contributors can revisit the
rationale rather than guess it from the code.

We follow a **MADR-lite** format (Markdown Architecture Decision Records,
condensed): title, status, date, context, decision, consequences,
alternatives considered, references. No elaborate toolchain — ADRs are
plain markdown files in this directory, numbered sequentially.

## Conventions

- **Immutable.** Once an ADR is marked `Accepted`, its substantive content
  does not change. If a later decision supersedes it, we write a *new* ADR
  referencing the old one and flip the old one's status to
  `Superseded by NNNN`.
- **Numbering is permanent.** A retired ADR keeps its number forever.
- **Short.** Most ADRs are under 200 lines. If an ADR needs more, it
  usually means two decisions are tangled together — split them.
- **Cross-link generously.** Architecture pages link to ADRs; ADRs link
  back to the relevant architecture / reference pages so the *why* and
  the *how* stay close.
- **Scoped to non-obvious choices.** We do not write ADRs for every
  module layout decision — only for choices a reader would plausibly
  question later.

## Template

See [`template.md`](template.md) for the copy-pasteable MADR-lite
skeleton. Copy it to `NNNN-short-slug.md`, fill in the sections, and
add a row to the index below.

## Index

| #    | Title                                                                    | Status   | Date       |
|------|--------------------------------------------------------------------------|----------|------------|
| 0001 | [Data-layer composition over inheritance](0001-data-layer-composition-over-inheritance.md) | Accepted | 2026-04-15 |
| 0002 | [Lazy-import optional dependencies](0002-lazy-import-optional-deps.md)   | Accepted | 2026-04-15 |
| 0003 | [MkDocs-Material over Sphinx for docs](0003-mkdocs-over-sphinx.md)       | Accepted | 2026-04-15 |
| 0004 | [ProcessPool as default offload backend](0004-process-pool-default-offload-backend.md) | Accepted | 2026-04-15 |
| 0005 | [Pluggable unlocker via `UNLOCKER` module attribute](0005-pluggable-unlocker-via-module-attr.md) | Accepted | 2026-04-15 |
| 0006 | [Fail-secure remote acquisition defaults](0006-fail-secure-remote-acquisition.md) | Accepted | 2026-04-15 |
| 0007 | [`EncryptionKeyScanner` feeds the unlock orchestrator](0007-encryptionkeyscanner-feeds-unlocker.md) | Accepted | 2026-04-15 |
| 0008 | [Typed events over per-call callbacks](0008-events-not-callbacks.md)     | Accepted | 2026-04-15 |
| 0009 | [Dump format detection: magic first, extension fallback](0009-dump-format-detection-by-magic-then-extension.md) | Accepted | 2026-04-15 |
| 0010 | [Strict mypy + Python 3.10 baseline](0010-strict-mypy-and-py310-baseline.md) | Accepted | 2026-04-15 |

## Reading order

For a new contributor, a reasonable first pass is:

1. **0008** — understand the event bus contract before anything else,
   because most subsystems talk through it.
2. **0001** — understand the `DataLayer` stacking model.
3. **0002** — understand why imports look the way they do.
4. **0010** — understand the typing / style baseline.
5. Everything else in numerical order.

## Related documents

- [Roadmap](../roadmap.md) — where the codebase is heading (speculative).
- [Architecture overview](../overview/architecture.md) — the *how* to
  complement the *why* here.
- [Interfaces reference](../reference/interfaces.md) — the ABCs that
  ADRs 0001, 0005, and 0008 shape.
