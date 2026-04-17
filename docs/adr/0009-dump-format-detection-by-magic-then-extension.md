# 0009. Dump format detection: magic first, extension fallback

- **Status:** Accepted
- **Date:** 2026-04-15

## Context

The memory-acquisition subsystem accepts image files in many formats:
raw `.dd` / `.bin`, LiME `.lime`, AVML `.avml`, Microsoft crash-dump
`.dmp` (multiple flavours), ELF core `.core` / `.elf`, Windows
hibernation `hiberfil.sys`, WinPMem / OSXPmem variants, and more.

The user hands us a path (or a byte source) and expects the system to
pick the right parser. There are two obvious signals:

- **File extension.** Cheap, obvious, but wrong in common cases.
  Forensic workflows rename files; images are often stored without
  extensions; some formats share `.dmp` with completely unrelated
  blobs.
- **Magic bytes.** The actual on-disk signature at a known offset.
  Authoritative but requires a read of the file's first few KiB.

Getting this wrong has operational cost: a LiME file parsed as raw
returns garbage until someone notices; a crashdump parsed as ELF
throws a confusing ELF parser error halfway through analysis.

## Decision

**Format detection probes magic bytes first; the file extension is a
tie-breaker and a fallback, never the primary signal.**

The detection routine
(`deepview.memory.formats.detect.detect_format(path)`):

1. Opens the file read-only, non-blocking, and reads the first 4 KiB
   into memory.
2. Runs each registered format's `MAGIC_MATCH(bytes) -> bool` predicate
   against that buffer, in a defined priority order (the more specific
   formats go first).
3. If exactly one format matches, returns it. If multiple match, picks
   the highest priority and logs a `FormatAmbiguityEvent`.
4. If no format matches, falls back to extension-based mapping, logs a
   `FormatDetectedByExtensionEvent`, and returns the best guess.
5. If the extension is also unrecognised, returns `"raw"` with a
   `FormatUnknownEvent` logged at `WARNING`.

Callers can override detection with `--format=<name>` on the CLI or
`MemoryManager.load(path, format=...)` in code. An explicit override
skips detection entirely.

## Consequences

### Positive

- **Robust against renames.** A `.dmp` file that is actually a LiME
  dump is detected correctly.
- **Robust against extension-less files.** A forensic pipeline that
  stores images as content-addressable blobs (no extension) gets
  correct detection with no extra work.
- **Observability.** Every detection path publishes an event, so an
  operator reviewing a session can see whether detection was by magic
  or by extension — useful when results are surprising.
- **Cheap.** Reading the first 4 KiB is a single `pread`. Most modern
  filesystems serve it from cache after the first touch.
- **Extensible.** Adding a new format means adding one module with a
  `MAGIC_MATCH` predicate, a priority, and a parser. No change to
  detection code.

### Negative

- **Overlapping magic is possible.** ELF core and vanilla ELF share
  `\x7fELF`; distinguishing them requires reading `e_type` and
  checking for the `NT_PRSTATUS` note. We handle it by giving
  ELF-core a more specific predicate at higher priority.
- **Not robust against encryption/compression.** A gzipped LiME file
  has gzip magic, not LiME magic. The detector correctly returns
  `gzip` in that case and the caller is expected to decompress first;
  there is no auto-decompress. We document this.
- **4 KiB buffer is a hard limit.** A format whose magic lies beyond
  4 KiB would need the buffer extended or a second probe pass; this
  has not been an issue for current formats.

### Neutral

- Extension tie-break logic is a short dispatch table, trivial to
  maintain.
- The `--format=` override is always available as an escape hatch.

## Alternatives considered

### Option A — Extension first, magic only on failure

Cheaper when the extension is right (no file read). Rejected because
being right 90% of the time and silently wrong 10% of the time is
exactly the operational hazard we want to avoid.

### Option B — Magic only; no extension fallback

Strict but brittle. A format without a clear magic signature (some
raw-dump variants, `.raw`, `.bin`) would be undetectable; every such
file would need `--format=raw`. Rejected as hostile.

### Option C — `libmagic` / python-magic

A mature library for general file identification. Rejected because:

- Adds a native dependency (`libmagic`) that complicates install.
- Its database does not cover forensic formats we care about (LiME,
  AVML, Windows hibernation file internals).
- We would still have to layer our own predicates for those formats.

### Option D — Heuristic content analysis (entropy, structure walks)

Read 10+ MiB and run statistical tests. Rejected as far too expensive
for a detection-time operation and because it is uncomfortably
close to "guessing."

## References

- Source: `src/deepview/memory/formats/` — per-format parsers and
  magic predicates.
- Source: `src/deepview/memory/formats/detect.py` — the dispatcher.
- Source: `src/deepview/memory/manager.py` — consumer; receives the
  detected format and instantiates the right parser.
- Reference page: [`../reference/interfaces.md`](../reference/interfaces.md)
- Related ADR: [0008 — Events over callbacks](0008-events-not-callbacks.md)
  — detection events flow through the standard bus.
