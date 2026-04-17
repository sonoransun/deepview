# Conference talk — 90-minute slide outline

A 30-slide outline for the 90-minute conference-talk version of the Deep
View workshop. Each slide has a title, 3-5 bullets, and speaker notes. Aim
for ~3 minutes per slide with a 5-minute buffer for transitions and
demos.

This version compresses the workshop's 3 hours into a single talk by
replacing the hands-on blocks with live demos. Audience members do not
install anything; they follow along on the projector.

---

## Slide 1 — Title

- Deep View: a forensics and runtime-analysis toolkit
- 90 minutes, 6 demos, 1 custom plugin
- Speaker name, affiliation, handle

*Speaker notes.* Housekeeping: this is a demo-heavy talk; if the projector
dies, fall back to screenshots in the handouts. Mention the QR code to the
handout repo.

---

## Slide 2 — Why are we here?

- Memory forensics is mature; everything around it isn't.
- Tracing, VM introspection, instrumentation, firmware: siloed tooling.
- One session object, one event bus, many subsystems.

*Speaker notes.* Don't oversell. Volatility 3 is used inside Deep View.

---

## Slide 3 — Outline

- Architecture (6 slides)
- Memory (5 slides)
- Tracing (4 slides)
- Instrumentation + mangle (3 slides)
- Plugins (3 slides)
- Reporting (2 slides)
- Wrap-up (3 slides + Q&A)

*Speaker notes.* Flip back to this slide whenever you transition sections.

---

## Slide 4 — The four-step workflow

- Acquire, Wrap, Analyse, Report.
- Every subsystem fits somewhere in those four.
- Icons: acquire / wrap / analyse / report.

*Speaker notes.* Drop the four-icon slide here. The audience will see these
icons on every section divider.

---

## Slide 5 — `AnalysisContext`

- Central session object.
- Owns config, layers, events, platform, artifacts, plugins.
- `AnalysisContext.for_testing()` in demos; `from cli/app.py` in production.

*Speaker notes.* The whiteboard drawing is optional in a conference talk;
use a simple graphic on the slide instead.

---

## Slide 6 — DataLayer

- Byte-addressable source with `read`, `write`, `is_valid`, `scan`.
- Physical: raw, LiME, ELF core, crashdump.
- Logical: virtual memory, `/proc/<pid>/mem`.
- Scanners compose over *any* layer unchanged.

*Speaker notes.* Emphasise the composition property — it's the headline
technical move.

---

## Slide 7 — Plugin system

- Three tiers: built-in, entry point, directory scan.
- Duplicates logged, not overridden.
- `@register_plugin` at import time.

*Speaker notes.* Foreshadow Demo 6 where we write one live.

---

## Slide 8 — Event / trace bus

- Core `EventBus`: synchronous, lifecycle + artefact events.
- `TraceEventBus`: async, bounded queues, drops on overflow.
- Monitor a slow consumer with `bus.stats()`.

*Speaker notes.* The drop-on-overflow contract is load-bearing; call it out
explicitly.

---

## Slide 9 — Platform detection

- `PlatformInfo.detect()` — OS, arch, kernel, capabilities.
- Subsystems gate on this object, not on `sys.platform` ad-hoc.
- Graceful degradation is the default.

*Speaker notes.* This is the "mundane plumbing that actually works"
moment.

---

## Slide 10 — Memory — section divider

- Acquire icon + "Memory".
- We'll cover acquisition, format parsing, analysis, artefact recovery.

*Speaker notes.* Breather slide.

---

## Slide 11 — Memory acquisition

- Linux: LiME.
- macOS: OSXPmem.
- Windows: winpmem, AVML.
- Live: `/dev/mem` or `/proc/kcore` where allowed.
- Hardware: PCIe DMA via leechcore + chipsec.

*Speaker notes.* Flag the hardware extras as opt-in.

---

## Slide 12 — Demo 1 — Open an image

- Live: open `mem-small.lime` from the Python REPL.
- Show `layer.is_valid()`, `layer.size`, `layer.read(0, 32)`.

*Speaker notes.* 2 minutes max. If the REPL stalls, fall back to the
screenshot in the handout.

---

## Slide 13 — Demo 2 — `pslist`

- Live: `deepview memory analyze --plugin pslist`.
- Point at `evil_daemon`.
- Tease Demo 3.

*Speaker notes.* 2-3 minutes. Pre-load the image to avoid parse latency.

---

## Slide 14 — Demo 3 — Anti-forensics

- Live: `deepview detect anti-forensics`.
- Explain the task-list / thread-list skew briefly.
- Show the HIGH-severity finding.

*Speaker notes.* This lands well with IR audiences.

---

## Slide 15 — Tracing — section divider

- Analyse icon + "Tracing".
- Linux / macOS / Windows.

*Speaker notes.* Breather.

---

## Slide 16 — Tracing providers

- Linux: eBPF via BCC.
- macOS: DTrace.
- Windows: ETW.
- All three fan out into the same `TraceEventBus`.

*Speaker notes.* The unified fan-out is the story.

---

## Slide 17 — Filter DSL

- Textual `parse_filter()` expressions.
- `FilterExpr.compile()` lifts cheap predicates into `KernelHints`.
- Hints become inline guards in the eBPF program.

*Speaker notes.* This is where eBPF stays performant despite a high-level
filter DSL.

---

## Slide 18 — Demo 4 — Live trace

- Live: `deepview trace --filter "syscall in (openat, execve)"`.
- Show a few events streaming.
- Ctrl-C and point at the drop counter in the summary.

*Speaker notes.* If BCC isn't on the demo box, substitute with a replay
session (see slide 29).

---

## Slide 19 — Classification + replay

- `EventClassifier` attaches rule matches to events.
- `SessionRecorder` writes events to SQLite (WAL).
- `SessionReplayer` re-publishes them — indistinguishable from live.

*Speaker notes.* This is what lets you tune rules offline.

---

## Slide 20 — Instrumentation + mangle — section divider

- Wrap icon + "Runtime intervention".
- Frida, static rewrites, NFQUEUE mangle.

*Speaker notes.* Warn the audience that this section covers dual-use
capabilities.

---

## Slide 21 — Frida engine

- `FridaEngine` attaches to a PID or spawns a binary.
- Pre-built JS scripts under `instrumentation/scripts/`.
- Results flow back into the `EventBus`.

*Speaker notes.* Skip the live demo here unless you have a spare 5 minutes.

---

## Slide 22 — Mangle

- `deepview netmangle run` — NFQUEUE + YAML ruleset.
- Requires root, `--enable-mangle`, non-empty ruleset.
- Fails open on error. `--dry-run` forces ACCEPT.
- Dual-use: authorised security testing, CTF, honeypot, defensive research.

*Speaker notes.* Read the gating list slowly. Emphasise fail-open.

---

## Slide 23 — Plugins — section divider

- Analyse icon + "Extend Deep View".
- Demo 6 comes next.

*Speaker notes.* Breather.

---

## Slide 24 — The `DeepViewPlugin` ABC

- Two methods: `get_requirements()`, `run() -> PluginResult`.
- `@register_plugin` decorator for metadata.
- Requirements are declarative (memory layer, argument, platform).

*Speaker notes.* 60 seconds on the interface.

---

## Slide 25 — Demo 6 — Write a plugin

- Live: write an `openfiles` plugin in ~30 lines.
- `deepview plugins list` picks it up.
- Run it against the demo image.

*Speaker notes.* 5 minutes. The fixture PID is 1337. If typing live, have a
backup `.py` ready to paste.

---

## Slide 26 — Reporting — section divider

- Report icon + "Deliverables".

*Speaker notes.* Breather.

---

## Slide 27 — Reporting outputs

- HTML, Markdown, JSON.
- ATT&CK Navigator layers.
- STIX 2.1 bundles.
- Timeline CSV for Super Timeline workflows.

*Speaker notes.* STIX is the one that makes SOC managers smile.

---

## Slide 28 — Wrap-up — section divider

- Logo slide, slightly larger.

*Speaker notes.* Breather.

---

## Slide 29 — Where to go next

- Full workshop: 3 hours, hands-on, repo link on the handout.
- Cookbook: worked examples for each subsystem.
- Reference: every CLI command, every plugin, every config field.
- Contribute: we actively review PRs; start with the plugin-authoring guide.

*Speaker notes.* Mention the contributor-friendly labels on the issue
tracker.

---

## Slide 30 — Q&A

- Questions.
- Mastodon / email / repo issues.
- Thank-you slide.

*Speaker notes.* Stay up front for 10 minutes after the talk for sidebar
questions. Record the hallway Qs for the FAQ doc.

---

## Pacing notes for the facilitator

- Slides 1-3: 6 minutes combined.
- Architecture (4-9): 15 minutes.
- Memory (10-14): 15 minutes, heavy demo.
- Tracing (15-19): 12 minutes.
- Instrumentation + mangle (20-22): 8 minutes.
- Plugins (23-25): 10 minutes, demo-heavy.
- Reporting (26-27): 5 minutes.
- Wrap-up + Q&A (28-30): 15 minutes.

Total: 86 minutes of content, 4 minutes buffer. If you're behind schedule at
slide 19, skip slide 21 (Frida) and collapse slides 26-27 into a single
page.
