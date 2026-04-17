# Hour 1 — Intro and architecture

Slide-by-slide outline for the first hour of the workshop. Each slide is
sized to roughly 2-3 minutes of speaking. The facilitator should read the
speaker notes before running the session and adjust for the specific room.

---

## Slide 1 — Title

**Title:** Deep View: a forensics and runtime-analysis toolkit

- *Speaker note:* Welcome, housekeeping (fire exits, bathrooms, Wi-Fi).
  Mention the workshop repo URL and confirm everyone installed prerequisites.
  If anyone is stuck on install, pair them with a facilitator during the
  first coffee break — don't slow the room down.

---

## Slide 2 — Who are you?

- Raise hands: GUI forensic suite users?
- Raise hands: Volatility 2 CLI users?
- Raise hands: Volatility 3 / Python API?
- Raise hands: ever written a custom plugin?
- *Speaker note:* Calibrate the first hour on the show of hands. If the
  room is all GUI users, spend extra time on slide 7 (why a CLI). If the
  room is mostly Volatility 2, compress slides 3 and 4.

---

## Slide 3 — Why another toolkit?

- Memory forensics is still mostly Volatility 3, which is excellent.
- Tracing, VM introspection, instrumentation, firmware, network mangle:
  each has its own tool with its own CLI shape.
- Deep View's thesis is *one session object*, `AnalysisContext`, that owns
  every subsystem and every event bus. You build one context, you get the
  whole toolkit.
- *Speaker note:* Avoid competitive framing. Volatility 3 is used *inside*
  Deep View as a library; we are not replacing it.

---

## Slide 4 — Forensic workflow, abstractly

Four steps. Deep View provides primitives for each.

1. **Acquire** — pull bytes off the target.
2. **Wrap** — ECC / FTL / decrypt / parse container format.
3. **Analyse** — plugins, scanners, classifiers.
4. **Report** — HTML, Markdown, JSON, ATT&CK layers, STIX bundles.

- *Speaker note:* The four-icon slide. Icons live at
  `docs/assets/icon-{acquire,wrap,analyse,report}.svg`.

---

## Slide 5 — The `AnalysisContext`

- `AnalysisContext` is the dependency-injection container.
- Owns: `config`, `layers`, `events`, `platform`, `artifacts`, `plugins`.
- Every CLI command builds one and stashes it on Click's context.
- Every subsystem has a `from_context(ctx)` constructor.
- *Speaker note:* Draw the diagram on the whiteboard as you talk; the
  mkdocs version is at `docs/architecture/index.md`.

---

## Slide 6 — DataLayer

- Volatility-3-inspired byte-addressable source.
- Interface: `read(offset, length)`, `write`, `is_valid`, `scan`.
- Physical layers (raw, LiME, ELF core, crashdump).
- Logical layers (virtual memory via page-table translation, live `/proc/<pid>/mem`).
- Scanners compose over any DataLayer unchanged.
- *Speaker note:* Emphasise that `LiveProcessLayer` lets the same YARA
  scanner you use on a disk image also scan a running process. This is the
  money shot.

---

## Slide 7 — Why CLI-first?

- Reproducibility. A command is a citation; a GUI click is not.
- Scriptability. You can build an incident-playbook `.sh` and hand it to a
  junior analyst.
- Automation. Deep View is meant to be invoked from orchestration (Ansible,
  a SOAR, CI pipelines that gate on a clean `doctor`).
- Evidence handling. A command history is something a court can read.
- *Speaker note:* The jury-readable argument lands well with investigators
  who have testified.

---

## Slide 8 — Install and `deepview doctor`

- Live demo.
- `pip install -e '.[dev,memory]'` — mention the extras system.
- `deepview doctor` — walk the output line by line.
- *Speaker note:* Keep your terminal on the projector with a big font.
  Pre-load the install so you aren't waiting for pip.

---

## Slide 9 — `deepview doctor` — the output

Expected output (roughly):

```
Deep View diagnostic report

core
  python 3.11.8                                   PASS
  AnalysisContext import                          PASS
  config file ~/.deepview/config.toml             WARN  (not found, defaults in use)

memory
  volatility3                                     PASS
  yara-python                                     PASS
  leechcore                                       SKIP  (no hardware acquisition requested)

tracing
  bcc (eBPF)                                      WARN  (module not installed)
  dtrace                                          SKIP  (not on macOS)
  etw                                             SKIP  (not on Windows)

plugins
  builtin                                         PASS  (42 registered)
  entry-points                                    PASS  (0 registered)
  directory scan                                  PASS  (0 registered)
```

- *Speaker note:* WARN lines are informational; the command exits 0. If the
  core PASS column has a FAIL, the install is broken.

---

## Slide 10 — Extras

- `memory` — Volatility 3, YARA, MemProcFS.
- `instrumentation` — Frida, LIEF, Capstone.
- `linux_monitoring` — BCC, pyroute2, psutil, netfilterqueue.
- `hardware` — leechcore, chipsec.
- `disassembly` — pyhidra (Ghidra bridge), Hopper SDK.
- `all` — everything.
- *Speaker note:* Extras exist because forensic workstations are often
  locked down; installing every native dep on every host is a non-starter.

---

## Slide 11 — The plugin system

Three tiers, in order:

1. Built-in (decorators in `plugins/builtin/`).
2. Entry points (third-party packages).
3. Directory scan (`~/.deepview/plugins/`).

- Duplicates are logged and skipped — first registration wins.
- *Speaker note:* We write a custom plugin in Exercise 6.

---

## Slide 12 — Events and the trace bus

- Core `EventBus` — synchronous pub/sub for lifecycle and artefact events.
- `TraceEventBus` — async fan-out with bounded queues for high-volume
  trace streams. Drops on overflow.
- *Speaker note:* Flag the drop-on-overflow contract now. We'll see it in
  exercise 3 when we crank up the syscall firehose.

---

## Slide 13 — `deepview storage list`

Live demo.

- Deep View keeps per-session state under `~/.deepview/`:
    - `config.toml` — user config.
    - `plugins/` — third-party plugins.
    - `sessions/` — replay SQLite databases.
    - `cache/` — analyser caches.
- `deepview storage list` prints what's there.
- *Speaker note:* Mention that `sessions/` can grow; show `deepview storage
  prune --older-than 30d` in passing.

---

## Slide 14 — Platforms

- Linux: most subsystems are first-class (eBPF, NFQUEUE, `/proc`, `procfs`).
- macOS: DTrace, OSXPmem, limited VM introspection.
- Windows: ETW, winpmem, crashdump parsing, memory analysis.
- *Speaker note:* Show `PlatformInfo.detect()` briefly; subsystems gate on
  this rather than on `sys.platform` ad-hoc.

---

## Slide 15 — Safety & dual-use

- Some subsystems can modify the host or the target. We gate them hard.
- Mangle: root + `--enable-mangle` + non-empty ruleset + confirmation prompt.
- Instrumentation: won't attach without PID or selector.
- Everything fails open on error.
- *Speaker note:* Reinforce that this is a defensive toolkit; red-team use
  is legitimate but scoped to authorised engagements.

---

## Slide 16 — First hands-on

- Open terminal. `deepview doctor`. Confirm PASS on core.
- `deepview storage list`. Note the empty-ish output.
- Point at [exercises.md](exercises.md). We'll work through Exercise 1
  together.
- *Speaker note:* Close the slide deck. The rest of the workshop is in the
  terminal.

---

## Slide 17 — What to bring back

- One command you'll paste into your runbook tomorrow.
- One subsystem you want to explore further.
- One question you want answered at the Q&A.
- *Speaker note:* This is a pre-commitment device to keep the room engaged
  through the exercises.

---

## Hand-off

From here, the facilitator switches to a live terminal and walks the room
through [Exercise 1](exercises.md#exercise-1-open-a-raw-memory-dump). Keep
this intro outline projected on a secondary monitor if you can — a couple of
people will want to re-read slides 5 and 6 while they're running `doctor`.
