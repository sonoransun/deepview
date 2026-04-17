# Deep View vs GDB + Mozilla rr

!!! abstract "GDB + Mozilla rr give you authoritative debugging; Deep View's replay is event-level only."
    rr records a target process at the instruction level and replays it deterministically under
    GDB — reverse-continue, reverse-step, watchpoints across history, the works. Deep View's
    `replay/SessionStore` records *events* (syscalls, classifier hits, Frida messages) and
    replays them into the classifier. These are different tools answering different questions.
    Don't expect one to do the other's job.

If you need deterministic reverse-execution of a process, you need rr, and Deep View will not
get in your way. If you need "replay last night's trace session through the current detection
ruleset," that's what Deep View does, and rr isn't the right tool.

## One-paragraph recap of rr

Mozilla **rr** (by Robert O'Callahan et al.) is an instruction-level record-and-replay
debugger for x86-64 Linux. It intercepts nondeterminism sources (syscalls, signals,
scheduling, rdtsc) during recording and replays the process deterministically afterwards,
cycle-by-cycle identically. Combined with GDB, it turns debugging into archaeology — you can
step *backwards* from a crash to the root cause with full register and memory fidelity.

It is the authoritative tool for "what exactly did this program do?" Nothing in Deep View
competes with that guarantee.

## The two "replays," side by side

| Dimension | rr | Deep View `replay/` |
| --- | --- | --- |
| Granularity | Every instruction | Each recorded event (syscall, trace, Frida msg, classifier hit) |
| Determinism | Full: same registers, same memory | Event stream is exact; the host state around it is not |
| Target scope | Single process tree | Whole session — may span many processes, kernels, providers |
| Storage | rr trace directory (large) | SQLite via `SessionStore`, WAL-mode, JSON columns |
| Reverse execution | Yes, reverse-step / reverse-continue | No — replay is strictly forward |
| Debugger integration | GDB, LLDB | None; replay drives the classifier |
| Platform | x86-64 Linux (with some ARM progress upstream) | Linux / macOS / Windows depending on provider |
| Overhead during record | Significant CPU + disk | Lightweight event logging |

The key point: **rr gives you ground truth on one process, Deep View gives you an event
history across a host**. Both are useful, for different things.

## What Deep View's replay actually does

`replay/SessionReplayer` re-emits stored events onto a private `TraceEventBus` at a configurable
speed. From the perspective of the classifier, the dashboard, or any subscriber, replayed
events are indistinguishable from live ones — so you can:

- Regress a detection rule against a captured incident.
- Reprocess a session with an updated ruleset.
- Drive a dashboard for a demo or a post-mortem walkthrough.

What it cannot do:

- Show you register state at an arbitrary point.
- Reverse-execute.
- Resurrect memory that wasn't captured at the time.
- Answer any question that requires instruction-level fidelity.

## What rr cannot do

rr is astonishing at what it does, but it has its own limits:

- It records one process tree at a time; it is not a fleet or whole-host instrument.
- Recordings are large — hours of recording can easily consume tens of gigabytes.
- Platform coverage is narrow: x86-64 Linux is the supported environment.
- It cannot re-run a trace through a *different* detection engine — the trace is the
  program, not a classifier-ready event stream.

## When you need each

**Reach for rr + GDB when:**

- You have a crash or a logic bug and need to rewind to the cause.
- You can reproduce the issue under rr-record.
- The question is "what exactly happened in this process?"
- You are debugging Deep View *itself* — rr is fantastic for that.

**Reach for Deep View replay when:**

- You captured a session from an incident and want to re-evaluate it with a new ruleset.
- You want to drive a dashboard from historical data for review.
- The question is "given these events, does our detector fire?"
- You need to regress detection rules across many recorded sessions in CI.

## Can they combine?

Loosely, yes. Record the target under rr, capture the same run's Deep View session in
parallel, and you get two complementary artefacts: the rr trace for instruction-level
forensics, and the Deep View session for rule-level reasoning. They do not share a data
format; the integration is "run both at the same time," not "convert between them."

!!! note "We are not trying to be rr"
    If someone asks for "reverse-step" in Deep View, the answer is rr. We're explicit about
    this because the word "replay" in both projects could mislead — the semantics are different
    and the right choice depends on which question you're asking.

## Honest limitations

- Deep View's event record is only as faithful as its providers. A dropped eBPF event
  (remember: the trace bus drops on overflow) will not be present in the replay.
- rr's determinism does not cover GPU, DMA, or kernel-internal state beyond its interposer —
  some forensic questions escape its model too.
- Neither tool substitutes for a proper memory capture if you need to inspect arbitrary
  addresses after the fact.

## Further reading

- [Architecture: tracing & classification](../architecture/tracing-and-classification.md)
- [rr upstream](https://rr-project.org/)
