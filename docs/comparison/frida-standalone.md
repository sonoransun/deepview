# Deep View vs Frida (standalone)

!!! abstract "Frida is the world's best dynamic instrumentation framework — Deep View wraps it."
    `src/deepview/instrumentation/frida_engine.py` instantiates Frida, attaches to a target,
    injects JavaScript agents from `instrumentation/scripts/`, and shuttles messages back onto
    the `EventBus`. We do not reimplement Stalker, GumJS, the injector, or any of the hard
    parts. If you have a Frida workflow that already works, Deep View's job is to make it
    play nicely with the rest of the toolkit, not to replace it.

This page exists to stop anyone confusing "wraps Frida" with "competes with Frida." We're
unambiguously downstream users of the Frida project.

## One-paragraph recap of Frida

Frida is Ole André Vadla Ravnås's cross-platform dynamic instrumentation framework. It runs
a JavaScript engine inside target processes, exposes low-level hooks via its Gum library,
ships a Python/Node/Swift/etc. client API, and works on Windows, macOS, Linux, iOS, Android,
and several embedded targets. The core CLIs — `frida`, `frida-trace`, `frida-ps`, `frida-ls-devices`
— plus the Python API (`frida` on PyPI) cover the vast majority of dynamic instrumentation
use cases.

Frida is authoritative in its domain. Nothing in Deep View competes with `frida-trace` or
GumJS as an instrumentation primitive.

## Where Deep View overlaps

- **Attach / spawn.** Deep View's `frida_engine.py` can attach to a running PID or spawn a
  target with arguments, the same way the Frida Python API does.
- **Script loading.** We load JavaScript agents — either ones we ship under
  `instrumentation/scripts/` or user-provided ones — exactly as Frida does.
- **Message pumping.** When an agent calls `send()`, we route the message onto the Deep View
  `EventBus` so other subsystems can react.
- **Interceptor-style hooks.** Our bundled agents use `Interceptor.attach` and `Stalker`
  underneath; the hook semantics are Frida's.

## Where Deep View does NOT overlap

- **GumJS / Stalker.** The engine itself is 100% upstream Frida. We don't fork it.
- **Cross-language bindings.** If you want frida-node, frida-swift, or the Qt tools, use
  Frida directly.
- **REPL.** Deep View does not implement an interactive JS REPL like `frida` does.
- **Device handling.** USB devices, `frida-server` deployment on Android/iOS, and similar
  transport concerns remain Frida's responsibility — Deep View exposes a Python-level
  session, not a device manager.

## Frida-native CLIs vs `deepview instrument`

### `frida` (REPL)

```bash
frida -p 1234
# interactive JS shell attached to PID 1234
```

Use it when you want to explore a target interactively. Deep View has no equivalent.

### `frida-trace`

```bash
frida-trace -i 'recv*' -p 1234
# auto-generates per-function stubs for symbols matching recv*
```

`frida-trace` is excellent for ad-hoc function-level tracing. It autogenerates a stub per
symbol and prints a running log.

`deepview instrument trace --pid 1234 --pattern 'recv*'` is the Deep View-flavoured
equivalent. The differences:

- Deep View's output lands on the `EventBus`, so classification rules and the live
  dashboard see it immediately.
- Deep View records the session into the replay store (`replay/SessionRecorder`) if enabled,
  so you can re-play instrumentation events offline through the classifier.
- Deep View unifies the output format with other subsystems — the same event type flows
  whether the data came from Frida, eBPF, DTrace, or ETW.

### `frida-ps`

Listing processes is a two-line script in both tools; neither one is meaningfully better
at it. If you're already in a Frida workflow, keep using `frida-ps`.

## Where Deep View adds value

The interesting question isn't "what can Frida do that Deep View can't?" — that list is
easy: almost everything Frida does standalone. The interesting question is "what does the
wrapping buy you?"

- **EventBus integration.** A Frida message becomes an event that classification rules,
  dashboards, and the session recorder all see. No glue code.
- **Classification.** The same YAML ruleset that tags suspicious eBPF events tags
  suspicious Frida interceptor hits.
- **Reporting.** `deepview report generate` pulls Frida events into the same HTML / STIX /
  ATT&CK Navigator output as memory and tracing results. No manual export.
- **Replay.** Recorded Frida sessions can be replayed through
  `replay/SessionReplayer` against the current classifier ruleset — useful for regressing
  detection rules against a captured trace.
- **Plugin composition.** A `DeepViewPlugin` can spawn a target, hook it with Frida, run
  a memory capture at a breakpoint, and scan the capture with YARA — all in one typed
  pipeline. That's tedious to do by hand across the Frida CLI and other tools.
- **Bundled scripts.** `instrumentation/scripts/` carries pre-built agents for common
  forensics tasks (anti-debug bypass, crypto API tracing, file-I/O shadowing) that you'd
  otherwise have to write from scratch.

## When to use Frida directly

- You want the REPL to poke at a target interactively.
- Your work is exploratory JavaScript authoring that benefits from `frida-trace`'s
  stub-generation flow.
- You're writing a Frida agent to *ship*, and Deep View is not part of the delivery.
- You're on a platform (iOS, Android) where Deep View's Python surface isn't what you
  want on the host — use Frida-node or Frida-Swift instead.

## When to use Deep View's wrapper

- The Frida work is one stage in a multi-stage forensic investigation.
- You want the output recorded and replayable through the classifier.
- You want classification rules to see Frida events alongside tracing events.
- You're composing Frida with Volatility, with eBPF, or with static rewriting.
- You want a single report that covers Frida findings along with everything else.

## Honest limitations

- **Version lag.** When Frida releases a new version with new API, Deep View may lag by a
  minor release before we adopt it. Standalone Frida is always ahead.
- **Not every Frida feature is surfaced.** If you need a niche Frida option (a specific
  device-manager flag, a custom `RelocatorGenerator`), the Deep View CLI might not expose
  it yet — you can still use the Python API under `frida_engine.py` directly.
- **Platform parity.** Mobile instrumentation (iOS / Android via `frida-server`) works
  under the hood but is less polished in the Deep View CLI than it is in the native Frida
  tools.

!!! tip "Wrap, don't replace"
    Deep View's Frida integration is explicitly a wrapper. If you want *more* from Frida
    itself, go upstream; we'll follow. If you want Frida to play well with memory forensics,
    classification, replay, and reporting — that's what we're for.

## Further reading

- [Architecture: tracing & classification](../architecture/tracing-and-classification.md)
- [Frida upstream](https://frida.re/)
