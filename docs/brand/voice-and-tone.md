# Voice and tone

Deep View writes for working forensic investigators, incident responders,
firmware reverse engineers, and defenders — not for buyers. The brand voice
follows from the audience.

## Voice principles

1. **Technical, specific, verifiable.** Every claim should be testable from
   the codebase or a sample artefact. If the claim needs a caveat, put it in
   the same sentence.
2. **Honest about limits.** Deep View is a toolkit, not an oracle. When a
   subsystem degrades (optional dep missing, kernel too old, sample too
   corrupted), the docs say so plainly.
3. **Calm under pressure.** Readers often arrive here at 03:00 in the middle
   of an incident. Short sentences. Ordered lists. No adjectives between the
   investigator and the answer.
4. **Dual-use respectful.** Deep View has offensive-capable subsystems
   (NFQUEUE mangle, Frida, static rewrites). Write about them the same way
   you write about `pslist`: neutral, precise, gated behind explicit consent
   flags.
5. **Evidence-oriented.** Prefer "the layer returns bytes" over "the layer
   magically reads memory". The product is about *observation* — the prose
   should be too.
6. **Kind to the operator.** Error messages suggest next steps. Docs
   assume the reader has a job to do and no time to be lectured.

## Tone by context

| Context                       | Tone                                                       |
| ----------------------------- | ---------------------------------------------------------- |
| Reference docs                | Neutral, dense, every claim footnoted to code.             |
| Tutorials                     | Warmer, second-person, step numbers, expected output.      |
| Release notes                 | Factual. No hype verbs ("powerful", "revolutionary").      |
| Error messages                | One line of what failed, one line of what to try next.     |
| Log lines                     | Structured, key=value; prose is for humans, logs are for `jq`. |
| Incident runbooks             | Imperative, numbered, outcome-first.                       |
| Blog / announcements          | Measured. Celebrate specific wins; link to the code.       |

## Words we use

- **Artefact** (with the British spelling, matching `AnalysisContext.artifacts`
  in code — note: the code uses American `artifacts`; docs tolerate both but
  within a page, pick one).
- **Subsystem** — a coherent package of functionality (memory, tracing).
- **DataLayer** — Deep View's byte-addressable source, Volatility-inspired.
- **Plugin** — a `DeepViewPlugin` subclass registered via `@register_plugin`.
- **Dual-use** — capability that can be used defensively or offensively.
- **Fail-open** / **fail-closed** — specific terms of art; keep them.

## Words we avoid

- **Powerful, revolutionary, cutting-edge, next-generation** — marketing
  filler. Replace with a measurable claim.
- **Easy, simple, just** — what's easy for the writer is never easy for the
  reader on night 3 of an incident.
- **Hack, exploit** (as verbs in positive framing) — we use these only as
  literal technical terms.
- **Enterprise-grade** — meaningless.
- **AI-powered** — Deep View has an anomaly detector; it's a scoring model,
  not an oracle. If you mean `detection/anomaly.py`, say so.

## Do / don't pairs

These examples are lifted from situations that genuinely arise in the
codebase.

### Describing an optional dependency

**Don't**

> Deep View features lightning-fast eBPF tracing powered by BCC!

**Do**

> eBPF tracing requires the `bcc` Python bindings from the
> `linux_monitoring` extra. Without them, `tracing/providers/ebpf.py`
> imports successfully but `start()` raises `MissingDependency`. Install
> with `pip install -e '.[linux_monitoring]'` or use the DTrace / ETW
> providers on non-Linux hosts.

### Describing a dropped event

**Don't**

> Never lose an event again with Deep View's robust streaming engine.

**Do**

> The trace fan-out uses bounded async queues. When a subscriber cannot
> keep up, the bus drops events on *that* subscriber's queue and
> increments its drop counter rather than blocking producers. Check
> `bus.stats()` for `dropped` to detect a slow consumer.

### Describing the mangle subsystem

**Don't**

> Supercharge your red-team engagement with real-time packet rewriting!

**Do**

> `deepview netmangle run` injects an NFQUEUE jump into the host iptables
> chain and rewrites matching packets. It refuses to start without
> `--enable-mangle`, a non-empty ruleset, and root. `--dry-run` forces
> every verdict to ACCEPT. Every verdict path fails open on error. Scope
> this subsystem to authorised security testing, CTF, honeypot, and
> defensive research.

### Describing a failure mode

**Don't**

> If something goes wrong, Deep View will let you know.

**Do**

> If the acquisition fails mid-transfer, `MemoryManager.load()` raises
> `AcquisitionError` with the last successfully read offset in
> `error.last_offset`. The partial image is *not* deleted; resume by
> passing that offset to `--resume-from`.

### Describing `deepview doctor`

**Don't**

> Deep View diagnoses your system like a pro.

**Do**

> `deepview doctor` walks every optional dependency, prints one line per
> check, and exits non-zero if any required core module failed to
> import. Warnings for missing optional extras do not fail the command.

## Error-message style

Every error surfaced to an operator should answer three questions in order:

1. **What did Deep View try to do?**
2. **What went wrong?**
3. **What should the operator try next?**

Example:

```
ERROR: could not translate virtual address 0x7ffe0030 in layer 'kernel'.
 - reason: page-table walk terminated at PDE; present bit clear.
 - next:   this page is swapped out; acquire the pagefile and load it
           with `--aux-layer pagefile=/path/to/pagefile.sys`.
```

## Voice in the CLI

The same principles apply to CLI output. Prefer:

- Progress indicators with a concrete denominator (`124/512 MB`) over
  indefinite spinners.
- Verdict lines (`PASS`, `WARN`, `FAIL`) in the palette roles from
  [Palette](palette.md).
- Hints printed on non-zero exit, never on success.

## When in doubt

Ask: *would I want to read this at 03:00, on page 4 of an incident, on a
laptop borrowed from someone else?* If the answer is no, cut it down.
