# Deep View vs Velociraptor

!!! abstract "Velociraptor is a distributed live-IR platform; Deep View is a single-host toolkit."
    Velociraptor and Deep View both do live endpoint analysis with a rule-driven classification
    story, but they answer different questions. Velociraptor answers "what is happening across
    my fleet right now?" Deep View answers "what is happening on this one host, and how do I
    wire that into a memory / trace / instrumentation pipeline?"

They are not substitutes for each other. If you need a fleet, use Velociraptor. If you need
a coordinator for deep single-host work, use Deep View. The two can interoperate cleanly.

## One-paragraph recap of Velociraptor

Velociraptor is an open-source DFIR platform by Mike Cohen (the original author of GRR). It
runs as a **server + agent** architecture: a central server pushes queries to agents on tens
or thousands of endpoints, aggregates responses, and exposes a GUI and REST API. Its query
language is **VQL** — a SQL-like DSL with hundreds of artifact plugins that cover Windows,
Linux, and macOS live data collection, YARA scanning, event monitoring, and file hunting.

Velociraptor is the authoritative choice for distributed live IR. Deep View does not
compete with that deployment model.

## Where they overlap

- **Live tracing.** Velociraptor has `Server.Monitoring.*` artifacts and client-side event
  queries; Deep View has `tracing/` with eBPF / DTrace / ETW providers. Both surface
  syscall-level and higher events to a rule engine.
- **Classification rules.** Velociraptor leans on YARA and custom VQL; Deep View has its
  own rule engine in `classification/` plus YARA via `scanning/`.
- **Live filesystem and process enumeration.** Both can introspect running processes and
  walk the filesystem of a live host.
- **Recording / session storage.** Velociraptor stores responses on the server. Deep View's
  `replay/SessionStore` stores events in SQLite for local replay.

## Where they differ

| Dimension | Velociraptor | Deep View |
| --- | --- | --- |
| Deployment model | Server + signed agents | Single-host CLI / Python library |
| Query language | VQL (SQL-like DSL, interpreted) | Python plugins + YAML rules |
| Scale | Designed for thousands of endpoints | Designed for one host at a time |
| Authority surface | Endpoint live state (files, processes, registry, EVTX) | Live state **plus** memory images, disk images, firmware, DMA |
| Offline analysis | Limited (some offline collectors) | First-class: memory images, disk images, ROM dumps |
| Instrumentation | No built-in DBI | Frida engine + static binary rewriting |
| Recording | Server-side artifact collection | Local SQLite session record / replay |
| Push model | Server schedules hunts | Operator runs a command |

Notice the diagonal: where Velociraptor has the fleet, Deep View has the depth-per-host.
Where Velociraptor has VQL (great for collection queries), Deep View has Python plugins
(great for multi-stage pipelines that cross subsystems).

## VQL vs Deep View's plugin model

VQL is optimised for **ad-hoc queries at scale**. A hunter can write:

```sql
SELECT Name, Pid, CommandLine
FROM pslist()
WHERE Name =~ "(?i)powershell"
```

…and ship it to 10,000 endpoints. That is exactly what VQL is for.

Deep View's plugin model is optimised for **multi-step, multi-subsystem pipelines on one
host**. A `DeepViewPlugin` can acquire memory, run a Volatility plugin, cross-reference its
output with live tracing data, run a YARA scan, and emit a STIX bundle — all in one Python
class with proper types, unit tests, and version control.

The honest translation table:

| If you want to… | Use |
| --- | --- |
| Run the same quick query across many hosts | VQL |
| Stand up persistent endpoint monitoring with a central view | Velociraptor |
| Build a reproducible single-host investigation as code | Deep View plugin |
| Combine memory forensics with live tracing in one session | Deep View |
| Chase an incident across a fleet and aggregate centrally | Velociraptor |

## When to use each

**Use Velociraptor when:**

- You operate more than a handful of endpoints.
- You need an agent that survives reboot and phones home on a schedule.
- You want a GUI-driven hunting experience across the fleet.
- The investigation is predominantly "collect and search," not "deeply introspect."

**Use Deep View when:**

- You are on one host at a time — malware lab, CTF, red-team box, IR jump kit for a single
  machine.
- You need memory-image analysis, firmware dumps, or hardware-assisted acquisition in the
  same session as live tracing.
- You want the session recorded deterministically for replay through the classifier.
- You want to combine Frida instrumentation with trace filtering in one workflow.

## Possible integration patterns

### Velociraptor collects, Deep View analyses

Velociraptor is excellent at *collection*. Have it collect a memory image, a selection of
files, or a timeline, then ship the artefact to a workstation and run Deep View against it:

```bash
# On the analysis workstation
deepview memory load /evidence/collected-by-velociraptor.lime
deepview memory scan --plugin windows.pslist
deepview report generate --format html --out ./report.html
```

### Deep View feeds Velociraptor artifacts

The reverse is also valid: write a VQL artifact that invokes Deep View on the endpoint to
produce a focused report, and ship the resulting JSON back through Velociraptor's normal
collection channel. This works because Deep View's CLI emits clean JSON when `--format json`
is passed.

### Shared rules

YARA rules are portable between the two. If a rule matches in Velociraptor's `yara.scan()`,
it will match in Deep View's `scanning/yara_engine.py`. Keep the rule repository neutral and
both tools can consume it.

## Limitations we own

- Deep View has **no** server component, **no** agent push model, and **no** fleet view.
- We do not speak VQL, and we do not plan to. If you need VQL, use Velociraptor.
- There's no managed authentication/authorisation for multi-analyst use — that's Velociraptor's
  territory.

!!! tip "Fleet scale vs depth per host"
    The clearest mental model: Velociraptor is wide, Deep View is deep. You almost always
    want both in a mature security operation, not one or the other.

## Further reading

- [Tracing & classification architecture](../architecture/tracing-and-classification.md)
- [Velociraptor upstream](https://docs.velociraptor.app/)
