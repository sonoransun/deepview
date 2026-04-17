# Integrations

Deep View is designed to slot into existing forensics, detection, and
observability pipelines rather than replace them. This section documents
the first-party integration recipes that ship with the toolkit, plus
reference code you can adapt to downstream systems.

Each recipe subscribes to a well-defined slice of the
[core event model][events] and either forwards serialized events to an
external system or imports external artifacts back into an
[`AnalysisContext`][arch-context].

[events]: ../reference/events.md
[arch-context]: ../architecture/tracing-and-classification.md

## SIEM and log aggregation

| Guide | Description |
| ----- | ----------- |
| [Splunk](splunk.md) | Forward `EventClassifiedEvent`, `RootkitDetectedEvent`, and `BaselineDeviationEvent` to Splunk HEC. |
| [Elastic](elastic.md) | Bulk-index Deep View events into Elasticsearch with ECS-compliant field mapping. |
| [Generic SIEM](siem-generic.md) | JSON-line streaming over stdout for fluentd, vector.dev, rsyslog, and similar collectors. |

## Threat intelligence and case management

| Guide | Description |
| ----- | ----------- |
| [MISP](misp.md) | Push `IoCEngine` findings to MISP via PyMISP with attribute-type mapping. |
| [Timesketch](timesketch.md) | Export `filesystem_timeline` plugin output as a Timesketch-compatible CSV. |

## Reverse engineering tools

| Guide | Description |
| ----- | ----------- |
| [IDA Pro](ida-pro.md) | Export `DisassembledInstruction` lists and `ControlFlowGraph` data as IDC scripts for annotation. |
| [Ghidra](ghidra.md) | Drive Ghidra headless via `pyhidra` to enrich Deep View disassembly results. |

## Packet and network tooling

| Guide | Description |
| ----- | ----------- |
| [Wireshark](wireshark.md) | Serialize `NetworkPacketObservedEvent` / `NetworkPacketMangledEvent` to pcapng for offline analysis. |

## Notebooks and ad-hoc analysis

| Guide | Description |
| ----- | ----------- |
| [Jupyter](jupyter.md) | Drive `AnalysisContext` interactively, render `PluginResult.rows` as pandas DataFrames, plot timelines with matplotlib. |

## Choosing an integration

!!! tip "Rule of thumb"
    - For **real-time alerting**, pick Splunk, Elastic, or the generic SIEM
      recipe and subscribe at the `TraceEventBus` / `EventBus` layer.
    - For **post-incident investigation**, export to Timesketch or Jupyter
      and work from persisted session stores (`replay/` SQLite).
    - For **reverse engineering handoff**, the IDA and Ghidra recipes
      bridge Capstone results into full-featured disassemblers.
    - For **threat sharing**, push IoCs through MISP and let downstream
      sensors consume the MISP feed.

!!! note "Event model stability"
    All recipes depend on the typed event classes under
    `deepview.core.events`. Treat these as semi-stable public API: fields
    may be added, but existing fields are not renamed without a migration
    note in the release changelog. When in doubt, pin to a specific
    Deep View version in your forwarder's requirements file.

## Pull request integrations

The integrations catalogued above are shipped in-tree because they have
at least one recipe tested in CI. Community integrations (Graylog,
Datadog, Chronicle, TheHive, Cortex, OpenCTI) live as example gists
linked from the project wiki. If you build a production-grade forwarder
for one of those systems, we welcome a pull request that promotes it
here.
