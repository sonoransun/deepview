# NIST SP 800-86 Mapping

[NIST Special Publication 800-86](https://csrc.nist.gov/publications/detail/sp/800-86/final),
*Guide to Integrating Forensic Techniques into Incident Response*,
partitions the forensic process into four procedural phases:
**Collection**, **Examination**, **Analysis**, and **Reporting**. This
page maps each phase and each referenced sub-section to concrete
Deep View capabilities.

!!! warning "Operational mapping, not a compliance certification"
    This is a feature map, not an attestation. NIST SP 800-86 is a
    guide, not a certifiable standard — there is no "NIST SP 800-86
    compliant" stamp to receive. Use this page to show an auditor
    *which* Deep View subsystem covers *which* section of the
    publication.

## Section 3: Performing the Forensic Process

The four phases are described in Section 3 of the publication. Each
has a sub-section with the responsibility and expected outputs.

### Section 3.1 — Collection

NIST SP 800-86 §3.1 defines the Collection phase as the
**identification, labelling, recording, and acquisition of data** from
the possible sources, while preserving the integrity of that data. The
document calls out volatility ordering (§3.1.2) and the use of
write-blockers for storage media (§3.1.3).

| NIST §3.1 requirement | Deep View capability | Module |
|-----------------------|----------------------|--------|
| Identify data sources | `deepview doctor` enumerates platform capabilities; `PlatformInfo.detect()` records kernel, arch, hypervisor context | `src/deepview/core/context.py`, `cli/commands/doctor.py` |
| Label and record acquisition | `AcquisitionResult` dataclass captures source, timestamp, acquirer, tool version; `structlog` emits an audit record for every acquisition call | `src/deepview/memory/manager.py`, `interfaces/acquisition.py` |
| Acquire memory (volatile) | Provider plugins: LiME (Linux), WinPMem (Windows), OSXPMem (macOS), AVML (Linux Azure), live `/proc/kcore` | `src/deepview/memory/acquisition/{lime,avml,winpmem,osxpmem,live}.py` |
| Acquire disk (non-volatile) | Read-only `DataLayer` abstraction; `FileAcquisition` hashes contents during read | `src/deepview/interfaces/layer.py`, `memory/acquisition/*.py` |
| Follow volatility order (§3.1.2) | Documented in [OPSEC guide](../security/opsec.md#acquisition-order); manager refuses to snapshot disk before memory by default when both are requested | `src/deepview/memory/manager.py::acquire()` |
| Preserve with hashes | `AcquisitionResult.hash_sha256` is computed inline with the write; also `hash_sha512` when `--strong-hash` is set | `src/deepview/memory/acquisition/base.py` |
| Use write-blockers (§3.1.3) | Deep View enforces read-only `DataLayer.read()` contract at the interface level — no `write()` method on the abstract layer; recommend hardware write-blocker for disk imaging | `src/deepview/interfaces/layer.py` |
| Chain of custody | Session store (`SessionRecorder`) persists every event with a timestamp, operator ID (from `DEEPVIEW_OPERATOR` env var), and SHA-256 of each artifact | `src/deepview/replay/recorder.py`, `replay/schema.py` |

### Section 3.1.2 — Order of Volatility

NIST enumerates the order in which to collect data: CPU registers and
cache, routing table and ARP cache, process table and kernel
statistics, memory, temporary files, disk, remote logging, archival
media.

| NIST order | Deep View source |
|------------|------------------|
| Registers / cache | Not collected — Deep View defers to OS live-snapshot primitives |
| Routing table / ARP | `tracing/linux/netlink.py` (live); `memory/network/tcp_reconstruct.py` (post-hoc from dump) |
| Process table | `inspect/process.py::ProcessInspector`; `tracing/linux/procfs.py` |
| Kernel statistics | `tracing/linux/kallsyms.py`; eBPF kprobe sampling in `tracing/providers/ebpf.py` |
| Memory | Memory acquisition providers (LiME, WinPMem, etc.) |
| Temporary files | File acquisition via `DataLayer` |
| Disk | Same — `DataLayer` over block device or image file |
| Remote logging | Not in scope; operator responsibility |

### Section 3.1.3 — Handling of Evidence

The "Handling Data" sub-section requires every access to the evidence
to be logged, the evidence to be write-protected, and the custody to
be traceable. Deep View's `EventBus` emits a typed event for every
acquisition, every plugin invocation, and every `DataLayer.read` that
a plugin explicitly opts into for audit. The structlog processor
chain adds an ISO-8601 timestamp, operator identifier, and a hash of
the evidence bytes that were touched.

## Section 3.2 — Examination

NIST SP 800-86 §3.2 describes Examination as the **application of
tools and techniques appropriate to the data** to identify and extract
relevant information while retaining the evidence's integrity. This
is the phase where filtering, carving, and indexing happen.

| NIST §3.2 requirement | Deep View capability | Module |
|-----------------------|----------------------|--------|
| Extract information from images | `deepview memory scan`, `deepview memory plugins <name>` dispatches Volatility 3 / MemProcFS | `src/deepview/memory/analysis/{volatility,memprocfs}.py` |
| YARA scanning | `scanning/yara_engine.py` accepts compiled rules or rule files, emits `YaraMatchEvent` | `src/deepview/scanning/yara_engine.py` |
| String carving | `scanning/string_carver.py` with encoding-aware extraction (ASCII, UTF-16LE, UTF-16BE) | `src/deepview/scanning/string_carver.py` |
| IoC matching | `scanning/ioc_engine.py` applies IP, domain, hash IoCs against memory and traffic | `src/deepview/scanning/ioc_engine.py` |
| Filter by relevance | Trace filter DSL (`parse_filter()`) compiles to a plan; kernel hints push predicates to eBPF where possible | `src/deepview/tracing/filters.py` |
| Preserve chain during examination | Examination plugins consume `DataLayer` (read-only); write access is not in the interface | `src/deepview/interfaces/layer.py` |
| Reduce large datasets | Replay subsystem + circular buffer supports windowed analysis on a subset of captured events | `src/deepview/replay/{reader,replayer,circular_buffer}.py` |

## Section 3.3 — Analysis

NIST SP 800-86 §3.3 defines Analysis as the **examination of the
output of Examination for significance and probative value**, using
legally justifiable methods and techniques to derive useful
information. This is where correlation and attribution happen.

| NIST §3.3 requirement | Deep View capability | Module |
|-----------------------|----------------------|--------|
| Correlate across data sources | `EventBus` + `EventClassifier` match cross-subsystem events against YAML rulesets | `src/deepview/classification/{classifier,ruleset}.py` |
| Timeline reconstruction | `reporting/timeline.py` collates events into a chronological view, supports filtering by artifact category | `src/deepview/reporting/timeline.py` |
| Attribution to ATT&CK | Built-in classifier rules tag events with `attack_ids` (see [ATT&CK mapping](attack-mapping.md)) | `src/deepview/classification/builtin_rules/*.yaml` |
| Anomaly detection | `detection/anomaly.py::AnomalyDetector.score_process` with windowed feature extraction | `src/deepview/detection/anomaly.py` |
| Rootkit / injection detection | `detection/{antiforensics,injection,encryption_keys}.py` emit typed events | `src/deepview/detection/*.py` |
| Legally justifiable methods | Every detection module documents its algorithm in its module docstring; open source — reviewable by opposing counsel's expert | `src/deepview/detection/*.py` |
| Reproducibility | Replay subsystem (`SessionReplayer`) re-publishes stored events; replayed analysis is byte-identical to live | `src/deepview/replay/replayer.py` |

## Section 3.4 — Reporting

NIST SP 800-86 §3.4 requires the production of a report that
**describes the actions, explains the tools used, recommends
improvements, and is tailored to the audience**. The report should
include methodology, findings, and supporting artifacts.

| NIST §3.4 requirement | Deep View capability | Module |
|-----------------------|----------------------|--------|
| Narrate actions taken | Session store contains every emitted event in order; `deepview report generate` walks the store | `src/deepview/reporting/engine.py` |
| Explain tools used | Report header includes Deep View version, platform, list of plugins invoked, list of optional deps loaded | `src/deepview/reporting/engine.py::_render_header` |
| HTML / Markdown / JSON output | `reporting/export.py` supports all three formats from the same `ReportModel` | `src/deepview/reporting/export.py` |
| Map to ATT&CK | Navigator layer export (`.json`) compatible with [attack-navigator](https://mitre-attack.github.io/attack-navigator/) | `src/deepview/reporting/export.py::export_attack_layer` |
| STIX bundle output | 2.1 bundle export via `reporting/export.py::export_stix_bundle` | See [STIX output](stix-output.md) |
| Tailor to audience | Three built-in templates: `executive`, `analyst`, `technical`; custom Jinja templates supported | `src/deepview/reporting/templates/` |
| Preserve findings | Generated reports are hashed on write; hash is captured in the session store as a `ReportGeneratedEvent` | `src/deepview/reporting/engine.py` |

## Section 4: Files

NIST SP 800-86 §4 describes file-layer acquisition and analysis.

| NIST §4 topic | Deep View equivalent |
|---------------|----------------------|
| §4.1 Basics (metadata, timestamps, attributes) | `inspect/file.py::FileInspector` — captures mtime, atime, ctime, mode, xattrs |
| §4.2 Collection (copies, hashing) | `DataLayer` over file path; SHA-256 during read |
| §4.3 Examination (carving, signature analysis) | `scanning/string_carver.py`, file-type heuristics |
| §4.4 Analysis | `detection/*.py` modules consume file-layer output |

## Section 5: Operating Systems

NIST SP 800-86 §5 covers OS-level artifacts. Deep View's OS coverage:

- **Linux** — full: eBPF tracing, procfs live inspection, kallsyms,
  netlink, fanotify, audit framework integration.
- **macOS** — moderate: DTrace provider, OSXPMem acquisition, Frida
  instrumentation.
- **Windows** — moderate: ETW provider, WinPMem, crash dump / hibernation
  file parsers.

| NIST §5 topic | Deep View module |
|---------------|------------------|
| §5.1 Basics (OS data categories) | `core/context.py::PlatformInfo` |
| §5.2 Collection (non-volatile OS data) | `memory/formats/{raw,lime_format,elf_core,crashdump,hibernation}.py` |
| §5.3 Examination (registry, logs, configs) | Volatility 3 plugins dispatched via `memory/analysis/volatility.py` |
| §5.4 Analysis | `detection/*.py` + classifier rulesets |

## Section 6: Network Traffic

NIST SP 800-86 §6 addresses network-traffic forensics.

| NIST §6 topic | Deep View module |
|---------------|------------------|
| §6.1 Basics (TCP/IP, NIDS data) | `networking/parser.py` stdlib IPv4/6 + TCP/UDP/ICMP |
| §6.2 Collection (packet capture) | `networking/nfqueue_source.py` (live); `memory/network/tcp_reconstruct.py` (from memory image) |
| §6.3 Examination | `inspect/net.py::NetInspector` |
| §6.4 Analysis | Classifier + anomaly detection |

Live packet mangling (`deepview netmangle`) is an **active** capability
and explicitly **outside the scope of NIST SP 800-86** — it modifies
evidence rather than preserving it. Use it only in the authorised
scenarios documented in the [dual-use statement](../security/dual-use-statement.md).

## Section 7: Applications

NIST SP 800-86 §7 covers application-layer forensics. Deep View's
application layer support is plugin-based — third parties can ship
application-specific parsers via the `deepview.plugins` entry point.

## Appendix A: Evidence retention

Deep View does not delete acquired evidence. Retention is the
operator's responsibility. The session store (SQLite + WAL) is
designed for append-only write patterns; exports (JSON, HTML,
Markdown, STIX) are intended as the long-term archive.

Retention recommendations (operator-configurable, not tool-enforced):

| Artifact | Recommended retention |
|----------|----------------------|
| Raw acquisition image | Case duration + statute-of-limitations period |
| Session store (SQLite) | Same as the image — custody log must outlive the image |
| Structlog audit log | 12 months minimum for tool-level audit evidence |
| Generated reports | Case duration; re-generation from the session is cheap |

## Appendix B: Tool validation (§3.2)

NIST SP 800-86 §3.2 briefly discusses tool testing. Deep View's
validation posture:

- **Unit tests** (`tests/unit/`) cover each plugin's output against
  golden-master fixtures — output hash assertions guarantee
  regression-free behaviour across releases.
- **Integration tests** (`tests/integration/`) acquire known-good
  test images and verify that Volatility 3, MemProcFS, YARA, and the
  detection modules produce expected findings.
- **Platform tests** (`tests/platform/`) run under real OS kernels
  via CI matrices (Linux, macOS, Windows).
- **Optional-dep tests** are gated by pytest markers (`requires_ghidra`,
  `requires_hopper`, `requires_root`, `integration`).

The test matrix is the primary artifact an auditor should inspect to
form a view of tool reliability. The publicly-released changelog
documents behavioural deltas between versions.

## Appendix C: Terminology alignment

NIST SP 800-86 uses specific terms that do not map 1:1 onto Deep
View's internal vocabulary. The rosetta stone:

| NIST term | Deep View term | Note |
|-----------|----------------|------|
| Media | Evidence source | A block device, a memory image, a capture file |
| Image | Acquisition output | What `AcquisitionResult.path` points at |
| Original evidence | Source | Deep View never mutates the source |
| Best evidence | Acquisition + hash | The `AcquisitionResult` pair satisfies "best evidence" |
| Hash function | SHA-256 (and optionally SHA-512) | MD5 and SHA-1 are *not* produced by Deep View for integrity — they are produced only for IoC-matching against existing threat feeds |
| Chain of custody | Session store + structlog audit log | Combined they cover the full custody timeline |
| Examiner | Operator | Operator identity captured via `DEEPVIEW_OPERATOR` env |
| Investigation | Session | One session per investigation (or more granularly, per acquisition + analysis run) |

## Appendix D: Workflow example

A worked example that walks through NIST SP 800-86 §3 with concrete
Deep View CLI invocations:

```bash
# §3.1 Collection — acquire memory from a live Linux host
export DEEPVIEW_OPERATOR="jdoe"
deepview session start --case CASE-2026-0414 --evidence-id E001
deepview memory acquire \
    --provider lime \
    --out /evidence/E001/mem.lime \
    --strong-hash

# §3.2 Examination — index with Volatility 3 and YARA
deepview memory plugins pslist --image /evidence/E001/mem.lime
deepview scan yara --rules /opt/yara/apt.yar /evidence/E001/mem.lime

# §3.3 Analysis — run detection modules and correlate
deepview detect injection --image /evidence/E001/mem.lime
deepview detect rootkit --image /evidence/E001/mem.lime

# §3.4 Reporting — export in multiple formats for distinct audiences
deepview report generate --format html --template executive \
    --out /reports/E001-exec.html
deepview report generate --format html --template technical \
    --out /reports/E001-tech.html
deepview report generate --format stix --out /reports/E001.stix.json
deepview report generate --format attack-navigator \
    --out /reports/E001-attack.json

# Close the session and archive it
deepview session close
deepview session export --out /archive/CASE-2026-0414.tar.gz
```

Every step emits structlog records that form the §3.1.3 audit trail.
The `deepview session export` bundle is what you retain per Appendix A.

## See also

- [Evidence integrity](evidence-integrity.md) — hash propagation and
  the audit trail story.
- [ISO 27037](iso-27037.md) — complementary international guideline
  with a finer-grained process model (identification → collection →
  acquisition → preservation).
- [ATT&CK mapping](attack-mapping.md) — how §3.3 analysis findings
  are tagged with technique IDs.
- [STIX output](stix-output.md) — how §3.4 reports serialise to the
  STIX 2.1 threat-intelligence bundle format.

