# Deep View vs Autopsy / The Sleuth Kit

!!! abstract "Deep View overlaps with Autopsy on filesystem analysis but is programmatic-first."
    Autopsy is the canonical GUI-driven digital-forensics workbench. Deep View touches the same
    filesystem surfaces through the same underlying library — The Sleuth Kit — but drives it from
    Python, the CLI, and plugin code rather than from a case-management GUI. The two tools are
    complementary; neither replaces the other.

If you're already running a case through Autopsy, Deep View is most useful either as a
scripted pre-stage (triage, bulk extraction, IoC sweeps) or a post-stage (feeding Autopsy-exported
artifacts into the EventBus for classification and reporting).

## One-paragraph recap of Autopsy and TSK

**The Sleuth Kit (TSK)** is a C library and set of command-line tools by Brian Carrier for
reading filesystems forensically — FAT, NTFS, ext2/3/4, HFS+, APFS, Ext-based LVM/RAID via
upstream helpers, and more. It exposes filesystem metadata, unallocated space, deleted files,
and timeline data without mounting the image.

**Autopsy** is the GUI on top of TSK. It adds case management, modular ingest pipelines (keyword
search, EXIF, hash lookup, web artifacts, email parsing, PhotoRec integration, plaso timeliner),
report templates, a Java-based extension point system, and a collaborative multi-user mode.

Autopsy is the authoritative end-to-end workbench for disk forensics. Deep View does not try to
be that.

## Where Deep View overlaps

- **Filesystem parsing.** Deep View uses TSK bindings (via `pytsk3` when available) to enumerate
  files, read metadata, and reach deleted / unallocated content. The same C library that powers
  Autopsy's *File System Content* view powers Deep View's filesystem layer.
- **Timeline generation.** Both tools produce MACB timelines — Autopsy through its timeline
  viewer, Deep View through `reporting/timeline.py`.
- **Hash lookup & keyword scanning.** Both can run a hash database and string/regex sweeps;
  Deep View additionally wires results onto the `EventBus` for classification.
- **Artifact extraction.** Both pull out user-level artifacts (browser history, registry hives
  on Windows images, shell histories on Linux) — Deep View via plugin code under
  `memory/` and `scanning/`, Autopsy via its Java ingest modules.

## Where Deep View does not overlap

- **No GUI case management.** Deep View has no Autopsy-style case browser, no multi-user
  concurrent editing, no keyword-index viewer, no drag-and-drop tagging. If the analyst
  workflow is GUI-centric, Autopsy wins.
- **No Autopsy module ecosystem.** Third-party Autopsy ingest modules (Java or Python via
  Jython) are not reachable from Deep View. Porting one means rewriting it as a
  `DeepViewPlugin`.
- **No keyword indexer.** Autopsy bundles Solr for full-text indexing; Deep View does not.
  For bulk keyword work, Autopsy or Elasticsearch stays the right answer.
- **Commercial-feature parity.** Autopsy-commercial add-ons (Basis Technology's Cyber Triage,
  etc.) are outside our scope.

## GUI vs CLI / Python: the real axis

This is the most important distinction:

| Dimension | Autopsy | Deep View |
| --- | --- | --- |
| Primary interface | Java Swing GUI | Click CLI + Python API |
| Extension language | Java, Jython ingest modules | Python plugins (`DeepViewPlugin`) |
| Persistence | Case directory (SQLite + flat files) | `AnalysisContext` + optional session store (`replay/`) |
| Concurrency | Multi-user collaborative mode | Single-host, programmatic |
| Reporting | HTML / Excel / PDF templates | HTML / Markdown / JSON / STIX / ATT&CK Navigator |
| Scripting hooks | Report modules, ingest modules | Any plugin stage, any event subscription |

If your workflow fits a GUI — interactive triage, tagging, keyword-driven drilldown — Autopsy is
built for that. If your workflow fits a script — "run these ten scans on these fifty images
overnight and send me a report" — Deep View is built for that.

## When to use Autopsy

- You want a GUI-first case-management experience.
- You're collaborating with analysts on the same case at the same time.
- You need Solr-backed full-text keyword search.
- You depend on an existing Autopsy module (EXIF, PhotoRec integration, commercial modules).
- Your deliverable is a human-readable case report that follows Autopsy's template structure.

## When to use Deep View

- You want filesystem analysis to plug into a larger automated pipeline that also does memory,
  tracing, instrumentation, or reporting.
- You want to express "run these checks" as Python plugins under version control, not as
  clicks through a GUI.
- You want filesystem findings to co-exist on the same `EventBus` as live tracing events or
  memory analysis results.
- You need outputs in STIX 2.1 or ATT&CK Navigator layer format without a separate conversion.

## How to combine them

Two patterns work well:

### Pattern 1: Deep View triages, Autopsy deep-dives

Run Deep View against a fleet of disk images to triage them — hash matching, IoC sweeps,
quick timeline generation. For the subset that warrants manual analysis, open the image in
Autopsy and continue with its GUI-driven workflow. Deep View's JSON and STIX exports can pre-
populate an Autopsy case's tags.

### Pattern 2: Autopsy exports, Deep View classifies

Let analysts drive the Autopsy GUI as usual. When they export artifacts (files, bookmarks,
tagged items), a Deep View plugin can ingest those exports, publish them onto the `EventBus`,
and run the classification ruleset (including the same YARA / Sigma rules used for live
monitoring) over them. The outputs feed a unified report.

## TSK version compatibility

- Deep View's filesystem layer relies on `pytsk3`, which is a thin wrapper around libtsk.
- The underlying TSK version is the same as the one Autopsy ships — they track upstream
  together. If a filesystem is readable in one, it is generally readable in the other.
- New filesystem support (e.g., a future FS that requires a new TSK minor version) arrives in
  both tools as upstream TSK updates.

## Honest limitations

- Deep View's filesystem module is **not** a full replacement for Autopsy's ingest pipeline.
  Autopsy has had a decade of attention from practitioners; our coverage is narrower.
- We do not implement an Autopsy case file reader. Round-tripping through JSON is the right
  integration path, not binary case compatibility.
- Complex disk layouts (encrypted containers within LVM within RAID) may still require manual
  assembly outside Deep View before the filesystem layer can see them.

!!! tip "Use the right tool for the interface"
    The interface — GUI versus programmatic — is a better selector than the feature list.
    If an analyst is going to click through results, Autopsy. If code is going to consume
    results, Deep View. Most real investigations want both, wired together.

## Further reading

- [Architecture: storage & layers](../architecture/storage.md)
- [Architecture: remote acquisition](../architecture/remote-acquisition.md)
- [Autopsy upstream](https://www.autopsy.com/)
- [The Sleuth Kit upstream](https://www.sleuthkit.org/)
