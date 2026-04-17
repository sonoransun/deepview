# Security

Deep View is a forensics and runtime-analysis toolkit. By design it
handles secrets (passphrases, key material carved from memory),
privileged I/O (raw disks, `/proc/<pid>/mem`, DMA), and capabilities
that are dual-use against any system (network mangling, container
unlock, remote acquisition). This section collects the security
posture of the toolkit itself: what we protect, how we reason about
threats, and how an operator should behave in the field.

!!! danger "If you have found a vulnerability in Deep View"
    **Do not** open a public GitHub issue. Follow the coordinated
    disclosure process documented in the repository-root
    [`SECURITY.md`](https://github.com/example/deepview/blob/main/SECURITY.md)
    file. That document is the authoritative contact channel and
    describes our PGP key, response SLA, and embargo policy.

## What's in this section

<div class="grid cards" markdown>

-   :material-shield-search:{ .lg .middle } **Threat model**

    ---

    STRIDE-style enumeration of the threats the toolkit is designed to
    resist and those it explicitly does not. Mitigation matrix maps
    each threat to the concrete control in the codebase.

    [:octicons-arrow-right-24: Threat model](threat-model.md)

-   :material-binoculars:{ .lg .middle } **Operator OPSEC**

    ---

    Field guidance for forensic investigators: acquisition order,
    hashing, chain of custody, handling recovered key material, and
    the authorisation boundaries around remote acquisition and
    network mangling.

    [:octicons-arrow-right-24: OPSEC](opsec.md)

-   :material-scale-balance:{ .lg .middle } **Dual-use statement**

    ---

    Plain-language statement of intended use, refused use cases, and
    what the MIT licence does and does not grant.

    [:octicons-arrow-right-24: Dual-use statement](dual-use-statement.md)

-   :material-lock-alert:{ .lg .middle } **Reporting a vulnerability**

    ---

    Coordinated disclosure process, contact channels, PGP key, and
    our embargo policy. This lives at the repository root so it is
    reachable from GitHub's security tab.

    [:octicons-arrow-right-24: SECURITY.md](https://github.com/example/deepview/blob/main/SECURITY.md)

</div>

## Who this section is for

- **Forensic operators** running Deep View against imaged evidence or
  live systems under authorisation. Start with
  [OPSEC](opsec.md).
- **Security engineers** evaluating Deep View for inclusion in a
  tooling stack. Start with the [Threat model](threat-model.md) and
  the [Dual-use statement](dual-use-statement.md).
- **Contributors** adding new subsystems or new optional extras. The
  [Threat model](threat-model.md) enumerates the invariants a new
  subsystem is expected to preserve — bounded queues, lazy imports,
  config file validation, hash propagation on acquired artefacts.

## Cross-references

- [Remote acquisition architecture](../architecture/remote-acquisition.md)
  — documents the CLI safety gates (`--enable-dma`, `--confirm`,
  `--authorization-statement`, 5-second banner) that the OPSEC and
  dual-use pages refer back to.
- [Plugin discovery](../overview/plugin-discovery.md) — explains why
  third-party plugin directories are scanned but symlinks are refused,
  which is part of the threat model.
- [Architecture overview](../overview/architecture.md) — describes
  the `AnalysisContext`, `EventBus`, and `TraceEventBus` drop-on-
  overflow contracts referenced throughout the threat model.
