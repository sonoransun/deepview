# Deployment

This section collects the deployment recipes we maintain for running
Deep View outside of an investigator's laptop: containers, cluster
jobs, CI pipelines, air-gapped labs, and shared forensic workstations.
Each page is tested against the extras declared in
[`pyproject.toml`][extras-ref] and the optional-dep fallbacks documented
in the [CLI reference][cli-ref].

[extras-ref]: ../reference/extras.md
[cli-ref]: ../reference/cli.md

!!! warning "Dual-use capabilities travel with the image"
    Every deployment target below inherits Deep View's live-capture
    primitives — eBPF, NFQUEUE, DMA, Frida injection. Before shipping
    any image or manifest beyond an authorised lab, re-read
    [operator OPSEC](../security/opsec.md) and the
    [dual-use statement](../security/dual-use-statement.md). A locked
    container running as root is still a forensics toolkit.

## Recipes at a glance

| Target | When to use | Privileges | Evidence mode | Page |
| --- | --- | --- | --- | --- |
| Docker | Reproducible local runs, CI stages, triage VMs | Varies — `--privileged` only for DMA / eBPF | Read-only bind mount | [docker.md](docker.md) |
| Kubernetes Job | Batch analysis of many images, CI fleets, shared cluster capacity | `runAsNonRoot: true` by default | PVC mounts (ROX evidence, RWX reports) | [kubernetes.md](kubernetes.md) |
| CI/CD | Plugin regression tests, `doctor` gate on pull requests | Unprivileged | No live evidence — synthetic fixtures only | [ci-cd.md](ci-cd.md) |
| Isolated lab | Air-gapped casework, classified engagements | Root on acquisition host | WORM-backed | [isolated-lab.md](isolated-lab.md) |
| SANS SIFT | Slot Deep View alongside Volatility/TSK on an analyst workstation | Unprivileged for analysis, sudo for acquisition | SIFT case tree | [sift-workstation.md](sift-workstation.md) |

## Choosing a target

!!! tip "Decision tree"
    - Need **reproducibility** and **disposable** runs → Docker.
    - Need to fan analysis over **many evidence images at once** → Kubernetes.
    - Need a **PR gate** that stops broken plugins from merging → CI/CD.
    - Need to run in a **SCIF / air-gapped lab** → isolated-lab.
    - Sitting at a **SANS SIFT VM** already → SIFT workstation.

## Common conventions

All recipes on this page share a small number of conventions so that
the `deepview` CLI behaves identically regardless of target:

- **`/evidence`** is the read-only mount for acquired images and
  raw artefacts. Never write into it.
- **`/reports`** is the writable mount for reports, sessions
  (`replay/*.sqlite`), and exports.
- **`/etc/deepview/config.toml`** is the primary config file, loaded via
  `DEEPVIEW_CONFIG` or the default `$XDG_CONFIG_HOME/deepview` lookup.
- **UID/GID `1000:1000`** is the default unprivileged user. Override
  via build arguments when your host uses a different convention.
- **Session outputs are immutable** — never rewrite a replay SQLite
  file in place; emit a new one per run.

## Related reading

- [Operator OPSEC](../security/opsec.md) — what "evidence-grade"
  actually means, including hashing, chain of custody, and the
  `--authorization-statement` flag.
- [Performance](../performance/index.md) — memory and CPU profiles
  for the heavy operations (ECC decode, container unlock, offload).
- [Reference: optional extras](../reference/extras.md) — the mapping
  from extras group to runtime capability, used to decide which
  extras your image needs.
