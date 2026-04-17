# Operator handbook

> Field guide for forensic investigators, incident responders, and security researchers running Deep View in live engagements.

This handbook is the counterpart to the [reference](../reference/index.md) and [guides](../guides/storage-image-walkthrough.md). Where those pages explain *what* Deep View does, the handbook explains *how to run an engagement* with it — the phases, the paperwork, the evidence discipline, and the hand-off artefacts.

!!! warning "Operational guidance — not legal advice"
    Everything in this handbook is field practice distilled from real engagements. It is **not** a substitute for legal counsel, jurisdiction-specific evidence rules, or your organisation's incident response policy. Consult counsel before relying on any template here in court or regulatory proceedings.

## Audience

This handbook assumes you already know Deep View's command surface from the [CLI reference](../reference/cli.md) and now need to:

- Run an end-to-end incident from triage to post-mortem.
- Produce evidence that will survive cross-examination.
- Hand off to peer responders, leadership, or legal without losing fidelity.

If you are brand new to Deep View, start with the [quick-start](../index.md#installation) and the [architecture overview](../overview/architecture.md); come back here once you have a working `deepview doctor` output.

## Pages in this handbook

<div class="grid cards" markdown>

-   :material-clipboard-pulse:{ .lg .middle } **Incident response runbook**

    ---

    NIST-aligned IR playbook (Preparation → Lessons Learned) mapped to Deep View commands.

    [:octicons-arrow-right-24: Runbook](incident-response-runbook.md)

-   :material-seal:{ .lg .middle } **Chain of custody**

    ---

    SHA-256 acquisition hashes, structlog WORM logging, signed manifests.

    [:octicons-arrow-right-24: Custody](chain-of-custody.md)

-   :material-file-document-multiple:{ .lg .middle } **Reporting templates**

    ---

    Executive summary, technical report, court-ready report.

    [:octicons-arrow-right-24: Templates](reporting-templates.md)

-   :material-archive-lock:{ .lg .middle } **Evidence handling**

    ---

    Volatility order, write-protection, air-gapped analysis, at-rest encryption.

    [:octicons-arrow-right-24: Handling](evidence-handling.md)

-   :material-gavel:{ .lg .middle } **Witness statement template**

    ---

    Copy-pasteable markdown for affidavits and expert declarations.

    [:octicons-arrow-right-24: Template](witness-statement-template.md)

-   :material-checkbox-multiple-marked:{ .lg .middle } **Debrief checklist**

    ---

    Post-engagement close-out — hashes, storage, lessons learned.

    [:octicons-arrow-right-24: Checklist](debrief-checklist.md)

</div>

## How the handbook cross-links

- **Threat model** — the risks this toolkit mitigates and the ones it does not are in [threat-model.md](../security/threat-model.md). Read it before you deploy.
- **OPSEC** — how to run Deep View without tipping off an adversary on the wire or the host is in [opsec.md](../security/opsec.md). Every IR phase below references OPSEC where applicable.
- **Dual-use statement** — [dual-use-statement.md](../security/dual-use-statement.md) scopes `deepview netmangle` and `deepview instrumentation` to authorised engagements only. If the current engagement does not satisfy those preconditions, stop and escalate.

## Versioning

Every page cites the Deep View version it was last validated against. The witness-statement template in particular must name the exact `deepview --version` output plus every installed extra — the [reporting-templates](reporting-templates.md) page shows how to capture that reproducibly.
