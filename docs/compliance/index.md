# Compliance and Standards Mapping

Deep View is a forensics and runtime-analysis toolkit. It does **not**
certify any compliance regime, does **not** produce auditor-ready
attestations, and cannot substitute for a QMS review by a qualified
assessor. What it *does* ship is a set of capabilities that map
cleanly onto the control objectives, procedural phases, and evidentiary
requirements that the major digital-forensics standards describe.

This section documents those mappings so that an organisation
integrating Deep View into an existing incident-response or
forensic-readiness programme can point its auditor at the feature that
satisfies a given clause. Consult your auditor for compliance
assertions.

!!! warning "Operational mapping, not a compliance certification"
    Every page in this section describes what Deep View *can* be used
    to do in service of a standard — not what Deep View *is certified*
    to do. A capability mapping is not an audit report. If you need
    an attestation (ISO 17025 lab accreditation, NIST-compliant chain
    of custody, GDPR Article 32 assessment), engage a qualified
    third-party assessor and use the relevant Deep View feature as
    evidence, not as a replacement.

## What's in this section

<div class="grid cards" markdown>

-   :material-file-document-outline:{ .lg .middle } **NIST SP 800-86**

    ---

    Phase-by-phase mapping of the NIST *Guide to Integrating Forensic
    Techniques into Incident Response* (Collection, Examination,
    Analysis, Reporting) to specific Deep View subsystems.

    [:octicons-arrow-right-24: NIST SP 800-86](nist-sp-800-86.md)

-   :material-certificate-outline:{ .lg .middle } **ISO/IEC 27037:2012**

    ---

    The four ISO 27037 evidence-handling principles — auditability,
    repeatability, reproducibility, justifiability — mapped to
    `AnalysisContext`, `EventBus`, the replay subsystem, and hash
    propagation through `AcquisitionResult`.

    [:octicons-arrow-right-24: ISO 27037](iso-27037.md)

-   :material-target:{ .lg .middle } **MITRE ATT&CK**

    ---

    Per-technique table: DKOM, SSDT hook, IDT/IRP hook, inline hook,
    hidden driver, DLL injection, PE injection, thread hijacking,
    process hollowing, PEB masquerading — each with its ATT&CK ID, the
    Deep View detector module, and the event schema.

    [:octicons-arrow-right-24: ATT&CK mapping](attack-mapping.md)

-   :material-graph-outline:{ .lg .middle } **STIX 2.1 output**

    ---

    Mapping of Deep View findings (Indicator, Sighting, Malware,
    AttackPattern, Identity) to STIX 2.1 object types, field-level
    schema from the `reporting/` subsystem, TAXII ingestion notes.

    [:octicons-arrow-right-24: STIX output](stix-output.md)

-   :material-shield-check-outline:{ .lg .middle } **Evidence integrity**

    ---

    Hash propagation (`AcquisitionResult.hash_sha256`), the read-only
    `DataLayer.read` contract, the structlog audit trail, and
    recommended write-blocker / immutable-storage workflows.

    [:octicons-arrow-right-24: Evidence integrity](evidence-integrity.md)

-   :material-account-lock-outline:{ .lg .middle } **GDPR and PII**

    ---

    Deep View extracts PII from memory and disk without filtering.
    Redaction is the operator's responsibility — default output is
    verbatim. Recommended post-processing workflow and GDPR
    Article 32 considerations.

    [:octicons-arrow-right-24: GDPR and PII](gdpr-and-pii.md)

</div>

## What is **not** in this section

This documentation set does **not** cover:

- **SOC 2 / ISO 27001 controls for Deep View itself as a SaaS.** Deep
  View is a local CLI, not a service — it has no tenant isolation,
  uptime SLO, or access-review programme, because those concepts do
  not apply.
- **Accreditation of a specific laboratory.** ISO 17025 accreditation
  is a property of the lab and its procedures, not of the tool.
- **Legal admissibility in a specific jurisdiction.** Admissibility
  depends on jurisdiction-specific rules of evidence. The mappings
  here describe *technical* alignment with widely-referenced standards.

If your question is "is this artifact admissible in court?", the
answer is: ask your counsel, not this documentation.

## How to use these pages

1. Identify the standard your programme references (NIST SP 800-86,
   ISO 27037, ATT&CK, STIX).
2. Read the relevant mapping page to see which Deep View subsystem
   produces the artifact that satisfies the clause.
3. Cross-reference the linked module under `src/deepview/` to see the
   exact implementation and its limitations.
4. Retain the operational evidence (structlog trace, session store,
   generated report) as your audit artifact.

Deep View ships capabilities. Your programme documents process.
Together they produce an audit trail.
