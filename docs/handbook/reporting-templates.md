# Reporting templates

> Three audiences, three reports, one evidence set. This page shows how to lift Deep View output into each report and what to redact.

!!! warning "Operational guidance — not legal advice"
    Court-ready reports must be reviewed by counsel before disclosure. These templates are technical starting points, not legal instruments.

Deep View's `reporting` subsystem (`src/deepview/reporting/`) can emit HTML, Markdown, JSON, STIX 2.1, and ATT&CK Navigator layers. The templates below describe how to structure the *human-written* narrative around those machine-generated artefacts.

---

## Template 1: Executive summary

**Audience:** leadership, executive sponsors, board-level stakeholders. **Length:** one page. **Tone:** plain language, quantified risk, action-oriented.

### Sections

1. **Incident identifier** — engagement ID, date, responder lead.
2. **One-sentence summary** — "On 2026-04-14, an unauthorised actor accessed host01 and exfiltrated approximately 2.4 GB of internal documents before being contained."
3. **Business impact** — affected systems, affected data categories, regulatory triggers (GDPR, HIPAA, SOX, etc.).
4. **Containment status** — contained / ongoing / recovery.
5. **Top three findings** — bullet list, one line each.
6. **Recommended decisions** — three to five, each with owner and deadline.
7. **Where the full report lives** — pointer to the technical report and the evidence package.

### What to lift verbatim from Deep View

- **Nothing.** The executive summary is a written narrative. Hex dumps, raw event JSON, stack traces belong in the technical report, not here.
- Exception: the ATT&CK tag list, if leadership is ATT&CK-literate. One line, e.g. "Observed TTPs: T1055.012, T1071.001, T1041".

### What to redact

- Specific usernames, unless already public.
- Specific IP addresses, unless legally required.
- Anything under legal privilege until counsel clears it.

### Copy-pasteable skeleton

> # Incident IR-2026-0414-01 — Executive Summary
>
> **Date:** 2026-04-14    **Lead:** J. Doe    **Status:** Contained
>
> On 2026-04-14 at 10:42 UTC an unauthorised actor executed code on a
> production database host and began staging files for exfiltration.
> Deep View live monitoring flagged the activity within 7 minutes; the
> actor was contained before data left the network perimeter.
>
> ## Business impact
> - One host offline for 4 hours during forensic imaging.
> - No confirmed data exfiltration; one false-positive regulatory
>   trigger reviewed and cleared by counsel.
>
> ## Top findings
> - Initial access via a re-used SSH key from a former contractor.
> - Lateral movement attempted but blocked by network segmentation.
> - A persistence mechanism (cron-based) was installed and removed.
>
> ## Recommended decisions
> 1. Rotate all SSH keys issued before 2025-01-01.             (CISO, 7d)
> 2. Mandate MFA for bastion access.                           (IT, 30d)
> 3. Expand Deep View live-monitoring coverage to all DB hosts.(SOC, 14d)
>
> Full technical report: evidence-package/IR-2026-0414-01/technical.html

---

## Template 2: Technical report

**Audience:** peer responders, SOC analysts, threat-intel consumers. **Length:** as long as it needs to be. **Tone:** precise, timestamped, reproducible.

### Sections

1. **Cover page** — engagement ID, responder team, Deep View version, extras installed, date range.
2. **Methodology** — tools used, acquisition methods, analysis environment. Reference [evidence-handling.md](evidence-handling.md).
3. **Scope and constraints** — what was in and out of scope, authorisation boundaries.
4. **Timeline** — lifted verbatim from `deepview report --format html --template technical`.
5. **Findings** — one subsection per finding, each with evidence pointers.
6. **Indicators of compromise (IoCs)** — IP/domain/hash/filename lists.
7. **ATT&CK matrix** — lifted from the Navigator layer JSON.
8. **Root cause analysis** — how the incident started and what would have prevented it.
9. **Appendix A — evidence manifest** — the signed SHA-256 manifest.
10. **Appendix B — session replay instructions** — so a reader can re-run the session.

### What to lift verbatim from Deep View

- **Timeline:** `deepview report --format html --template technical` produces a `timeline.py`-driven interactive timeline. Embed it.
- **IoC list:** output of `deepview plugins run scanning.ioc_engine` in JSON.
- **ATT&CK layer:** `deepview report --format attck` JSON — drop it into the MITRE Navigator directly and screenshot for the PDF.
- **STIX bundle:** `deepview report --format stix` — include as Appendix C for machine-readable hand-off.
- **Raw event extracts:** when a specific finding relies on a handful of events, include the JSON verbatim in a fenced code block. Do not paraphrase.

### What to redact

- Encryption keys, credentials, session tokens. Replace with `<redacted:key>` and record the redaction in the manifest.
- Personal data not relevant to the finding.
- Internal IP ranges if the report is shared outside the organisation — replace with `10.0.0.0/8-style` class markers.

### Copy-pasteable finding block

> ### Finding 3: persistence via cron
>
> **Severity:** High  **ATT&CK:** T1053.003 (Scheduled Task/Job: Cron)
>
> At 10:49:17 UTC the suspect process (PID 4123, `sh`) wrote a cron
> entry to `/etc/cron.d/.sys-update`. Deep View captured the write via
> eBPF tracing:
>
>     {
>       "ts": "2026-04-14T10:49:17.204Z",
>       "event": "openat",
>       "pid": 4123,
>       "path": "/etc/cron.d/.sys-update",
>       "flags": ["O_WRONLY", "O_CREAT"],
>       "classifications": {"attck": ["T1053.003"]}
>     }
>
> File hash after creation (acquired via `deepview inspect file`):
> `sha256:d41d...` (see evidence manifest entry 17).

---

## Template 3: Court-ready report

**Audience:** counsel, opposing counsel, judges, juries. **Length:** comprehensive but tightly scoped to the legal theory. **Tone:** factual, methodical, free of speculation.

!!! danger "Counsel review required"
    Do not disclose a court-ready report without counsel sign-off. This template is a starting structure; the final document must conform to jurisdictional rules of evidence and expert-witness protocols.

### Sections

1. **Expert identity and qualifications** — see [witness-statement-template.md](witness-statement-template.md).
2. **Engagement and instruction** — who retained the expert, scope of instruction, date of instruction.
3. **Methodology** — step-by-step, reproducible. Every command exactly as issued, with output captured to the manifest.
4. **Chain of custody** — copy of the signed manifest, hand-off log, counter-signatures. See [chain-of-custody.md](chain-of-custody.md).
5. **Factual findings** — one fact per numbered paragraph, each with an evidence reference.
6. **Opinions** — clearly labelled as opinion, separated from facts.
7. **Limitations** — what the analysis could not determine and why.
8. **Exhibits** — the actual Deep View outputs, labelled EX-A, EX-B, etc.
9. **Statement of truth** — jurisdiction-specific phrasing (e.g. CPR r.35 PD 3 in England; Rule 26 expert disclosure in US federal).
10. **Signature block** — see witness-statement template.

### What to lift verbatim from Deep View

- **Every command actually run**, with its full output, as an appendix. Redaction is allowed but must be marked and explained.
- **The signed SHA-256 manifest** in full.
- **The replay-verification output** (`deepview replay verify`) for each session file.
- **The timeline** as a PDF attachment — avoid interactive HTML unless the court accepts digital exhibits.
- **Any hex/raw data** that the court needs to inspect. Print it; do not describe it.

### What to redact

- Information legally required to be redacted (minors' names, protected-class data, privileged communications).
- Credentials, keys, tokens — always. Mark redactions as `<redacted:reason>` with the reason in the redaction log.
- Unrelated findings. A court-ready report must be tight to the matter.

### Opinion vs fact

The single most common cross-examination attack is "Expert, are you testifying to a fact or an opinion?" Structure the report so the answer is always obvious. Facts are timestamped, hashed, and manifest-referenced. Opinions are labelled "Opinion N:" and carry an explicit reasoning chain.

### Example statement of truth (England and Wales, illustrative)

> I confirm that I have made clear which facts and matters referred to
> in this report are within my own knowledge and which are not. Those
> that are within my own knowledge I confirm to be true. The opinions
> I have expressed represent my true and complete professional opinions
> on the matters to which they refer.
>
> Signed: ..........................................................
> Name:   J. Doe                                   Date: 2026-04-28

Adjust wording per jurisdiction with counsel.

---

## Cross-references

- [Incident response runbook](incident-response-runbook.md)
- [Chain of custody](chain-of-custody.md)
- [Witness statement template](witness-statement-template.md)
- [Evidence handling](evidence-handling.md)
- [Threat model](../security/threat-model.md)
- [OPSEC](../security/opsec.md)
