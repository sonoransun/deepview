# Witness statement template

> Copy-pasteable markdown skeleton for witness statements, expert declarations, and affidavits where Deep View output is cited. Fill in the blockquote sections and delete the guidance commentary.

!!! warning "Operational guidance — not legal advice"
    Witness statement wording is jurisdiction-specific. This template is a starting structure only. Counsel **must** review before filing, signing, or serving.

This template assumes a single expert giving evidence on Deep View-produced findings. For multi-expert or joint statements, adapt the qualifications and signature sections per counsel's direction.

---

## Template (copy from here)

> # Witness Statement of [Full Name]
>
> **Matter:** _[Case name / engagement identifier]_
> **Court / Tribunal:** _[Name, jurisdiction, claim number]_
> **Party on whose behalf:** _[Instructing party]_
> **Date of statement:** _[YYYY-MM-DD]_
>
> ## 1. Identity and qualifications
>
> 1.1 I am _[full name]_, of _[professional address]_.
>
> 1.2 My current role is _[title]_ with _[employer]_. I have held this role since _[date]_.
>
> 1.3 My relevant qualifications are:
>
> - _[Degree, institution, year]_
> - _[Professional certification, e.g. GCFA, GREM, OSCP, CISSP, CFCE]_
> - _[Years of practical experience in digital forensics / incident response]_
>
> 1.4 I am instructed in this matter as _[a fact witness / an expert witness]_. A full CV is attached as Exhibit **CV-1**.
>
> ## 2. Instruction and scope
>
> 2.1 I was instructed by _[instructing solicitor / counsel / in-house lead]_ on _[date]_ to _[summary of instruction]_.
>
> 2.2 The scope of my analysis is limited to:
>
> - _[Host(s) / image(s) / session(s) in scope]_
> - _[Time window]_
> - _[Specific questions I was asked to address]_
>
> 2.3 I confirm that my duty is to the court / tribunal and overrides any duty to the party instructing me _[if jurisdiction requires this declaration]_.
>
> ## 3. Tools used
>
> 3.1 The primary analytical toolkit used was **Deep View**, version `[output of deepview --version]`, a cross-platform forensics and runtime-analysis framework.
>
> 3.2 Deep View was installed with the following feature extras:
>
> - _[List from `pip show deepview` or `deepview doctor`, e.g. memory, instrumentation, linux_monitoring]_
>
> 3.3 The underlying Python interpreter was version `[python3 --version]` on `[platform from PlatformInfo.detect()]`.
>
> 3.4 Key supporting libraries, with versions as resolved at engagement time (full list attached as Exhibit **TL-1**):
>
> - volatility3 `[version]`
> - yara-python `[version]`
> - capstone `[version]`
> - lief `[version]`
> - frida `[version]`
> - bcc `[version]` / netfilterqueue `[version]` _(where applicable)_
>
> 3.5 The `deepview doctor` output at engagement start is attached as Exhibit **DR-1**. No missing mandatory dependencies or plugin collisions were reported.
>
> ## 4. Methodology
>
> 4.1 All acquisitions produced an `AcquisitionResult` with a streaming SHA-256 hash populated at write time. The hashes are recorded in the signed evidence manifest attached as Exhibit **MF-1**.
>
> 4.2 Live monitoring, where used, was performed via `deepview monitor` with the classification ruleset recorded in Exhibit **CR-1**. Events were captured into session file(s) recorded in Exhibit **SN-1**.
>
> 4.3 The session files are replayable via `deepview replay --session [file]`. I have verified their integrity using `deepview replay verify` — the verification output is attached as Exhibit **RV-1**.
>
> 4.4 Each analytical step, including the exact command line issued and the resulting output, is recorded in the engagement log attached as Exhibit **EL-1**. The log was written to WORM storage at the time of the step and has not been modified since.
>
> ## 5. Factual findings
>
> 5.1 _[One fact per numbered paragraph. Every fact has an evidence reference to an exhibit. No opinions in this section.]_
>
> 5.2 _[Example: "At 10:49:17.204 UTC on 2026-04-14, the process with PID 4123 (command name `sh`) wrote the file `/etc/cron.d/.sys-update`. This is recorded in event 2741 of session `host01.sqlite` (Exhibit **SN-1**)."]_
>
> 5.3 _[Continue. Err on the side of too many numbered facts, not too few — each is independently challengeable.]_
>
> ## 6. Opinions
>
> 6.1 _[Each opinion is clearly labelled and carries its own reasoning chain. Separate from facts above.]_
>
> 6.2 **Opinion 1:** _[e.g. "The cron entry described in paragraph 5.2 is consistent with a persistence mechanism of the type catalogued as MITRE ATT&CK T1053.003 because …"]_
>
> 6.3 **Opinion 2:** _[…]_
>
> ## 7. Limitations
>
> 7.1 _[What the analysis could not determine and why — e.g. "No disk image was acquired from host02; my findings do not extend to host02."]_
>
> 7.2 _[Known limitations of the tools used — e.g. "The eBPF tracing provider drops events on overflow; per the `TraceEventBus` contract, any dropped events are counted but not recoverable. The drop counters for the session are recorded in Exhibit **SN-1** and were zero."]_
>
> ## 8. Statement of truth / affirmation
>
> _[Jurisdiction-specific wording — consult counsel. Examples below are illustrative only.]_
>
> **England and Wales (CPR):** I believe that the facts stated in this witness statement are true. I understand that proceedings for contempt of court may be brought against anyone who makes, or causes to be made, a false statement in a document verified by a statement of truth without an honest belief in its truth.
>
> **US federal (28 USC s.1746):** I declare under penalty of perjury that the foregoing is true and correct.
>
> ## 9. Signature
>
> Signed: ..........................................................
>
> Name:   _[Full name]_
>
> Date:   _[YYYY-MM-DD]_
>
> Place:  _[City, country]_
>
> ---
>
> ## Exhibit list
>
> - **CV-1** — Curriculum vitae
> - **DR-1** — `deepview doctor` output at engagement start
> - **TL-1** — Tool and library version manifest
> - **MF-1** — Signed SHA-256 evidence manifest
> - **CR-1** — Classification ruleset
> - **SN-1** — Session file(s) and replay-verification output
> - **RV-1** — `deepview replay verify` output
> - **EL-1** — Engagement log (WORM-stored)

---

## How to fill it in

1. Start from the [reporting-templates.md](reporting-templates.md) court-ready report — the witness statement draws on the same facts, manifests, and exhibits.
2. Capture `deepview --version`, `pip show deepview`, and `deepview doctor` at engagement **start**, not at statement-writing time. Those are the exhibits that anchor your methodology.
3. Every fact cites an exhibit. Every opinion labels itself as opinion.
4. Send a draft to counsel before signing. Always.

## Cross-references

- [Incident response runbook](incident-response-runbook.md)
- [Chain of custody](chain-of-custody.md)
- [Reporting templates](reporting-templates.md)
- [Evidence handling](evidence-handling.md)
- [Threat model](../security/threat-model.md)
- [OPSEC](../security/opsec.md)
