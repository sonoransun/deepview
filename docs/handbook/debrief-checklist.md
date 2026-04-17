# Debrief checklist

> Post-engagement close-out. Tick every box before the engagement folder is archived and the responders stand down.

!!! warning "Operational guidance — not legal advice"
    A completed checklist does not, on its own, discharge legal, regulatory, or contractual obligations. Confirm close-out with counsel and compliance before final archival.

Run this checklist at the post-incident review meeting, with the incident lead and a peer witness present. Each box is a formal sign-off; do not tick unless the evidence supports it.

---

## 1. Integrity and custody

- [ ] **All SHA-256 hashes re-verified** against the signed manifest. Any mismatch raised, logged, and (if material) escalated to counsel.
- [ ] **Manifest signatures valid.** Every `.asc` counter-signature on the evidence manifest is verified against the responder's published key.
- [ ] **RFC 3161 timestamp tokens verified** (`openssl ts -verify`) for every timestamped manifest.
- [ ] **Chain-of-custody log complete.** Every hand-off from acquisition to current custody has an entry with who, when, and why. See [chain-of-custody.md](chain-of-custody.md).
- [ ] **No unresolved custody breaks.** If there are any, they are documented and counsel has signed off on how they are being handled.

## 2. Evidence storage

- [ ] **Evidence package encrypted at rest** with the engagement-specific key. See [evidence-handling.md](evidence-handling.md).
- [ ] **WORM archive written.** The engagement folder — images, session files, findings, reports, manifests, logs — has been written to immutable storage.
- [ ] **Retention period logged** per the contractual or regulatory requirement for this engagement.
- [ ] **Physical media inventoried and secured.** Evidence drives in tamper-evident bags, locked in the dual-control safe.
- [ ] **Keys escrowed.** The evidence-decryption key is held by a second custodian with the required legal authority.

## 3. Reports and disclosure

- [ ] **Executive summary delivered** to the approved leadership distribution list. See [reporting-templates.md](reporting-templates.md).
- [ ] **Technical report delivered** to the peer-responder / SOC distribution list.
- [ ] **Court-ready report** drafted and reviewed by counsel (where applicable). If not applicable, explicitly logged as such.
- [ ] **Witness statement** drafted per [witness-statement-template.md](witness-statement-template.md) (where applicable).
- [ ] **STIX 2.1 bundle shared** with the SOC / threat-intel team for future detection reuse.
- [ ] **ATT&CK Navigator layer shared** and added to the organisation's cumulative adversary-behaviour layer.
- [ ] **Regulatory notifications sent** (GDPR 72-hour, HIPAA, SOX, sector-specific) where triggered, with timestamps recorded.

## 4. Containment and recovery close-out

- [ ] **All `deepview netmangle` rules removed.** If `--install-iptables` was used during the engagement, the NFQUEUE jump rules have been removed and the state file at `~/.cache/deepview/mangle_state.json` has been cleaned up. The installer's removal path produces a log line — archive it.
- [ ] **All Frida instrumentations detached.** No Deep View-initiated runtime hooks remain on any production host.
- [ ] **All tracing sessions stopped cleanly.** `deepview trace` / `deepview monitor` processes exited; no orphan eBPF programs remain attached. Verify with `bpftool prog list` on Linux.
- [ ] **Compromised credentials rotated.** Passwords, keys, API tokens, SSH keys identified as exposed have been rotated and the rotation is logged.
- [ ] **Host rebuild / reimage complete** where indicated by the eradication plan.
- [ ] **Persistence mechanisms removed** and a follow-up scan confirms re-infection has not occurred.

## 5. Session replay and knowledge capture

- [ ] **Session files archived** alongside the evidence package. `deepview replay verify` run on each and the verification output stored.
- [ ] **Lessons-learned meeting held** with responders, incident lead, and affected service owners.
- [ ] **Classification ruleset updated.** Any TTP the classifier missed is captured as a new YAML rule and submitted to the shared `classification/builtin_rules/` pack (or an org-internal rule set).
- [ ] **New rules validated by replay.** The updated ruleset has been replayed against the session file and the relevant events now carry the expected `classifications` tag.
- [ ] **Detection gaps logged** in the engineering backlog (e.g. "eBPF probe X misses behaviour Y — file issue").
- [ ] **Playbook deltas captured.** Any deviation from the [incident response runbook](incident-response-runbook.md) is documented as either a one-off or a permanent change proposal.

## 6. Tooling hygiene

- [ ] **Deep View version recorded** in the engagement cover sheet (`deepview --version`).
- [ ] **Extras installed recorded** (`pip show deepview` or the matching `deepview doctor` output).
- [ ] **Responder workstation wiped and reflashed** per [evidence-handling.md](evidence-handling.md), or explicitly retained for ongoing analysis with documented rationale.
- [ ] **Temporary keys destroyed.** GPG engagement keys, SSH keys issued for this incident only, any TLS material generated for the containment comms channel.
- [ ] **Cached PyPI wheels** used for the air-gapped install verified and archived — this is needed if the engagement's methodology must be reproduced months later.

## 7. Communications and people

- [ ] **External communications archived.** Email, chat, call recordings (where lawful and retained) collected into the engagement folder.
- [ ] **Stakeholder briefing closed.** Leadership, affected teams, and any external partners have received the final briefing.
- [ ] **Responder well-being check-in done.** Incident response is stressful; the lead has checked in with each responder.
- [ ] **On-call handover** to steady-state monitoring is complete; the engagement is no longer in active incident state.

## 8. Formal close

- [ ] **Incident status set to Closed** in the ticketing system, with the engagement folder path recorded.
- [ ] **Final sign-off** by the incident lead and an independent witness, with timestamps.
- [ ] **Post-incident review scheduled** for T+30 days to confirm the lessons-learned actions have landed.

---

## Cross-references

- [Incident response runbook](incident-response-runbook.md)
- [Chain of custody](chain-of-custody.md)
- [Reporting templates](reporting-templates.md)
- [Evidence handling](evidence-handling.md)
- [Witness statement template](witness-statement-template.md)
- [Threat model](../security/threat-model.md)
- [OPSEC](../security/opsec.md)
