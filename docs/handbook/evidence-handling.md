# Evidence handling

> Physical and logical discipline for evidence that moves through Deep View. This is the "do not break custody" page — read it before you acquire anything.

!!! warning "Operational guidance — not legal advice"
    Evidence-handling requirements vary by jurisdiction, sector, and contract. Treat this page as a technical baseline; consult counsel for the specifics of your matter.

## 1. Order of volatility

Acquire the most volatile evidence first. When two artefacts are competing, the one that will disappear sooner wins.

The canonical order, adapted from RFC 3227 and applied to Deep View's capability surface:

| Rank | Class | Typical half-life | Deep View surface |
|------|-------|-------------------|-------------------|
| 1 | CPU registers, cache | microseconds | Not directly — capture via memory + PT translation |
| 2 | Routing / ARP / process / kernel tables | seconds | `deepview inspect net`, `deepview inspect process` |
| 3 | RAM contents | seconds–minutes | `deepview acquire memory --method {lime,avml,winpmem,osxpmem}` |
| 4 | Temp filesystem state | minutes | `deepview inspect file`, `deepview acquire storage --live` |
| 5 | Disk state | hours–days | `deepview acquire storage` with write-blocker |
| 6 | Remote logging / telemetry | days | Pull from SIEM, correlate in the report |
| 7 | Physical configuration / topology | engagement lifetime | Photograph, document |
| 8 | Archival media / backups | months–years | Separate acquisition track |

!!! tip "Do not debate the order mid-engagement"
    Decide the acquisition order **before** you touch the host. Re-planning mid-acquisition costs volatile data. If the engagement requires both a full memory image and live tracing, start tracing (cheap, non-destructive) *then* acquire memory.

## 2. Write-protection for non-volatile media

Non-volatile media (SATA/SAS/NVMe drives, USB mass storage, SD cards, magnetic tape) **must** be write-protected before Deep View touches it.

### Preferred: hardware write-blocker

- SATA / SAS: Tableau, WiebeTech, CRU, Atola.
- NVMe: certified NVMe blockers (the SATA-era devices will not work).
- USB: USB write-blocker bridge.

Validate the blocker before use — run a mount-and-attempt-write test on a sacrificial drive, confirm the write fails and the source is unmodified.

### Fallback: software write-blocker

- Linux: mount read-only via `mount -o ro,noload` for journaling filesystems; add `blockdev --setro /dev/...` for the block device.
- macOS: Disk Arbitration disabled before attachment.
- Windows: `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect = 1` for removable media, reboot required.

Software-only write-blocking is acceptable for triage but rarely for court. Document the method either way.

### Acquisition command pattern

```bash
# Hardware-write-blocked source — safe to read at full speed
deepview acquire storage \
    --source /dev/sdX \
    --out /evidence/host01/disk.dd \
    --hash sha256 \
    --manifest /evidence/host01/disk.manifest.json
```

The `hash_sha256` on `AcquisitionResult` is populated streaming-from-source; see [chain-of-custody.md](chain-of-custody.md).

## 3. Air-gapped analysis workstation

The responder workstation that runs Deep View against acquired evidence should be air-gapped — no Ethernet, no Wi-Fi, no Bluetooth, no LTE. Threats this mitigates:

- Malware embedded in the evidence reaching the corporate network.
- Sensitive evidence leaking to adversary telemetry.
- A compromised Python package silently exfiltrating findings.

### Practical build

- Dedicated laptop or desktop used only for forensic analysis.
- Full-disk encryption (LUKS on Linux, FileVault on macOS, BitLocker on Windows).
- Minimal OS image, re-flashed between engagements.
- Deep View installed from a vetted wheel cache on removable media — not from live PyPI.
- USB ports physically blocked except for designated evidence ports.
- Bluetooth / Wi-Fi radios disabled in BIOS where supported.
- Webcam / microphone physically covered.

### Multi-stage isolation when pure air-gap is impractical

When the engagement requires pulling updated Deep View extras or YARA rules:

1. A **curator** workstation with internet pulls updates, verifies signatures, writes to sterile media.
2. The **analyst** workstation (air-gapped) reads from that media only.
3. The curator never touches evidence; the analyst never touches the internet.

This is the "two-gap" model — the evidence is two hops from any network.

## 4. Data-at-rest encryption for evidence containers

Every evidence container stored outside a WORM vault must be encrypted at rest.

### Recommended formats

- **LUKS2** (Linux). See the [unlock-luks guide](../guides/unlock-luks-volume.md) for Deep View's unlock surface.
- **VeraCrypt** containers — hidden-volume support when legal deniability is a real requirement. See [unlock-veracrypt-hidden](../guides/unlock-veracrypt-hidden.md).
- **Age** for per-file encryption when the grain is files rather than volumes.
- **GPG** for signing manifests (see [chain-of-custody.md](chain-of-custody.md)).

### Key management

- Keys are escrowed with a second custodian, not carried solely by the responder.
- Passphrases are high-entropy (≥20 characters random, or diceware ≥8 words).
- Hardware tokens (YubiKey, Feitian) preferred over pure-software keys for signing.
- Key rotation at engagement close — see [debrief-checklist.md](debrief-checklist.md).

## 5. Physical storage discipline

- Evidence drives in tamper-evident bags with pre-printed sequence numbers.
- Bag serial, drive serial, and SHA-256 prefix all logged on the custody form.
- Storage safe with dual-control access (two-person integrity) for court-bound evidence.
- Temperature and humidity controlled — magnetic and flash media degrade faster outside 15–25 degC and 30–50% RH.
- No photographs of the evidence on personal devices.

## 6. Transport

- Couriered with signature-on-delivery; no drop-shipping.
- Dual-seal bags — outer bag numbered, inner bag numbered, both numbers on the custody form.
- For international transport, check ITAR / EAR / Wassenaar implications **before** packing. Some dual-use capabilities (including parts of Deep View) are export-controlled in some jurisdictions.

## 7. Disposal

- Cryptographic erase for self-encrypting drives (SED).
- Multi-pass overwrite for magnetic drives (DoD 5220.22-M or equivalent).
- Physical destruction (degauss + shred) for drives that held the most sensitive material.
- Document the disposal in the custody log — disposal is the last custody link, not an absence of one.

## Cross-references

- [Chain of custody](chain-of-custody.md)
- [Incident response runbook](incident-response-runbook.md)
- [Debrief checklist](debrief-checklist.md)
- [Threat model](../security/threat-model.md)
- [OPSEC](../security/opsec.md)
