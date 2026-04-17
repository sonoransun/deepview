# Operator OPSEC

This page is field guidance for forensic operators using Deep View on
real engagements. It is not a replacement for your organisation's
standard operating procedure, your engagement authorisation, or the
applicable regulation in your jurisdiction — but it captures the
operational practices that keep Deep View's output admissible,
reproducible, and minimally invasive.

If you are reading this as a contributor, the short version is:
**everything below is a user-facing expectation that new features must
either uphold or surface explicitly in the CLI.** The
[threat model](threat-model.md) cross-references this page wherever a
threat is mitigated by operator practice rather than by code.

!!! warning "Authorisation is a prerequisite, not a feature"
    Deep View does not ask for or verify authorisation. The
    `--authorization-statement` flag exists to bind a record of
    authorisation to the acquisition log; it does **not** constitute
    authorisation. If you do not have a written engagement scope, a
    warrant, or a corresponding internal ticket, stop here and get
    one.

## Acquisition order: volatile first

Volatility loss happens in seconds. Persistence is measured in hours.
Acquire in decreasing order of volatility.

1. **Live memory** — `deepview memory acquire` or the operator's
   preferred dumper. Save the raw dump and the SHA-256 before
   touching anything else.
2. **Running process state** — `deepview inspect process <pid>`
   captures `/proc/<pid>/` + `/proc/<pid>/mem` as a
   `PluginResult`. Do this before shutting the target down.
3. **Network state** — routing table, conntrack, arp, listening
   sockets, TLS SNI log if available. `deepview trace --filter
   'syscall == connect'` for a short window can be valuable as a
   corroborating capture.
4. **Mounted filesystems in-place** — checksum the block devices
   (`blkid`, `lsblk --output NAME,UUID,FSTYPE,PTTYPE,SIZE`) before
   imaging. Record mount state.
5. **Storage images** — use the best available write-blocker or a
   loopback mount in read-only mode. Prefer raw + E01 pairs for
   long-term preservation.
6. **Containers and encrypted volumes** — only *after* both memory
   and the encrypted storage are hashed and archived. Keys carved
   from memory are bound to the memory image that produced them.
7. **Cloud artefacts, log platforms, ticketing systems** — slowest
   and easiest to re-acquire; safe to leave for last.

!!! tip "Rule of thumb"
    If a reboot erases it, acquire it before doing anything that
    might trigger a reboot — including pressing `Ctrl-C` in a tool
    running on the target.

## Hash everything at acquisition time

Every artefact Deep View acquires is SHA-256'd at acquisition time
and the hash is embedded in the `PluginResult`. This is the
`hash_sha256` field discussed in the
[threat model](threat-model.md#t-t-1--modified-memory--disk-image-in-flight).

Operator practice:

- **Record the hash outside Deep View as well** — in your case-
  management system, your notebook, or a co-located WORM log.
- **Re-hash on import.** `deepview memory load <path>` computes
  SHA-256 and refuses to proceed silently if a previously recorded
  hash is known and does not match.
- **Never hash a file on the target.** The target's `sha256sum` may
  be trojaned. Hash on the analysis host, against the image, after
  acquisition.
- **Record the hash of the acquisition tool too.** If you used a
  LiME build from a specific commit, note the commit.

!!! note "Why SHA-256 and not SHA-3 / BLAKE3 / a Merkle tree"
    SHA-256 is the lowest-common-denominator format supported by
    every chain-of-custody tool we encounter in practice. Deep View
    additionally records BLAKE3 where the format allows it, but the
    `hash_sha256` field is the one that is guaranteed to exist and
    is the one your court exhibits are likely to cite.

## Chain of custody: the structured log is the record

Every action Deep View takes emits a structlog event and a core
`EventBus` message. Together these are the chain-of-custody record
for the session. They include the operator's UID, the correlation ID
for the CLI invocation, the argv (minus secrets), and the full
timing of each action.

Operational requirements:

- **Write the log to immutable storage.** `journald` with
  `Storage=persistent+seal`, `auditd` with a hashed log, or a WORM
  bucket (S3 Object Lock, etc.). The log file on the operator's
  workstation is a draft, not the artefact.
- **Include the log hash in the final report.** Deep View's reporter
  does this automatically when the structured log is passed to
  `deepview report generate --include-audit-log <path>`.
- **Do not rely on the replay SQLite DB as your chain of custody.**
  It is intentionally a convenience format — it can be rewritten
  offline without leaving a trace. The threat model covers this at
  [T-T-2](threat-model.md#t-t-2--tampering-with-the-session--replay-db).

!!! tip "Two-log approach"
    Run with both `DEEPVIEW_LOG_FILE=/path/to/run.log` and
    `DEEPVIEW_LOG_JOURNALD=1`. The file is your working copy; the
    journal is your tamper-evident copy. Compare hashes at the end
    of the engagement.

## Container unlock: redact keys before you report

Deep View can recover passphrases and keys from memory dumps
(`deepview unlock` family of commands, backed by
`deepview.storage.containers`). These values MUST NOT appear in any
final report shared outside the operator team.

The default behaviour of the reporter is to replace any
`Sensitivity.secret` field with a `<redacted>` token. To override,
the operator must pass `--include-secret-material` AND the CLI
prints a banner. The override exists for situations where the key
itself is evidence (e.g. proving key reuse across systems) — not for
convenience.

Checklist before sharing a report:

- [ ] `grep` the report for known passphrase prefixes, PEM headers
      (`-----BEGIN`), and wallet addresses.
- [ ] Confirm `Sensitivity` tags on every custom plugin you wrote.
- [ ] Regenerate the report with `--include-secret-material` removed
      if you had it on for any intermediate run.
- [ ] If distributing a STIX bundle, verify that indicator values
      are hashes or structural descriptors, not raw secrets.

!!! danger "Carved keys can unlock the subject's other systems"
    A passphrase recovered from one memory dump may unlock the
    subject's other devices or cloud accounts. Treat carved keys
    with the same care as the evidence store itself. In most
    jurisdictions, using them to access further systems requires a
    separate authorisation.

## Remote acquisition: authorisation statement is a record, not a licence

`deepview remote-image` supports SSH, DMA, IPMI, and AMT endpoints.
All four paths require:

1. `--enable-<method>` (e.g. `--enable-dma`) to opt into the
   capability explicitly.
2. `--authorization-statement "<free-text>"` which is logged verbatim
   at the start of the acquisition and embedded in the resulting
   `PluginResult`.
3. Confirmation after a 5-second banner displays the target, the
   method, and the authorisation statement. `--confirm` skips the
   wait but still emits the banner.

The `--authorization-statement` string is a record-keeping aid. It
does not constitute legal authorisation. Common values seen in
practice:

- `"Ticket INC0123456, corp-SOC, host owned by corp-IT"` (internal
  incident response).
- `"Warrant 2026-CR-4412, signed 2026-04-12"` (law enforcement).
- `"DEFCON CTF 32 finals, team blue-team-42"` (CTF / exercise).
- `"Red team engagement, SOW signed 2026-03-01, scope: 10.42.0.0/16"`
  (authorised red team).

The string is indexed in the session DB so future runs can surface
prior acquisitions against the same target.

See [remote-acquisition.md](../architecture/remote-acquisition.md)
for the full control flow and what each flag unlocks.

## Network mangling: scope the engagement before enabling

`deepview netmangle run` uses NFQUEUE to intercept, modify, delay,
drop, rewrite, or corrupt real network packets. It is a dual-use
capability (see the [dual-use
statement](dual-use-statement.md#refused-use-cases)).

Before enabling:

- [ ] Confirm the targets are on a network you are authorised to
      manipulate. CTF networks, dedicated honeypot VLANs, and
      lab-isolated subnets are fine; production networks, shared
      corporate VLANs, and public-ISP networks are not.
- [ ] Document the scope in the same authorisation record you use
      for remote acquisition. A signed SOW works.
- [ ] Start with `--dry-run` — it forces every verdict to ACCEPT so
      the ruleset exercises the engine without actually modifying
      traffic.
- [ ] Start with `--observe` rules before `--drop` or `--rewrite`.
- [ ] Never run against a network carrying emergency services,
      medical devices, industrial control, or safety-of-life
      traffic, regardless of authorisation.

Deep View additionally refuses to start the mangle engine without
all of:

- Root (or `CAP_NET_ADMIN` + `CAP_NET_RAW`).
- An explicit `--enable-mangle`.
- A non-empty ruleset file.
- Interactive confirmation (unless `--confirm` is passed).
- An opt-in `--install-iptables` if you want Deep View to install the
  NFQUEUE jump rule itself; otherwise the jump rule must already
  exist.

Every mangle action emits a `NetworkPacketMangledEvent` on the core
`EventBus`; the dashboard's `ManglePanel` surfaces them live. Do not
disable that panel during an engagement — it is the operator's
real-time view of what the engine is doing.

## DMA: physical access matters

DMA acquisition requires physical access to the target. Record the
physical chain of custody:

- Time and location where the target was accessed.
- Serial number of the DMA adapter (typically a PCILeech / ScreamerM2
  or similar).
- Photograph or serial-recorded evidence of the port used on the
  target.
- Return of the adapter to the evidence locker after acquisition.

The CLI does not ask for any of this. It is your case-management
system's job. Deep View records the tool serial (when the adapter
exposes one) in the `PluginResult`, which at least ties the
acquisition to the hardware that produced it.

## Reporting: redact PII per applicable regulation

Deep View's reporter produces HTML, Markdown, JSON, ATT&CK Navigator
layers, and STIX 2.1 bundles. All of these can contain PII if the
underlying investigation does:

- Usernames, device names, and hostnames from the target.
- IP addresses that may be residential.
- Geolocation inferred from network artefacts.
- Text strings carved from memory or disk (chat messages, emails,
  document contents).

Operator practice:

- **Tag PII at the plugin level** using the `Sensitivity` enum
  (`restricted` by default) so the reporter can redact it.
- **Consult the relevant regulation** before sharing a report with
  anyone outside the engagement — GDPR, CCPA, HIPAA, UK DPA 2018,
  Canadian PIPEDA, Australian Privacy Act 1988 — the list is long
  and the rules differ.
- **Prefer hashes and structural indicators** in STIX bundles shared
  externally. Raw strings stay in internal reports.
- **Watermark internal reports** with the recipient and the
  engagement ID so a leak is traceable. The reporter supports this
  with `--watermark`.

!!! note "When in doubt, ask counsel"
    Deep View ships with no default retention policy, no default
    disclosure policy, and no default jurisdiction. These are policy
    decisions for the operator's organisation.

## Analysis host hygiene

- **Clean, isolated VM.** Analysis is performed inside a VM that has
  no direct connectivity to the target network, no credentials for
  production systems, and a snapshot taken before the investigation
  starts. Revert the snapshot between engagements.
- **No outbound traffic during analysis.** Memory dumps can contain
  beaconing artefacts; yara / volatility plugins should not be
  allowed to phone home. Drop outbound at the host firewall.
- **Logs go outbound to WORM, everything else stays inbound-only.**
  The one exception to the previous rule.
- **Full-disk encryption on the analysis host.** The evidence store
  is sensitive; treat the machine it lives on accordingly.
- **Multi-user hosts are discouraged.** If unavoidable, use
  `DEEPVIEW_REFUSE_ROOT=1` and per-user plugin directories with
  restrictive permissions.

## Session hygiene

- **One session per engagement** — use `deepview --session-id`
  explicitly so the correlation IDs in the audit log are predictable.
- **Export the session DB at the end** — `deepview replay export
  <session_id>` produces a portable artefact that can be attached to
  the case file.
- **Rotate credentials.** If any credential was loaded into Deep
  View during an engagement, rotate it at the end. This includes
  carved keys that unlocked ephemeral containers.
- **Destroy working copies.** The analysis host should not retain
  evidence after the case closes unless explicitly required by
  retention policy.

## Cross-references

- [Threat model](threat-model.md) — the security properties this
  OPSEC guidance is designed to uphold.
- [Dual-use statement](dual-use-statement.md) — the scope within
  which this toolkit is intended to be used.
- [Remote acquisition architecture](../architecture/remote-acquisition.md)
  — the full control flow for the remote methods discussed here.
- [Unlock a LUKS volume](../guides/unlock-luks-volume.md) /
  [VeraCrypt hidden volume](../guides/unlock-veracrypt-hidden.md) —
  worked examples that apply the secret-handling practices above.
