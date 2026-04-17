# Chain of custody

> Evidence that cannot prove its own integrity is evidence that cannot be used. This page is the operator-facing guide to how Deep View preserves custody end-to-end.

!!! warning "Operational guidance — not legal advice"
    Chain-of-custody requirements vary by jurisdiction, regulator, and contract. Use this page as a technical baseline; have counsel review the specifics for your matter.

## Principles

1. **Every artefact has an identity.** A SHA-256 (minimum) at the earliest possible point and at every hand-off.
2. **Every event has a witness.** A structured, append-only log line recording who did what, when, on whose authority.
3. **Every change to custody has a signature.** A human — identified by a cryptographic key — signed at each hand-off.
4. **Storage is WORM.** Write-once-read-many, so "the log file was edited after the fact" is not a defensible accusation.

Deep View supports each of these in code; the rest of this page shows where.

---

## 1. SHA-256 at acquisition

Every acquisition method in `src/deepview/memory/acquisition/` — `lime`, `avml`, `winpmem`, `osxpmem`, and the `live` composite — returns an `AcquisitionResult` whose `hash_sha256` field is populated **while the image is being written**, not after. This matters: re-hashing a file on disk cannot distinguish an integrity error from a mid-flight swap, but a streaming hash computed from the raw bytes-as-acquired can.

### Practical usage

```bash
deepview acquire memory \
    --method lime \
    --out /evidence/host01/mem.lime \
    --manifest /evidence/host01/mem.manifest.json
```

The manifest is a JSON object with at least:

```json
{
  "artefact": "mem.lime",
  "size_bytes": 17179869184,
  "hash_sha256": "...",
  "acquired_at": "2026-04-14T10:42:03Z",
  "acquired_by": "j.doe@example.com",
  "deepview_version": "0.2.x",
  "method": "lime",
  "host": {
    "hostname": "host01",
    "kernel": "6.1.0-28-amd64",
    "uptime_seconds": 1842301
  }
}
```

**Do not** compute the hash post-hoc from the written file and substitute it in — that is a materially different claim.

### Storage-image equivalents

`deepview acquire storage` and the offload acquisition paths do the same — every `AcquisitionResult` across the tool is hash-populated at creation. The [storage-image walkthrough](../guides/storage-image-walkthrough.md) shows the full flow.

---

## 2. Structured logging via structlog

Deep View logs through `structlog`. The important property for custody is **structured, machine-parseable, append-only**. Configure a file handler on the responder workstation that writes to a WORM mount:

```python
# ~/.deepview/logging.py — loaded by AnalysisContext at startup
import structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.add_log_level,
        structlog.processors.EventRenamer("message"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO+
    logger_factory=structlog.WriteLoggerFactory(
        file=open("/mnt/worm/deepview-engagement.log.jsonl", "a")
    ),
    cache_logger_on_first_use=True,
)
```

Every log line includes: ISO-8601 UTC timestamp, log level, event name, any `AnalysisContext` fields injected by the subsystem, and the PID of the `deepview` process. This is the base custody trail.

### WORM storage options

- Enterprise NAS with retention locks (NetApp SnapLock, Dell ECS, etc.).
- Cloud object storage with object-lock / legal-hold (S3 Object Lock, GCS Bucket Lock).
- Append-only filesystems (`chattr +a` on ext4 — note that root can still un-set, so combine with a separate custody account).
- Physical WORM optical media for the most sensitive engagements.

---

## 3. Event-bus replay for audit trail

The `SessionStore` / `SessionRecorder` / `SessionReplayer` triple in `src/deepview/replay/` is a custody feature as much as an operational one. The recorder subscribes to the bus and batches writes into a SQLite file with WAL and JSON columns; the replayer reads them back onto a private `TraceEventBus` and re-emits them identically to live events.

### Why this is a custody artefact

1. Every decision a responder made was driven by some stream of events.
2. That stream is captured verbatim, not paraphrased.
3. Months later, in a legal proceeding, the replay is reproducible: anyone can take the SQLite file and watch the same events the responder watched.

### Verifying a session file

```bash
sha256sum /evidence/host01/session.sqlite
deepview replay verify --session /evidence/host01/session.sqlite
```

`deepview replay verify` checks schema integrity, event-sequence monotonicity, and internal counter consistency. It does **not** certify the contents — only the structural integrity of the SQLite container. Pair it with the signed manifest for end-to-end assurance.

---

## 4. Timestamped + signed acquisition manifests

Recommended workflow at every hand-off:

### 4.1 Build the manifest

```bash
cd /evidence/host01
sha256sum -- * > manifest.sha256
echo "engagement: IR-2026-0414-01" >> manifest.sha256
echo "responder: j.doe@example.com" >> manifest.sha256
echo "generated_at: $(date -u +%FT%TZ)" >> manifest.sha256
```

### 4.2 Timestamp it (RFC 3161)

An RFC-3161 timestamp authority gives you a cryptographic attestation that the manifest existed at a specific wall-clock time — independent of your responder workstation's clock.

```bash
openssl ts -query -data manifest.sha256 -sha256 -cert \
    -out manifest.tsq
curl -s -H "Content-Type: application/timestamp-query" \
    --data-binary @manifest.tsq \
    https://freetsa.org/tsr \
    > manifest.tsr
openssl ts -verify -data manifest.sha256 -in manifest.tsr -CAfile freetsa-cacert.pem
```

Pick a TSA your counsel accepts; `freetsa.org` is illustrative only.

### 4.3 Sign it

```bash
gpg --detach-sign --armor manifest.sha256
gpg --detach-sign --armor manifest.tsr
```

### 4.4 Store everything together

```
/evidence/host01/
├── mem.lime
├── mem.manifest.json
├── session.sqlite
├── findings/
│   ├── anti_forensics.json
│   └── injection.json
├── manifest.sha256
├── manifest.sha256.asc
├── manifest.tsq
├── manifest.tsr
└── manifest.tsr.asc
```

---

## 5. Hand-off protocol

Every time evidence moves — responder to analyst, analyst to legal, legal to expert witness — perform the four-step hand-off:

1. **Re-verify hashes** against the manifest. Any mismatch: stop, escalate.
2. **Append a custody entry** to the engagement log with who is receiving, who is handing over, wall-clock time, and purpose.
3. **Counter-sign** the manifest with the receiver's GPG key. The `.asc` files accumulate.
4. **Update the witness statement** — see [witness-statement-template.md](witness-statement-template.md) — with the new custody link.

## 6. When custody breaks

- Document the break immediately — pretending it did not happen is worse than admitting it.
- Preserve everything adjacent (logs, notes, session files) in case the break is material.
- Inform incident lead and counsel before any further action.
- The affected evidence may still be useful for intelligence purposes even if it is no longer admissible.

## Cross-references

- [Incident response runbook](incident-response-runbook.md)
- [Evidence handling](evidence-handling.md)
- [Witness statement template](witness-statement-template.md)
- [Threat model — evidence-integrity section](../security/threat-model.md)
- [OPSEC — custody-specific guidance](../security/opsec.md)
