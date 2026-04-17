# Evidence Integrity

Deep View's evidence-integrity model rests on three load-bearing
design choices: **hashes are computed at acquisition time**,
**`DataLayer.read()` is read-only by contract**, and **every
evidence access is logged through structlog into an append-only
audit trail**. This page documents each and the recommended
operator workflow that the tool assumes.

!!! warning "Operational mapping, not a compliance certification"
    Evidence integrity is a property of the process. The toolkit
    provides features that *enable* integrity; you still need
    hardware write-blockers, WORM storage, and a chain-of-custody
    procedure outside the tool.

## Hash propagation

### At acquisition

Every `AcquisitionResult` carries:

| Field | Computed when |
|-------|---------------|
| `hash_sha256: str` | Always, during the acquisition write |
| `hash_sha512: str \| None` | When `--strong-hash` is passed or `config.acquisition.strong_hash = true` |
| `byte_count: int` | During the write |
| `acquisition_start_ts: datetime` | At `acquire()` entry |
| `acquisition_end_ts: datetime` | At `acquire()` exit |
| `source_identifier: str` | Device path, `/proc/kcore`, PID, etc. |
| `tool_name: str` | LiME, WinPMem, OSXPMem, AVML, live |
| `tool_version: str` | Captured from the provider module |

The hash is *not* computed post-hoc on the written file — it is
updated streamingly through `hashlib.sha256().update(chunk)` as each
block is written. This means a torn write cannot leave a
mismatched file on disk without the acquisition raising
`AcquisitionIntegrityError` on verification.

Reference: `src/deepview/memory/acquisition/base.py::AcquisitionProvider.acquire`.

### Through the pipeline

Downstream consumers (Volatility 3, MemProcFS, YARA) open the
evidence by path but **never** through a writable file mode. The
abstract `DataLayer` has no `write()` method:

```python
# src/deepview/interfaces/layer.py
class DataLayer(ABC):
    @abstractmethod
    def read(self, offset: int, length: int) -> bytes: ...

    @abstractmethod
    def is_valid(self, offset: int, length: int) -> bool: ...

    # No write(). By design.
```

Concrete implementations (`FileLayer`, `MemoryImageLayer`,
`LiveProcessLayer`, `TranslationLayer`) open their backing file
with `os.O_RDONLY` (or `mmap.PROT_READ`) and treat any `write`
attempt as a programming error.

### At report time

`ReportGeneratedEvent` records:

- `evidence_refs: list[EvidenceRef]` — each a `{path, sha256}` pair
  captured from the `AcquisitionResult` or the source dataset;
- `report_sha256: str` — SHA-256 of the written report itself;
- `report_signature: str \| None` — present when the operator
  configured a signing key via `config.reporting.signing_key_path`
  (minisign / age / gpg backend, in that order of preference).

A verifying peer can:

1. Read the report's embedded `evidence_refs` block.
2. Re-hash the evidence file locally.
3. Compare against the embedded hash.
4. Verify the report signature against the operator's public key.

All four steps are scripted by `deepview report verify <report>`.

## Read-only contract

The `DataLayer` abstraction enforces read-only access at the type
level. Any plugin that attempts to modify evidence would have to
reach past the abstraction — which is grep-able and CI-enforced
(ruff rule `DPV001` rejects `os.O_WRONLY` / `os.O_RDWR` against
`config.acquisition.output_path`).

The *acquisition* path is, of course, a writer — but it writes to a
separate destination (the acquisition output), never to the source
device. The source device is opened `O_RDONLY` and optionally
through a file descriptor validated against `/sys/block/<dev>/ro`
set to 1.

### Exceptions — active subsystems

Two subsystems intentionally mutate state:

| Subsystem | Mutation target | Safeguard |
|-----------|-----------------|-----------|
| `instrumentation/` (Frida) | Target process memory | Off by default; explicit `--attach <pid>` required; mutates runtime only, not evidence files |
| `networking/` (mangle) | Live network packets | Dual-use-flagged; requires `--enable-mangle --confirm` and a non-empty ruleset; never writes to disk |

These are never engaged during evidence acquisition or post-hoc
analysis. The documentation for each is explicit about the dual-use
boundary.

## Audit trail via structlog

Every acquisition, every plugin run, every `DataLayer` open emits a
structured log record. The default processor chain is:

```python
# src/deepview/core/logging.py — simplified
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(sort_keys=True),
    ],
    ...
)
```

The log is written to **two** sinks:

1. **Stdout** (or the file configured via `--log-file`) for the
   operator to tail in real time.
2. **`~/.deepview/audit.log`** as an append-only JSONL file. The
   file is opened with `O_APPEND` and never truncated by the tool.

Operators are encouraged to mirror the audit log to WORM storage
(AWS S3 Object Lock, MinIO with compliance mode, or an offline LTO
tape spool). The documentation does not automate this because the
right answer depends on the programme's retention policy.

## Recommended workflow

For evidentiary-grade acquisitions:

1. **Pre-flight**
   - Hardware write-blocker on the source device (Tableau, WiebeTech,
     or similar hardware).
   - `DEEPVIEW_OPERATOR=<name> deepview doctor` to capture the
     operator identity in the session.
   - `deepview session start --case <case-id> --evidence-id <evid>`
     opens a new session with custody metadata.

2. **Acquisition**
   - Memory: `deepview memory acquire --format lime --out mem.lime
     --strong-hash` (or the appropriate provider).
   - Disk: acquire with a canonical tool (`ewfacquire`, `dc3dd`); then
     `deepview session attach-evidence mem.lime` to bring both hashes
     under the same custody log.

3. **Preservation**
   - Copy the `.lime` / `.E01` image onto two WORM volumes; retain
     the hashes from the `AcquisitionResult`.
   - Close the session (`deepview session close`); export the
     session store (`deepview session export --out case-<id>.zip`).

4. **Analysis**
   - Open a fresh analysis session from the preserved image:
     `deepview session start --resume-from case-<id>.zip`.
   - Run plugins; all `DataLayer.read` on the image is logged.

5. **Reporting**
   - `deepview report generate --format html,stix,attack-navigator`;
     the report embeds evidence hashes.
   - Sign the report with `--sign`.

6. **Retention**
   - Store: the preserved image, the session export, the signed
     report, and the operator's private notes.
   - All of the above carry a SHA-256 that you can verify at any
     point via `deepview report verify`.

## Write-blocker recommendations

Deep View cannot verify that a hardware write-blocker is in use —
but it can refuse to proceed when a device appears writable. The
`acquisition.enforce_readonly` config flag checks
`/sys/block/<dev>/ro` on Linux and refuses acquisition if the flag
is 0; on other platforms, the check is best-effort and documented
as incomplete. Defaults:

```toml
# ~/.deepview/config.toml
[acquisition]
enforce_readonly = true     # default true; refuse writable sources
strong_hash = false         # default false; enable for evidentiary use
output_directory = "~/evidence"
```

## Immutable storage

Deep View's session store is WAL-journaled SQLite. For immutable
archival, the intended workflow is:

1. `deepview session close` on the active session.
2. `deepview session export --out session-<id>.tar.gz` bundles the
   SQLite file, the schema version, the evidence manifest, and a
   MANIFEST.json with hashes.
3. Upload to WORM storage (S3 Object Lock `COMPLIANCE` mode, Azure
   immutable blob, GCS Bucket Lock, or offline LTO).
4. Store the SHA-256 of the `.tar.gz` separately for future
   verification.

Deep View does not ship a built-in uploader for WORM storage —
that's operator policy, not tool scope.

## See also

- [ISO 27037 mapping](iso-27037.md) — auditability and
  repeatability principles.
- [NIST SP 800-86 mapping](nist-sp-800-86.md) — Collection and
  Preservation phases.
- Security [OPSEC guide](../security/opsec.md) — acquisition order,
  chain of custody, operator discipline.
