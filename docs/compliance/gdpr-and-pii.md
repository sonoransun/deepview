# GDPR and PII Considerations

Deep View is a forensics tool. Forensic analysis routinely recovers
personal data: names in memory buffers, email addresses in heap,
passwords in cleartext, telephone numbers in SMS databases, geographic
coordinates in browser caches. None of this is filtered by default.
The operator is responsible for lawful processing.

!!! warning "Operational mapping, not a compliance certification"
    Running Deep View does **not** make you GDPR-compliant, and Deep
    View does **not** provide a DPIA. This page describes what the
    tool does (verbatim extraction, no built-in redaction) and what
    the operator must do (lawful basis, DPIA, redaction workflow,
    retention policy).

## Default behaviour: verbatim output

Deep View's default output is **verbatim**. Specifically:

- `scanning/string_carver.py` emits every printable string above the
  configured length threshold.
- `detection/encryption_keys.py` emits candidate key material (which
  may include passphrases) with a truncated excerpt.
- `memory/network/tcp_reconstruct.py` emits reconstructed TCP streams
  byte-for-byte.
- Generated reports (`reporting/export.py`) embed evidence fragments
  inline unless the operator enables redaction.

Default redactions applied by Deep View: **none**. The tool shows
what it finds.

## GDPR considerations by Article

| GDPR Article | Topic | Deep View implication |
|--------------|-------|-----------------------|
| Art. 5(1)(a) | Lawfulness, fairness, transparency | Operator must establish lawful basis before running Deep View against personal data |
| Art. 5(1)(b) | Purpose limitation | Results should be used only for the declared investigative purpose |
| Art. 5(1)(c) | Data minimisation | Operator is expected to discard non-relevant personal data post-analysis; see redaction workflow below |
| Art. 5(1)(e) | Storage limitation | Set retention on the session store and exported reports; Deep View has no automatic deletion |
| Art. 5(1)(f) | Integrity and confidentiality | Addressed by [Evidence integrity](evidence-integrity.md); storage encryption is operator responsibility |
| Art. 6 | Lawful basis | Typically Art. 6(1)(c) legal obligation (law enforcement) or Art. 6(1)(f) legitimate interest (incident response) |
| Art. 9 | Special categories | Memory dumps can contain health, biometric, or other special-category data — heightened controls apply |
| Art. 15 | Right of access | Operator should be able to produce, on request, the personal data about a data subject that resides in an investigation |
| Art. 17 | Right to erasure | Forensic necessity is an Art. 17(3)(e) derogation; document the justification in the session notes |
| Art. 30 | Records of processing | `SessionStartedEvent.purpose` field is intended for this; fill it in |
| Art. 32 | Security of processing | Evidence storage should meet Art. 32 standards — encryption at rest, access control, audit |
| Art. 35 | DPIA | Required for systematic and large-scale forensic analysis; Deep View is a candidate subject of a DPIA |

## Recommended redaction workflow

Deep View does not ship an opinionated redaction module because the
right scope depends on the case. The recommended workflow:

1. **Acquire without redaction** — the raw evidence is the evidentiary
   record; redact in the analytical output, not the source image.
2. **Analyse with Deep View** — produce a draft report.
3. **Redact the draft** — either:
   - manually in the HTML / Markdown output, or
   - programmatically by transforming the `ReportModel` before export
     (see below).
4. **Hash-link redacted to un-redacted** — retain both; the redacted
   version is for disclosure, the un-redacted version is for custody.
5. **Disclose only the redacted output** to parties who lack
   legitimate access to the personal data.

### Programmatic redaction pattern

```python
from deepview.reporting.export import generate_report
from deepview.replay.reader import SessionReader

REDACT_PATTERNS = [
    # Email addresses
    (re.compile(r"[\w\.-]+@[\w\.-]+\.\w+"), "<EMAIL_REDACTED>"),
    # IPv4 addresses outside investigation scope
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP_REDACTED>"),
    # Names list (loaded from a separate authorised file)
    # ...
]

def redact(text: str) -> str:
    for pattern, replacement in REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

with SessionReader.open(f"session-{session_id}.sqlite") as session:
    model = generate_report(session)
    for finding in model.findings:
        finding.excerpt = redact(finding.excerpt)
        finding.description = redact(finding.description)
    model.export_html("redacted-report.html")
```

A `reporting/redact.py` helper module is **not** shipped today —
the pattern above is the recommended path while the redaction API
remains operator-defined.

## Data subject requests (DSRs)

When an organisation using Deep View receives a data subject request:

- **Right of access (Art. 15)** — search the session store for
  indicators matching the data subject (name, email, IP). The
  SessionStore's SQLite schema allows SQL queries:
  ```sql
  SELECT * FROM events
   WHERE json_extract(payload, '$.excerpt') LIKE '%<identifier>%';
  ```
  Return the matching excerpts, filtered by legitimate-disclosure
  scope.
- **Right to rectification (Art. 16)** — rarely applicable to
  forensic evidence; evidence is a record of state, not a corrigible
  claim.
- **Right to erasure (Art. 17)** — Deep View sessions are append-only
  for integrity reasons; use the Art. 17(3)(e) forensic-necessity
  derogation with case-by-case justification. If erasure is
  compelled, document it in the case notes and preserve an
  operator-signed attestation that the erasure was applied.

## Cross-border transfers (Chapter V)

Deep View is a local CLI — it does not transfer data on the
operator's behalf. If your workflow ships session exports or
evidence images to another jurisdiction, that's an operator-initiated
transfer subject to Chapter V (adequacy decisions, SCCs, BCRs). Deep
View can encrypt exports at rest via the operator's configured GPG /
age key, but transfer-level lawfulness is not a tool concern.

## Retention

The session store has no automatic TTL. Set retention in your
programme; recommended defaults for incident-response teams:

| Artifact | Recommended retention |
|----------|----------------------|
| Raw acquisition images | Case duration + statute of limitations |
| Session store SQLite | Case duration + statute of limitations |
| Generated reports | Case duration + statute of limitations |
| Structlog audit log | 12 months minimum for the tool-itself compliance trail |

A retention policy is a programme artifact, not a tool artifact.

## See also

- [Evidence integrity](evidence-integrity.md) — hash propagation and
  audit trail.
- [ISO 27037 mapping](iso-27037.md) — auditability principle.
- Security [dual-use statement](../security/dual-use-statement.md) —
  authorised-use scope.
