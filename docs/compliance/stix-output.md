# STIX 2.1 Bundle Output

Deep View's `reporting/` subsystem exports findings as a
[STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
bundle suitable for ingestion into a TAXII 2.1 server or a threat-
intelligence platform (ThreatConnect, OpenCTI, MISP with STIX import,
etc.). This page documents which STIX object types Deep View
produces, how each is derived from the internal event schema, and how
to consume the output.

!!! warning "Operational mapping, not a compliance certification"
    STIX conformance is a specification conformance — producing
    syntactically valid STIX objects. It is not the same as a
    semantic warranty that your IOCs are correct.

## Object types produced

Deep View produces the following STIX 2.1 SDOs / SROs:

| STIX type | Deep View source | When emitted |
|-----------|------------------|--------------|
| `identity` | Session metadata (operator, organisation) | One per bundle — the examiner |
| `indicator` | Each `IOCMatchEvent`, `YaraMatchEvent`, `KeyMaterialFoundEvent` | One per unique indicator |
| `sighting` | Correlation between indicator and observed artifact | One per triggering event |
| `malware` | `RootkitDetectedEvent`, `ProcessInjectionDetectedEvent` where `malware_name` resolvable | One per named family |
| `attack-pattern` | ATT&CK technique ID from the event's `attack_ids` | One per unique technique |
| `observed-data` | Raw process / file / network observations from the `inspect/` primitives | One per inspected object |
| `relationship` | Links indicator → malware, sighting → indicator, malware → attack-pattern | One per semantic link |
| `report` | Bundle wrapper with session timeframe, narrative, and references to all contained objects | One per bundle |

Not produced (out of scope):

- `campaign`, `threat-actor`, `intrusion-set` — Deep View does not
  attribute, so does not invent these. If your analyst writes
  attribution text, it's attached to the `report` object's
  `description` field.
- `course-of-action` — remediation is operator judgement, not tool
  output.
- `tool` — the *tool* object type is reserved for offensive tooling
  that the adversary used; not applicable here.

## Field-level mapping

### `identity` from session metadata

```json
{
  "type": "identity",
  "spec_version": "2.1",
  "id": "identity--<uuid>",
  "created": "<session_started_at>",
  "modified": "<session_started_at>",
  "name": "<DEEPVIEW_OPERATOR or 'deepview'>",
  "identity_class": "individual",
  "sectors": [],
  "contact_information": "<optional DEEPVIEW_CONTACT env var>"
}
```

| Deep View field | STIX field |
|-----------------|-----------|
| `SessionStartedEvent.operator` | `identity.name` |
| `SessionStartedEvent.timestamp` | `identity.created`, `identity.modified` |
| `config.report.organisation` | `identity.sectors`, `identity.contact_information` |

### `indicator` from `IOCMatchEvent` / `YaraMatchEvent`

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<uuid5 of pattern>",
  "created_by_ref": "identity--<session_identity>",
  "created": "<first_seen>",
  "modified": "<last_seen>",
  "name": "<rule_name>",
  "description": "<rule_description or empty>",
  "indicator_types": ["malicious-activity"],
  "pattern_type": "stix",
  "pattern": "[file:hashes.'SHA-256' = '<sha256>']",
  "valid_from": "<first_seen>",
  "labels": ["<ioc_type>"]
}
```

| Deep View field | STIX field |
|-----------------|-----------|
| `IOCMatchEvent.rule_name` | `indicator.name` |
| `IOCMatchEvent.rule_description` | `indicator.description` |
| `IOCMatchEvent.ioc_type` | `indicator.labels`, `indicator.pattern` pattern-key |
| `IOCMatchEvent.value` (domain, IP, hash) | `indicator.pattern` pattern-value |
| `IOCMatchEvent.first_seen` | `indicator.created`, `indicator.valid_from` |
| `IOCMatchEvent.last_seen` | `indicator.modified` |

The STIX pattern syntax is assembled by
`reporting/stix_mapper.py::build_pattern()`, which covers these IoC
types:

| IoC type | STIX pattern template |
|----------|-----------------------|
| SHA-256 | `[file:hashes.'SHA-256' = '<value>']` |
| SHA-1 | `[file:hashes.'SHA-1' = '<value>']` |
| MD5 | `[file:hashes.MD5 = '<value>']` |
| IPv4 | `[ipv4-addr:value = '<value>']` |
| IPv6 | `[ipv6-addr:value = '<value>']` |
| Domain | `[domain-name:value = '<value>']` |
| URL | `[url:value = '<value>']` |
| Email | `[email-addr:value = '<value>']` |
| Mutex | `[mutex:name = '<value>']` |
| Filename | `[file:name = '<value>']` |

### `sighting` from observed matches

Each time an indicator matches real evidence, a `sighting` SRO is
emitted:

```json
{
  "type": "sighting",
  "spec_version": "2.1",
  "id": "sighting--<uuid>",
  "created_by_ref": "identity--<session_identity>",
  "first_seen": "<event.timestamp>",
  "last_seen": "<event.timestamp>",
  "count": 1,
  "sighting_of_ref": "indicator--<...>",
  "where_sighted_refs": ["identity--<session_identity>"],
  "observed_data_refs": ["observed-data--<...>"]
}
```

### `malware` from detection events

```json
{
  "type": "malware",
  "spec_version": "2.1",
  "id": "malware--<uuid5 of family name>",
  "created_by_ref": "identity--<session_identity>",
  "name": "<malware_name>",
  "is_family": true,
  "malware_types": ["rootkit" | "trojan" | "worm" | ...],
  "capabilities": ["installs-other-components", "persists-after-system-reboot"]
}
```

`malware_name` resolution is a best-effort mapping in
`reporting/malware_names.py` that looks up YARA rule metadata
(`meta.malware_family`) and classifier rule `malware_family:` keys.
If resolution fails, no `malware` object is emitted — the detection
stays as an `indicator` + `sighting`.

### `attack-pattern` from ATT&CK IDs

```json
{
  "type": "attack-pattern",
  "spec_version": "2.1",
  "id": "attack-pattern--<uuid5 of technique id>",
  "created_by_ref": "identity--<session_identity>",
  "name": "<technique name>",
  "external_references": [
    {
      "source_name": "mitre-attack",
      "external_id": "T1055.012",
      "url": "https://attack.mitre.org/techniques/T1055/012/"
    }
  ]
}
```

See [ATT&CK mapping](attack-mapping.md) for which Deep View events
carry `attack_ids`.

### `observed-data` from `inspect/` primitives

`inspect/` module outputs become STIX `observed-data` SDOs with
embedded Cyber Observable Objects (SCOs):

| Deep View source | STIX `observed-data` contains |
|------------------|-------------------------------|
| `ProcessInspector` | `process` + `file` SCOs |
| `FileInspector` | `file` + `directory` SCOs |
| `NetInspector` | `network-traffic`, `ipv4-addr`, `ipv6-addr`, `domain-name` SCOs |
| `MemoryPeek` | `artifact` SCO with `mime_type: application/octet-stream` |

### `relationship` semantics

| Source type | Relationship | Target type |
|-------------|--------------|-------------|
| `indicator` | `indicates` | `malware` |
| `indicator` | `indicates` | `attack-pattern` |
| `malware` | `uses` | `attack-pattern` |
| `sighting` | (implicit via `sighting_of_ref`) | `indicator` |

## Emitting a bundle

```bash
deepview report generate --session <id> --format stix --out bundle.json
```

The `--stix-version` flag selects 2.0 or 2.1 (default 2.1). Bundle
size is roughly linear in the number of events; expect 5–50 KB per
hundred events depending on indicator diversity.

Programmatic API:

```python
from deepview.reporting.export import export_stix_bundle
from deepview.replay.reader import SessionReader

with SessionReader.open("session-<id>.sqlite") as session:
    bundle = export_stix_bundle(session, spec_version="2.1")
    bundle.save("bundle.json")
```

## Consuming in a TAXII 2.1 server

Any TAXII 2.1 server that accepts `application/taxii+json;version=2.1`
can ingest the bundle. Example using `taxii2-client`:

```python
from taxii2client.v21 import Collection

collection = Collection(
    "https://taxii.example.org/api/collections/<uuid>/",
    user="deepview",
    password="<secret>",
)
with open("bundle.json", "rb") as f:
    collection.add_objects(f.read())
```

Tested against:

- OpenCTI TAXII 2.1 endpoint
- FreeTAXII server 0.6+
- MISP's built-in STIX 2.1 import (via `misp-stix`)

## Validation

The bundle is validated against the official OASIS STIX 2.1 JSON
schemas before write. Validation errors raise
`StixValidationError` rather than producing a malformed bundle. The
validator ships as an optional dependency under the `sigma` extra
(which also pulls `stix2-validator`):

```bash
pip install -e ".[sigma]"
deepview report validate-stix bundle.json
```

## Limitations

- Deep View does not emit `grouping` or `note` SDOs.
- Custom STIX extensions are not produced; Deep View stays on the
  OASIS core spec for maximum interoperability.
- The bundle is a snapshot at report time; incremental updates are
  not emitted (no `revoked`, `modified`-in-place for existing SDOs).
