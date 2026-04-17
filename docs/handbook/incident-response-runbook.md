# Incident response runbook

> NIST SP 800-61r2 aligned playbook for running an incident with Deep View as the primary forensics and runtime-analysis toolkit.

!!! warning "Operational guidance — not legal advice"
    Nothing in this runbook substitutes for your organisation's approved IR policy, counsel's direction, or jurisdiction-specific evidence rules. Treat it as a starting template, not a prescription.

This runbook mirrors the six NIST IR phases:

1. [Preparation](#1-preparation)
2. [Detection and analysis](#2-detection-and-analysis)
3. [Containment](#3-containment)
4. [Eradication](#4-eradication)
5. [Recovery](#5-recovery)
6. [Post-incident / lessons learned](#6-post-incident-lessons-learned)

For each phase the runbook lists the Deep View commands to run, the expected output, the red flags to watch for, and the paperwork produced. Always read the relevant [OPSEC](../security/opsec.md) and [threat-model](../security/threat-model.md) sections before executing a command in an adversarial environment.

---

## 1. Preparation

Preparation happens *before* the incident. If you are reading this during an incident, skip to [Detection](#2-detection-and-analysis) and come back later to close gaps.

### 1.1 Install Deep View on the responder workstation

Use an air-gapped or otherwise isolated workstation — see [Evidence handling](evidence-handling.md) for workstation hardening.

```bash
# Core install — everything else is optional
pip install -e ".[dev]"

# Engagement-specific extras
pip install -e ".[dev,memory,instrumentation,linux_monitoring]"

# Everything (air-gapped lab machines only)
pip install -e ".[all,dev]"
```

The extras are intentionally optional — a bare install must still `import deepview` and run `deepview doctor`. If a command complains about a missing module, install the matching extra; do not shim or monkey-patch.

### 1.2 Verify the toolchain

```bash
deepview doctor
deepview plugins
deepview --version
```

`deepview doctor` is the canonical pre-engagement check. It reports:

- Python version and platform.
- Which optional dependencies resolved (volatility3, yara, frida, lief, capstone, bcc, netfilterqueue, ...).
- Config-file status and any symlink/size rejections.
- Plugin-registry health (built-ins loaded, entry-points discovered, plugin-dir scan results).

**Red flags:**

- `doctor` reports a plugin collision or a missing mandatory dependency.
- `plugins` lists fewer built-ins than expected — something is not importing from `plugins/builtin/__init__.py`.
- A plugin directory refused to load because it is a symlink: do not work around the check, fix the directory layout.

Capture `deepview doctor` output into the engagement log — it is part of the witness-statement evidence trail. See [witness-statement-template.md](witness-statement-template.md).

### 1.3 Configure once, pin it

Create or review `~/.deepview/config.toml`. The loader (`DeepViewConfig.load`) rejects symlinks and oversized files — good, leave those checks alone. Environment-variable overrides use the `DEEPVIEW_` prefix and are useful for per-engagement tweaks without editing the on-disk config.

Pin the config hash in your engagement notebook:

```bash
sha256sum ~/.deepview/config.toml >> engagement-log.txt
deepview --version >> engagement-log.txt
```

### 1.4 Jump kit checklist

- [ ] Responder workstation with Deep View installed and `doctor` green.
- [ ] Write-blockers for non-volatile media (hardware preferred).
- [ ] Enough sterile storage for memory + disk images plus 20% headroom.
- [ ] Tamper-evident bags and a custody-label printer or pre-printed labels.
- [ ] Signed SSH/key material for remote acquisition (see [remote-acquire-ssh](../guides/remote-acquire-ssh.md)).
- [ ] GPG key pair for manifest signing (see [chain-of-custody.md](chain-of-custody.md)).
- [ ] Approved network-mangling authorisation, if `deepview netmangle` may be used.

---

## 2. Detection and analysis

Detection is where Deep View earns its keep. The goal of this phase is to turn a vague "something is wrong" into a timeline of observed events, with classified indicators and a list of affected hosts.

### 2.1 Open a live monitoring session

On Linux hosts with `[linux_monitoring]` installed and root privileges:

```bash
deepview monitor \
    --classify classification/builtin_rules/ \
    --record ~/ir/sessions/2026-04-14-host01.sqlite \
    --format live
```

What this does:

- `TraceManager.from_context(ctx)` constructs the manager from the current `AnalysisContext`.
- The eBPF provider starts attached probes with user-space pre-filtering (raw ctypes field checks) and inline compile-time PID/UID guards when a single-PID filter is staged.
- `EventClassifier` subscribes to the `TraceEventBus`, loads YAML rules, and tags matching events with `classifications` in `MonitorEvent.metadata`.
- `SessionRecorder` batches writes into the SQLite session file with WAL enabled.
- `LiveRenderer` prints a flowing event tail with rule hits highlighted.

**Red flags in the live view:**

- `raw_syscalls` firehose with no filter — the poll thread is drowning, you are losing events. Re-run with a PID filter or narrower probe set.
- `EventClassifiedEvent` hits for ATT&CK techniques you did not expect on this host (e.g. `T1055` process injection on a database server).
- Any `drop_count` on the bus subscriber queue — events were thrown away, not buffered. See the `TraceEventBus` drop-on-overflow contract in the [architecture overview](../overview/architecture.md).

### 2.2 Scope with on-demand inspection

While the live session runs, use `deepview inspect` for targeted, non-blocking pulls:

```bash
deepview inspect process --pid 4123 --yara-rules ~/ir/rules/persistence.yar
deepview inspect memory --pid 4123 --range 0x7f0000000000:0x7f0001000000
deepview inspect file /etc/ld.so.preload
deepview inspect net --established
```

The `LiveProcessLayer` is a real `DataLayer` over `/proc/[pid]/mem`, so existing YARA, string, and IoC scanners plug in unchanged.

### 2.3 Start the dashboard for situational awareness

```bash
deepview dashboard run --layout full
```

Named built-in layouts: `network`, `full`, `minimal`, `mangle`. Or pass `--config path/to/layout.yaml` for a custom region tree.

The dashboard is read-only by default — it subscribes to the core `EventBus` for already-published events. The mangle panel (`ManglePanel`) activates only when `--enable-mangle --mangle-rules ...` is also passed (see [Containment](#3-containment)).

### 2.4 Classify and prioritise

Deep View's classifier attaches ATT&CK tags and anomaly scores to events. Export the tagged event stream for triage:

```bash
deepview replay export \
    --session ~/ir/sessions/2026-04-14-host01.sqlite \
    --format json \
    --filter 'classifications.attck =~ "T10[0-9]{2}"' \
    > host01-triage.json
```

Feed this into the technical-report [template](reporting-templates.md#technical-report).

**Paperwork to produce at end of phase 2:**

- Initial scope statement (hosts, time window, suspected TTPs).
- Recorded session file(s) with SHA-256 hashes.
- Triage event export.

---

## 3. Containment

Containment stops the bleeding without destroying evidence. Deep View's containment surface is deliberately narrow — it traces, it mangles network traffic under explicit authorisation, and it can attach Frida for runtime control.

### 3.1 Process-level tracing with stricter filters

Once you know the suspect PIDs, narrow the tracer:

```bash
deepview trace \
    --pid 4123,4127 \
    --filter 'syscall in {execve, openat, connect}' \
    --record ~/ir/sessions/contain-4123.sqlite
```

The filter parser (`parse_filter()`) lifts cheap predicates into `KernelHints` via `FilterExpr.compile() → FilterPlan`, so the kernel side does the easy work and user-space only sees relevant events.

**Red flags:** rapid `execve` fan-out from a single parent, `openat` on `/etc/cron.*`, `connect` to unexpected ASNs.

### 3.2 Network mangling (authorised engagements only)

!!! danger "Dual-use surface"
    `deepview netmangle` modifies live host traffic. Read [dual-use-statement.md](../security/dual-use-statement.md) and confirm written authorisation before proceeding. Scope: authorised security testing, CTF, honeypot, defensive research.

```bash
deepview netmangle validate --rules ~/ir/mangle/contain.yaml
deepview netmangle run \
    --rules ~/ir/mangle/contain.yaml \
    --enable-mangle \
    --install-iptables \
    --confirm
```

Guard-rails built in:

- Refuses to start without root AND `--enable-mangle` AND a non-empty ruleset.
- Prompts for confirmation unless `--confirm` is passed.
- `--dry-run` forces every verdict to ACCEPT regardless of matched action.
- Default verdict on any engine error is ACCEPT (fail-open).
- `--install-iptables` is the explicit opt-in for the NFQUEUE jump rule installer; without it, Deep View never touches iptables.

A typical containment ruleset drops egress to a C2 IP while keeping a pcap of the attempts:

```yaml
rules:
  - name: block-c2
    match: 'packet.ipv4.dst == "203.0.113.42"'
    action: drop
  - name: observe-c2-attempts
    match: 'packet.ipv4.dst == "203.0.113.42"'
    action: observe
```

Pair it with `deepview dashboard run --enable-mangle --mangle-rules ~/ir/mangle/contain.yaml` so the `ManglePanel` shows the drop-rate live.

### 3.3 Runtime instrumentation

For processes you do not want to kill yet, Frida-based instrumentation can neutralise specific behaviours without process termination. See the [instrumentation guide](../guides/extending-deepview.md) for details and consult counsel before attaching to a third-party process.

**Paperwork to produce at end of phase 3:**

- Containment decision log: what was blocked, when, by whom, on whose authority.
- Ruleset file(s) with SHA-256 hashes and signatures.
- Mangle-engine event log exported from the session.

---

## 4. Eradication

Eradication identifies the artefacts that must be removed: rootkit components, persistence hooks, injected code, anti-forensics tripwires.

### 4.1 Anti-forensics sweep

```bash
deepview plugins run detection.anti_forensics \
    --memory ~/ir/images/host01.lime \
    --out ~/ir/findings/host01-antiforensics.json
```

Findings categories the plugin emits (consume via the artefact store):

- Timestamp anomalies (timestomping).
- Log-file truncation or rotation inconsistencies.
- `LD_PRELOAD` / ptrace-based hooks.
- Hidden PIDs / hidden kernel modules via cross-view.
- `fanotify` / `audit` tampering.

### 4.2 Rootkit and injection detection

```bash
deepview plugins run detection.injection --memory ~/ir/images/host01.lime
deepview plugins run detection.encryption_key --memory ~/ir/images/host01.lime
deepview plugins run detection.anomaly --session ~/ir/sessions/2026-04-14-host01.sqlite
```

`detection.anomaly` consumes the session store and runs `AnomalyDetector.score_process` on a windowed feature dict.

**Red flags:**

- Code pages in a process that do not map back to any on-disk file.
- Kernel modules not listed in `/proc/modules` but present via the memory image.
- Encryption keys found in process memory that do not correspond to any declared service.

### 4.3 Plan eradication actions

Deep View does not itself delete files or rebuild hosts — that is the responder's call with the sysadmin. Deep View produces the artefact list and hash manifest that the eradication team works from.

**Paperwork to produce at end of phase 4:**

- Artefact list with file paths, hashes, and `DataLayer` offsets.
- ATT&CK mapping of observed TTPs.
- Eradication plan signed off by the incident lead.

---

## 5. Recovery

Recovery restores services and begins the formal reporting flow. Deep View's role here is to produce the sealed evidence package and the reports.

### 5.1 Seal acquisitions

Every `AcquisitionResult` already carries a `hash_sha256` field populated at acquisition time — see [chain-of-custody.md](chain-of-custody.md). Before archiving:

```bash
sha256sum ~/ir/images/*.lime ~/ir/sessions/*.sqlite > ~/ir/manifest.sha256
gpg --detach-sign --armor ~/ir/manifest.sha256
```

Store the signed manifest alongside the evidence in WORM storage.

### 5.2 Generate reports

```bash
# HTML technical report with timeline
deepview report \
    --session ~/ir/sessions/2026-04-14-host01.sqlite \
    --findings ~/ir/findings/ \
    --format html \
    --template technical \
    --out ~/ir/reports/host01-technical.html

# STIX 2.1 bundle for SOC ingestion
deepview report --format stix --out ~/ir/reports/host01.stix.json

# ATT&CK Navigator layer
deepview report --format attck --out ~/ir/reports/host01.attck.json
```

See [reporting-templates.md](reporting-templates.md) for the three report audiences (executive, technical, court-ready).

**Red flags:** any report section that cites data without a corresponding hash in the manifest — treat the section as unverified and rerun.

**Paperwork to produce at end of phase 5:**

- Signed SHA-256 manifest covering every evidence file.
- Executive, technical, and (if applicable) court-ready reports.
- STIX/ATT&CK artefacts handed to the SOC.

---

## 6. Post-incident / lessons learned

### 6.1 Replay the session for the debrief

`deepview replay` re-publishes stored events onto a private `TraceEventBus` at configurable speed — replayed events are indistinguishable from live ones to classifier and renderer code, so the whole dashboard works against them.

```bash
deepview replay \
    --session ~/ir/sessions/2026-04-14-host01.sqlite \
    --speed 2x \
    --dashboard
```

Use this to walk peers through the incident without touching production.

### 6.2 Update rulesets and detections

If the classifier missed a TTP that responders caught manually, write a new YAML rule, drop it in `classification/builtin_rules/` (for the shared pack) or a local rule directory, and replay the session to confirm the rule fires.

### 6.3 Close the loop

Complete the [debrief checklist](debrief-checklist.md) and archive the engagement folder to WORM storage. The replay-capable session file is the single highest-value artefact for future training — treat it as such.

---

## Cross-references

- [Chain of custody](chain-of-custody.md)
- [Reporting templates](reporting-templates.md)
- [Evidence handling](evidence-handling.md)
- [Witness statement template](witness-statement-template.md)
- [Debrief checklist](debrief-checklist.md)
- [Threat model](../security/threat-model.md)
- [OPSEC guidance](../security/opsec.md)
