# MITRE ATT&CK Mapping

Deep View's `detection/` subsystem emits typed events that carry a
`attack_ids` attribute — a tuple of MITRE ATT&CK technique IDs
identifying the behaviour that triggered the detection. The built-in
classifier rulesets (`classification/builtin_rules/*.yaml`) further
tag arbitrary tracing / scanning events with ATT&CK IDs using the
`attack_ids:` key.

This page enumerates the techniques Deep View can detect, the
responsible module, and the event schema.

!!! warning "Operational mapping, not a compliance certification"
    Detecting an ATT&CK technique is not the same as attributing an
    adversary or concluding that an intrusion occurred. A detection
    is a signal; interpretation is the analyst's job.

## Summary of coverage

Deep View currently ships detectors for the following techniques:

| Category | Technique | ATT&CK ID |
|----------|-----------|-----------|
| Persistence / defence evasion | Rootkit | [T1014](https://attack.mitre.org/techniques/T1014/) |
| Defence evasion | Direct Volume Access | [T1006](https://attack.mitre.org/techniques/T1006/) |
| Persistence | Kernel Modules and Extensions | [T1547.006](https://attack.mitre.org/techniques/T1547/006/) |
| Privilege escalation / defence evasion | Process Injection — DLL Injection | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) |
| Privilege escalation / defence evasion | Process Injection — Portable Executable Injection | [T1055.002](https://attack.mitre.org/techniques/T1055/002/) |
| Privilege escalation / defence evasion | Process Injection — Thread Execution Hijacking | [T1055.003](https://attack.mitre.org/techniques/T1055/003/) |
| Privilege escalation / defence evasion | Process Injection — Process Hollowing | [T1055.012](https://attack.mitre.org/techniques/T1055/012/) |
| Privilege escalation / defence evasion | Process Injection — Ptrace Syscall | [T1055.008](https://attack.mitre.org/techniques/T1055/008/) |
| Defence evasion | Masquerading — Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |
| Discovery | Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) |
| Credential access | Credentials from Password Stores (memory-carved) | [T1555](https://attack.mitre.org/techniques/T1555/) |
| Credential access | OS Credential Dumping — LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003.001/) |

## Detection detail

### T1014 — Rootkit (DKOM, SSDT hook, IDT/IRP hook, inline hook, hidden driver)

Deep View collects several sub-behaviours under the T1014 umbrella.
Each is surfaced as a distinct detector with its own diagnostic, but
all raise a `RootkitDetectedEvent`.

#### DKOM (Direct Kernel Object Manipulation)

| Field | Value |
|-------|-------|
| ATT&CK ID | T1014 |
| Module | `src/deepview/detection/antiforensics.py::RootkitDetector.scan_dkom` |
| Triggers | Process present in `PsActiveProcessHead` (Windows) but not in `PspCidTable`; or present in `/proc` but not in `task_struct` list traversal (Linux) |
| Event | `RootkitDetectedEvent(technique="dkom", ...)` |
| Evidence schema | `{process_name: str, pid: int, expected_in: list[str], missing_from: list[str], kernel_address: int}` |

#### SSDT (System Service Descriptor Table) hook

| Field | Value |
|-------|-------|
| ATT&CK ID | T1014 |
| Module | `src/deepview/detection/antiforensics.py::RootkitDetector.scan_ssdt` |
| Triggers | SSDT entry points outside the address range of `ntoskrnl.exe` |
| Event | `RootkitDetectedEvent(technique="ssdt_hook", ...)` |
| Evidence schema | `{ssdt_index: int, expected_module: str, actual_target: int, actual_module: str \| None}` |

#### IDT / IRP hook

| Field | Value |
|-------|-------|
| ATT&CK ID | T1014 |
| Module | `src/deepview/detection/antiforensics.py::RootkitDetector.scan_idt`, `.scan_irp` |
| Triggers | IDT entry or driver IRP major-function pointer outside the owning module |
| Event | `RootkitDetectedEvent(technique="idt_hook" \| "irp_hook", ...)` |
| Evidence schema | `{interrupt_or_irp: int, driver_name: str, expected_range: tuple[int, int], actual_target: int}` |

#### Inline hook

| Field | Value |
|-------|-------|
| ATT&CK ID | T1014 |
| Module | `src/deepview/detection/antiforensics.py::RootkitDetector.scan_inline_hook` |
| Triggers | First bytes of an exported function do not match the disk image bytes (JMP / CALL / PUSH/RET pattern at prologue) |
| Event | `RootkitDetectedEvent(technique="inline_hook", ...)` |
| Evidence schema | `{function_name: str, module: str, disk_bytes: bytes, memory_bytes: bytes, detour_target: int \| None}` |

#### Hidden kernel driver / module

| Field | Value |
|-------|-------|
| ATT&CK ID | T1014, T1547.006 |
| Module | `src/deepview/detection/antiforensics.py::RootkitDetector.scan_hidden_modules` |
| Triggers | Driver visible in one enumeration source (e.g. `PsLoadedModuleList`) but not another (e.g. `MiProcessLoaderEntry`); or a `modules` vs `lsmod` mismatch on Linux |
| Event | `RootkitDetectedEvent(technique="hidden_module", ...)` |
| Evidence schema | `{module_name: str \| None, base_address: int, size: int, sources_present: list[str], sources_absent: list[str]}` |

### T1055.001 — DLL Injection

| Field | Value |
|-------|-------|
| ATT&CK ID | T1055.001 |
| Module | `src/deepview/detection/injection.py::InjectionDetector.detect_dll_injection` |
| Triggers | DLL present in `InLoadOrderModuleList` with no matching file on disk; or DLL path is inside a writable non-system directory |
| Event | `ProcessInjectionDetectedEvent(technique="dll_injection", ...)` |
| Evidence schema | `{pid: int, process_name: str, dll_path: str, dll_base: int, disk_present: bool, dll_sha256: str}` |

### T1055.002 — Portable Executable Injection

| Field | Value |
|-------|-------|
| ATT&CK ID | T1055.002 |
| Module | `src/deepview/detection/injection.py::InjectionDetector.detect_pe_injection` |
| Triggers | Private / RWX VAD contains a PE header (MZ/PE magic) that is not reflected in `InMemoryOrderModuleList` |
| Event | `ProcessInjectionDetectedEvent(technique="pe_injection", ...)` |
| Evidence schema | `{pid: int, vad_base: int, vad_size: int, vad_protection: str, pe_sha256: str, pe_export_dir: dict \| None}` |

### T1055.003 — Thread Execution Hijacking

| Field | Value |
|-------|-------|
| ATT&CK ID | T1055.003 |
| Module | `src/deepview/detection/injection.py::InjectionDetector.detect_thread_hijack` |
| Triggers | Thread's start address points inside a private / RWX VAD, not inside a loaded module |
| Event | `ProcessInjectionDetectedEvent(technique="thread_hijack", ...)` |
| Evidence schema | `{pid: int, tid: int, start_address: int, enclosing_vad: dict, enclosing_module: str \| None}` |

### T1055.012 — Process Hollowing

| Field | Value |
|-------|-------|
| ATT&CK ID | T1055.012 |
| Module | `src/deepview/detection/injection.py::InjectionDetector.detect_hollowing` |
| Triggers | Image base in process memory differs from the disk image of the same file (code section bytes mismatch); PEB `ImageBaseAddress` does not align with the VAD containing the code |
| Event | `ProcessInjectionDetectedEvent(technique="process_hollowing", ...)` |
| Evidence schema | `{pid: int, image_path: str, disk_sha256: str, memory_sha256: str, peb_image_base: int, vad_base: int}` |

### T1036.005 — PEB Masquerading / Match Legitimate Name

| Field | Value |
|-------|-------|
| ATT&CK ID | T1036.005 |
| Module | `src/deepview/detection/antiforensics.py::MasqueradeDetector.scan_peb` |
| Triggers | `PEB.ProcessParameters.ImagePathName` does not match the on-disk file of the process, or the process name matches a system binary but the parent / path does not |
| Event | `MasqueradeDetectedEvent` |
| Evidence schema | `{pid: int, claimed_name: str, actual_image_path: str, parent_pid: int, expected_parent: str \| None}` |

### T1003.001 — LSASS Credential Dumping (detected as reader)

| Field | Value |
|-------|-------|
| ATT&CK ID | T1003.001 |
| Module | `src/deepview/detection/encryption_keys.py::LsassAccessDetector` (Windows) |
| Triggers | A process opens a handle to lsass.exe with `PROCESS_VM_READ` that is not on the allow-list; detected live via ETW provider |
| Event | `SuspiciousAccessEvent(target="lsass", ...)` |
| Evidence schema | `{pid: int, process_name: str, access_rights: list[str], target_pid: int}` |

### T1555 — Credentials from Password Stores

| Field | Value |
|-------|-------|
| ATT&CK ID | T1555 |
| Module | `src/deepview/detection/encryption_keys.py::KeyMaterialScanner` |
| Triggers | Memory scan finds RSA / AES key schedule patterns, SSH host keys, KeePass master keys |
| Event | `KeyMaterialFoundEvent` |
| Evidence schema | `{key_type: str, pid: int, vaddr: int, confidence: float, excerpt_redacted: bool}` |

## Using the ATT&CK mapping

### Navigator layer export

```bash
deepview report generate --session <id> --format attack-navigator --out layer.json
```

Open the resulting JSON in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
to visualise the techniques triggered during an engagement.

### Filtering by technique

```bash
deepview replay query --session <id> --attack T1055.012
```

Replays the session and returns only events whose `attack_ids` tuple
contains `T1055.012`.

### Custom classifier rules with ATT&CK tags

YAML ruleset snippet:

```yaml
- id: suspicious-raw-socket
  match: 'syscall.name == "socket" and args.type & SOCK_RAW'
  attack_ids: ['T1040']       # Network Sniffing
  severity: medium
```

See `src/deepview/classification/ruleset.py::Rule` for the full rule
schema and `src/deepview/classification/builtin_rules/` for shipped
examples.

## What is **not** mapped

- **Tactics** — Deep View events carry technique IDs, not tactic
  labels; derive tactics from the MITRE ATT&CK JSON at report time.
- **Sub-techniques below the ones listed** — each detector claims the
  specific sub-technique it models; behaviours that span multiple are
  emitted as multiple events.
- **Mobile and ICS matrices** — Deep View targets the Enterprise
  matrix only.
