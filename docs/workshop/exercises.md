# Workshop exercises

Six hands-on exercises. Each one has: objective, fixtures, steps, expected
output, solution snippet, and common pitfalls. The facilitator should work
through Exercise 1 on the projector, then let the room work on the rest with
facilitator support.

Fixture files referenced below live under
`tests/fixtures/workshop/`. The generator scripts that produced them are at
`tests/fixtures/workshop/generate.py`; if you need to regenerate them in the
lab, run:

```bash
python tests/fixtures/workshop/generate.py --output tests/fixtures/workshop/
```

---

## Exercise 1 — Open a raw memory dump

**Objective.** Load a raw Linux memory image into Deep View and confirm the
layer is valid.

**Fixture.** `tests/fixtures/workshop/mem-small.lime` (512 MB, LiME format).

**Steps.**

1. Activate your virtual environment.
2. From the workshop repo root, open a Python REPL:

   ```bash
   python
   ```

3. Build a context and load the image:

   ```python
   from deepview.core.context import AnalysisContext
   from deepview.memory.manager import MemoryManager

   ctx = AnalysisContext.for_testing()
   manager = MemoryManager.from_context(ctx)
   layer = manager.load("tests/fixtures/workshop/mem-small.lime")
   print(layer)
   print("valid?", layer.is_valid())
   print("size:", layer.size)
   ```

**Expected output.**

```
<LiMELayer path='tests/fixtures/workshop/mem-small.lime' size=536870912>
valid? True
size: 536870912
```

**Solution snippet.** The two-line version:

```python
ctx = AnalysisContext.for_testing()
layer = MemoryManager.from_context(ctx).load("tests/fixtures/workshop/mem-small.lime")
assert layer.is_valid()
```

**Common pitfalls.**

- Path not found — check you ran the generator script, and use an absolute
  path if your `cwd` isn't the repo root.
- `ImportError: No module named 'volatility3'` — you missed the `[memory]`
  extra. `pip install -e '.[dev,memory]'` and retry.

---

## Exercise 2 — List processes with `pslist`

**Objective.** Run the `pslist` plugin against the memory image you loaded
in Exercise 1, first from the CLI and then from the Python API.

**Fixture.** Same image as Exercise 1.

**Steps (CLI).**

```bash
deepview memory analyze \
    --image tests/fixtures/workshop/mem-small.lime \
    --plugin pslist \
    --format table
```

**Expected output (abridged).**

```
PID    PPID   Name              State    Threads  Start time
1      0      systemd           S        1        2024-11-05 09:01:12
2      0      kthreadd          S        1        2024-11-05 09:01:12
456    1      sshd              S        1        2024-11-05 09:02:44
812    456    bash              S        1        2024-11-05 09:05:01
...
1337   1      evil_daemon       S        4        2024-11-05 09:12:30
```

Note the `evil_daemon` line — remember it, we come back to it in Exercise 3.

**Steps (Python).**

```python
from deepview.core.context import AnalysisContext
from deepview.memory.manager import MemoryManager

ctx = AnalysisContext.for_testing()
manager = MemoryManager.from_context(ctx)
manager.load("tests/fixtures/workshop/mem-small.lime")

result = manager.run_plugin("pslist")
for row in result.rows:
    print(f"{row.pid:>5}  {row.name:<20}  {row.state}")
```

**Solution snippet.** For the "print suspicious-looking names" pattern:

```python
suspicious = [r for r in result.rows if r.name.startswith("evil_")]
for r in suspicious:
    print("suspicious:", r.pid, r.name)
```

**Common pitfalls.**

- `pslist` takes a profile guess. On the workshop fixture the guess always
  resolves; on real images, pass `--profile` explicitly.
- The `table` formatter truncates long command lines. Use `--format json`
  when you need the full data.

---

## Exercise 3 — Detect a rootkit with `anti_forensics`

**Objective.** Use the `anti_forensics` detection module to flag the hidden
`evil_daemon` process.

**Fixture.** Same image.

**Background.** The fixture injects `evil_daemon` into the memory image via
a technique that unlinks it from the task-list but leaves it present in
kernel threads. `pslist` still finds it (the fixture is conservative),
but `anti_forensics` also flags it by comparing multiple process
enumeration primitives against each other.

**Steps.**

```bash
deepview detect anti-forensics \
    --image tests/fixtures/workshop/mem-small.lime \
    --format table
```

**Expected output.**

```
Finding                        PID     Severity  Evidence
Task-list / thread-list skew   1337    HIGH      present in thread_list,
                                                 absent from task_struct.next chain
Suspicious kthread name        1337    MEDIUM    name matches pattern 'evil_*'
```

**From Python.**

```python
from deepview.detection.anti_forensics import AntiForensicsDetector

detector = AntiForensicsDetector.from_context(ctx)
findings = detector.scan(layer)
for f in findings:
    print(f.severity, f.pid, f.kind, f.evidence)
```

**Solution snippet.** To gate a runbook step on detection output:

```python
critical = [f for f in findings if f.severity == "HIGH"]
if critical:
    raise SystemExit(f"Rootkit indicators: {len(critical)} finding(s); halting.")
```

**Common pitfalls.**

- The detector needs `pslist` output cached; running `pslist` first speeds
  things up but isn't required (the detector runs it internally if missing).
- HIGH-severity findings fail the command in CI mode (`--ci`); this is on
  purpose.

---

## Exercise 4 — Unlock a synthetic LUKS volume

**Objective.** Open a LUKS1 volume and mount its cleartext layer for
scanning.

**Fixture.** `tests/fixtures/workshop/luks-small.img`. Password:
`workshop-fixture-password-do-not-reuse`.

**Steps (CLI).**

```bash
deepview memory wrap \
    --image tests/fixtures/workshop/luks-small.img \
    --wrapper luks \
    --password-stdin <<< 'workshop-fixture-password-do-not-reuse' \
    --export /tmp/workshop-luks-cleartext.img
```

**Expected output.**

```
INFO  detected LUKS1 header, v1.3
INFO  key slot 0 accepted
INFO  cleartext layer is 62914560 bytes (60 MiB)
INFO  exported to /tmp/workshop-luks-cleartext.img
```

**From Python.**

```python
from deepview.memory.wrappers.luks import LUKSWrapper

layer = manager.load("tests/fixtures/workshop/luks-small.img")
cleartext = LUKSWrapper.unwrap(
    layer,
    password=b"workshop-fixture-password-do-not-reuse",
)
print("cleartext size:", cleartext.size)
```

**Solution snippet.** To chain the cleartext layer straight into a scan:

```python
from deepview.scanning.strings import StringScanner

scanner = StringScanner(min_length=8, charset="ascii")
hits = list(scanner.scan(cleartext))
print(f"{len(hits)} strings found")
```

**Common pitfalls.**

- LUKS2 vs LUKS1 — the fixture is LUKS1 so the wrap succeeds synchronously.
  LUKS2 goes through `argon2id`, which can take several seconds.
- Never paste the password on the command line; use `--password-stdin` or
  the keyring backend.

---

## Exercise 5 — Walk a FAT filesystem

**Objective.** Mount a FAT32 image as a file-tree layer and recover a
deleted file.

**Fixture.** `tests/fixtures/workshop/fat32-small.img` — 32 MB FAT32 with a
small directory structure and one deliberately-deleted file,
`/reports/draft.txt`.

**Steps (CLI).**

```bash
deepview fs walk \
    --image tests/fixtures/workshop/fat32-small.img \
    --fs fat32 \
    --format table
```

**Expected output (abridged).**

```
PATH                              SIZE    STATE      FIRST CLUSTER
/                                 -       dir        2
/README.txt                       412     allocated  5
/reports/                         -       dir        7
/reports/final.txt                1024    allocated  9
/reports/draft.txt                842     deleted    12
/photos/                          -       dir        15
...
```

**From Python.**

```python
from deepview.fs.fat import FATLayer

fs = FATLayer.open("tests/fixtures/workshop/fat32-small.img")
for entry in fs.walk():
    tag = "del" if entry.deleted else "ok"
    print(f"{tag} {entry.size:>6} {entry.path}")

# Recover the deleted draft.
deleted = fs.find("/reports/draft.txt")
assert deleted.deleted
data = fs.read_deleted(deleted)
print(data[:80])
```

**Expected recovered bytes (first line).**

```
b'DRAFT 2024-11-05 -- internal only -- do not distribute.\n'
```

**Solution snippet.** Recover every deleted file in one pass:

```python
from pathlib import Path

out_dir = Path("/tmp/workshop-fat-recovered")
out_dir.mkdir(exist_ok=True)
for entry in fs.walk():
    if entry.deleted:
        (out_dir / Path(entry.path).name).write_bytes(fs.read_deleted(entry))
```

**Common pitfalls.**

- FAT32 reuses cluster chains aggressively on small volumes. Recovered
  bytes may be partially overwritten; the recovered file's tail can be
  garbage.
- The walker follows long-file-name entries; short 8.3 names are surfaced
  in `entry.short_name`.

---

## Exercise 6 — Write a custom plugin

**Objective.** Write a tiny Deep View plugin that lists open files for a
given process in a running memory image. Load it through the directory-scan
tier so you don't need to reinstall.

**Fixture.** Same memory image.

**Steps.**

1. Create a plugin file:

   ```bash
   mkdir -p ~/.deepview/plugins
   $EDITOR ~/.deepview/plugins/openfiles.py
   ```

2. Paste the following:

   ```python
   """List open files for a given PID from a memory image."""
   from __future__ import annotations

   from dataclasses import dataclass

   from deepview.interfaces.plugin import (
       DeepViewPlugin,
       PluginRequirement,
       PluginResult,
   )
   from deepview.plugins.base import register_plugin


   @dataclass
   class OpenFile:
       fd: int
       path: str


   @register_plugin(
       name="openfiles",
       version="0.1.0",
       description="List open files for a given PID.",
       tags=("memory", "workshop"),
   )
   class OpenFilesPlugin(DeepViewPlugin):
       def get_requirements(self) -> list[PluginRequirement]:
           return [
               PluginRequirement.memory_layer(),
               PluginRequirement.argument("pid", kind=int),
           ]

       def run(self) -> PluginResult:
           pid = int(self.args["pid"])
           memory = self.context.layers.get("primary")
           # Use the process-table helper to find the task_struct for pid.
           from deepview.memory.linux.tasks import find_task
           task = find_task(memory, pid)
           if task is None:
               return PluginResult.error(f"no task with pid {pid}")
           open_files = [
               OpenFile(fd=fd, path=path)
               for fd, path in task.iter_files()
           ]
           return PluginResult.table(
               columns=("fd", "path"),
               rows=[(f.fd, f.path) for f in open_files],
           )
   ```

3. Confirm the plugin registers:

   ```bash
   deepview plugins list | grep openfiles
   ```

   You should see:

   ```
   openfiles  0.1.0  directory-scan  List open files for a given PID.
   ```

4. Run it:

   ```bash
   deepview plugins run openfiles \
       --image tests/fixtures/workshop/mem-small.lime \
       --arg pid=1337
   ```

**Expected output.**

```
fd    path
0     /dev/null
1     /tmp/evil_daemon.log
2     /tmp/evil_daemon.log
3     /tmp/secrets/stolen.txt
4     socket:[42351]
```

**Solution.** The plugin as written is the solution. The interesting line
is `@register_plugin(name="openfiles", ...)` — the decorator pushes the
class into the global `_REGISTERED_PLUGINS` dict at import time.

**Common pitfalls.**

- If your plugin file is symlinked, the registry refuses to load it. Copy
  the file rather than linking it.
- `deepview plugins list` lazy-loads the registry. If you edit the plugin,
  the next command picks it up — there's no daemon to restart.
- If you name your file `_openfiles.py` (leading underscore) the scanner
  skips it. Remove the underscore.

---

## Wrap-up

By the end of these six exercises you have:

1. Loaded a memory image.
2. Listed processes.
3. Detected a planted rootkit.
4. Unlocked a LUKS volume.
5. Walked a FAT filesystem and recovered a deleted file.
6. Written and run your own plugin.

That is the full Deep View workflow. Everything else — tracing, VM
introspection, Frida, mangle, reporting — composes the same way: build a
context, grab a subsystem manager from it, run primitives, handle events,
write artefacts. The [Cookbook](../cookbook/index.md) has worked examples of
each.
