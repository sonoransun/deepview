# Contributing to Deep View

Thanks for your interest in improving Deep View. This guide collects the
shortest path to a productive patch: where things live, how to run the dev
loop, and the conventions the project assumes.

For the full architectural tour (the `AnalysisContext` spine, the plugin
registry tiers, the trace fan-out contract, etc.) read
[`CLAUDE.md`](./CLAUDE.md) at the repo root — it is the canonical reference
and this file deliberately does not duplicate it.

---

## Where things live

Deep View is a `src/`-layout package. The high-level map:

| Path                              | What lives there                                           |
| --------------------------------- | ---------------------------------------------------------- |
| `src/deepview/cli/`               | Click command groups, formatters, the Rich dashboard       |
| `src/deepview/core/`              | `AnalysisContext`, `EventBus`, `PlatformInfo`, config tree |
| `src/deepview/interfaces/`        | Abstract base classes (one per subsystem)                  |
| `src/deepview/plugins/`           | Plugin registry + built-ins under `plugins/builtin/`       |
| `src/deepview/memory/`            | Acquisition, formats, Volatility/MemProcFS engines         |
| `src/deepview/tracing/`           | eBPF/DTrace/ETW providers, filter DSL, trace bus           |
| `src/deepview/instrumentation/`   | Frida engine + static-reassembly pipeline                  |
| `src/deepview/disassembly/`       | Capstone, Ghidra (pyhidra), Hopper wrappers                |
| `src/deepview/scanning/`          | YARA, string carving, IoC engine                           |
| `src/deepview/detection/`         | Anti-forensics, injection, anomaly scoring                 |
| `src/deepview/storage/`           | Raw layers, ECC codecs, FTL translators, filesystems       |
| `src/deepview/unlock/`            | Container unlockers (LUKS, BitLocker, FileVault, VeraCrypt) |
| `src/deepview/remote/`            | Remote acquisition providers (SSH, WinRM, iSCSI, NBD)      |
| `src/deepview/networking/`        | NFQUEUE packet mangling engine                             |
| `src/deepview/replay/`            | SessionStore, recorder, replayer                           |
| `src/deepview/reporting/`         | Timeline, HTML/MD/JSON export, ATT&CK, STIX                |
| `tests/unit/`                     | Pure-Python unit tests                                     |
| `tests/platform/{linux,macos,…}/` | Platform-gated tests                                       |
| `tests/integration/`              | End-to-end scenarios, usually `-m slow`                    |
| `docs/`                           | MkDocs site (guides, reference, cookbook, diagrams)        |

Again: if you need more than the table above, read `CLAUDE.md`.

---

## Dev install

Deep View has a lot of optional extras. For day-to-day development, install
the dev + docs extras, then add whichever subsystem extras you are touching:

```bash
# Core dev loop: tests, ruff, mypy, mkdocs
pip install -e ".[dev,docs]"

# Working on memory forensics? Pull in volatility3, yara-python, etc.
pip install -e ".[dev,docs,memory]"

# Working on instrumentation? Pull in frida, lief, capstone.
pip install -e ".[dev,docs,instrumentation]"

# Everything, kitchen sink included.
pip install -e ".[all,dev,docs]"
```

The editable install wires up the `deepview` CLI (see
`[project.scripts]` in `pyproject.toml`) and the `python -m deepview`
equivalent.

---

## Test / lint / typecheck

There is no Makefile or task runner. The three commands you run constantly:

```bash
pytest                          # full suite
pytest tests/unit/test_core/    # a subtree
pytest -m "not slow"            # skip slow/integration
pytest -m platform_linux        # platform-gated
pytest -m requires_root         # needs sudo/admin

ruff check src tests            # lint (py310, 100-char lines)
mypy src                        # strict mode
```

Every PR is expected to pass `pytest`, `ruff check`, and `mypy src` on the
changed surface. CI runs the same three. If a test is slow or needs a real
kernel/VM/tool, gate it behind a marker registered in `pyproject.toml`
(`slow`, `integration`, `requires_ghidra`, `requires_hopper`, ...).

---

## Adding a new filesystem adapter

Filesystem adapters live under `src/deepview/storage/filesystem/` and
subclass the `Filesystem` ABC in `src/deepview/interfaces/filesystem.py`.
Registration is centralised: append your class to the
`register_all()` function in `src/deepview/storage/filesystem/__init__.py`
so the CLI's `--fs-type` flag picks it up.

The adapter receives a `DataLayer` (typically already ECC-decoded and
FTL-translated) and exposes `list_dir`, `read_file`, `stat`, and an
iterator for timeline emission. See the existing ext4 and FAT32 adapters
for the shape.

Full walkthrough with a worked example:
[`docs/guides/extending-deepview.md`](./docs/guides/extending-deepview.md).

---

## Adding a new ECC codec

ECC codecs live under `src/deepview/storage/ecc/` and subclass
`ECCDecoder` in `src/deepview/interfaces/ecc.py`. The `decode()` method
takes a page+spare bytes pair and returns decoded data plus a
`BitflipReport`. Register in `src/deepview/storage/ecc/__init__.py` so
`deepview storage wrap --ecc <name>` finds it.

The existing `bch8` and `hamming` codecs are the reference
implementations. Follow the same pattern (pure Python by default, lazy
import of any C accelerator).

See [`docs/guides/extending-deepview.md`](./docs/guides/extending-deepview.md)
for the full recipe.

---

## Adding a new FTL translator

FTL translators live under `src/deepview/storage/ftl/` and subclass
`FTLTranslator` in `src/deepview/interfaces/ftl.py`. They wrap a
physical-page layer and expose a logical-page view by reading the FTL
metadata (UBI volume tables, YAFFS2 chunk headers, etc.). Register in
`src/deepview/storage/ftl/__init__.py`.

`ubi.py` and `yaffs2.py` are the reference implementations. Worked
example in [`docs/guides/extending-deepview.md`](./docs/guides/extending-deepview.md).

---

## Adding a new container unlocker

Unlockers live under `src/deepview/unlock/` and subclass `Unlocker` in
`src/deepview/interfaces/unlocker.py`. Each unlocker module exports a
module-level `UNLOCKER` attribute — that is the attribute the registry
scans for, *not* a decorator. Omitting `UNLOCKER` means your module will
silently not register.

The module layout:

```python
# src/deepview/unlock/myformat.py
from __future__ import annotations

from deepview.interfaces.unlocker import Unlocker, UnlockResult


class MyFormatUnlocker(Unlocker):
    name = "myformat"

    def detect(self, layer): ...
    def unlock(self, layer, secrets): ...


UNLOCKER = MyFormatUnlocker
```

The LUKS, BitLocker, FileVault, and VeraCrypt modules are the reference
implementations. See [`docs/guides/extending-deepview.md`](./docs/guides/extending-deepview.md).

---

## Adding a new remote acquisition provider

Providers live under `src/deepview/remote/` and subclass
`RemoteAcquisitionProvider` in `src/deepview/interfaces/remote.py`. Unlike
unlockers, providers use a factory-registration pattern: add a factory
callable to the `_PROVIDERS` dict in `src/deepview/remote/__init__.py`
keyed by the CLI name (`ssh`, `winrm`, `iscsi`, `nbd`, ...).

Providers are expected to be fail-secure: they must abort cleanly on
missing authorization-statement input, refuse to run without `--confirm`,
honour `--dry-run` by producing a plan without touching the target, and
leave a receipt behind even on partial failure.

Worked example: [`docs/guides/extending-deepview.md`](./docs/guides/extending-deepview.md).

---

## Adding a new built-in plugin

Built-in plugins live under `src/deepview/plugins/builtin/`. The pattern:

```python
# src/deepview/plugins/builtin/my_plugin.py
from __future__ import annotations

from deepview.interfaces.plugin import DeepViewPlugin, PluginResult
from deepview.plugins.base import register_plugin


@register_plugin(name="my_plugin", category="analysis")
class MyPlugin(DeepViewPlugin):
    def get_requirements(self): ...
    def run(self) -> PluginResult: ...
```

Two things to remember:

1. `@register_plugin` populates a module-global dict at import time. If
   the file is not imported, the plugin is not registered.
2. Therefore: import your module (directly or transitively) from
   `src/deepview/plugins/builtin/__init__.py`. No auto-scan, on purpose.

Entry-point plugins in third-party packages use the
`[project.entry-points."deepview.plugins"]` group in their own
`pyproject.toml` — see the plugin registry docs in `CLAUDE.md`.

---

## Documentation workflow

The docs site is MkDocs with the Material theme. With the `docs` extra
installed:

```bash
mkdocs serve                    # live-reload at http://127.0.0.1:8000
mkdocs build --strict           # fail on any broken link/nav warning
```

`--strict` is what CI runs. Fix every warning locally — do not merge a
PR that degrades the strict build.

Mermaid diagram sources live at `docs/diagrams/*.mmd` and render inline
via the Material Mermaid integration. Edit the `.mmd` source, not the
rendered SVG.

Screenshots and terminal casts live at `docs/assets/` and
`docs/casts/`. Do not commit raw `.cast` files larger than 200 KB — use
`svg-term` to render them to SVG and commit the SVG instead (the SVG is
what the docs site embeds).

---

## Re-recording asciinema casts

The canonical cast set is re-recorded by a shipped helper script:

```bash
bash docs/casts/make-casts.sh             # re-record all 8 scenarios
bash docs/casts/make-casts.sh 03-filesystem-ls   # just one
```

Install prerequisites first:

```bash
# asciinema (system package or pip)
pip install asciinema
# or:
sudo apt-get install asciinema

# svg-term-cli (npm)
npm install -g svg-term-cli
```

The script sets deterministic terminal dimensions (rows=24, cols=100) so
re-recorded casts do not produce noisy diffs. Commit both the `.cast`
(if <200 KB) and the `.svg` output — the docs embed the SVG.

---

## Optional-deps discipline

Deep View's install story is "core install is small; heavy deps are
opt-in". This is load-bearing for `deepview doctor` and the `pytest`
green-path, and for every user who does not want `volatility3` dragged
in for a CLI lint check.

**Rules for adding a new third-party dependency:**

1. **Lazy-import it.** Never `import foo` at module top-level if `foo`
   is not already in the core install. Import inside the function or
   behind a `try/except ImportError` guard. Mirror the pattern in
   `cli/app.py::doctor` and the manager modules.
2. **Declare it in `[project.optional-dependencies]`.** Put the dep in
   the right extra (`memory`, `instrumentation`, `hardware`, `firmware`,
   `gpu`, `ml`, `sigma`, `sidechannel`, `disassembly`,
   `linux_monitoring`, `storage`, `remote`, `unlock`, ...). Do not add
   to `[project.dependencies]` unless the core CLI genuinely cannot
   import without it.
3. **Surface it in `deepview doctor`.** The doctor command lists every
   optional dep by name and reports missing/present. Add a probe so
   users running `deepview doctor` can see at a glance what they are
   missing.
4. **Gate tests.** Tests that require the new dep must be marked so
   they skip cleanly when the dep is absent. Follow the existing
   `pytest.importorskip("volatility3")` / `@pytest.mark.requires_ghidra`
   patterns.

A PR that adds a heavy dep to `[project.dependencies]` or imports it at
module top-level will be asked to rework before review.

---

## Conventions

- `from __future__ import annotations` at the top of every module. PEP-604
  unions (`int | None`, not `Optional[int]`).
- Ruff target is `py310`. Line length is 100. Do not reformat unrelated
  lines.
- Mypy is in strict mode. No implicit `Any`, no untyped defs, no
  unreachable. If you need an escape hatch, prefer `cast()` over
  `# type: ignore` and leave a comment.
- Dataclasses (or pydantic models where already used) over ad-hoc dicts
  for any structured return value. Events, results, and findings are all
  dataclasses.
- Paths: `pathlib.Path` everywhere, never bare strings, never
  `os.path.join`.
- Logging: use a module-level `logger = logging.getLogger(__name__)`.
  Never print from library code — printing is a CLI concern.
- Error handling: narrow exceptions. `except Exception:` is only
  acceptable at CLI boundaries and in the trace engine's fail-open
  paths (which are documented as such).

---

## Pull request checklist

Before opening a PR, tick every box:

- [ ] Tests added or updated (unit at minimum; platform / integration
      where the change touches that surface).
- [ ] `pytest` passes locally on your platform. If you changed
      platform-gated code, run the matching `-m platform_*` marker.
- [ ] `ruff check src tests` is clean.
- [ ] `mypy src` is clean (strict mode).
- [ ] `mkdocs build --strict` passes if you touched docs, diagrams, or
      cookbook examples.
- [ ] New optional deps are lazy-imported, declared in an extra, and
      probed by `deepview doctor`.
- [ ] `CHANGELOG.md` has a bullet under the upcoming-release section.
      Follow the existing Keep-a-Changelog style (Added / Changed /
      Fixed / Removed / Security).
- [ ] Public CLI surface changes (new command, renamed flag, changed
      default) are reflected in `docs/reference/` and in the
      `deepview --help` snapshot tests.
- [ ] New built-in plugins are imported from
      `src/deepview/plugins/builtin/__init__.py`.
- [ ] New ABC implementations are registered in the matching
      `register_all()` / `_PROVIDERS` / `UNLOCKER` surface.
- [ ] Commit messages are imperative-mood one-liners; longer
      explanation in the body if the change is non-trivial.
- [ ] No secrets, tokens, personal paths, or `.env` files staged.

Thanks again — Deep View is a forensics toolkit, and the people who use
it rely on its correctness. Small, well-tested patches are much more
welcome than sprawling ones.
