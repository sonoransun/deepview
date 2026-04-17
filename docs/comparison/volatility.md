# Deep View vs Volatility 3

!!! abstract "Deep View IS a Volatility 3 wrapper for memory plugins."
    The memory-forensics story in Deep View is not an independent re-implementation of Volatility.
    The `deepview.memory.analysis.volatility` module imports `volatility3` as a library, builds a
    `volatility3.framework.contexts.Context` from a Deep View `DataLayer`, and runs vol3 plugins
    directly. When you run `deepview memory scan --plugin windows.pslist`, you are running
    Volatility 3.

That framing matters because it tells you what *not* to expect from Deep View: we do not fork
Volatility's plugin catalogue, we do not re-implement its symbol handling, and we do not try to
outperform it on pure memory-image analysis.

## One-paragraph recap of Volatility 3

Volatility 3 (`volatility3` on PyPI) is the open-source memory forensics framework maintained by
the Volatility Foundation. It ships a plugin-based architecture with rich OS profile support
(Windows, Linux, macOS), a symbol-table abstraction driven by `.json.xz` ISF files, and a large
catalogue of first-party plugins covering process lists, network state, registry, kernel objects,
malware-hunting primitives (`malfind`, `yarascan`), and much more.

It is the authoritative tool for memory image analysis. Nothing Deep View does replaces it.

## The two plugin models, side by side

### Volatility 3's plugin model

- A `PluginInterface` subclass with a `run()` method returning a `TreeGrid`.
- Requirements declared via `get_requirements()` returning a list of `RequirementInterface`
  instances (layer names, symbol tables, integer arguments, etc.).
- Output is a typed row-grid that the vol3 renderer system turns into a table (or JSON).
- Plugins discover one another through `framework.class_subclasses`.
- Lifetime of state is a `Context` object that carries layers, symbol tables, and config.

### Deep View's plugin model

- A `DeepViewPlugin` subclass (`src/deepview/interfaces/plugin.py`) with a `run()` method
  returning a `PluginResult`.
- Requirements declared via `get_requirements()` returning a list of Deep View `Requirement`
  objects (context, layer, config-key, capability-gated).
- Output is a `PluginResult` with structured findings, artifacts, and event-bus publications.
- Plugins are discovered by the three-tier `PluginRegistry` (built-in decorator, entry points,
  directory scan) described in the [architecture guide](../architecture/containers.md).
- Lifetime of state is an `AnalysisContext` that owns layers, events, platform detection, and
  config.

These two systems are *deliberately* shaped similarly. That lets a Deep View plugin delegate
cleanly to a Volatility plugin without forcing users to juggle two mental models.

## Invoking a Volatility plugin from Deep View

The thin bridge lives in `deepview.memory.analysis.volatility`. At a high level:

1. Deep View loads the memory image into a `DataLayer` via `MemoryManager`.
2. The bridge constructs a vol3 `Context` and registers the image as a `physical_layer`.
3. It resolves OS symbols (either from bundled ISF files or the vol3 symbol cache).
4. It imports the requested plugin class via `framework.import_files` and instantiates it.
5. It runs the plugin and converts the resulting `TreeGrid` into Deep View artifacts.

At the CLI this is:

```bash
deepview memory load /path/to/image.lime
deepview memory scan --plugin windows.pslist
deepview memory scan --plugin linux.bash
deepview memory scan --plugin windows.malfind --pid 1234
```

The plugin name is the exact vol3 dotted path. If vol3 accepts
`--plugin windows.netscan.NetScan`, so do we.

!!! note "We call vol3 as a library, not a subprocess"
    There is no `subprocess.run(["vol", ...])` anywhere in the memory engine. The Volatility
    framework is imported directly so that errors are catchable Python exceptions, layers are
    shared objects rather than file paths, and plugin output is a typed data structure instead of
    text that has to be re-parsed. If you see a PR that adds a `vol` subprocess call, reject it.

## When to use Volatility 3 standalone

Reach for vol3 directly when:

- You're doing ad-hoc memory analysis from a shell and don't need anything downstream.
- You're writing or debugging a *new* vol3 plugin — develop against the framework itself, then
  register it with Deep View once it's stable.
- You need vol3-specific CLI features: TUI `volshell`, interactive symbol downloads, or the
  native renderer flags.
- You don't want Python 3.10+ or the Deep View dependency footprint.

## When Deep View adds value

Reach for Deep View when:

- The memory plugin's output is step one of a pipeline (classification, reporting, ATT&CK
  mapping, STIX export).
- You want to run the same plugin across multiple images in parallel via
  `deepview memory scan --batch`.
- You want vol3 output to show up on the `EventBus` so live dashboards and classifiers see it.
- You're combining memory analysis with tracing, disassembly, or instrumentation in the same
  session — one `AnalysisContext`, one config tree, one artifact store.
- You want vol3 plugin findings converted into a report alongside other subsystems.

## Compatibility surface

- **Version pinning.** Deep View declares `volatility3` under the `[memory]` extra with a
  compatible-release constraint. A minor-version bump on our side is expected to follow vol3
  upstream minor releases; patch releases should Just Work.
- **ISF files.** Deep View reuses the vol3 symbol cache directory (`~/.cache/volatility3/` by
  default). If you've already analysed images with vol3, your symbol tables carry over.
- **Custom plugins.** If you've written a vol3 plugin, you don't need to port it — it's
  discoverable by the bridge exactly as it would be by vol3 itself. Deep View's own plugin
  system is *additive*, not a replacement.

## Example: round-trip from image to report

```bash
# 1. Acquire (or provide) a memory image
deepview memory load /evidence/host-42.lime --layer primary

# 2. Run a vol3 plugin via Deep View
deepview memory scan --plugin linux.pslist --layer primary

# 3. Run a second plugin; both results land on the same EventBus
deepview memory scan --plugin linux.bash --layer primary

# 4. Export a unified report
deepview report generate --format html --out /tmp/host-42.html
```

Under the hood, steps 2 and 3 are Volatility 3 doing what Volatility 3 does. Step 4 is Deep View
doing something Volatility 3 doesn't: producing a cross-subsystem report with timelines,
ATT&CK coverage, and classification hits.

## Limitations we own

- **Plugin parameters are a passthrough.** If a vol3 plugin takes an obscure flag that we
  haven't surfaced, you may need to use the vol3 CLI until we wire it.
- **Progress reporting.** vol3's progress bar is not always forwarded to the Rich live view.
- **Windows symbol auto-download** depends on vol3's own behaviour; Deep View does not proxy it.

!!! warning "No silent re-implementations"
    If you ever find Deep View returning a result that *looks* like a vol3 plugin but is actually
    a Deep View re-implementation, file a bug. The project's policy is to defer to vol3 for
    anything in its wheelhouse.

## Further reading

- [Memory subsystem architecture](../architecture/remote-acquisition.md)
- [Plugin system](../architecture/containers.md)
- [Volatility 3 upstream documentation](https://volatility3.readthedocs.io/)
