# Deep View examples

Runnable Python scripts demonstrating the Deep View forensics toolkit
APIs. Every script is self-contained, uses ``argparse`` with ``--help``,
lazy-imports optional dependencies, and prints friendly errors when a
required extra is missing.

Run any example with:

```bash
python examples/<name>.py --help
```

The default argument values use synthetic in-memory data where possible,
so the scripts that have no required fixture run out of the box against
a bare core install (`pip install -e .`). Scripts that *need* real
fixtures (memory dumps, encrypted containers, remote hosts) say so in
their docstring and below.

## Index

| Script | What it shows | Extras required | Needs fixture? |
|---|---|---|---|
| [`00_doctor.py`](00_doctor.py) | Programmatic `deepview doctor` — platform info + extras probe. | none | no |
| [`01_open_raw_image.py`](01_open_raw_image.py) | Open any memory image via `MemoryManager.open_layer`; hex-dump the head. | none (some formats need `storage`) | auto-generates if omitted |
| [`02_compose_nand_stack.py`](02_compose_nand_stack.py) | RawNANDLayer -> ECCDataLayer -> PartitionLayer -> FAT12. The full composition walkthrough. | none | no (synthetic) |
| [`03_auto_open.py`](03_auto_open.py) | One-line `auto_open(ctx, path)`: format detection + partitions + filesystems. | none | auto-generates if omitted |
| [`04_unlock_luks.py`](04_unlock_luks.py) | LUKS passphrase unlock through the offload-driven KDF path. | `containers` | yes (LUKS image + passphrase env) |
| [`05_unlock_auto.py`](05_unlock_auto.py) | `context.unlocker.auto_unlock`: memory-key scan + passphrases + keyfiles across every registered unlocker. | `containers` | yes (container image) |
| [`06_offload_pbkdf2.py`](06_offload_pbkdf2.py) | Submit a batch of PBKDF2 jobs, await results, subscribe to submit/complete events. | none | no |
| [`07_offload_argon2.py`](07_offload_argon2.py) | Same as 06 but Argon2id — memory-hard KDF on the process pool. | `containers` (`argon2-cffi`) | no |
| [`08_remote_image_dryrun.py`](08_remote_image_dryrun.py) | Build a `RemoteEndpoint`, construct the provider via `factory.build_remote_provider`, report availability — no network traffic. | none (`remote_acquisition` to *actually* run) | no |
| [`09_register_custom_plugin.py`](09_register_custom_plugin.py) | Write a `@register_plugin`-decorated `DeepViewPlugin`; run it against a synthetic layer. | none | no |
| [`10_event_bus_subscriber.py`](10_event_bus_subscriber.py) | Subscribe sync and async handlers to `OffloadJobCompletedEvent` and `ContainerUnlockedEvent`. | none | no |
| [`11_filesystem_walk.py`](11_filesystem_walk.py) | Walk a filesystem, emit body-file-style timeline. | none (native adapters); `storage` for TSK/APFS/etc. | no |
| [`12_carve_unallocated.py`](12_carve_unallocated.py) | Iterate `Filesystem.unallocated`, run `StringCarver` on each region. | none | no |

## Conventions

* Every script opens with a module-level docstring explaining what it
  demonstrates and any prerequisites.
* Inputs are parsed via `argparse`; running with `--help` prints the
  usage block.
* Optional dependencies are imported lazily *inside* ``main()`` or the
  function that needs them. When missing, scripts print a friendly
  `pip install -e '.[<extra>]'` hint and exit non-zero rather than
  raising an uncaught ``ImportError``.
* Synthetic data lives in [`_synthetic.py`](_synthetic.py) so it can be
  shared between scripts that need an in-memory FAT12 image, a NAND
  dump with Hamming ECC, or a `BytesLayer`.

## Related documentation

See [docs/guides/](../docs/guides/) for longer-form walkthroughs and
[docs/reference/](../docs/reference/) for API reference.
