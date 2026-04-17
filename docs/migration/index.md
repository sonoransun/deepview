# Migration guides

Deep View follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Major-version bumps may include breaking changes; minor-version bumps are
purely **additive**; patch releases are bug-fix-only.

!!! info "TL;DR for v0.1 → v0.2"
    **v0.2 is fully additive — every v0.1 invocation continues to work.**
    You can upgrade in place without touching your existing scripts, plugin
    code, test fixtures, or configuration files. If you never opt in to
    the new subsystems, Deep View v0.2 behaves exactly like v0.1 with a
    handful of parser bug-fixes.

## Per-version guides

| Upgrade path | Breaking changes | Recommended reading |
|---|---|---|
| [v0.1 → v0.2](0.1-to-0.2.md) | **None** | Full walkthrough of four new subsystems, six new CLI groups, thirteen new optional extras |

## Reading order

If you are upgrading across multiple releases, read the guides in order —
each one assumes you have already applied the previous migration.

## What "additive only" means in practice

A Deep View minor release promises:

- **No removed public APIs.** Classes, functions, and modules that existed
  in the previous minor are still importable and still type-check.
- **No changed public signatures.** Argument names, positional order, and
  return types of documented entry points do not change.
- **No removed or renamed CLI commands.** Every command and flag that
  shipped in the previous minor is still accepted — new functionality
  lives behind new commands, new subcommands, or new opt-in flags.
- **No silently changed defaults** for documented configuration knobs.
  Newly-added knobs default off (or to the previous hard-coded value).
- **No changed on-disk formats** for session replay databases, report
  exports, or config files written by prior versions.

Bug fixes that correct clearly-wrong behavior (for example, the
hibernation parser rejecting otherwise-valid dumps) are explicitly
carved out of this promise and called out in the relevant migration
page.

## Reverting

Any minor release is safely revertible by reinstalling the prior tag in
the same environment — Deep View does not perform on-disk upgrades, so
`pip install -e .` at an earlier tag simply reverts the import surface.

!!! tip "Pinning"
    CI pipelines consuming Deep View as a library should pin to a
    specific minor version (`deepview~=0.2.0`) rather than tracking
    `main`. Plugin authors should declare the minimum supported
    version in their own `pyproject.toml` (for example
    `"deepview>=0.2,<0.3"`).

## Reporting migration problems

If you hit anything that breaks between minor versions despite the
"additive" promise, that is a bug — please file it on the issue tracker
with the failing invocation, the previous working version, and the
Deep View version you upgraded to. See [SECURITY.md](../../SECURITY.md)
for security-sensitive regressions.
