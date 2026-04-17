# CI/CD

Use Deep View in CI to validate that the toolkit itself still builds,
that `deepview doctor` reports the expected capability matrix, and that
your plugins don't regress against the stable interface boundary.

!!! tip "Two audiences for this page"
    If you are a **Deep View contributor**, this is the recipe CI uses
    to gate pull requests. If you are a **downstream operator** who has
    written plugins against the `DeepViewPlugin` ABC, the same recipe
    template lets you smoke your plugins against the current release
    before rolling it onto lab hardware.

## GitHub Actions — reference workflow

The workflow below runs on every push and pull request. It installs
Deep View with the `[dev]` extras plus a platform-appropriate
capability set, caches the pip wheel cache, executes `deepview doctor`,
and runs a tiny plugin smoke that validates a built-in plugin's
`PluginResult`.

```yaml
name: deepview-ci

on:
  push:
    branches: [ main ]
  pull_request:
  schedule:
    - cron: "0 6 * * 1"    # Weekly sanity against upstream deps.

permissions:
  contents: read

jobs:
  smoke:
    name: smoke / ${{ matrix.os }} / py${{ matrix.python }}
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ ubuntu-22.04, macos-14, windows-2022 ]
        python: [ "3.10", "3.11", "3.12" ]
        include:
          - os: ubuntu-22.04
            extras: "dev,memory,tracing,detection,sigma,disassembly"
          - os: macos-14
            extras: "dev,memory,detection,sigma,disassembly"
          - os: windows-2022
            extras: "dev,memory,detection,sigma,disassembly"
        exclude:
          # Frida wheels lag on the freshest Python on macOS runners.
          - os: macos-14
            python: "3.12"
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
          cache: pip
          cache-dependency-path: |
            pyproject.toml

      - name: Install apt build deps (Linux)
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install --yes --no-install-recommends \
              build-essential libssl-dev libffi-dev \
              libcapstone-dev libmagic-dev libyara-dev libtsk-dev

      - name: Install brew build deps (macOS)
        if: runner.os == 'macOS'
        run: |
          brew install capstone yara libmagic sleuthkit

      - name: Install Deep View
        shell: bash
        run: |
          python -m pip install --upgrade pip
          python -m pip install -e ".[${{ matrix.extras }}]"

      - name: Ruff + mypy (Linux only — saves matrix minutes)
        if: runner.os == 'Linux' && matrix.python == '3.11'
        run: |
          ruff check src tests
          mypy src

      - name: Unit tests (skip requires_root / integration / slow)
        shell: bash
        run: |
          pytest -m "not slow and not integration and not requires_root"

      - name: Doctor gate
        shell: bash
        run: |
          deepview doctor --strict --output json > doctor.json
          python - <<'PY'
          import json, sys
          r = json.loads(open("doctor.json").read())
          missing = [c for c, v in r["capabilities"].items()
                     if v.get("expected") and not v.get("available")]
          if missing:
              print("Missing expected capabilities:", missing)
              sys.exit(1)
          PY

      - name: Plugin smoke
        shell: bash
        run: |
          deepview plugins list --format json > plugins.json
          python - <<'PY'
          import json, sys
          p = json.loads(open("plugins.json").read())
          # We expect at least the builtin process / file / net inspectors.
          required = {"inspect.process", "inspect.file", "inspect.net"}
          found = {entry["name"] for entry in p}
          missing = required - found
          assert not missing, f"Builtins missing: {missing}"
          PY
          deepview plugin run inspect.net --format json > inspect-net.json
          python -c "import json; r=json.load(open('inspect-net.json')); \
                     assert r['status']=='success', r"

      - name: Upload doctor report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: doctor-${{ matrix.os }}-py${{ matrix.python }}
          path: doctor.json
          retention-days: 14
```

## Caching pip extras

`actions/setup-python@v5` already caches the pip **wheel** cache keyed
by `pyproject.toml`. Two extra knobs are worth knowing:

- **Wheelhouse reuse across jobs** — if you build an image in CI (as
  in [docker.md](docker.md)), cache `/tmp/wheels` between runs and
  skip the wheel build whenever `pyproject.toml`'s hash matches:

  ```yaml
  - name: Cache wheelhouse
    uses: actions/cache@v4
    with:
      path: /tmp/wheels
      key: wheels-${{ runner.os }}-${{ hashFiles('pyproject.toml') }}
  ```

- **Capstone / LIEF prebuilt wheels** are big (~80 MB combined). The
  wheel cache handles them, but keep an eye on the 10 GB GitHub
  Actions per-repo cache ceiling; prune older entries with
  `gh actions-cache delete` in a weekly workflow.

## Matrix coverage

The matrix above is deliberately asymmetric:

| Platform | Why it's in the matrix | What we deliberately skip |
| --- | --- | --- |
| `ubuntu-22.04` | Primary development target, Linux-only code paths (eBPF, NFQUEUE, LiME). | None — this is the reference platform. |
| `macos-14` | macOS-specific code paths (DTrace, kextstat, osxpmem). | `tracing`, `linux_monitoring` extras — they intentionally refuse to install. |
| `windows-2022` | Windows-specific code paths (ETW, WinPMem, PE parsing). | `tracing`, `linux_monitoring`, `instrumentation` (Frida's CI wheels lag here). |

!!! note "`requires_root` tests stay off CI"
    The `requires_root` marker gates tests that need raw `/dev/mem`
    or kernel module load; those live in the release-gate job that
    runs on a self-hosted lab runner, not in PR CI. Never grant the
    hosted runner privileged scope.

## Gating behaviour

Three gates should fail the build:

1. **`deepview doctor --strict`** returns non-zero if any *expected*
   capability is unavailable. "Expected" is determined by the extras
   installed, so the matrix cell controls the gate implicitly.
2. **Plugin smoke** — the workflow re-runs a known-cheap built-in
   (`inspect.net`) and asserts its `PluginResult.status`. This
   catches interface-level regressions without shelling out to live
   capture.
3. **`pytest -m "not slow and not integration and not requires_root"`**
   — fast lane. The slow / integration / requires_root cuts live in
   a separate nightly workflow triggered by the scheduled cron.

## Release workflow — adding image publication

The PR workflow above deliberately stops at a smoke. Publishing the
Deep View Docker image to a registry is a separate workflow that runs
on tag pushes only:

```yaml
name: deepview-release

on:
  push:
    tags: [ "v*" ]

permissions:
  contents: read
  packages: write
  id-token: write   # For OIDC-signed publishing (cosign).

jobs:
  image:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ github.ref_name }}
            ghcr.io/${{ github.repository }}:latest
          build-args: |
            DEEPVIEW_VERSION=${{ github.ref_name }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
      - name: Sign image with cosign
        uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign --yes \
              ghcr.io/${{ github.repository }}:${{ github.ref_name }}
```

## Downstream plugin CI

If you are shipping a third-party plugin:

1. Add Deep View as a test dependency:
   `deepview[dev,memory] @ git+https://github.com/example/deepview@v0.2.0`.
2. In your test fixtures, use `AnalysisContext.for_testing()` — it
   produces a context with no live subsystems wired up, suitable for
   unit tests.
3. Copy the *Plugin smoke* step above and swap the plugin name for
   your own. A green smoke means the entry-point registration works
   end-to-end.

## Next

- Productionise the image you just built in CI with the
  [Kubernetes recipe](kubernetes.md).
- For offline-first environments that can't reach CI at all, see the
  [isolated lab](isolated-lab.md) setup.
