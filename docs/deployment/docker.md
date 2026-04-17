# Docker

Deep View ships a multi-stage `Dockerfile` at the repo root. This page
walks through building it, running it against a mounted evidence
directory, and the privilege escalations that become necessary once you
want live capture instead of offline analysis.

!!! warning "Images inherit the full toolkit"
    The default image bundles Volatility 3, YARA, Frida, LIEF, Capstone,
    and the Linux live-monitoring stack. **Do not publish this image to
    a registry that is readable by untrusted tenants.** Treat it the
    same way you would treat a signed forensics ISO. See
    [operator OPSEC](../security/opsec.md) for chain-of-custody
    obligations that extend to container images of the toolkit itself.

## Quick start

```bash
# Build (takes ~5 minutes on a warm cache; first build ~15-20 minutes).
docker build \
    --tag deepview:0.2.0 \
    --tag deepview:latest \
    --build-arg DEEPVIEW_VERSION=0.2.0 \
    .

# Smoke test — prints the CLI help banner.
docker run --rm deepview:latest --help

# Run `doctor` against the default (unprivileged) configuration.
docker run --rm deepview:latest doctor
```

`deepview doctor` inside the container reports which capabilities are
available. Expect most live-capture subsystems to show as *unavailable*
until you escalate privileges — see the matrix below.

## Multi-stage layout

The bundled `Dockerfile` has two stages:

| Stage | Base image | Purpose |
| --- | --- | --- |
| `builder` | `python:3.11-slim` + build-essential + `libssl-dev` / `libcapstone-dev` / `libtsk-dev` / … | Runs `pip wheel` for every extras group we want at runtime, dumps wheels into `/wheels`. |
| `runtime` | `python:3.11-slim` + only the shared-object runtime counterparts | `pip install --no-index --find-links /wheels deepview[...]` then drops to the `deepview` user. |

Splitting the stages keeps the runtime image free of `gcc`, header
packages, and `git`. The final image is ~450 MB compressed versus
~1.8 GB for a single-stage build.

### Optimisation choices

- **Slim base, not Alpine.** Alpine's `musl` breaks several native
  wheels (`volatility3`'s crypto path, `leechcore`). The space saving
  is ~60 MB, not worth the breakage.
- **Wheelhouse intermediate.** Resolving extras once in the builder
  means the runtime install is offline and reproducible; it also lets
  us delete `/wheels` after install so the wheels don't linger as a
  layer.
- **Extras curated.** The runtime stage installs
  `memory,tracing,instrumentation,detection,sigma,disassembly,storage,compression,ecc,containers,remote_acquisition`
  — roughly `[all]` minus `hardware`, `firmware`, `gpu`, `ml`,
  `sidechannel`, `docs`. Each excluded group would pull in
  multi-hundred-megabyte native deps (`pycuda`, `chipsec`, `xgboost`)
  that only a minority of operators use. Add them back with a custom
  build arg if you need them:

  ```bash
  docker build \
      --build-arg EXTRA_EXTRAS="gpu,ml" \
      --tag deepview:0.2.0-gpu \
      .
  ```

- **Apt cache deleted.** Both stages end in
  `rm -rf /var/lib/apt/lists/*`. Do not re-enable the cache to make
  rebuilds faster — use BuildKit's `--mount=type=cache,target=/var/cache/apt`
  instead so the cache stays out of the image.
- **Byte compilation skipped.** `PYTHONDONTWRITEBYTECODE=1` avoids
  shipping `.pyc` files that the runtime user often couldn't write
  anyway. Runtime AOT compile is negligible versus the live-trace
  hot path.
- **Non-root by default.** The final stage drops to `deepview:deepview`
  (UID/GID `1000:1000`). Operators who need root for DMA opt in via
  `--user 0`.

## Mounting evidence

Evidence directories **must** be read-only. Deep View never intentionally
writes to the evidence mount, but the bind mount is your belt-and-braces
defence against a bug doing so anyway.

```bash
docker run --rm \
    --mount type=bind,source=/case/evidence,target=/evidence,readonly \
    --mount type=bind,source=/case/reports,target=/reports \
    deepview:latest \
        memory scan \
            --image /evidence/mem.lime \
            --output /reports/scan-2026-04-14.json
```

The `target=/evidence,readonly` flag makes the kernel refuse writes; we
still recommend setting the filesystem itself to read-only where the
infrastructure allows (e.g. bind-mount a loop-mounted E01 image with
`-o ro,noload`).

!!! tip "Session SQLite files go in `/reports`"
    `SessionRecorder` opens its database with WAL mode; the containing
    directory must be writable or recording will fail at commit. Keep
    `/reports` writable and `/evidence` read-only.

## Privilege matrix

Live-capture features need capabilities the default Docker runtime
doesn't grant. The table below maps the capability to the Deep View
subcommand that needs it.

| Subcommand | Default | Needs | Rationale |
| --- | --- | --- | --- |
| `memory scan`, `memory analyze` (offline image) | OK | — | Pure userspace on a read-only bind mount. |
| `disassemble`, `plugin run yara-*` | OK | — | Userspace. |
| `trace` (eBPF provider) | Fails | `--cap-add=SYS_ADMIN --cap-add=BPF --cap-add=PERFMON` + `--pid=host` | eBPF attach requires BPF + perf-event access; `/proc` must be the host's. |
| `monitor`, `replay` (tracing consumers) | OK if provider works | Same as `trace` when driving the provider live | Consumers have no extra kernel needs. |
| `netmangle run` | Fails | `--cap-add=NET_ADMIN --network=host` + pre-installed NFQUEUE rule | NFQUEUE reads from a host-scoped queue number; container nets are invisible. |
| `memory acquire --provider lime` | Fails | `--privileged` + `--pid=host` + `/dev/mem` | Kernel module load and physical memory access. |
| `remote acquire dma` | Fails | `--privileged` + `/dev/{leechcore,uio}` passthrough | DMA device passthrough; no capability bit is sufficient. |

!!! danger "`--privileged` gives the container root on the host"
    A `--privileged` container can load kernel modules, mount arbitrary
    filesystems, and reach raw device nodes. **Only run Deep View with
    `--privileged` on a workstation you control and treat the container
    as equally trusted with the host.** If you are building a
    multi-tenant pipeline, isolate DMA acquisition on a dedicated
    non-shared host and ship only the resulting image to the tenant
    cluster.

### Minimum-privilege `trace` recipe

```bash
docker run --rm \
    --cap-add=SYS_ADMIN --cap-add=BPF --cap-add=PERFMON \
    --security-opt apparmor=unconfined \
    --pid=host \
    --mount type=bind,source=/sys/kernel/debug,target=/sys/kernel/debug \
    --mount type=bind,source=/sys/fs/bpf,target=/sys/fs/bpf \
    deepview:latest \
        trace \
            --filter 'syscall == execve or syscall == connect' \
            --duration 5m \
            --output /reports/trace.ndjson
```

`apparmor=unconfined` is required on Ubuntu / Debian hosts where the
default Docker AppArmor profile blocks `bpf()`. The capability triple
(`SYS_ADMIN` + `BPF` + `PERFMON`) is narrower than `--privileged` and
should be preferred whenever the acquisition host's kernel is
5.8 or newer.

### Full-privilege DMA recipe

```bash
docker run --rm \
    --privileged \
    --mount type=bind,source=/dev,target=/dev \
    --mount type=bind,source=/case/evidence,target=/evidence,readonly \
    --mount type=bind,source=/case/reports,target=/reports \
    deepview:latest \
        remote acquire dma \
            --host 10.0.0.42 \
            --output /reports/dma-dump.raw
```

## Config overrides

The image ships a minimal `/etc/deepview/config.toml`. Override it with
a bind mount or ConfigMap:

```bash
docker run --rm \
    --mount type=bind,source=./config.toml,target=/etc/deepview/config.toml,readonly \
    -e DEEPVIEW_CONFIG=/etc/deepview/config.toml \
    deepview:latest doctor
```

Environment overrides work without rebuilding — any `DEEPVIEW_*`
environment variable clobbers the matching TOML key. Use this for
per-run knobs (verbosity, output directory) and keep the config file
for lab-wide policy.

## Building a slimmer variant

If you only need offline memory analysis (no Frida, no live tracing),
swap the runtime extras to the memory-only subset:

```dockerfile
RUN /opt/deepview/bin/pip install --no-index --find-links /wheels \
        "deepview[memory,storage,compression,ecc]==${DEEPVIEW_VERSION}"
```

That cuts ~180 MB — mostly `frida-gadget`, `lief`, and `capstone`. Keep
a separate tag (`deepview:0.2.0-memory`) so the matrix is explicit.

## Troubleshooting

- **`ImportError: libvolatility…`** — you rebuilt without the
  `[memory]` extra. Rebuild with the full runtime extras group.
- **`PermissionError: /sys/fs/bpf/...`** — missing `BPF` capability
  or host has `kernel.unprivileged_bpf_disabled=2`; the latter is not
  fixable from inside the container.
- **`HEALTHCHECK` flapping** — container is starved of CPU during
  boot; increase `--start-period` on your orchestrator.
- **Layer is huge** — run `docker history deepview:latest` to find
  which apt or pip layer grew. The most common culprit is
  `python*-dev` leaking into runtime; rebuild with the builder stage
  only to confirm.

## Next

- Promote the image into a cluster with the
  [Kubernetes Job recipe](kubernetes.md).
- Gate pull requests on a small image smoke with the
  [CI/CD recipe](ci-cd.md).
