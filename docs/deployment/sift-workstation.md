# SANS SIFT workstation

[SIFT Workstation](https://www.sans.org/tools/sift-workstation/) is a
standard Ubuntu-based forensics VM maintained by SANS, shipping
Volatility, The Sleuth Kit, plaso, bulk_extractor, and a long tail of
IR tooling preconfigured for case work. Deep View slots in alongside
those tools rather than replacing them — it shares Volatility 3 as a
library, reuses TSK where it's present, and hands analysts a faster
path for the live-capture, container-unlock, and classification
workflows that SIFT covers more thinly.

!!! note "Tested against SIFT 2023-01 and Casey Anthony's 2024 respin"
    The steps below work on both stock SIFT images. If your SIFT VM
    has been customised heavily (different Python version, custom
    Volatility symbol packs, alternate TSK build), adapt paths as
    needed — the core package install is vanilla pip.

## Before you start

- A SIFT VM with network access, or a local wheel mirror (see the
  [isolated lab](isolated-lab.md) guide for the offline variant).
- `sudo` on the SIFT workstation. SIFT runs as `sansforensics` by
  default; every command below assumes that account.
- At least 8 GB RAM allocated to the VM, 16 GB recommended if you
  plan to run container-unlock or ECC decode workloads.

## System packages

Deep View's `[memory]`, `[tracing]`, `[disassembly]`, and `[storage]`
extras compile native wheels on first install. SIFT already has most
of the build deps — the list below fills the remaining gaps.

```bash
sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
    python3-venv python3-dev \
    build-essential pkg-config cmake \
    libssl-dev libffi-dev \
    libcapstone-dev libmagic-dev \
    libyara-dev libtsk-dev \
    libbde-dev libfvde-dev \
    libfuse3-dev \
    libdw-dev libelf-dev \
    libbcc-examples
```

!!! tip "Keep SIFT's Volatility"
    Do not `apt remove python3-volatility3`. Deep View imports its own
    pinned volatility3 inside its venv; SIFT's system-wide copy stays
    available for `vol` at the shell.

## Install Deep View into an isolated venv

Do **not** install into SIFT's system Python — several SIFT tools pin
specific transitive versions that Deep View would upgrade. Use a venv
under `~/tools/deepview`:

```bash
python3 -m venv ~/tools/deepview
source ~/tools/deepview/bin/activate
pip install --upgrade pip
pip install \
    "deepview[memory,tracing,linux_monitoring,instrumentation, \
              detection,sigma,disassembly,storage,compression, \
              ecc,containers,remote_acquisition]==0.2.0"
deactivate
```

If the SIFT VM is offline, point `pip` at your local wheel mirror or
`--find-links` wheelhouse as described in the
[isolated lab](isolated-lab.md#wheel-mirror) page.

## PATH integration

Expose the venv's `deepview` binary on the user's PATH without leaking
the venv's other scripts (which would shadow SIFT's `vol`, `log2timeline`,
`bulk_extractor`).

```bash
# ~/.local/bin/deepview — a hand-rolled shim, not a symlink.
mkdir -p ~/.local/bin
cat > ~/.local/bin/deepview <<'SH'
#!/usr/bin/env bash
exec "${HOME}/tools/deepview/bin/deepview" "$@"
SH
chmod +x ~/.local/bin/deepview
```

SIFT already has `~/.local/bin` on PATH for `sansforensics`. Verify:

```bash
which deepview                  # /home/sansforensics/.local/bin/deepview
deepview --version              # deepview 0.2.0
deepview doctor                 # capability matrix
```

`doctor` should report:

- `volatility3` — available (via Deep View's venv).
- `yara-python` — available.
- `frida`, `lief`, `capstone` — available.
- `bcc`, `pyroute2` — available after the `libbcc-examples` apt
  install above.
- `tsk3` / `pyfsapfs` etc. — available if `libtsk` / libfs* are
  present.

## SIFT case-management folder convention

SIFT organises engagements under `~/cases/<case>/` with a per-case
layout of `evidence/`, `reports/`, and `work/`. Deep View inherits that
convention by default if you set two env vars in the user shell:

```bash
# ~/.bashrc addition
export DEEPVIEW_CASE_ROOT="${HOME}/cases"

deepcase () {
    local case="${1:?case id required}"
    local root="${DEEPVIEW_CASE_ROOT}/${case}"
    mkdir -p "${root}"/{evidence,reports,work}
    export DEEPVIEW_REPORTING__OUTPUT_DIR="${root}/reports"
    export DEEPVIEW_REPORTING__RUN_ID="$(uuidgen)"
    export DEEPVIEW_ACQUISITION__EVIDENCE_DIR="${root}/evidence"
    cd "${root}" || return 1
    echo "deepview case ${case} @ ${root}"
}
```

Now every session starts with:

```bash
deepcase CASE-2026-00421
deepview memory scan --image evidence/hostA.lime
deepview inspect process 1234   # if live-capture applies
deepview report export --case CASE-2026-00421 --format html
```

Each report lands in `reports/CASE-2026-00421/...` following the
`filename_template` in the lab config (see
[isolated lab](isolated-lab.md#lab-wide-config)).

## Interop with SIFT tooling

| SIFT tool | How Deep View slots in |
| --- | --- |
| `vol` (Volatility 2/3 CLI) | Deep View's memory engine is Volatility 3 as a library. Keep `vol` for ad-hoc plugin runs; reach for `deepview memory analyze` when you want Deep View's classification, reporting, and session store bolted on. |
| `log2timeline` / `psort` / `plaso` | Deep View does not duplicate plaso's filesystem parsers. Export Deep View artefacts to JSON, then `log2timeline --parser custom` them into the master timeline. |
| `bulk_extractor` | Deep View's [IoCEngine](../reference/plugins.md#ioc-engine) overlaps bulk_extractor's carvers loosely. For large disk scans, keep bulk_extractor as the bulk carver; use Deep View for targeted YARA on memory and containers. |
| `Autopsy` | Deep View exports STIX 2.1 and HTML reports that Autopsy imports as external findings. |
| `regripper` | Independent — regripper handles registry hives, Deep View handles the rest. Chain them with shell scripts per engagement. |

## Upgrading

The SIFT VM update cycle is infrequent; Deep View releases every few
weeks. Upgrade in the venv, never globally:

```bash
~/tools/deepview/bin/pip install --upgrade "deepview[...same extras...]==0.3.0"
~/tools/deepview/bin/deepview doctor   # re-check after upgrade
```

## Troubleshooting

- **`deepview doctor` reports `bcc` unavailable**: you installed the
  apt package into the system Python, but the venv doesn't see it.
  SIFT's `python3-bpfcc` deb installs into `/usr/lib/python3/dist-packages`;
  either symlink the package into the venv's `site-packages`, or
  re-run `pip install --upgrade deepview[linux_monitoring]` to pull
  the PyPI `bcc` bindings.
- **Volatility plugins differ from SIFT's `vol`**: Deep View's pinned
  version may be ahead or behind SIFT's system copy. Check
  `deepview memory engines` and `vol --info` side-by-side; stick to
  the pinned version inside Deep View reports.
- **`deepview trace` fails with `EACCES`**: SIFT runs `sansforensics`
  as a normal user; eBPF attach needs `CAP_BPF` / `CAP_PERFMON`.
  Either run the command under `sudo`, or grant file capabilities to
  the venv python:

  ```bash
  sudo setcap 'cap_bpf,cap_perfmon,cap_sys_admin+eip' \
      ~/tools/deepview/bin/python3
  ```

  !!! danger "File capabilities are sticky"
      Capabilities survive package upgrades and are invisible to `ls`.
      Remove them (`setcap -r`) before sharing or snapshotting the
      VM.

## Next

- Pair the SIFT workstation with an
  [isolated lab](isolated-lab.md) setup for air-gapped engagements.
- If the same analyst also drives cluster batch jobs, the
  [Kubernetes recipe](kubernetes.md) uses the same config layout
  as the case-folder convention above.
