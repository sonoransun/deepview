# Recipe 11: Build a `RemoteEndpoint` from environment variables

Construct a `RemoteEndpoint` without putting credentials in source, then
hand it to `build_remote_provider()` to get a concrete transport
instance ready to `.acquire()`.

!!! note "Extras required"
    `pip install -e ".[remote_acquisition]"`. Per-transport deps
    (`paramiko` for SSH, `python-ipmi` for IPMI, `leechcore` for DMA)
    are lazy-imported by the concrete provider modules.

!!! danger "Dual-use"
    Remote acquisition is a dual-use capability. This recipe shows the
    in-process construction path; the CLI (`deepview remote-image
    <transport>`) mandates `--confirm` + `--authorization-statement`
    before any network traffic — adopt the same gates in your tools.

## The recipe

```python
import os
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.acquisition.remote.base import RemoteEndpoint
from deepview.memory.acquisition.remote.factory import build_remote_provider

def endpoint_from_env() -> RemoteEndpoint:
    """Build an SSH RemoteEndpoint from DV_REMOTE_* environment variables.

    Expected vars:
        DV_REMOTE_HOST            required
        DV_REMOTE_PORT            optional, default 22
        DV_REMOTE_USER            required
        DV_REMOTE_IDENTITY        optional; path to SSH key
        DV_REMOTE_KNOWN_HOSTS     required (TLS material)
        DV_REMOTE_PASSWORD_ENV    optional; name of another var
    """
    host = os.environ["DV_REMOTE_HOST"]
    user = os.environ["DV_REMOTE_USER"]
    known_hosts = Path(os.environ["DV_REMOTE_KNOWN_HOSTS"])

    identity = os.environ.get("DV_REMOTE_IDENTITY")
    port = int(os.environ.get("DV_REMOTE_PORT", "22"))

    return RemoteEndpoint(
        host=host,
        transport="ssh",
        port=port,
        username=user,
        identity_file=Path(identity) if identity else None,
        password_env=os.environ.get("DV_REMOTE_PASSWORD_ENV"),
        known_hosts=known_hosts,
        tls_ca=None,
        require_tls=True,
        extra={"source": "/dev/mem"},
    )

ctx = AnalysisContext()
endpoint = endpoint_from_env()

provider = build_remote_provider("ssh", endpoint, context=ctx)

result = provider.acquire(
    AcquisitionTarget(hostname=endpoint.host),
    Path("/evidence/remote.raw"),
    DumpFormat.RAW,
)
print(f"dumped {result.size_bytes} bytes in {result.duration_seconds:.1f}s")
```

## What happened

`RemoteEndpoint` is a frozen dataclass that deliberately *never*
stores passwords inline. The only credential fields are indirection
pointers:

| Field | Meaning |
|---|---|
| `identity_file` | Path to an SSH private key. |
| `password_env` | *Name* of an environment variable to consult at use-time. |
| `known_hosts` | Path to an SSH known_hosts file (pin remote identity). |
| `tls_ca` | Path to a CA bundle (pin TLS endpoint identity). |

That keeps secrets out of the dataclass's `repr`, out of downstream
JSON serialization, and out of core dumps. The concrete provider reads
the env var or file only at the moment it needs the credential, then
discards the buffer.

`build_remote_provider(transport, endpoint, context=ctx)` dispatches
by transport string: `"ssh"`, `"tcp"`, `"udp"`, `"agent"`, `"lime"`,
`"dma-tb"` / `"dma-pcie"` / `"dma-fw"`, `"ipmi"`, `"amt"`. See
[`memory/acquisition/remote/factory.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/memory/acquisition/remote/factory.py)
for the full dispatch table.

!!! tip "Progress events"
    Every remote provider publishes `RemoteAcquisitionProgressEvent` on
    `ctx.events` as it streams bytes. Subscribe the same way as in
    [Recipe 09](09-stream-trace-events.md) to render a live counter.

!!! warning "TLS defaults"
    `require_tls=True` is not cosmetic. For `ssh` the provider refuses
    to connect without `known_hosts`; for `agent` it refuses without
    `tls_ca`. Passing `require_tls=False` disables the check and should
    be avoided outside closed test environments.

## Cross-links

- Architecture: [`architecture/remote-acquisition.md`](../architecture/remote-acquisition.md).
- Guide: [`guides/remote-acquire-ssh.md`](../guides/remote-acquire-ssh.md).
- CLI: `deepview remote-image ssh` — see [`reference/cli.md`](../reference/cli.md).
