# 0006. Fail-secure defaults for remote acquisition

- **Status:** Accepted
- **Date:** 2026-04-15

## Context

The remote-acquisition subsystem (`src/deepview/memory/acquisition/remote/`)
lets operators pull a memory image off another machine through SSH,
TCP, UDP, IPMI, AMT, DMA (Thunderbolt/PCIe/FireWire), or gRPC (future).
These transports carry the raw contents of a host's RAM — including
passwords, private keys, and session tokens. A misconfigured
acquisition is a catastrophic data-leak waiting to happen.

Two recurring patterns in forensics tools fail dangerously:

1. **Silent TLS downgrade.** If a configured TLS handshake fails, some
   tools transparently fall back to plaintext "so the user isn't
   blocked." The result is that an attacker on-path can force
   plaintext and read the acquisition in flight.
2. **Authorization-by-absence.** If the operator has not supplied a
   written authorization statement, some tools proceed anyway because
   the flag defaulted to `False`. There is no audit trail that the
   operator actively asserted they are allowed to perform the
   acquisition.

Deep View is explicitly a **dual-use** tool: designed for authorized
forensics, abusable if pointed at a machine you don't own. Its defaults
must assume the operator may be wrong and refuse to proceed without
affirmative action.

## Decision

**Every `RemoteEndpoint` defaults `require_tls=True`. A TLS-capable
transport whose handshake fails aborts the acquisition with a clear
error; there is no silent fallback path.**

Further, every CLI command that touches remote acquisition requires
*both*:

- `--confirm` — a positive flag, no short form, that asserts "I mean
  to do this." A missing flag aborts with `AuthorizationError`.
- `--authorization-statement "..."` — a free-text statement the
  operator types at the prompt, recorded in the acquisition banner and
  the resulting session manifest. A missing statement aborts.

DMA transports add a third gate: `--enable-dma` must be set, *and* the
process must be running as root (or administrator on Windows). Absent
either, the CLI prints the IOMMU warning and aborts.

The default verdict on every engine error — TLS failure, authentication
failure, transport malformation, unexpected exception — is **abort**.
There is no "try another way" path. (This contrasts with the
`netmangle` engine, which is fail-open for a different reason: a
runtime error there must not jail the operator's traffic. Acquisition
has the opposite bias.)

## Consequences

### Positive

- **No silent plaintext.** An operator who misconfigures the CA path
  gets a loud failure rather than an over-the-wire RAM dump in cleartext.
- **Every acquisition is attributed.** The `--authorization-statement`
  text is embedded in the acquisition banner emitted on the wire
  *before* reading begins, so a remote agent or later audit can
  identify who claimed what authority.
- **DMA is gated three ways.** `--enable-dma` + root + explicit
  `transport="dma"` — no way to stumble into a raw PCIe read.
- **Fail-secure matches the expected mental model** of forensics
  practitioners subject to chain-of-custody obligations.

### Negative

- **Command lines are verbose.** Every `deepview remote image` invocation
  carries `--confirm --authorization-statement "..."` and for DMA,
  `--enable-dma`. We accept this as intentional friction.
- **No convenience modes.** There is no `--yes` or `--force`. Any
  automation must either answer the gates in its script (which makes
  the authorization assertion explicit) or maintain a config file
  (which is reviewable).
- **False starts are common.** New users hit the gates repeatedly
  before reading the docs. The CLI's error messages include the exact
  missing flag name, which helps.

### Neutral

- The decision does not restrict *what* acquisitions can happen — only
  *how* they are initiated. A user with legitimate authority can still
  acquire anything; they just have to state it.

## Alternatives considered

### Option A — TLS optional, warn on plaintext

Allow `require_tls=False` as default; print a warning to stderr when
plaintext is selected. Rejected: warnings are ignored in scripts,
especially when the acquisition still succeeds. The defense-in-depth
value of "default secure" is eroded the moment the default flips.

### Option B — Single mega-flag `--i-am-authorized`

One flag to bypass all gates. Rejected because it encourages habitual
use (operators add `--i-am-authorized` to their shell alias and never
think about it again). The multi-gate structure forces per-invocation
consideration.

### Option C — Interactive prompts instead of flags

Prompt for "are you authorized?" at runtime. Rejected because:

- Breaks non-interactive automation.
- Doesn't embed the operator's assertion into the acquisition record.
- Can be bypassed by piping "y" on stdin.

### Option D — Fail-open like the netmangle engine

Would be consistent with the netmangle engine's fail-open-on-error
posture. Rejected: acquisition errors at worst drop an acquisition
attempt; netmangle errors at worst drop or corrupt packets for the
whole host. The risk-shapes are opposite, so the defaults are opposite.

## References

- Source: `src/deepview/memory/acquisition/remote/base.py` — module
  docstring explicitly names the `AuthorizationError` surface.
- Source: `src/deepview/memory/acquisition/remote/` — transport
  implementations.
- CLI: `deepview remote image --help`
- Architecture page: [`../architecture/remote-acquisition.md`](../architecture/remote-acquisition.md)
- Guide: [`../guides/remote-acquire-ssh.md`](../guides/remote-acquire-ssh.md)
- Guide: [`../guides/remote-acquire-dma.md`](../guides/remote-acquire-dma.md)
- Related ADR: [0008 — Events over callbacks](0008-events-not-callbacks.md)
  — the progress event carries the same banner the operator signed.
