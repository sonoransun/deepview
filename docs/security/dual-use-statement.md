# Dual-use statement

Deep View ships a number of capabilities that are useful for
forensic investigation *and* useful for attack. This page is the
maintainers' plain-language statement of who we built the toolkit
for, what we will not help with, and what the MIT licence does and
does not grant.

It is written in the first person plural ("we") because the
statement is made on behalf of the project's maintainers, not on
behalf of any employer, sponsor, or downstream integrator.

## What's dual-use here

Most of Deep View is read-only analysis — parsing dumps, scanning
with YARA, reconstructing page tables, generating reports — and is
no more dual-use than `grep`. The following capabilities are
materially dual-use and receive extra treatment in the CLI and the
documentation:

- **DMA acquisition** via `leechcore` (PCILeech family adapters,
  ScreamerM2, FPGA-based DMA). Reads kernel memory over PCIe with
  physical access to the target.
- **Container unlock** — LUKS, VeraCrypt, BitLocker, APFS,
  FileVault, age, and friends. Given memory-carved keys or
  operator-supplied passphrases, mounts or decrypts the container.
- **Live binary instrumentation** via Frida — hooks arbitrary
  functions in arbitrary user-space processes.
- **Static binary reassembly** — LIEF + Capstone pipeline that
  rewrites executables with injected trampolines.
- **Network mangling** — NFQUEUE-backed engine that can delay, drop,
  rewrite, corrupt, or mark real packets on the network interface
  the operator controls.
- **Remote acquisition** — SSH, IPMI v2.0, Intel AMT, and cloud
  hypervisor APIs for pulling memory and disk from remote endpoints.

Every one of these is a legitimate forensic or security-research
tool and every one of these can be abused.

## Intended audiences

We built Deep View for, and we support it for, the following
communities:

- **Forensic investigators** working under warrant, subpoena, or a
  formal internal authorisation, responding to incidents on systems
  their employer or client owns or operates.
- **Incident responders** imaging compromised hosts on networks
  they are paid to defend.
- **Security researchers** reverse-engineering malware, analysing
  vulnerabilities, or studying system behaviour in isolated lab
  environments.
- **CTF participants** working through forensic, reverse-engineering,
  and network-manipulation challenges on dedicated CTF infrastructure.
- **Defensive security teams** using mangle and trace capabilities
  against their own honeypots, staging environments, and red-team
  engagements.
- **Authorised red teams** operating under a signed statement of
  work with an explicit scope, on systems the target organisation
  has consented to be tested against.

If your use case fits one of the above, Deep View is for you. File
issues, send PRs, tell us what's missing.

## Refused use cases

We will not knowingly help with, and we will refuse contributions
and support requests that facilitate:

- **Unauthorised access** to systems, networks, devices, or accounts
  that the operator does not own, does not operate, or has not been
  explicitly authorised to access.
- **Supply-chain attacks** — hiding malicious behaviour inside
  upstream packages, compromising build systems, or distributing
  tampered Deep View artefacts.
- **Mass surveillance** of private individuals, journalists,
  dissidents, activists, or communities on the basis of protected
  characteristics. If your use case involves monitoring people who
  have not consented and are not plausibly targets of a lawful
  investigation, this toolkit is not for you.
- **Domestic abuse and stalking** — any use that facilitates
  surveilling, controlling, or harming a partner, family member, or
  former associate.
- **Jailbreaking consumer devices on behalf of third parties without
  their consent.** Breaking into your own phone is fine; breaking
  into somebody else's is not.
- **Offensive operations outside a clearly authorised scope.** A
  signed SOW covering one network is not authorisation for the
  operator's curiosity about another network.

We do not have a mechanism for policing end use; the licence is
MIT. But we do have a mechanism for declining to support these
workflows, declining to accept features that primarily enable them,
and publicly naming known misuse. Contributions that facilitate any
of the above will be closed without merge.

## Speed bumps in the CLI

The CLI has a set of deliberate friction points in front of the
dual-use capabilities. These are **speed bumps, not safety nets.**
They are designed to prevent accidents and to create an auditable
record of deliberate actions. They do not and cannot prevent
deliberate misuse by an authorised operator.

- **`--confirm`.** Every destructive or dual-use command requires
  interactive confirmation by default. `--confirm` is the
  non-interactive equivalent and is logged to the structured audit
  trail.
- **`--enable-dma`, `--enable-mangle`, `--enable-rewrite`,
  `--enable-corrupt`.** Each capability class has its own opt-in
  flag. A typo cannot elevate an `observe` run to a `drop` run.
- **`--authorization-statement`.** Free-text operator-supplied
  record of authorisation. Logged verbatim and embedded in every
  resulting artefact. Not checked, not validated, not a licence.
- **5-second banner.** Before a remote-acquisition or mangle run
  starts, the CLI prints the target, the method, and the
  authorisation statement, then waits 5 seconds. `--confirm` skips
  the wait but not the banner.
- **`--dry-run` on mangle.** Forces every verdict to ACCEPT while
  still exercising the ruleset end-to-end. New rulesets should
  always be tested dry first.
- **`DEEPVIEW_REFUSE_ROOT=1`.** Opt-in env-var that makes Deep View
  refuse to run as root on multi-tenant analysis hosts, to reduce
  the blast radius of a plugin bug on a shared machine.
- **`--install-iptables`.** Explicit opt-in for the mangle
  installer. Without it, Deep View will not touch iptables on the
  operator's host.
- **Symlinked plugin / config refusal.** Not a dual-use speed bump
  strictly, but relevant: Deep View will not load plugins from a
  symlinked directory and will not load a symlinked config file.
  This blocks a class of local-privilege-escalation tricks.

Every one of these can be scripted around. That is intentional —
production forensic workflows are scripted. But none of them are
invisible: every bypass creates a structured log entry.

!!! warning "These are not a substitute for authorisation"
    If an audit finds that an operator used the speed bumps
    "correctly" (all flags set, banner acknowledged, statement
    logged) but never had authorisation to act in the first place,
    the operator is responsible. The speed bumps document *intent*;
    they do not grant *permission*.

## What the MIT licence does and does not grant

The MIT licence under which Deep View ships grants the recipient:

- The right to use, copy, modify, merge, publish, distribute,
  sublicence, and sell copies of the software.
- The licence text's warranty disclaimer and limitation of
  liability.

It does **not** grant:

- Permission to use the software unlawfully.
- Permission to access systems the operator does not own or is not
  authorised to access.
- An exemption from the Computer Fraud and Abuse Act, the UK
  Computer Misuse Act, the EU Cybercrime Directive, or equivalent
  legislation in any other jurisdiction.
- Indemnification for the operator's use of the software.

Every operator is solely responsible for obtaining the
authorisation necessary to use Deep View against any system,
network, or piece of data. "Written authorisation" is the shorthand;
the practical meaning is defined by the operator's jurisdiction, the
owner of the system under investigation, and (for investigators) the
applicable court.

## Cross-references

- [Threat model](threat-model.md) — the out-of-scope section there
  makes the same distinction from a different angle.
- [OPSEC notes](opsec.md) — the operator-facing expansion of the
  authorisation and scoping practices mentioned above.
- [Remote acquisition architecture](../architecture/remote-acquisition.md)
  — the control flow the speed bumps live inside.
- Repository-root [`SECURITY.md`](https://github.com/example/deepview/blob/main/SECURITY.md)
  for the coordinated-disclosure channel.
