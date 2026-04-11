"""Mangle actions.

Every ``Action`` subclass implements ``apply(packet_view, context)``
which returns an :class:`ActionOutcome` describing:

* ``verdict``  — "accept", "drop", "repeat" (for DelayAction), or
  "modified" (for RewriteAction/CorruptAction, which also populates
  ``new_bytes``).
* ``new_bytes`` — optional mutated packet payload (for verdict "modified").
* ``mark`` — optional netfilter fwmark (for MarkAction).
* ``description`` — human-readable summary for logging.

The engine is responsible for translating the outcome into a
concrete NFQUEUE verdict. Actions themselves never touch NFQUEUE
handles — they are pure functions of the packet state.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from deepview.networking.packet import PacketView
from deepview.networking.parser import rebuild_packet


@dataclass
class ActionOutcome:
    verdict: str  # "accept" | "drop" | "repeat" | "modified"
    new_bytes: bytes | None = None
    mark: int | None = None
    description: str = ""
    delay_ms: int = 0


class Action:
    """Base class. Subclasses must set ``type_name`` and implement ``apply``."""

    type_name: str = ""

    def apply(self, view: PacketView) -> ActionOutcome:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Core actions
# ---------------------------------------------------------------------------


@dataclass
class AcceptAction(Action):
    type_name: str = "accept"

    def apply(self, view: PacketView) -> ActionOutcome:
        return ActionOutcome(verdict="accept", description="accept")


@dataclass
class DropAction(Action):
    type_name: str = "drop"
    reason: str = ""

    def apply(self, view: PacketView) -> ActionOutcome:
        return ActionOutcome(verdict="drop", description=f"drop:{self.reason}")


@dataclass
class ObserveAction(Action):
    """No-op verdict ACCEPT that is still recorded as a hit for audit."""

    type_name: str = "observe"
    label: str = ""

    def apply(self, view: PacketView) -> ActionOutcome:
        return ActionOutcome(verdict="accept", description=f"observe:{self.label}")


@dataclass
class DelayAction(Action):
    """Delay the packet by ``ms`` before verdict-accepting it.

    The engine schedules the delay; this class just carries the
    metadata. Verdict comes back as ``"repeat"`` so the engine knows
    to re-inject instead of immediately accepting.
    """

    type_name: str = "delay"
    ms: int = 100

    def apply(self, view: PacketView) -> ActionOutcome:
        return ActionOutcome(
            verdict="repeat",
            delay_ms=int(self.ms),
            description=f"delay:{self.ms}ms",
        )


@dataclass
class MarkAction(Action):
    type_name: str = "mark"
    fwmark: int = 0

    def apply(self, view: PacketView) -> ActionOutcome:
        return ActionOutcome(
            verdict="accept",
            mark=int(self.fwmark),
            description=f"mark:0x{self.fwmark:x}",
        )


# ---------------------------------------------------------------------------
# Rewrite: regex find/replace in payload with checksum recompute
# ---------------------------------------------------------------------------


@dataclass
class RewriteOperation:
    find: bytes
    replace: bytes
    max_occurrences: int = 0  # 0 = unlimited

    @classmethod
    def from_mapping(cls, data: dict) -> "RewriteOperation":
        find = data.get("find")
        replace = data.get("replace")
        if find is None or replace is None:
            raise ValueError("rewrite operation requires 'find' and 'replace'")
        return cls(
            find=str(find).encode("utf-8") if not isinstance(find, bytes) else find,
            replace=str(replace).encode("utf-8") if not isinstance(replace, bytes) else replace,
            max_occurrences=int(data.get("max_occurrences", 0)),
        )


@dataclass
class RewriteAction(Action):
    type_name: str = "rewrite"
    operations: list[RewriteOperation] = field(default_factory=list)

    def apply(self, view: PacketView) -> ActionOutcome:
        if view.is_fragmented:
            return ActionOutcome(
                verdict="accept", description="rewrite skipped: fragmented"
            )
        parsed = view.parsed
        if parsed.tcp is None and parsed.udp is None:
            return ActionOutcome(
                verdict="accept", description="rewrite skipped: non-TCP/UDP"
            )
        payload = parsed.payload
        new_payload = payload
        changed = 0
        for op in self.operations:
            if op.max_occurrences <= 0:
                count = -1
            else:
                count = op.max_occurrences
            replaced = new_payload.replace(op.find, op.replace, count if count >= 0 else -1)
            if replaced != new_payload:
                changed += 1
            new_payload = replaced
        if changed == 0 or new_payload == payload:
            return ActionOutcome(
                verdict="accept", description="rewrite matched nothing"
            )
        try:
            new_bytes = rebuild_packet(parsed, new_payload=new_payload)
        except ValueError as e:
            return ActionOutcome(
                verdict="accept", description=f"rewrite failed: {e}"
            )
        return ActionOutcome(
            verdict="modified",
            new_bytes=new_bytes,
            description=f"rewrite:{changed}op{'s' if changed != 1 else ''}",
        )


# ---------------------------------------------------------------------------
# Corrupt: flip N bits at a random offset in the payload (seeded)
# ---------------------------------------------------------------------------


@dataclass
class CorruptAction(Action):
    type_name: str = "corrupt"
    bits: int = 1
    seed: int | None = None
    at: str = "payload_start"  # or "payload_random"

    def apply(self, view: PacketView) -> ActionOutcome:
        if view.is_fragmented:
            return ActionOutcome(
                verdict="accept", description="corrupt skipped: fragmented"
            )
        parsed = view.parsed
        if parsed.tcp is None and parsed.udp is None:
            return ActionOutcome(
                verdict="accept", description="corrupt skipped: non-TCP/UDP"
            )
        payload = bytearray(parsed.payload)
        if not payload:
            return ActionOutcome(verdict="accept", description="corrupt skipped: no payload")
        rng = random.Random(self.seed) if self.seed is not None else random.Random()
        bits_to_flip = max(1, int(self.bits))
        for _ in range(bits_to_flip):
            if self.at == "payload_random":
                byte_idx = rng.randrange(len(payload))
            else:
                byte_idx = 0
            bit = 1 << rng.randrange(8)
            payload[byte_idx] ^= bit
        try:
            new_bytes = rebuild_packet(parsed, new_payload=bytes(payload))
        except ValueError as e:
            return ActionOutcome(verdict="accept", description=f"corrupt failed: {e}")
        return ActionOutcome(
            verdict="modified",
            new_bytes=new_bytes,
            description=f"corrupt:{bits_to_flip}bit",
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def action_from_mapping(data: dict) -> Action:
    """Build a concrete :class:`Action` from a YAML mapping.

    Supported shapes::

        {type: accept}
        {type: drop}
        {type: delay, ms: 100}
        {type: mark, fwmark: 0x1000}
        {type: observe, label: "audit"}
        {type: rewrite, operations: [{find: "a", replace: "b"}]}
        {type: corrupt, bits: 2, at: payload_random, seed: 42}
    """
    if not isinstance(data, dict):
        raise ValueError(f"action must be a mapping, got {type(data).__name__}")
    tname = str(data.get("type", "")).lower()
    if not tname:
        raise ValueError("action mapping is missing 'type'")
    if tname == "accept":
        return AcceptAction()
    if tname == "drop":
        return DropAction(reason=str(data.get("reason", "")))
    if tname == "observe":
        return ObserveAction(label=str(data.get("label", "")))
    if tname == "delay":
        return DelayAction(ms=int(data.get("ms", 100)))
    if tname == "mark":
        mark = data.get("fwmark", 0)
        if isinstance(mark, str):
            mark = int(mark, 0)
        return MarkAction(fwmark=int(mark))
    if tname == "rewrite":
        ops_raw = data.get("operations") or []
        if not isinstance(ops_raw, list):
            raise ValueError("rewrite.operations must be a list")
        ops = [RewriteOperation.from_mapping(o) for o in ops_raw]
        if not ops:
            raise ValueError("rewrite action needs at least one operation")
        return RewriteAction(operations=ops)
    if tname == "corrupt":
        seed = data.get("seed")
        return CorruptAction(
            bits=int(data.get("bits", 1)),
            seed=int(seed) if seed is not None else None,
            at=str(data.get("at", "payload_start")),
        )
    raise ValueError(f"unknown action type: {tname!r}")
