"""MangleEngine — the runtime that dispatches packets through a ruleset.

The engine is intentionally transport-agnostic: it takes a
:class:`PacketSource` (NFQUEUE or a fake) and a :class:`MangleRuleset`
and wires them up. For every packet:

1. parse raw bytes into a :class:`ParsedPacket`
2. wrap into a :class:`MatchEnvelope` and find the first matching rule
3. dispatch to the matched :class:`Action`
4. apply the resulting verdict on the source's packet handle
5. publish a :class:`NetworkPacketMangledEvent` into the core EventBus

The engine's safety invariants:

- **Fail open.** Any exception during parse/match/dispatch yields an
  ACCEPT verdict and increments ``stats.errors``.
- **Dry-run.** When ``dry_run=True`` every action is still evaluated
  but the final verdict is *always* ACCEPT and modified-bytes are
  discarded.
- **Passthrough.** SIGUSR1 flips ``passthrough`` on; every packet
  gets an ACCEPT verdict without consulting the ruleset.
- **No dependency on ``netfilterqueue`` at import time.** The
  transport is injected via ``source`` so unit tests drive the
  engine with a :class:`FakeSource`.
"""
from __future__ import annotations

import signal
import threading
from dataclasses import dataclass
from typing import Callable

from deepview.core.logging import get_logger
from deepview.networking.actions import ActionOutcome
from deepview.networking.nfqueue_source import PacketHandle, PacketSource
from deepview.networking.packet import MatchEnvelope, PacketView
from deepview.networking.parser import parse_packet
from deepview.networking.ruleset import MangleRule, MangleRuleset

log = get_logger("networking.engine")


@dataclass
class MangleStats:
    observed: int = 0
    accepted: int = 0
    dropped: int = 0
    delayed: int = 0
    rewritten: int = 0
    corrupted: int = 0
    marked: int = 0
    errors: int = 0
    passthrough_hits: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "observed": self.observed,
            "accepted": self.accepted,
            "dropped": self.dropped,
            "delayed": self.delayed,
            "rewritten": self.rewritten,
            "corrupted": self.corrupted,
            "marked": self.marked,
            "errors": self.errors,
            "passthrough_hits": self.passthrough_hits,
        }


# The engine accepts an optional `alert_sink` callable that persists
# an action outcome into the session store. Kept as a Callable rather
# than a hard import of SessionStore so tests stay lightweight.
AlertSink = Callable[[MangleRule, ActionOutcome, PacketView], None]
EventSink = Callable[[MangleRule | None, ActionOutcome, PacketView], None]


class MangleEngine:
    def __init__(
        self,
        ruleset: MangleRuleset,
        source: PacketSource,
        *,
        direction: str = "out",
        dry_run: bool = False,
        alert_sink: AlertSink | None = None,
        event_sink: EventSink | None = None,
    ) -> None:
        self._ruleset = ruleset
        self._source = source
        self._direction = direction
        self._dry_run = dry_run
        self._alert_sink = alert_sink
        self._event_sink = event_sink
        self.stats = MangleStats()
        self._passthrough = False
        self._stopped = False
        self._lock = threading.Lock()
        self._signal_installed = False

    @property
    def passthrough(self) -> bool:
        return self._passthrough

    @property
    def stopped(self) -> bool:
        return self._stopped

    def set_passthrough(self, value: bool) -> None:
        self._passthrough = value
        log.info("mangle_passthrough", value=value)

    def stop(self) -> None:
        self._stopped = True
        try:
            self._source.close()
        except Exception:  # noqa: BLE001
            pass

    def install_signal_handlers(self) -> None:
        """Wire SIGUSR1 to passthrough toggle. Idempotent."""
        if self._signal_installed:
            return
        try:
            signal.signal(signal.SIGUSR1, lambda *_: self.set_passthrough(True))
            signal.signal(signal.SIGUSR2, lambda *_: self.set_passthrough(False))
            self._signal_installed = True
        except (ValueError, OSError) as e:  # noqa: BLE001
            log.debug("mangle_signal_install_failed", error=str(e))

    # ------------------------------------------------------------------
    # Main entry points
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Blocking run loop. Returns when the source closes."""
        self.install_signal_handlers()
        self._source.run(self._on_packet)

    def _on_packet(self, handle: PacketHandle) -> None:
        if self._stopped:
            try:
                handle.accept()
            except Exception:  # noqa: BLE001
                pass
            return
        try:
            raw = handle.get_payload()
        except Exception as e:  # noqa: BLE001
            log.warning("mangle_get_payload_failed", error=str(e))
            self.stats.errors += 1
            self._safe_accept(handle)
            return
        self.process_raw(raw, handle)

    # ------------------------------------------------------------------
    # Pure/test-friendly entry point
    # ------------------------------------------------------------------

    def process_raw(self, raw: bytes, handle: PacketHandle) -> ActionOutcome:
        """Parse + match + dispatch a single packet.

        Returns the outcome so tests can assert on it. On any error,
        this verdict-accepts the packet and returns an outcome with
        ``verdict='accept'`` and ``description='error'``.
        """
        self.stats.observed += 1
        try:
            parsed = parse_packet(raw)
        except Exception as e:  # noqa: BLE001
            log.warning("mangle_parse_error", error=str(e))
            self.stats.errors += 1
            self._safe_accept(handle)
            return ActionOutcome(verdict="accept", description="parse-error")
        if parsed is None:
            self._safe_accept(handle)
            self.stats.accepted += 1
            return ActionOutcome(verdict="accept", description="unparsed")

        view = PacketView(parsed=parsed, direction=self._direction, queue=self._ruleset.queue)

        if self._passthrough:
            self.stats.passthrough_hits += 1
            self._safe_accept(handle)
            return ActionOutcome(verdict="accept", description="passthrough")

        envelope = MatchEnvelope(packet=view)
        try:
            rule = self._ruleset.first_match(envelope)
        except Exception as e:  # noqa: BLE001
            log.warning("mangle_match_error", error=str(e))
            self.stats.errors += 1
            self._safe_accept(handle)
            return ActionOutcome(verdict="accept", description="match-error")

        if rule is None:
            self._apply_verdict(handle, ActionOutcome(verdict="accept", description="no-match"))
            self.stats.accepted += 1
            return ActionOutcome(verdict="accept", description="no-match")

        try:
            outcome = rule.action.apply(view)
        except Exception as e:  # noqa: BLE001
            log.warning("mangle_action_error", rule=rule.id, error=str(e))
            self.stats.errors += 1
            self._safe_accept(handle)
            return ActionOutcome(verdict="accept", description=f"action-error:{e}")

        # Dry-run forces ACCEPT regardless of the matched action but
        # keeps stats accounting so authors can preview a ruleset.
        if self._dry_run:
            self._tally(outcome)
            self._notify(rule, outcome, view)
            self._safe_accept(handle)
            return outcome

        self._tally(outcome)
        self._apply_verdict(handle, outcome)
        self._notify(rule, outcome, view)
        return outcome

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _apply_verdict(self, handle: PacketHandle, outcome: ActionOutcome) -> None:
        try:
            if outcome.mark is not None:
                handle.set_mark(outcome.mark)
            if outcome.verdict == "accept":
                handle.accept()
            elif outcome.verdict == "drop":
                handle.drop()
            elif outcome.verdict == "repeat":
                # DelayAction: mangle engine doesn't schedule in unit
                # tests; NFQUEUE supports verdict NF_REPEAT which
                # re-queues the same packet. For unit tests and dry-run
                # this behaves like accept.
                handle.repeat() if hasattr(handle, "repeat") else handle.accept()
            elif outcome.verdict == "modified":
                if outcome.new_bytes is None:
                    handle.accept()
                else:
                    handle.set_payload(outcome.new_bytes)
                    handle.accept()
            else:
                handle.accept()
        except Exception as e:  # noqa: BLE001
            log.warning("mangle_verdict_error", error=str(e))
            self.stats.errors += 1
            self._safe_accept(handle)

    def _safe_accept(self, handle: PacketHandle) -> None:
        try:
            handle.accept()
        except Exception:  # noqa: BLE001
            pass

    def _tally(self, outcome: ActionOutcome) -> None:
        if outcome.verdict == "accept" and outcome.mark is not None:
            self.stats.marked += 1
            self.stats.accepted += 1
        elif outcome.verdict == "accept":
            self.stats.accepted += 1
        elif outcome.verdict == "drop":
            self.stats.dropped += 1
        elif outcome.verdict == "repeat":
            self.stats.delayed += 1
        elif outcome.verdict == "modified":
            if outcome.description.startswith("corrupt"):
                self.stats.corrupted += 1
            else:
                self.stats.rewritten += 1

    def _notify(self, rule: MangleRule | None, outcome: ActionOutcome, view: PacketView) -> None:
        if self._alert_sink is not None and rule is not None:
            try:
                self._alert_sink(rule, outcome, view)
            except Exception as e:  # noqa: BLE001
                log.warning("mangle_alert_sink_error", error=str(e))
        if self._event_sink is not None:
            try:
                self._event_sink(rule, outcome, view)
            except Exception as e:  # noqa: BLE001
                log.warning("mangle_event_sink_error", error=str(e))
