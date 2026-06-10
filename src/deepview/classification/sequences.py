"""Per-PID stateful matcher for ``sequence`` and ``aggregate`` rules.

Single-event ``match`` rules are stateless and handled by
:meth:`Ruleset.classify`. Multi-step rules need memory across events, so
the classifier feeds every event through a :class:`StatefulMatcher` which
keeps a small state machine per ``(rule, pid)`` and emits a
:class:`SequenceHit` when a chain completes or a threshold is crossed.

State is intentionally per-PID and single-instance per rule (no overlapping
partial matches), which keeps it O(rules) per event under the trace
firehose; that is a deliberate simplicity/cost trade-off.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable

from deepview.classification.ruleset import ClassificationRule
from deepview.tracing.events import MonitorEvent
from deepview.tracing.filters import resolve_field


@dataclass
class SequenceHit:
    """A completed stateful rule, ready to become a ClassificationResult."""

    rule_id: str
    title: str
    severity: str
    category: str
    attack_ids: list[str]
    labels: dict[str, str]
    pid: int
    comm: str
    matched_event_ids: list[str]


@dataclass
class _SeqState:
    index: int = 0
    last_ts_ns: int = 0
    matched_ids: list[str] = field(default_factory=list)


class StatefulMatcher:
    """Advance sequence/aggregate rules over a per-PID event stream."""

    def __init__(self, rules: Iterable[ClassificationRule]) -> None:
        rule_list = list(rules)
        self._seq_rules = [r for r in rule_list if r.sequence]
        self._agg_rules = [r for r in rule_list if r.aggregate]
        self._seq_state: dict[tuple[str, int], _SeqState] = {}
        self._agg_state: dict[tuple[str, int], deque[tuple[int, object]]] = {}

    @property
    def active(self) -> bool:
        return bool(self._seq_rules or self._agg_rules)

    def feed(self, event: MonitorEvent) -> list[SequenceHit]:
        if not self.active:
            return []
        pid = event.process.pid if event.process else 0
        if pid <= 0:
            return []
        comm = event.process.comm if event.process else ""
        now = event.wall_clock_ns or time.time_ns()
        hits: list[SequenceHit] = []
        for rule in self._seq_rules:
            hit = self._advance_sequence(rule, event, pid, comm, now)
            if hit is not None:
                hits.append(hit)
        for rule in self._agg_rules:
            hit = self._advance_aggregate(rule, event, pid, comm, now)
            if hit is not None:
                hits.append(hit)
        return hits

    def _advance_sequence(
        self,
        rule: ClassificationRule,
        event: MonitorEvent,
        pid: int,
        comm: str,
        now: int,
    ) -> SequenceHit | None:
        assert rule.sequence is not None
        key = (rule.id, pid)
        st = self._seq_state.get(key, _SeqState())

        # Expire a partial chain whose next step missed its time budget.
        if st.index > 0:
            step = rule.sequence[st.index]
            if step.within_s > 0 and now - st.last_ts_ns > int(step.within_s * 1e9):
                st = _SeqState()

        step = rule.sequence[st.index]
        if step.match is not None and step.match.evaluate(event):
            st.index += 1
            st.last_ts_ns = now
            st.matched_ids.append(event.event_id)
            if st.index >= len(rule.sequence):
                self._seq_state[key] = _SeqState()
                return self._hit(rule, pid, comm, list(st.matched_ids))
        self._seq_state[key] = st
        return None

    def _advance_aggregate(
        self,
        rule: ClassificationRule,
        event: MonitorEvent,
        pid: int,
        comm: str,
        now: int,
    ) -> SequenceHit | None:
        spec = rule.aggregate
        assert spec is not None
        if spec.match is not None and not spec.match.evaluate(event):
            return None
        value: object = (
            resolve_field(event, spec.field) if spec.field else event.event_id
        )
        key = (rule.id, pid)
        window = self._agg_state.setdefault(key, deque())
        window.append((now, value))
        cutoff = now - int(spec.within_s * 1e9)
        while window and window[0][0] < cutoff:
            window.popleft()
        measure = len({v for _, v in window}) if spec.field else len(window)
        if measure >= spec.count:
            window.clear()  # re-arm so it does not fire on every later event
            return self._hit(rule, pid, comm, [event.event_id])
        return None

    @staticmethod
    def _hit(
        rule: ClassificationRule, pid: int, comm: str, matched_ids: list[str]
    ) -> SequenceHit:
        return SequenceHit(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            category=rule.category,
            attack_ids=list(rule.attack_ids),
            labels=dict(rule.labels),
            pid=pid,
            comm=comm,
            matched_event_ids=matched_ids,
        )
