"""Tests for the live EventClassifier."""
from __future__ import annotations


from deepview.classification import EventClassifier, Ruleset
from deepview.core.context import AnalysisContext
from deepview.core.events import EventClassifiedEvent
from deepview.core.types import EventCategory, EventSource, ProcessContext
from deepview.tracing.events import MonitorEvent
from deepview.tracing.stream import TraceEventBus


def _event(**kwargs) -> MonitorEvent:
    process = kwargs.pop("process", None) or ProcessContext(
        pid=42, tid=42, ppid=1, uid=0, gid=0, comm="test"
    )
    source = kwargs.pop("source", None) or EventSource(
        platform="linux", backend="test", probe_name="t"
    )
    return MonitorEvent(process=process, source=source, **kwargs)


def _critical_ruleset() -> Ruleset:
    return Ruleset.from_mappings(
        [
            {
                "id": "test.exec_tmp",
                "title": "Exec from /tmp",
                "severity": "critical",
                "category": "execution",
                "attack_ids": ["T1204"],
                "match": 'syscall_name == "execve" and args.filename glob "/tmp/*"',
                "labels": {"tactic": "execution"},
            }
        ]
    )


class TestClassifyAndPublish:
    def test_match_attaches_classification(self):
        bus = TraceEventBus()
        classifier = EventClassifier(None, _critical_ruleset(), source_bus=bus)
        ev = _event(
            category=EventCategory.SYSCALL_RAW,
            syscall_name="execve",
            args={"filename": "/tmp/evil"},
        )
        results = classifier.classify_and_publish(ev)
        assert len(results) == 1
        assert results[0].rule_id == "test.exec_tmp"
        assert "classifications" in ev.metadata
        assert ev.severity.value == "critical"

    def test_match_publishes_to_core_event_bus(self):
        ctx = AnalysisContext.for_testing()
        captured: list[EventClassifiedEvent] = []
        ctx.events.subscribe(EventClassifiedEvent, captured.append)

        bus = TraceEventBus()
        classifier = EventClassifier(ctx, _critical_ruleset(), source_bus=bus)
        ev = _event(
            category=EventCategory.SYSCALL_RAW,
            syscall_name="execve",
            args={"filename": "/tmp/evil"},
        )
        classifier.classify_and_publish(ev)
        assert len(captured) == 1
        assert captured[0].rule_id == "test.exec_tmp"
        assert captured[0].severity == "critical"

    def test_no_match_still_publishes_to_classified_bus(self):
        bus = TraceEventBus()
        classifier = EventClassifier(None, _critical_ruleset(), source_bus=bus)
        sub = classifier.bus.subscribe()
        ev = _event(syscall_name="read")
        classifier.classify_and_publish(ev)
        # The event makes it through even without classification.
        assert not sub.queue.empty()

    def test_sequence_rule_publishes_sequence_event(self):
        from deepview.core.events import EventSequenceDetectedEvent

        ruleset = Ruleset.from_mappings(
            [
                {
                    "id": "seq.exec_connect",
                    "title": "exec then connect",
                    "severity": "critical",
                    "attack_ids": ["T1204"],
                    "sequence": [
                        {"match": 'syscall_name == "execve"'},
                        {"match": 'syscall_name == "connect"', "within_s": 30},
                    ],
                }
            ]
        )
        ctx = AnalysisContext.for_testing()
        seq_events: list[EventSequenceDetectedEvent] = []
        ctx.events.subscribe(EventSequenceDetectedEvent, seq_events.append)

        bus = TraceEventBus()
        classifier = EventClassifier(ctx, ruleset, source_bus=bus)
        base = 1_700_000_000 * 1_000_000_000
        classifier.classify_and_publish(_event(wall_clock_ns=base, syscall_name="execve"))
        results = classifier.classify_and_publish(
            _event(wall_clock_ns=base + 1_000_000_000, syscall_name="connect")
        )
        # The completed chain shows up as a classification AND a typed event.
        assert any(r.rule_id == "seq.exec_connect" for r in results)
        assert len(seq_events) == 1
        assert seq_events[0].rule_id == "seq.exec_connect"
        assert seq_events[0].pid == 42

    def test_pid_window_accumulates_syscalls(self):
        bus = TraceEventBus()
        classifier = EventClassifier(None, Ruleset(), source_bus=bus)
        for _ in range(5):
            classifier.classify_and_publish(_event(syscall_name="read"))
        win = classifier.snapshot_window(42)
        assert win is not None
        assert win.syscalls == 5
