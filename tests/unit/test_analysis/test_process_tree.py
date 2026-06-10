"""Tests for the ProcessTree model and its renderers."""
from __future__ import annotations

from deepview.analysis.process_tree import ProcessTree
from deepview.core.types import EventCategory, EventSeverity, ProcessContext
from deepview.tracing.events import MonitorEvent


class TestBuild:
    def test_parent_child_linkage(self):
        tree = ProcessTree()
        tree.add(1, 0, "init")
        tree.add(100, 1, "bash")
        tree.add(101, 100, "curl")
        assert [n.pid for n in tree.roots()] == [1]
        assert [n.pid for n in tree.children(1)] == [100]
        assert [n.pid for n in tree.children(100)] == [101]

    def test_orphan_is_root(self):
        tree = ProcessTree()
        tree.add(500, 499, "orphan")  # ppid 499 unknown
        assert [n.pid for n in tree.roots()] == [500]

    def test_event_count_and_max_severity(self):
        tree = ProcessTree()
        tree.add(7, 1, "p", severity=EventSeverity.INFO, count=1)
        tree.add(7, 1, "p", severity=EventSeverity.CRITICAL, count=1)
        node = tree.node(7)
        assert node.event_count == 2
        assert node.max_severity == EventSeverity.CRITICAL

    def test_ingest_event(self):
        tree = ProcessTree()
        ev = MonitorEvent(
            category=EventCategory.PROCESS,
            severity=EventSeverity.WARNING,
            process=ProcessContext(pid=9, tid=9, ppid=1, uid=0, gid=0, comm="x"),
        )
        tree.ingest_event(ev)
        assert tree.node(9).max_severity == EventSeverity.WARNING
        assert tree.node(9).event_count == 1


class TestRender:
    def _tree(self) -> ProcessTree:
        tree = ProcessTree()
        tree.add(1, 0, "init")
        tree.add(100, 1, "bash", severity=EventSeverity.CRITICAL, count=3)
        tree.add(101, 100, "curl")
        return tree

    def test_to_dict_nests_children(self):
        data = self._tree().to_dict()
        assert len(data) == 1
        assert data[0]["pid"] == 1
        assert data[0]["children"][0]["pid"] == 100
        assert data[0]["children"][0]["severity"] == "critical"

    def test_to_svg_is_wellformed(self):
        svg = self._tree().to_svg()
        assert svg.startswith("<svg")
        assert svg.rstrip().endswith("</svg>")
        # one rect per node.
        assert svg.count("<rect") == 3
        # connectors for the two non-root nodes.
        assert svg.count("<path") == 2

    def test_to_svg_empty_tree(self):
        svg = ProcessTree().to_svg()
        assert svg.startswith("<svg")
        assert "no processes" in svg

    def test_render_rich_returns_tree(self):
        from rich.tree import Tree

        assert isinstance(self._tree().render_rich(), Tree)
