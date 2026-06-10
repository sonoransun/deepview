"""Process-ancestry model built from ``ppid`` relationships.

A :class:`ProcessTree` is the single source of truth for process lineage
shared by the dashboard's ``process_tree`` panel and the HTML report's
process diagram. Nodes can be fed from any source that exposes a pid/ppid
pair — live ``/proc``, tracing ``MonitorEvent.process``, a MemProcFS
process list, or a replayed session's ``events.ppid`` column — and the tree
renders to either a ``rich.tree.Tree`` (TUI) or self-contained SVG (report).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from deepview.core.findings import severity_rank
from deepview.core.types import EventSeverity

if TYPE_CHECKING:
    from rich.tree import Tree

    from deepview.tracing.events import MonitorEvent

_SEVERITY_FILL = {
    EventSeverity.INFO: ("#3b4252", "#d8dee9"),
    EventSeverity.WARNING: ("#b8860b", "#fff3cd"),
    EventSeverity.CRITICAL: ("#a4161a", "#ffd6d6"),
}
_SEVERITY_RICH = {
    EventSeverity.INFO: "white",
    EventSeverity.WARNING: "yellow",
    EventSeverity.CRITICAL: "bold red",
}


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


@dataclass
class ProcessNode:
    """One process in the tree."""

    pid: int
    ppid: int = 0
    comm: str = ""
    event_count: int = 0
    max_severity: EventSeverity = EventSeverity.INFO
    children: list[int] = field(default_factory=list)

    def to_dict(self, tree: ProcessTree) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "comm": self.comm,
            "event_count": self.event_count,
            "severity": self.max_severity.value,
            "children": [
                tree.node(c).to_dict(tree) for c in sorted(self.children)
            ],
        }


class ProcessTree:
    """A forest of :class:`ProcessNode` keyed by pid."""

    def __init__(self) -> None:
        self._nodes: dict[int, ProcessNode] = {}

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def add(
        self,
        pid: int,
        ppid: int = 0,
        comm: str = "",
        *,
        severity: EventSeverity = EventSeverity.INFO,
        count: int = 0,
    ) -> ProcessNode:
        """Insert or update a process node (idempotent upsert)."""
        node = self._nodes.get(pid)
        if node is None:
            node = ProcessNode(pid=pid, ppid=ppid, comm=comm)
            self._nodes[pid] = node
        if comm:
            node.comm = comm
        if ppid and ppid != pid:
            node.ppid = ppid
        node.event_count += count
        if severity_rank(severity) > severity_rank(node.max_severity):
            node.max_severity = severity
        self._link(node)
        return node

    def ingest_event(self, event: MonitorEvent) -> None:
        """Fold a ``MonitorEvent``'s process context into the tree."""
        proc = event.process
        if proc is None or proc.pid <= 0:
            return
        self.add(
            proc.pid,
            proc.ppid,
            proc.comm,
            severity=event.severity,
            count=1,
        )

    def _link(self, node: ProcessNode) -> None:
        parent = self._nodes.get(node.ppid)
        if parent is not None and parent.pid != node.pid:
            if node.pid not in parent.children:
                parent.children.append(node.pid)

    def _relink_all(self) -> None:
        for node in self._nodes.values():
            node.children.clear()
        for node in self._nodes.values():
            self._link(node)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def node(self, pid: int) -> ProcessNode:
        return self._nodes[pid]

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, pid: object) -> bool:
        return pid in self._nodes

    def children(self, pid: int) -> list[ProcessNode]:
        node = self._nodes.get(pid)
        if node is None:
            return []
        return [self._nodes[c] for c in sorted(node.children)]

    def roots(self) -> list[ProcessNode]:
        """Nodes whose parent is absent (or self/zero) — the forest tops."""
        roots = [
            n
            for n in self._nodes.values()
            if n.ppid == 0 or n.ppid == n.pid or n.ppid not in self._nodes
        ]
        return sorted(roots, key=lambda n: n.pid)

    def _preorder(self) -> list[tuple[ProcessNode, int]]:
        out: list[tuple[ProcessNode, int]] = []
        seen: set[int] = set()

        def walk(node: ProcessNode, depth: int) -> None:
            if node.pid in seen:
                return
            seen.add(node.pid)
            out.append((node, depth))
            for child in self.children(node.pid):
                walk(child, depth + 1)

        for root in self.roots():
            walk(root, 0)
        return out

    # ------------------------------------------------------------------
    # Renderers
    # ------------------------------------------------------------------

    def to_dict(self) -> list[dict[str, Any]]:
        return [root.to_dict(self) for root in self.roots()]

    def render_rich(self, *, label: str = "processes") -> Tree:
        """Render to a ``rich.tree.Tree`` for the dashboard."""
        from rich.tree import Tree

        root = Tree(label)

        def attach(parent_branch: Tree, node: ProcessNode) -> None:
            style = _SEVERITY_RICH.get(node.max_severity, "white")
            text = f"{node.comm or '?'} ({node.pid})  ·{node.event_count}"
            branch = parent_branch.add(f"[{style}]{text}[/{style}]")
            for child in self.children(node.pid):
                attach(branch, child)

        for top in self.roots():
            attach(root, top)
        return root

    def to_svg(
        self,
        *,
        width: int = 720,
        row_h: int = 26,
        indent: int = 26,
        margin: int = 12,
    ) -> str:
        """Render the forest to a self-contained inline SVG string."""
        rows = self._preorder()
        if not rows:
            return (
                f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
                f'height="40" role="img"><text x="{margin}" y="24" '
                f'font-family="monospace" font-size="12">(no processes)</text></svg>'
            )
        height = margin * 2 + len(rows) * row_h
        coords: dict[int, tuple[int, int]] = {}
        connectors: list[str] = []
        boxes: list[str] = []
        box_w = 230
        for i, (node, depth) in enumerate(rows):
            x = margin + depth * indent
            y = margin + i * row_h
            cy = y + row_h // 2
            coords[node.pid] = (x, cy)
            stroke, fill = _SEVERITY_FILL.get(node.max_severity, _SEVERITY_FILL[EventSeverity.INFO])
            label = _xml_escape(f"{node.comm or '?'} ({node.pid}) ·{node.event_count}")
            boxes.append(
                f'<rect x="{x}" y="{y + 3}" width="{box_w}" height="{row_h - 6}" '
                f'rx="4" fill="{fill}" stroke="{stroke}" stroke-width="1"/>'
                f'<text x="{x + 8}" y="{cy + 4}" font-family="monospace" '
                f'font-size="12" fill="#1a1a1a">{label}</text>'
            )
            if node.ppid in coords and node.ppid != node.pid:
                px, pcy = coords[node.ppid]
                connectors.append(
                    f'<path d="M{px + 6} {pcy + 6} V{cy} H{x}" fill="none" '
                    f'stroke="#9aa0a6" stroke-width="1"/>'
                )
        body = "".join(connectors) + "".join(boxes)
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
            f'height="{height}" role="img" aria-label="process tree">{body}</svg>'
        )

    # ------------------------------------------------------------------
    # Source helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_proc(cls) -> ProcessTree:
        """Build a snapshot from live ``/proc`` (Linux). Empty elsewhere."""
        from pathlib import Path

        tree = cls()
        proc = Path("/proc")
        if not proc.is_dir():
            return tree
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
                # comm is parenthesised and may contain spaces/parens.
                rparen = stat.rfind(")")
                comm = stat[stat.find("(") + 1 : rparen]
                after = stat[rparen + 2 :].split()
                ppid = int(after[1]) if len(after) > 1 else 0
            except (OSError, ValueError, IndexError):
                continue
            tree.add(pid, ppid, comm)
        return tree
