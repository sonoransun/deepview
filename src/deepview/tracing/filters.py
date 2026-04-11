"""Platform-independent filter DSL for trace events."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from deepview.tracing.events import MonitorEvent


@dataclass
class FilterRule:
    """One predicate in a filter expression."""
    field_path: str  # Dot-path: "process.pid", "category", "args.path"
    op: str  # "eq", "ne", "gt", "lt", "ge", "le", "in", "glob", "regex", "contains"
    value: Any


class FilterExpr:
    """Composable filter expression tree."""

    def __init__(self, op: str = "and", children: list[FilterExpr | FilterRule] | None = None):
        self.op = op  # "and", "or", "not"
        self.children: list[FilterExpr | FilterRule] = children or []

    def add(self, child: FilterExpr | FilterRule) -> FilterExpr:
        self.children.append(child)
        return self

    def evaluate(self, event: MonitorEvent) -> bool:
        """Evaluate this filter against a MonitorEvent."""
        if self.op == "and":
            return all(self._eval_child(c, event) for c in self.children)
        elif self.op == "or":
            return any(self._eval_child(c, event) for c in self.children)
        elif self.op == "not":
            return not self._eval_child(self.children[0], event) if self.children else True
        return True

    def _eval_child(self, child: FilterExpr | FilterRule, event: MonitorEvent) -> bool:
        if isinstance(child, FilterExpr):
            return child.evaluate(event)
        return self._eval_rule(child, event)

    def _eval_rule(self, rule: FilterRule, event: MonitorEvent) -> bool:
        value = self._resolve_field(event, rule.field_path)
        if value is None:
            return False

        if rule.op == "eq":
            return value == rule.value
        elif rule.op == "ne":
            return value != rule.value
        elif rule.op == "gt":
            return value > rule.value
        elif rule.op == "lt":
            return value < rule.value
        elif rule.op == "ge":
            return value >= rule.value
        elif rule.op == "le":
            return value <= rule.value
        elif rule.op == "in":
            return value in rule.value
        elif rule.op == "contains":
            return rule.value in str(value)
        elif rule.op == "glob":
            import fnmatch
            return fnmatch.fnmatch(str(value), rule.value)
        elif rule.op == "regex":
            import re
            return bool(re.search(rule.value, str(value)))
        return False

    def _resolve_field(self, event: MonitorEvent, path: str) -> Any:
        """Resolve a dot-path field from a MonitorEvent."""
        parts = path.split(".")
        obj: Any = event
        for part in parts:
            if obj is None:
                return None
            if isinstance(obj, dict):
                obj = obj.get(part)
            elif hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                return None
        return obj

    @classmethod
    def pid_filter(cls, pid: int) -> FilterExpr:
        """Convenience: filter by process PID."""
        return cls("and", [FilterRule("process.pid", "eq", pid)])

    @classmethod
    def syscall_filter(cls, *names: str) -> FilterExpr:
        """Convenience: filter by syscall name(s)."""
        return cls("or", [FilterRule("syscall_name", "eq", name) for name in names])

    @classmethod
    def category_filter(cls, category: str) -> FilterExpr:
        """Convenience: filter by event category."""
        return cls("and", [FilterRule("category", "eq", category)])

    @classmethod
    def path_filter(cls, path_glob: str) -> FilterExpr:
        """Convenience: filter by file-access path (glob)."""
        return cls("and", [FilterRule("args.path", "glob", path_glob)])


# Fields eligible for kernel-side push-down across backends. The backend
# decides which of these it can actually compile; the rest stay in user
# space. Using a module-level set keeps all providers in sync.
PUSH_DOWN_FIELDS: set[str] = {
    "process.pid",
    "process.uid",
    "process.comm",
    "args.path",
    "args.protocol",
    "args.dst_port",
    "args.src_port",
    "category",
}


def split_for_pushdown(
    filter_expr: FilterExpr | None,
    *,
    supported_fields: set[str] | None = None,
) -> tuple[list[FilterRule], list[FilterRule]]:
    """Split a filter tree into kernel-pushable and residual rules.

    Only leaf ``FilterRule`` nodes inside a top-level ``and`` expression can be
    pushed down — OR / NOT semantics would require more delicate treatment and
    are left for future work.
    """
    if filter_expr is None:
        return [], []
    allowed = supported_fields or PUSH_DOWN_FIELDS
    pushed: list[FilterRule] = []
    remaining: list[FilterRule] = []
    if filter_expr.op != "and":
        # Flatten only AND trees; hand everything else back as residual.
        residual = _collect_rules(filter_expr)
        return [], residual
    for child in filter_expr.children:
        if isinstance(child, FilterRule):
            if child.field_path in allowed and child.op in ("eq", "glob", "in"):
                pushed.append(child)
            else:
                remaining.append(child)
        else:
            remaining.extend(_collect_rules(child))
    return pushed, remaining


def _collect_rules(expr: FilterExpr | FilterRule) -> list[FilterRule]:
    if isinstance(expr, FilterRule):
        return [expr]
    out: list[FilterRule] = []
    for child in expr.children:
        out.extend(_collect_rules(child))
    return out
