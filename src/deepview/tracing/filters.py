"""Platform-independent filter DSL for trace events.

This module owns three responsibilities:

1. The filter *tree*: :class:`FilterExpr` + :class:`FilterRule`, both
   usable directly from Python for composing filters programmatically.
2. A *textual* surface: :func:`parse_filter` accepts the same DSL the
   CLI ``--filter`` flag advertises and emits a :class:`FilterExpr`.
3. A *compile* step: :meth:`FilterExpr.compile` walks the tree and
   lifts cheap predicates (``process.pid``, ``process.uid``,
   ``process.comm``, ``syscall_nr``, ``category``) into a
   :class:`FilterPlan` whose ``kernel_hints`` can be installed into
   BPF maps by :mod:`deepview.tracing.providers.ebpf`. Anything that
   cannot be pushed down stays in ``FilterPlan.remainder`` and is
   evaluated user-side on every event.

The compile step is intentionally conservative: it only lifts
top-level ``and``-chain predicates. Anything nested under ``or`` /
``not`` stays in the remainder verbatim. This keeps semantics obvious
("what's in the hint set behaves as an allowlist; the remainder still
has the full filter tree") and avoids turning this into a query
planner.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from deepview.tracing.events import MonitorEvent


@dataclass
class FilterRule:
    """One predicate in a filter expression."""
    field_path: str  # Dot-path: "process.pid", "category", "args.path"
    op: str  # "eq", "ne", "gt", "lt", "ge", "le", "in", "glob", "regex", "contains"
    value: Any


class FilterExpr:
    """Composable filter expression tree."""

    def __init__(self, op: str = "and", children: list["FilterExpr | FilterRule"] | None = None):
        self.op = op  # "and", "or", "not"
        self.children: list[FilterExpr | FilterRule] = children or []

    def add(self, child: "FilterExpr | FilterRule") -> "FilterExpr":
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

    def _eval_child(self, child: "FilterExpr | FilterRule", event: MonitorEvent) -> bool:
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
        # Normalise enum-like values (EventCategory, EventSeverity) to
        # their string values so comparisons in user-supplied filters
        # work without forcing callers to import the enum.
        if hasattr(obj, "value") and not isinstance(obj, (str, int, float, bool)):
            return obj.value
        return obj

    def compile(self) -> "FilterPlan":
        """Lift cheap predicates into a :class:`FilterPlan`.

        Only top-level ``and``-chains are considered. A lifted rule is
        kept in ``FilterPlan.remainder`` as well so that the user-space
        evaluator stays correct even if the kernel hint was ignored by
        the backend.
        """
        hints = KernelHints()
        if self is None or self.op != "and":
            return FilterPlan(kernel_hints=hints, remainder=self)

        for child in self.children:
            if isinstance(child, FilterRule):
                _try_lift(child, hints)
        return FilterPlan(kernel_hints=hints, remainder=self)

    @classmethod
    def pid_filter(cls, pid: int) -> "FilterExpr":
        return cls("and", [FilterRule("process.pid", "eq", pid)])

    @classmethod
    def syscall_filter(cls, *names: str) -> "FilterExpr":
        return cls("or", [FilterRule("syscall_name", "eq", name) for name in names])

    @classmethod
    def category_filter(cls, category: str) -> "FilterExpr":
        return cls("and", [FilterRule("category", "eq", category)])


# ---------------------------------------------------------------------------
# Compile target
# ---------------------------------------------------------------------------


@dataclass
class KernelHints:
    """Lifted predicates ready to push into a backend's kernel filter."""

    pids: set[int] = field(default_factory=set)
    uids: set[int] = field(default_factory=set)
    comms: set[str] = field(default_factory=set)
    syscall_nrs: set[int] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)

    def is_empty(self) -> bool:
        return not (self.pids or self.uids or self.comms or self.syscall_nrs or self.categories)

    def merge(self, other: "KernelHints") -> None:
        self.pids |= other.pids
        self.uids |= other.uids
        self.comms |= other.comms
        self.syscall_nrs |= other.syscall_nrs
        self.categories |= other.categories


@dataclass
class FilterPlan:
    """Result of :meth:`FilterExpr.compile`.

    ``kernel_hints`` is an advisory set-of-allowlists. ``remainder``
    is the full filter expression (possibly the same tree that was
    compiled) and is always evaluated user-side; backends that
    successfully install the hints may therefore skip predicates they
    already handled, but backends that ignore them still stay correct.
    """

    kernel_hints: KernelHints
    remainder: FilterExpr | None


def _try_lift(rule: FilterRule, hints: KernelHints) -> None:
    value = rule.value
    if rule.field_path == "process.pid":
        if rule.op == "eq":
            hints.pids.add(int(value))
        elif rule.op == "in" and isinstance(value, Iterable):
            for v in value:
                hints.pids.add(int(v))
    elif rule.field_path == "process.uid":
        if rule.op == "eq":
            hints.uids.add(int(value))
        elif rule.op == "in" and isinstance(value, Iterable):
            for v in value:
                hints.uids.add(int(v))
    elif rule.field_path == "process.comm":
        if rule.op == "eq":
            hints.comms.add(str(value))
        elif rule.op == "in" and isinstance(value, Iterable):
            for v in value:
                hints.comms.add(str(v))
    elif rule.field_path == "syscall_nr":
        if rule.op == "eq":
            hints.syscall_nrs.add(int(value))
        elif rule.op == "in" and isinstance(value, Iterable):
            for v in value:
                hints.syscall_nrs.add(int(v))
    elif rule.field_path == "syscall_name":
        if rule.op == "eq":
            _add_syscall_names(hints, [str(value)])
        elif rule.op == "in" and isinstance(value, Iterable):
            _add_syscall_names(hints, [str(v) for v in value])
    elif rule.field_path == "category":
        if rule.op == "eq":
            hints.categories.add(str(value))
        elif rule.op == "in" and isinstance(value, Iterable):
            for v in value:
                hints.categories.add(str(v))


def _add_syscall_names(hints: KernelHints, names: list[str]) -> None:
    # Local import to avoid pulling the Linux syscall table when the
    # filter subsystem is used on non-Linux platforms.
    try:
        from deepview.tracing.linux.syscalls import syscall_nr
    except ImportError:
        return
    for name in names:
        nr = syscall_nr(name)
        if nr is not None:
            hints.syscall_nrs.add(nr)


# ---------------------------------------------------------------------------
# Textual parser
# ---------------------------------------------------------------------------


class FilterSyntaxError(ValueError):
    """Raised by :func:`parse_filter` on unparsable input."""


def parse_filter(text: str) -> FilterExpr:
    """Parse a filter expression from text.

    Grammar (informal)::

        expr    := term ( ('and' | 'or') term )*
        term    := 'not' term | '(' expr ')' | rule
        rule    := FIELD OP value
        OP      := '==' | '!=' | '>' | '<' | '>=' | '<=' | 'in' |
                   'contains' | 'glob' | 'regex'
        value   := STRING | INT | '[' value (',' value)* ']'
        FIELD   := dot.path (letters, digits, '_', '.')
        STRING  := "..." | '...'

    Example::

        'process.pid == 1234'
        'syscall_name in ["openat","openat2"] and args.path glob "/etc/*"'
        'category == "file_io" and not process.comm == "systemd"'
    """
    parser = _Parser(text)
    expr = parser.parse_expr()
    parser.expect_eof()
    return expr


_TOKEN_OPS_MULTI = {"==", "!=", ">=", "<="}
_TOKEN_OPS_SINGLE = {">", "<"}
_WORD_OPS = {"in", "contains", "glob", "regex", "and", "or", "not"}


class _Parser:
    def __init__(self, text: str) -> None:
        self._text = text
        self._pos = 0

    # Lexer helpers ---------------------------------------------------------

    def _skip_ws(self) -> None:
        while self._pos < len(self._text) and self._text[self._pos].isspace():
            self._pos += 1

    def _peek(self) -> str:
        self._skip_ws()
        return self._text[self._pos] if self._pos < len(self._text) else ""

    def _match(self, literal: str) -> bool:
        self._skip_ws()
        end = self._pos + len(literal)
        if self._text[self._pos : end] == literal:
            # Word literal must not be adjacent to identifier chars.
            if literal.isalpha() and end < len(self._text):
                nxt = self._text[end]
                if nxt.isalnum() or nxt == "_":
                    return False
            self._pos = end
            return True
        return False

    def _read_ident(self) -> str:
        self._skip_ws()
        start = self._pos
        while self._pos < len(self._text):
            c = self._text[self._pos]
            if c.isalnum() or c == "_" or c == ".":
                self._pos += 1
            else:
                break
        if start == self._pos:
            raise FilterSyntaxError(f"expected identifier at offset {self._pos}")
        return self._text[start : self._pos]

    def _read_string(self) -> str:
        self._skip_ws()
        if self._pos >= len(self._text):
            raise FilterSyntaxError("expected string literal")
        quote = self._text[self._pos]
        if quote not in ("'", '"'):
            raise FilterSyntaxError(f"expected quote at offset {self._pos}")
        self._pos += 1
        out: list[str] = []
        while self._pos < len(self._text):
            c = self._text[self._pos]
            if c == quote:
                self._pos += 1
                return "".join(out)
            if c == "\\" and self._pos + 1 < len(self._text):
                nxt = self._text[self._pos + 1]
                out.append({"n": "\n", "t": "\t", "\\": "\\", "'": "'", '"': '"'}.get(nxt, nxt))
                self._pos += 2
                continue
            out.append(c)
            self._pos += 1
        raise FilterSyntaxError("unterminated string literal")

    def _read_int(self) -> int:
        self._skip_ws()
        start = self._pos
        if self._pos < len(self._text) and self._text[self._pos] in "+-":
            self._pos += 1
        while self._pos < len(self._text) and self._text[self._pos].isdigit():
            self._pos += 1
        if start == self._pos:
            raise FilterSyntaxError(f"expected integer at offset {self._pos}")
        return int(self._text[start : self._pos])

    # Grammar ---------------------------------------------------------------

    def parse_expr(self) -> FilterExpr:
        left = self._parse_term()
        while True:
            if self._match("and"):
                right = self._parse_term()
                if isinstance(left, FilterExpr) and left.op == "and":
                    left.children.append(right)
                else:
                    left = FilterExpr("and", [left, right])
            elif self._match("or"):
                right = self._parse_term()
                if isinstance(left, FilterExpr) and left.op == "or":
                    left.children.append(right)
                else:
                    left = FilterExpr("or", [left, right])
            else:
                break
        if isinstance(left, FilterRule):
            return FilterExpr("and", [left])
        return left

    def _parse_term(self) -> FilterExpr | FilterRule:
        if self._match("not"):
            inner = self._parse_term()
            return FilterExpr("not", [inner])
        if self._match("("):
            inner = self.parse_expr()
            if not self._match(")"):
                raise FilterSyntaxError("expected ')'")
            return inner
        return self._parse_rule()

    def _parse_rule(self) -> FilterRule:
        field = self._read_ident()
        op = self._read_op()
        value = self._parse_value()
        return FilterRule(field, op, value)

    def _read_op(self) -> str:
        self._skip_ws()
        for multi in _TOKEN_OPS_MULTI:
            if self._text[self._pos : self._pos + 2] == multi:
                self._pos += 2
                return {"==": "eq", "!=": "ne", ">=": "ge", "<=": "le"}[multi]
        if self._pos < len(self._text) and self._text[self._pos] in _TOKEN_OPS_SINGLE:
            c = self._text[self._pos]
            self._pos += 1
            return {">": "gt", "<": "lt"}[c]
        # Word op.
        for word in ("in", "contains", "glob", "regex"):
            if self._match(word):
                return word
        raise FilterSyntaxError(f"expected comparison operator at offset {self._pos}")

    def _parse_value(self) -> Any:
        self._skip_ws()
        if self._pos < len(self._text) and self._text[self._pos] in ("'", '"'):
            return self._read_string()
        if self._pos < len(self._text) and self._text[self._pos] == "[":
            self._pos += 1
            items: list[Any] = []
            while True:
                self._skip_ws()
                if self._pos < len(self._text) and self._text[self._pos] == "]":
                    self._pos += 1
                    return items
                items.append(self._parse_value())
                self._skip_ws()
                if self._pos < len(self._text) and self._text[self._pos] == ",":
                    self._pos += 1
                    continue
                if self._pos < len(self._text) and self._text[self._pos] == "]":
                    self._pos += 1
                    return items
                raise FilterSyntaxError("expected ',' or ']' in list literal")
        # Integer or bare word (identifier treated as string).
        if self._pos < len(self._text) and (self._text[self._pos].isdigit() or self._text[self._pos] in "+-"):
            return self._read_int()
        return self._read_ident()

    def expect_eof(self) -> None:
        self._skip_ws()
        if self._pos != len(self._text):
            raise FilterSyntaxError(f"unexpected trailing input at offset {self._pos}")
