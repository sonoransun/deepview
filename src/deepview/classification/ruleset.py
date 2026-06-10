"""YAML ruleset loader and :class:`Ruleset` container.

Rule file shape (one document per file, or a top-level ``rules`` list)::

    id: exec_from_worldwritable
    title: Exec from world-writable directory
    severity: critical
    category: execution
    attack_ids: [T1203, T1204]
    match: 'syscall_name == "execve" and args.filename glob "/tmp/*"'
    labels:
      tactic: execution
    metadata:
      source: deepview.builtin

Only ``id`` and ``match`` are mandatory. ``match`` is the textual
filter DSL that :func:`deepview.tracing.filters.parse_filter` already
understands, so authors do not need to learn a second syntax.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Iterator

from deepview.core.logging import get_logger
from deepview.tracing.events import MonitorEvent
from deepview.tracing.filters import FilterExpr, FilterSyntaxError, parse_filter

if TYPE_CHECKING:
    from deepview.classification.classifier import ClassificationResult

log = get_logger("classification.ruleset")


class RuleLoadError(ValueError):
    """Raised when a rule file or inline mapping cannot be loaded."""


_SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


@dataclass
class SequenceStep:
    """One ordered step in a multi-event ``sequence`` rule."""

    match: FilterExpr
    within_s: float = 0.0  # max gap from the previous step (0 = unbounded)


@dataclass
class AggregateSpec:
    """A thresholded count over a sliding window for an ``aggregate`` rule."""

    count: int
    within_s: float
    match: FilterExpr | None = None  # events to count (None = all for the PID)
    field: str | None = None  # count DISTINCT values of this field (None = events)


@dataclass
class ClassificationRule:
    """A single classification rule after compile.

    A rule is either *simple* (a single-event ``match``) or *stateful*
    (a ``sequence`` of steps, or an ``aggregate`` threshold). Stateful
    rules are evaluated by the per-PID matcher in the classifier, not by
    :meth:`Ruleset.classify`.
    """

    id: str
    title: str
    severity: str
    category: str
    attack_ids: list[str]
    match: FilterExpr | None = None
    sequence: list[SequenceStep] | None = None
    aggregate: AggregateSpec | None = None
    labels: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_simple(self) -> bool:
        return self.match is not None and self.sequence is None and self.aggregate is None

    @property
    def is_stateful(self) -> bool:
        return self.sequence is not None or self.aggregate is not None

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "ClassificationRule":
        if not isinstance(data, dict):
            raise RuleLoadError(f"rule must be a mapping, got {type(data).__name__}")
        rule_id = data.get("id")
        if not rule_id:
            raise RuleLoadError("rule is missing 'id'")

        match_expr = cls._parse_match(rule_id, data.get("match")) if data.get("match") else None
        sequence = cls._parse_sequence(rule_id, data.get("sequence"))
        aggregate = cls._parse_aggregate(rule_id, data.get("aggregate"))
        if match_expr is None and sequence is None and aggregate is None:
            raise RuleLoadError(
                f"rule '{rule_id}' needs one of 'match', 'sequence', or 'aggregate'"
            )

        severity = str(data.get("severity", "warning")).lower()
        if severity not in _SEVERITY_ORDER:
            raise RuleLoadError(
                f"rule '{rule_id}' has unknown severity '{severity}', "
                "expected one of info|warning|critical"
            )
        labels = data.get("labels") or {}
        if not isinstance(labels, dict):
            raise RuleLoadError(f"rule '{rule_id}' labels must be a mapping")
        metadata = data.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise RuleLoadError(f"rule '{rule_id}' metadata must be a mapping")
        return cls(
            id=str(rule_id),
            title=str(data.get("title", rule_id)),
            severity=severity,
            category=str(data.get("category", "generic")),
            attack_ids=[str(t) for t in (data.get("attack_ids") or [])],
            match=match_expr,
            sequence=sequence,
            aggregate=aggregate,
            labels={str(k): str(v) for k, v in labels.items()},
            metadata=dict(metadata),
        )

    @staticmethod
    def _parse_match(rule_id: object, text: object) -> FilterExpr:
        try:
            return parse_filter(str(text))
        except FilterSyntaxError as e:
            raise RuleLoadError(f"rule '{rule_id}' match expression invalid: {e}") from e

    @classmethod
    def _parse_sequence(
        cls, rule_id: object, raw: object
    ) -> list[SequenceStep] | None:
        if raw is None:
            return None
        if not isinstance(raw, list) or not raw:
            raise RuleLoadError(f"rule '{rule_id}' sequence must be a non-empty list")
        steps: list[SequenceStep] = []
        for i, item in enumerate(raw):
            if not isinstance(item, dict) or "match" not in item:
                raise RuleLoadError(
                    f"rule '{rule_id}' sequence[{i}] must be a mapping with 'match'"
                )
            steps.append(
                SequenceStep(
                    match=cls._parse_match(rule_id, item["match"]),
                    within_s=float(item.get("within_s", 0.0)),
                )
            )
        return steps

    @classmethod
    def _parse_aggregate(cls, rule_id: object, raw: object) -> AggregateSpec | None:
        if raw is None:
            return None
        if not isinstance(raw, dict):
            raise RuleLoadError(f"rule '{rule_id}' aggregate must be a mapping")
        if "count" not in raw or "within_s" not in raw:
            raise RuleLoadError(
                f"rule '{rule_id}' aggregate needs 'count' and 'within_s'"
            )
        match_raw = raw.get("match")
        return AggregateSpec(
            count=int(raw["count"]),
            within_s=float(raw["within_s"]),
            match=cls._parse_match(rule_id, match_raw) if match_raw else None,
            field=str(raw["field"]) if raw.get("field") else None,
        )


class Ruleset:
    """A loadable collection of :class:`ClassificationRule`."""

    def __init__(self, rules: Iterable[ClassificationRule] | None = None) -> None:
        self._rules: list[ClassificationRule] = list(rules or [])

    def __iter__(self) -> Iterator[ClassificationRule]:
        return iter(self._rules)

    def __len__(self) -> int:
        return len(self._rules)

    def add(self, rule: ClassificationRule) -> None:
        self._rules.append(rule)

    def extend(self, rules: Iterable[ClassificationRule]) -> None:
        self._rules.extend(rules)

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    @classmethod
    def from_mappings(cls, entries: Iterable[dict[str, Any]]) -> "Ruleset":
        return cls(ClassificationRule.from_mapping(e) for e in entries)

    @classmethod
    def load_yaml(cls, path: Path | str) -> "Ruleset":
        """Load one YAML file.

        The file may contain either a top-level list of rule mappings
        or a mapping with a ``rules`` key.
        """
        try:
            import yaml  # type: ignore
        except ImportError as e:
            raise RuleLoadError(
                "PyYAML is required to load ruleset files; install with "
                "'pip install pyyaml'"
            ) from e
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as e:
            raise RuleLoadError(f"cannot read {p}: {e}") from e
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise RuleLoadError(f"invalid YAML in {p}: {e}") from e
        entries: list[dict[str, Any]]
        if isinstance(data, list):
            entries = [e for e in data if isinstance(e, dict)]
        elif isinstance(data, dict) and "rules" in data:
            entries = [e for e in data["rules"] if isinstance(e, dict)]
        else:
            raise RuleLoadError(f"{p} has no 'rules' list and is not a list of rules")
        ruleset = cls.from_mappings(entries)
        log.info("ruleset_loaded", path=str(p), count=len(ruleset))
        return ruleset

    @classmethod
    def load_sigma_dir(cls, directory: Path | str) -> "Ruleset":
        """Load Sigma rules from *directory* (best-effort conversion)."""
        from deepview.classification.sigma_loader import load_sigma_dir

        return load_sigma_dir(directory)

    @classmethod
    def load_builtin(cls) -> "Ruleset":
        """Load every YAML file under ``builtin_rules/``."""
        base = Path(__file__).parent / "builtin_rules"
        if not base.exists():
            return cls()
        combined = cls()
        for yaml_path in sorted(base.glob("*.yaml")):
            try:
                combined.extend(cls.load_yaml(yaml_path))
            except RuleLoadError as e:
                log.warning("builtin_ruleset_load_failed", path=str(yaml_path), error=str(e))
        return combined

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def classify(self, event: MonitorEvent) -> list["ClassificationResult"]:
        """Return one :class:`ClassificationResult` per matching rule."""
        from deepview.classification.classifier import ClassificationResult

        out: list[ClassificationResult] = []
        for rule in self._rules:
            if not rule.is_simple or rule.match is None:
                continue
            try:
                if rule.match.evaluate(event):
                    out.append(
                        ClassificationResult(
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            category=rule.category,
                            attack_ids=list(rule.attack_ids),
                            labels=dict(rule.labels),
                        )
                    )
            except Exception as e:  # noqa: BLE001
                log.debug("rule_eval_error", rule_id=rule.id, error=str(e))
        return out

    def severity_rank(self, severity: str) -> int:
        return _SEVERITY_ORDER.get(severity.lower(), 0)
