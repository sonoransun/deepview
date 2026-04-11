"""Mangle ruleset YAML loader.

Deliberately modelled on :class:`deepview.classification.ruleset.Ruleset`
so rule authors only have to learn one style. The ``match:`` clause
reuses :func:`deepview.tracing.filters.parse_filter` and predicates
walk an envelope whose top-level attribute is ``packet`` (a
:class:`PacketView`).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from deepview.core.logging import get_logger
from deepview.networking.actions import Action, action_from_mapping
from deepview.networking.packet import MatchEnvelope
from deepview.tracing.filters import FilterExpr, FilterSyntaxError, parse_filter

log = get_logger("networking.ruleset")


class MangleRuleLoadError(ValueError):
    """Raised by :class:`MangleRuleset` YAML loader errors."""


@dataclass
class MangleRule:
    id: str
    description: str
    match: FilterExpr
    action: Action
    metadata: dict[str, Any] = field(default_factory=dict)

    def matches(self, envelope: MatchEnvelope) -> bool:
        try:
            return self.match.evaluate(envelope)  # type: ignore[arg-type]
        except Exception as e:  # noqa: BLE001
            log.debug("mangle_rule_eval_error", rule_id=self.id, error=str(e))
            return False


@dataclass
class MangleRuleset:
    rules: list[MangleRule] = field(default_factory=list)
    queue: int = 0
    default_verdict: str = "accept"
    fail_open: bool = True
    source_sha256: str = ""

    def __iter__(self):
        return iter(self.rules)

    def __len__(self) -> int:
        return len(self.rules)

    @classmethod
    def from_mappings(
        cls,
        entries: Iterable[dict[str, Any]],
        *,
        queue: int = 0,
        default_verdict: str = "accept",
        fail_open: bool = True,
        source_sha256: str = "",
    ) -> "MangleRuleset":
        compiled = [_compile_rule(e) for e in entries]
        return cls(
            rules=compiled,
            queue=queue,
            default_verdict=default_verdict,
            fail_open=fail_open,
            source_sha256=source_sha256,
        )

    @classmethod
    def load_yaml(cls, path: Path | str) -> "MangleRuleset":
        try:
            import yaml  # type: ignore
        except ImportError as e:
            raise MangleRuleLoadError(
                "PyYAML is required to load mangle rulesets"
            ) from e
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as e:
            raise MangleRuleLoadError(f"cannot read {p}: {e}") from e
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise MangleRuleLoadError(f"invalid YAML in {p}: {e}") from e
        if not isinstance(data, dict):
            raise MangleRuleLoadError(f"{p}: top-level must be a mapping")
        queue = int(data.get("queue", 0))
        default_verdict = str(data.get("default_verdict", "accept")).lower()
        fail_open = bool(data.get("fail_open", True))
        rule_entries = data.get("rules") or []
        if not isinstance(rule_entries, list):
            raise MangleRuleLoadError(f"{p}: 'rules' must be a list")
        ruleset = cls.from_mappings(
            rule_entries,
            queue=queue,
            default_verdict=default_verdict,
            fail_open=fail_open,
            source_sha256=digest,
        )
        log.info("mangle_ruleset_loaded", path=str(p), rules=len(ruleset), queue=queue)
        return ruleset

    def first_match(self, envelope: MatchEnvelope) -> MangleRule | None:
        for rule in self.rules:
            if rule.matches(envelope):
                return rule
        return None


def _compile_rule(data: dict[str, Any]) -> MangleRule:
    if not isinstance(data, dict):
        raise MangleRuleLoadError(f"rule must be a mapping, got {type(data).__name__}")
    rule_id = data.get("id")
    if not rule_id:
        raise MangleRuleLoadError("rule is missing 'id'")
    match_text = data.get("match")
    if not match_text:
        raise MangleRuleLoadError(f"rule '{rule_id}' is missing 'match'")
    try:
        match_expr = parse_filter(str(match_text))
    except FilterSyntaxError as e:
        raise MangleRuleLoadError(
            f"rule '{rule_id}' match expression invalid: {e}"
        ) from e
    action_data = data.get("action")
    if action_data is None:
        raise MangleRuleLoadError(f"rule '{rule_id}' is missing 'action'")
    try:
        action = action_from_mapping(action_data)
    except ValueError as e:
        raise MangleRuleLoadError(f"rule '{rule_id}': {e}") from e
    return MangleRule(
        id=str(rule_id),
        description=str(data.get("description", "")),
        match=match_expr,
        action=action,
        metadata=dict(data.get("metadata") or {}),
    )
