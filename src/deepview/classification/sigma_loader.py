"""Best-effort Sigma-rule loader.

Converts the common subset of `Sigma <https://sigmahq.io>`_ detection rules
into Deep View :class:`ClassificationRule` objects so operators can reuse the
large public Sigma corpus. This is a pragmatic in-tree translator (PyYAML
only, no pySigma dependency): it handles ``selection`` maps with the usual
field modifiers and ``condition`` strings combining selections with a single
``and``/``or``. Constructs it does not understand (``not``, ``1 of``,
``all of``, keyword lists, mixed and/or) raise :class:`SigmaUnsupported`, and
:meth:`Ruleset.load_sigma_dir` skips those with a warning rather than failing
the whole load — never silently mistranslating.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from deepview.classification.ruleset import ClassificationRule, RuleLoadError, Ruleset
from deepview.core.logging import get_logger
from deepview.tracing.filters import FilterExpr, FilterRule

log = get_logger("classification.sigma")


class SigmaUnsupported(RuleLoadError):
    """A Sigma rule uses a construct this lightweight loader cannot map."""


# Sigma field name -> Deep View event dot-path. Unmapped fields fall back to
# ``args.<lowercased-name>`` which matches how backends stash raw arguments.
_FIELD_MAP = {
    "Image": "process.exe_path",
    "OriginalFileName": "process.comm",
    "CommandLine": "args.cmdline",
    "TargetFilename": "args.filename",
    "Filename": "args.filename",
    "DestinationIp": "args.daddr",
    "DestinationPort": "args.dport",
    "DestinationHostname": "args.dhost",
    "Syscall": "syscall_name",
    "syscall": "syscall_name",
}

_LEVEL_MAP = {
    "critical": "critical",
    "high": "critical",
    "medium": "warning",
    "low": "info",
    "informational": "info",
}


def _field_rule(key: str, value: Any) -> FilterRule:
    name, _, modifier = key.partition("|")
    path = _FIELD_MAP.get(name, f"args.{name.lower()}")
    if modifier in ("", "all"):
        return FilterRule(path, "eq", value)
    if modifier == "endswith":
        return FilterRule(path, "glob", f"*{value}")
    if modifier == "startswith":
        return FilterRule(path, "glob", f"{value}*")
    if modifier == "contains":
        return FilterRule(path, "contains", str(value))
    if modifier in ("re", "regex"):
        return FilterRule(path, "regex", str(value))
    raise SigmaUnsupported(f"unsupported field modifier '|{modifier}'")


def _selection_expr(selection: Any) -> FilterExpr:
    if not isinstance(selection, dict):
        raise SigmaUnsupported("only map-style selections are supported")
    node = FilterExpr("and")
    for key, value in selection.items():
        if isinstance(value, list):
            or_node = FilterExpr("or")
            for v in value:
                or_node.add(_field_rule(key, v))
            node.add(or_node)
        else:
            node.add(_field_rule(key, value))
    return node


def _condition_expr(condition: str, selections: dict[str, FilterExpr]) -> FilterExpr:
    tokens = str(condition).split()
    unsupported = {"not", "1", "all", "of", "(", ")", "|", "them", "*"}
    if any(t in unsupported for t in tokens):
        raise SigmaUnsupported(f"unsupported condition '{condition}'")
    has_and = "and" in tokens
    has_or = "or" in tokens
    if has_and and has_or:
        raise SigmaUnsupported("mixed and/or conditions are not supported")
    op = "or" if has_or else "and"
    names = [t for t in tokens if t not in ("and", "or")]
    if not names:
        raise SigmaUnsupported(f"empty condition '{condition}'")
    node = FilterExpr(op)
    for name in names:
        if name not in selections:
            raise SigmaUnsupported(f"condition references unknown selection '{name}'")
        node.add(selections[name])
    return node


def _attack_ids(tags: Any) -> list[str]:
    ids: list[str] = []
    for tag in tags or []:
        text = str(tag)
        if text.lower().startswith("attack.t"):
            ids.append(text.split(".", 1)[1].upper())
    return ids


def sigma_to_rule(data: dict[str, Any]) -> ClassificationRule:
    """Convert one parsed Sigma document into a :class:`ClassificationRule`."""
    if not isinstance(data, dict):
        raise SigmaUnsupported("Sigma document must be a mapping")
    detection = data.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaUnsupported("Sigma rule missing 'detection.condition'")
    selections = {
        name: _selection_expr(body)
        for name, body in detection.items()
        if name != "condition"
    }
    expr = _condition_expr(detection["condition"], selections)
    rule_id = str(data.get("id") or data.get("title") or "sigma_rule")
    severity = _LEVEL_MAP.get(str(data.get("level", "medium")).lower(), "warning")
    return ClassificationRule(
        id=rule_id,
        title=str(data.get("title", rule_id)),
        severity=severity,
        category=str((data.get("logsource") or {}).get("category", "sigma")),
        attack_ids=_attack_ids(data.get("tags")),
        match=expr,
        labels={"source": "sigma"},
        metadata={"sigma_id": rule_id},
    )


def load_sigma_file(path: Path | str) -> ClassificationRule:
    """Load and convert a single Sigma YAML file."""
    import yaml

    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise RuleLoadError(f"cannot read Sigma file {p}: {e}") from e
    return sigma_to_rule(data)


def load_sigma_dir(directory: Path | str) -> Ruleset:
    """Load every ``*.yml``/``*.yaml`` Sigma rule under *directory*.

    Files using unsupported constructs are skipped with a warning so a
    single complex rule does not abort the whole load.
    """
    base = Path(directory)
    ruleset = Ruleset()
    for path in sorted([*base.glob("*.yml"), *base.glob("*.yaml")]):
        try:
            ruleset.add(load_sigma_file(path))
        except RuleLoadError as e:
            log.warning("sigma_rule_skipped", path=str(path), reason=str(e))
    return ruleset
