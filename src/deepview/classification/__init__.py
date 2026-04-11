"""Live event classification engine.

Takes a :class:`~deepview.tracing.events.MonitorEvent` stream from a
:class:`~deepview.tracing.stream.TraceEventBus`, matches each event
against a :class:`Ruleset`, and attaches classification results to
events plus publishes :class:`~deepview.core.events.EventClassifiedEvent`
records into the core :class:`~deepview.core.events.EventBus`.

Rules are expressed as small YAML documents that reference the shared
:class:`~deepview.tracing.filters.FilterExpr` syntax, so the same
textual filter DSL used by the CLI drives the rule match predicate.
"""
from __future__ import annotations

from deepview.classification.classifier import (
    ClassificationResult,
    EventClassifier,
)
from deepview.classification.ruleset import (
    ClassificationRule,
    RuleLoadError,
    Ruleset,
)

__all__ = [
    "ClassificationResult",
    "EventClassifier",
    "ClassificationRule",
    "RuleLoadError",
    "Ruleset",
]
