"""Unified timeline + causality builder.

The timeline merges events from every Deep View subsystem into a single
stream of :class:`TimelineEvent` records, reconciles clocks, detects
timestomping, and walks the correlation graph to produce causal chains.

Legacy ``TimelineEntry`` / ``TimelineBuilder`` names remain as thin
compatibility shims so any third-party code that imported them off the
flat ``reporting/timeline.py`` still works.
"""
from __future__ import annotations

from deepview.reporting.timeline.causality import CausalChain, CausalityBuilder
from deepview.reporting.timeline.event import (
    Severity,
    SourceType,
    TimelineEvent,
    TimelineEntry,  # compat alias
)
from deepview.reporting.timeline.merger import TimelineBuilder, TimelineMerger
from deepview.reporting.timeline.super_timeline import write_plaso_csv
from deepview.reporting.timeline.timestomping import TimestompingDetector

__all__ = [
    "CausalChain",
    "CausalityBuilder",
    "Severity",
    "SourceType",
    "TimelineBuilder",
    "TimelineEntry",
    "TimelineEvent",
    "TimelineMerger",
    "TimestompingDetector",
    "write_plaso_csv",
]
