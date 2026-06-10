"""Reusable analysis models that turn raw events into visualizable shapes.

This package is the backbone the dashboard panels and HTML reports draw
from: an :class:`~deepview.analysis.aggregate.EventAggregator` (rolling
counts / top-N / time buckets) and a
:class:`~deepview.analysis.process_tree.ProcessTree` (process ancestry from
``ppid``). Both are pure, dependency-light, and deterministic so they can be
unit-tested and reused from either the live TUI or an offline report.
"""
from __future__ import annotations

from deepview.analysis.aggregate import EventAggregator
from deepview.analysis.process_tree import ProcessNode, ProcessTree

__all__ = ["EventAggregator", "ProcessTree", "ProcessNode"]
