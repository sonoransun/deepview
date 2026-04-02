from __future__ import annotations

from abc import ABC, abstractmethod
from typing import IO

from deepview.interfaces.plugin import PluginResult


class ResultRenderer(ABC):
    """Abstract renderer that serialises a :class:`PluginResult` into a
    human- or machine-readable format."""

    @abstractmethod
    def render(
        self,
        result: PluginResult,
        output: IO | None = None,
    ) -> str:
        """Render *result*.

        If *output* is provided the rendered text is also written there.
        Returns the rendered string in all cases.
        """

    @abstractmethod
    def format_name(self) -> str:
        """Short identifier for this output format (e.g. ``"json"``,
        ``"table"``, ``"csv"``)."""
