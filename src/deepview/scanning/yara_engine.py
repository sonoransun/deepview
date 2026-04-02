"""YARA rule-based scanning engine."""
from __future__ import annotations
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from deepview.core.logging import get_logger
from deepview.core.types import ScanResult
from deepview.core.exceptions import ScanError, RuleCompileError
from deepview.interfaces.scanner import PatternScanner

if TYPE_CHECKING:
    from deepview.interfaces.layer import DataLayer

log = get_logger("scanning.yara")


class YaraScanner(PatternScanner):
    """YARA rule-based pattern scanner for memory and files."""

    def __init__(self):
        self._rules = None
        self._rule_count = 0
        self._available = False
        try:
            import yara
            self._yara = yara
            self._available = True
        except ImportError:
            log.debug("yara_python_not_installed")

    @property
    def is_available(self) -> bool:
        return self._available

    def load_rules(self, path: Path) -> None:
        """Load YARA rules from a file or directory."""
        if not self._available:
            raise ScanError("yara-python is not installed")

        try:
            if path.is_dir():
                # Load all .yar/.yara files from directory
                rule_files = {}
                for ext in ("*.yar", "*.yara"):
                    for f in sorted(path.glob(ext)):
                        rule_files[f.stem] = str(f)
                if not rule_files:
                    raise ScanError(f"No YARA rules found in {path}")
                self._rules = self._yara.compile(filepaths=rule_files)
                self._rule_count = len(rule_files)
            else:
                self._rules = self._yara.compile(filepath=str(path))
                self._rule_count = 1  # Approximate

            log.info("rules_loaded", path=str(path), count=self._rule_count)
        except self._yara.SyntaxError as e:
            raise RuleCompileError(f"YARA rule syntax error: {e}") from e
        except Exception as e:
            raise ScanError(f"Failed to load YARA rules: {e}") from e

    def load_rules_from_string(self, source: str) -> None:
        """Compile YARA rules from a string."""
        if not self._available:
            raise ScanError("yara-python is not installed")
        try:
            self._rules = self._yara.compile(source=source)
            self._rule_count = 1
        except self._yara.SyntaxError as e:
            raise RuleCompileError(f"YARA rule syntax error: {e}") from e

    @property
    def rule_count(self) -> int:
        return self._rule_count

    def scan(self, data: bytes, offset: int = 0) -> Iterator[ScanResult]:
        """Scan a bytes buffer against loaded YARA rules."""
        if self._rules is None:
            raise ScanError("No YARA rules loaded")

        matches = self._rules.match(data=data)
        for match in matches:
            for string_match in match.strings:
                for instance in string_match.instances:
                    yield ScanResult(
                        offset=offset + instance.offset,
                        length=instance.matched_length,
                        rule_name=match.rule,
                        data=instance.matched_data[:256],
                        metadata={
                            "tags": list(match.tags),
                            "meta": dict(match.meta),
                            "string_id": string_match.identifier,
                            "namespace": match.namespace,
                        },
                    )

    def scan_file(self, path: Path) -> Iterator[ScanResult]:
        """Scan a file against loaded YARA rules."""
        if self._rules is None:
            raise ScanError("No YARA rules loaded")

        matches = self._rules.match(filepath=str(path))
        for match in matches:
            for string_match in match.strings:
                for instance in string_match.instances:
                    yield ScanResult(
                        offset=instance.offset,
                        length=instance.matched_length,
                        rule_name=match.rule,
                        data=instance.matched_data[:256],
                        metadata={
                            "tags": list(match.tags),
                            "meta": dict(match.meta),
                            "string_id": string_match.identifier,
                        },
                    )

    def scan_layer(self, layer: DataLayer, progress_callback: Callable | None = None) -> Iterator[ScanResult]:
        """Scan a DataLayer (memory dump) against loaded YARA rules."""
        yield from layer.scan(self, progress_callback)
