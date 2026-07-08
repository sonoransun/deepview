"""Indicator of Compromise matching engine."""
from __future__ import annotations
import hashlib
import hmac
import re
import json
from dataclasses import dataclass, field
from pathlib import Path
from deepview.core.logging import get_logger

log = get_logger("scanning.indicators")


@dataclass
class Indicator:
    """A single indicator of compromise."""
    ioc_type: str  # "ip", "domain", "hash_md5", "hash_sha256", "url", "mutex", "string"
    value: str
    description: str = ""
    severity: str = "medium"
    tags: list[str] = field(default_factory=list)


@dataclass
class IndicatorMatch:
    """A match result from IoC scanning."""
    indicator: Indicator
    found_at: str = ""  # Context of where it was found
    offset: int = 0


class IndicatorEngine:
    """IoC matching engine."""

    def __init__(self):
        self._indicators: list[Indicator] = []

    def load_indicators(self, path: Path) -> None:
        """Load IoCs from a JSON file."""
        with open(path) as f:
            data = json.load(f)

        for item in data.get("indicators", []):
            self._indicators.append(Indicator(
                ioc_type=item["type"],
                value=item["value"],
                description=item.get("description", ""),
                severity=item.get("severity", "medium"),
                tags=item.get("tags", []),
            ))

        log.info("indicators_loaded", count=len(self._indicators), path=str(path))

    def add_indicator(self, indicator: Indicator) -> None:
        self._indicators.append(indicator)

    def scan_text(self, text: str) -> list[IndicatorMatch]:
        """Scan text content for IoC matches."""
        matches = []
        for ioc in self._indicators:
            if ioc.ioc_type in ("string", "url", "domain", "mutex"):
                if ioc.value in text:
                    matches.append(IndicatorMatch(indicator=ioc, found_at="text_match"))
            elif ioc.ioc_type == "ip":
                if re.search(re.escape(ioc.value), text):
                    matches.append(IndicatorMatch(indicator=ioc, found_at="text_match"))
        return matches

    def scan_bytes(self, data: bytes, offset: int = 0) -> list[IndicatorMatch]:
        """Scan a binary artifact for IoC matches.

        Hash indicators are matched by hashing the *content* of ``data`` and
        comparing to the indicator digest (constant-time) -- not by searching for
        the hex digest string inside the bytes, which both missed real matches
        and produced false positives when a digest string happened to appear.
        """
        matches = []
        digest_cache: dict[str, str] = {}
        for ioc in self._indicators:
            if ioc.ioc_type in ("hash_md5", "hash_sha256"):
                algo = "md5" if ioc.ioc_type == "hash_md5" else "sha256"
                if algo not in digest_cache:
                    if algo == "md5":
                        # md5 is used only to match known-bad threat-intel hashes,
                        # not for evidence integrity.
                        digest_cache[algo] = hashlib.md5(data, usedforsecurity=False).hexdigest()
                    else:
                        digest_cache[algo] = hashlib.sha256(data).hexdigest()
                if hmac.compare_digest(digest_cache[algo], ioc.value.strip().lower()):
                    matches.append(IndicatorMatch(
                        indicator=ioc,
                        found_at="content_hash",
                        offset=offset,
                    ))
            elif ioc.ioc_type in ("string", "url", "domain", "ip", "mutex"):
                value_bytes = ioc.value.encode("utf-8")
                idx = data.find(value_bytes)
                if idx >= 0:
                    matches.append(IndicatorMatch(
                        indicator=ioc,
                        found_at="binary_match",
                        offset=offset + idx,
                    ))
        return matches

    @property
    def indicator_count(self) -> int:
        return len(self._indicators)
