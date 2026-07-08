"""Boot-sector (bootkit) integrity detection -- MITRE T1542.003.

Software-only, offline analysis over an acquired disk image's first sectors:
verifies the MBR/VBR boot signature and bootstrap-code region, and optionally
diffs the bootstrap code against a known-good template. This is the tractable,
hardware-free slice of the advertised firmware/rootkit detection surface.

Named-implant coverage (TDL4/FinSpy) is intentionally template/hash-based rather
than heuristic pattern-matching: supply a known-good MBR to flag any deviation.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from deepview.core.logging import get_logger
from deepview.core.types import EventSeverity
from deepview.detection.anti_forensics import Detection

log = get_logger("detection.rootkit")

SECTOR_SIZE = 512
BOOT_SIGNATURE = b"\x55\xAA"  # bytes 0x1FE-0x1FF of a valid boot sector
BOOTSTRAP_END = 0x1BE  # partition table begins here in an MBR


class BootkitDetector:
    """Detect boot-sector tampering over acquired disk-image sectors."""

    def analyze_mbr(self, sector: bytes) -> list[Detection]:
        """Structural integrity checks on a 512-byte MBR/VBR sector."""
        detections: list[Detection] = []

        if len(sector) < SECTOR_SIZE:
            detections.append(
                Detection(
                    name="BOOTKIT",
                    severity=EventSeverity.WARNING,
                    description=f"Boot sector is {len(sector)} bytes (< {SECTOR_SIZE}); truncated or invalid",
                    technique="T1542.003",
                )
            )
            return detections

        signature = sector[0x1FE:0x200]
        if signature != BOOT_SIGNATURE:
            detections.append(
                Detection(
                    name="BOOTKIT",
                    severity=EventSeverity.CRITICAL,
                    description=(
                        f"Invalid MBR boot signature {signature.hex()} (expected 55aa) -- "
                        "corrupted or overwritten boot sector"
                    ),
                    technique="T1542.003",
                    evidence={"signature": signature.hex()},
                )
            )

        bootstrap = sector[0:BOOTSTRAP_END]
        if bootstrap == b"\x00" * BOOTSTRAP_END:
            detections.append(
                Detection(
                    name="BOOTKIT",
                    severity=EventSeverity.WARNING,
                    description="MBR bootstrap code region is entirely zero (no boot code present)",
                    technique="T1542.003",
                )
            )

        self._log(detections)
        return detections

    def compare_to_known_good(self, sector: bytes, known_good: bytes) -> list[Detection]:
        """Flag bootstrap-code deviation from a known-good MBR template.

        Only the bootstrap-code region (0x000-0x1BD) is compared; the partition
        table (0x1BE-0x1FD) legitimately varies per disk and is excluded.
        """
        cur = sector[0:BOOTSTRAP_END]
        good = known_good[0:BOOTSTRAP_END]
        if cur != good:
            return [
                Detection(
                    name="BOOTKIT",
                    severity=EventSeverity.CRITICAL,
                    description="MBR bootstrap code differs from the known-good template",
                    technique="T1542.003",
                    evidence={
                        "current_sha256": hashlib.sha256(cur).hexdigest(),
                        "known_good_sha256": hashlib.sha256(good).hexdigest(),
                    },
                )
            ]
        return []

    def analyze_image(self, path: Path, known_good: Path | None = None) -> list[Detection]:
        """Read the first sector of a disk image and analyze it."""
        with open(path, "rb") as f:
            sector = f.read(SECTOR_SIZE)
        detections = self.analyze_mbr(sector)
        if known_good is not None:
            detections.extend(self.compare_to_known_good(sector, Path(known_good).read_bytes()))
        return detections

    @staticmethod
    def _log(detections: list[Detection]) -> None:
        for d in detections:
            log.warning("bootkit_finding", name=d.name, technique=d.technique)
