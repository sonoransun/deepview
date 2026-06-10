"""Tests for the dynamic ATT&CK mapper."""
from __future__ import annotations

from deepview.core.types import EventSeverity
from deepview.detection.anti_forensics import Detection
from deepview.reporting.export import ATTCKMapper


def _det(name: str, *, technique: str = "", severity=EventSeverity.WARNING) -> Detection:
    return Detection(
        name=name,
        severity=severity,
        description=name,
        offset=0,
        pid=1,
        process_name="p",
        technique=technique,
        evidence={},
    )


class TestDynamicMapping:
    def test_static_name_map_still_works(self):
        m = ATTCKMapper()
        mapping = m.map_detection(_det("DKOM_HIDDEN_PROCESS"))
        assert mapping is not None
        assert mapping["id"] == "T1014"

    def test_falls_back_to_detection_technique(self):
        m = ATTCKMapper()
        mapping = m.map_detection(_det("custom_finding", technique="T1486"))
        assert mapping is not None
        assert mapping["id"] == "T1486"
        assert mapping["name"] == "Data Encrypted for Impact"

    def test_coverage_dedupes_and_rolls_up_severity(self):
        m = ATTCKMapper()
        cov = m.coverage(
            [
                _det("custom", technique="T1055", severity=EventSeverity.WARNING),
                _det("other", technique="T1055", severity=EventSeverity.CRITICAL),
            ]
        )
        assert len(cov) == 1
        assert cov[0]["technique_id"] == "T1055"
        assert cov[0]["count"] == 2
        assert cov[0]["severity"] == "critical"

    def test_navigator_layer_scores_by_count(self):
        m = ATTCKMapper()
        layer = m.generate_navigator_layer(
            [_det("a", technique="T1059"), _det("b", technique="T1059")]
        )
        techs = layer["techniques"]
        assert len(techs) == 1
        assert techs[0]["techniqueID"] == "T1059"
        assert techs[0]["score"] == 2
