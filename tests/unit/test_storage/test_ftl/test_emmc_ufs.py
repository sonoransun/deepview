"""Tests for ``EMMCHintTranslator`` and ``UFSTranslator`` — identity default."""
from __future__ import annotations

from deepview.storage.ftl.emmc_hints import EMMCHintTranslator
from deepview.storage.ftl.ufs import UFSTranslator
from deepview.storage.geometry import NANDGeometry


def _flat_geometry(page_size: int = 4096) -> NANDGeometry:
    return NANDGeometry(
        page_size=page_size,
        spare_size=0,
        pages_per_block=8,
        blocks=4,
    )


class TestEMMCHintTranslator:
    def test_identity_translate_lba_zero(self) -> None:
        geo = _flat_geometry()
        trans = EMMCHintTranslator(geo)
        mapping = trans.translate(0)
        assert mapping is not None
        assert mapping.lba == 0
        assert mapping.physical.block == 0
        assert mapping.physical.page == 0
        assert mapping.physical.data_offset == 0

    def test_probe_true_for_4k_no_oob(self) -> None:
        assert EMMCHintTranslator.probe(object(), _flat_geometry(4096)) is True  # type: ignore[arg-type]

    def test_probe_true_for_8k_no_oob(self) -> None:
        assert EMMCHintTranslator.probe(object(), _flat_geometry(8192)) is True  # type: ignore[arg-type]

    def test_probe_false_with_oob(self) -> None:
        geo = NANDGeometry(
            page_size=4096, spare_size=128, pages_per_block=8, blocks=4
        )
        assert EMMCHintTranslator.probe(object(), geo) is False  # type: ignore[arg-type]

    def test_logical_size_is_full_surface(self) -> None:
        geo = _flat_geometry()
        trans = EMMCHintTranslator(geo)
        assert trans.logical_size() == 4 * 8 * 4096

    def test_translate_beyond_end_returns_none(self) -> None:
        geo = _flat_geometry()
        trans = EMMCHintTranslator(geo)
        assert trans.translate(9999) is None


class TestUFSTranslator:
    def test_identity_translate_lba_zero(self) -> None:
        geo = _flat_geometry()
        trans = UFSTranslator(geo)
        mapping = trans.translate(0)
        assert mapping is not None
        assert mapping.lba == 0
        assert mapping.physical.block == 0
        assert mapping.physical.page == 0

    def test_probe_true_for_4k_no_oob(self) -> None:
        assert UFSTranslator.probe(object(), _flat_geometry(4096)) is True  # type: ignore[arg-type]

    def test_probe_false_with_oob(self) -> None:
        geo = NANDGeometry(
            page_size=4096, spare_size=128, pages_per_block=8, blocks=4
        )
        assert UFSTranslator.probe(object(), geo) is False  # type: ignore[arg-type]

    def test_logical_size_is_full_surface(self) -> None:
        geo = _flat_geometry()
        trans = UFSTranslator(geo)
        assert trans.logical_size() == 4 * 8 * 4096
