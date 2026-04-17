"""Tests for ``BadBlockRemapTranslator``."""
from __future__ import annotations

from deepview.storage.ftl.badblock import BadBlockRemapTranslator
from deepview.storage.geometry import NANDGeometry

PAGE_SIZE = 512
SPARE_SIZE = 16
PAGES_PER_BLOCK = 4
BLOCKS = 8


def _geometry() -> NANDGeometry:
    return NANDGeometry(
        page_size=PAGE_SIZE,
        spare_size=SPARE_SIZE,
        pages_per_block=PAGES_PER_BLOCK,
        blocks=BLOCKS,
    )


class TestBadBlockRemap:
    def test_translate_lba_0_is_block_0(self) -> None:
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks={2, 5})
        mapping = trans.translate(0)
        assert mapping is not None
        assert mapping.physical.block == 0
        assert mapping.physical.page == 0

    def test_translate_skips_first_bad_block(self) -> None:
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks={2, 5})
        # LBAs 0..3 -> block 0, 4..7 -> block 1, 8..11 -> block 3 (skipping 2)
        mapping = trans.translate(8)
        assert mapping is not None
        assert mapping.physical.block == 3
        assert mapping.physical.page == 0

    def test_translate_skips_second_bad_block(self) -> None:
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks={2, 5})
        # After skipping block 2 and 5, LBA 16 -> block 6.
        mapping = trans.translate(16)
        assert mapping is not None
        assert mapping.physical.block == 6
        assert mapping.physical.page == 0

    def test_logical_size_counts_good_blocks(self) -> None:
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks={2, 5})
        good_blocks = BLOCKS - 2
        expected = good_blocks * PAGES_PER_BLOCK * PAGE_SIZE
        assert trans.logical_size() == expected

    def test_probe_is_always_true(self) -> None:
        from deepview.storage.ftl.badblock import BadBlockRemapTranslator as BBR

        class _Dummy:
            pass

        assert BBR.probe(_Dummy(), _geometry()) is True  # type: ignore[arg-type]

    def test_no_bad_blocks_is_identity(self) -> None:
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks=set())
        for lba in range(BLOCKS * PAGES_PER_BLOCK):
            mapping = trans.translate(lba)
            assert mapping is not None
            assert mapping.physical.block == lba // PAGES_PER_BLOCK
            assert mapping.physical.page == lba % PAGES_PER_BLOCK
