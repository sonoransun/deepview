"""Tests for the VeraCrypt / TrueCrypt KDF iteration tables."""
from __future__ import annotations

import pytest

from deepview.storage.containers._kdf_table import iter_tc_kdfs, iter_vc_kdfs


def test_vc_kdfs_default_non_system() -> None:
    rows = list(iter_vc_kdfs(pim=0, system_enc=False))
    # Ordered: sha512, sha256, whirlpool, streebog, ripemd160.
    names = [r[0] for r in rows]
    assert names == ["sha512", "sha256", "whirlpool", "streebog", "ripemd160"]
    assert rows[0] == ("sha512", 500_000, 64)
    assert rows[1] == ("sha256", 500_000, 64)
    # RIPEMD-160 has its own base iteration count.
    assert rows[4] == ("ripemd160", 655_331, 64)


def test_vc_kdfs_with_pim_485_adds_pim_times_1000() -> None:
    # Per the brief: pim=485, system_enc=False -> 500000 + 485*1000 = 985000.
    rows = list(iter_vc_kdfs(pim=485, system_enc=False))
    sha512 = next(r for r in rows if r[0] == "sha512")
    assert sha512 == ("sha512", 500_000 + 485 * 1000, 64)
    assert sha512[1] == 985_000


def test_vc_kdfs_system_enc_uses_lower_base() -> None:
    rows = list(iter_vc_kdfs(pim=0, system_enc=True))
    sha512 = next(r for r in rows if r[0] == "sha512")
    assert sha512[1] == 200_000


def test_vc_kdfs_pim_system_enc_scales_by_2048() -> None:
    rows = list(iter_vc_kdfs(pim=10, system_enc=True))
    sha512 = next(r for r in rows if r[0] == "sha512")
    # 200000 + 10*2048 = 220480.
    assert sha512[1] == 200_000 + 10 * 2048


def test_vc_kdfs_negative_pim_rejected() -> None:
    with pytest.raises(ValueError):
        list(iter_vc_kdfs(pim=-1))


def test_tc_kdfs_default_iteration_counts() -> None:
    rows = list(iter_tc_kdfs(system_enc=False))
    by_name = {r[0]: r for r in rows}
    assert by_name["ripemd160"] == ("ripemd160", 2000, 64)
    assert by_name["sha512"] == ("sha512", 1000, 64)
    assert by_name["whirlpool"] == ("whirlpool", 1000, 64)


def test_tc_kdfs_system_enc_halves_ripemd160() -> None:
    rows = list(iter_tc_kdfs(system_enc=True))
    by_name = {r[0]: r for r in rows}
    assert by_name["ripemd160"] == ("ripemd160", 1000, 64)
