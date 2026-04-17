"""FileVault 2 end-to-end unlock smoke test.

As with BitLocker, libfvde refuses volumes whose Core Storage / APFS
metadata is not cryptographically consistent — we cannot synthesize a
valid volume in-process. This test import-skips when ``pyfvde`` is
missing and skips with a clear message pointing at the fixture
directory a future maintainer should populate:

    tests/fixtures/filevault/
        small-recovery.dmg           (4 MiB Core Storage image unlocked
                                      by the recovery key in recovery.txt)
        small-recovery.txt           (24-character recovery key)

Once such a fixture is committed, wire the real test here (instantiate
:class:`FileVault2Unlocker`, detect, unlock with ``Passphrase``, read
plaintext, compare checksum).
"""
from __future__ import annotations

import pytest

pyfvde = pytest.importorskip("pyfvde")


def test_filevault_unlock_real_fixture_required() -> None:
    pytest.skip(
        "Requires a real FileVault 2 fixture under tests/fixtures/filevault/ "
        "(libfvde rejects synthetic Core Storage metadata)."
    )
