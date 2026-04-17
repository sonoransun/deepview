"""BitLocker end-to-end unlock smoke test.

A real BitLocker unlock can only be verified against a genuine
BitLocker volume — the libbde library refuses synthesized headers that
do not carry a cryptographically-consistent FVE metadata block. We
therefore import-skip if ``pybde`` is missing (the common case) and,
if it IS present, skip with a clear message pointing at the fixture
directory a future maintainer should populate:

    tests/fixtures/bitlocker/
        small-recovery.vhd           (4 MiB image unlocked by the
                                      recovery password in recovery.txt)
        small-recovery.txt           (48-digit recovery password)

Once such a fixture is committed, wire the real test here (instantiate
:class:`BitLockerUnlocker`, detect, unlock with
``Passphrase(recovery_password)``, read 512 bytes of plaintext,
compare against a known-good checksum).
"""
from __future__ import annotations

import pytest

pybde = pytest.importorskip("pybde")


def test_bitlocker_unlock_real_fixture_required() -> None:
    pytest.skip(
        "Requires a real BitLocker fixture under tests/fixtures/bitlocker/ "
        "(libbde rejects synthetic FVE metadata)."
    )
