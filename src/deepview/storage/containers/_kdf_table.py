"""VeraCrypt / TrueCrypt KDF iteration tables.

Each entry is ``(kdf_name, iterations, dklen)`` where *kdf_name* is one of
the five PBKDF2 PRFs VeraCrypt supports and *dklen* is fixed at 64 bytes
for every PRF (the derived buffer is ``header_key || tweak_key``, both of
which are 32 bytes). TrueCrypt uses a strictly smaller set and locks
iterations to 2000 for every PRF.

The iteration formulas mirror VeraCrypt's source
(``Common/Pkcs5.c::get_pkcs5_iteration_count``):

* SHA-512 / Whirlpool / Streebog:  ``500_000 + pim * 1000`` (non-boot)
  or                                ``15_000 + pim * 1000``  (system).
* SHA-256:                          ``500_000 + pim * 1000`` (non-boot)
  or                                ``200_000 + pim * 2048`` (system).
* RIPEMD-160 (legacy):              ``655_331 + pim * 15_331`` (non-boot)
  or                                ``327_661 + pim * 15_331`` (system).

For TrueCrypt: SHA-512 / Whirlpool = 1000 iterations (non-boot) or 1000
(boot); RIPEMD-160 = 2000 iterations (non-boot) or 1000 (boot).
"""
from __future__ import annotations

from collections.abc import Iterator

# Byte length of the derived buffer. Enough room for two 32-byte keys
# (header + tweak) for AES / Twofish / Serpent in XTS mode.
_DKLEN = 64


def iter_vc_kdfs(
    pim: int = 0, *, system_enc: bool = False
) -> Iterator[tuple[str, int, int]]:
    """Yield every (kdf_name, iterations, dklen) candidate for VeraCrypt.

    Parameters
    ----------
    pim:
        Personal Iterations Multiplier (``0`` = default). Legal values
        are ``0..2147468``.
    system_enc:
        ``True`` for the system-encryption boot path (iterations are
        lower to keep pre-boot unlock practical).

    The order matters — SHA-512 is overwhelmingly the default since
    VeraCrypt 1.12, so we try it first.
    """
    if pim < 0:
        raise ValueError("pim must be non-negative")

    if system_enc:
        sha512 = 200_000 + pim * 2048 if pim else 200_000
        sha256 = 200_000 + pim * 2048 if pim else 200_000
        whirlpool = 200_000 + pim * 2048 if pim else 200_000
        streebog = 200_000 + pim * 2048 if pim else 200_000
        ripemd160 = 327_661 + pim * 15_331 if pim else 327_661
    else:
        base = 500_000
        sha512 = base + pim * 1000 if pim else base
        sha256 = base + pim * 1000 if pim else base
        whirlpool = base + pim * 1000 if pim else base
        streebog = base + pim * 1000 if pim else base
        ripemd160 = 655_331 + pim * 15_331 if pim else 655_331

    yield ("sha512", sha512, _DKLEN)
    yield ("sha256", sha256, _DKLEN)
    yield ("whirlpool", whirlpool, _DKLEN)
    yield ("streebog", streebog, _DKLEN)
    yield ("ripemd160", ripemd160, _DKLEN)


def iter_tc_kdfs(*, system_enc: bool = False) -> Iterator[tuple[str, int, int]]:
    """Yield every (kdf_name, iterations, dklen) candidate for TrueCrypt.

    TrueCrypt has a much smaller PRF menu and does not honour PIM.
    """
    if system_enc:
        yield ("ripemd160", 1000, _DKLEN)
        yield ("sha512", 1000, _DKLEN)
        yield ("whirlpool", 1000, _DKLEN)
    else:
        yield ("ripemd160", 2000, _DKLEN)
        yield ("sha512", 1000, _DKLEN)
        yield ("whirlpool", 1000, _DKLEN)


__all__ = ["iter_vc_kdfs", "iter_tc_kdfs"]
