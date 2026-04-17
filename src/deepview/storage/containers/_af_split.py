"""Anti-Forensic (AF) split / merge helper for LUKS keyslot material.

LUKS spreads a keyslot's master-key material across ``stripe_count``
copies (stripes) XOR-diffused with a hash so that any single stripe
leaking does not reveal the key. On unlock, the stripes are XORed
together with an iterated hash-diffusion step and the result is the raw
master-key candidate.

The algorithm is specified in the LUKS1 on-disk format (section 5,
"AF-split") and reused unchanged by LUKS2 for the PBKDF2-derived
keyslot material. The diffusion hash is SHA-1 by default for LUKS1 and
configurable (SHA-1 / SHA-256 / SHA-512) for LUKS2.

This helper is pure-Python + stdlib-only; no optional dependency pulls
it into a code path where it could silently vanish.
"""
from __future__ import annotations

import hashlib


_HASH_DIGEST_SIZE = {
    "sha1": 20,
    "sha256": 32,
    "sha512": 64,
}


def _diffuse(block: bytes, hash_name: str) -> bytes:
    """Iterated-hash diffusion matching the LUKS on-disk specification.

    The input *block* is split into digest-sized chunks. Each chunk is
    prefixed with its 4-byte big-endian chunk index and hashed; the
    resulting digests are concatenated, truncated back to ``len(block)``,
    and returned.
    """
    digest_size = _HASH_DIGEST_SIZE.get(hash_name.lower())
    if digest_size is None:
        # Fall back to asking hashlib; raises ``ValueError`` cleanly on
        # unknown digest names.
        digest_size = hashlib.new(hash_name).digest_size
    blocks = (len(block) + digest_size - 1) // digest_size
    out = bytearray()
    for i in range(blocks):
        start = i * digest_size
        end = min(start + digest_size, len(block))
        h = hashlib.new(hash_name)
        h.update(i.to_bytes(4, "big"))
        h.update(bytes(block[start:end]))
        out.extend(h.digest())
    return bytes(out[: len(block)])


def af_merge(
    stripes: bytes,
    keylen: int,
    stripe_count: int,
    hash_name: str = "sha1",
) -> bytes:
    """Merge the AF-split *stripes* back into a ``keylen``-byte key.

    Parameters
    ----------
    stripes:
        The ``keylen * stripe_count``-byte keyslot material read from
        disk (after the user's passphrase has been used to decrypt it —
        AF-merge itself is symmetric key-agnostic).
    keylen:
        Length of one stripe (and of the resulting master key).
    stripe_count:
        Number of stripes (``LUKS_STRIPES`` = 4000 for LUKS1; carried
        per-keyslot in LUKS2 metadata).
    hash_name:
        Diffusion hash. ``"sha1"`` is the LUKS1 default; LUKS2 allows
        any digest supported by the kernel's crypto API — ``"sha256"``
        and ``"sha512"`` are the common configured values.

    Returns
    -------
    The recovered master-key candidate (``keylen`` bytes).
    """
    if keylen <= 0:
        raise ValueError("keylen must be positive")
    if stripe_count <= 0:
        raise ValueError("stripe_count must be positive")
    expected = keylen * stripe_count
    if len(stripes) != expected:
        raise ValueError(
            f"stripes length {len(stripes)} != keylen*stripe_count {expected}"
        )

    # Iterate stripes 0..n-2 XOR-ing + diffusing; the final stripe is
    # the one that XORs out to the original key.
    accum = bytearray(keylen)
    for i in range(stripe_count - 1):
        stripe = stripes[i * keylen : (i + 1) * keylen]
        for j in range(keylen):
            accum[j] ^= stripe[j]
        diffused = _diffuse(bytes(accum), hash_name)
        accum = bytearray(diffused)
    last = stripes[(stripe_count - 1) * keylen : stripe_count * keylen]
    for j in range(keylen):
        accum[j] ^= last[j]
    return bytes(accum)


def af_split(
    key: bytes,
    stripe_count: int,
    random_bytes: bytes,
    hash_name: str = "sha1",
) -> bytes:
    """Inverse of :func:`af_merge`. Used only by tests.

    The caller supplies ``(stripe_count - 1) * len(key)`` pre-generated
    random bytes so tests can produce deterministic fixtures. The
    resulting buffer round-trips through :func:`af_merge` back to *key*.
    """
    keylen = len(key)
    if keylen == 0:
        raise ValueError("key must not be empty")
    if stripe_count <= 0:
        raise ValueError("stripe_count must be positive")
    needed = keylen * (stripe_count - 1)
    if len(random_bytes) != needed:
        raise ValueError(
            f"random_bytes length {len(random_bytes)} != {needed}"
        )

    accum = bytearray(keylen)
    out = bytearray()
    for i in range(stripe_count - 1):
        stripe = random_bytes[i * keylen : (i + 1) * keylen]
        out.extend(stripe)
        for j in range(keylen):
            accum[j] ^= stripe[j]
        diffused = _diffuse(bytes(accum), hash_name)
        accum = bytearray(diffused)
    last = bytearray(keylen)
    for j in range(keylen):
        last[j] = accum[j] ^ key[j]
    out.extend(last)
    return bytes(out)


__all__ = ["af_merge", "af_split"]
