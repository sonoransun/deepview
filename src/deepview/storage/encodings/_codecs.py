"""Shared helper for optional compression-codec availability errors.

The zram / zswap layers decompress pages with optional accelerators (`lz4`,
`zstandard`, `python-lzo`). When the page's algorithm needs a codec that is not
installed, surface a clear, actionable message — mirroring the `argon2id`
offload helper — instead of a bare ``ImportError`` leaking out mid-read.
"""
from __future__ import annotations

_CODEC_PKG = {
    "lz4": "lz4",
    "zstd": "zstandard",
    "lzo": "python-lzo",
    "deflate": "zlib (stdlib)",
}


def codec_missing(algo: str) -> ImportError:
    """Return a clear :class:`ImportError` for a missing optional codec *algo*."""
    pkg = _CODEC_PKG.get(algo, algo)
    return ImportError(
        f"{algo!r} compression codec is not available — install it with "
        f"pip install 'deepview[compression]' (provides {pkg})"
    )
