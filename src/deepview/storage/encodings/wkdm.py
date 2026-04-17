"""macOS WKdm (Wilson-Kaplan direct-mapped) page decompressor.

WKdm is the compressor Apple ships in XNU for compressed memory pool pages.
It operates on a single 4096-byte page, which it views as 1024 32-bit words,
and emits a tagged stream of four word-classes against a 16-entry direct-
mapped dictionary indexed by the low 8 bits of each input word:

* **ZERO**   (tag 00): the full 32-bit word is zero.
* **EXACT**  (tag 01): the word equals the current dictionary entry for its
  hash slot. Emit just the 4-bit dictionary index.
* **PARTIAL**(tag 10): the high 22 bits match the dictionary entry but the
  low 10 bits differ. Emit the index + 10-bit low-bits patch; update the
  dictionary entry.
* **MISS**   (tag 11): no match. Emit the full 32-bit word and install it
  into the dictionary.

The stream layout is (all little-endian 32-bit words):

    [ header (4 words) ][ tags (2 bits per word) ][ full words ][ dict refs /
    partial references ][ 10-bit patches packed ]

where the header gives the four section end-offsets in words. The exact bit
packing of the partial/index streams is what makes this non-trivial to port
from the XNU C source (~600 LOC).

This pure-Python module documents the algorithm faithfully but only ships a
stub: the full decoder is out of scope for the storage-encoding slice.
Callers should treat a :class:`NotImplementedError` from this function as a
signal to either install a C-extension port (e.g. the FBT vendored in the
``volatility3-macos`` fork) or to skip the page with a zero-fill placeholder.
"""
from __future__ import annotations

from typing import Final

__all__ = ["decompress_wkdm"]


WKDM_PAGE_SIZE: Final[int] = 4096
_WORDS_PER_PAGE: Final[int] = WKDM_PAGE_SIZE // 4
_DICT_SIZE: Final[int] = 16


def decompress_wkdm(buf: bytes, expected_size: int = WKDM_PAGE_SIZE) -> bytes:
    """Decompress a single WKdm-compressed page.

    Parameters
    ----------
    buf:
        Compressed byte stream for exactly one 4 KiB page.
    expected_size:
        The uncompressed page size. WKdm is defined against 4096-byte pages;
        any other value is rejected.

    Returns
    -------
    bytes
        The decompressed 4 KiB page.

    Raises
    ------
    NotImplementedError
        Always, currently — the full bit-packing decoder is not implemented.
        The stub is in place so that callers can structure their code around
        the intended API; see the module docstring for the algorithm.
    """
    if expected_size != WKDM_PAGE_SIZE:
        raise ValueError(
            f"decompress_wkdm only supports {WKDM_PAGE_SIZE}-byte pages "
            f"(got expected_size={expected_size})"
        )
    if len(buf) < 16:
        raise ValueError("WKdm: compressed stream shorter than 16-byte header")

    # Parse the 4-word header so downstream code that upgrades this module
    # has a starting point. The offsets below are documented in XNU's
    # ``osfmk/vm/WKdmCompress.c`` / ``WKdmDecompress.c``.
    # Each header word is a count of 32-bit words consumed by the
    # corresponding section.
    _tags_end_word = int.from_bytes(buf[0:4], "little")      # noqa: F841
    _full_words_end = int.from_bytes(buf[4:8], "little")     # noqa: F841
    _dict_refs_end = int.from_bytes(buf[8:12], "little")     # noqa: F841
    _low_bits_end = int.from_bytes(buf[12:16], "little")     # noqa: F841

    raise NotImplementedError(
        "WKdm decoder stub: pure-Python bit-stream decoder for the "
        "tag/dict/low-bits sections is not implemented. A full port of "
        f"XNU's WKdmDecompress.c (~600 LOC) is required. Pages are "
        f"{_WORDS_PER_PAGE} words against a {_DICT_SIZE}-entry direct-"
        "mapped dictionary; see module docstring for stream layout."
    )
