"""BCH codec with an optional ``galois`` accelerator and a minimal fallback.

When the ``galois`` PyPI package is importable at construction time we
use it for arbitrary-parameter BCH over GF(2^m). Otherwise we fall back
to a hard-coded pure-Python BCH(n=7, k=4, t=1) generator so the module
imports and round-trips a minimum-viable codeword without any optional
deps — enough to keep ``pytest`` green on an air-gapped system, but not
enough to cover realistic NAND codec parameters.

The constructor accepts (t, m, data_chunk) per the plan; real ECC
parameters such as t=4/8/16 require ``galois`` (or another GF-arithmetic
library) at runtime. Tests that exercise those parameters should
``pytest.importorskip('galois')``.
"""
from __future__ import annotations

from typing import Any

from deepview.interfaces.ecc import ECCDecoder, ECCResult


class _TinyBCH74:
    """Hard-coded BCH(7, 4, t=1) over GF(2^3), primitive poly x^3+x+1.

    Exists only as a fallback so importing this module on a machine
    without ``galois`` still yields a working codec (for the single
    supported parameter set). Encodes 4 bits into a 7-bit codeword
    appending 3 ECC bits; corrects up to 1 bit error.
    """

    # Generator polynomial g(x) = x^3 + x + 1 (coefficients 1011 little-endian)
    GENERATOR: tuple[int, ...] = (1, 1, 0, 1)
    N = 7
    K = 4
    T = 1

    @classmethod
    def encode_nibble(cls, nibble: int) -> int:
        """Encode a 4-bit message -> 7-bit codeword (systematic, MSB-first)."""
        # Compute parity = (msg << 3) mod g(x)
        reg = 0
        for i in range(cls.K - 1, -1, -1):
            bit = (nibble >> i) & 1
            top = ((reg >> 2) & 1) ^ bit
            reg = ((reg << 1) & 0x7) ^ (top * 0b011)
        # Codeword = message (4 bits) || parity (3 bits)
        return ((nibble & 0xF) << 3) | (reg & 0x7)

    @classmethod
    def decode_codeword(cls, cw: int) -> tuple[int, int, bool]:
        """Decode a 7-bit codeword -> (4-bit nibble, nerr, uncorrectable)."""
        # Syndrome = cw mod g(x)
        reg = 0
        for i in range(cls.N - 1, -1, -1):
            bit = (cw >> i) & 1
            top = ((reg >> 2) & 1) ^ bit
            reg = ((reg << 1) & 0x7) ^ (top * 0b011)
        syn = reg & 0x7
        if syn == 0:
            return (cw >> 3) & 0xF, 0, False
        # Chien search: flip bit at position where x^pos == syn.
        # Precomputed: alpha^i for alpha=2 in GF(8) under x^3+x+1
        alpha_pow = [1, 2, 4, 3, 6, 7, 5]
        for pos, val in enumerate(alpha_pow):
            if val == syn:
                corrected = cw ^ (1 << pos)
                return (corrected >> 3) & 0xF, 1, False
        return (cw >> 3) & 0xF, 0, True


class BCHDecoder(ECCDecoder):
    """BCH SEC/DEC/... codec.

    Parameters
    ----------
    t:
        Number of correctable bit errors per data chunk. Default 8.
    m:
        Galois field exponent; ``n = 2**m - 1``. Default 13.
    data_chunk:
        Number of message bytes per codeword. Default 512.

    The constructor attempts to ``import galois`` lazily. If successful,
    arbitrary parameters are supported. Otherwise, only the pre-baked
    (t=1, m=3, data_chunk=1) fallback is available; any other parameter
    combination will raise ``RuntimeError`` at construction time,
    prompting callers to install ``pip install galois``.
    """

    def __init__(self, t: int = 8, m: int = 13, data_chunk: int = 512) -> None:
        if t < 1:
            raise ValueError("t must be >= 1")
        if data_chunk < 1:
            raise ValueError("data_chunk must be >= 1")
        self.t = t
        self.m = m
        self.data_chunk = data_chunk
        self.name = f"bch(t={t},m={m})"

        self._galois_bch: Any | None = None
        self._tiny: _TinyBCH74 | None = None

        try:
            import galois  # type: ignore[import-not-found]

            self._galois_bch = galois.BCH(2**m - 1, d=2 * t + 1)
            n = int(self._galois_bch.n)
            k = int(self._galois_bch.k)
            self.ecc_bytes = ((n - k) + 7) // 8
            if data_chunk * 8 > k:
                raise ValueError(
                    f"data_chunk={data_chunk} bytes exceeds BCH message "
                    f"capacity {k} bits for t={t}, m={m}"
                )
        except ImportError:
            if (t, m, data_chunk) != (1, 3, 1):
                raise RuntimeError(
                    "BCHDecoder fallback only supports (t=1, m=3, data_chunk=1); "
                    "install the 'galois' package for other parameters"
                ) from None
            self._tiny = _TinyBCH74()
            self.ecc_bytes = 1

    # ---- codec ----

    def encode(self, data: bytes) -> bytes:
        if len(data) != self.data_chunk:
            raise ValueError(
                f"bch encode expects {self.data_chunk} bytes, got {len(data)}"
            )
        if self._galois_bch is not None:
            return self._encode_galois(data)
        assert self._tiny is not None
        # data_chunk=1, so encode the low nibble; pad 3 bits into 1 ECC byte.
        nibble = data[0] & 0xF
        cw = _TinyBCH74.encode_nibble(nibble)
        parity = cw & 0x7
        return bytes((parity,))

    def decode(self, data: bytes, ecc: bytes) -> ECCResult:
        if len(data) != self.data_chunk:
            raise ValueError(
                f"bch decode expects {self.data_chunk} data bytes, got {len(data)}"
            )
        if len(ecc) != self.ecc_bytes:
            raise ValueError(
                f"bch decode expects {self.ecc_bytes} ecc bytes, got {len(ecc)}"
            )
        if self._galois_bch is not None:
            return self._decode_galois(data, ecc)
        assert self._tiny is not None
        nibble = data[0] & 0xF
        parity = ecc[0] & 0x7
        cw = (nibble << 3) | parity
        recovered, nerr, uncorr = _TinyBCH74.decode_codeword(cw)
        out = bytes(((data[0] & 0xF0) | (recovered & 0xF),))
        return ECCResult(data=out, errors_corrected=nerr, uncorrectable=uncorr)

    # ---- galois backend ----

    def _encode_galois(self, data: bytes) -> bytes:
        import numpy as np  # type: ignore[import-not-found]

        bch = self._galois_bch
        assert bch is not None
        n = int(bch.n)
        k = int(bch.k)
        bits = _bytes_to_bits_msb(data)
        msg = np.zeros(k, dtype=np.uint8)
        msg[k - len(bits):] = bits
        cw = np.asarray(bch.encode(msg), dtype=np.uint8)
        parity_bits = [int(x) for x in cw[k:n]]
        total_bits = self.ecc_bytes * 8
        if len(parity_bits) < total_bits:
            parity_bits = [0] * (total_bits - len(parity_bits)) + parity_bits
        return _bits_to_bytes_msb(parity_bits)

    def _decode_galois(self, data: bytes, ecc: bytes) -> ECCResult:
        import numpy as np  # type: ignore[import-not-found]

        bch = self._galois_bch
        assert bch is not None
        n = int(bch.n)
        k = int(bch.k)
        data_bits = _bytes_to_bits_msb(data)
        ecc_bits_padded = _bytes_to_bits_msb(ecc)
        pad = self.ecc_bytes * 8 - (n - k)
        ecc_bits = ecc_bits_padded[pad:]
        msg_bits = [0] * (k - len(data_bits)) + list(data_bits)
        codeword = np.array(msg_bits + list(ecc_bits), dtype=np.uint8)
        decoded, nerr = bch.decode(codeword, errors=True)
        nerr_int = int(nerr)
        if nerr_int < 0:
            return ECCResult(data=bytes(data), errors_corrected=0, uncorrectable=True)
        decoded_bits = [int(x) for x in decoded[-len(data_bits):]]
        return ECCResult(
            data=_bits_to_bytes_msb(decoded_bits),
            errors_corrected=nerr_int,
            uncorrectable=False,
        )


def _bytes_to_bits_msb(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes_msb(bits: list[int]) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i >> 3] |= 1 << (7 - (i & 7))
    return bytes(out)
