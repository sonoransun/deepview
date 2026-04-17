"""Reed-Solomon codec over GF(2^8).

Attempts to lazy-import the ``reedsolo`` PyPI package in the constructor.
If unavailable, falls back to a small vendored pure-Python RS codec
adapted from the public-domain Wikiversity reference implementation.

The fallback stores polynomials *highest-degree-first*, uses systematic
encoding (message || parity), alpha=2 as the primitive element, and
consecutive generator roots alpha^0..alpha^(nsym-1).
"""
from __future__ import annotations

from typing import Any

from deepview.interfaces.ecc import ECCDecoder, ECCResult


# --- GF(2^8) tables (primitive poly 0x11d, alpha = 2) ---

_PRIM_POLY = 0x11D
_GF_EXP: list[int] = [0] * 512
_GF_LOG: list[int] = [0] * 256


def _build_tables() -> None:
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= _PRIM_POLY
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_build_tables()


def _gf_mul(x: int, y: int) -> int:
    if x == 0 or y == 0:
        return 0
    return _GF_EXP[_GF_LOG[x] + _GF_LOG[y]]


def _gf_div(x: int, y: int) -> int:
    if y == 0:
        raise ZeroDivisionError()
    if x == 0:
        return 0
    return _GF_EXP[(_GF_LOG[x] + 255 - _GF_LOG[y]) % 255]


def _gf_pow(x: int, power: int) -> int:
    return _GF_EXP[(_GF_LOG[x] * power) % 255]


def _gf_inverse(x: int) -> int:
    return _GF_EXP[255 - _GF_LOG[x]]


# --- polynomial helpers (highest-degree-first) ---


def _poly_scale(p: list[int], x: int) -> list[int]:
    return [_gf_mul(p[i], x) for i in range(len(p))]


def _poly_add(p: list[int], q: list[int]) -> list[int]:
    r = [0] * max(len(p), len(q))
    for i in range(len(p)):
        r[i + len(r) - len(p)] = p[i]
    for i in range(len(q)):
        r[i + len(r) - len(q)] ^= q[i]
    return r


def _poly_mul(p: list[int], q: list[int]) -> list[int]:
    r = [0] * (len(p) + len(q) - 1)
    lp = [_GF_LOG[p[i]] if p[i] else -1 for i in range(len(p))]
    for j in range(len(q)):
        qj = q[j]
        if qj == 0:
            continue
        lq = _GF_LOG[qj]
        for i in range(len(p)):
            if lp[i] == -1:
                continue
            r[i + j] ^= _GF_EXP[lp[i] + lq]
    return r


def _poly_eval(p: list[int], x: int) -> int:
    y = p[0]
    for i in range(1, len(p)):
        y = _gf_mul(y, x) ^ p[i]
    return y


# --- RS core (Wikiversity-style) ---


def _rs_generator_poly(nsym: int) -> list[int]:
    g = [1]
    for i in range(nsym):
        g = _poly_mul(g, [1, _GF_EXP[i]])
    return g


def _rs_encode_msg(msg_in: list[int], nsym: int) -> list[int]:
    gen = _rs_generator_poly(nsym)
    msg_out = list(msg_in) + [0] * (len(gen) - 1)
    for i in range(len(msg_in)):
        coef = msg_out[i]
        if coef != 0:
            for j in range(1, len(gen)):
                msg_out[i + j] ^= _gf_mul(gen[j], coef)
    msg_out[: len(msg_in)] = msg_in
    return msg_out


def _rs_calc_syndromes(msg: list[int], nsym: int) -> list[int]:
    return [0] + [_poly_eval(msg, _GF_EXP[i]) for i in range(nsym)]


def _rs_find_error_locator(
    synd: list[int], nsym: int, erase_count: int = 0
) -> list[int]:
    err_loc = [1]
    old_loc = [1]
    synd_shift = 0
    if len(synd) > nsym:
        synd_shift = len(synd) - nsym
    for i in range(nsym - erase_count):
        k = i + synd_shift
        delta = synd[k]
        for j in range(1, len(err_loc)):
            delta ^= _gf_mul(err_loc[-(j + 1)], synd[k - j])
        old_loc = old_loc + [0]
        if delta != 0:
            if len(old_loc) > len(err_loc):
                new_loc = _poly_scale(old_loc, delta)
                old_loc = _poly_scale(err_loc, _gf_inverse(delta))
                err_loc = new_loc
            err_loc = _poly_add(err_loc, _poly_scale(old_loc, delta))
    while len(err_loc) and err_loc[0] == 0:
        del err_loc[0]
    return err_loc


def _rs_find_errors(err_loc: list[int], nmess: int) -> list[int] | None:
    errs = len(err_loc) - 1
    err_pos = []
    for i in range(nmess):
        if _poly_eval(err_loc, _gf_pow(2, i)) == 0:
            err_pos.append(nmess - 1 - i)
    if len(err_pos) != errs:
        return None
    return err_pos


def _rs_find_error_evaluator(
    synd: list[int], err_loc: list[int], nsym: int
) -> list[int]:
    _q, remainder = _poly_div(
        _poly_mul(synd, err_loc), [1] + [0] * (nsym + 1)
    )
    return remainder


def _poly_div(dividend: list[int], divisor: list[int]) -> tuple[list[int], list[int]]:
    msg_out = list(dividend)
    for i in range(len(dividend) - len(divisor) + 1):
        coef = msg_out[i]
        if coef != 0:
            for j in range(1, len(divisor)):
                if divisor[j] != 0:
                    msg_out[i + j] ^= _gf_mul(divisor[j], coef)
    separator = -(len(divisor) - 1)
    return msg_out[:separator], msg_out[separator:]


def _rs_correct_errata(
    msg_in: list[int], synd: list[int], err_pos: list[int]
) -> list[int]:
    coef_pos = [len(msg_in) - 1 - p for p in err_pos]
    err_loc = _rs_find_errata_locator(coef_pos)
    err_eval = _rs_find_error_evaluator(synd[::-1], err_loc, len(err_loc) - 1)[::-1]

    X = []
    for i in range(len(coef_pos)):
        L = 255 - coef_pos[i]
        X.append(_GF_EXP[(-L) % 255])

    E = [0] * len(msg_in)
    Xlen = len(X)
    for i, Xi in enumerate(X):
        Xi_inv = _gf_inverse(Xi)
        err_loc_prime_tmp = []
        for j in range(Xlen):
            if j != i:
                err_loc_prime_tmp.append(1 ^ _gf_mul(Xi_inv, X[j]))
        err_loc_prime = 1
        for c in err_loc_prime_tmp:
            err_loc_prime = _gf_mul(err_loc_prime, c)
        y = _poly_eval(err_eval[::-1], Xi_inv)
        y = _gf_mul(_gf_pow(Xi, 1), y)
        if err_loc_prime == 0:
            raise ValueError("Decoding failure: err_loc_prime=0")
        magnitude = _gf_div(y, err_loc_prime)
        E[err_pos[i]] = magnitude
    msg_in = _poly_add(msg_in, E)
    return msg_in


def _rs_find_errata_locator(e_pos: list[int]) -> list[int]:
    e_loc = [1]
    for i in e_pos:
        e_loc = _poly_mul(e_loc, _poly_add([1], [_gf_pow(2, i), 0]))
    return e_loc


def _rs_decode_msg(
    msg_in: list[int], nsym: int
) -> tuple[list[int], list[int], int, bool]:
    if len(msg_in) > 255:
        raise ValueError("message too long")
    msg_out = list(msg_in)
    synd = _rs_calc_syndromes(msg_out, nsym)
    if max(synd) == 0:
        return msg_out[:-nsym], msg_out[-nsym:], 0, False
    err_loc = _rs_find_error_locator(synd, nsym)
    err_pos = _rs_find_errors(err_loc[::-1], len(msg_out))
    if err_pos is None:
        return msg_out[:-nsym], msg_out[-nsym:], 0, True
    try:
        msg_out = _rs_correct_errata(msg_out, synd, err_pos)
    except (ValueError, ZeroDivisionError):
        return list(msg_in)[:-nsym], list(msg_in)[-nsym:], 0, True
    verify = _rs_calc_syndromes(msg_out, nsym)
    if max(verify) > 0:
        return list(msg_in)[:-nsym], list(msg_in)[-nsym:], 0, True
    return msg_out[:-nsym], msg_out[-nsym:], len(err_pos), False


class _PurePythonRS:
    """Vendored pure-Python RS(nsym) codec over GF(2^8), alpha=2."""

    def __init__(self, nsym: int) -> None:
        if nsym < 1 or nsym > 254:
            raise ValueError("nsym must be in 1..254")
        self.nsym = nsym

    def encode(self, data: bytes) -> bytes:
        full = _rs_encode_msg(list(data), self.nsym)
        return bytes(full[-self.nsym:])

    def decode(self, data: bytes, ecc: bytes) -> tuple[bytes, int, bool]:
        full_in = list(data) + list(ecc)
        msg, _parity, nerr, uncorr = _rs_decode_msg(full_in, self.nsym)
        if uncorr:
            return bytes(data), 0, True
        return bytes(msg), nerr, False


class ReedSolomonDecoder(ECCDecoder):
    """Reed-Solomon codec over GF(2^8).

    Parameters
    ----------
    nsym:
        Number of parity bytes (== 2t corrective capability). Default 16
        -> corrects up to 8 byte errors per chunk.
    data_chunk:
        Number of message bytes per codeword. Default 512. Note that RS
        over GF(2^8) requires ``data_chunk + nsym <= 255`` for a
        non-shortened code. With the default ``nsym=16`` the usable
        ``data_chunk`` is at most 239. Callers needing a larger chunk
        should split it into multiple RS blocks at the layer level.
    """

    def __init__(self, nsym: int = 16, data_chunk: int = 512) -> None:
        if nsym < 1:
            raise ValueError("nsym must be >= 1")
        if data_chunk < 1:
            raise ValueError("data_chunk must be >= 1")
        if nsym + data_chunk > 255:
            raise ValueError(
                f"nsym + data_chunk must be <= 255 (got {nsym + data_chunk})"
            )
        self.nsym = nsym
        self.data_chunk = data_chunk
        self.ecc_bytes = nsym
        self.name = f"rs(n={data_chunk + nsym},k={data_chunk})"

        self._reedsolo: Any | None = None
        self._fallback: _PurePythonRS | None = None
        try:
            import reedsolo  # type: ignore[import-not-found]

            self._reedsolo = reedsolo.RSCodec(nsym)
        except ImportError:
            self._fallback = _PurePythonRS(nsym=nsym)

    def encode(self, data: bytes) -> bytes:
        if len(data) != self.data_chunk:
            raise ValueError(
                f"rs encode expects {self.data_chunk} bytes, got {len(data)}"
            )
        if self._reedsolo is not None:
            full = self._reedsolo.encode(bytearray(data))
            return bytes(full[-self.nsym:])
        assert self._fallback is not None
        return self._fallback.encode(data)

    def decode(self, data: bytes, ecc: bytes) -> ECCResult:
        if len(data) != self.data_chunk:
            raise ValueError(
                f"rs decode expects {self.data_chunk} data bytes, got {len(data)}"
            )
        if len(ecc) != self.ecc_bytes:
            raise ValueError(
                f"rs decode expects {self.ecc_bytes} ecc bytes, got {len(ecc)}"
            )
        if self._reedsolo is not None:
            return self._decode_reedsolo(data, ecc)
        assert self._fallback is not None
        out, nerr, uncorr = self._fallback.decode(data, ecc)
        return ECCResult(data=out, errors_corrected=nerr, uncorrectable=uncorr)

    def _decode_reedsolo(self, data: bytes, ecc: bytes) -> ECCResult:
        import reedsolo  # type: ignore[import-not-found]

        codec = self._reedsolo
        assert codec is not None
        try:
            decoded, _full, errata = codec.decode(bytearray(data) + bytearray(ecc))
        except reedsolo.ReedSolomonError:
            return ECCResult(data=bytes(data), errors_corrected=0, uncorrectable=True)
        nerr = len(errata) if errata is not None else 0
        return ECCResult(
            data=bytes(decoded[: self.data_chunk]),
            errors_corrected=nerr,
            uncorrectable=False,
        )
