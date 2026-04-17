"""Hand-crafted LUKS1 + LUKS2 header parse tests."""
from __future__ import annotations

import json
import struct
from collections.abc import Callable, Iterator

import pytest

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer


class _Mem(DataLayer):
    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        end = min(offset + length, len(self._data))
        out = self._data[offset:end]
        if pad and len(out) < length:
            out = out + b"\x00" * (length - len(out))
        return out

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._data)

    def scan(
        self, scanner: object, progress_callback: Callable | None = None
    ) -> Iterator[ScanResult]:
        yield from ()

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(0, len(self._data) - 1)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name="mem")


def _pad(s: bytes, n: int) -> bytes:
    if len(s) > n:
        raise ValueError("too long")
    return s + b"\x00" * (n - len(s))


def _build_luks1_header(
    *,
    cipher_name: bytes = b"aes",
    cipher_mode: bytes = b"xts-plain64",
    hash_spec: bytes = b"sha256",
    payload_offset_sectors: int = 4096,
    key_bytes: int = 32,
    mk_digest: bytes = b"\xAA" * 20,
    mk_digest_salt: bytes = b"\xBB" * 32,
    mk_digest_iter: int = 1000,
    uuid: bytes = b"11111111-2222-3333-4444-555555555555",
    keyslot_salt: bytes = b"\xCC" * 32,
    keyslot_iter: int = 2000,
    km_offset_sectors: int = 8,
    stripes: int = 4000,
) -> bytes:
    buf = bytearray(592)
    buf[0:6] = b"LUKS\xba\xbe"
    buf[6:8] = struct.pack(">H", 1)
    buf[8:40] = _pad(cipher_name, 32)
    buf[40:72] = _pad(cipher_mode, 32)
    buf[72:104] = _pad(hash_spec, 32)
    buf[104:108] = struct.pack(">I", payload_offset_sectors)
    buf[108:112] = struct.pack(">I", key_bytes)
    buf[112:132] = mk_digest
    buf[132:164] = mk_digest_salt
    buf[164:168] = struct.pack(">I", mk_digest_iter)
    buf[168:208] = _pad(uuid, 40)
    # Keyslot 0 — active.
    ks_off = 208
    buf[ks_off : ks_off + 4] = struct.pack(">I", 0x00AC71F3)
    buf[ks_off + 4 : ks_off + 8] = struct.pack(">I", keyslot_iter)
    buf[ks_off + 8 : ks_off + 40] = keyslot_salt
    buf[ks_off + 40 : ks_off + 44] = struct.pack(">I", km_offset_sectors)
    buf[ks_off + 44 : ks_off + 48] = struct.pack(">I", stripes)
    # Keyslots 1..7 — inactive.
    for i in range(1, 8):
        off = 208 + i * 48
        buf[off : off + 4] = struct.pack(">I", 0x0000DEAD)
    return bytes(buf)


def test_luks1_detect_parses_known_fields() -> None:
    from deepview.storage.containers.luks import LUKSUnlocker

    raw = _build_luks1_header(
        cipher_name=b"aes",
        cipher_mode=b"xts-plain64",
        payload_offset_sectors=4096,
        key_bytes=32,
    )
    # Make the "image" big enough so data_length is reported
    # sensibly — 4096-sector payload + a bit extra.
    layer = _Mem(raw + b"\x00" * (4096 * 512 + 1024))

    unlocker = LUKSUnlocker()
    header = unlocker.detect(layer)
    assert header is not None
    assert header.format == "luks1"
    assert header.cipher.startswith("aes-xts")
    assert header.sector_size == 512
    assert header.data_offset == 4096 * 512
    assert header.kdf == "pbkdf2"
    assert header.kdf_params["dklen"] == 32
    assert header.kdf_params["hash"] == "sha256"
    assert header.kdf_params["iterations"] == 2000
    assert header.kdf_params["mk_digest_iter"] == 1000
    assert len(header.kdf_params["mk_digest_salt"]) == 32  # type: ignore[arg-type]


def test_luks1_detect_missing_magic_returns_none() -> None:
    from deepview.storage.containers.luks import LUKSUnlocker

    layer = _Mem(b"\x00" * 1024)
    assert LUKSUnlocker().detect(layer) is None


def _build_luks2_header(
    *,
    kdf_type: str = "argon2id",
    payload_offset: int = 16 * 1024 * 1024,
    segment_size: str | int = "dynamic",
) -> bytes:
    meta = {
        "keyslots": {
            "0": {
                "type": "luks2",
                "key_size": 64,
                "area": {
                    "type": "raw",
                    "offset": "32768",
                    "size": "258048",
                    "encryption": "aes-xts-plain64",
                    "key_size": 64,
                },
                "kdf": {
                    "type": kdf_type,
                    "time": 4,
                    "memory": 1048576,
                    "cpus": 4,
                    "salt": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nw==",
                },
                "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
            }
        },
        "segments": {
            "0": {
                "type": "crypt",
                "offset": str(payload_offset),
                "iv_tweak": "0",
                "size": segment_size if isinstance(segment_size, str) else str(segment_size),
                "encryption": "aes-xts-plain64",
                "sector_size": 512,
            }
        },
        "digests": {
            "0": {
                "type": "pbkdf2",
                "keyslots": ["0"],
                "segments": ["0"],
                "salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "digest": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
                "hash": "sha256",
                "iterations": 98765,
            }
        },
        "tokens": {},
        "config": {"json_size": "12288", "keyslots_size": "16744448"},
    }
    json_blob = json.dumps(meta).encode("utf-8")
    total = 4096 + len(json_blob)
    # Round up to a 4 KiB boundary so the binary hdr + JSON align.
    if total % 4096:
        total += 4096 - (total % 4096)
    buf = bytearray(total)
    buf[0:6] = b"LUKS\xba\xbe"
    buf[6:8] = struct.pack(">H", 2)
    buf[8:16] = struct.pack(">Q", total)
    buf[16:24] = struct.pack(">Q", 1)  # seqid
    buf[24:72] = _pad(b"label", 48)
    buf[72:104] = _pad(b"sha256", 32)
    buf[104:168] = b"\x00" * 64  # salt
    buf[168:208] = _pad(b"aa-bb-cc", 40)
    buf[208:256] = _pad(b"subsystem", 48)
    buf[256:264] = struct.pack(">Q", 0)
    buf[448:512] = b"\x00" * 64  # csum
    buf[512 : 512 + len(json_blob)] = json_blob
    return bytes(buf)


def test_luks2_detect_argon2id_kdf() -> None:
    from deepview.storage.containers.luks import LUKSUnlocker

    raw = _build_luks2_header(kdf_type="argon2id", payload_offset=16 * 1024 * 1024)
    # image is 32 MiB so the "dynamic" segment has somewhere to land.
    layer = _Mem(raw + b"\x00" * (32 * 1024 * 1024))
    header = LUKSUnlocker().detect(layer)
    assert header is not None
    assert header.format == "luks2"
    assert header.cipher == "aes-xts-plain64"
    assert header.sector_size == 512
    assert header.data_offset == 16 * 1024 * 1024
    assert header.kdf == "argon2id"
    assert header.kdf_params["time_cost"] == 4
    assert header.kdf_params["memory_cost"] == 1048576
    assert header.kdf_params["parallelism"] == 4
    assert header.kdf_params["keyslot_af_stripes"] == 4000
    assert header.kdf_params["keyslot_af_hash"] == "sha256"
    assert header.kdf_params["keyslot_offset"] == 32768
    assert header.kdf_params["keyslot_size"] == 258048
    assert isinstance(header.kdf_params["salt"], bytes)


def test_luks2_detect_pbkdf2_kdf() -> None:
    from deepview.storage.containers.luks import LUKSUnlocker

    raw = _build_luks2_header(kdf_type="pbkdf2")
    layer = _Mem(raw + b"\x00" * (32 * 1024 * 1024))
    header = LUKSUnlocker().detect(layer)
    assert header is not None
    assert header.format == "luks2"
    assert header.kdf == "pbkdf2"
    # pbkdf2 path stores iterations + hash.
    assert "iterations" in header.kdf_params


@pytest.mark.parametrize(
    "cipher_mode,expected_mode",
    [
        (b"xts-plain64", "xts"),
        (b"cbc-essiv:sha256", "cbc-essiv"),
        (b"cbc-plain64", "cbc-plain64"),
    ],
)
def test_luks1_cipher_mode_maps_correctly(cipher_mode: bytes, expected_mode: str) -> None:
    from deepview.storage.containers.luks import LUKSUnlocker, _iv_mode_for_cipher

    raw = _build_luks1_header(cipher_mode=cipher_mode)
    layer = _Mem(raw + b"\x00" * (4096 * 512 + 1024))
    header = LUKSUnlocker().detect(layer)
    assert header is not None
    dv_mode, _ = _iv_mode_for_cipher("aes", cipher_mode.decode("utf-8"))
    assert dv_mode == expected_mode
