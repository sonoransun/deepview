"""VeraCrypt + TrueCrypt (standard + hidden volume) unlocker.

This adapter implements the VeraCrypt on-disk header layout described in
``VeraCrypt/Common/Volumes.c`` (version 1.25-Update8). Both the legacy
TrueCrypt layout and the modern VeraCrypt layout share a 65 536-byte
sector-aligned header whose first 64 bytes are a salt and whose next
448 bytes are the password-encrypted volume header:

=========  ======  =================================================
offset     length  field
=========  ======  =================================================
0          64      salt
64         4       magic (``"VERA"`` for VeraCrypt, ``"TRUE"`` for
                   TrueCrypt) — inside the encrypted portion
68         2       version
70         2       required_version
72         4       crc32(keys)
76         16      reserved
92         8       hidden_volume_size
100        8       volume_size
108        8       encrypted_area_start
116        8       encrypted_area_size
124        4       flag_bits
128        4       sector_size
132        120     reserved
252        4       crc32(header data 0..251)
256        256     master_key + tweak_key (cipher / cascade specific)
=========  ======  =================================================

A *hidden* volume is an independent VeraCrypt volume whose 65 536-byte
header starts at ``volume_total_size - 65 536`` (modern layout) or at
``volume_total_size - 131 072`` (legacy layout). A different passphrase
unlocks it; the two volumes share the same outer ciphertext and are
cryptographically indistinguishable.

The unlock flow is a brute-force trial decryption — the on-disk header
never tells us which PRF / iteration count / cipher cascade was used,
so we iterate (``KDF`` × ``cascade``) combinations, derive a 64-byte
candidate header key through :mod:`deepview.offload`, attempt to
decrypt the 448-byte blob, and call it a hit when the magic and the
inner CRC32 both match. Every failed attempt is cheap (one CRC32) but
every KDF derivation is expensive — we always offload.

All cipher primitives are lazy-imported so a core install without the
``containers`` extra still imports this module without error.
"""
from __future__ import annotations

import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, cast

from deepview.interfaces.layer import DataLayer
from deepview.storage.containers.unlock import ContainerHeader, KeySource, Unlocker

if TYPE_CHECKING:
    from deepview.storage.containers.layer import DecryptedVolumeLayer

# ---------------------------------------------------------------------------
# Header constants
# ---------------------------------------------------------------------------

_HEADER_SIZE = 65_536
_SALT_LEN = 64
_ENCRYPTED_HEADER_LEN = 448
_KEY_AREA_LEN = 256
_MAGIC_VERACRYPT = b"VERA"
_MAGIC_TRUECRYPT = b"TRUE"

# Offsets *within* the 448-byte decrypted header block.
_OFF_MAGIC = 0
_OFF_VERSION = 4
_OFF_REQUIRED_VERSION = 6
_OFF_CRC_KEYS = 8
_OFF_HIDDEN_SIZE = 28
_OFF_VOLUME_SIZE = 36
_OFF_ENC_AREA_START = 44
_OFF_ENC_AREA_SIZE = 52
_OFF_FLAGS = 60
_OFF_SECTOR_SIZE = 64
_OFF_CRC_DATA = 188
_OFF_MASTER_KEYS = 192


@dataclass(frozen=True)
class _ParsedHeader:
    """Decoded fields from a validated 448-byte decrypted header."""

    magic: bytes
    version: int
    required_version: int
    crc_keys: int
    hidden_volume_size: int
    volume_size: int
    encrypted_area_start: int
    encrypted_area_size: int
    flags: int
    sector_size: int
    crc_data: int
    master_key_material: bytes


def _parse_header(plaintext: bytes, expected_magic: bytes) -> _ParsedHeader | None:
    """Parse 448 bytes of candidate plaintext. Return ``None`` if invalid.

    The CRC32 check is the primary false-positive filter — a wrong key
    produces random 448 bytes so the 32-bit match has a ``~2**-32``
    accidental-hit probability per PRF x cascade trial.
    """
    if len(plaintext) != _ENCRYPTED_HEADER_LEN:
        return None
    magic = plaintext[_OFF_MAGIC:_OFF_MAGIC + 4]
    if magic != expected_magic:
        return None

    # Inner CRC: CRC32 over the 188 bytes [0:188] (fields up through the
    # sector_size block); the stored crc32 is big-endian at offset 252.
    # VeraCrypt actually computes it over the first 188 bytes of the
    # decrypted header — see Common/Volumes.c:ReadVolumeHeader.
    computed_data_crc = zlib.crc32(plaintext[0:_OFF_CRC_DATA]) & 0xFFFFFFFF
    stored_data_crc = int.from_bytes(
        plaintext[_OFF_CRC_DATA:_OFF_CRC_DATA + 4], "big"
    )
    if computed_data_crc != stored_data_crc:
        return None

    # Secondary CRC: of the 256-byte master-key area.
    key_area = plaintext[_OFF_MASTER_KEYS:_OFF_MASTER_KEYS + _KEY_AREA_LEN]
    computed_keys_crc = zlib.crc32(key_area) & 0xFFFFFFFF
    stored_keys_crc = int.from_bytes(
        plaintext[_OFF_CRC_KEYS:_OFF_CRC_KEYS + 4], "big"
    )
    if computed_keys_crc != stored_keys_crc:
        return None

    version = struct.unpack(">H", plaintext[_OFF_VERSION:_OFF_VERSION + 2])[0]
    required_version = struct.unpack(
        ">H", plaintext[_OFF_REQUIRED_VERSION:_OFF_REQUIRED_VERSION + 2]
    )[0]
    hidden_vol_size = struct.unpack(
        ">Q", plaintext[_OFF_HIDDEN_SIZE:_OFF_HIDDEN_SIZE + 8]
    )[0]
    volume_size = struct.unpack(
        ">Q", plaintext[_OFF_VOLUME_SIZE:_OFF_VOLUME_SIZE + 8]
    )[0]
    enc_area_start = struct.unpack(
        ">Q", plaintext[_OFF_ENC_AREA_START:_OFF_ENC_AREA_START + 8]
    )[0]
    enc_area_size = struct.unpack(
        ">Q", plaintext[_OFF_ENC_AREA_SIZE:_OFF_ENC_AREA_SIZE + 8]
    )[0]
    flags = struct.unpack(">I", plaintext[_OFF_FLAGS:_OFF_FLAGS + 4])[0]
    sector_size = struct.unpack(
        ">I", plaintext[_OFF_SECTOR_SIZE:_OFF_SECTOR_SIZE + 4]
    )[0]
    if sector_size == 0:
        sector_size = 512

    return _ParsedHeader(
        magic=magic,
        version=version,
        required_version=required_version,
        crc_keys=stored_keys_crc,
        hidden_volume_size=hidden_vol_size,
        volume_size=volume_size,
        encrypted_area_start=enc_area_start,
        encrypted_area_size=enc_area_size,
        flags=flags,
        sector_size=sector_size,
        crc_data=stored_data_crc,
        master_key_material=key_area,
    )


# ---------------------------------------------------------------------------
# Unlocker base
# ---------------------------------------------------------------------------


class _VeraCryptBase(Unlocker):
    """Shared detect + unlock machinery for VeraCrypt + TrueCrypt."""

    format_name: ClassVar[str] = "veracrypt"
    expected_magic: ClassVar[bytes] = _MAGIC_VERACRYPT

    def __init__(
        self,
        *,
        pim: int = 0,
        system_enc: bool = False,
        override_iterations: int | None = None,
    ) -> None:
        """Construct an unlocker.

        Parameters
        ----------
        pim:
            VeraCrypt Personal Iterations Multiplier (0 = default).
        system_enc:
            True for the system-encryption (pre-boot) path.
        override_iterations:
            **Test-only.** Replace every KDF's iteration count with this
            value. Only used to keep fixture tests fast — production
            code never passes this.
        """
        self._pim = pim
        self._system_enc = system_enc
        self._override_iterations = override_iterations

    # ------------------------------------------------------------------
    # detect
    # ------------------------------------------------------------------

    def detect(self, layer: DataLayer, offset: int = 0) -> ContainerHeader | None:
        """Return a generic :class:`ContainerHeader` when *layer* is a candidate.

        We can't distinguish VeraCrypt from TrueCrypt or identify the
        cipher cascade without a successful trial decrypt — so we only
        confirm that there is enough room for a 65 536-byte header and
        stash the trailing hidden-volume offsets into ``kdf_params``
        for :meth:`unlock`.
        """
        try:
            total = layer.maximum_address + 1
        except Exception:
            return None
        if total < _HEADER_SIZE:
            return None

        try:
            salt = layer.read(offset, _SALT_LEN)
        except Exception:
            return None
        if len(salt) != _SALT_LEN:
            return None

        return ContainerHeader(
            format=self.format_name,
            cipher="aes-xts (trial)",
            sector_size=512,
            data_offset=_HEADER_SIZE,
            data_length=max(0, total - _HEADER_SIZE),
            kdf="trial-decrypt",
            kdf_params={
                "salt": salt,
                "header_offset": offset,
                "standard_header_offset": offset,
                "hidden_header_offset_modern": max(0, total - _HEADER_SIZE),
                "hidden_header_offset_legacy": max(0, total - 2 * _HEADER_SIZE),
                "total_size": total,
                "pim": self._pim,
                "system_enc": self._system_enc,
            },
            raw=salt,
        )

    # ------------------------------------------------------------------
    # unlock
    # ------------------------------------------------------------------

    async def unlock(
        self,
        layer: DataLayer,
        header: ContainerHeader,
        source: KeySource,
        *,
        try_hidden: bool = False,
    ) -> "DecryptedVolumeLayer":
        """Trial-decrypt the header and build a :class:`DecryptedVolumeLayer`."""
        # Lazy to preserve slice 14 independence.
        from deepview.storage.containers.unlock import MasterKey, Passphrase

        kdf_params = dict(header.kdf_params)
        total_size_raw = kdf_params.get("total_size", layer.maximum_address + 1)
        total_size = int(total_size_raw)  # type: ignore[arg-type]
        standard_offset = int(kdf_params.get("standard_header_offset", 0))  # type: ignore[arg-type]

        candidate_offsets: list[int] = []
        if not try_hidden:
            candidate_offsets.append(standard_offset)
        else:
            modern = int(kdf_params.get("hidden_header_offset_modern", 0))  # type: ignore[arg-type]
            legacy = int(kdf_params.get("hidden_header_offset_legacy", 0))  # type: ignore[arg-type]
            candidate_offsets.append(modern)
            if legacy != modern:
                candidate_offsets.append(legacy)

        for header_offset in candidate_offsets:
            if header_offset < 0 or header_offset + _HEADER_SIZE > total_size:
                continue
            salt = layer.read(header_offset, _SALT_LEN)
            ciphertext = layer.read(
                header_offset + _SALT_LEN, _ENCRYPTED_HEADER_LEN
            )
            if len(salt) != _SALT_LEN or len(ciphertext) != _ENCRYPTED_HEADER_LEN:
                continue

            if isinstance(source, MasterKey):
                parsed, cascade_name = self._trial_decrypt_with_key(
                    ciphertext, source.key
                )
                if parsed is None:
                    continue
                return self._build_layer(
                    layer=layer,
                    parsed=parsed,
                    cascade_name=cascade_name,
                    header_offset=header_offset,
                    total_size=total_size,
                )

            if isinstance(source, Passphrase):
                result = self._try_passphrase(
                    layer=layer,
                    passphrase=source.passphrase,
                    salt=salt,
                    ciphertext=ciphertext,
                    header_offset=header_offset,
                    total_size=total_size,
                )
                if result is not None:
                    return result
                continue

            raise RuntimeError(
                f"{self.format_name} unlock does not support KeySource "
                f"{type(source).__name__} directly; supply a Passphrase "
                "or MasterKey"
            )

        raise RuntimeError(
            f"{self.format_name} header trial-decrypt failed "
            f"(try_hidden={try_hidden})"
        )

    # ------------------------------------------------------------------
    # KDF + cascade trial loop
    # ------------------------------------------------------------------

    def _try_passphrase(
        self,
        *,
        layer: DataLayer,
        passphrase: str,
        salt: bytes,
        ciphertext: bytes,
        header_offset: int,
        total_size: int,
    ) -> "DecryptedVolumeLayer | None":
        from deepview.offload.jobs import make_job

        from deepview.storage.containers._cipher_cascades import wired_cascades

        engine = _InlineEngine()
        kdfs = self._kdf_candidates()

        for kdf_name, iterations, dklen in kdfs:
            callable_ref = _callable_ref_for(kdf_name)
            if callable_ref is None:
                # PRF we don't have a worker for (whirlpool/streebog/
                # ripemd160) — skip silently. SHA256/SHA512 always
                # resolve.
                continue
            effective_iters = iterations
            if self._override_iterations is not None:
                effective_iters = self._override_iterations
            payload = {
                "password": passphrase,
                "salt": salt,
                "iterations": effective_iters,
                "dklen": dklen,
            }
            job = make_job(
                kind=f"pbkdf2_{kdf_name}",
                payload=payload,
                callable_ref=callable_ref,
            )
            fut = engine.submit(job)
            result = fut.await_result()
            if not result.ok:
                continue
            output = result.output
            if not isinstance(output, (bytes, bytearray)):
                continue
            header_key = bytes(output)

            for cascade in wired_cascades():
                try:
                    plaintext = cascade.decrypt_header(header_key, ciphertext)
                except NotImplementedError:
                    continue
                except Exception:
                    continue
                parsed = _parse_header(plaintext, self.expected_magic)
                if parsed is None:
                    continue
                return self._build_layer(
                    layer=layer,
                    parsed=parsed,
                    cascade_name=cascade.name,
                    header_offset=header_offset,
                    total_size=total_size,
                )
        return None

    def _trial_decrypt_with_key(
        self, ciphertext: bytes, header_key: bytes
    ) -> tuple[_ParsedHeader | None, str]:
        from deepview.storage.containers._cipher_cascades import wired_cascades

        for cascade in wired_cascades():
            try:
                plaintext = cascade.decrypt_header(header_key, ciphertext)
            except NotImplementedError:
                continue
            except Exception:
                continue
            parsed = _parse_header(plaintext, self.expected_magic)
            if parsed is not None:
                return parsed, cascade.name
        return None, ""

    # ------------------------------------------------------------------
    # Layer construction
    # ------------------------------------------------------------------

    def _build_layer(
        self,
        *,
        layer: DataLayer,
        parsed: _ParsedHeader,
        cascade_name: str,
        header_offset: int,
        total_size: int,
    ) -> "DecryptedVolumeLayer":
        from deepview.storage.containers._cipher_cascades import cascade_by_name
        from deepview.storage.containers.layer import DecryptedVolumeLayer

        cascade = cascade_by_name(cascade_name)
        if cascade is None:
            raise RuntimeError(f"unknown cascade {cascade_name!r}")

        data_offset = parsed.encrypted_area_start
        data_length = parsed.encrypted_area_size
        if data_offset == 0:
            # Fall back to "payload immediately after header" layout used
            # by some test fixtures and older VeraCrypt versions.
            data_offset = header_offset + _HEADER_SIZE
        if data_length == 0:
            data_length = max(0, total_size - data_offset)

        # The concatenated "master_key || tweak_key" buffer lives in
        # the master-key area and its layout depends on the cascade.
        # For AES-XTS it's 32 + 32 bytes at offset 0; for longer
        # cascades VeraCrypt concatenates ``key_n || ... || tweak_n``
        # — DecryptedVolumeLayer today only consumes the first 64.
        key_material = parsed.master_key_material[: cascade.key_bytes]
        if len(key_material) < 64:
            raise RuntimeError(
                f"{self.format_name} header does not carry enough key "
                f"material for cascade {cascade.name} "
                f"(got {len(key_material)} bytes)"
            )

        sector_size = parsed.sector_size or 512
        return DecryptedVolumeLayer(
            underlying=layer,
            cipher_name=cascade.first_cipher_name,
            key=key_material[:64],
            sector_size=sector_size,
            data_offset=data_offset,
            data_length=data_length,
            mode="xts",
            iv_mode="tweak",
            name=f"{self.format_name}:{cascade.name}",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _kdf_candidates(self) -> list[tuple[str, int, int]]:
        from deepview.storage.containers._kdf_table import iter_vc_kdfs

        return list(iter_vc_kdfs(pim=self._pim, system_enc=self._system_enc))


# ---------------------------------------------------------------------------
# Concrete classes
# ---------------------------------------------------------------------------


class VeraCryptUnlocker(_VeraCryptBase):
    """VeraCrypt (VERA magic) standard + hidden volume unlocker."""

    format_name: ClassVar[str] = "veracrypt"
    expected_magic: ClassVar[bytes] = _MAGIC_VERACRYPT


class TrueCryptUnlocker(_VeraCryptBase):
    """TrueCrypt (TRUE magic) standard + hidden volume unlocker."""

    format_name: ClassVar[str] = "truecrypt"
    expected_magic: ClassVar[bytes] = _MAGIC_TRUECRYPT

    def _kdf_candidates(self) -> list[tuple[str, int, int]]:
        from deepview.storage.containers._kdf_table import iter_tc_kdfs

        return list(iter_tc_kdfs(system_enc=self._system_enc))


# Orchestrator discovery hook.
UNLOCKER = VeraCryptUnlocker


# ---------------------------------------------------------------------------
# Inline (no context) offload shim + PRF dispatch
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _InlineResult:
    job_id: str
    ok: bool
    output: object
    error: str | None
    elapsed_s: float
    backend: str


class _InlineFuture:
    """Future-like wrapper for :class:`_InlineEngine` jobs."""

    def __init__(self, result: _InlineResult) -> None:
        self._result = result
        self.job_id = result.job_id

    def await_result(self, timeout: float | None = None) -> _InlineResult:
        return self._result

    def done(self) -> bool:
        return True


class _InlineEngine:
    """Tiny in-process offload shim used when no AnalysisContext is plumbed.

    The real :class:`~deepview.offload.engine.OffloadEngine` wants an
    ``AnalysisContext`` so it can publish events; here we just run the
    callable synchronously and return an object that quacks like
    :class:`~deepview.offload.futures.OffloadFuture`.
    """

    def submit(self, job: object) -> _InlineFuture:
        callable_ref = cast("str | None", getattr(job, "callable_ref", None))
        payload = getattr(job, "payload", None)
        job_id = cast(str, getattr(job, "job_id", "inline"))
        try:
            fn = _resolve_callable(callable_ref)
            output: object = fn(payload)
            return _InlineFuture(
                _InlineResult(
                    job_id=job_id,
                    ok=True,
                    output=output,
                    error=None,
                    elapsed_s=0.0,
                    backend="inline",
                )
            )
        except Exception as exc:  # noqa: BLE001
            return _InlineFuture(
                _InlineResult(
                    job_id=job_id,
                    ok=False,
                    output=None,
                    error=f"{type(exc).__name__}: {exc}",
                    elapsed_s=0.0,
                    backend="inline",
                )
            )


def _resolve_callable(ref: str | None) -> Callable[[Any], Any]:
    """Resolve ``"module:function"`` to the callable object."""
    if not ref:
        raise ValueError("inline engine requires a callable_ref")
    module_name, _, attr = ref.partition(":")
    if not module_name or not attr:
        raise ValueError(f"invalid callable_ref {ref!r}")
    import importlib

    module = importlib.import_module(module_name)
    resolved = getattr(module, attr)
    if not callable(resolved):
        raise TypeError(f"{ref!r} does not resolve to a callable")
    return cast("Callable[[Any], Any]", resolved)


def _callable_ref_for(kdf_name: str) -> str | None:
    """Map a PRF name to the offload callable handling it.

    We only wire SHA-256 and SHA-512 here — the other PRFs (Whirlpool /
    Streebog / RIPEMD-160) would need ``hashlib`` extensions available
    only through OpenSSL's legacy provider. ``None`` is returned so
    the caller skips cleanly.
    """
    if kdf_name == "sha256":
        return "deepview.offload.kdf:pbkdf2_sha256"
    if kdf_name == "sha512":
        return "deepview.storage.containers.veracrypt:pbkdf2_sha512"
    return None


def pbkdf2_sha512(payload: object) -> bytes:
    """Top-level PBKDF2-HMAC-SHA512 offload handler.

    Kept in this module (instead of in :mod:`deepview.offload.kdf`) so
    slice 16 does not touch files owned by slice 12. The
    ``callable_ref`` machinery imports us as
    ``deepview.storage.containers.veracrypt:pbkdf2_sha512``.
    """
    import hashlib

    if not isinstance(payload, dict):
        raise TypeError("payload must be a mapping")
    password_raw = payload["password"]
    if isinstance(password_raw, str):
        password: bytes = password_raw.encode("utf-8")
    elif isinstance(password_raw, (bytes, bytearray)):
        password = bytes(password_raw)
    else:
        raise TypeError("password must be str or bytes")
    salt_raw = payload["salt"]
    if isinstance(salt_raw, str):
        salt: bytes = salt_raw.encode("utf-8")
    elif isinstance(salt_raw, (bytes, bytearray)):
        salt = bytes(salt_raw)
    else:
        raise TypeError("salt must be str or bytes")
    iterations = int(payload["iterations"])
    dklen = int(payload["dklen"])
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if dklen <= 0:
        raise ValueError("dklen must be positive")
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen)


__all__ = [
    "VeraCryptUnlocker",
    "TrueCryptUnlocker",
    "UNLOCKER",
    "pbkdf2_sha512",
]
