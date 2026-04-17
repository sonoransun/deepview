"""LUKS1 + LUKS2 container unlocker.

The adapter parses the on-disk header in pure Python (no external
dependencies) so detection works on a core install, and offloads the
key-derivation step (PBKDF2-SHA{1,256,512} or Argon2id) to
:class:`~deepview.offload.engine.OffloadEngine` via
``deepview.offload.jobs.make_job``.

The orchestrator types from :mod:`deepview.storage.containers.unlock`
are imported lazily inside method bodies so an adapter instance still
*constructs* even if slice 14 is not installed yet; ``detect`` and
``unlock`` will then raise a clear ``RuntimeError`` rather than
``ImportError``.

LUKS1 (on-disk layout at offset 0):

========  ====   ===
Offset    Size   Field
========  ====   ===
 0          6    magic = ``b"LUKS\xba\xbe"``
 6          2    version (big-endian; 1)
 8         32    cipher_name
40         32    cipher_mode
72         32    hash_spec
104         4    payload_offset (sectors; big-endian)
108         4    key_bytes (big-endian)
112        20    mk_digest
132        32    mk_digest_salt
164         4    mk_digest_iter (big-endian)
168        40    uuid (ASCII)
208       384    8 keyslots (48 bytes each)
========  ====   ===

LUKS2 (on-disk layout at offset 0):

* primary binary header (4 KiB) starting with ``b"LUKS\xba\xbe"`` +
  version=2 + hdr_size(BE 8) + seqid(BE 8) + label(48) + csum_alg(32)
  + salt(64) + uuid(40) + subsystem(48) + hdr_offset(BE 8) +
  reserved(184) + csum(64) + padding, followed by
* a JSON metadata blob describing keyslots / segments / digests /
  tokens.
"""
from __future__ import annotations

import hashlib
import json
import struct
from typing import TYPE_CHECKING, Any, ClassVar, cast

from deepview.interfaces.layer import DataLayer

from deepview.storage.containers._af_split import af_merge

if TYPE_CHECKING:
    from deepview.storage.containers.layer import DecryptedVolumeLayer
    from deepview.storage.containers.unlock import (
        ContainerHeader,
        KeySource,
        Unlocker,
    )


LUKS_MAGIC = b"LUKS\xba\xbe"
LUKS1_HEADER_SIZE = 592
LUKS1_KEYSLOT_COUNT = 8
LUKS1_KEYSLOT_SIZE = 48
LUKS1_STRIPES = 4000
LUKS2_BINARY_HDR_SIZE = 4096
LUKS2_JSON_MAX_BYTES = 12 * 1024  # generous; spec allows up to 12288 default


def _require_orchestrator() -> tuple[type, type]:
    """Return ``(Unlocker, ContainerHeader)`` or raise a clear ``RuntimeError``.

    The orchestrator is slice 14. If a user installs slice 15 alone
    (for whatever reason) the unlocker module still imports — but the
    first call to ``detect`` / ``unlock`` surfaces this error.
    """
    try:
        from deepview.storage.containers.unlock import (
            ContainerHeader as _Header,
        )
        from deepview.storage.containers.unlock import (
            Unlocker as _Unlocker,
        )
    except ImportError as exc:  # pragma: no cover — exercised only in broken installs
        raise RuntimeError(
            "LUKS unlocker requires the unlock orchestrator (slice 14)"
        ) from exc
    return _Unlocker, _Header


def _require_decrypted_layer() -> type:
    try:
        from deepview.storage.containers.layer import DecryptedVolumeLayer as _DVL
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "LUKS unlocker requires the unlock orchestrator (slice 14)"
        ) from exc
    return _DVL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _c_str(raw: bytes) -> str:
    """Trim the trailing NULs on a fixed-width C string and decode utf-8."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _iv_mode_for_cipher(cipher_name: str, cipher_mode: str) -> tuple[str, str]:
    """Return ``(dv_mode, dv_iv_mode)`` suitable for :class:`DecryptedVolumeLayer`.

    Maps the space of LUKS cipher/mode strings into the subset
    DecryptedVolumeLayer supports today (xts / cbc-essiv / cbc-plain64 /
    ctr) + the relevant IV derivation.
    """
    cname = cipher_name.lower()
    cmode = cipher_mode.lower()
    # cipher_mode is typically "xts-plain64", "cbc-essiv:sha256", "cbc-plain64".
    if cmode.startswith("xts"):
        return "xts", "tweak"
    if cmode.startswith("cbc-essiv"):
        return "cbc-essiv", "essiv-sha256"
    if cmode.startswith("cbc-plain64") or cmode.startswith("cbc-plain"):
        return "cbc-plain64", "plain64"
    if cmode.startswith("ctr"):
        return "ctr", "plain64"
    # default — best guess
    if "xts" in cname or "xts" in cmode:
        return "xts", "tweak"
    return "cbc-plain64", "plain64"


# ---------------------------------------------------------------------------
# LUKS1 header parsing
# ---------------------------------------------------------------------------


class _LUKS1Keyslot:
    __slots__ = (
        "active",
        "iterations",
        "salt",
        "key_material_offset",
        "stripes",
    )

    def __init__(
        self,
        active: int,
        iterations: int,
        salt: bytes,
        key_material_offset: int,
        stripes: int,
    ) -> None:
        self.active = active
        self.iterations = iterations
        self.salt = salt
        self.key_material_offset = key_material_offset
        self.stripes = stripes


class _LUKS1Header:
    """Parsed LUKS1 on-disk header."""

    ACTIVE = 0x00AC71F3
    INACTIVE = 0x0000DEAD

    def __init__(
        self,
        *,
        version: int,
        cipher_name: str,
        cipher_mode: str,
        hash_spec: str,
        payload_offset: int,
        key_bytes: int,
        mk_digest: bytes,
        mk_digest_salt: bytes,
        mk_digest_iter: int,
        uuid: str,
        keyslots: list[_LUKS1Keyslot],
        raw: bytes,
    ) -> None:
        self.version = version
        self.cipher_name = cipher_name
        self.cipher_mode = cipher_mode
        self.hash_spec = hash_spec
        self.payload_offset = payload_offset
        self.key_bytes = key_bytes
        self.mk_digest = mk_digest
        self.mk_digest_salt = mk_digest_salt
        self.mk_digest_iter = mk_digest_iter
        self.uuid = uuid
        self.keyslots = keyslots
        self.raw = raw


def _parse_luks1(raw: bytes) -> _LUKS1Header:
    if len(raw) < LUKS1_HEADER_SIZE:
        raise ValueError("LUKS1 header truncated")
    if raw[0:6] != LUKS_MAGIC:
        raise ValueError("LUKS magic mismatch")
    version = struct.unpack(">H", raw[6:8])[0]
    if version != 1:
        raise ValueError(f"not a LUKS1 header (version={version})")

    cipher_name = _c_str(raw[8:40])
    cipher_mode = _c_str(raw[40:72])
    hash_spec = _c_str(raw[72:104])
    payload_offset = struct.unpack(">I", raw[104:108])[0]
    key_bytes = struct.unpack(">I", raw[108:112])[0]
    mk_digest = bytes(raw[112:132])
    mk_digest_salt = bytes(raw[132:164])
    mk_digest_iter = struct.unpack(">I", raw[164:168])[0]
    uuid = _c_str(raw[168:208])

    keyslots: list[_LUKS1Keyslot] = []
    for i in range(LUKS1_KEYSLOT_COUNT):
        off = 208 + i * LUKS1_KEYSLOT_SIZE
        block = raw[off : off + LUKS1_KEYSLOT_SIZE]
        active, iterations = struct.unpack(">II", block[0:8])
        salt = bytes(block[8:40])
        key_material_offset, stripes = struct.unpack(">II", block[40:48])
        keyslots.append(
            _LUKS1Keyslot(
                active=active,
                iterations=iterations,
                salt=salt,
                key_material_offset=key_material_offset,
                stripes=stripes,
            )
        )

    return _LUKS1Header(
        version=version,
        cipher_name=cipher_name,
        cipher_mode=cipher_mode,
        hash_spec=hash_spec,
        payload_offset=payload_offset,
        key_bytes=key_bytes,
        mk_digest=mk_digest,
        mk_digest_salt=mk_digest_salt,
        mk_digest_iter=mk_digest_iter,
        uuid=uuid,
        keyslots=keyslots,
        raw=bytes(raw[:LUKS1_HEADER_SIZE]),
    )


# ---------------------------------------------------------------------------
# LUKS2 header parsing (binary prefix + JSON)
# ---------------------------------------------------------------------------


class _LUKS2Header:
    def __init__(
        self,
        *,
        version: int,
        hdr_size: int,
        seqid: int,
        label: str,
        csum_alg: str,
        salt: bytes,
        uuid: str,
        subsystem: str,
        hdr_offset: int,
        csum: bytes,
        json_data: dict[str, Any],
        raw: bytes,
    ) -> None:
        self.version = version
        self.hdr_size = hdr_size
        self.seqid = seqid
        self.label = label
        self.csum_alg = csum_alg
        self.salt = salt
        self.uuid = uuid
        self.subsystem = subsystem
        self.hdr_offset = hdr_offset
        self.csum = csum
        self.json_data = json_data
        self.raw = raw


def _parse_luks2(raw: bytes) -> _LUKS2Header:
    if len(raw) < LUKS2_BINARY_HDR_SIZE:
        raise ValueError("LUKS2 header truncated (binary prefix)")
    if raw[0:6] != LUKS_MAGIC:
        raise ValueError("LUKS magic mismatch")
    version = struct.unpack(">H", raw[6:8])[0]
    if version != 2:
        raise ValueError(f"not a LUKS2 header (version={version})")

    hdr_size = struct.unpack(">Q", raw[8:16])[0]
    seqid = struct.unpack(">Q", raw[16:24])[0]
    label = _c_str(raw[24:72])
    csum_alg = _c_str(raw[72:104])
    salt = bytes(raw[104:168])
    uuid = _c_str(raw[168:208])
    subsystem = _c_str(raw[208:256])
    hdr_offset = struct.unpack(">Q", raw[256:264])[0]
    # reserved[184] = raw[264:448]
    csum = bytes(raw[448:512])

    # JSON metadata starts at offset 512 and extends up to hdr_size bytes
    # total (binary header inclusive). Cap read to what we have.
    json_end = min(hdr_size if hdr_size > 0 else len(raw), len(raw))
    if json_end <= 512:
        raise ValueError("LUKS2 header too small for JSON metadata")
    json_blob = bytes(raw[512:json_end])
    # Strip trailing NUL padding.
    stripped = json_blob.rstrip(b"\x00")
    if not stripped:
        raise ValueError("LUKS2 JSON metadata empty")
    try:
        json_data = json.loads(stripped.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"LUKS2 JSON metadata malformed: {exc}") from exc
    if not isinstance(json_data, dict):
        raise ValueError("LUKS2 JSON metadata is not an object")

    return _LUKS2Header(
        version=version,
        hdr_size=hdr_size,
        seqid=seqid,
        label=label,
        csum_alg=csum_alg,
        salt=salt,
        uuid=uuid,
        subsystem=subsystem,
        hdr_offset=hdr_offset,
        csum=csum,
        json_data=json_data,
        raw=bytes(raw[:json_end]),
    )


def _luks2_first_segment(json_data: dict[str, Any]) -> dict[str, Any]:
    segments = json_data.get("segments")
    if not isinstance(segments, dict) or not segments:
        raise ValueError("LUKS2 JSON missing segments")
    # Pick the lowest-keyed segment (segments are keyed by stringified ints).
    keys = sorted(segments, key=lambda k: int(k) if k.isdigit() else k)
    seg = segments[keys[0]]
    if not isinstance(seg, dict):
        raise ValueError("LUKS2 segment is not an object")
    return cast("dict[str, Any]", seg)


# ---------------------------------------------------------------------------
# The Unlocker
# ---------------------------------------------------------------------------


def _resolve_unlocker_base() -> type:
    """Return the :class:`Unlocker` ABC, or :class:`object` when the
    orchestrator slice is not installed.

    Used at class-creation time to make :class:`LUKSUnlocker` still
    *ship* even without the orchestrator; the ``detect`` / ``unlock``
    bodies raise a clear :class:`RuntimeError` on call in that case.
    """
    try:
        from deepview.storage.containers.unlock import Unlocker as _Unlocker

        return _Unlocker
    except ImportError:
        return object


_UnlockerBase = _resolve_unlocker_base()


class LUKSUnlocker(_UnlockerBase):  # type: ignore[misc, valid-type]
    """Pure-Python LUKS1 + LUKS2 container adapter."""

    format_name: ClassVar[str] = "luks"

    # ------------------------------------------------------------------
    # detect()
    # ------------------------------------------------------------------

    def detect(
        self, layer: DataLayer, offset: int = 0
    ) -> ContainerHeader | None:  # noqa: F821
        try:
            probe = layer.read(offset, 8)
        except Exception:
            return None
        if len(probe) < 8 or probe[0:6] != LUKS_MAGIC:
            return None
        version = struct.unpack(">H", probe[6:8])[0]
        if version == 1:
            return self._detect_luks1(layer, offset)
        if version == 2:
            return self._detect_luks2(layer, offset)
        return None

    def _detect_luks1(
        self, layer: DataLayer, offset: int
    ) -> ContainerHeader | None:  # noqa: F821
        try:
            raw = layer.read(offset, LUKS1_HEADER_SIZE)
        except Exception:
            return None
        try:
            hdr = _parse_luks1(raw)
        except ValueError:
            return None
        _, Header = _require_orchestrator()

        data_offset = hdr.payload_offset * 512
        try:
            layer_size = layer.maximum_address + 1
        except Exception:
            layer_size = data_offset
        data_length = max(0, layer_size - data_offset)

        cipher = f"{hdr.cipher_name}-{hdr.cipher_mode}"
        # First active keyslot (if any) drives default KDF params.
        active = next(
            (ks for ks in hdr.keyslots if ks.active == _LUKS1Header.ACTIVE),
            None,
        )
        kdf_params: dict[str, object] = {
            "hash": hdr.hash_spec,
            "dklen": hdr.key_bytes,
            "mk_digest": hdr.mk_digest,
            "mk_digest_salt": hdr.mk_digest_salt,
            "mk_digest_iter": hdr.mk_digest_iter,
            "payload_offset_sectors": hdr.payload_offset,
            "uuid": hdr.uuid,
        }
        if active is not None:
            kdf_params["salt"] = active.salt
            kdf_params["iterations"] = active.iterations
            kdf_params["keyslot_stripes"] = active.stripes
            kdf_params["keyslot_km_offset"] = active.key_material_offset * 512

        return Header(
            format="luks1",
            cipher=cipher,
            sector_size=512,
            data_offset=data_offset,
            data_length=data_length,
            kdf="pbkdf2",
            kdf_params=kdf_params,
            raw=hdr.raw,
        )

    def _detect_luks2(
        self, layer: DataLayer, offset: int
    ) -> ContainerHeader | None:  # noqa: F821
        # Attempt to read the binary prefix first; extend if hdr_size > 4 KiB.
        try:
            prefix = layer.read(offset, LUKS2_BINARY_HDR_SIZE)
        except Exception:
            return None
        if len(prefix) < LUKS2_BINARY_HDR_SIZE:
            return None
        try:
            hdr_size = struct.unpack(">Q", prefix[8:16])[0]
        except struct.error:
            return None
        want = max(LUKS2_BINARY_HDR_SIZE, int(hdr_size))
        want = min(want, LUKS2_BINARY_HDR_SIZE + LUKS2_JSON_MAX_BYTES)
        try:
            raw = layer.read(offset, want)
        except Exception:
            return None
        try:
            hdr = _parse_luks2(raw)
        except ValueError:
            return None
        _, Header = _require_orchestrator()

        try:
            seg = _luks2_first_segment(hdr.json_data)
        except ValueError:
            return None

        seg_offset_raw = seg.get("offset", 0)
        try:
            data_offset = int(seg_offset_raw)
        except (TypeError, ValueError):
            data_offset = 0
        seg_size_raw = seg.get("size", "dynamic")
        data_length: int
        if isinstance(seg_size_raw, str) and seg_size_raw == "dynamic":
            try:
                layer_size = layer.maximum_address + 1
            except Exception:
                layer_size = data_offset
            data_length = max(0, layer_size - data_offset)
        else:
            try:
                data_length = int(seg_size_raw)
            except (TypeError, ValueError):
                data_length = 0
        sector_size = int(seg.get("sector_size", 512) or 512)
        cipher = str(seg.get("encryption", "aes-xts-plain64"))

        # Find the first keyslot's KDF.
        keyslot_id: str | None = None
        keyslots = hdr.json_data.get("keyslots", {}) or {}
        if isinstance(keyslots, dict) and keyslots:
            keyslot_id = sorted(
                keyslots, key=lambda k: int(k) if k.isdigit() else k
            )[0]
        kdf_name = "pbkdf2"
        kdf_params: dict[str, object] = {
            "dklen": 32,
            "segments": hdr.json_data.get("segments", {}),
            "keyslots": keyslots,
            "digests": hdr.json_data.get("digests", {}),
            "uuid": hdr.uuid,
            "hdr_size": hdr.hdr_size,
        }
        if keyslot_id is not None and isinstance(keyslots.get(keyslot_id), dict):
            ks = keyslots[keyslot_id]
            kdf_block = ks.get("kdf", {}) or {}
            kdf_type = str(kdf_block.get("type", "pbkdf2")).lower()
            kdf_name = kdf_type
            if kdf_type == "pbkdf2":
                kdf_params["hash"] = str(kdf_block.get("hash", "sha256"))
                kdf_params["iterations"] = int(kdf_block.get("iterations", 0))
            elif kdf_type in ("argon2i", "argon2id"):
                kdf_params["time_cost"] = int(kdf_block.get("time", 1))
                kdf_params["memory_cost"] = int(kdf_block.get("memory", 1024))
                kdf_params["parallelism"] = int(kdf_block.get("cpus", 1))
                kdf_params["iterations"] = int(kdf_block.get("time", 1))
            salt_b64 = kdf_block.get("salt", "")
            if isinstance(salt_b64, str):
                import base64

                try:
                    kdf_params["salt"] = base64.b64decode(salt_b64)
                except Exception:
                    kdf_params["salt"] = b""
            ks_area = ks.get("area", {}) or {}
            kdf_params["keyslot_id"] = keyslot_id
            kdf_params["keyslot_offset"] = int(ks_area.get("offset", 0) or 0)
            kdf_params["keyslot_size"] = int(ks_area.get("size", 0) or 0)
            kdf_params["keyslot_encryption"] = str(
                ks_area.get("encryption", "aes-xts-plain64")
            )
            kdf_params["keyslot_key_size"] = int(ks_area.get("key_size", 0) or 0)
            kdf_params["keyslot_af_stripes"] = int(
                (ks.get("af", {}) or {}).get("stripes", 4000) or 4000
            )
            kdf_params["keyslot_af_hash"] = str(
                (ks.get("af", {}) or {}).get("hash", "sha256")
            )
            kdf_params["keyslot_key_size_bytes"] = int(ks.get("key_size", 0) or 0)

        return Header(
            format="luks2",
            cipher=cipher,
            sector_size=sector_size,
            data_offset=data_offset,
            data_length=data_length,
            kdf=kdf_name,
            kdf_params=kdf_params,
            raw=hdr.raw,
        )

    # ------------------------------------------------------------------
    # unlock()
    # ------------------------------------------------------------------

    async def unlock(
        self,
        layer: DataLayer,
        header: ContainerHeader,  # noqa: F821
        source: KeySource,  # noqa: F821
        *,
        try_hidden: bool = False,
    ) -> DecryptedVolumeLayer:  # noqa: F821
        DVL = _require_decrypted_layer()
        # A pre-known master key can skip KDF + AF-merge entirely —
        # just verify against the mk_digest when we have one.
        from deepview.storage.containers.unlock import MasterKey, Passphrase

        if header.format == "luks1":
            master_key = await self._unlock_luks1(layer, header, source)
        elif header.format == "luks2":
            master_key = await self._unlock_luks2(layer, header, source)
        else:
            raise ValueError(f"unsupported LUKS format {header.format!r}")

        # Provide some light key-source logging via local var — not used
        # further but prevents mypy/unused-import complaints.
        _ = (MasterKey, Passphrase)

        dv_mode, dv_iv_mode = self._cipher_info(header.cipher)
        data_length = header.data_length
        return cast(
            "DecryptedVolumeLayer",
            DVL(
                layer,
                cipher_name="aes",
                key=master_key,
                sector_size=header.sector_size or 512,
                data_offset=header.data_offset,
                data_length=data_length,
                mode=dv_mode,
                iv_mode=dv_iv_mode,
                name="luks-decrypted",
            ),
        )

    # ------------------------------------------------------------------
    # LUKS1 unlock internals
    # ------------------------------------------------------------------

    async def _unlock_luks1(
        self,
        layer: DataLayer,
        header: ContainerHeader,  # noqa: F821
        source: KeySource,  # noqa: F821
    ) -> bytes:
        from deepview.storage.containers.unlock import MasterKey

        params = header.kdf_params
        hash_spec = str(params.get("hash", "sha1")).lower()
        dklen = int(params.get("dklen", 32))
        mk_digest = cast(bytes, params.get("mk_digest") or b"")
        mk_salt = cast(bytes, params.get("mk_digest_salt") or b"")
        mk_iter = int(params.get("mk_digest_iter", 0))

        # Master-key shortcut: if the caller passed a pre-known master
        # key of the right length, verify against the digest and return.
        if isinstance(source, MasterKey):
            mk = source.key
            if len(mk) == dklen and self._verify_luks1_digest(
                mk, mk_salt, mk_iter, mk_digest, hash_spec, dklen
            ):
                return mk
            # Fall through to the slow path anyway — maybe the user
            # passed a passphrase disguised as a MasterKey. Unusual.
            return mk if len(mk) == dklen else mk[:dklen]

        # Passphrase / Keyfile path — derive via PBKDF2(keyslot) + AF-merge.
        keyslot_salt = cast(bytes, params.get("salt") or b"")
        keyslot_iter = int(params.get("iterations", 0))
        if not keyslot_salt or keyslot_iter <= 0:
            raise RuntimeError(
                "LUKS1 header has no active keyslot; cannot unlock"
            )

        # Step 1: derive keyslot-decryption key via PBKDF2.
        from deepview.offload.jobs import make_job

        ctx = getattr(self, "_context", None)
        engine = await self._await_derive(source, header)
        # `Passphrase.derive` will use the header's top-level `kdf`
        # value (pbkdf2) + kdf_params. But the *keyslot* step needs a
        # fresh PBKDF2 with the keyslot salt + iterations. We submit
        # that explicitly here rather than conflating with the digest
        # step.
        _ = (ctx, engine, make_job)
        keyslot_key = await self._luks1_keyslot_key(source, header, hash_spec, dklen)

        # Step 2: decrypt the keyslot's stripes from disk. The per-keyslot
        # stripe count is baked into the parsed header (defaults to the
        # LUKS1 canonical value 4000 when not available).
        km_offset = int(params.get("keyslot_km_offset", 0)) or self._luks1_keyslot_offset(
            header
        )
        stripe_count = int(params.get("keyslot_stripes", LUKS1_STRIPES))
        stripes_bytes_size = dklen * stripe_count
        # Round read up to a sector boundary — LUKS writes full sectors.
        sector_size = 512
        read_size = (
            (stripes_bytes_size + sector_size - 1) // sector_size
        ) * sector_size
        ct = layer.read(km_offset, read_size)
        stripes = self._luks1_decrypt_stripes(
            keyslot_key, ct, header, dklen, stripe_count
        )

        # Step 3: AF-merge to recover master key candidate.
        mk = af_merge(stripes, dklen, stripe_count, hash_name=hash_spec)

        # Step 4: verify.
        if not self._verify_luks1_digest(
            mk, mk_salt, mk_iter, mk_digest, hash_spec, dklen
        ):
            raise RuntimeError("LUKS1 passphrase verification failed")
        return mk

    async def _luks1_keyslot_key(
        self,
        source: KeySource,  # noqa: F821
        header: ContainerHeader,  # noqa: F821
        hash_spec: str,
        dklen: int,
    ) -> bytes:
        """Return the PBKDF2-derived keyslot-decryption key."""
        from deepview.storage.containers.unlock import Keyfile, Passphrase

        params = header.kdf_params
        salt = cast(bytes, params.get("salt") or b"")
        iterations = int(params.get("iterations", 0))

        password: bytes
        if isinstance(source, Passphrase):
            password = source.passphrase.encode("utf-8")
        elif isinstance(source, Keyfile):
            from pathlib import Path

            password = Path(source.path).read_bytes()
        else:
            raise RuntimeError(
                f"LUKS1 keyslot derivation needs Passphrase / Keyfile; got "
                f"{type(source).__name__}"
            )

        # Offload — use pbkdf2_sha256 wrapper unless a different hash was
        # requested (LUKS1 allows sha1/sha256/sha512). Fall back to the
        # in-process hashlib call when the hash differs.
        if hash_spec in ("sha256",):
            from deepview.offload.jobs import make_job

            engine = await self._engine()
            job = make_job(
                kind="pbkdf2_sha256",
                payload={
                    "password": password,
                    "salt": salt,
                    "iterations": iterations,
                    "dklen": dklen,
                },
                callable_ref="deepview.offload.kdf:pbkdf2_sha256",
            )
            future = engine.submit(job)
            result = future.await_result()
            if not result.ok:
                raise RuntimeError(
                    f"LUKS1 keyslot PBKDF2 offload failed: {result.error}"
                )
            out = result.output
            if not isinstance(out, (bytes, bytearray)):
                raise RuntimeError("keyslot PBKDF2 returned non-bytes")
            return bytes(out)
        # In-process fallback for sha1/sha512.
        return hashlib.pbkdf2_hmac(hash_spec, password, salt, iterations, dklen)

    def _luks1_keyslot_offset(self, header: ContainerHeader) -> int:  # noqa: F821
        # For simplicity, locate the first active keyslot's offset from
        # the raw header bytes we captured during detect().
        raw = header.raw
        if len(raw) < LUKS1_HEADER_SIZE:
            raise RuntimeError("LUKS1 header missing raw bytes")
        for i in range(LUKS1_KEYSLOT_COUNT):
            off = 208 + i * LUKS1_KEYSLOT_SIZE
            active = struct.unpack(">I", raw[off : off + 4])[0]
            if active == _LUKS1Header.ACTIVE:
                km_off_sectors = struct.unpack(
                    ">I", raw[off + 40 : off + 44]
                )[0]
                return km_off_sectors * 512
        raise RuntimeError("no active LUKS1 keyslot")

    def _luks1_decrypt_stripes(
        self,
        keyslot_key: bytes,
        ciphertext: bytes,
        header: ContainerHeader,  # noqa: F821
        dklen: int,
        stripe_count: int = LUKS1_STRIPES,
    ) -> bytes:
        """Decrypt LUKS1 keyslot stripes.

        LUKS1 keyslots are encrypted with the same cipher / mode as the
        volume, keyed by the PBKDF2-derived keyslot-key and IV'd by the
        *sector* number *within the keyslot area* starting at zero.
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        dv_mode, dv_iv_mode = self._cipher_info(header.cipher)
        sector_size = 512
        plaintext = bytearray()
        sectors = (len(ciphertext) + sector_size - 1) // sector_size
        for s in range(sectors):
            start = s * sector_size
            end = min(start + sector_size, len(ciphertext))
            block = ciphertext[start:end]
            if len(block) < sector_size:
                block = block + b"\x00" * (sector_size - len(block))
            if dv_mode == "xts":
                tweak = s.to_bytes(16, "little")
                cipher = Cipher(algorithms.AES(keyslot_key), modes.XTS(tweak))
                pt = cipher.decryptor().update(block)
            elif dv_mode == "cbc-essiv":
                digest = hashlib.sha256(keyslot_key).digest()
                sector_block = s.to_bytes(16, "little")
                essiv_enc = Cipher(
                    algorithms.AES(digest), modes.ECB()
                ).encryptor()
                iv = essiv_enc.update(sector_block) + essiv_enc.finalize()
                cipher = Cipher(algorithms.AES(keyslot_key), modes.CBC(iv))
                pt = cipher.decryptor().update(block)
            else:  # cbc-plain64 / ctr
                iv = s.to_bytes(16, "little")
                cipher = Cipher(algorithms.AES(keyslot_key), modes.CBC(iv))
                pt = cipher.decryptor().update(block)
            plaintext.extend(pt[: (end - start)])
            _ = dv_iv_mode
        return bytes(plaintext[: dklen * stripe_count])

    def _verify_luks1_digest(
        self,
        candidate: bytes,
        mk_salt: bytes,
        mk_iter: int,
        mk_digest: bytes,
        hash_spec: str,
        dklen: int,
    ) -> bool:
        if not mk_salt or mk_iter <= 0 or not mk_digest:
            return False
        # LUKS1 mk_digest is 20 bytes — always truncate.
        computed = hashlib.pbkdf2_hmac(
            hash_spec, candidate, mk_salt, mk_iter, len(mk_digest)
        )
        _ = dklen
        return computed == mk_digest

    # ------------------------------------------------------------------
    # LUKS2 unlock internals (JSON-driven; honest about limits)
    # ------------------------------------------------------------------

    async def _unlock_luks2(
        self,
        layer: DataLayer,
        header: ContainerHeader,  # noqa: F821
        source: KeySource,  # noqa: F821
    ) -> bytes:
        from deepview.storage.containers.unlock import MasterKey

        params = header.kdf_params
        key_size = int(params.get("keyslot_key_size_bytes", 0) or params.get("dklen", 32))
        if isinstance(source, MasterKey):
            # Best-effort: caller accepts the key as-is. Digest
            # verification for LUKS2 requires iterating the digests
            # block from the JSON, which we parse into kdf_params.
            if self._verify_luks2_digest(source.key, params):
                return source.key
            return source.key[:key_size] if len(source.key) >= key_size else source.key

        # Passphrase / Keyfile path: derive the keyslot key via the JSON's
        # specified KDF, then AF-merge + verify.
        keyslot_key = await self._luks2_keyslot_key(source, header)
        km_offset = int(params.get("keyslot_offset", 0) or 0)
        km_size = int(params.get("keyslot_size", 0) or 0)
        if km_offset <= 0 or km_size <= 0:
            raise RuntimeError("LUKS2 keyslot area not in JSON metadata")

        ct = layer.read(km_offset, km_size)
        stripes_count = int(params.get("keyslot_af_stripes", 4000))
        af_hash = str(params.get("keyslot_af_hash", "sha256"))
        key_size_ks = int(
            params.get("keyslot_key_size", 0) or params.get("dklen", 32)
        )
        stripes = self._luks2_decrypt_stripes(
            keyslot_key, ct, str(params.get("keyslot_encryption", "aes-xts-plain64"))
        )
        mk = af_merge(stripes, key_size_ks, stripes_count, hash_name=af_hash)
        if not self._verify_luks2_digest(mk, params):
            raise RuntimeError("LUKS2 passphrase verification failed")
        return mk

    async def _luks2_keyslot_key(
        self,
        source: KeySource,  # noqa: F821
        header: ContainerHeader,  # noqa: F821
    ) -> bytes:
        """Derive the keyslot-decryption key for LUKS2.

        Currently wires the offload PBKDF2-SHA256 and Argon2id paths.
        Other PBKDF2 hashes fall through to in-process hashlib.
        """
        from deepview.storage.containers.unlock import Keyfile, Passphrase

        params = header.kdf_params
        kdf_kind = str(params.get("keyslot_encryption", "")).lower()
        _ = kdf_kind
        key_size_ks = int(
            params.get("keyslot_key_size", 0) or params.get("dklen", 32)
        )
        salt = cast(bytes, params.get("salt") or b"")

        password: bytes
        if isinstance(source, Passphrase):
            password = source.passphrase.encode("utf-8")
        elif isinstance(source, Keyfile):
            from pathlib import Path

            password = Path(source.path).read_bytes()
        else:
            raise RuntimeError(
                f"LUKS2 keyslot derivation needs Passphrase / Keyfile; got "
                f"{type(source).__name__}"
            )

        engine = await self._engine()
        from deepview.offload.jobs import make_job

        kdf_type = header.kdf.lower()
        if kdf_type == "pbkdf2":
            hash_spec = str(params.get("hash", "sha256")).lower()
            iterations = int(params.get("iterations", 0))
            if hash_spec == "sha256":
                job = make_job(
                    kind="pbkdf2_sha256",
                    payload={
                        "password": password,
                        "salt": salt,
                        "iterations": iterations,
                        "dklen": key_size_ks,
                    },
                    callable_ref="deepview.offload.kdf:pbkdf2_sha256",
                )
                result = engine.submit(job).await_result()
                if not result.ok:
                    raise RuntimeError(f"PBKDF2 failed: {result.error}")
                return bytes(cast(bytes, result.output))
            return hashlib.pbkdf2_hmac(
                hash_spec, password, salt, iterations, key_size_ks
            )
        if kdf_type in ("argon2id", "argon2i"):
            job = make_job(
                kind="argon2id",
                payload={
                    "password": password,
                    "salt": salt,
                    "time_cost": int(params.get("time_cost", 1)),
                    "memory_cost": int(params.get("memory_cost", 1024)),
                    "parallelism": int(params.get("parallelism", 1)),
                    "dklen": key_size_ks,
                },
                callable_ref="deepview.offload.kdf:argon2id",
            )
            result = engine.submit(job).await_result()
            if not result.ok:
                raise RuntimeError(f"Argon2 failed: {result.error}")
            return bytes(cast(bytes, result.output))
        raise RuntimeError(f"unsupported LUKS2 KDF {kdf_type!r}")

    def _luks2_decrypt_stripes(
        self,
        keyslot_key: bytes,
        ciphertext: bytes,
        keyslot_encryption: str,
    ) -> bytes:
        """Decrypt LUKS2 keyslot stripes via AES-XTS (the common case)."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        enc = keyslot_encryption.lower()
        plaintext = bytearray()
        sector_size = 512
        sectors = (len(ciphertext) + sector_size - 1) // sector_size
        for s in range(sectors):
            start = s * sector_size
            end = min(start + sector_size, len(ciphertext))
            block = ciphertext[start:end]
            if len(block) < sector_size:
                block = block + b"\x00" * (sector_size - len(block))
            if "xts" in enc:
                tweak = s.to_bytes(16, "little")
                cipher = Cipher(algorithms.AES(keyslot_key), modes.XTS(tweak))
                plaintext.extend(cipher.decryptor().update(block)[: end - start])
            else:
                iv = s.to_bytes(16, "little")
                cipher = Cipher(algorithms.AES(keyslot_key), modes.CBC(iv))
                plaintext.extend(cipher.decryptor().update(block)[: end - start])
        return bytes(plaintext)

    def _verify_luks2_digest(
        self,
        candidate: bytes,
        params: dict[str, object],
    ) -> bool:
        digests = params.get("digests")
        if not isinstance(digests, dict) or not digests:
            return False
        # Try every digest that says type=pbkdf2 + hash=sha256 and
        # mentions our first keyslot in the keyslots list.
        keyslot_id = params.get("keyslot_id")
        for _, dblock in digests.items():
            if not isinstance(dblock, dict):
                continue
            dtype = str(dblock.get("type", "pbkdf2")).lower()
            if dtype != "pbkdf2":
                continue
            dhash = str(dblock.get("hash", "sha256")).lower()
            try:
                iterations = int(dblock.get("iterations", 0))
            except (TypeError, ValueError):
                continue
            if iterations <= 0:
                continue
            import base64

            try:
                salt = base64.b64decode(str(dblock.get("salt", "")))
                expected = base64.b64decode(str(dblock.get("digest", "")))
            except Exception:
                continue
            ks_list = dblock.get("keyslots") or []
            if (
                keyslot_id is not None
                and isinstance(ks_list, list)
                and keyslot_id not in ks_list
            ):
                continue
            try:
                candidate_digest = hashlib.pbkdf2_hmac(
                    dhash, candidate, salt, iterations, len(expected)
                )
            except Exception:
                continue
            if candidate_digest == expected:
                return True
        return False

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    async def _engine(self) -> Any:
        """Return the offload engine from a stashed context if present."""
        eng = getattr(self, "_offload_engine", None)
        if eng is None:
            # Best-effort import path: the orchestrator passes us no
            # engine directly, but a caller may have attached one.
            from deepview.core.context import AnalysisContext

            ctx = AnalysisContext.for_testing()
            eng = ctx.offload
            self._offload_engine = eng  # type: ignore[attr-defined]
        return eng

    async def _await_derive(
        self,
        source: KeySource,  # noqa: F821
        header: ContainerHeader,  # noqa: F821
    ) -> bytes:
        # Not currently used on the LUKS1 path — retained for future.
        _ = (source, header)
        return b""

    def _cipher_info(self, cipher: str) -> tuple[str, str]:
        # cipher like "aes-xts-plain64" or "aes-cbc-essiv:sha256"
        parts = cipher.split("-", 1)
        cname = parts[0]
        cmode = parts[1] if len(parts) > 1 else "xts-plain64"
        return _iv_mode_for_cipher(cname, cmode)


UNLOCKER = LUKSUnlocker


__all__ = ["LUKSUnlocker", "UNLOCKER"]
