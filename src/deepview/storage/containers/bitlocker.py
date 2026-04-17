"""BitLocker volume unlocker adapter (libbde / ``pybde`` backend).

The :class:`BitLockerUnlocker` wraps the ``libbde-python`` (``pybde``)
package when available. ``pybde`` is a *library shim* — this module
does **not** reimplement BitLocker's crypto; it delegates every
operation to libbde and exposes the resulting plaintext stream as a
:class:`~deepview.interfaces.layer.DataLayer` so the rest of Deep View
(filesystems, carvers, key-scanners, nested unlockers) can consume it
uniformly.

``pybde`` is imported *lazily* inside every method body that needs it.
A core install without the ``containers`` extra can still ``import``
this module; only ``detect`` / ``unlock`` will raise a clear
``RuntimeError`` if the library is missing.

BitLocker detection
-------------------
BitLocker (Vista+) volumes begin with a standard NTFS / FAT BIOS
Parameter Block whose OEM ID is ``"-FVE-FS-"`` at byte offset 3 of
sector 0 (BPB.OEMID). Legacy Vista uses the same pattern. We treat
the presence of that signature as a positive detection. ``to-go`` /
``Windows Recovery Environment`` variants use ``"MSWIN4.1"`` with a
different FVE signature inside the FVE metadata block; we intentionally
do NOT try to cover those exotic cases without a real fixture.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner
    from deepview.storage.containers.unlock import ContainerHeader, KeySource


# BitLocker Vista+ signature at BPB.OEMID (offset 3, length 8).
_BITLOCKER_SIGNATURE = b"-FVE-FS-"
_BITLOCKER_OEMID_OFFSET = 3
_BITLOCKER_SIGNATURE_LEN = 8


class BitLockerDecryptedLayer(DataLayer):
    """A :class:`DataLayer` that reads plaintext from a ``pybde`` volume.

    ``pybde`` exposes the unlocked volume as a seekable byte stream via
    ``read_buffer_at_offset`` / ``read_buffer`` / ``seek_offset`` /
    ``get_size``. We wrap that stream behind the :class:`DataLayer`
    contract so carvers, filesystems, and nested unlockers consume the
    decrypted bytes uniformly.
    """

    def __init__(self, volume: object, *, name: str = "bitlocker-decrypted") -> None:
        self._volume = volume
        self._name = name
        try:
            self._size = int(self._volume.get_size())  # type: ignore[attr-defined]
        except Exception:
            self._size = 0

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        if offset < 0:
            if pad:
                head = b"\x00" * min(-offset, length)
                rest = length - len(head)
                if rest <= 0:
                    return head
                return head + self.read(0, rest, pad=pad)
            raise ValueError(f"negative offset: {offset}")
        end = offset + length
        if end > self._size:
            if pad:
                take = max(0, self._size - offset)
                data = self._do_read(offset, take) if take > 0 else b""
                return data + b"\x00" * (length - len(data))
            raise ValueError(
                f"read out of bounds: offset={offset} length={length} size={self._size}"
            )
        return self._do_read(offset, length)

    def _do_read(self, offset: int, length: int) -> bytes:
        vol = self._volume
        try:
            # pybde exposes read_buffer_at_offset(size, offset).
            return bytes(vol.read_buffer_at_offset(length, offset))  # type: ignore[attr-defined]
        except AttributeError:
            vol.seek_offset(offset, 0)  # type: ignore[attr-defined]
            return bytes(vol.read_buffer(length))  # type: ignore[attr-defined]

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("BitLockerDecryptedLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and length >= 0 and offset + length <= self._size

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        remaining = self._size
        pos = 0
        chunk = 64 * 1024
        while remaining > 0:
            take = min(chunk, remaining)
            data = self.read(pos, take)
            for result in scanner.scan(data, offset=pos):
                yield result
            pos += take
            remaining -= take
            if progress_callback and self._size > 0:
                progress_callback(pos / self._size)

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        if self._size == 0:
            return 0
        return self._size - 1

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )


class BitLockerUnlocker:
    """Concrete :class:`Unlocker` for BitLocker volumes (Vista+).

    The class body deliberately does not import ``pybde`` — the import
    happens inside :meth:`unlock` so a core install still loads this
    module. :meth:`detect` is pure-Python and never touches the
    optional dependency.
    """

    format_name: ClassVar[str] = "bitlocker"

    def __init__(self) -> None:
        # Lazy-import probe: do not fail at construction if pybde is
        # missing — the orchestrator may still want detect() to work.
        try:
            import pybde  # noqa: F401

            self._pybde_available = True
        except Exception:
            self._pybde_available = False

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def detect(
        self, layer: DataLayer, offset: int = 0
    ) -> ContainerHeader | None:
        """Return a :class:`ContainerHeader` if *layer* looks like BitLocker."""
        from deepview.storage.containers.unlock import ContainerHeader

        try:
            head = layer.read(offset, 512, pad=True)
        except Exception:
            return None
        if len(head) < _BITLOCKER_OEMID_OFFSET + _BITLOCKER_SIGNATURE_LEN:
            return None
        sig = head[
            _BITLOCKER_OEMID_OFFSET : _BITLOCKER_OEMID_OFFSET
            + _BITLOCKER_SIGNATURE_LEN
        ]
        if sig != _BITLOCKER_SIGNATURE:
            return None
        try:
            raw = layer.read(offset, 4096, pad=True)
        except Exception:
            raw = head
        try:
            size = int(layer.maximum_address) + 1
        except Exception:
            size = 0
        return ContainerHeader(
            format="bitlocker",
            cipher="aes-xts",
            sector_size=512,
            data_offset=0,
            data_length=max(0, size - offset),
            kdf="pbkdf2_sha256",
            kdf_params={"iterations": 4096},
            raw=raw,
        )

    # ------------------------------------------------------------------
    # Unlock
    # ------------------------------------------------------------------

    async def unlock(
        self,
        layer: DataLayer,
        header: ContainerHeader,
        source: KeySource,
        *,
        try_hidden: bool = False,
    ) -> DataLayer:
        """Open *layer* via ``pybde`` and return a :class:`DataLayer`."""
        try:
            import pybde
        except ImportError as e:
            raise RuntimeError(
                "pybde required for BitLocker unlock; install via "
                "`pip install libbde-python`"
            ) from e

        from deepview.storage.containers._layer_file_io import LayerFileIO
        from deepview.storage.containers.unlock import (
            Keyfile,
            MasterKey,
            Passphrase,
        )

        file_io = LayerFileIO(layer)
        volume = pybde.volume()  # type: ignore[attr-defined]

        if isinstance(source, Passphrase):
            # BitLocker distinguishes recovery passwords (48-digit
            # numeric groups) from regular user passwords. Try recovery
            # first if the string looks like a recovery token.
            pw = source.passphrase
            if _looks_like_recovery_password(pw):
                try:
                    volume.set_recovery_password(pw)  # type: ignore[attr-defined]
                except Exception:
                    volume.set_password(pw)  # type: ignore[attr-defined]
            else:
                try:
                    volume.set_password(pw)  # type: ignore[attr-defined]
                except Exception:
                    volume.set_recovery_password(pw)  # type: ignore[attr-defined]
        elif isinstance(source, MasterKey):
            # FVEK (Full Volume Encryption Key) extracted from memory.
            volume.set_full_volume_encryption_key(source.key)  # type: ignore[attr-defined]
        elif isinstance(source, Keyfile):
            # BitLocker Startup Key (.BEK) is a file, not hashed bytes —
            # pybde takes the path directly.
            volume.set_startup_key(str(Path(source.path)))  # type: ignore[attr-defined]
        else:
            raise RuntimeError(
                f"unsupported key source for BitLocker: {type(source).__name__}"
            )

        try:
            volume.open_file_object(file_io)  # type: ignore[attr-defined]
        except Exception as e:
            raise RuntimeError(f"BitLocker open failed: {e}") from e

        return BitLockerDecryptedLayer(volume, name="bitlocker-decrypted")


def _looks_like_recovery_password(pw: str) -> bool:
    """Heuristic: BitLocker recovery passwords are 8x6-digit groups.

    Example: ``123456-234567-345678-456789-567890-678901-789012-890123``.
    """
    parts = pw.strip().split("-")
    if len(parts) != 8:
        return False
    return all(p.isdigit() and len(p) == 6 for p in parts)


# Module-level hook consumed by :class:`UnlockOrchestrator`.
UNLOCKER = BitLockerUnlocker


__all__ = [
    "BitLockerUnlocker",
    "BitLockerDecryptedLayer",
    "UNLOCKER",
]
