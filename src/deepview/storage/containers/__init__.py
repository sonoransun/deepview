"""Encrypted-container unlockers and the :class:`DecryptedVolumeLayer`.

Public names are re-exported on demand via submodule imports rather than
eagerly, so importing this package does not pull in the optional
``cryptography`` / ``argon2-cffi`` extras.
"""
from __future__ import annotations

__all__: list[str] = []
