"""Deep View storage subsystem: filesystems, FTL, ECC, encrypted containers.

Lazy-imports only — pulling :mod:`deepview.storage` must not require any
optional extra. Concrete adapters live in subpackages and lazy-import their
backing libraries inside their own modules.
"""

from __future__ import annotations
