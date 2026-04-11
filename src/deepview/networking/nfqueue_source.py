"""Optional ``netfilterqueue``-backed packet source.

The :class:`NFQueueSource` wraps the PyPI ``netfilterqueue`` binding
behind a small interface so the mangle engine never touches the C
library directly. Import is lazy so unit tests that use the
:class:`FakeSource` can run without the extra installed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from deepview.core.exceptions import BackendNotAvailableError
from deepview.core.logging import get_logger

log = get_logger("networking.nfqueue_source")


class PacketHandle(Protocol):
    """Minimal interface over ``netfilterqueue.Packet`` the engine uses."""

    def get_payload(self) -> bytes: ...
    def accept(self) -> None: ...
    def drop(self) -> None: ...
    def set_payload(self, data: bytes) -> None: ...
    def set_mark(self, mark: int) -> None: ...
    def repeat(self) -> None: ...


class PacketSource(Protocol):
    """Abstract source of packets; used by :class:`MangleEngine`."""

    def run(self, handler: Callable[[PacketHandle], None]) -> None: ...
    def close(self) -> None: ...


@dataclass
class NFQueueSource:
    queue_num: int

    def __post_init__(self) -> None:
        try:
            import netfilterqueue  # type: ignore
        except Exception as e:  # noqa: BLE001
            raise BackendNotAvailableError(
                "netfilterqueue is not installed. Install with "
                "'pip install deepview[linux_monitoring]' or 'pip install netfilterqueue'."
            ) from e
        self._module = netfilterqueue
        self._nfq: Any = None

    def run(self, handler: Callable[[PacketHandle], None]) -> None:
        self._nfq = self._module.NetfilterQueue()
        self._nfq.bind(self.queue_num, handler)
        try:
            self._nfq.run()
        except KeyboardInterrupt:
            pass
        finally:
            self.close()

    def close(self) -> None:
        if self._nfq is not None:
            try:
                self._nfq.unbind()
            except Exception:  # noqa: BLE001
                pass
            self._nfq = None
