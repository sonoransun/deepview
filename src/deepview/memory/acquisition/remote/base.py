"""Base types for remote memory acquisition providers.

This module defines the minimal shared surface for every remote provider:

- :class:`RemoteEndpoint` is a frozen dataclass describing *where* and *how*
  to reach a remote host. Credentials are never stored inline — only
  environment-variable names or file paths are kept, so secrets never leak
  into the process's attribute tree.
- :class:`RemoteAcquisitionProvider` extends
  :class:`~deepview.interfaces.acquisition.MemoryAcquisitionProvider` with an
  ``endpoint`` instance attribute, a progress-publishing helper that feeds
  :class:`RemoteAcquisitionProgressEvent` into the analysis context's
  :class:`~deepview.core.events.EventBus`, and a ``transport_name`` hook used
  by the CLI factory.
- :class:`AuthorizationError` is the exception surface the CLI raises when
  the operator has not supplied the ``--confirm`` and
  ``--authorization-statement`` flags required by every dual-use remote
  command.
"""
from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Mapping

from deepview.core.events import RemoteAcquisitionProgressEvent
from deepview.interfaces.acquisition import MemoryAcquisitionProvider

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext


RemoteTransport = Literal["ssh", "tcp", "udp", "ipmi", "amt", "dma", "grpc"]


@dataclass(frozen=True)
class RemoteEndpoint:
    """Description of a remote host + transport, including auth indirection.

    Credentials are intentionally *not* stored inline. ``password_env`` is the
    name of an environment variable the provider should consult at run time;
    ``identity_file`` / ``known_hosts`` / ``tls_ca`` are filesystem paths the
    provider reads when it needs them. That keeps secrets out of the
    dataclass' repr and out of any downstream serialization.
    """

    host: str
    transport: RemoteTransport
    port: int | None = None
    username: str | None = None
    identity_file: Path | None = None
    password_env: str | None = None
    known_hosts: Path | None = None
    tls_ca: Path | None = None
    require_tls: bool = True
    extra: Mapping[str, str] = field(default_factory=dict)


class AuthorizationError(RuntimeError):
    """Raised when a remote acquisition lacks operator-attested authorization.

    The CLI uses this to signal that ``--confirm`` and/or
    ``--authorization-statement`` were not supplied or were empty.
    """


class RemoteAcquisitionProvider(MemoryAcquisitionProvider):
    """Abstract base for all providers that acquire memory over a network.

    Concrete subclasses implement :meth:`transport_name` and the usual
    :class:`MemoryAcquisitionProvider` contract. They should publish
    progress via :meth:`_emit_progress` so the CLI / dashboard can render
    a live counter without coupling to the transport internals.
    """

    def __init__(
        self,
        endpoint: RemoteEndpoint,
        *,
        context: AnalysisContext,
    ) -> None:
        self.endpoint = endpoint
        self._context = context

    @abstractmethod
    def transport_name(self) -> str:
        """Short identifier for this transport (matches ``RemoteEndpoint.transport``)."""

    def _emit_progress(self, bytes_done: int, bytes_total: int, stage: str) -> None:
        """Publish a :class:`RemoteAcquisitionProgressEvent` on the context bus."""
        self._context.events.publish(
            RemoteAcquisitionProgressEvent(
                endpoint=self.endpoint.host,
                bytes_done=bytes_done,
                bytes_total=bytes_total,
                stage=stage,
            )
        )
