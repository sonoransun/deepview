"""Native seam for the macOS Endpoint Security framework.

A real implementation would wrap ``libEndpointSecurity.dylib`` via ``ctypes``
(or PyObjC) and deliver ``es_message_t`` structures through a subscribe
callback. Because Endpoint Security requires the
``com.apple.developer.endpoint-security.client`` entitlement — which a pip-
installed Python interpreter does not have — Deep View splits the transport
from the protocol: :mod:`endpoint_security` decodes dictionaries, and the
helper below produces them from whichever source is available.

Off-macOS every call raises :class:`BackendNotAvailableError`. Unit tests
inject a stub via ``monkeypatch`` to exercise the decoder without needing
ES privileges.
"""
from __future__ import annotations

import sys
from typing import Any, Callable

from deepview.core.exceptions import BackendNotAvailableError

_IS_MACOS = sys.platform == "darwin"


def open_client(
    on_event: Callable[[dict[str, Any]], None],
    subscribe: list[str],
) -> Any:
    """Open a new Endpoint Security client.

    Returns an opaque client handle. Raises ``BackendNotAvailableError`` on
    non-macOS or when the ES entitlement is missing.
    """
    if not _IS_MACOS:
        raise BackendNotAvailableError("Endpoint Security is only available on macOS")
    # Real implementation would:
    #   1. load /usr/lib/libEndpointSecurity.dylib via ctypes
    #   2. call es_new_client with a block that marshals es_message_t into a dict
    #   3. call es_subscribe with the event types requested in ``subscribe``
    # Absent that, surface a clear error so callers fall back to the legacy
    # DTrace backend rather than silently doing nothing.
    raise BackendNotAvailableError(
        "Endpoint Security entitlement is not present on this interpreter; "
        "Deep View is running unsigned. Fall back to the DTrace backend."
    )


def close_client(client: Any) -> None:
    if not _IS_MACOS:
        return
    # Real impl: es_delete_client
    return None
