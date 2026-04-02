from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from deepview.core.types import ModuleInfo


# ------------------------------------------------------------------
# Data classes
# ------------------------------------------------------------------


@dataclass
class HookDefinition:
    """Describes a function hook to inject into a target process."""

    hook_id: str
    module: str
    function: str
    address: int | None = None
    on_enter: str | None = None
    on_leave: str | None = None
    arg_types: list[str] = field(default_factory=list)
    capture_backtrace: bool = False
    capture_args: bool = True
    capture_retval: bool = True
    enabled: bool = True


@dataclass
class HookHandle:
    """Opaque handle returned when a hook is successfully injected."""

    handle_id: str
    hook: HookDefinition


# ------------------------------------------------------------------
# ABCs
# ------------------------------------------------------------------


class InstrumentationSession(ABC):
    """A live connection to a single instrumented process."""

    @abstractmethod
    def inject_hook(self, hook: HookDefinition) -> HookHandle:
        """Inject *hook* into the target process."""

    @abstractmethod
    def remove_hook(self, handle: HookHandle) -> None:
        """Remove a previously injected hook."""

    @abstractmethod
    def read_memory(self, address: int, size: int) -> bytes:
        """Read *size* bytes from *address* in the target process."""

    @abstractmethod
    def write_memory(self, address: int, data: bytes) -> None:
        """Write *data* to *address* in the target process."""

    @abstractmethod
    def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules / shared libraries in the target."""

    @abstractmethod
    def on_message(self, callback: Callable) -> None:
        """Register a callback invoked for every message from injected hooks."""

    @property
    @abstractmethod
    def pid(self) -> int:
        """PID of the instrumented process."""


class Instrumentor(ABC):
    """Factory / manager for :class:`InstrumentationSession` instances
    (e.g. backed by Frida)."""

    @abstractmethod
    def attach(self, target: int | str) -> InstrumentationSession:
        """Attach to a running process by PID or name."""

    @abstractmethod
    def spawn(
        self,
        program: Path,
        args: list[str] | None = None,
    ) -> InstrumentationSession:
        """Spawn *program* in a suspended state and return a session."""

    @abstractmethod
    def detach(self, session: InstrumentationSession) -> None:
        """Detach from *session*, releasing all hooks."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return ``True`` when the instrumentation backend is usable."""
