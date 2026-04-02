"""Python-JS message bridge for Frida instrumentation."""
from __future__ import annotations
import asyncio
from typing import Any, Callable

from deepview.core.logging import get_logger
from deepview.core.types import EventCategory, EventSource, ProcessContext
from deepview.tracing.events import MonitorEvent
from deepview.tracing.stream import TraceEventBus

log = get_logger("instrumentation.bridge")


class FridaBridge:
    """Converts Frida JS messages to MonitorEvents and publishes to EventBus."""

    def __init__(self, event_bus: TraceEventBus | None = None):
        self._bus = event_bus
        self._handlers: dict[str, list[Callable]] = {}

    def register_handler(self, msg_type: str, handler: Callable) -> None:
        self._handlers.setdefault(msg_type, []).append(handler)

    def handle_message(self, message: dict, data: bytes | None) -> None:
        """Process a Frida message."""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type", "unknown")

            for handler in self._handlers.get(msg_type, []):
                handler(payload, data)

            if msg_type == "hook_event" and self._bus:
                event = self._convert_hook_event(payload)
                if event:
                    self._bus.publish_sync(event)

        elif message.get("type") == "error":
            log.error("frida_script_error",
                      description=message.get("description", ""),
                      stack=message.get("stack", ""))

    def _convert_hook_event(self, payload: dict) -> MonitorEvent | None:
        """Convert a hook_event payload to a MonitorEvent."""
        try:
            return MonitorEvent(
                category=EventCategory.SYSCALL_RAW,
                source=EventSource(
                    platform="",
                    backend="frida",
                    probe_name=payload.get("hook_id", "unknown"),
                ),
                process=ProcessContext(
                    pid=payload.get("pid", 0),
                    tid=payload.get("tid", 0),
                    ppid=0,
                    uid=0,
                    gid=0,
                    comm="",
                ),
                syscall_name=payload.get("function", ""),
                args={"raw_args": payload.get("args", [])},
                return_value=payload.get("retval"),
                metadata={
                    "phase": payload.get("phase", ""),
                    "backtrace": payload.get("backtrace", []),
                },
            )
        except Exception as e:
            log.warning("event_conversion_failed", error=str(e))
            return None
