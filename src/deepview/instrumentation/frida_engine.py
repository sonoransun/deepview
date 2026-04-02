"""Frida-based dynamic instrumentation engine."""
from __future__ import annotations
import asyncio
import json
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from deepview.core.logging import get_logger
from deepview.core.exceptions import AttachError, ScriptError, HookError
from deepview.interfaces.instrumentor import (
    Instrumentor, InstrumentationSession,
    HookDefinition, HookHandle,
)
from deepview.core.types import ModuleInfo

log = get_logger("instrumentation.frida")


class FridaEngine(Instrumentor):
    """Frida-based dynamic instrumentation."""

    def __init__(self):
        self._frida = None
        self._available = False
        self._device = None
        try:
            import frida
            self._frida = frida
            self._available = True
        except ImportError:
            log.debug("frida_not_installed")

    def is_available(self) -> bool:
        return self._available

    def _get_device(self):
        if self._device is None:
            self._device = self._frida.get_local_device()
        return self._device

    def attach(self, target: int | str) -> InstrumentationSession:
        if not self._available:
            raise AttachError("Frida is not installed")
        try:
            device = self._get_device()
            session = device.attach(target)
            log.info("attached", target=target)
            return FridaSession(session, target, self._frida)
        except Exception as e:
            raise AttachError(f"Failed to attach to {target}: {e}") from e

    def spawn(self, program: Path, args: list[str] | None = None) -> InstrumentationSession:
        if not self._available:
            raise AttachError("Frida is not installed")
        try:
            device = self._get_device()
            argv = [str(program)] + (args or [])
            pid = device.spawn(argv)
            session = device.attach(pid)
            log.info("spawned", program=str(program), pid=pid)
            return FridaSession(session, pid, self._frida, spawned=True, device=device)
        except Exception as e:
            raise AttachError(f"Failed to spawn {program}: {e}") from e

    def detach(self, session: InstrumentationSession) -> None:
        if isinstance(session, FridaSession):
            session.detach()


class FridaSession(InstrumentationSession):
    """Active Frida instrumentation session."""

    def __init__(self, session, target, frida_module, spawned=False, device=None):
        self._session = session
        self._target = target
        self._frida = frida_module
        self._spawned = spawned
        self._device = device
        self._scripts: dict[str, Any] = {}
        self._hooks: dict[str, HookDefinition] = {}
        self._message_callbacks: list[Callable] = []
        self._pid_value = target if isinstance(target, int) else 0

    @property
    def pid(self) -> int:
        return self._pid_value

    def resume(self) -> None:
        """Resume a spawned process after hooks are installed."""
        if self._spawned and self._device:
            self._device.resume(self._pid_value)

    def inject_hook(self, hook: HookDefinition) -> HookHandle:
        self._hooks[hook.hook_id] = hook
        self._reload_hooks()
        return HookHandle(handle_id=hook.hook_id, hook=hook)

    def remove_hook(self, handle: HookHandle) -> None:
        self._hooks.pop(handle.handle_id, None)
        self._reload_hooks()

    def _reload_hooks(self) -> None:
        """Regenerate and reload the hook script."""
        if "hooks" in self._scripts:
            try:
                self._scripts["hooks"].unload()
            except Exception:
                pass

        if not self._hooks:
            return

        source = self._generate_hook_script()
        try:
            script = self._session.create_script(source)
            script.on("message", self._on_message)
            script.load()
            self._scripts["hooks"] = script
        except Exception as e:
            raise ScriptError(f"Failed to load hook script: {e}") from e

    def _generate_hook_script(self) -> str:
        """Generate JavaScript for all active hooks."""
        lines = ["'use strict';"]

        for hook in self._hooks.values():
            if not hook.enabled:
                continue

            if hook.address is not None:
                resolve = f"ptr('{hex(hook.address)}')"
            else:
                module_arg = f"'{hook.module}'" if hook.module else "null"
                resolve = f"Module.findExportByName({module_arg}, '{hook.function}')"

            on_enter = hook.on_enter or self._default_on_enter(hook)
            on_leave = hook.on_leave or self._default_on_leave(hook)

            lines.append(f"""
try {{
    var addr_{hook.hook_id} = {resolve};
    if (addr_{hook.hook_id}) {{
        Interceptor.attach(addr_{hook.hook_id}, {{
            onEnter: function(args) {{
                {on_enter}
            }},
            onLeave: function(retval) {{
                {on_leave}
            }}
        }});
    }}
}} catch(e) {{
    send({{type: 'hook_error', hook_id: '{hook.hook_id}', error: e.message}});
}}""")

        return "\n".join(lines)

    def _default_on_enter(self, hook: HookDefinition) -> str:
        parts = [f"send({{type: 'hook_event', hook_id: '{hook.hook_id}', phase: 'enter', "
                 f"function: '{hook.function}', pid: Process.id, tid: this.threadId"]
        if hook.capture_args:
            parts.append(", args: [args[0], args[1], args[2], args[3]].map(String)")
        if hook.capture_backtrace:
            parts.append(", backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).map(String)")
        parts.append("});")
        return "".join(parts)

    def _default_on_leave(self, hook: HookDefinition) -> str:
        if not hook.capture_retval:
            return ""
        return (f"send({{type: 'hook_event', hook_id: '{hook.hook_id}', phase: 'leave', "
                f"function: '{hook.function}', retval: retval.toInt32()}});")

    def _on_message(self, message: dict, data: bytes | None) -> None:
        for cb in self._message_callbacks:
            cb(message, data)

    def on_message(self, callback: Callable) -> None:
        self._message_callbacks.append(callback)

    def read_memory(self, address: int, size: int) -> bytes:
        script_src = f"rpc.exports.readMem = function(addr, sz) {{ return Memory.readByteArray(ptr(addr), sz); }};"
        script = self._session.create_script(script_src)
        script.load()
        try:
            result = script.exports_sync.readMem(address, size)
            return bytes(result) if result else b""
        finally:
            script.unload()

    def write_memory(self, address: int, data: bytes) -> None:
        script_src = """
        rpc.exports.writeMem = function(addr, data) {
            Memory.writeByteArray(ptr(addr), data);
        };
        """
        script = self._session.create_script(script_src)
        script.load()
        try:
            script.exports_sync.writeMem(address, list(data))
        finally:
            script.unload()

    def enumerate_modules(self) -> list[ModuleInfo]:
        script_src = """
        rpc.exports.listModules = function() {
            return Process.enumerateModules().map(function(m) {
                return {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
            });
        };
        """
        script = self._session.create_script(script_src)
        script.load()
        try:
            modules = script.exports_sync.listModules()
            return [
                ModuleInfo(
                    name=m["name"],
                    base_address=int(m["base"], 16) if isinstance(m["base"], str) else m["base"],
                    size=m["size"],
                    path=m.get("path", ""),
                )
                for m in modules
            ]
        finally:
            script.unload()

    def detach(self) -> None:
        for script in self._scripts.values():
            try:
                script.unload()
            except Exception:
                pass
        self._scripts.clear()
        try:
            self._session.detach()
        except Exception:
            pass
        log.info("detached", target=self._target)
