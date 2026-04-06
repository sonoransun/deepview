"""Subprocess management utilities."""
from __future__ import annotations

import asyncio
import os
import platform
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass

from deepview.core.exceptions import ToolNotFoundError

# Cap captured output to 50 MB to prevent memory exhaustion from chatty tools.
_MAX_OUTPUT_BYTES = 50 * 1024 * 1024


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        return self.returncode == 0


def find_tool(name: str) -> Path:
    """Find an external tool on PATH, raising ToolNotFoundError if not found."""
    path = shutil.which(name)
    if path is None:
        raise ToolNotFoundError(f"Required tool not found: {name}")
    return Path(path)


def run_command(args: list[str], timeout: int = 300, cwd: Path | None = None) -> CommandResult:
    """Run a command synchronously with timeout.

    On Unix, the child runs in a new session so that the entire process
    group can be cleaned up on timeout.
    """
    kwargs: dict = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "cwd": cwd,
    }
    # Use a new session on Unix so we can kill the whole process group.
    if platform.system() != "Windows":
        kwargs["start_new_session"] = True

    try:
        result = subprocess.run(args, **kwargs)
    except subprocess.TimeoutExpired:
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr="Command timed out",
        )
    except FileNotFoundError:
        return CommandResult(returncode=-1, stdout="", stderr=f"Command not found: {args[0]}")

    return CommandResult(
        returncode=result.returncode,
        stdout=result.stdout[:_MAX_OUTPUT_BYTES],
        stderr=result.stderr[:_MAX_OUTPUT_BYTES],
    )


async def run_command_async(args: list[str], timeout: int = 300, cwd: Path | None = None) -> CommandResult:
    """Run a command asynchronously with timeout."""
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return CommandResult(returncode=-1, stdout="", stderr="Command timed out")

    return CommandResult(
        returncode=proc.returncode or 0,
        stdout=stdout_bytes.decode("utf-8", errors="replace")[:_MAX_OUTPUT_BYTES],
        stderr=stderr_bytes.decode("utf-8", errors="replace")[:_MAX_OUTPUT_BYTES],
    )
