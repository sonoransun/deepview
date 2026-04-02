"""Subprocess management utilities."""
from __future__ import annotations
import asyncio
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass
from deepview.core.exceptions import ToolNotFoundError

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
    """Run a command synchronously with timeout."""
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
    )
    return CommandResult(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
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
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
    )
