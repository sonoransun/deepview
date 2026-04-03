"""Command history extraction from memory images.

Recovers shell command history from process memory for:
  - Windows cmd.exe (COMMAND_HISTORY structures in conhost.exe)
  - PowerShell (ConsoleHost history buffer, PSReadLine)
  - Bash (HIST_ENTRY structures, readline history)

References:
    - Volatility ``consoles`` and ``cmdscan`` plugins
    - Windows console host internals (conhost.exe)
    - Bash readline ``HIST_ENTRY`` structures
    - PowerShell ``ConsoleHost`` history buffer
"""
from __future__ import annotations

import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from deepview.core.logging import get_logger

if TYPE_CHECKING:
    from deepview.interfaces.layer import DataLayer

log = get_logger("memory.artifacts.command_history")

# Signature patterns for locating history structures
_CMD_HISTORY_MAGIC = b"cmd.exe"
_POWERSHELL_MAGIC = b"powershell"
_BASH_MAGIC = b"HISTFILE"

# ASCII/UTF-8 printable command patterns
_COMMAND_PATTERN = re.compile(
    rb"[\x20-\x7e\t]{4,512}"
)
# UTF-16LE command pattern (Windows)
_COMMAND_PATTERN_UTF16 = re.compile(
    rb"(?:[\x20-\x7e]\x00){4,512}"
)

# Scan chunk size
_CHUNK_SIZE = 4 * 1024 * 1024
_OVERLAP = 4096


@dataclass(slots=True)
class CommandEntry:
    """A single recovered command from shell history."""

    command: str
    shell_type: str  # "cmd", "powershell", "bash", "unknown"
    offset: int
    pid: int = 0
    user: str = ""
    sequence_number: int = -1
    metadata: dict = field(default_factory=dict)


class CommandHistoryExtractor:
    """Extract shell command history from memory images.

    Scans physical memory for recognizable command-line patterns
    near shell process signatures. Works without requiring process
    listing or virtual address translation (brute-force physical scan).
    """

    def __init__(self, layer: DataLayer):
        self._layer = layer

    def extract_all(self) -> list[CommandEntry]:
        """Extract command history from all detected shell types."""
        entries: list[CommandEntry] = []
        entries.extend(self._extract_cmd_history())
        entries.extend(self._extract_powershell_history())
        entries.extend(self._extract_bash_history())
        log.info("command_history_extracted", count=len(entries))
        return entries

    # ------------------------------------------------------------------
    # Windows cmd.exe / conhost.exe
    # ------------------------------------------------------------------

    def _extract_cmd_history(self) -> Iterator[CommandEntry]:
        """Extract cmd.exe command history.

        Windows stores command history in conhost.exe process memory.
        The COMMAND_HISTORY structure contains a linked list of
        COMMAND structures, each holding a Unicode command string.

        We use a heuristic: scan for UTF-16LE strings near "cmd.exe"
        signatures that look like command lines (start with common
        Windows commands or contain common path patterns).
        """
        for chunk_data, chunk_base in self._iter_chunks():
            # Find cmd.exe signatures in this chunk
            cmd_offsets = self._find_all(chunk_data, _CMD_HISTORY_MAGIC)

            for sig_off in cmd_offsets:
                # Search in a window around the signature for UTF-16LE commands
                window_start = max(0, sig_off - 0x2000)
                window_end = min(len(chunk_data), sig_off + 0x10000)
                window = chunk_data[window_start:window_end]

                for m in _COMMAND_PATTERN_UTF16.finditer(window):
                    try:
                        text = m.group().decode("utf-16-le").strip()
                    except UnicodeDecodeError:
                        continue

                    if self._looks_like_command(text, "cmd"):
                        yield CommandEntry(
                            command=text,
                            shell_type="cmd",
                            offset=chunk_base + window_start + m.start(),
                        )

    # ------------------------------------------------------------------
    # PowerShell
    # ------------------------------------------------------------------

    def _extract_powershell_history(self) -> Iterator[CommandEntry]:
        """Extract PowerShell command history.

        PowerShell stores history in the ConsoleHost history buffer
        and optionally via PSReadLine. Both store Unicode strings.
        We scan for UTF-16LE strings near "powershell" signatures
        that match PowerShell cmdlet patterns.
        """
        for chunk_data, chunk_base in self._iter_chunks():
            ps_offsets = self._find_all(chunk_data, _POWERSHELL_MAGIC)

            for sig_off in ps_offsets:
                window_start = max(0, sig_off - 0x2000)
                window_end = min(len(chunk_data), sig_off + 0x10000)
                window = chunk_data[window_start:window_end]

                for m in _COMMAND_PATTERN_UTF16.finditer(window):
                    try:
                        text = m.group().decode("utf-16-le").strip()
                    except UnicodeDecodeError:
                        continue

                    if self._looks_like_command(text, "powershell"):
                        yield CommandEntry(
                            command=text,
                            shell_type="powershell",
                            offset=chunk_base + window_start + m.start(),
                        )

    # ------------------------------------------------------------------
    # Bash
    # ------------------------------------------------------------------

    def _extract_bash_history(self) -> Iterator[CommandEntry]:
        """Extract bash command history.

        Bash maintains an in-memory history list of HIST_ENTRY structures.
        Each entry contains a ``char *line`` pointer and a timestamp string.

        We use a heuristic: scan for ASCII strings near HISTFILE or
        bash-related signatures that look like Unix commands.
        """
        for chunk_data, chunk_base in self._iter_chunks():
            bash_offsets = self._find_all(chunk_data, _BASH_MAGIC)
            # Also look for common bash prompt patterns
            bash_offsets.extend(self._find_all(chunk_data, b"/.bash_history"))

            for sig_off in bash_offsets:
                window_start = max(0, sig_off - 0x4000)
                window_end = min(len(chunk_data), sig_off + 0x10000)
                window = chunk_data[window_start:window_end]

                for m in _COMMAND_PATTERN.finditer(window):
                    text = m.group().decode("ascii", errors="replace").strip()
                    if self._looks_like_command(text, "bash"):
                        yield CommandEntry(
                            command=text,
                            shell_type="bash",
                            offset=chunk_base + window_start + m.start(),
                        )

    # ------------------------------------------------------------------
    # Heuristics
    # ------------------------------------------------------------------

    # Common prefixes for different shell types
    _CMD_PREFIXES = (
        "dir", "cd", "copy", "del", "move", "type", "cls", "echo",
        "set", "net", "ipconfig", "ping", "tasklist", "taskkill",
        "reg", "sc ", "wmic", "bcdedit", "shutdown", "systeminfo",
        "whoami", "hostname", "attrib", "certutil", "bitsadmin",
        "powershell", "cmd", "start", "runas",
    )

    _PS_PREFIXES = (
        "Get-", "Set-", "New-", "Remove-", "Invoke-", "Start-",
        "Stop-", "Import-", "Export-", "Write-", "Read-",
        "Test-", "Select-", "Where-", "ForEach-", "Sort-",
        "$", "IEX", "iex", "Invoke-Expression", "Invoke-WebRequest",
        "DownloadString", "DownloadFile",
    )

    _BASH_PREFIXES = (
        "ls", "cd ", "cat ", "grep ", "find ", "chmod ", "chown ",
        "cp ", "mv ", "rm ", "mkdir ", "touch ", "echo ",
        "curl ", "wget ", "ssh ", "scp ", "git ", "docker ",
        "sudo ", "apt ", "yum ", "pip ", "python", "make ",
        "gcc ", "vim ", "nano ", "tar ", "zip ", "unzip ",
        "ps ", "kill ", "top", "htop", "awk ", "sed ",
        "export ", "source ", "./", "bash ", "sh ",
    )

    @classmethod
    def _looks_like_command(cls, text: str, shell_type: str) -> bool:
        """Heuristic check if a string looks like a shell command."""
        if not text or len(text) < 3:
            return False

        # Skip obvious non-commands
        if text.startswith(("http://", "https://", "<", "{", "[")):
            return False

        lower = text.lower()

        if shell_type == "cmd":
            return any(lower.startswith(p) for p in cls._CMD_PREFIXES)
        elif shell_type == "powershell":
            return any(text.startswith(p) for p in cls._PS_PREFIXES)
        elif shell_type == "bash":
            return any(lower.startswith(p) for p in cls._BASH_PREFIXES)

        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _iter_chunks(self) -> Iterator[tuple[bytes, int]]:
        """Iterate over the layer in chunks, yielding (data, base_offset)."""
        start = self._layer.minimum_address
        end = self._layer.maximum_address
        pos = start

        while pos < end:
            chunk_end = min(pos + _CHUNK_SIZE, end)
            try:
                data = self._layer.read(pos, chunk_end - pos, pad=True)
            except Exception:
                pos += _CHUNK_SIZE - _OVERLAP
                continue
            yield data, pos
            pos += _CHUNK_SIZE - _OVERLAP

    @staticmethod
    def _find_all(data: bytes, pattern: bytes) -> list[int]:
        """Find all occurrences of pattern in data."""
        offsets = []
        start = 0
        while True:
            idx = data.find(pattern, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
        return offsets
