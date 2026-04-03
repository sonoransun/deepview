"""Tests for command history extraction from memory."""
from __future__ import annotations

import pytest

from deepview.core.types import LayerMetadata
from deepview.interfaces.layer import DataLayer
from deepview.memory.artifacts.command_history import (
    CommandEntry,
    CommandHistoryExtractor,
)


class FakeLayer(DataLayer):
    """In-memory DataLayer for testing."""

    def __init__(self, data: bytes):
        self._data = bytearray(data)

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        end = offset + length
        if end > len(self._data):
            if pad:
                return bytes(self._data[offset:]) + b"\x00" * (end - len(self._data))
            raise ValueError("read beyond end")
        return bytes(self._data[offset:end])

    def write(self, offset: int, data: bytes) -> None:
        self._data[offset : offset + len(data)] = data

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset < len(self._data)

    def scan(self, scanner, progress_callback=None):
        yield from []

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return len(self._data)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name="fake")


class TestCommandEntry:
    def test_fields(self):
        entry = CommandEntry(
            command="dir /s",
            shell_type="cmd",
            offset=0x1000,
            pid=1234,
        )
        assert entry.command == "dir /s"
        assert entry.shell_type == "cmd"
        assert entry.pid == 1234


class TestLooksLikeCommand:
    def test_cmd_commands(self):
        assert CommandHistoryExtractor._looks_like_command("dir /s", "cmd") is True
        assert CommandHistoryExtractor._looks_like_command("ipconfig /all", "cmd") is True
        assert CommandHistoryExtractor._looks_like_command("whoami", "cmd") is True
        assert CommandHistoryExtractor._looks_like_command("net user", "cmd") is True

    def test_powershell_commands(self):
        assert CommandHistoryExtractor._looks_like_command("Get-Process", "powershell") is True
        assert CommandHistoryExtractor._looks_like_command("Invoke-WebRequest", "powershell") is True
        assert CommandHistoryExtractor._looks_like_command("$env:PATH", "powershell") is True

    def test_bash_commands(self):
        assert CommandHistoryExtractor._looks_like_command("ls -la", "bash") is True
        assert CommandHistoryExtractor._looks_like_command("cat /etc/passwd", "bash") is True
        assert CommandHistoryExtractor._looks_like_command("sudo apt update", "bash") is True
        assert CommandHistoryExtractor._looks_like_command("curl http://example.com", "bash") is True

    def test_non_commands(self):
        assert CommandHistoryExtractor._looks_like_command("", "cmd") is False
        assert CommandHistoryExtractor._looks_like_command("ab", "cmd") is False
        assert CommandHistoryExtractor._looks_like_command("http://example.com", "bash") is False


class TestCmdHistoryExtraction:
    def test_find_cmd_commands_utf16(self):
        # Build memory with cmd.exe signature and nearby UTF-16LE commands
        padding = b"\x00" * 1024
        sig = b"cmd.exe"
        # Place some cmd commands as UTF-16LE near the signature
        cmd1 = "dir /s /b".encode("utf-16-le")
        cmd2 = "ipconfig /all".encode("utf-16-le")

        data = padding + sig + b"\x00" * 256 + cmd1 + b"\x00\x00" + cmd2 + padding
        layer = FakeLayer(data)
        extractor = CommandHistoryExtractor(layer)
        entries = extractor.extract_all()

        cmd_entries = [e for e in entries if e.shell_type == "cmd"]
        commands = [e.command for e in cmd_entries]
        assert any("dir" in c for c in commands)
        assert any("ipconfig" in c for c in commands)

    def test_find_powershell_commands_utf16(self):
        padding = b"\x00" * 1024
        sig = b"powershell"
        cmd = "Get-Process".encode("utf-16-le")

        data = padding + sig + b"\x00" * 256 + cmd + padding
        layer = FakeLayer(data)
        extractor = CommandHistoryExtractor(layer)
        entries = extractor.extract_all()

        ps_entries = [e for e in entries if e.shell_type == "powershell"]
        assert any("Get-Process" in e.command for e in ps_entries)


class TestBashHistoryExtraction:
    def test_find_bash_commands(self):
        padding = b"\x00" * 1024
        sig = b"HISTFILE"
        cmd1 = b"ls -la /tmp"
        cmd2 = b"cat /etc/passwd"

        data = padding + sig + b"\x00" * 256 + cmd1 + b"\x00" + cmd2 + padding
        layer = FakeLayer(data)
        extractor = CommandHistoryExtractor(layer)
        entries = extractor.extract_all()

        bash_entries = [e for e in entries if e.shell_type == "bash"]
        commands = [e.command for e in bash_entries]
        assert any("ls" in c for c in commands)
        assert any("cat" in c for c in commands)

    def test_no_history_in_empty_memory(self):
        data = b"\x00" * 8192
        layer = FakeLayer(data)
        extractor = CommandHistoryExtractor(layer)
        entries = extractor.extract_all()
        assert len(entries) == 0


class TestFindAll:
    def test_finds_multiple(self):
        data = b"xxABCxxABCxx"
        offsets = CommandHistoryExtractor._find_all(data, b"ABC")
        assert offsets == [2, 7]

    def test_finds_none(self):
        data = b"nothing here"
        offsets = CommandHistoryExtractor._find_all(data, b"XYZ")
        assert offsets == []
