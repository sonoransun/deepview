"""Security tests for address parsing in disassembly CLI."""
from __future__ import annotations

import pytest
import click

from deepview.cli.commands.disassemble import _parse_address, _MAX_ADDRESS


class TestAddressParsing:
    def test_hex_address(self):
        assert _parse_address("0x1000") == 0x1000

    def test_decimal_address(self):
        assert _parse_address("4096") == 4096

    def test_zero(self):
        assert _parse_address("0x0") == 0

    def test_max_address(self):
        assert _parse_address(f"0x{_MAX_ADDRESS:x}") == _MAX_ADDRESS


class TestAddressBoundsValidation:
    def test_exceeds_64bit_rejected(self):
        with pytest.raises(click.exceptions.BadParameter, match="out of range"):
            _parse_address("0x10000000000000000")  # > 2^64

    def test_negative_rejected(self):
        with pytest.raises(click.exceptions.BadParameter, match="out of range"):
            _parse_address("-1")

    def test_astronomically_large_rejected(self):
        with pytest.raises(click.exceptions.BadParameter, match="out of range"):
            _parse_address("0x" + "FF" * 100)


class TestMalformedAddresses:
    def test_non_numeric_rejected(self):
        with pytest.raises(click.exceptions.BadParameter, match="Invalid address"):
            _parse_address("not_a_number")

    def test_empty_string_rejected(self):
        with pytest.raises(click.exceptions.BadParameter, match="Invalid address"):
            _parse_address("")
