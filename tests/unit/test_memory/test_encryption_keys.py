"""Tests for encryption key material scanning."""
from __future__ import annotations

import os
import struct

import pytest

from deepview.detection.encryption_keys import EncryptionKeyScanner, KeyFinding


@pytest.fixture
def scanner() -> EncryptionKeyScanner:
    return EncryptionKeyScanner()


class TestScanAESKeys:
    """Test AES key schedule detection."""

    def test_scan_aes_rejects_zeros(self, scanner: EncryptionKeyScanner):
        """240 zero bytes should not be detected as AES key schedule."""
        data = b"\x00" * 240
        findings = scanner.scan_aes_keys(data)
        assert len(findings) == 0

    def test_scan_aes_rejects_same_byte(self, scanner: EncryptionKeyScanner):
        """240 bytes of the same byte value should not be detected."""
        data = b"\xaa" * 240
        findings = scanner.scan_aes_keys(data)
        assert len(findings) == 0


class TestScanRSAKeys:
    """Test RSA private key detection."""

    def test_scan_rsa_detects_pattern(self, scanner: EncryptionKeyScanner):
        """Craft bytes matching the ASN.1 DER RSA private key header."""
        # Build: 30 82 [seq_len] 02 01 00 02 82 [mod_len] ...
        seq_len = 256  # total sequence length
        mod_len = 128
        pattern = (
            b"\x30\x82" + struct.pack(">H", seq_len) +
            b"\x02\x01\x00" +       # INTEGER version = 0
            b"\x02\x82" +           # INTEGER modulus header
            struct.pack(">H", mod_len) +
            os.urandom(mod_len)     # dummy modulus data
        )
        # Pad to ensure the sequence length check passes
        data = pattern + b"\x00" * (seq_len - len(pattern) + 4)

        findings = scanner.scan_rsa_keys(data)
        assert len(findings) >= 1
        assert findings[0].key_type == "rsa"
        assert findings[0].offset == 0

    def test_scan_rsa_no_false_positive(self, scanner: EncryptionKeyScanner):
        """Random data without the ASN.1 pattern should produce no findings."""
        # Use a deterministic pattern that won't accidentally contain the header
        data = bytes(range(256)) * 4
        findings = scanner.scan_rsa_keys(data)
        # If any are found, they should not have the rsa type incorrectly
        # (the pattern bytes(range(256)) does contain 0x30 at pos 0x30 but
        # the full sequence check is very unlikely to pass)
        # We just verify no findings for this specific data
        assert len(findings) == 0


class TestScanBitLockerKeys:
    """Test BitLocker FVEK detection."""

    def test_scan_bitlocker_finds_signature(self, scanner: EncryptionKeyScanner):
        """Embed the FVE signature and verify detection."""
        data = b"\x00" * 100 + b"-FVE-FS-" + b"\x00" * 100
        findings = scanner.scan_bitlocker_keys(data)

        assert len(findings) == 1
        assert findings[0].key_type == "bitlocker"
        assert findings[0].offset == 100

    def test_scan_bitlocker_with_offset(self, scanner: EncryptionKeyScanner):
        """Verify the offset parameter is correctly added to finding offsets."""
        data = b"-FVE-FS-" + b"\x00" * 56
        findings = scanner.scan_bitlocker_keys(data, offset=0x1000)

        assert len(findings) == 1
        assert findings[0].offset == 0x1000

    def test_scan_bitlocker_no_match(self, scanner: EncryptionKeyScanner):
        """Data without the BitLocker signature should produce no findings."""
        data = b"\x00" * 512
        findings = scanner.scan_bitlocker_keys(data)
        assert len(findings) == 0


class TestScanAll:
    """Test the combined scan_all method."""

    def test_scan_all_combines_results(self, scanner: EncryptionKeyScanner):
        """Data containing both BitLocker sig and RSA pattern yields both."""
        # Build an RSA pattern
        seq_len = 256
        mod_len = 128
        rsa_pattern = (
            b"\x30\x82" + struct.pack(">H", seq_len) +
            b"\x02\x01\x00" +
            b"\x02\x82" +
            struct.pack(">H", mod_len) +
            os.urandom(mod_len)
        )
        rsa_data = rsa_pattern + b"\x00" * (seq_len - len(rsa_pattern) + 4)

        # Build a BitLocker signature section
        bitlocker_data = b"-FVE-FS-" + b"\x00" * 56

        # Combine with some padding between them
        data = rsa_data + b"\x00" * 64 + bitlocker_data

        findings = scanner.scan_all(data)

        key_types = {f.key_type for f in findings}
        assert "rsa" in key_types
        assert "bitlocker" in key_types
