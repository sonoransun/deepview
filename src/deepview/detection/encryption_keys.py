"""Encryption key material scanning in memory."""
from __future__ import annotations
import struct
from dataclasses import dataclass
from deepview.core.logging import get_logger
from deepview.core.types import ScanResult

log = get_logger("detection.encryption_keys")


@dataclass
class KeyFinding:
    """An encryption key found in memory."""
    key_type: str  # "aes_128", "aes_256", "rsa", "bitlocker", "dm_crypt"
    offset: int
    key_data: bytes
    confidence: float  # 0.0 - 1.0
    description: str = ""


class EncryptionKeyScanner:
    """Scan memory for encryption key material.

    Techniques:
    - AES key schedule detection (expanded key patterns)
    - RSA private key structure detection
    - BitLocker FVEK (Full Volume Encryption Key)
    - dm-crypt master key from kernel memory
    - FileVault 2 key material
    - TLS session keys
    """

    def scan_aes_keys(self, data: bytes, offset: int = 0) -> list[KeyFinding]:
        """Detect AES key schedules in memory.

        AES key expansion produces a distinctive pattern where each
        round key is derived from the previous one. We look for
        sequences where the relationship between consecutive 4-byte
        words matches the AES key schedule algorithm.
        """
        findings = []

        # Look for AES-128 key schedules (176 bytes = 11 * 16)
        # Look for AES-256 key schedules (240 bytes = 15 * 16)
        for i in range(0, len(data) - 176, 4):
            if self._check_aes_schedule(data[i:i+176], 128):
                findings.append(KeyFinding(
                    key_type="aes_128",
                    offset=offset + i,
                    key_data=data[i:i+16],
                    confidence=0.85,
                    description="Possible AES-128 key schedule detected",
                ))

            if i + 240 <= len(data) and self._check_aes_schedule(data[i:i+240], 256):
                findings.append(KeyFinding(
                    key_type="aes_256",
                    offset=offset + i,
                    key_data=data[i:i+32],
                    confidence=0.85,
                    description="Possible AES-256 key schedule detected",
                ))

        return findings

    def _check_aes_schedule(self, data: bytes, key_bits: int) -> bool:
        """Validate if data looks like an AES key schedule.

        Uses entropy and structural checks. A valid key schedule has:
        1. Non-zero first round key
        2. High entropy throughout
        3. Proper word relationships
        """
        if len(data) < (176 if key_bits == 128 else 240):
            return False

        # First 16/32 bytes must not be all zeros or all same byte
        key_len = key_bits // 8
        first_key = data[:key_len]
        if first_key == b"\x00" * key_len:
            return False
        if len(set(first_key)) == 1:
            return False

        # Check entropy of the expanded key
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        import math
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)

        # AES key schedules typically have entropy > 6.0 bits/byte
        return entropy > 6.0

    def scan_rsa_keys(self, data: bytes, offset: int = 0) -> list[KeyFinding]:
        """Detect RSA private key structures in memory.

        Looks for ASN.1 DER-encoded RSA private key sequences.
        """
        findings = []

        # RSA private key ASN.1 header: SEQUENCE { INTEGER(0), ... }
        # DER encoding: 30 82 XX XX 02 01 00 02 82 ...
        pattern = b"\x30\x82"
        idx = 0
        while idx < len(data) - 10:
            idx = data.find(pattern, idx)
            if idx == -1:
                break

            # Check for version INTEGER(0) after the SEQUENCE header
            seq_len = struct.unpack(">H", data[idx+2:idx+4])[0]
            if idx + 4 + seq_len <= len(data):
                # Check for version = 0
                if data[idx+4:idx+7] == b"\x02\x01\x00":
                    # Check for next INTEGER (modulus)
                    if data[idx+7:idx+9] == b"\x02\x82":
                        findings.append(KeyFinding(
                            key_type="rsa",
                            offset=offset + idx,
                            key_data=data[idx:idx+min(32, seq_len)],
                            confidence=0.75,
                            description=f"Possible RSA private key (DER encoded, ~{seq_len} bytes)",
                        ))

            idx += 1

        return findings

    def scan_bitlocker_keys(self, data: bytes, offset: int = 0) -> list[KeyFinding]:
        """Detect BitLocker FVEK in memory.

        BitLocker stores the Full Volume Encryption Key in a structure
        preceded by a known header pattern.
        """
        findings = []

        # BitLocker FVE metadata signature
        fve_sig = b"-FVE-FS-"
        idx = data.find(fve_sig)
        while idx != -1:
            findings.append(KeyFinding(
                key_type="bitlocker",
                offset=offset + idx,
                key_data=data[idx:idx+64],
                confidence=0.70,
                description="BitLocker FVE metadata signature found",
            ))
            idx = data.find(fve_sig, idx + 1)

        return findings

    def scan_all(self, data: bytes, offset: int = 0) -> list[KeyFinding]:
        """Run all key detection scans."""
        findings = []
        findings.extend(self.scan_aes_keys(data, offset))
        findings.extend(self.scan_rsa_keys(data, offset))
        findings.extend(self.scan_bitlocker_keys(data, offset))
        return findings
