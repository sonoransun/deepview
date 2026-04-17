# BitLocker volume format

BitLocker is Microsoft's full-volume-encryption stack, shipped with
every Windows release since Vista. A BitLocker-protected volume
begins with a **standard NTFS / FAT BIOS Parameter Block (BPB)** whose
**OEM ID** field has been overwritten with the ASCII marker
`"-FVE-FS-"`. This lets the boot code decide whether to hand off to
`fvevol.sys` before the filesystem driver binds.

Deep View's BitLocker unlocker is a **shim over libbde** (`pybde`): all
detection logic is pure-Python, and the actual decryption is handled
by libbde. This document focuses on detection and the on-disk layout
consumers need to understand — not on the crypto details, which are
exhaustively covered in libbde's reference.

## Signature

* **OEM ID (offset `0x03`, 8 bytes):** `"-FVE-FS-"`
  (`2D 46 56 45 2D 46 53 2D`).

```python
_BITLOCKER_SIGNATURE = b"-FVE-FS-"
_BITLOCKER_OEMID_OFFSET = 3
_BITLOCKER_SIGNATURE_LEN = 8
```

## BPB prefix (relevant fields only)

| Offset | Size | Field              | Description                                              |
| -----: | ---: | ------------------ | -------------------------------------------------------- |
| `0x00` |  3   | `jmp`              | `EB 58 90` — JMP to boot code. Standard FAT/NTFS pattern.|
| `0x03` |  8   | **`OEMID`**        | **`"-FVE-FS-"` for BitLocker**; `"NTFS    "` for NTFS.   |
| `0x0B` |  2   | `BytesPerSector`   | `512` or `4096`.                                         |
| `0x0D` |  1   | `SectorsPerCluster`| Ignored at this layer.                                   |
| `0x0E` |  2   | `ReservedSectors`  | Reserved before the filesystem.                          |
| `0x18` |  2   | `SectorsPerTrack`  | Ignored.                                                 |
| `0x1FE`|  2   | `BootSignature`    | `55 AA` (standard MBR boot signature).                   |

A matching sector 0 is a **strong** BitLocker signature: third-party
volumes do not use `-FVE-FS-` as an OEM ID.

## BitLocker volume layout

Beyond the BPB, the volume is structured as a sequence of
`FVE_BLOCK` regions (FVE = "Full Volume Encryption") + encrypted
payload:

```
sector 0:   [BPB][OEMID="-FVE-FS-"][FS boot code][0x55 0xAA]
sector 1+:  [--- 3 FVE metadata block copies, at FveOffsetA/B/C ---]
            each block: signature="FVE-FS-" + header + entries
                        entries encode:
                          - Volume Master Key (VMK) entries (protectors)
                          - Full Volume Encryption Key (FVEK) entry
                          - description / properties
later:      [--- encrypted filesystem (AES-128-CBC, AES-256-CBC,
                AES-128-XTS (Win10+), AES-256-XTS (Win10+)) ---]
```

## Keys

| Key                           | Role                                                    |
| ----------------------------- | ------------------------------------------------------- |
| **VMK** (Volume Master Key)   | Intermediate key; protected by *protectors* (password, recovery key, TPM, startup key, smartcard). |
| **FVEK** (Full Volume Encryption Key) | Actual AES-CBC / AES-XTS key used to decrypt sectors. Protected by the VMK. |

A BitLocker-protected volume always has **at least one** VMK
protector. The common ones are:

| Protector type          | On-disk marker                       |
| ----------------------- | ------------------------------------ |
| Password                | Clear-text entry with PBKDF2 salt.   |
| Recovery password       | 48-digit numeric key (8 × 6-digit groups). |
| TPM                     | Sealed blob verified by platform state. |
| TPM + PIN               | TPM-sealed with user PIN.            |
| Startup key (.BEK file) | Raw key material on USB.             |
| Smartcard               | PKCS#11 certificate-based unwrap.    |

## Recovery password format

A recovery password is **48 digits** grouped into 8 clusters of 6
digits, each cluster separated by `-`:

```
123456-234567-345678-456789-567890-678901-789012-890123
```

Deep View's heuristic `_looks_like_recovery_password()`:

```python
def _looks_like_recovery_password(pw: str) -> bool:
    parts = pw.strip().split("-")
    if len(parts) != 8:
        return False
    return all(p.isdigit() and len(p) == 6 for p in parts)
```

Each 6-digit group must be divisible by 11 (parity check) and the
resulting integers form a 128-bit intermediate key; see the
[Elcomsoft Forensic Disk Decryptor notes](https://www.elcomsoft.com/efdd.html)
and the libbde reference for the exact derivation.

## Detection flow

1. Read the first 512 bytes of the volume.
2. Check `head[3:11] == b"-FVE-FS-"`.
3. If matched, instantiate a `ContainerHeader` with:
   * `format = "bitlocker"`,
   * `cipher = "aes-xts"` (detection-time default — actual cipher
     comes from FVEK entry after libbde parses the FVE blocks),
   * `sector_size = 512`,
   * `kdf = "pbkdf2_sha256"`, `kdf_params = {"iterations": 4096}`.

The KDF params are placeholders for orchestration; libbde re-derives
them from the actual FVE block when `pybde.set_password` is called.

## Unlock flow (via libbde)

```python
import pybde
volume = pybde.volume()

# Pass a DataLayer-backed file-like object to libbde
volume.open_file_object(file_io)

# Apply the protector:
if looks_like_recovery_password(pw):
    volume.set_recovery_password(pw)
elif isinstance(source, MasterKey):
    volume.set_full_volume_encryption_key(source.key)   # FVEK direct
elif isinstance(source, Keyfile):
    volume.set_startup_key(str(Path(source.path)))       # .BEK file
else:
    volume.set_password(pw)

# libbde now exposes the plaintext
decrypted = BitLockerDecryptedLayer(volume)
```

## Known variations

!!! note "BitLocker-to-Go (removable media)"
    Uses `"MSWIN4.1"` as OEM ID and stores FVE metadata inside a
    different structure. Deep View **does not** cover this variant;
    use `pybde` directly.

!!! note "Windows Recovery Environment (WinRE)"
    WinRE-enabled volumes may have the BitLocker BPB but with the
    FVE metadata stored in a sibling partition. Detection still
    triggers on the `-FVE-FS-` signature.

!!! note "AES-CBC vs AES-XTS"
    Windows 7 / 8 default to AES-128-CBC or AES-256-CBC (with
    Elephant diffuser on 7). Windows 10+ default to AES-128-XTS or
    AES-256-XTS. libbde handles both transparently; the
    `ContainerHeader.cipher` value is informative only.

!!! warning "Suspended protection"
    A volume with BitLocker "suspended" still carries the
    `"-FVE-FS-"` signature but its FVEK is written to the volume in
    plaintext. Detection reports the volume as BitLocker; reads
    succeed without any protector because libbde surfaces the
    clear-key VMK entry. This is normal Windows behaviour when a
    user suspends protection during a firmware update.

## Gotchas

* **Extract FVEK from RAM.** When a BitLocker volume is mounted, the
  FVEK lives in the kernel's `dumppwd`-reachable memory. Deep View's
  memory-scan plugins can recover it; feed it as `MasterKey(source=...)`.
* **libbde is a C library.** It requires the `libbde-python` pip
  package, which vendors `libbde`. Installing only Deep View without
  the `containers` extra leaves the adapter importable but
  `unlock()` will raise `RuntimeError`.
* **Startup key files (`.BEK`)** are opaque 128-bit or 256-bit raw
  key blobs, not passphrases. Pass the **file path**, not the
  bytes, to `set_startup_key()`.

## Parser

* Implementation: `src/deepview/storage/containers/bitlocker.py`
* Detection class: `BitLockerUnlocker`
* Decrypted layer: `BitLockerDecryptedLayer(DataLayer)` — wraps libbde.
* Heuristic helper: `_looks_like_recovery_password(pw)`.

## References

* [libbde: BitLocker library](https://github.com/libyal/libbde)
* [`libbde-python` (`pybde`) docs](https://github.com/libyal/libbde/wiki/Python-development)
* [Microsoft: "BitLocker technical overview"](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview)
* [Recovery password format explained — Elcomsoft](https://blog.elcomsoft.com/2019/02/bitlocker-recovery-keys/)
* [joachimmetz's FVE structures reference](https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc)
