# VeraCrypt / TrueCrypt volume format

VeraCrypt (a maintained fork of the discontinued TrueCrypt) stores a
fully encrypted disk in a **65 536-byte sector-aligned header** followed
by the encrypted payload. Unlike LUKS / BitLocker / FileVault 2, the
VeraCrypt on-disk header gives away **no** information about the PRF
or cipher cascade used — the only way to determine them is **trial
decryption**. A successful decryption is recognised by the `"VERA"`
(or `"TRUE"`) magic string + a CRC32 that matches, inside the 448-byte
plaintext that sits at header offset `0x40` after the salt.

A **hidden volume** is a second, independent VeraCrypt volume whose
header sits at the tail of the outer volume; modern volumes place it
at `total_size - 65 536`, legacy volumes at `total_size - 131 072`. A
hidden volume's passphrase is cryptographically independent from the
outer volume's; you cannot prove a hidden volume exists without
knowing its passphrase — this is the plausible-deniability feature.

## File structure

```
offset 0x00000:     [---------- 65 536-byte VeraCrypt header ----------]
                    | 64-byte salt (unencrypted)                       |
                    | 448-byte encrypted header (magic+crcs+meta+keys) |
                    | 65 024 bytes padding (random)                    |
offset 0x10000:     [---------- encrypted payload ----------]
                    | AES-XTS / Serpent-XTS / Twofish-XTS /            |
                    | cascades thereof, sector-addressed               |

(tail, hidden volume if present)
offset size-0x10000: [---------- 65 536-byte hidden volume header ----]
```

## Header layout (65 536 bytes, after decryption)

The **first 64 bytes** are the salt — plaintext. The **next 448 bytes**
are the VeraCrypt-encrypted header. The remaining 65 024 bytes are
random padding (or the hidden volume's encrypted keyslot, depending on
volume flags).

| Offset | Size | Field         | Description                                                  |
| -----: | ---: | ------------- | ------------------------------------------------------------ |
| `0x00` | 64   | `salt`        | PBKDF2 salt fed to the chosen PRF.                            |
| `0x40` | 448  | `enc_header`  | Encrypted with `(header_enc_key, header_tweak_key)` under XTS mode, sector 0. |

Inside the decrypted 448 bytes (all multi-byte values **big-endian**):

| Offset | Size | Field                   | Description                                               |
| -----: | ---: | ----------------------- | --------------------------------------------------------- |
| `0x00` |  4   | `magic`                 | `"VERA"` (VeraCrypt) or `"TRUE"` (TrueCrypt).             |
| `0x04` |  2   | `version`               | Header format version.                                    |
| `0x06` |  2   | `required_version`      | Minimum version required to mount.                        |
| `0x08` |  4   | `crc_keys`              | CRC32 of `master_key_material` (bytes `0xC0..0x1BF`).     |
| `0x0C` | 16   | *reserved*              | Zero.                                                     |
| `0x1C` |  8   | `hidden_volume_size`    | Size of the hidden volume if present (outer header only). |
| `0x24` |  8   | `volume_size`           | Total volume size in bytes.                               |
| `0x2C` |  8   | `encrypted_area_start`  | Byte offset where the encrypted payload starts.           |
| `0x34` |  8   | `encrypted_area_size`   | Number of bytes encrypted.                                |
| `0x3C` |  4   | `flag_bits`             | Flags (system enc, TrueCrypt-mode, etc).                  |
| `0x40` |  4   | `sector_size`           | Sector size (512 or 4 096).                               |
| `0x44` | 120  | *reserved*              | Zero.                                                     |
| `0xBC` |  4   | `crc_data`              | CRC32 over bytes `0x00 .. 0xBB` (this header prefix).     |
| `0xC0` | 256  | `master_keys`           | Cipher-cascade-specific master + tweak keys.              |

Constants used by the parser:

```python
_HEADER_SIZE = 65_536
_SALT_LEN = 64
_ENCRYPTED_HEADER_LEN = 448
_KEY_AREA_LEN = 256
_MAGIC_VERACRYPT = b"VERA"
_MAGIC_TRUECRYPT = b"TRUE"
```

## Key derivation

```
header_key = PBKDF2(PRF, passphrase, salt, iterations, 64)
```

The PRF is one of **SHA-512**, **SHA-256**, **Whirlpool**,
**Streebog**, or **RIPEMD-160**. The iteration count is a function of
the PRF, the **PIM** (Personal Iterations Multiplier), and whether
this is a system-encryption (pre-boot) volume:

### Non-system encryption (the default)

| PRF         | Iterations formula                  |
| ----------- | ----------------------------------- |
| SHA-512     | `500_000 + pim * 1000`              |
| SHA-256     | `500_000 + pim * 1000`              |
| Whirlpool   | `500_000 + pim * 1000`              |
| Streebog    | `500_000 + pim * 1000`              |
| RIPEMD-160  | `655_331 + pim * 15_331`            |

When `pim == 0` the formulas collapse to: `500 000` for SHA/Whirlpool/
Streebog, `655 331` for RIPEMD-160.

### System encryption (pre-boot)

| PRF         | Iterations formula                  |
| ----------- | ----------------------------------- |
| SHA-512     | `200_000 + pim * 2048`              |
| SHA-256     | `200_000 + pim * 2048`              |
| Whirlpool   | `200_000 + pim * 2048`              |
| Streebog    | `200_000 + pim * 2048`              |
| RIPEMD-160  | `327_661 + pim * 15_331`            |

With `pim == 0`: `200 000` for SHA/Whirlpool/Streebog, `327 661` for
RIPEMD-160.

### Legacy TrueCrypt

TrueCrypt uses a fixed low iteration count and does not honour PIM:

| PRF         | Non-boot | System / Boot |
| ----------- | -------: | ------------: |
| RIPEMD-160  |    2 000 |         1 000 |
| SHA-512     |    1 000 |         1 000 |
| Whirlpool   |    1 000 |         1 000 |

Source: `deepview.storage.containers._kdf_table`.

## Cipher cascades

The derived 64-byte `header_key` is split as `aes_key (32) ||
tweak_key (32)` and used to decrypt the 448-byte encrypted header in a
single XTS unit with sector index 0. For cascades, the header is
decrypted **last cipher first** (the outermost encryption listed in
`ciphers` was applied first on write).

Declared cascades (`deepview.storage.containers._cipher_cascades`):

| Cascade                 | Ciphers (outermost first) | Key bytes | Decrypt wired? |
| ----------------------- | -------------------------- | --------: | :------------: |
| `aes-xts`               | AES                        | 64        | ✓              |
| `serpent-xts`           | Serpent                    | 64        | —              |
| `twofish-xts`           | Twofish                    | 64        | —              |
| `aes-twofish-xts`       | AES → Twofish              | 128       | —              |
| `serpent-aes-xts`       | Serpent → AES              | 128       | —              |
| `twofish-serpent-xts`   | Twofish → Serpent          | 128       | —              |
| `aes-twofish-serpent-xts` | AES → Twofish → Serpent  | 192       | —              |
| `serpent-twofish-aes-xts` | Serpent → Twofish → AES  | 192       | —              |

Only AES-XTS has a real backend today (via `cryptography`'s
`modes.XTS`). The remaining cascades are listed for detection but
`decrypt_header()` raises `NotImplementedError` until a Serpent /
Twofish primitive is wired.

## Validation (false-positive control)

After decrypting, Deep View runs:

1. **Magic check.** `plaintext[0:4] == b"VERA"` (or `b"TRUE"` for
   TrueCrypt-mode).
2. **Inner CRC32.** `crc32(plaintext[0:188]) == plaintext[188:192]` (BE).
3. **Key-area CRC32.** `crc32(plaintext[192:448]) == plaintext[8:12]` (BE).

Any mismatch rejects the candidate. The cumulative probability of an
accidental hit per (PRF × cascade) trial is `~2^-32` from the inner
CRC alone; adding the key-area CRC and the 4-byte magic drops it to
astronomically small.

## Hidden volume

If present, the hidden volume's 65 536-byte header sits at **the tail**
of the outer volume:

| Variant  | Tail offset                  |
| -------- | ---------------------------- |
| Modern   | `total_size - 65 536`        |
| Legacy   | `total_size - 131 072`       |

Try both during detection when `try_hidden=True`.

## Known variations

!!! note "System encryption has fewer iterations"
    Pre-boot unlock must complete in under a few hundred ms on modest
    hardware, so iteration counts are an order of magnitude smaller.
    Don't cross-wire the two tables.

!!! note "PIM = 0 defaults"
    When the user did not specify a PIM, VeraCrypt uses the **base
    constants** (`500_000` etc.), not `base + 0 * 1000`. The
    difference matters only if you pre-compute tables.

!!! warning "TrueCrypt parity"
    VeraCrypt volumes created with "TrueCrypt mode" use the `"TRUE"`
    magic and fixed TrueCrypt iteration counts. The trial-decrypt
    engine must enumerate both iteration tables.

!!! warning "Corrupted headers"
    VeraCrypt writes a backup header at the tail of the volume (at
    `total_size - 65 536` for non-hidden, mirroring the hidden
    volume's location). If the primary header is corrupted, fall
    back to the backup.

## Gotchas

* **448-byte decrypt is a single XTS unit.** Do not decrypt 448 bytes
  as three 512-byte sectors — VeraCrypt uses `sector_index = 0` and a
  single call, which matches `cryptography.hazmat.primitives.ciphers.modes.XTS`
  when fed a 16-byte zero tweak.
* **Scalars are big-endian** inside the 448-byte blob. Unlike the
  memory formats, use `>H`, `>I`, `>Q`.
* **Trial decryption is expensive.** Every PRF × cascade × iteration
  combination is a PBKDF2 derivation; Deep View always offloads to
  `OffloadEngine`. Per-failure cost is one CRC32.
* **Offload iteration count** can be reduced for fixture tests by
  passing `override_iterations=`. Never use this in production.

## Parser

* Implementation: `src/deepview/storage/containers/veracrypt.py`
* Dataclass: `_ParsedHeader(magic, version, hidden_volume_size, volume_size, encrypted_area_start, encrypted_area_size, flags, sector_size, crc_data, crc_keys, master_key_material)`
* Parse function: `_parse_header(plaintext, expected_magic)`
* KDF table: `src/deepview/storage/containers/_kdf_table.py`
* Cipher cascades: `src/deepview/storage/containers/_cipher_cascades.py`

## References

* [VeraCrypt documentation: Volume Format Specification](https://veracrypt.eu/en/VeraCrypt%20Volume%20Format%20Specification.html)
* [VeraCrypt source: `Common/Volumes.c`](https://github.com/veracrypt/VeraCrypt)
* [TrueCrypt 7.1a Volume Format Specification (historical)](https://www.truecrypt71a.com/documentation/)
* [Argon2 considerations for disk encryption — discussion](https://crypto.stackexchange.com/questions/)
* [Elcomsoft: "VeraCrypt: Breaking the Encryption"](https://blog.elcomsoft.com/2017/04/accessing-veracrypt-and-truecrypt-volumes/)
