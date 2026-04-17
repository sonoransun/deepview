# LUKS2 on-disk format

LUKS2 is the current Linux disk-encryption container format — default
in `cryptsetup` 2.0+ (2018). It replaces LUKS1's fixed 592-byte
header with a **4 096-byte binary prefix + a JSON metadata blob**.
The JSON describes keyslots, segments, digests, and tokens; slots are
no longer capped at 8, Argon2 can replace PBKDF2, and the layout is
forward-extensible.

The *binary* prefix is always 4 096 bytes; the overall header size
(binary + JSON + padding) is stored in the binary prefix as
`hdr_size` and is typically 16 KiB — two copies of the header live
at offsets 0 and 16 384, providing atomic updates.

## Signature

* **Magic (offset `0x00`, 6 bytes):** `"LUKS\xba\xbe"`.
* **Version (offset `0x06`, BE `uint16_t`):** `2`.

Deep View recognises a LUKS2 container by reading the first 8 bytes
and dispatching on the version.

## Binary header (4 096 bytes, big-endian)

| Offset  | Size | Field          | Description                                                     |
| ------: | ---: | -------------- | --------------------------------------------------------------- |
| `0x000` |  6   | `magic`        | `"LUKS\xba\xbe"`.                                               |
| `0x006` |  2   | `version`      | `2`.                                                            |
| `0x008` |  8   | `hdr_size`     | Total header size (binary + JSON + padding). Typical: `0x4000`. |
| `0x010` |  8   | `seqid`        | Monotonic update sequence (drives atomic swap between two header copies). |
| `0x018` | 48   | `label`        | NUL-padded UTF-8 user label.                                    |
| `0x048` | 32   | `csum_alg`     | Checksum algorithm name, e.g. `"sha256"`.                       |
| `0x068` | 64   | `salt`         | Random salt used for the header checksum computation.           |
| `0x0A8` | 40   | `uuid`         | ASCII UUID, NUL-padded.                                         |
| `0x0D0` | 48   | `subsystem`    | Subsystem tag (e.g. `"CRYPT"`) for kernel dispatch.             |
| `0x100` |  8   | `hdr_offset`   | Byte offset of **this** header copy within the device.          |
| `0x108` |184   | *reserved*     | Zero-filled. Do not interpret.                                  |
| `0x1C0` | 64   | `csum`         | Hash of the binary header (zeroed for the computation) + JSON.  |
| `0x200` | 3584 | *padding*      | Zero-filled to 4 096 bytes total.                               |

## JSON metadata blob

Starts at offset `0x200` of the binary header (offset 512 in the file)
and extends to `hdr_size - 4096` bytes (when combined with the 4 096-
byte binary prefix == `hdr_size`). UTF-8-encoded, NUL-padded on the
right.

**Top-level keys:**

| Key            | Type               | Description                                                 |
| -------------- | ------------------ | ----------------------------------------------------------- |
| `keyslots`     | object             | Mapping of stringified integers → keyslot descriptors.      |
| `tokens`       | object             | Mapping of stringified integers → token descriptors.        |
| `segments`     | object             | Mapping of stringified integers → segment descriptors.      |
| `digests`      | object             | Mapping of stringified integers → digest descriptors.       |
| `config`       | object             | Global configuration (JSON size, flags, requirements).      |

### `keyslots[id]`

```json
{
    "type": "luks2",
    "key_size": 64,
    "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
    "area": {
        "type": "raw",
        "offset": "32768",
        "size": "258048",
        "encryption": "aes-xts-plain64",
        "key_size": 64
    },
    "kdf": {
        "type": "argon2id",
        "time": 4,
        "memory": 1048576,
        "cpus": 4,
        "salt": "<base64>"
    },
    "priority": 1
}
```

| Field         | Description                                                                     |
| ------------- | ------------------------------------------------------------------------------- |
| `type`        | `"luks2"` for passphrase slots; future types reserved.                          |
| `key_size`    | Master key size in bytes (combined across cascade; 64 for AES-256-XTS).         |
| `af`          | AF splitter — `stripes` and `hash` match LUKS1 semantics.                        |
| `area`        | Where the split keyslot material lives and which cipher/mode encrypts it.       |
| `kdf`         | KDF parameters: `pbkdf2` (with `hash`, `iterations`, `salt`) or `argon2i`/`argon2id` (with `time`, `memory`, `cpus`, `salt`). |
| `priority`    | 0..3; higher values unlock first.                                                |

### `segments[id]`

```json
{
    "type": "crypt",
    "offset": "16777216",
    "size": "dynamic",
    "iv_tweak": "0",
    "encryption": "aes-xts-plain64",
    "sector_size": 512
}
```

| Field         | Description                                                                     |
| ------------- | ------------------------------------------------------------------------------- |
| `type`        | `"crypt"` for encrypted data segments.                                          |
| `offset`      | Byte offset into the device where the plaintext begins (string-encoded integer).|
| `size`        | Bytes in the segment; `"dynamic"` means "to end of device".                     |
| `iv_tweak`    | IV tweak offset added to the sector index.                                      |
| `encryption`  | Cipher spec string, e.g. `"aes-xts-plain64"`.                                   |
| `sector_size` | Sector size in bytes (almost always 512).                                       |

### `digests[id]`

```json
{
    "type": "pbkdf2",
    "keyslots": ["0", "1"],
    "segments": ["0"],
    "hash": "sha256",
    "iterations": 100000,
    "salt": "<base64>",
    "digest": "<base64>"
}
```

Used to verify that a candidate master key recovered from any
referenced keyslot matches the corresponding segments.

### `tokens[id]`

Variable-schema objects describing external unlocker mechanisms
(systemd-cryptenroll TPM2 bindings, FIDO2, LUKS2 keyrings). The
built-in types are:

| `type`                       | Purpose                                                 |
| ---------------------------- | ------------------------------------------------------- |
| `luks2-keyring`              | Unlock via keyring-stored passphrase.                   |
| `systemd-tpm2`               | TPM2 sealed key.                                        |
| `systemd-fido2`              | FIDO2 hardware token.                                   |
| `systemd-recovery`           | Recovery key.                                           |

## Body layout

```
offset 0x00000:  [--- 4 KiB binary header (primary copy)  ---]
offset 0x00200:  [--- JSON metadata (primary)             ---]
offset 0x04000:  [--- 4 KiB binary header (secondary copy) ---]
offset 0x04200:  [--- JSON metadata (secondary)           ---]
offset 0x08000+: [--- keyslot areas (per keyslots[i].area.offset) ---]
offset segments[0].offset: [--- encrypted payload ---]
```

## Addressing

1. Parse the binary prefix at offset 0 to find `hdr_size`.
2. Read `json_blob = raw[512 : hdr_size]`, strip trailing NULs,
   decode UTF-8, parse as JSON.
3. For each active keyslot:
   1. `pwkey = KDF(passphrase, kdf.salt, kdf.time/iterations, kdf.memory, kdf.cpus)`.
   2. Read `encrypted_area = read(area.offset, area.size)`.
   3. Decrypt with `area.encryption`, then AF-merge with `af.stripes`.
   4. Verify via `digests[i]` referencing the keyslot.
4. Master key unlocks `segments[0]` using `segments[0].encryption`
   at `segments[0].offset`.

## Known variations

!!! note "Argon2id vs PBKDF2"
    LUKS2 defaults to **Argon2id** since cryptsetup 2.3. PBKDF2 is
    still accepted for legacy systems. Deep View dispatches on
    `kdf.type` and offloads both to `OffloadEngine`.

!!! note "Reencryption in progress"
    Online reencryption (`--online` mode) adds a
    `requirements.mandatory = ["online-reencrypt"]` entry under
    `config`. The on-disk layout is still valid; the segment list
    simply has more entries describing the old and new cipher.

!!! warning "Detached headers"
    `cryptsetup luksHeaderBackup` produces a standalone 16 KiB header
    file. Unlock with `--header` refers to this file; segment
    offsets are then interpreted against the *data device*, not
    the header file.

!!! warning "Header corruption of one copy"
    Two identical header copies exist at offsets 0 and 16 384. If one
    is corrupted, `cryptsetup` recovers from the other via `seqid`
    comparison. Deep View currently only reads the primary copy.

## Gotchas

* **Integers in JSON are strings.** `offset`, `size`, `iv_tweak`, and
  `key_size` are sometimes strings (`"16777216"`) because 64-bit
  values can exceed JSON's safe integer range on JS-based consumers.
  Coerce with `int(s, 10)`.
* **Salt / digest fields are base64-encoded.** Decode before using.
* **`segments[i].size == "dynamic"`** means "run to the end of the
  backing device"; compute `data_length = device_size - segment.offset`.
* **Binary header is big-endian** but `iv_tweak` / sector counters
  used inside the KDF are little-endian. Don't conflate.

## Parser

* Implementation: `src/deepview/storage/containers/luks.py`
* Binary header class: `_LUKS2Header`
* Function: `_parse_luks2(raw: bytes) -> _LUKS2Header`
* Helper: `_luks2_first_segment(json_data: dict) -> dict`

## References

* [LUKS2 On-Disk Format Specification v1.1.0](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS2-docs)
* [cryptsetup source tree](https://gitlab.com/cryptsetup/cryptsetup)
* [Argon2 PHC (RFC 9106)](https://datatracker.ietf.org/doc/rfc9106/)
* [`systemd-cryptenroll(1)` — TPM2/FIDO2 token binding](https://www.freedesktop.org/software/systemd/man/systemd-cryptenroll.html)
