# LUKS1 on-disk format

LUKS1 ("Linux Unified Key Setup", version 1) is the legacy Linux
full-disk-encryption container used by `cryptsetup` before LUKS2
became default in 2018. A LUKS1 container starts with a **592-byte
big-endian header** containing the master-key digest, 8 fixed-size
**key slots**, and pointers into an encrypted payload that follows.
Every active key slot holds an AF-split, PBKDF2-stretched, cipher-
decrypted copy of the master key.

## Signature

* **Magic (offset `0x00`, 6 bytes):** `"LUKS\xba\xbe"` — the ASCII
  prefix `LUKS` followed by `0xBA 0xBE`.
* **Version (offset `0x06`, big-endian `uint16_t`):** `1` for LUKS1,
  `2` for LUKS2.

```python
LUKS_MAGIC = b"LUKS\xba\xbe"     # 6 bytes
LUKS1_HEADER_SIZE = 592
```

## Header layout (big-endian)

| Offset  | Size | Field             | Description                                                              |
| ------: | ---: | ----------------- | ------------------------------------------------------------------------ |
| `0x000` |  6   | `magic`           | `"LUKS\xba\xbe"`.                                                        |
| `0x006` |  2   | `version`         | `1`.                                                                     |
| `0x008` | 32   | `cipher_name`     | NUL-padded ASCII, e.g. `"aes"`, `"serpent"`, `"twofish"`.                |
| `0x028` | 32   | `cipher_mode`     | NUL-padded, e.g. `"xts-plain64"`, `"cbc-essiv:sha256"`, `"cbc-plain64"`. |
| `0x048` | 32   | `hash_spec`       | NUL-padded, e.g. `"sha256"`, `"sha512"`, `"ripemd160"`.                  |
| `0x068` |  4   | `payload_offset`  | Offset of encrypted payload, **in 512-byte sectors**.                    |
| `0x06C` |  4   | `key_bytes`       | Master-key size in bytes: typically 32 or 64.                            |
| `0x070` | 20   | `mk_digest`       | SHA-1 (or `hash_spec`-derived) digest of the master key.                 |
| `0x084` | 32   | `mk_digest_salt`  | Salt fed to the KDF when producing `mk_digest`.                          |
| `0x0A4` |  4   | `mk_digest_iter`  | PBKDF2 iteration count for the master-key digest.                        |
| `0x0A8` | 40   | `uuid`            | ASCII UUID, NUL-padded. Survives keyslot rotation.                       |
| `0x0D0` | 48×8 | `keyslot[0..7]`   | 8 keyslot descriptors, 48 bytes each. See below.                         |
| `0x250` |  —   | *end of header*   | Total: 592 bytes.                                                        |

## Keyslot descriptor (48 bytes)

| Offset | Size | Field                   | Description                                                    |
| -----: | ---: | ----------------------- | -------------------------------------------------------------- |
| `+0x00`|  4   | `active`                | `0x00AC71F3` if in use; `0x0000DEAD` if empty.                  |
| `+0x04`|  4   | `iterations`            | PBKDF2 iterations for this keyslot's passphrase.                |
| `+0x08`| 32   | `salt`                  | Per-keyslot PBKDF2 salt.                                        |
| `+0x28`|  4   | `key_material_offset`   | Sector offset of the AF-split keyslot material (512-byte units).|
| `+0x2C`|  4   | `stripes`               | AF (anti-forensic) stripe count; spec value is **4000**.        |

Constants:

```python
ACTIVE   = 0x00AC71F3   # LUKS1 _active_ keyslot marker
INACTIVE = 0x0000DEAD
LUKS1_KEYSLOT_COUNT = 8
LUKS1_STRIPES = 4000    # AF stripes (== 4000 for every LUKS1 keyslot)
```

## Body layout

```
 offset 0:          +------------------------------+
                    | LUKS1 header (592 bytes)     |
                    | magic, cipher, hashes, MKD,  |
                    | 8 keyslot descriptors        |
                    +------------------------------+
 offset varies:     | Keyslot material             |
   (per keyslot)    | (key_bytes × stripes = 128 KiB@32B + 4000 stripes)  |
                    | AF-split, cipher-encrypted   |
                    +------------------------------+
 payload_offset*512:| Encrypted payload            |
                    | sectorwise XTS/CBC with IV   |
                    | derived from sector index    |
                    +------------------------------+
```

## AF-split (anti-forensic splitter)

The master key `mk[key_bytes]` is expanded to `key_bytes × stripes`
bytes ( = 4000 × 32 = 128 KiB for AES-256) via the AF algorithm
described in Peter Gutmann's "A Cryptographically Secure Pseudorandom
Number Generator". The resulting buffer is **encrypted with the
keyslot's passphrase-derived key** and stored at
`key_material_offset × 512`.

Decoding a keyslot:

1. `pwkey = PBKDF2(passphrase, keyslot.salt, keyslot.iterations, key_bytes, hash_spec)`.
2. `encrypted = layer.read(keyslot.key_material_offset * 512, key_bytes * stripes)`.
3. `stripe_buf = cipher.decrypt(pwkey, encrypted)` using
   `(cipher_name, cipher_mode)` with IV=0 for each 512-byte sector.
4. `candidate_mk = AF_merge(stripe_buf, key_bytes, stripes)`
   (stored in `deepview.storage.containers._af_split.af_merge`).
5. Check: `PBKDF2(candidate_mk, mk_digest_salt, mk_digest_iter, len(mk_digest), hash_spec) == mk_digest`.
6. If yes, `candidate_mk` is the master key — use it to decrypt the
   payload at `payload_offset * 512`.

## Cipher modes

LUKS1's `cipher_mode` strings decode to Deep View's
`DecryptedVolumeLayer` mode + IV derivation:

| `cipher_mode`           | Layer mode     | IV derivation         |
| ----------------------- | -------------- | --------------------- |
| `xts-plain64`           | `xts`          | `tweak` (sector index)|
| `cbc-essiv:sha256`      | `cbc-essiv`    | `essiv-sha256`        |
| `cbc-plain64`           | `cbc-plain64`  | `plain64`             |
| `ctr-plain`             | `ctr`          | `plain64`             |

## Known variations

!!! note "Detached headers"
    `cryptsetup --header` stores the LUKS1 header in a separate file
    from the payload. The `payload_offset` field becomes a logical
    offset into the data device, not the header file — the orchestrator
    (`unlock.py`) handles this case when a detached header is supplied.

!!! note "`hash_spec` variants"
    `"sha256"` is the canonical default from cryptsetup 1.6+. Older
    installations use `"ripemd160"` or `"sha1"`. Deep View supports
    all of these at the PBKDF2 level via `hashlib`.

!!! warning "`active` field values"
    The "active" constant is `0x00AC71F3` — literally ASCII `"ΑC7/"`
    misinterpreted — and the "inactive" constant is `0x0000DEAD`.
    Any other value indicates corruption; treat the keyslot as
    empty and move to the next one.

!!! warning "Stripes != 4000"
    LUKS1 locks `stripes` at 4000. If a LUKS1 header reports anything
    else, it is either a buggy fork or corruption. Deep View reads
    the value faithfully but no supported implementation ever writes
    a non-4000 value.

## Gotchas

* **Big-endian scalars.** Unlike every memory format in this docs
  set, LUKS1 scalars are **big-endian**. Use `>H`, `>I`, `>Q` or
  equivalent when touching the header.
* **Payload offset is in sectors, not bytes.** Multiply by 512 before
  seeking.
* **Master-key digest uses PBKDF2, not a bare hash.** The salt and
  iteration count are in the header; the digest length is
  `len(mk_digest) = 20` regardless of the hash algorithm.

## Parser

* Implementation: `src/deepview/storage/containers/luks.py`
* Header class: `_LUKS1Header`
* Keyslot class: `_LUKS1Keyslot`
* Function: `_parse_luks1(raw: bytes) -> _LUKS1Header`
* AF helpers: `src/deepview/storage/containers/_af_split.py`

## References

* [LUKS1 On-Disk Format Specification v1.2.3](https://gitlab.com/cryptsetup/cryptsetup/-/raw/main/docs/on-disk-format.pdf)
* [Peter Gutmann — AFsplit algorithm rationale](https://www.cypherpunks.to/~peter/)
* [`cryptsetup` man page](https://man.archlinux.org/man/cryptsetup.8)
* [LUKS1 source: `lib/luks1/luks.h`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/lib/luks1/luks.h)
