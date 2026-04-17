# FileVault 2 (Apple disk encryption)

FileVault 2 is Apple's full-volume-encryption stack for macOS. It was
originally built on **Core Storage** (introduced with Lion, 10.7) and
was migrated to **APFS-native encryption** starting with High Sierra
(10.13). A FileVault-protected disk may therefore present itself as
*either*:

1. A **Core Storage** volume, whose volume header carries the ASCII
   magic `"CS"` at offset `0x10` of sector 0.
2. An **APFS** container whose NXSB superblock at offset `0x20` carries
   encryption flags, with key material held in a sibling KEK file.

Deep View's adapter is a **shim over libfvde** (`pyfvde`): detection is
pure-Python and the decryption itself is delegated to the C library,
which handles both variants transparently.

## Signatures

### Core Storage

* **Magic (offset `0x10`, 2 bytes):** `"CS"` (`0x43 0x53`).

The preceding 16 bytes are an unused reserved region + an 8-byte
checksum field.

### APFS encrypted

* **Magic (offset `0x20`, 4 bytes):** `"NXSB"` (`0x4E 0x58 0x53 0x42`).

The preceding 32 bytes are the `obj_phys_t` object header (checksum +
oid + xid + type + subtype).

```python
_CORE_STORAGE_MAGIC = b"CS"
_CORE_STORAGE_MAGIC_OFFSET = 0x10
_APFS_MAGIC = b"NXSB"
_APFS_MAGIC_OFFSET = 0x20
```

Both markers are checked at the same file offset; either match is
treated as a FileVault 2 hit.

## Core Storage volume header (relevant fields)

| Offset  | Size | Field               | Description                                              |
| ------: | ---: | ------------------- | -------------------------------------------------------- |
| `0x000` |  8   | `checksum`          | Fletcher-64 checksum of the remainder of the block.      |
| `0x008` |  8   | `cs_version`        | Core Storage on-disk format version.                     |
| `0x010` |  2   | `cs_magic`          | `"CS"`.                                                  |
| `0x012` |  2   | `block_size`        | Block size (typically 4 096).                            |
| `0x014` |  4   | `flags`             | Volume flags.                                            |
| `0x018` |  8   | `block_count`       | Total blocks in the volume.                              |
| `0x020` | 16   | `volume_uuid`       | UUID of the encrypted volume.                            |
| `0x030` |  8   | `aes_key_index`     | Internal offset to the KEK store.                        |
| `0x038` |  8   | `encryption_ctx_ptr`| Pointer to the encrypted metadata context.               |

## APFS container superblock (NXSB, relevant fields)

| Offset  | Size | Field                | Description                                              |
| ------: | ---: | -------------------- | -------------------------------------------------------- |
| `0x000` | 32   | `obj_phys_t`         | Object header (checksum, oid, xid, type=0x01, subtype).  |
| `0x020` |  4   | `nx_magic`           | `"NXSB"`.                                                |
| `0x024` |  4   | `nx_block_size`      | Block size (4 096 default).                              |
| `0x028` |  8   | `nx_block_count`     | Total blocks.                                            |
| `0x030` |  8   | `nx_features`        | Feature bitmap.                                          |
| `0x038` |  8   | `nx_readonly_compatible_features` |                                             |
| `0x040` |  8   | `nx_incompatible_features`        | Contains `NX_INCOMPAT_FUSION = 0x02`.       |
| `0x048` | 16   | `nx_uuid`            | APFS container UUID.                                     |
| `0x058` |  8   | `nx_next_oid`        | Next object ID.                                          |
| `0x060` |  8   | `nx_next_xid`        | Next transaction ID.                                     |

When `nx_incompatible_features` has `NX_INCOMPAT_FEATURE_ENCRYPTED`
set, the volume is FileVault-encrypted.

## Keys

| Key                         | Role                                                    |
| --------------------------- | ------------------------------------------------------- |
| **User password → KEK**     | PBKDF2-derived key-encryption key. iterations ≈ 41 000 for CS; APFS uses a tunable number stored in the keybag. |
| **KEK → Volume Key**        | Unwraps the volume encryption key. AES-KW (RFC 3394). |
| **Volume Key**              | AES-256-XTS master key; encrypts every sector.         |
| **Recovery Key**            | User-displayed 24-character alphanumeric token that can independently unwrap the volume key. |

## Recovery key format

```
XXXX-XXXX-XXXX-XXXX-XXXX-XXXX    (6 groups × 4 alphanumerics = 24 chars)
```

Deep View's heuristic:

```python
def _looks_like_recovery_key(pw: str) -> bool:
    parts = pw.strip().split("-")
    return len(parts) == 6 and all(len(p) == 4 and p.isalnum() for p in parts)
```

## Detection flow

1. Read the first 4 096 bytes of the volume.
2. Check `head[0x10:0x12] == b"CS"` **or** `head[0x20:0x24] == b"NXSB"`.
3. On match, instantiate a `ContainerHeader`:
   * `format = "filevault2"`
   * `cipher = "aes-xts"`
   * `sector_size = 512`
   * `kdf = "pbkdf2_sha256"`, `kdf_params = {"iterations": 41000, "dklen": 16}`.

These KDF parameters are **orchestration placeholders**; libfvde
reads the actual iteration count from the keybag.

## Unlock flow (via libfvde)

```python
import pyfvde
volume = pyfvde.volume()

volume.open_file_object(file_io)

if isinstance(source, Passphrase):
    pw = source.passphrase
    if looks_like_recovery_key(pw):
        volume.set_recovery_password(pw)
    else:
        volume.set_password(pw)
elif isinstance(source, MasterKey):
    # Raw Volume Key Data (extracted from kernel memory).
    volume.set_volume_key_data(source.key)
elif isinstance(source, Keyfile):
    # libfvde reads the raw file contents as key material.
    raw = Path(source.path).read_bytes()
    volume.set_volume_key_data(raw)

decrypted = FileVaultDecryptedLayer(volume)
```

## Known variations

!!! note "Core Storage → APFS migration"
    Upgrading from HFS+ / Core Storage to APFS on the same disk
    rewrites the container layout. Old disks may still contain
    Core Storage structures interleaved with APFS; libfvde handles
    the discrimination.

!!! note "Fusion drives"
    Apple Fusion drives combine an SSD and an HDD under a single Core
    Storage logical volume group. The encryption layer sits at the
    logical-volume level — a chip-off dump of just the HDD or SSD
    will not be unlockable on its own.

!!! note "T2 / Apple Silicon secure enclave"
    On T2 Macs and Apple Silicon, the password-derived KEK is unwrapped
    inside the Secure Enclave via the **sepOS SKS** process. A direct
    memory dump of macOS userland or the kernel will not find the
    KEK in cleartext. Physical extraction requires Secure Enclave
    exploitation, which is out of scope for Deep View.

!!! warning "Institutional Recovery Key (IRK)"
    Enterprise deployments can install a FileVault IRK keypair that
    unlocks any user's disk. The IRK is a PKCS#12 bundle, not a
    passphrase — pass it via `Keyfile(path=...)`.

## Gotchas

* **Two magic locations.** Check both `0x10` and `0x20` — presence of
  either indicates FileVault 2.
* **Password hashing uses SHA-256 by default** for Core Storage;
  APFS keybags negotiate the hash algorithm at volume creation.
* **`pyfvde` delegates encryption.** Deep View's adapter does no
  crypto itself — if `pyfvde` is not installed, `unlock()` raises
  `RuntimeError` but `detect()` still works.
* **Volume key extraction from memory.** `fseventsd` and
  `cs_blkmgr` retain the volume key in kernel memory while mounted;
  scan `kmem`/`apfs.kext` pages for 32-byte aligned high-entropy
  blocks bracketed by known Apple magic.

## Parser

* Implementation: `src/deepview/storage/containers/filevault2.py`
* Detection class: `FileVault2Unlocker`
* Decrypted layer: `FileVaultDecryptedLayer(DataLayer)`.
* Heuristic helper: `_looks_like_recovery_key(pw)`.

## References

* [libfvde: FileVault library](https://github.com/libyal/libfvde)
* [`libfvde-python` (`pyfvde`) docs](https://github.com/libyal/libfvde/wiki/Python-development)
* [Apple: "About FileVault"](https://support.apple.com/en-us/HT204837)
* [Apple APFS reference](https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf)
* [joachimmetz's Core Storage documentation](https://github.com/libyal/libfvde/blob/main/documentation/Core%20Storage%20(CS)%20format.asciidoc)
