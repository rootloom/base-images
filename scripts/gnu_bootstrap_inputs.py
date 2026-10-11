"""Acquire locked GNU bootstrap inputs with frozen public-key snapshots."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile
import tempfile

from base_files_slice import fetch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "images/debian-slim"))
from bootstrap import SOURCES
from gcc_bootstrap import MATERIALS, SIGNER

KEYS_SHA256 = "d1c8e308ed317fcf89d7a41d56d5dba7298b0bc338a2cc23bfa7f10578c5d8ad"
PACKAGES = (
    (SOURCES[0], 1855, "https://deb.debian.org/debian/pool/main/b/bison/"),
    (SOURCES[1], 1771, "https://deb.debian.org/debian/pool/main/g/gawk/"),
    (SOURCES[2], 1802, "https://deb.debian.org/debian/pool/main/a/autoconf2.69/"),
    (SOURCES[3], 2227, "https://deb.debian.org/debian/pool/main/q/quilt/"),
    (SOURCES[4], 1762, "https://deb.debian.org/debian/pool/main/p/patchutils/"),
    (SOURCES[5], 290418, "https://security.debian.org/debian-security/pool/updates/main/l/linux/"),
    (SOURCES[6], 7576, "https://deb.debian.org/debian/pool/main/g/glibc/"),
    (("gcc", "14.2.0-19", "", SIGNER, MATERIALS), 47347, "https://deb.debian.org/debian/pool/main/g/gcc-14/"),
)
MATH = (
    ("gmp-6.2.1.tar.bz2", 2493916, "eae9326beb4158c386e39a356818031bd28f3124cf915f8c5b1dc4c7a36b4d7c"),
    ("mpfr-4.1.0.tar.bz2", 1747243, "feced2d430dd5a97805fa289fed3fc8ff2b094c02d05287fd6133e7f1f0ec926"),
    ("mpc-1.2.1.tar.gz", 838731, "17503d2c395dfcf106b622dc142683c1199431d095367c6aacba6eec30340459"),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    args = parser.parse_args()
    keys = ROOT / "images/debian-slim/source-keys.tar.gz"
    if hashlib.sha256(keys.read_bytes()).hexdigest() != KEYS_SHA256:
        raise ValueError("GNU public-key snapshot checksum mismatch")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        lock_path = directory / "inputs.json"
        with tarfile.open(keys) as archive:
            for spec, size, url in PACKAGES:
                materials = spec[4]
                filename, expected = materials[3]
                member = archive.getmember(filename)
                if not member.isfile():
                    raise ValueError("GNU public key must be a regular file")
                data = archive.extractfile(member).read()
                if hashlib.sha256(data).hexdigest() != expected:
                    raise ValueError("GNU public-key checksum mismatch: " + filename)
                (directory / filename).write_bytes(data)
                lock = {"sources": [{"filename": materials[0][0], "sha256": materials[0][1],
                                     "size": size, "url": url + materials[0][0]}],
                        "verification_inputs": [{"filename": filename, "sha256": expected,
                                                 "size": len(data), "local_file": filename}]}
                lock_path.write_text(json.dumps(lock))
                fetch(args.inputs, lock_path)
                descriptor = (args.inputs / materials[0][0]).read_text()
                lock["sources"] = []
                for filename, expected in materials[1:3]:
                    match = re.search(rf"^ {expected} (\d+) {re.escape(filename)}$", descriptor, re.MULTILINE)
                    if not match:
                        raise ValueError("GNU descriptor does not bind archive: " + filename)
                    lock["sources"].append({"filename": filename, "sha256": expected,
                                            "size": int(match[1]), "url": url + filename})
                lock_path.write_text(json.dumps(lock))
                fetch(args.inputs, lock_path)
        lock = {"sources": [{"filename": name, "size": size, "sha256": digest,
                              "url": "https://gcc.gnu.org/pub/gcc/infrastructure/" + name}
                             for name, size, digest in MATH]}
        lock_path.write_text(json.dumps(lock))
        fetch(args.inputs, lock_path)


if __name__ == "__main__":
    main()
