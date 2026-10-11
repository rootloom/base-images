"""Build Debian GNU compiler/runtime helpers for temporary bootstrap only."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile

from bootstrap import verify_source


SIGNER = "D56571B88A8BBAF140BF63D6BD7EAA60778FA6F5"
MATERIALS = (
    ("gcc-14_14.2.0-19.dsc", "7db1e202cce66617e9134a662c877a3a773de5b612fd52179815877e0ecfb847"),
    ("gcc-14_14.2.0.orig.tar.gz", "e162a5ef3f0077ecae598c6556908d2ab80841532df3398072a96a6df6e6aa29"),
    ("gcc-14_14.2.0-19.debian.tar.xz", "31cbab4bafa48aa1c540497bd8098cbcf98e673778f927651ed944709f687781"),
    ("debian-gcc-source-key.asc", "2593077d65942a9636a5f22a92a3d0428f1c6a313cd9412f3149d9ab9cf4413a"),
)
PREREQUISITES = ("gmp-6.2.1.tar.bz2", "mpfr-4.1.0.tar.bz2", "mpc-1.2.1.tar.gz")


def main():
    from origins import snapshot_sources

    inputs, directory, evidence = Path("/inputs"), Path("/build/gcc"), Path("/evidence")
    directory.mkdir()
    primary = verify_source(inputs, directory, SIGNER, MATERIALS)
    with tarfile.open(inputs / MATERIALS[1][0]) as archive:
        archive.extractall(directory, filter="data")
    source = directory / "gcc-14-14.2.0"
    with tarfile.open(inputs / MATERIALS[2][0]) as archive:
        archive.extractall(source, filter="data")
    architecture = {"aarch64": "arm64", "x86_64": "amd64"}[os.uname().machine]
    vendor = ["make", "-f", "debian/rules", "distribution=Debian", "derivative=Debian",
              "distrelease=trixie", "DEB_BUILD_OPTIONS=lang=c nostrap nolto nopgo",
              "DEB_TARGET_ARCH=" + architecture]
    commands = [vendor + ["unpack"], vendor + ["patch"]]
    objects = directory / "objects"
    objects.mkdir()
    commands += [[str(source / "src/configure"), "--prefix=/gnu-bootstrap", "--disable-bootstrap",
                  "--enable-languages=c", "--disable-multilib", "--disable-libsanitizer",
                  "--disable-libgomp", "--disable-libquadmath", "--disable-libatomic",
                  "--enable-default-pie", "--enable-default-ssp", "--disable-nls",
                  # Debian's non-mutex linker branch requires /usr/bin/time.
                  "--enable-link-mutex"],
                 ["make", "-j2", "all-gcc", "all-target-libgcc"],
                 ["make", "install-gcc", "install-target-libgcc"]]
    record = {"name": "gcc", "version": "14.2.0-19", "materials": dict(MATERIALS),
              "signing_fingerprint": SIGNER, "primary_fingerprint": primary,
              "scope": "temporary-bootstrap", "release_qualified": False,
              "bootstrap_headers_and_runtime_allowed": True, "commands": commands,
              "completed": False}
    receipt = evidence / "gcc-bootstrap.json"
    receipt.write_text(json.dumps(record, indent=2) + "\n")
    with (evidence / "gcc-bootstrap.build.log").open("wb") as log:
        for index, command in enumerate(commands):
            print("Building gcc", command, flush=True)
            result = subprocess.run(command, cwd=source if index < 2 else objects,
                                    stdout=log, stderr=subprocess.STDOUT)
            if result.returncode:
                print((evidence / "gcc-bootstrap.build.log").read_text(errors="replace")[-12000:], flush=True)
                raise RuntimeError("GNU compiler bootstrap command failed")
            if index == 1:
                patches = source / "debian/patches"
                record["patches"] = [{"path": line.split()[0], "sha256": hashlib.sha256(
                    (patches / line.split()[0]).read_bytes()).hexdigest()}
                    for line in (patches / "series").read_text().splitlines() if line.strip()]
                record["distro_defaults_sha256"] = hashlib.sha256(
                    (source / "src/gcc/distro-defaults.h").read_bytes()).hexdigest()
                snapshot = evidence / "gcc.source-files.json"
                snapshot_sources({source / "src": "gcc"}, snapshot)
                record["source_snapshot_sha256"] = hashlib.sha256(snapshot.read_bytes()).hexdigest()
                manifest = source / "src/contrib/prerequisites.sha512"
                expected = {filename: checksum for checksum, filename in
                            (line.split() for line in manifest.read_text().splitlines())}
                record["prerequisites_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
                record["prerequisites"] = {}
                for filename in PREREQUISITES:
                    actual = hashlib.sha512((inputs / filename).read_bytes()).hexdigest()
                    if actual != expected[filename]:
                        raise ValueError("GCC prerequisite checksum mismatch: " + filename)
                    with tarfile.open(inputs / filename) as archive:
                        archive.extractall(source / "src", filter="data")
                    package = filename.split(".tar.")[0]
                    (source / "src" / package.split("-", 1)[0]).symlink_to(package, target_is_directory=True)
                    record["prerequisites"][filename] = {"sha512": actual, "binding": str(manifest.relative_to(source))}
                receipt.write_text(json.dumps(record, indent=2) + "\n")
    record["completed"] = True
    receipt.write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
