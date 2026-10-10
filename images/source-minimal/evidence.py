"""Verify output hardening and emit source inventory and build evidence."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def main(arch):
    root = Path("/rootfs")
    lock_bytes = Path("/recipe/sources.lock.json").read_bytes()
    lock = json.loads(lock_bytes)
    if int(os.environ["SOURCE_DATE_EPOCH"]) != lock["source_date_epoch"]:
        raise ValueError("SOURCE_DATE_EPOCH must match the reviewed lock")
    if arch not in lock["supported_architectures"]:
        raise ValueError("Unsupported architecture")
    for name in ["musl", "busybox"]:
        link_map = Path("/evidence/" + name + ".link.map").read_text()
        loaded = [line.removeprefix("LOAD ") for line in link_map.splitlines() if line.startswith("LOAD ")]
        offenders = [line for line in loaded if any(token in line for token in ["libgcc.a", "libgcc_eh.a", "crtbegin", "crtend"])]
        if offenders:
            raise ValueError(f"Bootstrap runtime object in {name} link map: {offenders[:5]}")
        if "/build/compiler-builtins.a" not in loaded:
            raise ValueError(f"Missing source-built compiler runtime in {name} link map")
    for path in root.rglob("*"):
        if not path.is_symlink() and path.stat().st_mode & 0o6000:
            raise ValueError(f"Setuid or setgid output: {path}")
    effective_config = Path("/build/busybox-1.37.0/.config").read_text()
    for key in ["CONFIG_BUSYBOX=y", "CONFIG_ASH=y", "CONFIG_SH_IS_ASH=y", "CONFIG_PIE=y"]:
        if key not in effective_config.splitlines():
            raise ValueError(f"Missing effective config: {key}")
    for key in ["CONFIG_SU=y", "CONFIG_LOGIN=y", "CONFIG_WGET=y", "CONFIG_FEATURE_SH_MATH=y"]:
        if key in effective_config.splitlines():
            raise ValueError(f"Unexpected effective config: {key}")
    for name in ["bin/busybox", "lib/libc.so"]:
        file = root / name
        elf = subprocess.check_output(["readelf", "-hW", "-lW", "-dW", "-sW", str(file)], text=True)
        machine = {"amd64": "Advanced Micro Devices X86-64", "arm64": "AArch64"}[arch]
        if not re.search(r"Machine:\s+" + re.escape(machine) + r"\s*$", elf, re.M):
            raise ValueError(f"ELF architecture mismatch: {name}")
        if not re.search(r"Type:\s+DYN", elf) or "GNU_RELRO" not in elf:
            raise ValueError(f"Missing PIE/shared ELF or RELRO: {name}")
        if "BIND_NOW" not in elf:
            raise ValueError(f"Missing immediate binding: {name}")
        stack = next(line for line in elf.splitlines() if "GNU_STACK" in line)
        if "E" in stack.split()[-2]:
            raise ValueError(f"Executable stack: {name}")
        if name == "bin/busybox" and "__stack_chk_fail" not in elf:
            raise ValueError("BusyBox stack protector is absent")
        if name == "bin/busybox":
            needed = re.findall(r"Shared library: \[(.*?)\]", elf)
            if needed != ["libc.so"]:
                raise ValueError(f"Unexpected runtime libraries: {needed}")
    packages = []
    for item in lock["sources"]:
        refs = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": item["purl"]}]
        if item["cpe"]:
            refs.append({"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": item["cpe"]})
        packages.append({
            "SPDXID": "SPDXRef-" + item["name"], "name": item["name"],
            "versionInfo": item["version"], "downloadLocation": item["url"],
            "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": item["license"],
            "copyrightText": "NOASSERTION", "externalRefs": refs,
            "checksums": [{"algorithm": "SHA256", "checksumValue": item["sha256"]}],
            "comment": "Source archive identity, not distribution package metadata. " + item["verification"],
        })
    lock_hash = hashlib.sha256(lock_bytes).hexdigest()
    inventory = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "rootloom-source-minimal-source-inventory",
        "documentNamespace": "https://rootloom.com/spdx/source-minimal/" + lock_hash + "/" + arch,
        "creationInfo": {"created": "2026-09-18T00:00:00Z", "creators": ["Tool: rootloom-source-minimal"]},
        "packages": packages,
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": p["SPDXID"]} for p in packages],
    }
    evidence = {
        "schema_version": 1, "architecture": arch, "lock_sha256": lock_hash,
        "builder": lock["builder"], "compiler": subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0],
        "compile_network": "none", "source_date_epoch": lock["source_date_epoch"],
        "hardening_verified": ["busybox-pie", "relro", "bind-now", "non-executable-stack", "busybox-stack-protector", "musl-only-linkage"],
        "patches": lock["patches"], "full_compiler_bootstrap": False,
        "source_authenticity": {"musl": json.loads(Path("/downloads/musl-signature-verification.json").read_text()), "busybox": "Reviewed upstream HTTPS checksum; no detached signature supplied.", "compiler-rt-builtins": "Reviewed primary LLVM release asset SHA-256; detached signature not verified.", "patches": "Reviewed upstream advisory HTTPS content, checksum pinned; not signer authenticated.", "ca": "Reviewed dated upstream HTTPS data and checksum."},
        "effective_busybox_config_sha256": hashlib.sha256(effective_config.encode()).hexdigest(),
        "compiler_runtime": {"name": "compiler-rt-builtins", "version": "23.1.3", "bootstrap_libgcc": False, "bootstrap_crtbegin_crtend": False},
        "rootfs_checksum_scope": "Normalized GNU tar of /rootfs, excluding usr/share/rootloom/rootfs.sha256; before embedding checksum.",
        "coverage": "Source inventory only. No vulnerability scan or FIPS validation is implied.",
    }
    for name, value in [("source-inventory.spdx.json", inventory), ("build-evidence.json", evidence)]:
        data = json.dumps(value, indent=2, sort_keys=True) + "\n"
        (Path("/evidence") / name).write_text(data)
        (root / "usr/share/rootloom" / name).write_text(data)
    for destination in [Path("/evidence/sources.lock.json"), root / "usr/share/rootloom/sources.lock.json"]:
        destination.write_bytes(lock_bytes)


if __name__ == "__main__":
    main(sys.argv[1])
