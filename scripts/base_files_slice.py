"""Build a locked Debian or Ubuntu base-files data slice offline."""

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import Request, urlopen


def fetch(inputs, lock_path):
    lock = json.loads(lock_path.read_bytes())
    inputs = Path(inputs)
    inputs.mkdir(parents=True, exist_ok=True)
    for item in lock["sources"] + lock.get("verification_inputs", []):
        name = item["filename"]
        if PurePosixPath(name).name != name or name in ("", ".", ".."):
            raise ValueError("Invalid input filename")
        target = inputs / name
        if target.is_symlink():
            raise ValueError("Source input must not be a symlink: " + name)
        if target.exists():
            data = target.read_bytes()
        else:
            if not item["url"].startswith("https://"):
                raise ValueError("Source URL must use HTTPS")
            with urlopen(Request(item["url"], headers={"User-Agent": "rootloom-source-slice"}), timeout=60) as response:
                if not response.url.startswith("https://"):
                    raise ValueError("Source redirect must use HTTPS")
                data = response.read(item["size"] + 1)
        if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("Source checksum or size mismatch: " + name)
        if not target.exists():
            target.write_bytes(data)


def build(inputs, output, lock_path):
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes)
    inputs, output = Path(inputs), Path(output)
    prefix, vendor = lock["source_root"], lock["vendor"]
    if PurePosixPath(prefix).name != prefix or vendor not in ("debian", "ubuntu"):
        raise ValueError("Invalid source root or vendor")
    if output.exists():
        raise ValueError("Output must not exist")
    verified = []
    materials = lock["sources"] + lock.get("verification_inputs", [])
    for item in materials:
        name = item["filename"]
        if PurePosixPath(name).name != name or name in ("", ".", ".."):
            raise ValueError("Invalid input filename")
        if (inputs / name).is_symlink():
            raise ValueError("Source input must not be a symlink: " + name)
        data = (inputs / name).read_bytes()
        if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("Source checksum or size mismatch: " + name)
        verified.append(data)
    descriptor = verified[0].decode("utf-8")
    archive = lock["sources"][1]
    checksum_line = rf"^ {archive['sha256']} {archive['size']} {re.escape(archive['filename'])}$"
    if not re.search(checksum_line, descriptor, re.MULTILINE):
        raise ValueError("Descriptor does not bind the locked source archive")
    signature = None
    if lock.get("verification_inputs"):
        if len(lock["verification_inputs"]) != 1:
            raise ValueError("Expected one pinned descriptor key")
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "key.asc").write_bytes(verified[2])
            (home / "source.dsc").write_bytes(verified[0])
            subprocess.run(["gpg", "--no-options", "--homedir", tmp, "--batch", "--dearmor", "--output",
                            str(home / "key.gpg"), str(home / "key.asc")], check=True, capture_output=True)
            result = subprocess.run(["gpg", "--no-options", "--homedir", tmp, "--batch", "--no-auto-key-retrieve",
                                     "--no-default-keyring", "--keyring", str(home / "key.gpg"), "--status-fd", "1",
                                     "--verify", str(home / "source.dsc")], check=True, capture_output=True, text=True)
            fingerprint = lock["verification_inputs"][0]["fingerprint"]
            signatures = [line.split() for line in result.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
            if len(signatures) != 1 or signatures[0][-1] != fingerprint:
                raise ValueError("Unexpected descriptor signer")
            signature = {"primary_fingerprint": fingerprint, "status": "verified"}
    elif lock["authentication"]["status"] != "unverified-signature":
        raise ValueError("Signature claim requires a pinned key and verification")

    # Read members directly. Never extract archive paths or follow archive links.
    selected = {}
    with tarfile.open(fileobj=io.BytesIO(verified[1]), mode="r:xz") as source:
        for member in source:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Unsafe source archive path")
            if member.name in selected:
                raise ValueError("Duplicate source archive member")
            parts = path.parts
            keep = len(parts) == 3 and parts[0] == prefix and (
                parts[1] in ("etc", "licenses")
                or member.name in (prefix + "/origins/" + vendor, prefix + "/debian/copyright", prefix + "/debian/rules")
            )
            if not keep:
                continue
            if not member.isfile() or member.size > 1024 * 1024:
                raise ValueError("Invalid retained source member")
            selected[member.name] = source.extractfile(member).read()
    required = {prefix + "/etc/" + name for name in ("debian_version", "host.conf", "issue", "issue.net", "os-release")}
    required |= {prefix + "/licenses/GPL-2", prefix + "/origins/" + vendor, prefix + "/debian/copyright", prefix + "/debian/rules"}
    if vendor == "ubuntu":
        required |= {prefix + "/etc/lsb-release", prefix + "/etc/legal"}
    if not required.issubset(selected):
        raise ValueError("Required source data or recipe is missing")

    rootfs = output / "rootfs"
    output.mkdir(parents=True)
    records = []
    for name, data in sorted(selected.items()):
        _, group, leaf = name.split("/")
        if leaf == "rules" and group == "debian":
            continue
        original_hash = hashlib.sha256(data).hexdigest()
        generated = group == "etc" and leaf in ("issue", "issue.net", "os-release")
        if generated:
            data = data.replace(b"#OSNAME#", b"GNU/Linux")
        if group == "etc":
            dest = "usr/lib/os-release" if leaf == "os-release" else "etc/" + leaf
        elif group == "licenses":
            dest = "usr/share/common-licenses/" + leaf
        elif group == "origins":
            dest = "etc/dpkg/origins/" + leaf
        else:
            dest = "usr/share/doc/base-files/copyright"
        target = rootfs / dest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o644)
        records.append({"path": dest, "type": "file", "mode": "0644", "sha256": hashlib.sha256(data).hexdigest(),
                        "source": name, "source_sha256": original_hash, "archive_sha256": archive["sha256"],
                        "origin": "generated-data" if generated else "source-data"})
    (rootfs / "etc/os-release").symlink_to("../usr/lib/os-release")
    records.append({"path": "etc/os-release", "type": "symlink", "target": "../usr/lib/os-release",
                    "origin": "generated-data", "source": prefix + "/debian/rules"})
    bundle = output / "corresponding-source"
    bundle.mkdir()
    for item, data in zip(materials, verified):
        (bundle / item["filename"]).write_bytes(data)
    (bundle / "source-slice.lock.json").write_bytes(lock_bytes)
    shutil.copyfile(Path(__file__), bundle / "base_files_slice.py")
    manifest = {"schema_version": 1, "image": lock["image"], "scope": lock["scope"], "release_qualified": False,
                "authentication": lock["authentication"], "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
                "recipe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "descriptor_signature": signature,
                "upstream_recipe_sha256": hashlib.sha256(selected[prefix + "/debian/rules"]).hexdigest(), "files": records}
    (output / "source-origins.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fetch-only", action="store_true")
    args = parser.parse_args()
    if args.fetch_only:
        fetch(args.inputs, args.lock)
    elif args.output is None:
        parser.error("--output is required for an offline build")
    else:
        build(args.inputs, args.output, args.lock)
