"""Fetch only reviewed lock entries. Never discover or adopt new versions."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlparse


def fetch(lock_path, destination):
    lock = json.loads(Path(lock_path).read_text())
    if lock["schema_version"] != 1:
        raise ValueError("Unsupported source lock schema")
    output = Path(destination)
    output.mkdir(parents=True, exist_ok=True)
    for item in lock["sources"] + lock["patches"] + lock.get("verification_inputs", []):
        url = urlparse(item["url"])
        if url.scheme != "https" or url.hostname not in {
            "musl.libc.org", "busybox.net", "curl.se", "www.openwall.com", "github.com"
        }:
            raise ValueError("Source URL is not an approved primary-source HTTPS endpoint")
        filename = item["filename"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", filename):
            raise ValueError("Unsafe source filename")
        if not re.fullmatch(r"[a-f0-9]{64}", item["sha256"]):
            raise ValueError("Invalid source checksum")
        target = output / filename
        subprocess.run([
            "curl", "--silent", "--show-error", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
            "--retry", "3", "--connect-timeout", "30", "--max-time", "180",
            "--output", str(target), item["url"],
        ], check=True)
        if hashlib.sha256(target.read_bytes()).hexdigest() != item["sha256"]:
            target.unlink()
            raise ValueError(f"Source checksum mismatch: {filename}")
    with tempfile.TemporaryDirectory() as home:
        gpg = ["gpg", "--batch", "--homedir", home, "--no-auto-key-retrieve"]
        key = output / "musl.pub"
        fingerprint = next(x["fingerprint"] for x in lock["verification_inputs"] if x["name"] == "musl-release-key")
        listing = subprocess.check_output(gpg + ["--with-colons", "--show-keys", str(key)], text=True)
        fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
        if not fingerprints or fingerprints[0] != fingerprint:
            raise ValueError("musl signing key fingerprint mismatch")
        subprocess.run(gpg + ["--import", str(key)], check=True)
        status = subprocess.check_output(gpg + ["--status-fd", "1", "--verify", str(output / "musl-1.2.6.tar.gz.asc"), str(output / "musl-1.2.6.tar.gz")], text=True)
        if "[GNUPG:] VALIDSIG " + fingerprint + " " not in status:
            raise ValueError("musl release signature does not match pinned signer")
        (output / "musl-signature-verification.json").write_text(json.dumps({"status": "verified", "fingerprint": fingerprint}, sort_keys=True) + "\n")


if __name__ == "__main__":
    fetch(*sys.argv[1:])
