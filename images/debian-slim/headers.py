"""Install GNU headers and report source matches without runtime admission."""

import json
from pathlib import Path
import subprocess

from origins import input_origin, sha256


def audit_headers(roots, source_files):
    by_hash = {}
    for name, item in source_files.items():
        if Path(name).suffix == ".h":
            by_hash.setdefault(item["sha256"], []).append(name)
    records = []
    for root in roots:
        root = Path(root).resolve()
        if not root.is_dir():
            raise ValueError("Missing installed header tree: " + str(root))
        for path in sorted(root.rglob("*")):
            if path.suffix != ".h" or not path.is_file():
                continue
            if path.is_symlink() and not path.resolve().is_relative_to(root):
                raise ValueError("Installed header symlink escapes its tree")
            digest = sha256(path)
            matches = [{"path": source, "component": input_origin(source, source_files)}
                       for source in by_hash.get(digest, []) if sha256(source) == digest]
            records.append({"path": str(path), "sha256": digest, "sources": matches,
                            "verified": bool(matches)})
    return records


def main():
    evidence = Path("/evidence")
    bootstrap = json.loads((evidence / "bootstrap.json").read_text())
    gcc = json.loads((evidence / "gcc-bootstrap.json").read_text())
    sources = {item["name"]: item for item in bootstrap["sources"]}
    sources["gcc"] = gcc
    source_files = {}
    for name in ("linux", "glibc", "gcc"):
        record = sources[name]
        if not record["completed"]:
            raise ValueError("Source preparation is incomplete: " + name)
        snapshot = evidence / (name + ".source-files.json")
        if sha256(snapshot) != record["source_snapshot_sha256"]:
            raise ValueError("Source snapshot checksum mismatch: " + name)
        index = json.loads(snapshot.read_text())
        if not index or {item["component"] for item in index.values()} != {name}:
            raise ValueError("Unexpected source snapshot component")
        source_files.update(index)
    command = ["make", "install-headers", "install_root=/build/source-sysroot"]
    with (evidence / "gnu-headers.build.log").open("wb") as log:
        subprocess.run(command, cwd="/build/glibc/objects", stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    compiler_headers = subprocess.check_output(
        ["/gnu-bootstrap/bin/gcc", "-print-file-name=include"], text=True).strip()
    headers = audit_headers(["/build/source-sysroot/usr/include", compiler_headers,
                             "/build/linux/linux-6.12.107/usr/include"], source_files)
    retained = evidence / "header-inputs"
    retained.mkdir()
    for header in headers:
        (retained / header["sha256"]).write_bytes(Path(header["path"]).read_bytes())
    report = {"scope": "source-header-audit", "release_qualified": False,
              "commands": [command], "completed": True,
              "headers_verified": bool(headers) and all(item["verified"] for item in headers),
              "headers": headers}
    (evidence / "gnu-headers.json").write_text(json.dumps(report, indent=2) + "\n")
    unknown = [item["path"] for item in headers if not item["verified"]]
    print(json.dumps({"headers": len(headers), "unreviewed_headers": unknown}), flush=True)


if __name__ == "__main__":
    main()
