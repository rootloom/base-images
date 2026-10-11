"""Install GNU headers and report source matches without runtime admission."""

import json
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

from origins import input_origin, sha256


def generated_headers(source_files, compiler_headers, retained):
    gcc = Path("/build/gcc/gcc-14-14.2.0/src/gcc")
    glibc = Path("/build/glibc/glibc-2.41/sysdeps/unix/sysv/linux")
    recipes = [
        (Path(compiler_headers) / "limits.h", "gcc",
         [gcc / "Makefile.in", gcc / "limitx.h", gcc / "glimits.h", gcc / "limity.h"],
         ["cat", str(gcc / "limitx.h"), str(gcc / "glimits.h"), str(gcc / "limity.h")]),
        (Path("/build/source-sysroot/usr/include/bits/syscall.h"), "glibc",
         [glibc / "Makefile", glibc / "gen-syscall-h.awk", glibc / "syscall-names.list"],
         ["/bootstrap/bin/gawk", "-f", str(glibc / "gen-syscall-h.awk"), str(glibc / "syscall-names.list")]),
    ]
    generated = {}
    for output, component, inputs, command in recipes:
        references = []
        for path in inputs:
            if input_origin(path, source_files) != component:
                raise ValueError("Unexpected header producer component")
            digest = sha256(path)
            references.append({"path": str(path), "component": component, "sha256": digest})
            (retained / digest).write_bytes(path.read_bytes())
        data = subprocess.check_output(command, env={**os.environ, "LC_ALL": "C"})
        generated[str(output)] = {"sha256": hashlib.sha256(data).hexdigest(),
                                  "inputs": references, "command": command}
    kernel = Path("/build/linux/linux-6.12.107")
    architecture = {"aarch64": "arm64", "x86_64": "x86"}[os.uname().machine]
    helpers = [kernel / "scripts/headers_install.sh", kernel / "scripts/Makefile.headersinst",
               kernel / "scripts/unifdef.c"]
    for path in helpers:
        if input_origin(path, source_files) != "linux":
            raise ValueError("Unexpected Linux header producer component")
        (retained / sha256(path)).write_bytes(path.read_bytes())
    with tempfile.TemporaryDirectory(prefix="header-reproduction-", dir="/build") as directory:
        work = Path(directory)
        (work / "scripts").mkdir()
        tool_command = ["/gnu-bootstrap/bin/gcc", "-O2", str(helpers[-1]),
                        "-o", str(work / "scripts/unifdef")]
        subprocess.run(tool_command, check=True)
        for output in sorted((kernel / "usr/include").rglob("*.h")):
            relative = output.relative_to(kernel / "usr/include")
            source = kernel / "include/uapi" / relative
            if relative.parts[0] == "asm":
                source = kernel / "arch" / architecture / "include/uapi" / relative
            if str(source) not in source_files:
                continue
            inputs = [source, *helpers]
            references = []
            for path in inputs:
                if input_origin(path, source_files) != "linux":
                    raise ValueError("Unexpected Linux header input component")
                digest = sha256(path)
                (retained / digest).write_bytes(path.read_bytes())
                references.append({"path": str(path), "component": "linux", "sha256": digest})
            reproduced = work / "header.h"
            command = ["sh", str(helpers[0]), str(source), str(reproduced)]
            subprocess.run(command, cwd=work, check=True)
            generated[str(output)] = {"sha256": sha256(reproduced), "inputs": references,
                                      "command": command, "cwd": str(work), "tool_command": tool_command}
    return generated


def audit_headers(roots, source_files, generated=None):
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
            producer = (generated or {}).get(str(path))
            if producer and (not producer.get("inputs") or not producer.get("command")):
                raise ValueError("Generated header lacks source producer inputs")
            if producer and any(input_origin(item["path"], source_files) != item["component"]
                                or sha256(item["path"]) != item["sha256"] for item in producer["inputs"]):
                raise ValueError("Generated header producer input differs from verified source")
            if producer and producer["sha256"] != digest:
                raise ValueError("Generated header differs from its source producer: " + str(path))
            records.append({"path": str(path), "sha256": digest, "sources": matches,
                            "producer": producer, "verified": bool(matches or producer)})
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
    retained = evidence / "header-inputs"
    retained.mkdir()
    generated = generated_headers(source_files, compiler_headers, retained)
    headers = audit_headers(["/build/source-sysroot/usr/include", compiler_headers,
                             "/build/linux/linux-6.12.107/usr/include"], source_files, generated)
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
