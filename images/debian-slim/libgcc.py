"""Construct fresh GNU runtime objects; do not qualify a release."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

from gcc_bootstrap import MATERIALS, SIGNER
from origins import sha256, verify_record


STARTUP = ("crtbegin.o", "crtbeginS.o", "crtbeginT.o", "crtend.o", "crtendS.o")


def source_inputs(evidence):
    gcc = json.loads((evidence / "gcc-bootstrap.json").read_text())
    if (not gcc.get("completed") or gcc.get("materials") != dict(MATERIALS)
            or gcc.get("signing_fingerprint") != SIGNER):
        raise ValueError("Missing pinned Debian GCC preparation")
    index = {}
    bootstrap = json.loads((evidence / "bootstrap.json").read_text())
    sources = {item["name"]: item for item in bootstrap["sources"]}
    sources["gcc"] = gcc
    for name in ("gcc", "glibc", "linux"):
        snapshot = evidence / (name + ".source-files.json")
        if not sources[name].get("completed") or sha256(snapshot) != sources[name]["source_snapshot_sha256"]:
            raise ValueError("Source snapshot checksum mismatch: " + name)
        items = json.loads(snapshot.read_text())
        if not items or any(item["component"] != name or sha256(path) != item["sha256"]
                            for path, item in items.items()):
            raise ValueError("Prepared source differs from its snapshot: " + name)
        index.update(items)
    headers = json.loads((evidence / "gnu-headers.json").read_text())
    if headers.get("scope") != "source-header-audit" or not headers.get("headers_verified"):
        raise ValueError("Missing verified source headers")
    for header in headers["headers"]:
        references = header["sources"] or (header.get("producer") or {}).get("inputs", [])
        if not header["verified"] or not references or sha256(header["path"]) != header["sha256"]:
            raise ValueError("Unverified installed header")
        for item in references:
            original = index.get(item["path"])
            if (not original or original["component"] != item["component"]
                    or ("sha256" in item and original["sha256"] != item["sha256"])
                    or (header["sources"] and original["sha256"] != header["sha256"])):
                raise ValueError("Unverified header source reference")
        producer = header.get("producer")
        if producer and (producer["sha256"] != header["sha256"] or not producer.get("command")):
            raise ValueError("Installed header differs from producer")
        if sha256(evidence / "header-inputs" / header["sha256"]) != header["sha256"]:
            raise ValueError("Retained installed header changed")
        index[header["path"]] = {"sha256": header["sha256"], "component": references[0]["component"]}
    return index, headers


def inspect_runtime(work, directory, source_files, retained):
    """Require fresh object paths and retain every archive member's proof."""
    work = work.resolve()
    records = {}
    for path in sorted(directory.glob("*.json")):
        record = json.loads(path.read_text())
        obj = Path(record["object"]).resolve()
        if obj.is_relative_to(work):
            records[str(obj)] = (path, record)
    retained.mkdir(parents=True, exist_ok=True)

    def object_proof(path, digest):
        path = path.resolve()
        if not path.is_relative_to(work) or str(path) not in records:
            raise ValueError("Prebuilt or unrecorded runtime object: " + str(path))
        record_path, record = records[str(path)]
        if sha256(path) != digest or record["object_sha256"] != digest:
            raise ValueError("Runtime object checksum mismatch")
        for item in record["inputs"]:
            origin = source_files.get(str(Path(item["path"]).resolve()))
            if not origin or origin["sha256"] != item["sha256"]:
                raise ValueError("Unknown runtime input: " + item["path"])
        components = verify_record(record, directory, source_files)
        (retained / digest).write_bytes(path.read_bytes())
        retained_record = retained / (sha256(record_path) + ".json")
        retained_record.write_bytes(record_path.read_bytes())
        return {"path": str(path), "sha256": digest, "components": components,
                "record": str(record_path), "record_sha256": sha256(record_path),
                "retained_record": str(retained_record),
                "inputs": record["inputs"], "retained": str(retained / digest)}

    artifacts = []
    for name in ("libgcc.a", "libgcc_eh.a", *STARTUP):
        path = work / name
        if not path.is_file() or not path.resolve().is_relative_to(work):
            raise ValueError("Missing or prebuilt runtime artifact: " + name)
        digest = sha256(path)
        artifact = {"path": str(path), "sha256": digest, "retained": str(retained / digest)}
        if path.suffix == ".a":
            if path.read_bytes()[:8] != b"!<arch>\n":
                raise ValueError("Runtime archive must not be thin or prebuilt")
            members = subprocess.check_output(["ar", "t", str(path)], text=True).splitlines()
            if not members or len(members) != len(set(members)):
                raise ValueError("Empty or duplicate runtime archive members")
            artifact["members"] = []
            for member in members:
                if Path(member).name != member:
                    raise ValueError("Runtime archive member escapes build directory")
                data = subprocess.check_output(["ar", "p", str(path), member])
                proof = object_proof(work / member, hashlib.sha256(data).hexdigest())
                artifact["members"].append({"name": member, **proof})
        else:
            artifact["object"] = object_proof(path, digest)
        (retained / digest).write_bytes(path.read_bytes())
        artifacts.append(artifact)
    return artifacts


def main():
    evidence = Path("/evidence")
    source_files, headers = source_inputs(evidence)
    source = Path("/build/gcc/gcc-14-14.2.0/src/libgcc")
    if str(source / "configure") not in source_files:
        raise ValueError("Missing pinned libgcc configure source")
    target = subprocess.check_output(["/gnu-bootstrap/bin/gcc", "-dumpmachine"], text=True).strip()
    if not target or Path(target).name != target:
        raise ValueError("Invalid GNU target")
    root = Path("/build/libgcc-runtime")
    root.mkdir()  # A pre-existing tree must not supply runtime objects.
    (root / "gcc").symlink_to("/build/gcc/objects/gcc", target_is_directory=True)
    work = root / target / "libgcc"
    work.mkdir(parents=True)
    original = Path("/build/gcc/objects") / target / "libgcc/config.status"
    arguments = shlex.split(subprocess.check_output([str(original), "--config"], text=True))
    arguments = [item for item in arguments if not item.startswith(("--srcdir=", "CC=", "CXX="))]
    cc = "python3 /recipe/trace_compiler.py --sysroot=/build/source-sysroot"
    commands = [[str(source / "configure"), *arguments, "--srcdir=" + str(source),
                 "--disable-shared", "--disable-multilib", "CC=" + cc],
                ["make", "-j1", "libgcc.a", "libgcc_eh.a", *STARTUP, "CC=" + cc, "AR=ar", "AR_FLAGS=rcD"]]
    receipt = {"schema_version": 1, "scope": "gnu-libgcc-construction", "release_qualified": False,
               "completed": False, "runtime_verified": False, "commands": commands,
               "machine": os.uname().machine, "target": target, "headers": headers["headers"],
               "source_snapshots": {name: sha256(evidence / (name + ".source-files.json"))
                                    for name in ("gcc", "glibc", "linux")},
               "bootstrap_config_status_sha256": sha256(original),
               "gcc_preparation_sha256": sha256(evidence / "gcc-bootstrap.json"),
               "header_audit_sha256": sha256(evidence / "gnu-headers.json")}
    output = evidence / "gnu-libgcc.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    environment = {**os.environ, "PATH": "/gnu-bootstrap/bin:" + os.environ["PATH"]}
    with (evidence / "gnu-libgcc.build.log").open("wb") as log:
        for command in commands:
            subprocess.run(command, cwd=work, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    receipt["completed"] = True
    try:
        receipt["artifacts"] = inspect_runtime(work, evidence / "sources/compilation", source_files,
                                                evidence / "sources/libgcc")
        receipt["runtime_verified"] = True
    except ValueError as error:
        receipt["blocking_error"] = str(error)
        raise
    finally:
        output.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
