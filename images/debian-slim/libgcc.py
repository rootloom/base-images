"""Construct fresh GNU runtime objects; do not qualify a release."""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

from gcc_bootstrap import MATERIALS, SIGNER
from origins import sha256, verify_record
from compiler import dependency_inputs, reject_assembler_imports


STARTUP = ("crtbegin.o", "crtbeginS.o", "crtbeginT.o", "crtend.o", "crtendS.o")


def verify_retained_runtime(evidence):
    """Check construction evidence offline; never grant release admission."""
    evidence = Path(evidence).resolve()

    def checked(path, digest):
        if (not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)
                or path.is_symlink() or not path.is_file()
                or not path.resolve().is_relative_to(evidence) or sha256(path) != digest):
            raise ValueError("Retained evidence checksum mismatch: " + str(path))
        return path.read_bytes()

    receipt = json.loads((evidence / "gnu-libgcc.json").read_text())
    if (receipt.get("schema_version") != 1 or receipt.get("scope") != "gnu-libgcc-construction"
            or receipt.get("release_qualified") is not False
            or receipt.get("completed") is not True or receipt.get("runtime_verified") is not True
            or receipt.get("machine") not in ("x86_64", "aarch64")):
        raise ValueError("Incomplete or qualified libgcc construction receipt")
    gcc = json.loads(checked(evidence / "gcc-bootstrap.json", receipt["gcc_preparation_sha256"]))
    if (gcc.get("completed") is not True or gcc.get("materials") != dict(MATERIALS)
            or gcc.get("signing_fingerprint") != SIGNER):
        raise ValueError("Missing pinned Debian GCC preparation")
    bootstrap = json.loads((evidence / "bootstrap.json").read_text())
    sources = {item["name"]: item for item in bootstrap["sources"]}
    sources["gcc"] = gcc
    index = {}
    for name in ("gcc", "glibc", "linux"):
        digest = receipt["source_snapshots"][name]
        if sources[name].get("completed") is not True or sources[name]["source_snapshot_sha256"] != digest:
            raise ValueError("Source snapshot checksum mismatch: " + name)
        snapshot = json.loads(checked(evidence / (name + ".source-files.json"), digest))
        if not snapshot or any(item["component"] != name for item in snapshot.values()):
            raise ValueError("Invalid source snapshot: " + name)
        if index.keys() & snapshot.keys():
            raise ValueError("Duplicate source snapshot path")
        index.update(snapshot)
    headers = json.loads(checked(evidence / "gnu-headers.json", receipt["header_audit_sha256"]))
    if (headers.get("scope") != "source-header-audit" or headers.get("headers_verified") is not True
            or not headers.get("headers") or receipt["headers"] != headers["headers"]):
        raise ValueError("Missing verified source headers")
    for header in headers["headers"]:
        checked(evidence / "header-inputs" / header["sha256"], header["sha256"])
        references = header["sources"] or (header.get("producer") or {}).get("inputs", [])
        if header.get("verified") is not True or not references:
            raise ValueError("Unverified installed header")
        for item in references:
            origin = index.get(item["path"])
            if (not origin or origin["component"] != item["component"]
                    or origin["sha256"] != item.get("sha256", origin["sha256"])
                    or (header["sources"] and origin["sha256"] != header["sha256"])):
                raise ValueError("Unverified header source reference")
            checked(evidence / "header-inputs" / origin["sha256"], origin["sha256"])
        producer = header.get("producer")
        if producer and (producer.get("sha256") != header["sha256"] or not producer.get("command")):
            raise ValueError("Installed header differs from producer")
        index[header["path"]] = {"sha256": header["sha256"], "component": references[0]["component"]}
    producers = evidence / "sources/libgcc-producers"
    checked(producers / receipt["bootstrap_config_status_sha256"], receipt["bootstrap_config_status_sha256"])
    proofs = receipt.get("generated_headers", [])
    if sorted(Path(item["path"]).name for item in proofs) != ["auto-target.h", "libgcc_tm.h"]:
        raise ValueError("Missing generated-header proofs")
    for proof in proofs:
        checked(producers / proof["sha256"], proof["sha256"])
        if (proof.get("replay_verified") is not True or proof.get("admitted") is not False
                or not proof.get("blocking_error") or not proof.get("commands") or not proof.get("inputs")):
            raise ValueError("Unproved generated-header admission")
        for item in proof["inputs"]:
            checked(producers / item["sha256"], item["sha256"])
            if item["kind"] == "source":
                if index.get(item["path"]) != {"component": item["component"], "sha256": item["sha256"]}:
                    raise ValueError("Unknown generated-header producer")
            elif item["kind"] != "configure-output":
                raise ValueError("Unknown generated-header input")
    artifacts = receipt.get("artifacts", [])
    if sorted(Path(item["path"]).name for item in artifacts) != sorted(("libgcc.a", "libgcc_eh.a", *STARTUP)):
        raise ValueError("Missing or duplicate runtime artifacts")
    retained = evidence / "sources/libgcc"
    compilation = evidence / "sources/compilation"
    for artifact in artifacts:
        path = retained / artifact["sha256"]
        data = checked(path, artifact["sha256"])
        if Path(artifact["path"]).suffix == ".a":
            if not data.startswith(b"!<arch>\n"):
                raise ValueError("Runtime archive must not be thin")
            members = subprocess.check_output(["ar", "t", str(path)], text=True).splitlines()
            objects = artifact["members"]
            if (not members or len(members) != len(set(members))
                    or members != [item["name"] for item in objects]):
                raise ValueError("Runtime archive members differ from receipt")
        else:
            objects = [artifact["object"]]
        for obj in objects:
            checked(retained / obj["sha256"], obj["sha256"])
            if "members" in artifact:
                if Path(obj["name"]).name != obj["name"]:
                    raise ValueError("Invalid runtime archive member")
                member = subprocess.check_output(["ar", "p", str(path), obj["name"]])
                if hashlib.sha256(member).hexdigest() != obj["sha256"]:
                    raise ValueError("Runtime archive member checksum mismatch")
            elif artifact["sha256"] != obj["sha256"] or artifact["path"] != obj["path"]:
                raise ValueError("Startup object differs from artifact")
            record = json.loads(checked(retained / (obj["record_sha256"] + ".json"), obj["record_sha256"]))
            if (record["object"] != obj["path"] or record["object_sha256"] != obj["sha256"]
                    or not record["inputs"] or record["inputs"] != obj["inputs"]):
                raise ValueError("Runtime object differs from compiler record")
            command = record.get("command", [])
            if ("-c" not in command or "-o" not in command
                    or command.index("-o") + 1 >= len(command)
                    or command[command.index("-o") + 1] != record["object"]):
                raise ValueError("Missing runtime compilation command")
            compiler_bytes = {}
            for kind in ("preprocessed", "dependencies", "assembly"):
                if Path(record[kind]).name != record[kind]:
                    raise ValueError("Invalid compiler evidence path")
                compiler_bytes[kind] = checked(compilation / record[kind], record[kind + "_sha256"])
            reject_assembler_imports(compiler_bytes["assembly"].decode())
            if {str(item) for item in dependency_inputs(compiler_bytes["dependencies"].decode())} != {
                    item["path"] for item in record["inputs"]}:
                raise ValueError("Compiler dependency list differs from inputs")
            components = set()
            for item in record["inputs"]:
                origin = index.get(item["path"])
                if not origin or origin["sha256"] != item["sha256"]:
                    raise ValueError("Unknown runtime input: " + item["path"])
                checked(compilation / "inputs" / item["sha256"], item["sha256"])
                components.add(origin["component"])
            if sorted(components) != obj["components"]:
                raise ValueError("Runtime components differ from source inputs")
    return receipt


def replay_generated_headers(work, source, source_files, retained, environment):
    """Record local replay, without admitting unresolved configure probe inputs."""
    inputs = []
    retained.mkdir(parents=True, exist_ok=True)
    for name in ("configure", "config.host", "config.in", "Makefile.in", "mkheader.sh"):
        path = (source / name).resolve()
        origin = source_files.get(str(path))
        if not origin or origin["component"] != "gcc" or sha256(path) != origin["sha256"]:
            raise ValueError("Unknown generated-header producer: " + str(path))
        inputs.append({"path": str(path), **origin, "kind": "source"})
    for name in ("Makefile", "config.status"):
        path = work / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing fresh configure output: " + name)
        inputs.append({"path": str(path), "sha256": sha256(path), "kind": "configure-output"})
    values = {}
    makefile = (work / "Makefile").read_text()
    for name in ("libgcc_tm_defines", "libgcc_tm_file"):
        matches = re.findall(r"^" + name + r" = ([^\n]*)$", makefile, re.MULTILINE)
        if len(matches) != 1 or any(char in matches[0] for char in "$`\\"):
            raise ValueError("Unknown generated-header parameter: " + name)
        values[name] = matches[0]
    commands = [["/bin/sh", str(source / "mkheader.sh")],
                ["/bin/sh", str(work / "config.status"),
                 "--header=auto-target.h:" + str(source / "config.in")]]
    generated = subprocess.check_output(commands[0], cwd=work,
        env={**environment, "DEFINES": values["libgcc_tm_defines"], "HEADERS": values["libgcc_tm_file"]})
    with tempfile.TemporaryDirectory(prefix="libgcc-header-replay-") as temporary:
        subprocess.run(commands[1], cwd=temporary, env=environment, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        outputs = {"libgcc_tm.h": generated, "auto-target.h": (Path(temporary) / "auto-target.h").read_bytes()}
        replay_directory = temporary
    for item in inputs:
        if sha256(item["path"]) != item["sha256"]:
            raise ValueError("Generated-header producer changed during replay")
        destination = retained / item["sha256"]
        destination.write_bytes(Path(item["path"]).read_bytes())
        item["retained"] = str(destination)
    proofs = []
    for name, data in outputs.items():
        path = work / name
        digest = hashlib.sha256(data).hexdigest()
        if path.is_symlink() or not path.is_file() or sha256(path) != digest:
            raise ValueError("Generated header differs from replay: " + name)
        (retained / digest).write_bytes(data)
        proofs.append({"path": str(path), "sha256": digest, "retained": str(retained / digest),
                       "commands": commands, "parameters": values, "inputs": inputs,
                       "working_directories": [str(work), replay_directory],
                       "replay_verified": True, "admitted": False,
                       "blocking_error": "Configure probes and compiler generated-header inputs remain unproved"})
    return proofs


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
    retained_config = evidence / "sources/libgcc-producers"
    retained_config.mkdir(parents=True, exist_ok=True)
    (retained_config / receipt["bootstrap_config_status_sha256"]).write_bytes(original.read_bytes())
    output = evidence / "gnu-libgcc.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    environment = {**os.environ, "PATH": "/gnu-bootstrap/bin:" + os.environ["PATH"]}
    try:
        with (evidence / "gnu-libgcc.build.log").open("wb") as log:
            for command in commands:
                subprocess.run(command, cwd=work, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
        receipt["completed"] = True
        receipt["generated_headers"] = replay_generated_headers(
            work, source, source_files, evidence / "sources/libgcc-producers", environment)
        receipt["artifacts"] = inspect_runtime(work, evidence / "sources/compilation", source_files,
                                                evidence / "sources/libgcc")
        receipt["runtime_verified"] = True
    except (ValueError, subprocess.CalledProcessError, OSError) as error:
        receipt["blocking_error"] = str(error)
        raise
    finally:
        output.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
