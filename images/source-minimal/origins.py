"""Fail closed on unknown shipped files, link inputs, and compiler headers."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from compiler import reject_assembler_imports


SOURCE_TREES = {
    "/build/musl-1.2.6": "musl",
    "/build/busybox-1.37.0": "busybox",
    "/build/llvm-project-23.1.3.src/compiler-rt": "compiler-rt-builtins",
}
GENERATED_INPUTS = {
    "/build/musl-1.2.6/obj/include/bits/alltypes.h": ("musl", "musl Makefile: alltypes.h.in and tools/mkalltypes.sed"),
    "/build/musl-1.2.6/obj/include/bits/syscall.h": ("musl", "musl Makefile: architecture syscall.h.in"),
    "/build/musl-1.2.6/obj/src/internal/version.h": ("musl", "musl Makefile: VERSION"),
    "/opt/musl/lib/musl-gcc.specs": ("musl", "tools/musl-gcc.specs.sh and build.sh: remove bootstrap libraries, startup objects, and headers"),
    "/build/busybox-1.37.0/include/common_bufsiz.h": ("busybox", "scripts/generate_BUFSIZ.sh: source-defined buffer declarations selected by effective .config"),
    "/build/busybox-1.37.0/include/applets.h": ("busybox", "scripts/gen_build_files.sh: applets.src.h and source //applet declarations"),
    "/build/busybox-1.37.0/include/usage.h": ("busybox", "scripts/gen_build_files.sh: usage.src.h and source //usage declarations"),
}
for name in ["autoconf.h", "applet_tables.h", "NUM_APPLETS.h", "usage_compressed.h", "bbconfigopts.h", "bbconfigopts_bz2.h"]:
    GENERATED_INPUTS["/build/busybox-1.37.0/include/" + name] = ("busybox", "BusyBox Makefile and applets/Kbuild: generated header from source and effective .config")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot_sources(trees, output):
    index = {}
    for tree, component in trees.items():
        tree = Path(tree).resolve()
        if not tree.is_dir():
            raise ValueError(f"Missing locked source tree: {tree}")
        for path in sorted(tree.rglob("*")):
            if path.is_file():
                if not path.resolve().is_relative_to(tree):
                    raise ValueError(f"Source symlink escapes locked tree: {path}")
                index[str(path.resolve())] = {"component": component, "sha256": sha256(path)}
    Path(output).write_text(json.dumps(index, sort_keys=True, indent=2) + "\n")


def input_origin(path, source_files=None):
    path = Path(path).resolve()
    if source_files is None:
        source_files = json.loads(Path("/evidence/sources/source-files.json").read_text())
    item = source_files.get(str(path))
    if item and sha256(path) == item["sha256"]:
        return item["component"]
    if str(path) in GENERATED_INPUTS:
        return GENERATED_INPUTS[str(path)][0]
    if path.is_relative_to("/opt/musl/include"):
        relative = path.relative_to("/opt/musl/include")
        candidates = [Path("/build/musl-1.2.6") / prefix / relative for prefix in ["include", "obj/include", "arch/generic", "arch/x86_64", "arch/aarch64"]]
        for candidate in candidates:
            if candidate.is_file() and sha256(candidate) == sha256(path):
                return input_origin(candidate, source_files)
    raise ValueError(f"Unreviewed compiler input: {path}")


def verify_record(record, directory, source_files=None):
    for kind in ["preprocessed", "dependencies", "assembly"]:
        path = directory / record[kind]
        if path.parent != directory or sha256(path) != record[kind + "_sha256"]:
            raise ValueError("Compiler evidence checksum mismatch")
    reject_assembler_imports((directory / record["assembly"]).read_text())
    if not record["inputs"]:
        raise ValueError("Missing compiler inputs")
    components = set()
    for item in record["inputs"]:
        components.add(input_origin(item["path"], source_files))
        if sha256(item["path"]) != item["sha256"]:
            raise ValueError(f"Compiler input changed: {item['path']}")
        retained = directory / "inputs" / item["sha256"]
        retained.parent.mkdir(exist_ok=True)
        retained.write_bytes(Path(item["path"]).read_bytes())
    return sorted(components)


def verify_links(link_map, cwd, records, directory, runtime=None, source_files=None, partial_links=None, require_runtime=True, active=()):
    loaded = [line.removeprefix("LOAD ").strip() for line in link_map.splitlines() if line.startswith("LOAD ")]
    if not loaded:
        raise ValueError("Missing linker inputs")
    by_hash = {}
    for record in records:
        by_hash.setdefault(record["object_sha256"], []).append(record)
    verified = []
    for name in loaded:
        path = (cwd / name).resolve()
        if name == "linker stubs" and not path.exists():
            verified.append({"path": name, "kind": "linker-generated", "recipe": "Pinned bootstrap GNU ld: branch veneers generated from compiled input relocations", "components": []})
            continue
        components = set()
        hashes = []
        compilation_records = set()
        if path.suffix == ".a" or (path.is_file() and path.read_bytes()[:8] == b"!<arch>\n"):
            members = subprocess.check_output(["ar", "t", str(path)], text=True).splitlines()
            if len(members) != len(set(members)):
                raise ValueError(f"Duplicate archive member: {path}")
            for member in members:
                data = subprocess.check_output(["ar", "p", str(path), member])
                hashes.append(hashlib.sha256(data).hexdigest())
        elif runtime and str(path) in runtime and sha256(path) == runtime[str(path)]["sha256"]:
            components.update(runtime[str(path)]["components"])
        else:
            hashes.append(sha256(path))
        for value in hashes:
            candidates = by_hash.get(value, [])
            if not candidates:
                partial = (partial_links or {}).get(value)
                if not partial or value in active:
                    raise ValueError(f"Unrecorded linker input or cyclic partial link: {path}")
                if sha256(partial["map"]) != partial["map_sha256"] or sha256(partial["output"]) != value:
                    raise ValueError("Partial link evidence checksum mismatch")
                for script in partial["scripts"]:
                    input_origin(script["path"], source_files)
                    if sha256(script["path"]) != script["sha256"]:
                        raise ValueError("Partial link script changed")
                inputs = verify_links(Path(partial["map"]).read_text(), Path(partial["cwd"]), records, directory,
                                      source_files=source_files, partial_links=partial_links, require_runtime=False, active=(*active, value))
                components.update(component for item in inputs for component in item["components"])
                compilation_records.update(record for item in inputs for record in item.get("compilation_records", []))
                continue
            # Equal bytes do not bypass source or header validation.
            for record in candidates:
                components.update(verify_record(record, directory, source_files))
                key = hashlib.sha256(record["object"].encode()).hexdigest()
                compilation_records.add("sources/compilation/" + key + ".json")
        verified.append({"path": str(path), "sha256": sha256(path), "components": sorted(components), "compilation_records": sorted(compilation_records)})
    if require_runtime and not any(item["path"] == "/build/compiler-builtins.a" for item in verified):
        raise ValueError("Missing source-built compiler runtime")
    return verified


def file_origins(root, lock):
    sources = {item["name"]: item for item in lock["sources"]}
    exact = {
        "bin/busybox": ("compiled", ["busybox", "musl", "compiler-rt-builtins"], "build.sh: BusyBox compilation and applet selection"),
        "lib/libc.so": ("compiled", ["musl", "compiler-rt-builtins"], "build.sh: patched musl compilation"),
        "etc/ssl/certs/ca-certificates.crt": ("trust-data", ["mozilla-ca-bundle"], "Copy verified dated CA input; trust behavior is not audited"),
        "usr/share/licenses/musl.txt": ("license", ["musl"], "musl COPYRIGHT"),
        "usr/share/licenses/busybox.txt": ("license", ["busybox"], "BusyBox LICENSE"),
        "usr/share/licenses/compiler-rt.txt": ("license", ["compiler-rt-builtins"], "compiler-rt LICENSE.TXT"),
        "usr/share/licenses/mozilla-ca-bundle.txt": ("license", ["mozilla-ca-bundle"], "recipe/CA-NOTICE.txt"),
    }
    generated = {
        "etc/passwd": "build.sh: fixed account data", "etc/group": "build.sh: fixed group data",
        "etc/shadow": "build.sh: locked accounts",
        "usr/share/rootloom/build-evidence.json": "evidence.py: compiler, hardening, and source evidence",
        "usr/share/rootloom/source-inventory.spdx.json": "evidence.py: pinned source inventory",
        "usr/share/rootloom/sources.lock.json": "recipe/sources.lock.json: reviewed source pins",
        "usr/share/rootloom/source-origins.json": "origins.py: file mapping; self hash excluded",
        "usr/share/rootloom/rootfs.sha256": "build.sh: normalized rootfs tar checksum; excluded from checksum scope",
    }
    directories = {"bin", "lib", "etc", "etc/ssl", "etc/ssl/certs", "usr", "usr/share", "usr/share/licenses", "usr/share/rootloom", "app", "home", "home/rootloom", "tmp", "proc", "dev", "sys"}
    paths = {path.relative_to(root).as_posix(): path for path in root.rglob("*")}
    for name in ["usr/share/rootloom/source-origins.json", "usr/share/rootloom/rootfs.sha256"]:
        paths.setdefault(name, root / name)
    result = []
    for name, path in sorted(paths.items()):
        components = []
        target = None
        if path.is_symlink():
            target = path.readlink().as_posix()
            if name.startswith("bin/") and target == "busybox":
                kind, components, recipe = "symlink", ["busybox"], "build.sh: source-built BusyBox --list"
            elif name in {"lib/ld-musl-x86_64.so.1", "lib/ld-musl-aarch64.so.1"} and target == "libc.so":
                kind, components, recipe = "symlink", ["musl"], "build.sh: musl loader alias"
            elif name == "etc/ssl/cert.pem" and target == "certs/ca-certificates.crt":
                kind, components, recipe = "symlink", ["mozilla-ca-bundle"], "build.sh: CA alias"
            else:
                raise ValueError(f"Unmapped shipped symlink: {name}")
        elif path.is_dir() and name in directories:
            kind, recipe = "directory", "build.sh: runtime directories and permissions"
        elif path.is_file() and name in exact:
            kind, components, recipe = exact[name]
        elif name in generated and (not path.exists() or path.is_file()):
            kind, recipe = "generated-data", generated[name]
        else:
            raise ValueError(f"Unmapped shipped file: {name}")
        item = {"path": name, "kind": kind, "recipe": recipe, "sources": [{"name": component, "sha256": sources[component]["sha256"], "license": sources[component]["license"]} for component in components]}
        item["patches"] = [patch for patch in lock["patches"] if patch["component"] in components]
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            item.update(mode=oct(metadata.st_mode & 0o7777), uid=metadata.st_uid, gid=metadata.st_gid)
        if target is not None:
            item["target"] = target
        elif path.is_file() and name not in {"usr/share/rootloom/source-origins.json", "usr/share/rootloom/rootfs.sha256"}:
            item["sha256"] = sha256(path)
        result.append(item)
    return result


def closure(root, lock):
    directory = Path("/evidence/sources/compilation")
    records = [json.loads(path.read_text()) for path in sorted(directory.glob("*.json"))]
    if not records:
        raise ValueError("Missing compiler records")
    source_files = json.loads(Path("/evidence/sources/source-files.json").read_text())
    link_commands = {}
    for name, output in {"musl": "/build/musl-1.2.6/lib/libc.so", "busybox": "/build/busybox-1.37.0/busybox_unstripped"}.items():
        key = hashlib.sha256(output.encode()).hexdigest()
        record = json.loads((directory.parent / "linking" / (key + ".json")).read_text())
        if record["output"] != output or record["output_sha256"] != sha256(output):
            raise ValueError("Link command output checksum mismatch")
        for item in record["scripts"]:
            input_origin(item["path"], source_files)
            if sha256(item["path"]) != item["sha256"]:
                raise ValueError("Link script changed")
            retained = directory.parent / "linking" / item["sha256"]
            retained.write_bytes(Path(item["path"]).read_bytes())
        link_commands[name] = record
    copies = {
        "bin/busybox": "/build/busybox-1.37.0/busybox",
        "lib/libc.so": "/build/musl-1.2.6/lib/libc.so",
        "etc/ssl/certs/ca-certificates.crt": "/downloads/cacert-2026-09-25.pem",
        "usr/share/licenses/musl.txt": "/build/musl-1.2.6/COPYRIGHT",
        "usr/share/licenses/busybox.txt": "/build/busybox-1.37.0/LICENSE",
        "usr/share/licenses/compiler-rt.txt": "/build/llvm-project-23.1.3.src/compiler-rt/LICENSE.TXT",
        "usr/share/licenses/mozilla-ca-bundle.txt": "/recipe/CA-NOTICE.txt",
    }
    for destination, source in copies.items():
        if sha256(root / destination) != sha256(source):
            raise ValueError(f"Shipped file differs from declared origin: {destination}")
    applets = subprocess.check_output(["/opt/musl/lib/libc.so", str(root / "bin/busybox"), "--list"], text=True).splitlines()
    actual = {path.name for path in (root / "bin").iterdir()}
    if actual != set(applets) | {"busybox"}:
        raise ValueError("Shipped applets differ from source-built BusyBox list")
    links = {}
    partial_links = {record["output_sha256"]: record for path in sorted((directory.parent / "partial-links").glob("*.json")) for record in [json.loads(path.read_text())]}
    links["musl"] = verify_links(Path("/evidence/musl.link.map").read_text(), Path("/build/musl-1.2.6"), records, directory, source_files=source_files, partial_links=partial_links)
    runtime = {"/opt/musl/lib/libc.so": {"sha256": sha256(root / "lib/libc.so"), "components": ["musl", "compiler-rt-builtins"]}}
    links["busybox"] = verify_links(Path("/evidence/busybox.link.map").read_text(), Path("/build/busybox-1.37.0"), records, directory, runtime, source_files, partial_links)
    manifest = {"schema_version": 1, "files": file_origins(root, lock), "link_inputs": links, "link_commands": link_commands,
                "source_index_sha256": sha256("/evidence/sources/source-files.json"),
                "compiler_headers": "Linked objects use source-index-matching inputs, allowlisted generated headers, or byte-matching installed musl headers. Bootstrap headers and assembler file imports are not allowed. Consumed input bytes are retained by SHA-256 under sources/compilation/inputs.",
                "generated_compiler_inputs": {path: {"component": component, "recipe": recipe} for path, (component, recipe) in GENERATED_INPUTS.items()},
                "scope": "Source and generated-input origin evidence. Not a compiler bootstrap, advisory coverage, or FIPS validation."}
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (root / "usr/share/rootloom/source-origins.json").write_text(text)
    Path("/evidence/source-origins.json").write_text(text)


if __name__ == "__main__":
    if sys.argv[1:] != ["snapshot"]:
        raise ValueError("Use origins.py snapshot after verified extraction and patching")
    snapshot_sources(SOURCE_TREES, "/evidence/sources/source-files.json")
