"""Install GNU headers and report source matches without runtime admission."""

import json
import hashlib
import os
import re
from pathlib import Path
import subprocess
import tempfile

from origins import input_origin, sha256


def make_header(component, inputs, body, target, source_files, retained, variables=()):
    references = []
    for path in inputs:
        if input_origin(path, source_files) != component:
            raise ValueError("Unexpected make header producer component")
        digest = sha256(path)
        (retained / digest).write_bytes(path.read_bytes())
        references.append({"path": str(path), "component": component, "sha256": digest})
    with tempfile.TemporaryDirectory(prefix="make-header-", dir="/build") as directory:
        work = Path(directory)
        output = work / target
        output.parent.mkdir(parents=True, exist_ok=True)
        recipe = work / "Makefile"
        recipe.write_text(body)
        recipe_digest = sha256(recipe)
        (retained / recipe_digest).write_bytes(recipe.read_bytes())
        command = ["make", "-f", str(recipe), *variables, target]
        subprocess.run(command, cwd=work, env={**os.environ, "LC_ALL": "C"}, check=True)
        return {"sha256": sha256(output), "inputs": references, "command": command,
                "cwd": str(work), "recipe_sha256": recipe_digest}


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
    makefile = kernel / "Makefile"
    version_body = re.search(r"^define filechk_version.h\n.*?^endef$", makefile.read_text(), re.M | re.S).group()
    version_values = "\n".join(re.findall(r"^(?:VERSION|PATCHLEVEL|SUBLEVEL) = [0-9]+$", makefile.read_text(), re.M))
    generated[str(kernel / "usr/include/linux/version.h")] = make_header(
        "linux", [makefile], version_values + "\n" + version_body +
        "\nversion.h:\n\t{ $(filechk_version.h); } > $@\n", "version.h", source_files, retained)
    libc = glibc.parents[3]
    abi = glibc / ("aarch64" if architecture == "arm64" else "x86") / "Makefile"
    makerules, makeconfig = libc / "Makerules", libc / "Makeconfig"
    wrapper = re.search(r"^\$\(common-objpfx\)gnu/lib-names.h:\n.*?(?=^endif$)",
                        makerules.read_text(), re.M | re.S).group()
    abi_defaults = re.search(r"^ifndef abi-includes\n.*?^endif$", makeconfig.read_text(), re.M | re.S).group()
    generated["/build/source-sysroot/usr/include/gnu/lib-names.h"] = make_header(
        "glibc", [makerules, makeconfig, abi], abi_defaults + "\ninclude " + str(abi) +
        "\ncommon-objpfx :=\n" + wrapper, "gnu/lib-names.h", source_files, retained,
        ["default-abi=" + ("lp64" if architecture == "arm64" else "64")])
    helpers = [kernel / "scripts/headers_install.sh", kernel / "scripts/Makefile.headersinst",
               kernel / "scripts/unifdef.c"]
    asm_rules = kernel / "scripts/Makefile.asm-headers"
    mandatory = kernel / "include/uapi/asm-generic/Kbuild"
    arch_kbuild = kernel / "arch" / architecture / "include/uapi/asm/Kbuild"
    wrapper_names = set(re.findall(r"^(?:mandatory|generic)-y \+= (\S+\.h)$",
                                   mandatory.read_text() + "\n" + arch_kbuild.read_text(), re.M))
    asm_text = asm_rules.read_text()
    wrap_command = re.search(r"^\s*cmd_wrap = .*?$", asm_text, re.M).group().strip()
    wrap_rule = re.search(r"^\$\(obj\)/%.h:.*?\n\t.*?$", asm_text, re.M).group()
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
            generation_command = None
            syscall_inputs = []
            if str(source) not in source_files:
                generic = kernel / "include/uapi/asm-generic" / relative.name
                if relative.parts[0] == "asm" and relative.name in wrapper_names and str(generic) in source_files:
                    generated[str(output)] = make_header(
                        "linux", [asm_rules, mandatory, arch_kbuild, generic],
                        "obj := asm\nsrctree := " + str(kernel) + "\ngeneric := include/uapi/asm-generic\n" +
                        wrap_command + "\ncmd = $(cmd_$(1))\n" + wrap_rule + "\n",
                        "asm/" + relative.name, source_files, retained)
                    continue
                if relative.parts[0] != "asm" or relative.name not in ("unistd_32.h", "unistd_64.h", "unistd_x32.h"):
                    continue
                script = kernel / "scripts/syscallhdr.sh"
                if architecture == "x86":
                    rules = kernel / "arch/x86/entry/syscalls/Makefile"
                    table = kernel / "arch/x86/entry/syscalls" / ("syscall_32.tbl" if relative.name == "unistd_32.h" else "syscall_64.tbl")
                    abis = {"unistd_32.h": "i386", "unistd_64.h": "common,64", "unistd_x32.h": "common,x32"}[relative.name]
                else:
                    if relative.name != "unistd_64.h":
                        continue
                    rules = kernel / "arch/arm64/kernel/Makefile.syscalls"
                    table = (kernel / "arch/arm64/tools/syscall_64.tbl").resolve()
                    abis = "common,64,renameat,rlimit,memfd_secret"
                syscall_inputs = [script, rules, table, asm_rules, arch_kbuild]
                for path in syscall_inputs:
                    if input_origin(path, source_files) != "linux":
                        raise ValueError("Unexpected syscall header producer component")
                source = work / relative.name
                generation_command = ["sh", str(script), "--emit-nr", "--abis", abis]
                if relative.name == "unistd_x32.h":
                    generation_command += ["--offset", "__X32_SYSCALL_BIT"]
                generation_command += [str(table), str(source)]
                subprocess.run(generation_command, check=True)
            inputs = [*(syscall_inputs or [source]), *helpers]
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
                                      "command": command, "cwd": str(work), "tool_command": tool_command,
                                      "generation_command": generation_command}
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
