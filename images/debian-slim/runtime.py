"""Trace a fresh GNU libc build without admitting it to a release."""

import json
import contextlib
import io
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types

from headers import make_header
from compiler import dependency_inputs
from origins import input_origin, sha256


def replay_constants(libc, symbol, stdin, assembly, source_files, retained):
    inputs = [libc / "scripts/gen-as-const.py", libc / "scripts/glibcextract.py", symbol]
    references = []
    for path in inputs:
        source = source_files.get(str(path.resolve()))
        if not source or source["sha256"] != sha256(path) or source["component"] != "glibc":
            raise ValueError("Unverified constant producer")
        digest = sha256(path)
        (retained / digest).write_bytes(path.read_bytes())
        references.append({"path": str(path), "component": "glibc", "sha256": digest})
    extract = types.ModuleType("glibcextract")
    exec(compile(inputs[1].read_bytes(), str(inputs[1]), "exec"), extract.__dict__)

    def compile_probe(command, shell):
        # The verified script must reproduce stdin before it can consume assembly.
        match = re.fullmatch(r"replay -S -o (\S+) -x c - < (\S+)", command)
        if not shell or not match or Path(match[2]).read_bytes() != stdin:
            raise ValueError("Constant producer stdin mismatch")
        Path(match[1]).write_bytes(assembly)

    extract.subprocess = types.SimpleNamespace(check_call=compile_probe)
    previous = sys.modules.get("glibcextract")
    argv = sys.argv
    try:
        sys.modules["glibcextract"] = extract
        producer = types.ModuleType("gen_as_const")
        exec(compile(inputs[0].read_bytes(), str(inputs[0]), "exec"), producer.__dict__)
        sys.argv = [str(inputs[0]), "--cc", "replay", str(symbol)]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            producer.main()
    finally:
        sys.argv = argv
        if previous is None:
            sys.modules.pop("glibcextract", None)
        else:
            sys.modules["glibcextract"] = previous
    data = output.getvalue().encode()
    if not data:
        raise ValueError("Empty constant producer output")
    digest = hashlib.sha256(data).hexdigest()
    return {"sha256": digest, "inputs": references,
            "command": ["python3", str(inputs[0]), "--cc", "retained-assembly-replay", str(symbol)],
            "replay": "verified-stdin-retained-assembly"}


def constant_inputs(libc, source_files, retained, generations, generated, work):
    symbols = [Path(name) for name in source_files
               if Path(name).is_relative_to(libc) and Path(name).suffix == ".sym"]
    result = {}
    for record_path in sorted(generations.glob("*.json")):
        record = json.loads(record_path.read_text())
        stdin = [item for item in record["inputs"] if item["path"] == "<stdin>"]
        if len(stdin) != 1:
            continue
        for field in ("assembly", "dependencies"):
            name = record[field]
            if Path(name).name != name or sha256(generations / name) != record[field + "_sha256"]:
                raise ValueError("Constant generation evidence changed")
        dependencies = []
        for item in record["inputs"]:
            path = generations / "inputs" / item["sha256"]
            if sha256(path) != item["sha256"]:
                raise ValueError("Retained constant input changed")
            if item["path"] == "<stdin>":
                continue
            try:
                source = source_files.get(str(Path(item["path"]).resolve()))
                if not source or source["sha256"] != item["sha256"]:
                    raise ValueError("Unverified constant dependency")
                component = input_origin(item["path"], source_files)
                if sha256(item["path"]) != item["sha256"]:
                    raise ValueError("Constant dependency changed")
                dependencies.append({**item, "component": component})
            except ValueError:
                path = Path(item["path"])
                relative = str(path.relative_to(work)) if path.is_relative_to(work) else None
                producer = generated.get(relative)
                if not producer or producer["sha256"] != item["sha256"]:
                    break
                dependencies.append({**item, "producer": producer})
        else:
            if not dependencies:
                continue
            for symbol in symbols:
                try:
                    producer = replay_constants(libc, symbol,
                        (generations / "inputs" / stdin[0]["sha256"]).read_bytes(),
                        (generations / record["assembly"]).read_bytes(), source_files, retained)
                except ValueError as error:
                    if str(error) == "Constant producer stdin mismatch":
                        continue
                    raise
                producer.update({"generation_record": record_path.name,
                                 "generation_record_sha256": sha256(record_path),
                                 "generation_inputs": dependencies, "stdin_sha256": stdin[0]["sha256"]})
                result[producer["sha256"]] = producer
    return result


def verify_constant_proofs(evidence, record, source_files):
    constants = [(name, producer) for name, producer in record["verified_inputs"].items()
                 if producer.get("replay") == "verified-stdin-retained-assembly"]
    if not constants:
        raise ValueError("Missing actual constant producer")
    generations = evidence / "sources/generation"
    retained = evidence / "runtime-inputs"
    consumed = {(item["path"], item["sha256"])
                for path in (evidence / "sources/compilation").glob("*.json")
                for item in json.loads(path.read_text())["inputs"]}

    def checked(root, name, digest):
        if not re.fullmatch(r"[a-f0-9]{64}", digest) or Path(name).name != name:
            raise ValueError("Invalid constant evidence reference")
        path = root / name
        if sha256(path) != digest:
            raise ValueError("Constant evidence changed")
        return path

    for output, producer in constants:
        if (output, producer["sha256"]) not in consumed or output in record["unknown_inputs"]:
            raise ValueError("Constant output is not a verified compiler input")
        name = producer["generation_record"]
        digest = producer["generation_record_sha256"]
        if record["generation_records"].get(name) != digest:
            raise ValueError("Wrong constant generation record")
        generation = json.loads(checked(generations, name, digest).read_text())
        if "object" in generation or "-S" not in generation["command"]:
            raise ValueError("Constant generation is not assembly")
        assembly = checked(generations, generation["assembly"], generation["assembly_sha256"])
        dependency_file = checked(generations, generation["dependencies"], generation["dependencies_sha256"])
        if generation["output_sha256"] != generation["assembly_sha256"]:
            raise ValueError("Constant generation output changed")
        stdin = [item for item in generation["inputs"] if item["path"] == "<stdin>"]
        dependencies = [item for item in generation["inputs"] if item["path"] != "<stdin>"]
        if {str(path) for path in dependency_inputs(dependency_file.read_text())} != {
                item["path"] for item in dependencies}:
            raise ValueError("Constant dependency list differs from inputs")
        if len(stdin) != 1 or stdin[0]["sha256"] != producer["stdin_sha256"]:
            raise ValueError("Wrong constant generation stdin")
        links = producer["generation_inputs"]
        if not links or [{"path": item["path"], "sha256": item["sha256"]} for item in links] != dependencies:
            raise ValueError("Wrong constant generation inputs")
        for item in generation["inputs"]:
            checked(generations / "inputs", item["sha256"], item["sha256"])
        for item in links:
            if "producer" in item:
                dependency = record["verified_inputs"].get(item["path"])
                if dependency != item["producer"] or dependency["sha256"] != item["sha256"]:
                    raise ValueError("Unverified generated constant dependency")
                if item["path"] in record["unknown_inputs"]:
                    raise ValueError("Unknown constant dependency")
                checked(retained, dependency["recipe_sha256"], dependency["recipe_sha256"])
                for source in dependency["inputs"]:
                    if source_files.get(source["path"]) != {"component": source["component"], "sha256": source["sha256"]}:
                        raise ValueError("Unverified constant dependency source")
                    checked(retained, source["sha256"], source["sha256"])
            elif source_files.get(item["path"]) != {"component": item["component"], "sha256": item["sha256"]}:
                raise ValueError("Unverified constant dependency")
        with tempfile.TemporaryDirectory() as directory:
            libc = Path(directory)
            index = {}
            names = []
            for source in producer["inputs"]:
                if source_files.get(source["path"]) != {"component": "glibc", "sha256": source["sha256"]} or source["component"] != "glibc":
                    raise ValueError("Unverified constant producer source")
                relative = Path(source["path"]).relative_to("/build/glibc/glibc-2.41")
                if ".." in relative.parts:
                    raise ValueError("Invalid constant producer path")
                path = libc / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(checked(retained, source["sha256"], source["sha256"]).read_bytes())
                index[str(path.resolve())] = {"component": "glibc", "sha256": source["sha256"]}
                names.append(relative)
            symbols = [name for name in names if name.suffix == ".sym"]
            if len(names) != 3 or len(set(names)) != 3 or len(symbols) != 1 or not {
                    Path("scripts/gen-as-const.py"), Path("scripts/glibcextract.py")}.issubset(names):
                raise ValueError("Missing constant producer scripts or symbol")
            replay = replay_constants(libc, libc / symbols[0],
                (generations / "inputs" / stdin[0]["sha256"]).read_bytes(), assembly.read_bytes(), index, libc)
            if replay["sha256"] != producer["sha256"]:
                raise ValueError("Constant replay output mismatch")
            checked(evidence / "sources/trace-inputs", producer["sha256"], producer["sha256"])
    return len(constants)


def loader_input(libc, source_files, retained):
    makefile = libc / "elf/Makefile"
    text = makefile.read_text()
    symbols = re.search(r"^rtld-stubbed-symbols = .*?(?=^\$\(objpfx\)librtld.map:)",
                        text, re.M | re.S).group()
    loop = re.search(r"^\tfor symbol in \$\(rtld-stubbed-symbols\);.*?^\tdone \| \$\(CC\)",
                     text, re.M | re.S).group().removesuffix(" | $(CC)")
    target = "elf/librtld.mapT.o.stdin.s"
    body = "have-ssp := yes\n" + symbols + target + ":\n\tmkdir -p elf\n" + loop + " > $@\n"
    return make_header("glibc", [makefile], body, target, source_files, retained)


def generated_inputs(libc, source_files, retained, machine, awk="/bootstrap/bin/gawk"):
    makefile = libc / "math/Makefile"
    text = makefile.read_text()
    rule = re.search(r"^\$\(objpfx\)gen-libm-templates.stmp: Makefile\n.*?(?=^\n)",
                     text, re.M | re.S).group()
    calls = re.search(r"^gen-calls = .*?$", text, re.M).group()
    suffixes = "\n".join(re.findall(r"^type-(?:double|float|ldouble|float128)-suffix :=.*?$", text, re.M))
    body = ("objpfx := math/\nmake-target-directory = mkdir -p math\n" + calls + "\n" + suffixes +
            "\ntypes := double float ldouble float128\ngen-all-calls = $(gen-calls)\n" + rule + "\n")
    generated = {}
    for suffix in ("", "f", "l", "f128"):
        target = "math/s_ldexp" + suffix + ".c"
        generated[target] = make_header(
            "glibc", [makefile], body + target + ": math/gen-libm-templates.stmp\n",
            target, source_files, retained)
    makefile = libc / "locale/Makefile"
    script = libc / "locale/gen-translit.py"
    rule = re.search(r"^\$\(objpfx\)C-translit.h:.*?(?=^\n)", makefile.read_text(), re.M | re.S).group()
    body = ("objpfx := locale/\nmake-target-directory = mkdir -p locale\nPYTHON := python3\n" +
            "VPATH := " + str(libc / "locale") + "\n" + rule.replace("gen-translit.py", str(script)) + "\n")
    generated["locale/C-translit.h"] = make_header(
        "glibc", [makefile, script, libc / "locale/C-translit.h.in"], body,
        "locale/C-translit.h", source_files, retained)
    vendor = {"x86_64": "pc", "aarch64": "unknown"}[machine]
    variables = (".. := " + str(libc) + "/\ncommon-objpfx :=\nSHELL := /bin/sh\n" +
                 "config-machine := " + machine + "\nbase-machine := " + machine + "\n" +
                 "config-vendor := " + vendor + "\nconfig-os := linux-gnu\n" +
                 "move-if-change = $(SHELL) $(..)scripts/move-if-change\n")
    makefile = libc / "csu/Makefile"
    rule = re.search(r"^\$\(objpfx\)abi-tag.h:.*?(?=^\n)", makefile.read_text(), re.M | re.S).group()
    generated["csu/abi-tag.h"] = make_header(
        "glibc", [makefile, libc / "abi-tags"],
        variables + "objpfx := csu/\nmake-target-directory = mkdir -p csu\n" + rule + "\n",
        "csu/abi-tag.h", source_files, retained)
    makefile = libc / "Makerules"
    rule = re.search(r"^\$\(common-objpfx\)libc-abis.h:.*?(?=^common-generated)",
                     makefile.read_text(), re.M | re.S).group()
    generated["libc-abis.h"] = make_header(
        "glibc", [makefile, libc / "scripts/gen-libc-abis", libc / "libc-abis", libc / "scripts/move-if-change"],
        variables + rule + "\n", "libc-abis.h", source_files, retained)
    makefile = libc / "Makeconfig"
    rule = re.search(r"^\$\(common-objpfx\)dl-tunable-list.h:.*?(?=^\n)",
                     makefile.read_text(), re.M | re.S).group()
    sysdirs = ["sysdeps/x86_64/64", "sysdeps/x86"] if machine == "x86_64" else ["sysdeps/aarch64"]
    lists = [libc / (name + "/dl-tunables.list") for name in ["elf", "sysdeps/nptl", *sysdirs]]
    generated["dl-tunable-list.h"] = make_header(
        "glibc", [makefile, libc / "scripts/gen-tunables.awk", libc / "scripts/move-if-change", *lists],
        variables + "AWK := " + awk + "\nsubdirs := sysdeps/nptl\nsysdirs := " +
        " ".join(str(libc / name) for name in sysdirs) + "\n" + rule + "\n",
        "dl-tunable-list.h", source_files, retained)
    makefile = libc / "posix/Makefile"
    rule = re.search(r"^\$\(objpfx\)posix-conf-vars-def.h:.*?(?=^\n)",
                     makefile.read_text(), re.M | re.S).group()
    generated["posix/posix-conf-vars-def.h"] = make_header(
        "glibc", [makefile, libc / "scripts/gen-posix-conf-vars.awk", libc / "posix/posix-conf-vars.list"],
        variables + "objpfx := posix/\nmake-target-directory = mkdir -p posix\nAWK := " + awk +
        "\nVPATH := " + str(libc / "posix") + "\n" + rule + "\n",
        "posix/posix-conf-vars-def.h", source_files, retained)
    makerules, makeconfig = libc / "Makerules", libc / "Makeconfig"
    abi = libc / "sysdeps/unix/sysv/linux" / ("x86" if machine == "x86_64" else "aarch64") / "Makefile"
    wrapper = re.search(r"^\$\(common-objpfx\)gnu/lib-names.h:\n.*?(?=^endif$)",
                        makerules.read_text(), re.M | re.S).group()
    defaults = re.search(r"^ifndef abi-includes\n.*?^endif$", makeconfig.read_text(), re.M | re.S).group()
    generated["gnu/lib-names.h"] = make_header(
        "glibc", [makerules, makeconfig, abi], defaults + "\ninclude " + str(abi) +
        "\ncommon-objpfx :=\n" + wrapper, "gnu/lib-names.h", source_files, retained,
        ["default-abi=" + ("64" if machine == "x86_64" else "lp64")])
    generated["elf/librtld.mapT.o.stdin.s"] = loader_input(libc, source_files, retained)
    return generated


def main():
    evidence = Path("/evidence")
    headers = json.loads((evidence / "gnu-headers.json").read_text())
    if headers["scope"] != "source-header-audit" or not headers["headers_verified"]:
        raise ValueError("Verified source sysroot is required")
    source_files = {}
    for name in ("glibc", "gcc", "linux"):
        source_files.update(json.loads((evidence / (name + ".source-files.json")).read_text()))
    for header in headers["headers"]:
        if not header["verified"] or sha256(header["path"]) != header["sha256"]:
            raise ValueError("Verified installed header changed")
        references = header["sources"] or header["producer"]["inputs"]
        source_files[header["path"]] = {"sha256": header["sha256"], "component": references[0]["component"]}
    work = Path("/build/glibc-runtime")
    work.mkdir()
    environment = {**os.environ, "PATH": "/gnu-bootstrap/bin:" + os.environ["PATH"],
                   "CC": "/gnu-bootstrap/bin/gcc --sysroot=/build/source-sysroot", "CFLAGS": "-O2"}
    commands = [["/build/glibc/glibc-2.41/configure", "--prefix=/usr", "--disable-werror",
                 "--without-selinux", "--with-headers=/build/linux/linux-6.12.107/usr/include"],
                ["make", "-j1", "lib", "CC=python3 /recipe/trace_compiler.py --sysroot=/build/source-sysroot"]]
    with (evidence / "gnu-libc-trace.build.log").open("wb") as log:
        for command in commands:
            result = subprocess.run(command, cwd=work, env=environment, stdout=log,
                                    stderr=subprocess.STDOUT)
            if result.returncode:
                log.flush()
                print((evidence / "gnu-libc-trace.build.log").read_text(errors="replace")[-12000:], flush=True)
                raise RuntimeError("GNU libc trace build failed")
    compilation = evidence / "sources/compilation"
    records = [json.loads(path.read_text()) for path in sorted(compilation.glob("*.json"))]
    if not records:
        raise ValueError("Missing GNU libc compilation records")
    unknown = {}
    retained = evidence / "sources/trace-inputs"
    retained.mkdir()
    producer_inputs = evidence / "runtime-inputs"
    producer_inputs.mkdir()
    generated = generated_inputs(Path("/build/glibc/glibc-2.41"), source_files, producer_inputs, os.uname().machine)
    constants = constant_inputs(Path("/build/glibc/glibc-2.41"), source_files, producer_inputs,
                                evidence / "sources/generation", generated, work)
    verified_inputs = {}
    for record in records:
        for item in record["inputs"]:
            if sha256(item["path"]) != item["sha256"]:
                raise ValueError("Traced compiler input changed")
            (retained / item["sha256"]).write_bytes(Path(item["path"]).read_bytes())
            try:
                input_origin(item["path"], source_files)
            except ValueError:
                relative = str(Path(item["path"]).relative_to(work)) if Path(item["path"]).is_relative_to(work) else None
                producer = generated.get(relative) or constants.get(item["sha256"])
                if producer:
                    if producer["sha256"] != item["sha256"]:
                        raise ValueError("Runtime input differs from its source producer: " + item["path"])
                    verified_inputs[item["path"]] = producer
                else:
                    unknown[item["path"]] = item["sha256"]
    maps = evidence / "sources/link-maps"
    link_maps = {path.name: sha256(path) for path in sorted(maps.glob("*.map"))}
    if not link_maps:
        raise ValueError("Missing GNU libc linker maps")
    generations = evidence / "sources/generation"
    generation_records = {path.name: sha256(path) for path in sorted(generations.glob("*.json"))}
    if len(generation_records) < 4:
        raise ValueError("Missing GNU libc compiler generation records")
    libc = work / "libc.so"
    receipt = {"scope": "gnu-runtime-trace", "release_qualified": False, "completed": True,
               "machine": os.uname().machine,
               "commands": commands, "compiler_records": len(records), "link_maps": link_maps,
               "generation_records": generation_records,
               "unknown_inputs": unknown, "verified_inputs": verified_inputs, "libc_sha256": sha256(libc),
               "header_audit_sha256": sha256(evidence / "gnu-headers.json")}
    (evidence / "gnu-libc-trace.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"compiler_records": len(records), "unknown_inputs": unknown}), flush=True)


if __name__ == "__main__":
    main()
