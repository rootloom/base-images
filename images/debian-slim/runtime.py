"""Trace a fresh GNU libc build without admitting it to a release."""

import json
import os
from pathlib import Path
import re
import subprocess

from headers import make_header
from origins import input_origin, sha256


def generated_inputs(libc, source_files, retained):
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
    generated = generated_inputs(Path("/build/glibc/glibc-2.41"), source_files, producer_inputs)
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
                producer = generated.get(relative)
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
    libc = work / "libc.so"
    receipt = {"scope": "gnu-runtime-trace", "release_qualified": False, "completed": True,
               "commands": commands, "compiler_records": len(records), "link_maps": link_maps,
               "unknown_inputs": unknown, "verified_inputs": verified_inputs, "libc_sha256": sha256(libc),
               "header_audit_sha256": sha256(evidence / "gnu-headers.json")}
    (evidence / "gnu-libc-trace.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"compiler_records": len(records), "unknown_inputs": unknown}), flush=True)


if __name__ == "__main__":
    main()
