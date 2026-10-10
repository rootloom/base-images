"""Compile numeric compiler-rt helpers with musl headers, without bootstrap libraries."""

from pathlib import Path
import re
import subprocess
import sys


def main(arch):
    sources = Path("/build/llvm-project-23.1.3.src/compiler-rt/lib/builtins")
    cmake = (sources / "CMakeLists.txt").read_text()
    groups = ["GENERIC_SOURCES", "GENERIC_TF_SOURCES"]
    if arch == "x86_64":
        groups.append("x86_80_BIT_SOURCES")
    names = []
    for group in groups:
        block = re.search(r"set\(" + group + r"\s+(.*?)\)", cmake, re.S).group(1)
        names.extend(re.findall(r"\b[A-Za-z0-9_]+\.c\b", block))
    names = sorted(set(names) - {"apple_versioning.c", "os_version_check.c", "trampoline_setup.c"})
    output = Path("/build/compiler-builtins")
    output.mkdir()
    include = []
    for path in ["/build/musl-1.2.6/obj/include", "/build/musl-1.2.6/include", "/build/musl-1.2.6/arch/" + arch, "/build/musl-1.2.6/arch/generic"]:
        include.extend(["-isystem", path])
    objects = []
    for name in names:
        object_path = output / (name + ".o")
        subprocess.run(["/recipe/compiler.sh", "-std=gnu11", "-O2", "-fPIC", "-ffreestanding", "-fno-stack-protector", "-fvisibility=hidden", "-nostdinc", "-ffile-prefix-map=/build=.", *include, "-c", str(sources / name), "-o", str(object_path)], check=True)
        objects.append(str(object_path))
    subprocess.run(["ar", "rcsD", "/build/compiler-builtins.a", *objects], check=True)
    Path("/evidence/sources/compiler-builtins.sources").write_text("\n".join(names) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
