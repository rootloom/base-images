"""Record source, dependencies, and preprocessing for each compiled object."""

import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

BUILD_ROOT = Path("/build")
RECORDS = Path("/evidence/sources/compilation")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reject_assembler_imports(text):
    if re.search(r"\.(?:include|incbin)\b", text, re.I):
        raise ValueError("Assembler file imports are not allowed")


def dependency_inputs(text):
    rule = text.replace("\\\n", " ").splitlines()[0]
    return [Path(name).resolve() for name in shlex.split(rule.split(":", 1)[1])]


def link_scripts(args):
    tokens = []
    for arg in args:
        if arg == "-Xlinker":
            continue
        tokens.extend(arg[4:].split(",") if arg.startswith("-Wl,") else [arg])
    scripts = []
    for index, token in enumerate(tokens):
        if token.startswith("@"):
            raise ValueError("Unreviewed compiler or linker response file")
        for option in ["-specs", "--specs", "-T", "--script", "--dynamic-list", "--version-script"]:
            if token == option:
                scripts.append(tokens[index + 1])
            elif token.startswith(option + "="):
                scripts.append(token.split("=", 1)[1])
        if token.startswith("-T") and token != "-T" and not token.startswith("-T="):
            scripts.append(token[2:])
    return [{"path": str(Path(path).resolve()), "sha256": digest(path)} for path in scripts]


def main(args):
    if "-c" not in args or "-o" not in args or "-S" in args or "-E" in args:
        subprocess.run(["gcc", *args], check=True)
        if "-o" in args and not any(flag in args for flag in ["-E", "-S"]):
            output = Path(args[args.index("-o") + 1]).resolve()
            if output.is_relative_to(BUILD_ROOT):
                scripts = link_scripts(args)
                links = RECORDS.parent / "linking"
                links.mkdir(parents=True, exist_ok=True)
                record = {"output": str(output), "output_sha256": digest(output), "cwd": str(Path.cwd()), "command": ["gcc", *args], "scripts": scripts}
                key = hashlib.sha256(str(output).encode()).hexdigest()
                (links / (key + ".json")).write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
        return
    output = Path(args[args.index("-o") + 1]).resolve()
    if not output.is_relative_to(BUILD_ROOT):
        subprocess.run(["gcc", *args], check=True)
        return
    records = RECORDS
    records.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(str(output).encode()).hexdigest()
    dependency = records / (key + ".d")
    preprocessed = records / (key + ".i")
    raw_assembly = [Path(arg).resolve() for arg in args if arg.endswith(".s") and Path(arg).is_file()]
    build_dependencies = [arg.split(",", 2)[2] for arg in args if arg.startswith(("-Wp,-MD,", "-Wp,-MMD,"))]
    compile_args = [arg for arg in args if arg != "-pipe" and not arg.startswith(("-Wp,-MD,", "-Wp,-MMD,"))]
    command = ["gcc", *compile_args, "-save-temps=obj", "-MD", "-MF", str(dependency)]
    subprocess.run(command, check=True)
    assembly = output.with_suffix(".s")
    if raw_assembly:
        if len(raw_assembly) != 1:
            raise ValueError("Unexpected assembler inputs")
        assembly = raw_assembly[0]
        dependency.write_text("object: " + str(assembly) + "\n")
        preprocessed.write_bytes(assembly.read_bytes())
    else:
        candidate = output.with_suffix(".i")
        preprocessed.write_bytes((candidate if candidate.exists() else assembly).read_bytes())
    # Inspect the actual assembler input, including compiler-generated inline assembly.
    reject_assembler_imports(assembly.read_text())
    retained_assembly = records / (key + ".s")
    retained_assembly.write_bytes(assembly.read_bytes())
    text = dependency.read_text().replace("\\\n", " ")
    for destination in build_dependencies:
        Path(destination).write_bytes(dependency.read_bytes())
    inputs = dependency_inputs(text)
    if not inputs:
        raise ValueError("Empty compiler dependency record")
    record = {
        "object": str(output), "object_sha256": digest(output),
        "cwd": str(Path.cwd()), "command": command,
        "inputs": [{"path": str(path), "sha256": digest(path)} for path in sorted(set(inputs))],
        "preprocessed": preprocessed.name, "preprocessed_sha256": digest(preprocessed),
        "dependencies": dependency.name, "dependencies_sha256": digest(dependency),
        "assembly": retained_assembly.name, "assembly_sha256": digest(retained_assembly),
    }
    (records / (key + ".json")).write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])
