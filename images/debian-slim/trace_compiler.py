"""Reuse object tracing and retain GNU linker maps for runtime closure."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

import compiler

GENERATIONS = Path("/evidence/sources/generation")
GENERATION_ROOTS = (Path("/build"), Path("/tmp").resolve())


def main(args):
    if "-S" in args and "-E" not in args and "-o" in args:
        output = Path(args[args.index("-o") + 1]).resolve()
        if any(output.is_relative_to(root) for root in GENERATION_ROOTS):
            if any(item.startswith("@") for item in args):
                raise ValueError("Unreviewed compiler response file")
            stdin = sys.stdin.buffer.read() if "-" in args else None
            directory = GENERATIONS
            directory.mkdir(parents=True, exist_ok=True)
            retained = directory / "inputs"
            retained.mkdir(exist_ok=True)
            key = hashlib.sha256(str(output).encode()).hexdigest()
            # Temporary paths can be reused for different constant probes.
            if not output.is_relative_to("/build"):
                key = uuid.uuid4().hex
            dependency = directory / (key + ".d")
            destinations = [item.split(",", 2)[2] for item in args if item.startswith(("-Wp,-MD,", "-Wp,-MMD,"))]
            destinations += [args[index + 1] for index, item in enumerate(args) if item == "-MF"]
            destinations += [item[3:] for item in args if item.startswith("-MF") and item != "-MF"]
            arguments = []
            skip = False
            for item in args:
                if skip:
                    skip = False
                    continue
                if item == "-MF":
                    skip = True
                    continue
                if item == "-pipe" or item.startswith(("-Wp,-MD,", "-Wp,-MMD,", "-MF")):
                    continue
                arguments.append(item)
            command = ["gcc", *arguments, "-MD", "-MF", str(dependency)]
            if stdin is None:
                subprocess.run(command, check=True)
            else:
                subprocess.run(command, input=stdin, check=True)
            compiler.reject_assembler_imports(output.read_text())
            for destination in destinations:
                Path(destination).write_bytes(dependency.read_bytes())
            inputs = []
            if stdin is not None:
                digest = hashlib.sha256(stdin).hexdigest()
                (retained / digest).write_bytes(stdin)
                inputs.append({"path": "<stdin>", "sha256": digest})
            for path in sorted(set(compiler.dependency_inputs(dependency.read_text()))):
                digest = compiler.digest(path)
                (retained / digest).write_bytes(path.read_bytes())
                inputs.append({"path": str(path), "sha256": digest})
            if not inputs:
                raise ValueError("Missing compiler generation inputs")
            assembly = directory / (key + ".s")
            assembly.write_bytes(output.read_bytes())
            record = {"output": str(output), "output_sha256": compiler.digest(output),
                      "cwd": str(Path.cwd()), "command": command, "inputs": inputs,
                      "dependencies": dependency.name, "dependencies_sha256": compiler.digest(dependency),
                      "assembly": assembly.name, "assembly_sha256": compiler.digest(assembly)}
            (directory / (key + ".json")).write_text(json.dumps(record, indent=2) + "\n")
            return
    existing_map = None
    retained_map = None
    if "-c" in args and "-o" in args and "-" in args and "-x" in args:
        language = args[args.index("-x") + 1]
        if language == "assembler":
            output = Path(args[args.index("-o") + 1]).resolve()
            data = sys.stdin.buffer.read()
            compiler.reject_assembler_imports(data.decode())
            source = output.with_name(output.name + ".stdin.s")
            source.write_bytes(data)
            args = [str(source) if item == "-" else item for item in args]
    if "-o" in args and not any(flag in args for flag in ("-c", "-E", "-S")):
        output = Path(args[args.index("-o") + 1]).resolve()
        if output.is_relative_to("/build"):
            maps = Path("/evidence/sources/link-maps")
            maps.mkdir(parents=True, exist_ok=True)
            key = hashlib.sha256(str(output).encode()).hexdigest()
            retained_map = maps / (key + ".map")
            existing_map = next((Path(item[len("-Wl,-Map,"):]) for item in args
                                 if item.startswith("-Wl,-Map,")), None)
            if existing_map is None:
                args = [*args, "-Wl,-Map=" + str(retained_map)]
    compiler.main(args)
    if existing_map is not None:
        retained_map.write_bytes(existing_map.read_bytes())


if __name__ == "__main__":
    main(sys.argv[1:])
