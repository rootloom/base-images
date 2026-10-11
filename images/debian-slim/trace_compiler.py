"""Reuse object tracing and retain GNU linker maps for runtime closure."""

import hashlib
from pathlib import Path
import sys

import compiler


def main(args):
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
