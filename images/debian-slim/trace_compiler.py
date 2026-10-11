"""Reuse object tracing and retain GNU linker maps for runtime closure."""

import hashlib
from pathlib import Path
import sys

import compiler


def main(args):
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
            args = [*args, "-Wl,-Map=" + str(maps / (key + ".map"))]
    compiler.main(args)


if __name__ == "__main__":
    main(sys.argv[1:])
